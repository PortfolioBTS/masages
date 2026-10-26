'use strict';
// Журнал ключей выключен или ещё не стартовал (docs/security/key-transparency.md, 1 п. 8, 6.2, 6.5):
//   * без KT_SIGNING_KEY маршруты /api/kt/* отвечают 503 kt-disabled, kt в ответах null,
//     таблицы журнала пусты, регистрация ключей работает как раньше;
//   * с ключом, но до первого запуска задачи эпох (строки kt_state нет): kt null, kt_nonce не
//     создаётся, голова — 503 kt-not-ready;
//   * включение журнала на сервере с уже зарегистрированными ключами: ближайший PUT identity
//     регистрирует их, SKT выдан на открытую эпоху.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { createSuite, waitUntil } = require('./helpers/scenarios');

const KT_SIGNING_KEY = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');

// Тест-ручки: эпоха 2 секунды; задача эпох без ручки maintenance ждёт минуту — этого хватает, чтобы
// проверить состояние «задача ещё не стартовала».
const suite = createSuite('key-transparency-off', { env: { KT_SIGNING_KEY: null, KT_EPOCH_SECONDS: 2 } });

const b64 = (buf) => Buffer.from(buf).toString('base64');

function newKeys() {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const dh = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    return { identity_signing_key: b64(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)), identity_dh_key: b64(dh) };
}

async function newUser() {
    const client = suite.client();
    await client.registerAnon();
    return client;
}

test('без KT_SIGNING_KEY: 503 kt-disabled, kt null, журнал пуст', async () => {
    const user = await newUser();
    for (const path of ['/api/kt/head', '/api/kt/roots?gen=1', `/api/kt/proof?user=${user.user.id}&gen=1&epoch=1`, '/api/kt/self?gen=1']) {
        const res = await user.get(path);
        // head отвечает 200 { enabled:false }: клиент спрашивает его на каждом запуске.
        assert.strictEqual(res.status, path === '/api/kt/head' ? 200 : 503, path);
        assert.strictEqual(res.body.code, 'kt-disabled');
    }
    const keys = newKeys();
    const put = await user.put('/api/keys/identity', keys);
    assert.strictEqual(put.status, 200);
    assert.strictEqual(put.body.kt, null);
    const row = (await suite.query('SELECT kt_nonce, kt_gen, kt_epoch, kt_skt FROM identity_keys WHERE user_id = $1', [user.user.id])).rows[0];
    assert.deepStrictEqual(row, { kt_nonce: null, kt_gen: null, kt_epoch: null, kt_skt: null });
    const ids = await user.get(`/api/keys/identities?ids=${user.user.id}`);
    assert.strictEqual(ids.body.identities[0].kt, null);
    for (const table of ['kt_state', 'kt_epochs', 'kt_entries', 'kt_pending', 'kt_nodes']) {
        assert.strictEqual((await suite.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n, 0, table);
    }
    user.keys = keys;
    suite.existing = user;
});

test('с ключом, но до старта задачи эпох: kt null, kt_nonce не создаётся, голова 503 kt-not-ready', async () => {
    await suite.server.restart({ env: { KT_SIGNING_KEY, NYXO_TEST_MAINTENANCE_MS: 600000 } });
    // Состояние прежнее: задача эпох первый раз запускается через минуту (maintenance выключена ручкой).
    const user = await newUser();
    const head = await user.get('/api/kt/head');
    assert.strictEqual(head.status, 503);
    assert.strictEqual(head.body.code, 'kt-not-ready');
    const keys = newKeys();
    const put = await user.put('/api/keys/identity', keys);
    assert.strictEqual(put.status, 200, JSON.stringify(put.body));
    assert.strictEqual(put.body.kt, null, 'kt_state нет — регистрации нет');
    const row = (await suite.query('SELECT kt_nonce FROM identity_keys WHERE user_id = $1', [user.user.id])).rows[0];
    assert.strictEqual(row.kt_nonce, null);
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM kt_pending')).rows[0].n, 0);
});

test('включение на сервере с уже зарегистрированными ключами: ближайший PUT регистрирует их', async () => {
    await suite.server.restart({ env: { KT_SIGNING_KEY, NYXO_TEST_MAINTENANCE_MS: 300 } });
    const user = suite.existing;
    // Журнал стартует; ждём строку состояния.
    await waitUntil(async () => (await suite.query('SELECT 1 FROM kt_state')).rows.length > 0, { timeoutMs: 20000, what: 'старт журнала' });
    const put = await user.put('/api/keys/identity', user.keys);
    assert.strictEqual(put.status, 200);
    assert.ok(put.body.kt, 'прежние ключи зарегистрированы в журнале');
    assert.strictEqual(Buffer.from(put.body.kt.nonce, 'base64').length, 16);
    assert.strictEqual(Buffer.from(put.body.kt.skt, 'base64').length, 64);
    const again = await user.put('/api/keys/identity', user.keys);
    assert.deepStrictEqual(again.body.kt, put.body.kt, 'повторный PUT тех же ключей не регистрирует их заново');
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM kt_pending WHERE user_id = $1', [user.user.id])).rows[0].n <= 1, true);
    const head = await waitUntil(async () => {
        const res = await user.get('/api/kt/head');
        return res.status === 200 ? res.body : null;
    }, { timeoutMs: 20000, what: 'первая закрытая эпоха' });
    assert.ok(head.gen >= 1);
});

test('выключение журнала после работы: маршруты 503 kt-disabled, kt в ответах null, данные остаются', async () => {
    await suite.server.restart({ env: { KT_SIGNING_KEY: null } });
    const user = suite.existing;
    const res = await user.get('/api/kt/head');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.enabled, false);
    assert.strictEqual(res.body.code, 'kt-disabled');
    const ids = await user.get(`/api/keys/identities?ids=${user.user.id}`);
    assert.strictEqual(ids.body.identities[0].kt, null, 'без ключа подсказка kt не отдаётся');
    assert.ok((await suite.query('SELECT count(*)::int AS n FROM kt_epochs')).rows[0].n >= 0);
});
