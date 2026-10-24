'use strict';
// Хранилище ключей и журнал (lib/key-store.js, docs/security/key-transparency.md, 6.2):
// регистрация identity одной транзакцией вместе с записью в журнал, kt (с SKT) в ответах PUT,
// identities и bundle, 429 kt-rate с машинным кодом, откат транзакции при отказе, прежний путь
// без журнала. Сервис журнала здесь — поддельный (его SQL проверяют сквозные тесты на Postgres).
// Запуск: node test/key-store-kt.test.js

const assert = require('assert');
const crypto = require('crypto');
const { createKeyStore, KeyStoreError } = require('../lib/key-store');
const { makeFakeKeyDb } = require('./fake-key-db');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const b64 = (buf) => Buffer.from(buf).toString('base64');
const raw = (type) => crypto.generateKeyPairSync(type).publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const keysBody = () => ({ identity_signing_key: b64(raw('ed25519')), identity_dh_key: b64(raw('x25519')) });

// Поддельный журнал: kt_state есть/нет, предел регистраций, учёт порядка вызовов.
function makeKt({ state = { gen: 3, gen_start: 1, open_epoch: 77 }, enabled = true, limit = 16, db } = {}) {
    const log = [];
    const registered = new Map(); // userId -> число регистраций
    const kt = {
        enabled,
        log,
        async lockState(client) {
            log.push('lockState');
            assert.ok(client && typeof client.query === 'function', 'в транзакцию передан клиент');
            return enabled ? state : null;
        },
        async registerInTx(client, st, { userId, keysChanged }) {
            log.push(`register:${keysChanged ? 'changed' : 'same'}`);
            const row = db._state.identities.get(userId);
            if (!keysChanged && row.kt_nonce) return kt.hintOf(row);
            const n = (registered.get(userId) || 0) + 1;
            if (n > limit) throw new KeyStoreError(429, 'лимит', 'kt-rate');
            registered.set(userId, n);
            Object.assign(row, {
                kt_nonce: Buffer.alloc(16, n), kt_gen: st.gen, kt_epoch: st.open_epoch, kt_skt: Buffer.alloc(64, n),
            });
            return kt.hintOf(row);
        },
        hintOf(row) {
            if (!row || !row.kt_nonce) return null;
            return { gen: row.kt_gen, epoch: row.kt_epoch, nonce: b64(row.kt_nonce), skt: row.kt_skt ? b64(row.kt_skt) : null };
        },
    };
    return kt;
}

// Транзакция поверх фейковой базы: клиент отвечает теми же запросами; журнал вызовов и откат — по исключению.
function makeTransaction(db) {
    const events = [];
    return {
        events,
        async withTransaction(work) {
            events.push('BEGIN');
            const client = { query: async (sql, params) => ({ rows: await db.dbAll(sql, params) }) };
            try {
                const result = await work(client);
                events.push('COMMIT');
                return result;
            } catch (err) {
                events.push('ROLLBACK');
                throw err;
            }
        },
    };
}

function setup(ktOptions = {}) {
    const db = makeFakeKeyDb();
    const tx = makeTransaction(db);
    const kt = makeKt({ ...ktOptions, db });
    const store = createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll, withTransaction: tx.withTransaction, kt });
    return { db, tx, kt, store };
}

const put = (store, userId, body) => store.call(userId, 'PUT', '/internal/v1/keys/identity', body);

async function main() {
    await test('регистрация одной транзакцией: сначала kt_state, потом identity; в ответе kt с SKT', async () => {
        const { store, tx, kt } = setup();
        const res = await put(store, 7, keysBody());
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.data, { success: true, kt: { gen: 3, epoch: 77, nonce: b64(Buffer.alloc(16, 1)), skt: b64(Buffer.alloc(64, 1)) } });
        assert.deepStrictEqual(tx.events, ['BEGIN', 'COMMIT']);
        assert.deepStrictEqual(kt.log, ['lockState', 'register:changed'], 'порядок блокировок: kt_state, затем identity_keys');
    });

    await test('те же ключи: регистрации нет, ответ тот же; новые ключи — новая регистрация; prekey старой identity стираются в той же транзакции', async () => {
        const { store, db, kt } = setup();
        const keys = keysBody();
        const first = await put(store, 7, keys);
        const again = await put(store, 7, keys);
        assert.deepStrictEqual(again.data.kt, first.data.kt);
        assert.deepStrictEqual(kt.log.slice(-1), ['register:same']);
        db._state.spks.set(7, { key_id: 1, public_key: Buffer.alloc(32), signature: Buffer.alloc(64) });
        const changed = await put(store, 7, keysBody());
        assert.notStrictEqual(changed.data.kt.nonce, first.data.kt.nonce);
        assert.strictEqual(db._state.spks.has(7), false, 'SPK прежней identity стёрт');
    });

    await test('kt_state ещё нет или журнал выключен: kt = null, регистрации нет', async () => {
        const noState = setup({ state: null });
        const res = await put(noState.store, 7, keysBody());
        assert.deepStrictEqual(res.data, { success: true, kt: null });
        assert.deepStrictEqual(noState.kt.log, ['lockState']);
        const disabled = setup({ enabled: false });
        assert.deepStrictEqual((await put(disabled.store, 7, keysBody())).data, { success: true, kt: null });
        assert.ok(!disabled.kt.log.some(entry => entry.startsWith('register')));
    });

    await test('предел регистраций: 429 с кодом kt-rate, транзакция откатывается (откат записи — сквозной тест на Postgres)', async () => {
        const { store, tx } = setup({ limit: 1 });
        assert.strictEqual((await put(store, 7, keysBody())).status, 200);
        const refused = await put(store, 7, keysBody());
        assert.strictEqual(refused.status, 429);
        assert.strictEqual(refused.ok, false);
        assert.strictEqual(refused.data.code, 'kt-rate');
        assert.strictEqual(refused.data.success, false);
        assert.deepStrictEqual(tx.events.slice(-2), ['BEGIN', 'ROLLBACK']);
    });

    await test('ошибка базы внутри транзакции откатывает её и поднимается наверх (маршрут ответит 503 busy или 500)', async () => {
        const { store, db, tx } = setup();
        db.failNextQuery(new Error('обрыв соединения'));
        await assert.rejects(() => put(store, 7, keysBody()), /обрыв соединения/);
        assert.strictEqual(tx.events[tx.events.length - 1], 'ROLLBACK');
        assert.strictEqual(db._state.identities.size, 0);
    });

    await test('identities и bundle отдают kt собеседника (с skt) и null, пока ключ не в журнале', async () => {
        const { store, db } = setup();
        const aliceKeys = keysBody();
        await put(store, 7, aliceKeys);
        const bobKeys = keysBody();
        await put(store, 8, bobKeys);
        // У Боба регистрации в журнале нет (как у ключей, внесённых до включения журнала).
        for (const key of ['kt_nonce', 'kt_gen', 'kt_epoch', 'kt_skt']) delete db._state.identities.get(8)[key];
        const ids = await store.call(1, 'GET', '/internal/v1/keys/identities?ids=7,8');
        assert.strictEqual(ids.data.identities[0].kt.skt, b64(Buffer.alloc(64, 1)));
        assert.strictEqual(ids.data.identities[1].kt, null);
        // bundle: нужен SPK.
        const signing = crypto.generateKeyPairSync('ed25519');
        const body = { identity_signing_key: b64(signing.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)), identity_dh_key: b64(raw('x25519')) };
        await put(store, 9, body);
        const spk = raw('x25519');
        const sig = crypto.sign(null, spk, signing.privateKey);
        assert.strictEqual((await store.call(9, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1, public_key: b64(spk), signature: b64(sig) })).status, 200);
        const bundle = await store.call(1, 'GET', '/internal/v1/keys/bundle/9');
        assert.strictEqual(bundle.status, 200);
        assert.strictEqual(bundle.data.kt.nonce, b64(Buffer.alloc(16, 1)));
    });

    await test('прежний путь без журнала и транзакций: ответы без поля kt', async () => {
        const db = makeFakeKeyDb();
        const store = createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll });
        const res = await put(store, 7, keysBody());
        assert.deepStrictEqual(res.data, { success: true });
        const ids = await store.call(1, 'GET', '/internal/v1/keys/identities?ids=7');
        assert.ok(!('kt' in ids.data.identities[0]));
        assert.throws(() => createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll, kt: makeKt({ db }) }), /withTransaction/);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
