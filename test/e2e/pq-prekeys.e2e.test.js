'use strict';
// Одноразовые PQ-prekey (ML-KEM-768) на настоящем сервере и Postgres:
// загрузка с подписью identity-ключа и меткой домена, выдача в bundle ровно
// один раз (в том числе при параллельных запросах), запасной ключ, когда
// одноразовые кончились, лимиты, смена identity, отсутствие времени в
// таблицах ключей.
//
// Подпись: Ed25519(IK, 'nyxo-pqopk-v1\0' ‖ u64be(key_id) ‖ pk[1184]). Байты
// собираются здесь независимо от кода сервера.
//
// Клиент E2EE в этом наборе не участвует: протокол клиента проверяют
// test/pq-prekeys.protocol.test.js и test/e2ee.protocol.test.js, а здесь — то,
// что может сломаться только на настоящей базе (SQL, параллельные запросы).

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const MLKEM = require('../../public/mlkem.js');
const { createSuite } = require('./helpers/scenarios');
const { count } = require('./helpers/anon');

const suite = createSuite('pq-prekeys');

const b64 = (buf) => Buffer.from(buf).toString('base64');
const LABEL = Buffer.from([...'nyxo-pqopk-v1'].map(c => c.charCodeAt(0)).concat([0]));

function labelled(keyId, publicKey) {
    const id = Buffer.alloc(8);
    id.writeBigUInt64BE(BigInt(keyId));
    return Buffer.concat([LABEL, id, Buffer.from(publicKey)]);
}

// Ключи пользователя: identity (Ed25519 + X25519) — для подписей и проверки.
function newIdentity() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const x = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    return {
        signPub: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32),
        dhPub: x,
        sign: (msg) => crypto.sign(null, msg, privateKey),
        verify: (msg, sig) => crypto.verify(null, msg, publicKey, sig),
    };
}

// Одноразовый PQ-prekey с корректной подписью.
function pqKey(identity, keyId) {
    const pk = Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);
    return { key_id: keyId, public_key: b64(pk), signature: b64(identity.sign(labelled(keyId, pk))) };
}

// Регистрирует identity, SPK и PQ last-resort через настоящие маршруты.
async function enroll(client, { pq = true } = {}) {
    const identity = newIdentity();
    // Подписанный состав: допуски и приглашения этого клиента подписываются тем же identity-ключом.
    client.identity = identity;
    await client.ok(client.put('/api/keys/identity', {
        identity_signing_key: b64(identity.signPub), identity_dh_key: b64(identity.dhPub),
    }), 'identity');
    const spk = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    await client.ok(client.put('/api/keys/signed-prekey', {
        key_id: 7, public_key: b64(spk), signature: b64(identity.sign(spk)),
    }), 'signed prekey');
    if (pq) {
        const ek = Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);
        // last-resort подписан «сырыми» байтами, без метки
        identity.lastResort = { key_id: 9, public_key: b64(ek), signature: b64(identity.sign(ek)) };
        await client.ok(client.put('/api/keys/pq-prekey', identity.lastResort), 'pq prekey');
    }
    return identity;
}

const classical = (keyId) => ({ key_id: keyId, public_key: b64(crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)) });

// Цель T и n участников её комнаты (каждый сможет запросить bundle T).
async function roomWith(target, n) {
    const callers = [];
    const ownerChat = await target.createRoom('Ключи');
    const { code } = await target.invite(ownerChat.id);
    for (let i = 0; i < n; i++) {
        const member = suite.client({ name: 'участник ' + (i + 1) });
        await member.registerAnon();
        const pending = await member.join(code);
        await target.approve(pending.requestId);
        callers.push(member);
    }
    return { callers, ownerChat };
}

const bundleOf = (caller, targetId) => caller.get(`/api/keys/bundle/${targetId}`);
const counts = async (client) => (await client.get('/api/keys/one-time-prekeys/count')).body;

test('в таблицах ключей нет столбцов времени, а таблица одноразовых PQ-ключей создана', async () => {
    const cols = await suite.query(
        `SELECT table_name, column_name FROM information_schema.columns
         WHERE table_name IN ('identity_keys', 'signed_prekeys', 'one_time_prekeys', 'signed_pq_prekeys', 'pq_one_time_prekeys')
         ORDER BY table_name, ordinal_position`);
    const byTable = {};
    for (const row of cols.rows) (byTable[row.table_name] = byTable[row.table_name] || []).push(row.column_name);
    assert.deepStrictEqual(byTable.pq_one_time_prekeys, ['id', 'user_id', 'key_id', 'public_key', 'signature']);
    for (const [table, columns] of Object.entries(byTable)) {
        assert.ok(!columns.some(c => /created_at|updated_at|time/i.test(c)), `${table}: ${columns.join(', ')}`);
    }
});

test('загрузка: с подписью и меткой принимается, остальное — 400/409; ответ count содержит оба пула', async () => {
    const user = suite.client({ name: 'загрузка' });
    await user.registerAnon();
    // identity ещё нет — 409, как у подписанных prekey
    const early = await user.post('/api/keys/pq-one-time-prekeys', { keys: [pqKey(newIdentity(), 1)] });
    assert.strictEqual(early.status, 409);

    const id = await enroll(user);
    const good = [1, 2, 3].map(n => pqKey(id, n));
    const res = await user.post('/api/keys/pq-one-time-prekeys', { keys: good });
    assert.strictEqual(res.status, 200, JSON.stringify(res.body));
    assert.deepStrictEqual(res.body, { success: true, inserted: 3 });
    // повтор тех же ключей ничего не добавляет
    assert.deepStrictEqual((await user.post('/api/keys/pq-one-time-prekeys', { keys: good })).body, { success: true, inserted: 0 });
    assert.deepStrictEqual(await counts(user), { count: 0, pq_count: 3 });

    const pk = Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);
    const bad = {
        'без подписи': { key_id: 10, public_key: b64(pk) },
        'подпись «сырых» байтов (формат last-resort)': { key_id: 10, public_key: b64(pk), signature: b64(id.sign(pk)) },
        'подпись другого key_id': { ...pqKey(id, 10), key_id: 11 },
        'подпись чужой identity': { key_id: 10, public_key: b64(pk), signature: b64(newIdentity().sign(labelled(10, pk))) },
        'отрицательный key_id': { ...pqKey(id, 10), key_id: -1 },
    };
    for (const [what, key] of Object.entries(bad)) {
        const r = await user.post('/api/keys/pq-one-time-prekeys', { keys: [key] });
        assert.strictEqual(r.status, 400, `${what}: ${JSON.stringify(r.body)}`);
        assert.strictEqual(r.body.success, false);
    }
    // ключ ML-KEM с коэффициентом ≥ q (подпись верна — ключ нечестный)
    const big = Buffer.from(pk);
    big[0] = 0x01; big[1] = (big[1] & 0xf0) | 0x0d;
    const r = await user.post('/api/keys/pq-one-time-prekeys', { keys: [{ key_id: 12, public_key: b64(big), signature: b64(id.sign(labelled(12, big))) }] });
    assert.strictEqual(r.status, 400);
    assert.match(r.body.message, /modulus/);
    assert.deepStrictEqual(await counts(user), { count: 0, pq_count: 3 }, 'отказы ничего не сохранили');

    // без сессии — 401
    const anon = suite.client({ name: 'аноним' });
    assert.strictEqual((await anon.post('/api/keys/pq-one-time-prekeys', { keys: [good[0]] })).status, 401);
});

test('лимиты: 50 в запросе, 100 на пользователя, 500 классических; удаление освобождает место', async () => {
    const user = suite.client({ name: 'лимиты' });
    await user.registerAnon();
    const id = await enroll(user);
    const batch = (from, n) => Array.from({ length: n }, (_, i) => pqKey(id, from + i));
    const post = (keys) => user.post('/api/keys/pq-one-time-prekeys', { keys });

    const tooMany = await post(batch(1, 51));
    assert.strictEqual(tooMany.status, 400);
    assert.match(tooMany.body.message, /max 50/);
    // 50 ключей — это около 90 КБ JSON: проходят через свой разбор тела
    assert.strictEqual((await post(batch(1, 50))).status, 200);
    assert.strictEqual((await post(batch(51, 50))).status, 200);
    const over = await post(batch(101, 1));
    assert.strictEqual(over.status, 400);
    assert.match(over.body.message, /too many stored keys/);
    assert.deepStrictEqual(await counts(user), { count: 0, pq_count: 100 });

    // Тело больше 256 КБ отклоняется до разбора.
    const huge = await user.post('/api/keys/pq-one-time-prekeys', { keys: [], pad: 'x'.repeat(300 * 1024) });
    assert.strictEqual(huge.status, 413, JSON.stringify(huge.body).slice(0, 200));

    const del = await user.del('/api/keys/pq-one-time-prekeys');
    assert.strictEqual(del.status, 200);
    assert.deepStrictEqual(del.body, { success: true });
    assert.deepStrictEqual(await counts(user), { count: 0, pq_count: 0 });
    assert.strictEqual((await post(batch(200, 50))).status, 200, 'место освободилось');
    // last-resort при очистке пула не тронут
    assert.strictEqual((await user.get('/api/keys/one-time-prekeys/count')).status, 200);

    // Классические: потолок 500 (раньше его не было).
    let next = 1;
    const opks = (n) => ({ keys: Array.from({ length: n }, () => classical(next++)) });
    for (const n of [200, 200, 100]) assert.strictEqual((await user.post('/api/keys/one-time-prekeys', opks(n))).status, 200);
    const full = await user.post('/api/keys/one-time-prekeys', opks(1));
    assert.strictEqual(full.status, 400);
    assert.match(full.body.message, /too many stored keys/);
    assert.deepStrictEqual(await counts(user), { count: 500, pq_count: 50 });
});

test('bundle: ключи по порядку, каждый ровно один раз, затем null; запасной (last-resort) остаётся всегда', async () => {
    const target = suite.client({ name: 'цель' });
    await target.registerAnon();
    const id = await enroll(target);
    const { callers } = await roomWith(target, 4);
    const sent = [21, 22, 23].map(n => pqKey(id, n));
    await target.ok(target.post('/api/keys/pq-one-time-prekeys', { keys: sent }), 'загрузка');

    const got = [];
    for (const caller of callers) {
        const res = await bundleOf(caller, target.user.id);
        assert.strictEqual(res.status, 200, JSON.stringify(res.body));
        assert.deepStrictEqual(res.body.pq_prekey, id.lastResort, 'last-resort идёт в каждом bundle');
        got.push(res.body.pq_one_time_prekey);
    }
    assert.deepStrictEqual(got.map(k => k && k.key_id), [21, 22, 23, null]);
    // ключ — тот, что загружен, подпись проверяется независимо от сервера
    for (let i = 0; i < 3; i++) {
        assert.deepStrictEqual(got[i], sent[i]);
        assert.ok(id.verify(labelled(got[i].key_id, Buffer.from(got[i].public_key, 'base64')), Buffer.from(got[i].signature, 'base64')));
    }
    assert.deepStrictEqual(await counts(target), { count: 0, pq_count: 0 });
});

test('параллельная выдача: 20 ключей и 12 одновременных запросов — ни один ключ не уходит дважды', async () => {
    const target = suite.client({ name: 'цель параллельная' });
    await target.registerAnon();
    const id = await enroll(target);
    const { callers } = await roomWith(target, 12);
    const pq = Array.from({ length: 20 }, (_, i) => pqKey(id, 100 + i));
    await target.ok(target.post('/api/keys/pq-one-time-prekeys', { keys: pq.slice(0, 10) }), 'загрузка 1');
    await target.ok(target.post('/api/keys/pq-one-time-prekeys', { keys: pq.slice(10) }), 'загрузка 2');
    await target.ok(target.post('/api/keys/one-time-prekeys', { keys: Array.from({ length: 20 }, (_, i) => classical(500 + i)) }), 'классические');

    const round = async () => {
        const responses = await Promise.all(callers.map(c => bundleOf(c, target.user.id)));
        for (const r of responses) assert.strictEqual(r.status, 200, JSON.stringify(r.body));
        return responses.map(r => r.body);
    };
    const first = await round();
    const firstPq = first.map(b => b.pq_one_time_prekey).filter(Boolean);
    const firstClassical = first.map(b => b.one_time_prekey).filter(Boolean);
    assert.strictEqual(firstPq.length, 12, 'каждому из 12 достался PQ-ключ');
    assert.strictEqual(new Set(firstPq.map(k => k.key_id)).size, 12, 'и все разные');
    assert.strictEqual(new Set(firstClassical.map(k => k.key_id)).size, 12, 'классические тоже разные');
    assert.deepStrictEqual(await counts(target), { count: 8, pq_count: 8 });

    // Вторая волна: осталось 8 — 8 запросов получают ключ, 4 — null; вместе обе волны отдали все 20 ровно по разу.
    const second = await round();
    const secondPq = second.map(b => b.pq_one_time_prekey).filter(Boolean);
    assert.strictEqual(secondPq.length, 8);
    assert.strictEqual(second.filter(b => b.pq_one_time_prekey === null).length, 4);
    const all = [...firstPq, ...secondPq].map(k => k.key_id).sort((a, b) => a - b);
    assert.deepStrictEqual(all, pq.map(k => k.key_id), 'каждый загруженный ключ выдан ровно один раз');
    for (const k of [...firstPq, ...secondPq]) {
        assert.ok(id.verify(labelled(k.key_id, Buffer.from(k.public_key, 'base64')), Buffer.from(k.signature, 'base64')), 'подпись выданного ключа верна');
    }
    assert.deepStrictEqual(await counts(target), { count: 0, pq_count: 0 });
});

test('участник не может выкачать пул: 5 запросов в час на пару, лимитированный запрос ключей не тратит', async () => {
    const target = suite.client({ name: 'цель лимит' });
    await target.registerAnon();
    const id = await enroll(target);
    const { callers } = await roomWith(target, 1);
    await target.ok(target.post('/api/keys/pq-one-time-prekeys', { keys: Array.from({ length: 10 }, (_, i) => pqKey(id, 1 + i)) }), 'загрузка');
    const [greedy] = callers;
    for (let i = 0; i < 5; i++) assert.strictEqual((await bundleOf(greedy, target.user.id)).status, 200);
    const limited = await bundleOf(greedy, target.user.id);
    assert.strictEqual(limited.status, 429);
    assert.deepStrictEqual(await counts(target), { count: 0, pq_count: 5 }, 'лимитированный запрос не расходует ключ');
});

test('bundle без SPK — 404 и одноразовые PQ-ключи не расходуются; без общей комнаты — 403', async () => {
    const target = suite.client({ name: 'цель без SPK' });
    await target.registerAnon();
    const id = newIdentity();
    target.identity = id;   // допуски участников подписывает этот же ключ (подписанный состав)
    await target.ok(target.put('/api/keys/identity', { identity_signing_key: b64(id.signPub), identity_dh_key: b64(id.dhPub) }), 'identity');
    await target.ok(target.post('/api/keys/pq-one-time-prekeys', { keys: [pqKey(id, 1)] }), 'загрузка');
    const { callers } = await roomWith(target, 1);
    assert.strictEqual((await bundleOf(callers[0], target.user.id)).status, 404);
    assert.deepStrictEqual(await counts(target), { count: 0, pq_count: 1 });
    const stranger = suite.client({ name: 'чужой' });
    await stranger.registerAnon();
    assert.strictEqual((await bundleOf(stranger, target.user.id)).status, 403);
    assert.deepStrictEqual(await counts(target), { count: 0, pq_count: 1 });
});

test('смена identity стирает все prekey старой; повторная регистрация той же identity их не трогает', async () => {
    const user = suite.client({ name: 'смена identity' });
    await user.registerAnon();
    const id = await enroll(user);
    await user.ok(user.post('/api/keys/pq-one-time-prekeys', { keys: [pqKey(id, 1), pqKey(id, 2)] }), 'pq');
    await user.ok(user.post('/api/keys/one-time-prekeys', { keys: [classical(1)] }), 'classical');
    const { callers } = await roomWith(user, 1);

    await user.ok(user.put('/api/keys/identity', { identity_signing_key: b64(id.signPub), identity_dh_key: b64(id.dhPub) }), 'та же identity');
    assert.deepStrictEqual(await counts(user), { count: 1, pq_count: 2 }, 'та же identity ничего не стёрла');
    assert.strictEqual((await bundleOf(callers[0], user.user.id)).status, 200);

    const fresh = newIdentity();
    await user.ok(user.put('/api/keys/identity', { identity_signing_key: b64(fresh.signPub), identity_dh_key: b64(fresh.dhPub) }), 'новая identity');
    assert.deepStrictEqual(await counts(user), { count: 0, pq_count: 0 });
    const rows = {};
    for (const table of ['signed_prekeys', 'signed_pq_prekeys', 'one_time_prekeys', 'pq_one_time_prekeys']) {
        rows[table] = await count(suite, `SELECT 1 FROM ${table} WHERE user_id = $1`, [user.user.id]);
    }
    assert.deepStrictEqual(rows, { signed_prekeys: 0, signed_pq_prekeys: 0, one_time_prekeys: 0, pq_one_time_prekeys: 0 });
    assert.strictEqual((await bundleOf(callers[0], user.user.id)).status, 404, 'SPK новой identity ещё не загружен');
    // ключи, подписанные старой identity, больше не принимаются
    assert.strictEqual((await user.post('/api/keys/pq-one-time-prekeys', { keys: [pqKey(id, 3)] })).status, 400);
    assert.strictEqual((await user.post('/api/keys/pq-one-time-prekeys', { keys: [pqKey(fresh, 3)] })).status, 200);
});
