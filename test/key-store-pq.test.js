'use strict';
// Одноразовые PQ-prekey во встроенном хранилище ключей (lib/key-store.js):
// подпись с меткой домена и её привязка к key_id, проверка модуля ML-KEM,
// лимиты, выдача по порядку, очистка и смена identity. Подписываемые байты
// здесь собираются независимо от кода хранилища (BigInt, свой литерал метки):
// иначе тест повторял бы ошибку формата вместе с реализацией.
// Запуск: node test/key-store-pq.test.js

const assert = require('assert');
const crypto = require('crypto');
const { createKeyStore, _internal } = require('../lib/key-store');
const { makeFakeKeyDb } = require('./fake-key-db');
const MLKEM = require('../public/mlkem.js');

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
const POST = '/internal/v1/keys/pq-one-time-prekeys';
const OPK_POST = '/internal/v1/keys/one-time-prekeys';
const COUNT = '/internal/v1/keys/one-time-prekeys/count';

function ed25519Pair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    return { raw, sign: (msg) => crypto.sign(null, msg, privateKey) };
}

function x25519Raw() {
    const { publicKey } = crypto.generateKeyPairSync('x25519');
    return publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
}

// Независимая сборка подписываемых байтов: 'nyxo-pqopk-v1' + NUL, u64be, ключ.
function labelled(keyId, publicKey) {
    const id = Buffer.alloc(8);
    id.writeBigUInt64BE(BigInt(keyId));
    return Buffer.concat([Buffer.from([...'nyxo-pqopk-v1'].map(c => c.charCodeAt(0)).concat([0])), id, Buffer.from(publicKey)]);
}

const mlkemPublicKey = () => Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);

function makeStore() {
    const db = makeFakeKeyDb();
    return { db, store: createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll }) };
}

async function register(store, userId, { spk = true, pq = true } = {}) {
    const signing = ed25519Pair();
    let r = await store.call(userId, 'PUT', '/internal/v1/keys/identity', {
        identity_signing_key: b64(signing.raw), identity_dh_key: b64(x25519Raw()),
    });
    assert.strictEqual(r.status, 200, JSON.stringify(r.data));
    if (spk) {
        const key = x25519Raw();
        r = await store.call(userId, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 7, public_key: b64(key), signature: b64(signing.sign(key)) });
        assert.strictEqual(r.status, 200, JSON.stringify(r.data));
    }
    if (pq) {
        const ek = mlkemPublicKey();
        r = await store.call(userId, 'PUT', '/internal/v1/keys/pq-prekey', { key_id: 9, public_key: b64(ek), signature: b64(signing.sign(ek)) });
        assert.strictEqual(r.status, 200, JSON.stringify(r.data));
    }
    return { signing };
}

// Корректный одноразовый PQ-prekey: подпись с меткой над своим key_id.
function pqKey(signing, keyId) {
    const publicKey = mlkemPublicKey();
    return { key_id: keyId, public_key: b64(publicKey), signature: b64(signing.sign(labelled(keyId, publicKey))), _pk: publicKey };
}

const wire = (keys) => keys.map(({ key_id, public_key, signature }) => ({ key_id, public_key, signature }));

async function main() {
    console.log('One-time PQ prekeys in the built-in key store\n');

    await test('signature = Ed25519(IK, label ‖ u64be(key_id) ‖ pk): accepted; the module builds the same bytes', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        const keys = [1, 2, 3].map(id => pqKey(signing, id));
        const r = await store.call(1, 'POST', POST, { keys: wire(keys) });
        assert.deepStrictEqual(r, { status: 200, ok: true, data: { success: true, inserted: 3 } });
        assert.strictEqual(db._state.pqOpks.length, 3);
        assert.deepStrictEqual(
            [..._internal.pqOneTimePrekeyMessage(5, keys[0]._pk)],
            [...labelled(5, keys[0]._pk)],
            'message layout is identical'
        );
        assert.strictEqual(_internal.pqOneTimePrekeyMessage(5, keys[0]._pk).length, 14 + 8 + 1184);
    });

    await test('key_id above 2^32 and up to 2^53-1 is encoded as u64be (high word is not lost)', async () => {
        const { store } = makeStore();
        const { signing } = await register(store, 1);
        for (const keyId of [2 ** 32, 2 ** 32 + 5, 2 ** 40 + 12345, Number.MAX_SAFE_INTEGER]) {
            const r = await store.call(1, 'POST', POST, { keys: wire([pqKey(signing, keyId)]) });
            assert.strictEqual(r.status, 200, `key_id ${keyId}: ${JSON.stringify(r.data)}`);
        }
        assert.deepStrictEqual([..._internal.u64be(2 ** 32 + 5)], [0, 0, 0, 1, 0, 0, 0, 5]);
        assert.deepStrictEqual([..._internal.u64be(Number.MAX_SAFE_INTEGER)], [0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    });

    await test('a signature made for another key_id is rejected (the id is bound to the key)', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        const key = pqKey(signing, 10);
        const r = await store.call(1, 'POST', POST, { keys: wire([{ ...key, key_id: 11 }]) });
        assert.strictEqual(r.status, 400);
        assert.match(r.data.message, /signature verification failed/);
        assert.strictEqual(db._state.pqOpks.length, 0);
    });

    await test('the raw-bytes signature (last-resort format) and a signature over another key are rejected', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        const pk = mlkemPublicKey();
        let r = await store.call(1, 'POST', POST, { keys: [{ key_id: 1, public_key: b64(pk), signature: b64(signing.sign(pk)) }] });
        assert.strictEqual(r.status, 400, 'a last-resort signature must not pass as a one-time one');
        // и наоборот: подпись с меткой не годится для last-resort
        r = await store.call(1, 'PUT', '/internal/v1/keys/pq-prekey', { key_id: 2, public_key: b64(pk), signature: b64(signing.sign(labelled(2, pk))) });
        assert.strictEqual(r.status, 400, 'a one-time signature must not pass as a last-resort one');
        const other = pqKey(signing, 1);
        r = await store.call(1, 'POST', POST, { keys: [{ key_id: 1, public_key: b64(pk), signature: other.signature }] });
        assert.strictEqual(r.status, 400, 'signature of another public key');
        const stranger = ed25519Pair();
        r = await store.call(1, 'POST', POST, { keys: [{ key_id: 1, public_key: b64(pk), signature: b64(stranger.sign(labelled(1, pk))) }] });
        assert.strictEqual(r.status, 400, 'signature by someone else’s identity key');
        assert.strictEqual(db._state.pqOpks.length, 0);
    });

    await test('one bad key rejects the whole batch (nothing is stored)', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        const keys = wire([pqKey(signing, 1), pqKey(signing, 2), { ...pqKey(signing, 3), key_id: 4 }]);
        assert.strictEqual((await store.call(1, 'POST', POST, { keys })).status, 400);
        assert.strictEqual(db._state.pqOpks.length, 0);
    });

    await test('input checks: key_id (integer ≥ 0), ML-KEM modulus, lengths, base64, empty and non-array batches', async () => {
        const { store } = makeStore();
        const { signing } = await register(store, 1);
        const good = pqKey(signing, 1);
        const call = (keys) => store.call(1, 'POST', POST, { keys });
        for (const bad of [-1, 1.5, '1', null, undefined, Number.MAX_SAFE_INTEGER + 1]) {
            assert.strictEqual((await call([{ ...wire([good])[0], key_id: bad }])).status, 400, 'key_id ' + String(bad));
        }
        // коэффициент ≥ q: подпись верна, но ключ нечестный
        const big = Buffer.from(good._pk);
        big[0] = 0x01; big[1] = (big[1] & 0xf0) | 0x0d;
        const bigKey = { key_id: 2, public_key: b64(big), signature: b64(signing.sign(labelled(2, big))) };
        let r = await call([bigKey]);
        assert.strictEqual(r.status, 400);
        assert.match(r.data.message, /modulus/);
        const short = good._pk.subarray(0, 1183);
        r = await call([{ key_id: 3, public_key: b64(short), signature: b64(signing.sign(labelled(3, short))) }]);
        assert.match(r.data.message, /1184 bytes/);
        r = await call([{ ...wire([good])[0], signature: b64(crypto.randomBytes(63)) }]);
        assert.match(r.data.message, /64 bytes/);
        r = await call([{ ...wire([good])[0], public_key: '!!!' }]);
        assert.match(r.data.message, /base64/);
        for (const keys of [[], null, undefined, 'x', {}]) assert.strictEqual((await call(keys)).status, 400);
        assert.strictEqual((await store.call(1, 'POST', POST, null)).status, 400);
        assert.strictEqual((await call([null])).status, 400);
    });

    await test('identity must be registered first: 409 (as for the signed prekeys), nothing stored', async () => {
        const { store, db } = makeStore();
        const signing = ed25519Pair();
        const r = await store.call(1, 'POST', POST, { keys: wire([pqKey(signing, 1)]) });
        assert.strictEqual(r.status, 409);
        assert.strictEqual(db._state.pqOpks.length, 0);
    });

    await test('limits: at most 50 per request and 100 stored per user (the 101st is a 400, not a silent cut)', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        assert.strictEqual(_internal.MAX_PQ_OTPK_BATCH, 50);
        assert.strictEqual(_internal.MAX_PQ_OTPK_STORED, 100);
        const make = (from, n) => wire(Array.from({ length: n }, (_, i) => pqKey(signing, from + i)));
        let r = await store.call(1, 'POST', POST, { keys: make(1, 51) });
        assert.strictEqual(r.status, 400);
        assert.match(r.data.message, /max 50/);
        assert.strictEqual((await store.call(1, 'POST', POST, { keys: make(1, 50) })).status, 200);
        assert.strictEqual((await store.call(1, 'POST', POST, { keys: make(51, 50) })).status, 200);
        r = await store.call(1, 'POST', POST, { keys: make(101, 1) });
        assert.strictEqual(r.status, 400);
        assert.match(r.data.message, /too many stored keys/);
        assert.strictEqual(db._state.pqOpks.length, 100);
        // Потолок — на пользователя: другой пользователь не затронут.
        const other = await register(store, 2);
        assert.strictEqual((await store.call(2, 'POST', POST, { keys: make(1, 1).map(() => wire([pqKey(other.signing, 1)])[0]) })).status, 200);
        // Освободившееся место снова доступно.
        await store.call(1, 'DELETE', POST);
        assert.strictEqual((await store.call(1, 'POST', POST, { keys: make(200, 50) })).status, 200);
    });

    await test('concurrent uploads that both passed the pre-check are cut back to the cap afterwards', async () => {
        const db = makeFakeKeyDb();
        let peak = 0; // наибольшее число строк в пуле между запросами
        const dbAll = async (sql, params) => {
            const rows = await db.dbAll(sql, params);
            peak = Math.max(peak, db._state.pqOpks.length);
            return rows;
        };
        const store = createKeyStore({ dbGet: async (sql, params) => (await dbAll(sql, params))[0] || null, dbAll });
        const { signing } = await register(store, 1);
        const batchA = wire(Array.from({ length: 50 }, (_, i) => pqKey(signing, 1 + i)));
        const batchB = wire(Array.from({ length: 50 }, (_, i) => pqKey(signing, 51 + i)));
        const batchC = wire(Array.from({ length: 50 }, (_, i) => pqKey(signing, 101 + i)));
        await Promise.all([store.call(1, 'POST', POST, { keys: batchA }), store.call(1, 'POST', POST, { keys: batchB }), store.call(1, 'POST', POST, { keys: batchC })]);
        assert.ok(peak > 100, 'the race must really happen in this test (peak ' + peak + ')');
        assert.strictEqual(db._state.pqOpks.length, 100, 'the cap is restored');
    });

    await test('classical one-time prekeys get a ceiling of 500 per user as well', async () => {
        const { store, db } = makeStore();
        await register(store, 1);
        assert.strictEqual(_internal.MAX_OTPK_STORED, 500);
        let next = 1;
        const batch = (n) => ({ keys: Array.from({ length: n }, () => ({ key_id: next++, public_key: b64(x25519Raw()) })) });
        assert.strictEqual((await store.call(1, 'POST', OPK_POST, batch(200))).status, 200);
        assert.strictEqual((await store.call(1, 'POST', OPK_POST, batch(200))).status, 200);
        assert.strictEqual((await store.call(1, 'POST', OPK_POST, batch(100))).status, 200);
        const r = await store.call(1, 'POST', OPK_POST, batch(1));
        assert.strictEqual(r.status, 400);
        assert.match(r.data.message, /too many stored keys/);
        assert.strictEqual(db._state.opks.length, 500);
    });

    await test('count returns both pools: { count, pq_count }', async () => {
        const { store } = makeStore();
        const { signing } = await register(store, 1);
        assert.deepStrictEqual((await store.call(1, 'GET', COUNT)).data, { count: 0, pq_count: 0 });
        await store.call(1, 'POST', OPK_POST, { keys: [1, 2].map(key_id => ({ key_id, public_key: b64(x25519Raw()) })) });
        await store.call(1, 'POST', POST, { keys: wire([1, 2, 3].map(id => pqKey(signing, id))) });
        assert.deepStrictEqual((await store.call(1, 'GET', COUNT)).data, { count: 2, pq_count: 3 });
    });

    await test('bundle: PQ one-time prekeys come out once each, in upload order, then null; last-resort stays in every bundle', async () => {
        const { store } = makeStore();
        const { signing } = await register(store, 2);
        const keys = [21, 22, 23].map(id => pqKey(signing, id));
        await store.call(2, 'POST', POST, { keys: wire(keys) });
        const got = [];
        for (let i = 0; i < 4; i++) {
            const r = await store.call(1, 'GET', '/internal/v1/keys/bundle/2');
            assert.strictEqual(r.status, 200);
            assert.strictEqual(r.data.pq_prekey.key_id, 9, 'last-resort is always present');
            got.push(r.data.pq_one_time_prekey);
        }
        assert.deepStrictEqual(got.map(k => k && k.key_id), [21, 22, 23, null]);
        // Выданный ключ — тот же, что загружен, вместе с подписью.
        assert.strictEqual(got[0].public_key, keys[0].public_key);
        assert.strictEqual(got[0].signature, keys[0].signature);
        assert.strictEqual(Buffer.from(got[0].public_key, 'base64').length, 1184);
        assert.strictEqual(Buffer.from(got[0].signature, 'base64').length, 64);
    });

    await test('bundle: the classical and the PQ pool are drained independently; no SPK → 404 and nothing is consumed', async () => {
        const { store, db } = makeStore();
        const noSpk = await register(store, 3, { spk: false });
        await store.call(3, 'POST', POST, { keys: wire([pqKey(noSpk.signing, 1)]) });
        assert.strictEqual((await store.call(1, 'GET', '/internal/v1/keys/bundle/3')).status, 404);
        assert.strictEqual(db._state.pqOpks.length, 1, 'a failed bundle must not burn the PQ key');

        const { signing } = await register(store, 4);
        await store.call(4, 'POST', OPK_POST, { keys: [{ key_id: 1, public_key: b64(x25519Raw()) }] });
        await store.call(4, 'POST', POST, { keys: wire([pqKey(signing, 5), pqKey(signing, 6)]) });
        const r1 = (await store.call(1, 'GET', '/internal/v1/keys/bundle/4')).data;
        const r2 = (await store.call(1, 'GET', '/internal/v1/keys/bundle/4')).data;
        assert.deepStrictEqual([r1.one_time_prekey && r1.one_time_prekey.key_id, r1.pq_one_time_prekey.key_id], [1, 5]);
        assert.deepStrictEqual([r2.one_time_prekey, r2.pq_one_time_prekey.key_id], [null, 6]);
    });

    await test('a bundle without a last-resort PQ key still carries a one-time one (the client decides what to accept)', async () => {
        const { store } = makeStore();
        const { signing } = await register(store, 5, { pq: false });
        await store.call(5, 'POST', POST, { keys: wire([pqKey(signing, 1)]) });
        const r = await store.call(1, 'GET', '/internal/v1/keys/bundle/5');
        assert.strictEqual(r.data.pq_prekey, null);
        assert.strictEqual(r.data.pq_one_time_prekey.key_id, 1);
    });

    await test('DELETE clears only the PQ pool of the caller', async () => {
        const { store, db } = makeStore();
        const a = await register(store, 1);
        const b = await register(store, 2);
        await store.call(1, 'POST', OPK_POST, { keys: [{ key_id: 1, public_key: b64(x25519Raw()) }] });
        await store.call(1, 'POST', POST, { keys: wire([pqKey(a.signing, 1), pqKey(a.signing, 2)]) });
        await store.call(2, 'POST', POST, { keys: wire([pqKey(b.signing, 1)]) });
        const r = await store.call(1, 'DELETE', POST);
        assert.deepStrictEqual(r, { status: 200, ok: true, data: { success: true } });
        assert.deepStrictEqual((await store.call(1, 'GET', COUNT)).data, { count: 1, pq_count: 0 });
        assert.deepStrictEqual((await store.call(2, 'GET', COUNT)).data.pq_count, 1);
        assert.strictEqual(db._state.pqs.has(1), true, 'last-resort is not touched');
    });

    await test('DELETE /keys (account removal) takes the PQ pool with it', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        await store.call(1, 'POST', POST, { keys: wire([pqKey(signing, 1)]) });
        await store.deleteAll(1);
        assert.strictEqual(db._state.pqOpks.length, 0);
        assert.strictEqual(db._state.identities.size, 0);
    });

    await test('a changed identity wipes every prekey signed by the old one; the same identity again wipes nothing', async () => {
        const { store, db } = makeStore();
        const { signing } = await register(store, 1);
        await store.call(1, 'POST', OPK_POST, { keys: [{ key_id: 1, public_key: b64(x25519Raw()) }] });
        await store.call(1, 'POST', POST, { keys: wire([pqKey(signing, 1), pqKey(signing, 2)]) });
        const identity = db._state.identities.get(1);
        // Повторная регистрация той же identity — ключи на месте.
        let r = await store.call(1, 'PUT', '/internal/v1/keys/identity', {
            identity_signing_key: b64(identity.identity_signing_key), identity_dh_key: b64(identity.identity_dh_key),
        });
        assert.strictEqual(r.status, 200);
        assert.deepStrictEqual([db._state.spks.size, db._state.pqs.size, db._state.opks.length, db._state.pqOpks.length], [1, 1, 1, 2]);
        // Новая identity — всё прежнее стёрто, кроме неё самой.
        const fresh = ed25519Pair();
        r = await store.call(1, 'PUT', '/internal/v1/keys/identity', { identity_signing_key: b64(fresh.raw), identity_dh_key: b64(x25519Raw()) });
        assert.strictEqual(r.status, 200);
        assert.deepStrictEqual([db._state.spks.size, db._state.pqs.size, db._state.opks.length, db._state.pqOpks.length], [0, 0, 0, 0]);
        assert.strictEqual(db._state.identities.size, 1);
        // Ключи старой identity больше не принимаются, новой — принимаются.
        assert.strictEqual((await store.call(1, 'POST', POST, { keys: wire([pqKey(signing, 3)]) })).status, 400);
        assert.strictEqual((await store.call(1, 'POST', POST, { keys: wire([pqKey(fresh, 3)]) })).status, 200);
        assert.strictEqual((await store.call(1, 'GET', '/internal/v1/keys/bundle/1')).status, 404, 'no SPK of the new identity yet');
    });

    await test('another user’s prekeys survive a change of identity', async () => {
        const { store, db } = makeStore();
        await register(store, 1);
        const other = await register(store, 2);
        await store.call(2, 'POST', POST, { keys: wire([pqKey(other.signing, 1)]) });
        await store.call(1, 'PUT', '/internal/v1/keys/identity', { identity_signing_key: b64(ed25519Pair().raw), identity_dh_key: b64(x25519Raw()) });
        assert.strictEqual(db._state.pqOpks.length, 1);
        assert.strictEqual(db._state.spks.has(2), true);
    });

    await test('server code: the PQ pool route has its own JSON parser (256 KB) before the general one', () => {
        const src = require('./server-source').readServerSource();
        const own = src.indexOf("app.use('/api/keys/pq-one-time-prekeys', express.json({ limit: '256kb' }))");
        const general = src.indexOf('app.use(express.json());');
        assert.ok(own > 0, 'parser for /api/keys/pq-one-time-prekeys is missing');
        assert.ok(own < general, 'it must come before the general parser, which would otherwise parse the body first');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
