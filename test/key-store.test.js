'use strict';
// Встроенное хранилище E2EE-ключей (lib/key-store.js): проверки ввода и
// подписей, семантика ответов как у e2ee-key-server и полный прогон
// протокола public/e2ee.js, в котором все операции с ключами идут через него.
// Запуск: node test/key-store.test.js

const assert = require('assert');
const crypto = require('crypto');
const { createKeyStore, _internal } = require('../lib/key-store');
const { makeFakeKeyDb } = require('./fake-key-db');
const { makeFakeServer } = require('./fake-server');
const E2EE = require('../public/e2ee.js');
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

function ed25519Pair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    return { raw, sign: (msg) => crypto.sign(null, msg, privateKey) };
}

function x25519Raw() {
    const { publicKey } = crypto.generateKeyPairSync('x25519');
    return publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
}

function makeStore() {
    const db = makeFakeKeyDb();
    return { db, store: createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll }) };
}

// Регистрирует identity + SPK (+ PQ-prekey) пользователя, возвращает ключи.
async function register(store, userId, { pq = true } = {}) {
    const signing = ed25519Pair();
    let r = await store.call(userId, 'PUT', '/internal/v1/keys/identity', {
        identity_signing_key: b64(signing.raw), identity_dh_key: b64(x25519Raw()),
    });
    assert.strictEqual(r.status, 200, JSON.stringify(r.data));
    const spk = x25519Raw();
    r = await store.call(userId, 'PUT', '/internal/v1/keys/signed-prekey', {
        key_id: 7, public_key: b64(spk), signature: b64(signing.sign(spk)),
    });
    assert.strictEqual(r.status, 200, JSON.stringify(r.data));
    if (pq) {
        const ek = MLKEM.keygen(crypto.randomBytes(64)).publicKey;
        r = await store.call(userId, 'PUT', '/internal/v1/keys/pq-prekey', {
            key_id: 9, public_key: b64(ek), signature: b64(signing.sign(Buffer.from(ek))),
        });
        assert.strictEqual(r.status, 200, JSON.stringify(r.data));
    }
    return { signing, spk };
}

// Транспорт клиента E2EE: операции с ключами — во встроенное хранилище (как
// это делает lib/e2ee-proxy.js без INTERNAL_KEY_SERVER_SECRET), участники и
// key-share — в фейковый сервер.
function builtinTransport(server, store, userId) {
    const base = server.transportFor(userId);
    const via = async (method, path, body) => {
        const r = await store.call(userId, method, path, body);
        return { status: r.status, data: r.data };
    };
    return Object.assign({}, base, {
        putIdentity: (b) => via('PUT', '/internal/v1/keys/identity', b),
        putSignedPrekey: (b) => via('PUT', '/internal/v1/keys/signed-prekey', b),
        putPqPrekey: (b) => via('PUT', '/internal/v1/keys/pq-prekey', b),
        postOneTimePrekeys: (b) => via('POST', '/internal/v1/keys/one-time-prekeys', b),
        getOneTimePrekeyCount: () => via('GET', '/internal/v1/keys/one-time-prekeys/count'),
        getBundle: (id) => via('GET', '/internal/v1/keys/bundle/' + id),
        deleteKeys: () => via('DELETE', '/internal/v1/keys'),
        async getIdentities(ids) {
            const r = await via('GET', '/internal/v1/keys/identities?ids=' + ids.join(','));
            return r.status === 200 ? { status: 200, data: { success: true, identities: r.data.identities } } : r;
        },
    });
}

async function main() {
    console.log('Built-in E2EE key store tests\n');

    await test('strict base64 and key checks (length, all-zero, invalid characters)', () => {
        const { decodeB64, decodePubkey, decodeSignature } = _internal;
        assert.deepStrictEqual([...decodeB64('f', 'AAEC')], [0, 1, 2]);
        for (const bad of ['AAE', 'AA=C', 'A*EC', 'AAEC\n', 123, null]) {
            assert.throws(() => decodeB64('f', bad), (e) => e.status === 400, String(bad));
        }
        assert.throws(() => decodeB64('f', 'AAF='), (e) => e.status === 400, 'non-canonical padding bits');
        assert.throws(() => decodePubkey('k', b64(Buffer.alloc(32))), /all-zero/);
        assert.throws(() => decodePubkey('k', b64(crypto.randomBytes(31))), /32 bytes/);
        assert.strictEqual(decodePubkey('k', b64(Buffer.alloc(32, 7))).length, 32);
        assert.throws(() => decodeSignature('s', b64(crypto.randomBytes(63))), /64 bytes/);
    });

    await test('ML-KEM public key: FIPS 203 modulus check and all-zero t rejected, honest key accepted', () => {
        const { decodePqPubkey } = _internal;
        const ek = Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);
        assert.strictEqual(decodePqPubkey('pq', b64(ek)).length, 1184);
        const tooBig = Buffer.from(ek);
        tooBig[0] = 0x01; tooBig[1] = (tooBig[1] & 0xf0) | 0x0d; // c0 = 0xd01 = 3329 = q
        assert.throws(() => decodePqPubkey('pq', b64(tooBig)), /modulus/);
        const qMinus1 = Buffer.from(ek);
        qMinus1[0] = 0x00; qMinus1[1] = (qMinus1[1] & 0xf0) | 0x0d; // 0xd00 = 3328
        assert.strictEqual(decodePqPubkey('pq', b64(qMinus1)).length, 1184);
        const zeroT = Buffer.concat([Buffer.alloc(1152), ek.subarray(1152)]);
        assert.throws(() => decodePqPubkey('pq', b64(zeroT)), /all-zero/);
        assert.throws(() => decodePqPubkey('pq', b64(ek.subarray(0, 1183))), /1184 bytes/);
    });

    await test('ids list parsing: sorted, deduplicated, bounded; junk rejected', () => {
        const { parseIdList } = _internal;
        assert.deepStrictEqual(parseIdList('3,1,3,2'), [1, 2, 3]);
        for (const bad of ['', '1,,2', '1,-2', '0', '1,a', '+1', null]) {
            assert.throws(() => parseIdList(bad), (e) => e.status === 400, String(bad));
        }
        assert.throws(() => parseIdList(Array.from({ length: 201 }, (_, i) => i + 1).join(',')), /max 200/);
    });

    await test('identity upsert; signed prekeys need a registered identity (409) and a valid signature', async () => {
        const { store } = makeStore();
        const signing = ed25519Pair();
        const spk = x25519Raw();
        let r = await store.call(1, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1, public_key: b64(spk), signature: b64(signing.sign(spk)) });
        assert.strictEqual(r.status, 409);
        r = await store.call(1, 'PUT', '/internal/v1/keys/identity', { identity_signing_key: b64(signing.raw), identity_dh_key: b64(x25519Raw()) });
        assert.deepStrictEqual(r, { status: 200, ok: true, data: { success: true } });
        const other = ed25519Pair();
        r = await store.call(1, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1, public_key: b64(spk), signature: b64(other.sign(spk)) });
        assert.strictEqual(r.status, 400);
        assert.match(r.data.message, /signature verification failed/);
        r = await store.call(1, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1.5, public_key: b64(spk), signature: b64(signing.sign(spk)) });
        assert.strictEqual(r.status, 400, 'non-integer key_id');
        r = await store.call(1, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1, public_key: b64(spk), signature: b64(signing.sign(spk)) });
        assert.strictEqual(r.status, 200);
        // PQ-prekey: подпись над сырыми байтами ключа тем же identity signing key
        const ek = MLKEM.keygen(crypto.randomBytes(64)).publicKey;
        r = await store.call(1, 'PUT', '/internal/v1/keys/pq-prekey', { key_id: 2, public_key: b64(ek), signature: b64(other.sign(Buffer.from(ek))) });
        assert.strictEqual(r.status, 400);
        r = await store.call(1, 'PUT', '/internal/v1/keys/pq-prekey', { key_id: 2, public_key: b64(ek), signature: b64(signing.sign(Buffer.from(ek))) });
        assert.strictEqual(r.status, 200);
    });

    await test('one-time prekeys: batch limits, duplicates ignored, count', async () => {
        const { store } = makeStore();
        await register(store, 1);
        const keys = [1, 2, 3].map(key_id => ({ key_id, public_key: b64(x25519Raw()) }));
        let r = await store.call(1, 'POST', '/internal/v1/keys/one-time-prekeys', { keys });
        assert.deepStrictEqual(r.data, { success: true, inserted: 3 });
        r = await store.call(1, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: [keys[0], { key_id: 4, public_key: b64(x25519Raw()) }] });
        assert.deepStrictEqual(r.data, { success: true, inserted: 1 }, 'duplicate key_id ignored');
        assert.strictEqual((await store.call(1, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: [] })).status, 400);
        const tooMany = Array.from({ length: 201 }, (_, i) => ({ key_id: 100 + i, public_key: b64(x25519Raw()) }));
        assert.strictEqual((await store.call(1, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: tooMany })).status, 400);
        r = await store.call(1, 'GET', '/internal/v1/keys/one-time-prekeys/count');
        assert.deepStrictEqual(r.data, { count: 4 });
    });

    await test('bundle: 404 before SPK (no OPK consumed), OPKs handed out once each in order, then null', async () => {
        const { store, db } = makeStore();
        const signing = ed25519Pair();
        await store.call(2, 'PUT', '/internal/v1/keys/identity', { identity_signing_key: b64(signing.raw), identity_dh_key: b64(x25519Raw()) });
        await store.call(2, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: [{ key_id: 1, public_key: b64(x25519Raw()) }] });
        let r = await store.call(1, 'GET', '/internal/v1/keys/bundle/2');
        assert.strictEqual(r.status, 404);
        assert.strictEqual(db._state.opks.length, 1, 'OPK must not be consumed by a failed bundle');
        await register(store, 3);
        await store.call(3, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: [11, 12].map(key_id => ({ key_id, public_key: b64(x25519Raw()) })) });
        const got = [];
        for (let i = 0; i < 3; i++) {
            r = await store.call(1, 'GET', '/internal/v1/keys/bundle/3');
            assert.strictEqual(r.status, 200);
            got.push(r.data.one_time_prekey && r.data.one_time_prekey.key_id);
            assert.strictEqual(r.data.signed_prekey.key_id, 7);
            assert.strictEqual(r.data.pq_prekey.key_id, 9);
            assert.strictEqual(Buffer.from(r.data.pq_prekey.public_key, 'base64').length, 1184);
        }
        assert.deepStrictEqual(got, [11, 12, null]);
        await register(store, 4, { pq: false });
        assert.strictEqual((await store.call(1, 'GET', '/internal/v1/keys/bundle/4')).data.pq_prekey, null);
    });

    await test('identities: only registered users, sorted, OPKs untouched; bad list → 400', async () => {
        const { store, db } = makeStore();
        await register(store, 5);
        await register(store, 2);
        await store.call(2, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: [{ key_id: 1, public_key: b64(x25519Raw()) }] });
        const r = await store.call(1, 'GET', '/internal/v1/keys/identities?ids=5,9,2,5');
        assert.deepStrictEqual(r.data.identities.map(i => i.user_id), [2, 5]);
        assert.strictEqual(Buffer.from(r.data.identities[0].identity_dh_key, 'base64').length, 32);
        assert.strictEqual(db._state.opks.length, 1);
        assert.strictEqual((await store.call(1, 'GET', '/internal/v1/keys/identities?ids=1,x')).status, 400);
    });

    await test('delete removes everything; unknown route → 404; DB errors propagate (proxy answers 502)', async () => {
        const { store, db } = makeStore();
        await register(store, 6);
        await store.call(6, 'POST', '/internal/v1/keys/one-time-prekeys', { keys: [{ key_id: 1, public_key: b64(x25519Raw()) }] });
        assert.deepStrictEqual((await store.deleteAll(6)).data, { success: true });
        assert.strictEqual((await store.call(1, 'GET', '/internal/v1/keys/bundle/6')).status, 404);
        assert.deepStrictEqual((await store.call(6, 'GET', '/internal/v1/keys/one-time-prekeys/count')).data, { count: 0 });
        assert.strictEqual((await store.call(1, 'GET', '/internal/v1/keys/nope')).status, 404);
        assert.strictEqual((await store.call(1, 'POST', '/internal/v1/keys/bundle/6')).status, 404, 'wrong method');
        db.failNextQuery(new Error('connection lost'));
        await assert.rejects(store.call(1, 'GET', '/internal/v1/keys/one-time-prekeys/count'), /connection lost/);
    });

    await test('E2EE protocol end to end through the built-in store: PQXDH, group message, OPK consumed', async () => {
        const server = makeFakeServer();
        const { store, db } = makeStore();
        server.addParticipant(500, 1, 11);
        server.addParticipant(500, 2, 22);
        server.addParticipant(500, 3, 33);
        const mk = (id) => E2EE.createClient({ userId: id, storage: new E2EE.MemoryStorage(), transport: builtinTransport(server, store, id), kem: MLKEM });
        const alice = mk(1), bob = mk(2), carol = mk(3);
        await alice.init(); await bob.init(); await carol.init();
        assert.ok(db._state.identities.has(1) && db._state.pqs.has(2) && db._state.spks.has(3), 'keys registered in the built-in store');
        const opkBefore = db._state.opks.filter(o => o.user_id === 2).length;
        const parts = [{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }, { id: 3, username: 'carol' }];
        const r = await alice.ensureRoomSession(11, 500, parts);
        assert.strictEqual(r.ok, true);
        assert.deepStrictEqual(r.warnings, []);
        assert.strictEqual(db._state.opks.filter(o => o.user_id === 2).length, opkBefore - 1, 'one OPK of bob consumed');
        assert.strictEqual((await bob.syncKeyShares(22, 500)).applied, 1);
        assert.strictEqual((await carol.syncKeyShares(33, 500)).applied, 1);
        const ct = await alice.encryptOutgoing(500, 'через встроенное хранилище');
        assert.strictEqual((await bob.decryptIncoming(500, 1, ct, 1)).text, 'через встроенное хранилище');
        assert.strictEqual((await carol.decryptIncoming(500, 1, ct, 1)).text, 'через встроенное хранилище');
        // Коды безопасности совпадают — identity берутся из того же хранилища
        await alice.checkPeerIdentities([2]);
        await bob.checkPeerIdentities([1]);
        assert.strictEqual(await alice.getSafetyNumber(2), await bob.getSafetyNumber(1));
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
