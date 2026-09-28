'use strict';
// Прогон протокола E2EE (PQXDH + Sender Keys) в чистом Node, без браузера
// и без реального сервера — public/e2ee.js использует только
// globalThis.crypto (Web Crypto) и public/mlkem.js, поэтому тестируется
// буквально тот же код, что грузится в браузере.
// Запуск: node test/e2ee.protocol.test.js

// ML-KEM в Node WebCrypto экспериментальный и шумит предупреждениями на
// каждый вызов адаптера — глушим только их.
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const nodeCrypto = require('crypto');
const E2EE = require('../public/e2ee.js');
const { makeFakeServer } = require('./fake-server');

const subtle = globalThis.crypto.subtle;
const { b64encode: b64, b64decode: unb64 } = E2EE._internal;
const DAY = 24 * 60 * 60 * 1000;

// ===================== Реализации KEM =====================

// Адаптер интерфейса К2 поверх ML-KEM-768 из Node WebCrypto — независимая
// реализация для проверки совместимости с public/mlkem.js. WebCrypto не
// отдаёт развёрнутый 2400-байтовый ключ декапсуляции, поэтому secretKey
// здесь — непрозрачный 64-байтовый seed; e2ee.js секретный ключ между
// реализациями не передаёт, только публичный ключ и шифротекст (FIPS 203).
function makeWebCryptoKem() {
    const alg = { name: 'ML-KEM-768' };
    return {
        async keygen(seed) {
            const priv = await subtle.importKey('raw-seed', seed, alg, false, ['decapsulateBits']);
            const pub = await subtle.getPublicKey(priv, ['encapsulateBits']);
            return { publicKey: new Uint8Array(await subtle.exportKey('raw-public', pub)), secretKey: seed.slice() };
        },
        async encapsulate(publicKey) {
            const pub = await subtle.importKey('raw-public', publicKey, alg, false, ['encapsulateBits']);
            const r = await subtle.encapsulateBits(alg, pub);
            return { ciphertext: new Uint8Array(r.ciphertext), sharedSecret: new Uint8Array(r.sharedKey) };
        },
        async decapsulate(secretKey, ciphertext) {
            const priv = await subtle.importKey('raw-seed', secretKey, alg, false, ['decapsulateBits']);
            return new Uint8Array(await subtle.decapsulateBits(alg, priv, ciphertext));
        },
    };
}

function loadMlkem() {
    try {
        const kem = require('../public/mlkem.js');
        const kp = kem.keygen(globalThis.crypto.getRandomValues(new Uint8Array(64)));
        const enc = kem.encapsulate(kp.publicKey);
        const ss = kem.decapsulate(kp.secretKey, enc.ciphertext);
        return Buffer.from(ss).equals(Buffer.from(enc.sharedSecret)) ? kem : null;
    } catch {
        return null;
    }
}

const mlkem = loadMlkem();
const webKem = makeWebCryptoKem();
const primaryKem = mlkem || webKem;

// ===================== Мини-раннер =====================

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

// ===================== Хелперы =====================

function makeUser(server, userId, opts = {}) {
    const storage = opts.storage || new E2EE.MemoryStorage();
    const client = E2EE.createClient({
        userId,
        storage,
        transport: opts.transport || server.transportFor(userId),
        kem: opts.kem || primaryKem,
        now: opts.now,
    });
    client._storage = storage;
    return client;
}

async function setupPair(roomId = 100, opts = {}) {
    const server = makeFakeServer();
    server.addParticipant(roomId, 1, 11);
    server.addParticipant(roomId, 2, 22);
    const alice = makeUser(server, 1, opts);
    const bob = makeUser(server, 2, opts);
    await alice.init();
    await bob.init();
    return { server, alice, bob, roomId, parts: [{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }] };
}

// Alice раздаёт свой ключ, Bob его забирает.
async function connectPair(ctx) {
    await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
    const r = await ctx.bob.syncKeyShares(22, ctx.roomId);
    assert.strictEqual(r.applied, 1, 'Bob должен применить key-share Alice');
    return r;
}

function randomBytes(n) {
    return new Uint8Array(nodeCrypto.randomBytes(n));
}

function containsJwk(value, seen = new Set()) {
    if (!value || typeof value !== 'object' || seen.has(value)) return false;
    seen.add(value);
    if (typeof value.kty === 'string') return true;
    return Object.values(value).some(v => containsJwk(v, seen));
}

async function hmac(keyBytes, byte) {
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', key, new Uint8Array([byte])));
}

async function hkdf32(ikm, info) {
    const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(info) }, key, 256));
}

// Генерация ключей так, как это делала прежняя версия (извлекаемые JWK).
async function legacyGen(alg, usages) {
    const kp = await subtle.generateKey({ name: alg }, true, usages);
    return {
        pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)),
        privJwk: await subtle.exportKey('jwk', kp.privateKey),
    };
}

async function toSigningKey(value) {
    return value && value.kty ? subtle.importKey('jwk', value, { name: 'Ed25519' }, false, ['sign']) : value;
}

// v1-конверт ровно так, как его собирал прежний encryptOutgoing: AAD
// 'senderkey:…', HKDF-info 'nyxo-e2ee-msgkey-v1', подпись над
// iv ‖ ct ‖ Uint32Array([iteration]) в порядке байт платформы.
async function legacyEncryptV1(storage, roomId, userId, plaintext) {
    const name = 'senderKey:' + roomId + ':' + userId;
    const state = await storage.get(name);
    const iteration = state.nextIteration;
    const chainKey = unb64(state.chainKey);
    const messageKey = await hmac(chainKey, 0x01);
    state.cachedKeys[iteration] = b64(messageKey);
    state.chainKey = b64(await hmac(chainKey, 0x02));
    state.nextIteration = iteration + 1;
    await storage.set(name, state);

    const aesRaw = await hkdf32(messageKey, 'nyxo-e2ee-msgkey-v1');
    const aesKey = await subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = randomBytes(12);
    const aad = new TextEncoder().encode('senderkey:' + roomId + ':' + userId + ':' + state.senderKeyId);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aesKey, new TextEncoder().encode(plaintext)));
    const sigInput = new Uint8Array(iv.length + ct.length + 4);
    sigInput.set(iv, 0);
    sigInput.set(ct, iv.length);
    sigInput.set(new Uint8Array(new Uint32Array([iteration]).buffer), iv.length + ct.length);
    const sig = new Uint8Array(await subtle.sign('Ed25519', await toSigningKey(state.signingPrivateKey), sigInput));
    return JSON.stringify({ v: 1, alg: 'senderkey-v1', senderKeyId: state.senderKeyId, iteration, iv: b64(iv), ct: b64(ct), sig: b64(sig) });
}

// Хранилище, каким его оставляла прежняя версия (до v2): JWK-ключи,
// флаг 'uploaded', статичные попарные секреты. Ключи зарегистрированы на
// сервере так же, как это делал старый init().
async function makeLegacyStorage(server, userId) {
    const storage = new E2EE.MemoryStorage();
    const transport = server.transportFor(userId);
    const dhKp = await legacyGen('X25519', ['deriveBits']);
    const signKp = await legacyGen('Ed25519', ['sign', 'verify']);
    await storage.set('identity', { dhPub: b64(dhKp.pub), dhPriv: dhKp.privJwk, signPub: b64(signKp.pub), signPriv: signKp.privJwk });

    const spkKp = await legacyGen('X25519', ['deriveBits']);
    const spkSig = new Uint8Array(await subtle.sign('Ed25519', await toSigningKey(signKp.privJwk), spkKp.pub));
    const spkId = 5000 + userId * 100;
    await storage.set('spk', { keyId: spkId, pub: b64(spkKp.pub), priv: spkKp.privJwk, sig: b64(spkSig) });

    const opks = [];
    for (let i = 1; i <= 12; i++) {
        const kp = await legacyGen('X25519', ['deriveBits']);
        await storage.set('opk:' + (spkId + i), { pub: b64(kp.pub), priv: kp.privJwk });
        opks.push({ key_id: spkId + i, public_key: b64(kp.pub) });
    }
    await storage.set('nextKeyId', spkId + 50);

    await transport.putIdentity({ identity_signing_key: b64(signKp.pub), identity_dh_key: b64(dhKp.pub) });
    await transport.putSignedPrekey({ key_id: spkId, public_key: b64(spkKp.pub), signature: b64(spkSig) });
    await transport.postOneTimePrekeys({ keys: opks });
    await storage.set('uploaded', true);
    return { storage, identityPub: b64(dhKp.pub), spkId };
}

async function getStored(client, name) {
    return client._storage.get(name);
}

async function main() {
    console.log('E2EE protocol tests');
    console.log(mlkem
        ? '(основной набор — public/mlkem.js; WebCrypto ML-KEM — в тестах совместимости)\n'
        : '(public/mlkem.js недоступен — основной набор на WebCrypto-адаптере)\n');

    // ===================== Базовое =====================

    await test('base64 round-trip (binary edge cases)', async () => {
        for (const len of [0, 1, 2, 3, 4, 5, 16, 31, 32, 33, 64]) {
            const bytes = globalThis.crypto.getRandomValues(new Uint8Array(len));
            const decoded = unb64(b64(bytes));
            assert.strictEqual(decoded.length, bytes.length, 'length len=' + len);
            assert.deepStrictEqual(Array.from(decoded), Array.from(bytes), 'content len=' + len);
        }
    });

    await test('init() is idempotent and uploads identity, SPK and signed PQ-prekey once', async () => {
        const server = makeFakeServer();
        const alice = makeUser(server, 1);
        const r1 = await alice.init();
        const spkId = server._signedPrekeys.get(1).key_id;
        const pq = server._pqPrekeys.get(1);
        const r2 = await alice.init();
        assert.strictEqual(r1.identityPub, r2.identityPub, 'identity key stable across init() calls');
        assert.strictEqual(server._signedPrekeys.get(1).key_id, spkId, 'SPK не пересоздаётся без ротации');
        assert.ok(pq, 'PQ-prekey загружен');
        assert.strictEqual(unb64(pq.public_key).length, 1184);
        const signKey = await subtle.importKey('raw', unb64(r1.signPub), { name: 'Ed25519' }, false, ['verify']);
        assert.ok(await subtle.verify('Ed25519', signKey, unb64(pq.signature), unb64(pq.public_key)), 'PQ-prekey подписан identity signing key');
        assert.strictEqual(server._pqPrekeys.get(1).key_id, pq.key_id);
    });

    await test('init() tops up one-time prekeys above the low-water mark', async () => {
        const server = makeFakeServer();
        const alice = makeUser(server, 1);
        await alice.init();
        const countRes = await server.transportFor(1).getOneTimePrekeyCount();
        assert.ok(countRes.data.count >= 10, 'should have topped up OPK pool, got ' + countRes.data.count);
    });

    await test('basic round trip v2: Alice sends, Bob decrypts', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, 'привет');
        const env = JSON.parse(ct);
        assert.strictEqual(env.v, 2);
        assert.strictEqual(env.alg, 'senderkey-v2');
        const res = await ctx.bob.decryptIncoming(ctx.roomId, 1, ct, 1);
        assert.deepStrictEqual(res, { ok: true, text: 'привет' });
    });

    await test('ciphertext does not leak plaintext or contain it verbatim', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const secret = 'the-quick-brown-fox-SECRET-42';
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, secret);
        assert.ok(!ct.includes(secret), 'ciphertext must not contain plaintext substring');
    });

    await test('sequential messages ratchet forward (different ciphertext, different keys)', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const ct1 = await ctx.alice.encryptOutgoing(ctx.roomId, 'msg1');
        const ct2 = await ctx.alice.encryptOutgoing(ctx.roomId, 'msg1');
        assert.notStrictEqual(ct1, ct2, 'same plaintext at different iterations must produce different ciphertext');
        assert.strictEqual(JSON.parse(ct1).iteration, 0);
        assert.strictEqual(JSON.parse(ct2).iteration, 1);
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct1, 1)).text, 'msg1');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct2, 2)).text, 'msg1');
    });

    await test('out-of-order delivery: message N+1 arrives before N, both still decrypt', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const ct0 = await ctx.alice.encryptOutgoing(ctx.roomId, 'zero');
        const ct1 = await ctx.alice.encryptOutgoing(ctx.roomId, 'one');
        const ct2 = await ctx.alice.encryptOutgoing(ctx.roomId, 'two');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct2, 3)).text, 'two');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct0, 1)).text, 'zero');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct1, 2)).text, 'one');
    });

    await test('history redisplay: same message (same messageId) can be decrypted twice', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, 'reread me');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct, 7)).text, 'reread me');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct, 7)).text, 'reread me');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct)).text, 'reread me', 'без messageId проверка повтора не применяется');
    });

    await test('sender can decrypt their own past outgoing messages (self chain is cached)', async () => {
        const ctx = await setupPair();
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, 'note to self');
        assert.deepStrictEqual(await ctx.alice.decryptIncoming(ctx.roomId, 1, ct, 1), { ok: true, text: 'note to self' });
    });

    await test('tampered ciphertext is rejected (bit flip in ct)', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const env = JSON.parse(await ctx.alice.encryptOutgoing(ctx.roomId, 'integrity check'));
        const bytes = unb64(env.ct);
        bytes[0] ^= 0xff;
        env.ct = b64(bytes);
        const res = await ctx.bob.decryptIncoming(ctx.roomId, 1, JSON.stringify(env), 1);
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.reason, 'bad-signature', 'подпись покрывает шифротекст');
    });

    await test('forged signature is rejected; tampered iteration/senderKeyId break the signature', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const original = JSON.parse(await ctx.alice.encryptOutgoing(ctx.roomId, 'trust me'));
        const forged = Object.assign({}, original, { sig: b64(randomBytes(64)) });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ctx.roomId, 1, JSON.stringify(forged), 1), { ok: false, reason: 'bad-signature' });
        const moved = Object.assign({}, original, { iteration: original.iteration + 1 });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ctx.roomId, 1, JSON.stringify(moved), 1), { ok: false, reason: 'bad-signature' });
        const ok = await ctx.bob.decryptIncoming(ctx.roomId, 1, JSON.stringify(original), 1);
        assert.strictEqual(ok.text, 'trust me');
    });

    await test('message from a sender with no known Sender Key fails gracefully', async () => {
        const { bob, roomId } = await setupPair();
        const fake = JSON.stringify({ v: 2, alg: 'senderkey-v2', senderKeyId: b64(randomBytes(16)), iteration: 0, iv: b64(randomBytes(12)), ct: b64(randomBytes(272)), sig: b64(randomBytes(64)) });
        assert.deepStrictEqual(await bob.decryptIncoming(roomId, 999, fake, 1), { ok: false, reason: 'no-sender-key' });
        assert.deepStrictEqual(await bob.decryptIncoming(roomId, 999, 'not json', 1), { ok: false, reason: 'bad-envelope' });
    });

    await test('key rotation: old messages stay decryptable for both sender and receiver after rotation', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const ctOld = await ctx.alice.encryptOutgoing(ctx.roomId, 'before rotation');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ctOld, 1)).text, 'before rotation');

        await ctx.alice.rotateRoomKey(ctx.roomId);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        await ctx.bob.syncKeyShares(22, ctx.roomId);

        const ctNew = await ctx.alice.encryptOutgoing(ctx.roomId, 'after rotation');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ctNew, 2)).text, 'after rotation');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ctOld, 1)).text, 'before rotation');
        assert.strictEqual((await ctx.alice.decryptIncoming(ctx.roomId, 1, ctOld, 1)).text, 'before rotation');
    });

    await test('bidirectional: Bob replies and Alice decrypts (independent pairwise sessions both directions)', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        await ctx.bob.ensureRoomSession(22, ctx.roomId, ctx.parts);
        await ctx.alice.syncKeyShares(11, ctx.roomId);
        const aliceToBob = await ctx.alice.encryptOutgoing(ctx.roomId, 'hi bob');
        const bobToAlice = await ctx.bob.encryptOutgoing(ctx.roomId, 'hi alice');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, aliceToBob, 1)).text, 'hi bob');
        assert.strictEqual((await ctx.alice.decryptIncoming(ctx.roomId, 2, bobToAlice, 2)).text, 'hi alice');
    });

    await test('re-run is idempotent: does not resend an already-delivered share', async () => {
        const { server, alice, roomId, parts } = await setupPair();
        await alice.ensureRoomSession(11, roomId, parts);
        assert.strictEqual(server._keyShares.length, 1, 'one share sent to Bob');
        await alice.ensureRoomSession(11, roomId, parts);
        assert.strictEqual(server._keyShares.length, 1, 'no duplicate share for a key already marked as shared');
    });

    await test('rotating the Sender Key reuses the pairwise session (no new one-time prekey consumed)', async () => {
        const ctx = await setupPair();
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const countAfterFirst = (await ctx.server.transportFor(2).getOneTimePrekeyCount()).data.count;
        await ctx.alice.rotateRoomKey(ctx.roomId);
        const r2 = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.strictEqual(r2.warnings.length, 0);
        const countAfterSecond = (await ctx.server.transportFor(2).getOneTimePrekeyCount()).data.count;
        assert.strictEqual(countAfterFirst, countAfterSecond, 'reusing the pairwise session must not touch the OPK pool again');
        await ctx.bob.syncKeyShares(22, ctx.roomId);
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, 'after rotation, reused pairwise channel');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct, 1)).text, 'after rotation, reused pairwise channel');
    });

    await test('group of 3: all pairwise sessions established, all can decrypt one sender', async () => {
        const server = makeFakeServer();
        server.addParticipant(200, 1, 11);
        server.addParticipant(200, 2, 22);
        server.addParticipant(200, 3, 33);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        const carol = makeUser(server, 3);
        await Promise.all([alice.init(), bob.init(), carol.init()]);
        const r = await alice.ensureRoomSession(11, 200, [{ id: 1 }, { id: 2 }, { id: 3 }]);
        assert.strictEqual(r.warnings.length, 0);
        await bob.syncKeyShares(22, 200);
        await carol.syncKeyShares(33, 200);
        const ct = await alice.encryptOutgoing(200, 'group hello');
        assert.strictEqual((await bob.decryptIncoming(200, 1, ct, 1)).text, 'group hello');
        assert.strictEqual((await carol.decryptIncoming(200, 1, ct, 1)).text, 'group hello');
    });

    await test('participant with no E2EE keys yet is skipped with a warning, others still succeed', async () => {
        const server = makeFakeServer();
        server.addParticipant(300, 1, 11);
        server.addParticipant(300, 2, 22);
        server.addParticipant(300, 3, 33);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        await alice.init();
        await bob.init();
        const r = await alice.ensureRoomSession(11, 300, [{ id: 1 }, { id: 2 }, { id: 3 }]);
        assert.strictEqual(r.warnings.length, 1);
        assert.strictEqual(r.warnings[0].userId, 3);
        assert.strictEqual(r.warnings[0].reason, 'у собеседника ещё не настроен E2EE');
        await bob.syncKeyShares(22, 300);
        const ct = await alice.encryptOutgoing(300, 'partial group');
        assert.strictEqual((await bob.decryptIncoming(300, 1, ct, 1)).text, 'partial group');
    });

    await test('no bundle request for a peer without identity on the server (saves the per-pair bundle quota); sent once keys appear', async () => {
        const server = makeFakeServer();
        server.addParticipant(310, 1, 11);
        server.addParticipant(310, 3, 33);
        const bundleCalls = [];
        const base = server.transportFor(1);
        const transport = Object.assign({}, base, {
            getBundle(target) { bundleCalls.push(Number(target)); return base.getBundle(target); },
        });
        const alice = makeUser(server, 1, { transport });
        await alice.init();
        const parts = [{ id: 1 }, { id: 3 }];
        for (let i = 0; i < 7; i++) {
            const r = await alice.ensureRoomSession(11, 310, parts);
            assert.strictEqual(r.warnings[0].reason, 'у собеседника ещё не настроен E2EE');
        }
        assert.deepStrictEqual(bundleCalls, [], 'bundle не запрашивается, пока у собеседника нет identity');
        // Собеседник настроил E2EE — ключ уходит при следующем открытии комнаты.
        const carol = makeUser(server, 3);
        await carol.init();
        const r = await alice.ensureRoomSession(11, 310, parts);
        assert.strictEqual(r.warnings.length, 0, JSON.stringify(r.warnings));
        assert.deepStrictEqual(bundleCalls, [3]);
        assert.strictEqual((await carol.syncKeyShares(33, 310)).applied, 1);
        const ct = await alice.encryptOutgoing(310, 'после настройки ключей');
        assert.strictEqual((await carol.decryptIncoming(310, 1, ct, 5)).text, 'после настройки ключей');
    });

    await test('rooms are isolated: a message encrypted for room A cannot be replayed into room B', async () => {
        const server = makeFakeServer();
        server.addParticipant(400, 1, 11);
        server.addParticipant(400, 2, 22);
        server.addParticipant(500, 1, 13);
        server.addParticipant(500, 2, 23);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        await alice.init();
        await bob.init();
        await alice.ensureRoomSession(11, 400, [{ id: 1 }, { id: 2 }]);
        await alice.ensureRoomSession(13, 500, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, 400);
        await bob.syncKeyShares(23, 500);
        const ctForRoomA = await alice.encryptOutgoing(400, 'room A only');
        const replayed = await bob.decryptIncoming(500, 1, ctForRoomA, 1);
        assert.strictEqual(replayed.ok, false, 'AAD must bind ciphertext to its room; cross-room replay must fail');
    });

    // ===================== Совместимость с историей =====================

    await test('legacy v1 envelope (old format, assembled by hand) still decrypts as text', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const v1 = await legacyEncryptV1(ctx.alice._storage, ctx.roomId, 1, 'старое сообщение');
        assert.strictEqual(JSON.parse(v1).alg, 'senderkey-v1');
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ctx.roomId, 1, v1, 1), { ok: true, text: 'старое сообщение' });
        assert.deepStrictEqual(await ctx.alice.decryptIncoming(ctx.roomId, 1, v1, 1), { ok: true, text: 'старое сообщение' });
        // v1 и v2 живут на одной цепочке: следующий v2 идёт со следующей итерации.
        const v2 = await ctx.alice.encryptOutgoing(ctx.roomId, 'новое');
        assert.strictEqual(JSON.parse(v2).iteration, 1);
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, v2, 2)).text, 'новое');
    });

    await test('legacy storage migration: JWK keys become non-extractable, old history still reads', async () => {
        const server = makeFakeServer();
        const roomId = 700;
        server.addParticipant(roomId, 1, 11);
        server.addParticipant(roomId, 2, 22);
        const legacyA = await makeLegacyStorage(server, 1);
        const legacyB = await makeLegacyStorage(server, 2);

        // Sender Key Alice, уже разосланный Бобу прежней версией.
        const signKp = await legacyGen('Ed25519', ['sign', 'verify']);
        const own = {
            senderKeyId: b64(randomBytes(16)), signingPublicKey: b64(signKp.pub), signingPrivateKey: signKp.privJwk,
            chainKey: b64(randomBytes(32)), nextIteration: 0, cachedKeys: {}, archived: [],
        };
        await legacyA.storage.set('senderKey:' + roomId + ':1', own);
        await legacyB.storage.set('senderKey:' + roomId + ':1', {
            senderKeyId: own.senderKeyId, signingPublicKey: own.signingPublicKey, chainKey: own.chainKey,
            nextIteration: 0, cachedKeys: {}, archived: [],
        });
        await legacyA.storage.set('pairwiseSend:2', { sk: b64(randomBytes(32)) });
        await legacyA.storage.set('sharedWith:' + roomId + ':' + own.senderKeyId + ':2', true);
        await legacyB.storage.set('pairwiseRecv:1', { sk: b64(randomBytes(32)) });

        const history1 = await legacyEncryptV1(legacyA.storage, roomId, 1, 'история 1');
        const history2 = await legacyEncryptV1(legacyA.storage, roomId, 1, 'история 2');

        const alice = makeUser(server, 1, { storage: legacyA.storage });
        const bob = makeUser(server, 2, { storage: legacyB.storage });
        assert.strictEqual((await alice.init()).identityPub, legacyA.identityPub, 'identity сохранён');
        assert.strictEqual((await bob.init()).identityPub, legacyB.identityPub);

        for (const client of [alice, bob]) {
            const values = Array.from(client._storage.map.values());
            assert.ok(!values.some(v => containsJwk(v)), 'в хранилище не осталось JWK');
            const identity = await getStored(client, 'identity');
            for (const key of [identity.dhPriv, identity.signPriv]) {
                assert.strictEqual(key.extractable, false);
                await assert.rejects(subtle.exportKey('jwk', key));
            }
            const opkNames = await client._storage.keys('opk:');
            assert.ok(opkNames.length > 0);
            assert.strictEqual((await getStored(client, opkNames[0])).priv.extractable, false);
            for (const prefix of ['pairwiseSend:', 'pairwiseRecv:', 'sharedWith:']) {
                assert.deepStrictEqual(await client._storage.keys(prefix), [], 'удалены ' + prefix);
            }
            assert.strictEqual(await getStored(client, 'uploaded'), null);
        }
        assert.strictEqual((await getStored(alice, 'senderKey:' + roomId + ':1')).signingPrivateKey.extractable, false);

        // SPK прежней версии без даты создания сразу ротирован, но хранится.
        assert.notStrictEqual(server._signedPrekeys.get(1).key_id, legacyA.spkId);
        assert.ok(await getStored(alice, 'spkOld:' + legacyA.spkId));
        assert.ok(server._pqPrekeys.get(1) && server._pqPrekeys.get(2), 'PQ-prekey загружены при миграции');

        assert.strictEqual((await bob.decryptIncoming(roomId, 1, history1, 1)).text, 'история 1');
        assert.strictEqual((await bob.decryptIncoming(roomId, 1, history2, 2)).text, 'история 2');
        assert.strictEqual((await alice.decryptIncoming(roomId, 1, history1, 1)).text, 'история 1');

        // Ключ переразослан по новому каналу; у Боба он уже был — просто подтверждение.
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        const synced = await bob.syncKeyShares(22, roomId);
        assert.strictEqual(synced.applied, 1);
        const fresh = await alice.encryptOutgoing(roomId, 'после миграции');
        assert.strictEqual((await bob.decryptIncoming(roomId, 1, fresh, 3)).text, 'после миграции');
        assert.strictEqual((await bob.decryptIncoming(roomId, 1, history1, 1)).text, 'история 1');
    });

    // ===================== Неизвлекаемые ключи =====================

    await test('private keys are non-extractable CryptoKeys (exportKey throws)', async () => {
        const ctx = await setupPair();
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const identity = await getStored(ctx.alice, 'identity');
        const spk = await getStored(ctx.alice, 'spk');
        const opk = await getStored(ctx.alice, (await ctx.alice._storage.keys('opk:'))[0]);
        const own = await getStored(ctx.alice, 'senderKey:' + ctx.roomId + ':1');
        for (const key of [identity.dhPriv, identity.signPriv, spk.priv, opk.priv, own.signingPrivateKey]) {
            assert.strictEqual(key.type, 'private');
            assert.strictEqual(key.extractable, false);
            await assert.rejects(subtle.exportKey('jwk', key));
            await assert.rejects(subtle.exportKey('pkcs8', key));
        }
        assert.ok(!Array.from(ctx.alice._storage.map.values()).some(v => containsJwk(v)));
    });

    // ===================== PQXDH =====================

    await test('PQXDH: x3dh-init carries pqCiphertext + identity keys; key-share envelope fits server limits', async () => {
        const ctx = await setupPair();
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const share = ctx.server._keyShares[0];
        const env = JSON.parse(share.ciphertext);
        assert.strictEqual(env.v, 2);
        assert.strictEqual(env.init.type, 'x3dh-init');
        assert.strictEqual(unb64(env.init.pqCiphertext).length, 1088);
        assert.strictEqual(env.init.usedPqPrekeyId, ctx.server._pqPrekeys.get(2).key_id);
        const aliceIdentity = await getStored(ctx.alice, 'identity');
        assert.strictEqual(env.init.senderIdentitySignPub, aliceIdentity.signPub);
        assert.strictEqual(env.init.senderIdentityDhPub, aliceIdentity.dhPub);
        assert.ok(env.init.usedOneTimePrekeyId !== null, 'самый крупный вариант — с OPK');
        // Сервер: ≤ 8192 символа на share; держим запас минимум вдвое.
        assert.ok(share.ciphertext.length <= 4096, 'key-share слишком большой: ' + share.ciphertext.length);
        assert.ok(share.ciphertext.length <= E2EE._internal.MAX_SHARE_CHARS);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
    });

    await test('PQXDH: the ML-KEM shared secret is part of the key (wrong decapsulation → share rejected)', async () => {
        const server = makeFakeServer();
        server.addParticipant(100, 1, 11);
        server.addParticipant(100, 2, 22);
        const brokenKem = {
            keygen: (seed) => primaryKem.keygen(seed),
            encapsulate: (pk) => primaryKem.encapsulate(pk),
            decapsulate: async () => randomBytes(32),
        };
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2, { kem: brokenKem });
        await alice.init();
        await bob.init();
        await alice.ensureRoomSession(11, 100, [{ id: 1 }, { id: 2 }]);
        const r = await bob.syncKeyShares(22, 100);
        assert.strictEqual(r.applied, 0);
        assert.strictEqual(r.failed, 1);
    });

    await test('PQXDH: header without pqCiphertext or with a tampered one is rejected by the recipient', async () => {
        const ctx = await setupPair();
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const original = ctx.server._keyShares.splice(0, 1)[0];

        const stripped = JSON.parse(original.ciphertext);
        delete stripped.init.pqCiphertext;
        delete stripped.init.usedPqPrekeyId;
        ctx.server.evil.injectKeyShare({ roomId: ctx.roomId, senderId: 1, recipientId: 2, ciphertext: JSON.stringify(stripped) });
        const tampered = JSON.parse(original.ciphertext);
        const pqct = unb64(tampered.init.pqCiphertext);
        pqct[10] ^= 0x01;
        tampered.init.pqCiphertext = b64(pqct);
        ctx.server.evil.injectKeyShare({ roomId: ctx.roomId, senderId: 1, recipientId: 2, ciphertext: JSON.stringify(tampered) });
        const r1 = await ctx.bob.syncKeyShares(22, ctx.roomId);
        assert.strictEqual(r1.applied, 0);
        assert.strictEqual(r1.failed, 2);

        // Неудачные попытки ничего не испортили: настоящий share проходит (OPK не сожжён).
        ctx.server.evil.injectKeyShare({ roomId: ctx.roomId, senderId: 1, recipientId: 2, ciphertext: original.ciphertext });
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
    });

    await test('PQXDH: no pq_prekey in bundle → peer "not ready", no fallback to classic X3DH', async () => {
        const ctx = await setupPair();
        ctx.server.evil.hidePqPrekey(2);
        const r = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.deepStrictEqual(r.warnings, [{ userId: 2, reason: 'у собеседника устаревшая версия E2EE' }]);
        assert.strictEqual(ctx.server._keyShares.length, 0, 'ключ не отправлен без PQ-части');
    });

    await test('PQXDH: forged PQ-prekey signature in bundle is refused', async () => {
        const ctx = await setupPair();
        const t = ctx.server.transportFor(1);
        const realGetBundle = t.getBundle;
        t.getBundle = async (id) => {
            const res = await realGetBundle(id);
            if (res.status === 200 && res.data.pq_prekey) {
                res.data.pq_prekey = Object.assign({}, res.data.pq_prekey, { signature: b64(randomBytes(64)) });
            }
            return res;
        };
        const alice = makeUser(ctx.server, 1, { transport: t });
        await alice.init();
        const r = await alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.strictEqual(r.warnings.length, 1);
        assert.ok(/PQ-prekey/.test(r.warnings[0].reason), r.warnings[0].reason);
        assert.strictEqual(ctx.server._keyShares.length, 0);
    });

    await test('PQXDH interop: public/mlkem.js ↔ Node WebCrypto ML-KEM-768, both directions', async () => {
        if (!mlkem) {
            console.log('        (пропущено: public/mlkem.js недоступен)');
            return;
        }
        const parts = [{ id: 1 }, { id: 2 }];
        const server = makeFakeServer();
        server.addParticipant(100, 1, 11);
        server.addParticipant(100, 2, 22);
        const alice = makeUser(server, 1, { kem: mlkem });
        const bob = makeUser(server, 2, { kem: webKem });
        await alice.init();
        await bob.init();
        await alice.ensureRoomSession(11, 100, parts);
        await bob.ensureRoomSession(22, 100, parts);
        assert.strictEqual((await bob.syncKeyShares(22, 100)).applied, 1, 'mlkem.js encapsulate → WebCrypto decapsulate');
        assert.strictEqual((await alice.syncKeyShares(11, 100)).applied, 1, 'WebCrypto encapsulate → mlkem.js decapsulate');
        const a = await alice.encryptOutgoing(100, 'от mlkem.js');
        const b = await bob.encryptOutgoing(100, 'от WebCrypto');
        assert.strictEqual((await bob.decryptIncoming(100, 1, a, 1)).text, 'от mlkem.js');
        assert.strictEqual((await alice.decryptIncoming(100, 2, b, 2)).text, 'от WebCrypto');
    });

    // ===================== Identity и коды безопасности =====================

    await test('safety number: same 60 digits on both sides, stable, and different for a different pair', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        await ctx.alice.checkPeerIdentities([2]);
        const fromAlice = await ctx.alice.getSafetyNumber(2);
        const fromBob = await ctx.bob.getSafetyNumber(1);
        assert.ok(/^(\d{5} ){11}\d{5}$/.test(fromAlice), 'формат: 12 групп по 5 цифр — ' + fromAlice);
        assert.strictEqual(fromAlice, fromBob, 'у обеих сторон один и тот же код');
        assert.strictEqual(await ctx.alice.getSafetyNumber(2), fromAlice, 'детерминирован');
        assert.strictEqual(await ctx.alice.getSafetyNumber(3), null, 'нет закреплённого ключа — нет кода');
        assert.strictEqual(await ctx.alice.getSafetyNumber(1), null, 'для себя код не считается');
    });

    await test('identity statuses: unknown → unverified (TOFU) → verified; markPeerVerified', async () => {
        const ctx = await setupPair();
        assert.strictEqual(await ctx.alice.getPeerIdentityStatus(2), 'unknown');
        const res = await ctx.alice.checkPeerIdentities([2, 3, 1]);
        assert.deepStrictEqual(res, [{ userId: 2, status: 'unverified' }, { userId: 3, status: 'unknown' }]);
        assert.strictEqual(await ctx.alice.markPeerVerified(2), true);
        assert.strictEqual(await ctx.alice.getPeerIdentityStatus(2), 'verified');
        assert.deepStrictEqual(await ctx.alice.checkPeerIdentities([2]), [{ userId: 2, status: 'verified' }]);
    });

    await test('identity change: status changed, no key-share to/from the new key until accepted, then works', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        await ctx.bob.ensureRoomSession(22, ctx.roomId, ctx.parts);
        await ctx.alice.syncKeyShares(11, ctx.roomId);
        await ctx.alice.markPeerVerified(2);
        const numberBefore = await ctx.alice.getSafetyNumber(2);

        // Боб переустановил клиент: новый identity на сервере.
        const bob2 = makeUser(ctx.server, 2);
        await bob2.init();
        assert.deepStrictEqual(await ctx.alice.checkPeerIdentities([2]), [{ userId: 2, status: 'changed' }]);
        assert.strictEqual(await ctx.alice.markPeerVerified(2), false, 'сменившийся ключ нельзя отметить проверенным');

        // Alice ротирует ключ — новому identity он не уходит.
        await ctx.alice.rotateRoomKey(ctx.roomId);
        const r = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.deepStrictEqual(r.identityChanges, [{ userId: 2, username: 'bob' }]);
        assert.ok(r.warnings.some(w => w.userId === 2));
        assert.strictEqual(ctx.server._keyShares.length, 0, 'key-share собеседнику со сменившимся identity не отправлен');

        // x3dh-init от нового identity откладывается, а не применяется.
        await bob2.ensureRoomSession(22, ctx.roomId, ctx.parts);
        const synced = await ctx.alice.syncKeyShares(11, ctx.roomId);
        assert.deepStrictEqual(synced, { applied: 0, failed: 0, identityChanges: [2] });
        const fromBob2 = await bob2.encryptOutgoing(ctx.roomId, 'я с нового устройства');
        assert.strictEqual((await ctx.alice.decryptIncoming(ctx.roomId, 2, fromBob2, 50)).ok, false);

        // Подтверждение: отложенный share применяется, ключ закрепляется заново.
        assert.strictEqual(await ctx.alice.acceptPeerIdentityChange(2), true);
        assert.strictEqual(await ctx.alice.getPeerIdentityStatus(2), 'unverified');
        assert.strictEqual((await ctx.alice.decryptIncoming(ctx.roomId, 2, fromBob2, 50)).text, 'я с нового устройства');
        const numberAfter = await ctx.alice.getSafetyNumber(2);
        assert.notStrictEqual(numberAfter, numberBefore, 'код безопасности сменился вместе с ключом');
        assert.strictEqual(numberAfter, await bob2.getSafetyNumber(1));

        // Свой ключ Alice теперь отправляет новому Бобу.
        const r2 = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.deepStrictEqual(r2.identityChanges, []);
        assert.strictEqual((await bob2.syncKeyShares(22, ctx.roomId)).applied, 1);
        const toBob2 = await ctx.alice.encryptOutgoing(ctx.roomId, 'добро пожаловать обратно');
        assert.strictEqual((await bob2.decryptIncoming(ctx.roomId, 1, toBob2, 51)).text, 'добро пожаловать обратно');
        assert.strictEqual(await ctx.alice.acceptPeerIdentityChange(2), false, 'повторно принимать нечего');
    });

    await test('malicious server: forged x3dh-init under a foreign identity is rejected', async () => {
        const ctx = await setupPair();
        // Клиент атакующего выдаёт себя за Alice (userId 1) со своими ключами.
        const mallory = E2EE.createClient({
            userId: 1, storage: new E2EE.MemoryStorage(), transport: ctx.server.shadowTransportFor(1), kem: primaryKem,
        });
        await mallory.init();
        await mallory.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const r1 = await ctx.bob.syncKeyShares(22, ctx.roomId);
        assert.deepStrictEqual(r1, { applied: 0, failed: 1, identityChanges: [] }, 'без закрепления: сервер не подтверждает identity из заголовка');
        assert.strictEqual(await ctx.bob.getPeerIdentityStatus(1), 'unknown');

        await ctx.bob.checkPeerIdentities([1]);
        await mallory.rotateRoomKey(ctx.roomId);
        await mallory.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const r2 = await ctx.bob.syncKeyShares(22, ctx.roomId);
        assert.deepStrictEqual(r2, { applied: 0, failed: 1, identityChanges: [] }, 'с закреплением: чужой identity отвергнут');
        assert.strictEqual(await ctx.bob.getPeerIdentityStatus(1), 'unverified');
        const fake = await mallory.encryptOutgoing(ctx.roomId, 'я Alice, честно');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, fake, 1)).ok, false);
        await connectPair(ctx); // настоящий ключ Alice по-прежнему принимается
    });

    await test('malicious server: substituted bundle for a pinned peer → changed, key not sent', async () => {
        const ctx = await setupPair();
        ctx.server.addParticipant(999, 666, 6666);
        const attacker = makeUser(ctx.server, 666);
        await attacker.init();
        await ctx.alice.checkPeerIdentities([2]); // Боб уже закреплён
        ctx.server.evil.impersonate(2, 666);
        const r = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.deepStrictEqual(r.identityChanges, [{ userId: 2, username: 'bob' }]);
        assert.strictEqual(ctx.server._keyShares.length, 0);
        assert.strictEqual(await ctx.alice.getPeerIdentityStatus(2), 'changed');
        // Сервер "одумался" — закреплённому ключу доверяем снова.
        ctx.server.evil.stopImpersonating(2);
        assert.deepStrictEqual(await ctx.alice.checkPeerIdentities([2]), [{ userId: 2, status: 'unverified' }]);
    });

    await test('malicious server: MITM on first contact is exposed by mismatching safety numbers', async () => {
        const ctx = await setupPair();
        ctx.server.addParticipant(999, 666, 6666);
        const attacker = makeUser(ctx.server, 666);
        await attacker.init();
        ctx.server.evil.impersonate(2, 666);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts); // TOFU закрепил ключ атакующего
        ctx.server.evil.stopImpersonating(2);
        await ctx.bob.checkPeerIdentities([1]);
        assert.notStrictEqual(await ctx.alice.getSafetyNumber(2), await ctx.bob.getSafetyNumber(1));
        // Настоящий Боб полученный share прочитать не может.
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 0);
    });

    // ===================== Повтор =====================

    await test('replay: same envelope under another messageId → "replay"; edit of the same message is fine', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const id1 = ctx.server.postMessage(ctx.roomId, 1, await ctx.alice.encryptOutgoing(ctx.roomId, 'оригинал'));
        const text1 = ctx.server.getMessage(id1).text;
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, text1, id1)).text, 'оригинал');

        const id2 = ctx.server.evil.replayMessage(id1);
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ctx.roomId, 1, ctx.server.getMessage(id2).text, id2), { ok: false, reason: 'replay' });
        assert.deepStrictEqual(await ctx.alice.decryptIncoming(ctx.roomId, 1, text1, id1), { ok: true, text: 'оригинал' });
        assert.deepStrictEqual(await ctx.alice.decryptIncoming(ctx.roomId, 1, text1, id2), { ok: false, reason: 'replay' });
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, text1, id1)).text, 'оригинал', 'повторный показ истории — не повтор');

        ctx.server.editMessage(id1, await ctx.alice.encryptOutgoing(ctx.roomId, 'исправлено'));
        const edited = ctx.server.getMessage(id1).text;
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, edited, id1)).text, 'исправлено');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, edited, id2)).reason, 'replay');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, edited, String(id1))).text, 'исправлено', 'messageId сравнивается как строка');
    });

    // ===================== Паддинг и лимиты =====================

    await test('padding: 1-char and 200-char messages give envelopes of the same length (Padmé, min 256)', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const short = await ctx.alice.encryptOutgoing(ctx.roomId, 'x');
        const long = await ctx.alice.encryptOutgoing(ctx.roomId, 'y'.repeat(200));
        assert.strictEqual(short.length, long.length);
        assert.strictEqual(unb64(JSON.parse(short).ct).length, 256 + 16);
        const longer = await ctx.alice.encryptOutgoing(ctx.roomId, 'z'.repeat(400));
        assert.ok(longer.length > long.length);
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, long, 2)).text, 'y'.repeat(200));
        const { padmeLength } = E2EE._internal;
        assert.strictEqual(padmeLength(8021), 8192);
        assert.strictEqual(padmeLength(5 * 1024 * 1024), 5 * 1024 * 1024);
        for (const len of [2, 3, 17, 1000, 4097, 70000, 1234567]) {
            const p = padmeLength(len);
            assert.ok(p >= len && p <= len * 1.125 + 1, 'Padmé overhead for ' + len + ' → ' + p);
        }
    });

    await test('encryptOutgoing refuses envelopes over the server limit (12000 chars)', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const maxRussian = await ctx.alice.encryptOutgoing(ctx.roomId, 'ж'.repeat(4000));
        assert.ok(maxRussian.length <= 12000, '4000 символов кириллицы укладываются: ' + maxRussian.length);
        await assert.rejects(ctx.alice.encryptOutgoing(ctx.roomId, 'ж'.repeat(6000)), /слишком длинное/);
        await assert.rejects(ctx.alice.encryptOutgoing(ctx.roomId, { type: 'file', mime: 'x' }), /описание файла/);
        await assert.rejects(ctx.alice.encryptOutgoing(ctx.roomId, 42), /неподдерживаемое/);
    });

    // ===================== Файлы =====================

    await test('files: AES-GCM with Padmé padding round-trips for 0, 1, 4095, 4096, 100 KB, 5 MB', async () => {
        const { alice, bob } = await setupPair();
        for (const size of [0, 1, 4095, 4096, 100 * 1024, 5 * 1024 * 1024]) {
            const data = randomBytes(size);
            const enc = await alice.encryptFile(data);
            assert.strictEqual(enc.size, size);
            assert.strictEqual(enc.ciphertext.length, E2EE._internal.filePaddedLength(size) + 16, 'size ' + size);
            assert.ok(enc.ciphertext.length >= 4096 + 16);
            const dec = await bob.decryptFile(enc.ciphertext, enc.key, enc.iv, enc.size);
            assert.ok(Buffer.from(dec).equals(Buffer.from(data)), 'content size ' + size);
        }
        const same = await alice.encryptFile(randomBytes(10));
        const other = await alice.encryptFile(randomBytes(3000));
        assert.strictEqual(same.ciphertext.length, other.ciphertext.length, 'мелкие файлы неотличимы по размеру');
    });

    await test('files: tampered ciphertext, wrong key or wrong size → error', async () => {
        const { alice } = await setupPair();
        const data = randomBytes(5000);
        data[4999] = 0xab;
        const enc = await alice.encryptFile(data);
        const tampered = enc.ciphertext.slice();
        tampered[100] ^= 0x01;
        await assert.rejects(alice.decryptFile(tampered, enc.key, enc.iv, enc.size), /повреждён или подменён/);
        await assert.rejects(alice.decryptFile(enc.ciphertext, b64(randomBytes(32)), enc.iv, enc.size), /повреждён или подменён/);
        await assert.rejects(alice.decryptFile(enc.ciphertext, enc.key, enc.iv, 9000), /размер/);
        // 4999 даёт ту же Padmé-длину, что и 5000, но последний байт данных не ноль.
        assert.strictEqual(E2EE._internal.filePaddedLength(4999), E2EE._internal.filePaddedLength(5000));
        await assert.rejects(alice.decryptFile(enc.ciphertext, enc.key, enc.iv, 4999), /паддинг/);
        await assert.rejects(alice.decryptFile(enc.ciphertext, 'short', enc.iv, enc.size), /ключ файла/);
        const ok = await alice.decryptFile(enc.ciphertext.buffer.slice(0), enc.key, enc.iv, enc.size);
        assert.ok(Buffer.from(ok).equals(Buffer.from(data)), 'ArrayBuffer тоже принимается');
    });

    await test('file message: descriptor travels inside the E2EE envelope', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const data = randomBytes(12345);
        const enc = await ctx.alice.encryptFile(data);
        const env = await ctx.alice.encryptOutgoing(ctx.roomId, {
            type: 'file', mime: 'image/png', name: 'photo.png', size: enc.size, key: enc.key, iv: enc.iv, caption: 'подпись',
        });
        assert.ok(!env.includes('photo.png') && !env.includes(enc.key));
        const res = await ctx.bob.decryptIncoming(ctx.roomId, 1, env, 9);
        assert.deepStrictEqual(res, {
            ok: true, text: 'подпись',
            file: { mime: 'image/png', name: 'photo.png', size: 12345, key: enc.key, iv: enc.iv },
        });
        const plain = await ctx.bob.decryptFile(enc.ciphertext, res.file.key, res.file.iv, res.file.size);
        assert.ok(Buffer.from(plain).equals(Buffer.from(data)));
        const noCaption = await ctx.alice.encryptOutgoing(ctx.roomId, { type: 'file', mime: 'a/b', name: '', size: 1, key: enc.key, iv: enc.iv });
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, noCaption, 10)).text, '');
    });

    // ===================== Состав комнаты =====================

    await test('membership: first call is a baseline; a new (e.g. ghost) member shows up in newMembers', async () => {
        const ctx = await setupPair();
        const first = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.server.participantsOf(ctx.roomId));
        assert.deepStrictEqual(first.newMembers, []);
        assert.deepStrictEqual(first.removedMembers, []);
        assert.strictEqual(first.rotated, false);
        const before = await ctx.alice.encryptOutgoing(ctx.roomId, 'до ghost');

        // Сервер молча добавляет "призрачного" участника со своими ключами.
        const ghost = makeUser(ctx.server, 3);
        ctx.server.evil.addGhost(ctx.roomId, 3, 33);
        await ghost.init();
        const second = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.server.participantsOf(ctx.roomId));
        assert.deepStrictEqual(second.newMembers, [{ id: 3, username: 'user3' }], 'новый участник виден клиенту');
        assert.strictEqual(second.rotated, false);
        const third = await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.server.participantsOf(ctx.roomId));
        assert.deepStrictEqual(third.newMembers, [], 'сообщается один раз');
        // Новичок получает ключ с текущей позиции цепочки — сообщения до его
        // появления ему недоступны; последующие — доступны, поэтому клиент и
        // обязан показать пользователю, что в комнате кто-то появился.
        await ghost.syncKeyShares(33, ctx.roomId);
        assert.strictEqual((await ghost.decryptIncoming(ctx.roomId, 1, before, 1)).ok, false);
        const after = await ctx.alice.encryptOutgoing(ctx.roomId, 'после ghost');
        assert.strictEqual((await ghost.decryptIncoming(ctx.roomId, 1, after, 2)).text, 'после ghost');
    });

    await test('membership: a removed member triggers rotation; they cannot read new messages, others can', async () => {
        const server = makeFakeServer();
        const roomId = 250;
        server.addParticipant(roomId, 1, 11);
        server.addParticipant(roomId, 2, 22);
        server.addParticipant(roomId, 3, 33);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        const carol = makeUser(server, 3);
        await Promise.all([alice.init(), bob.init(), carol.init()]);
        await alice.ensureRoomSession(11, roomId, server.participantsOf(roomId));
        await bob.syncKeyShares(22, roomId);
        await carol.syncKeyShares(33, roomId);
        const early = await alice.encryptOutgoing(roomId, 'все трое');
        assert.strictEqual((await carol.decryptIncoming(roomId, 1, early, 1)).text, 'все трое');

        server.removeParticipant(roomId, 3);
        const r = await alice.ensureRoomSession(11, roomId, server.participantsOf(roomId));
        assert.strictEqual(r.rotated, true);
        assert.deepStrictEqual(r.removedMembers, [{ id: 3, username: 'user3' }]);
        assert.deepStrictEqual(r.newMembers, []);
        assert.ok(server._keyShares.every(s => s.recipientId !== 3), 'новый ключ ушедшему не отправлен');
        assert.strictEqual(server._keyShares.length, 1);

        await bob.syncKeyShares(22, roomId);
        const late = await alice.encryptOutgoing(roomId, 'без Кэрол');
        assert.strictEqual((await bob.decryptIncoming(roomId, 1, late, 2)).text, 'без Кэрол');
        const carolRes = await carol.decryptIncoming(roomId, 1, late, 2);
        assert.strictEqual(carolRes.ok, false);
        assert.strictEqual(carolRes.reason, 'stale-sender-key');
        // Боб не открывал это сообщение до автоматической ротации — оно всё
        // равно читается по сохранённой позиции архивной цепочки.
        assert.strictEqual((await bob.decryptIncoming(roomId, 1, early, 1)).text, 'все трое', 'история после ротации читается');
    });

    await test('key-shares are posted in batches of at most 50 recipients', async () => {
        const server = makeFakeServer();
        const roomId = 900;
        const count = 56;
        const clients = [];
        for (let id = 1; id <= count; id++) server.addParticipant(roomId, id, 9000 + id);
        for (let id = 2; id <= count; id++) {
            const c = makeUser(server, id);
            clients.push(c);
        }
        await Promise.all(clients.map(c => c.init()));
        const t = server.transportFor(1);
        const batches = [];
        const realPost = t.postKeyShares;
        t.postKeyShares = (chatId, shares) => { batches.push(shares.length); return realPost(chatId, shares); };
        const alice = makeUser(server, 1, { transport: t });
        await alice.init();
        const r = await alice.ensureRoomSession(9001, roomId, server.participantsOf(roomId));
        assert.strictEqual(r.ok, true);
        assert.deepStrictEqual(batches, [50, 5]);
        assert.strictEqual(server._keyShares.length, count - 1);
    });

    // ===================== Ротация prekey =====================

    await test('SPK/PQ-prekey rotation: x3dh-init to the old prekeys still works within 14 days', async () => {
        let t = Date.UTC(2026, 0, 1);
        const ctx = await setupPair(100, { now: () => t });
        const oldSpk = ctx.server._signedPrekeys.get(2).key_id;
        const oldPq = ctx.server._pqPrekeys.get(2).key_id;
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts); // собран по старым prekey

        t += 8 * DAY;
        await ctx.bob.init();
        assert.notStrictEqual(ctx.server._signedPrekeys.get(2).key_id, oldSpk, 'SPK ротирован');
        assert.notStrictEqual(ctx.server._pqPrekeys.get(2).key_id, oldPq, 'PQ-prekey ротирован');
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, 'через неделю');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct, 1)).text, 'через неделю');
    });

    await test('SPK/PQ-prekey rotation: after 14 days the old private keys are gone', async () => {
        let t = Date.UTC(2026, 0, 1);
        const ctx = await setupPair(100, { now: () => t });
        const oldSpk = ctx.server._signedPrekeys.get(2).key_id;
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        t += 8 * DAY;
        await ctx.bob.init();
        assert.ok(await getStored(ctx.bob, 'spkOld:' + oldSpk));
        t += 15 * DAY;
        await ctx.bob.init();
        assert.strictEqual(await getStored(ctx.bob, 'spkOld:' + oldSpk), null, 'старый SPK удалён');
        const r = await ctx.bob.syncKeyShares(22, ctx.roomId);
        assert.strictEqual(r.applied, 0);
        assert.strictEqual(r.failed, 1);
    });

    await test('pairwise session is re-established with a fresh PQXDH after 7 days', async () => {
        let t = Date.UTC(2026, 0, 1);
        const ctx = await setupPair(100, { now: () => t });
        await connectPair(ctx);
        const eph1 = (await getStored(ctx.alice, 'pw2Send:2')).header.senderEphemeralPub;
        t += 8 * DAY;
        await ctx.alice.rotateRoomKey(ctx.roomId);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const session = await getStored(ctx.alice, 'pw2Send:2');
        assert.notStrictEqual(session.header.senderEphemeralPub, eph1);
        assert.strictEqual(session.n, 1);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
    });

    // ===================== Прямая секретность канала key-share =====================

    await test('key-share channel forward secrecy: used chain keys are deleted, replays fail', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const recv0 = await getStored(ctx.bob, 'pw2Recv:1');
        assert.strictEqual(recv0.n, 1);
        assert.deepStrictEqual(recv0.skipped, {});
        const send0 = await getStored(ctx.alice, 'pw2Send:2');
        assert.strictEqual(send0.n, 1);

        // Повтор уже применённого key-share: ключ n=0 удалён — не расшифровать.
        ctx.server.evil.replayDeliveredKeyShare(0);
        assert.deepStrictEqual(await ctx.bob.syncKeyShares(22, ctx.roomId), { applied: 0, failed: 1, identityChanges: [] });

        // Две ротации → передачи n=1 и n=2; доставляем n=2 раньше n=1.
        await ctx.alice.rotateRoomKey(ctx.roomId);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        await ctx.alice.rotateRoomKey(ctx.roomId);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const [share1] = ctx.server._keyShares.splice(0, 1);
        assert.strictEqual(JSON.parse(share1.ciphertext).n, 1);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
        const recv2 = await getStored(ctx.bob, 'pw2Recv:1');
        assert.strictEqual(recv2.n, 3);
        assert.deepStrictEqual(Object.keys(recv2.skipped), ['1'], 'хранится только ключ ещё не пришедшей передачи');
        assert.notStrictEqual(recv2.ck, recv0.ck);
        const latestKeyId = (await getStored(ctx.alice, 'senderKey:' + ctx.roomId + ':1')).senderKeyId;

        ctx.server.evil.injectKeyShare(share1);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
        const recv3 = await getStored(ctx.bob, 'pw2Recv:1');
        assert.deepStrictEqual(recv3.skipped, {}, 'пропущенный ключ удалён после использования');
        assert.strictEqual((await getStored(ctx.bob, 'senderKey:' + ctx.roomId + ':1')).senderKeyId, latestKeyId, 'опоздавший старый ключ не заменил новый');
        const all = JSON.stringify(Array.from(ctx.bob._storage.map.values()).map(v => (v && typeof v === 'object' ? Object.assign({}, v, { priv: undefined, dhPriv: undefined, signPriv: undefined }) : v)));
        assert.ok(!all.includes(recv0.ck), 'использованный chainKey нигде не сохранён');
        const ct = await ctx.alice.encryptOutgoing(ctx.roomId, 'после перестановки');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, ct, 1)).text, 'после перестановки');
    });

    await test('tampered key-share (skdm ct flip) is rejected without burning state; next share recovers', async () => {
        const ctx = await setupPair();
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        const share = ctx.server._keyShares[0];
        const env = JSON.parse(share.ciphertext);
        const opkId = env.init.usedOneTimePrekeyId;
        const ct = unb64(env.ct);
        ct[3] ^= 0x80;
        env.ct = b64(ct);
        share.ciphertext = JSON.stringify(env);
        assert.deepStrictEqual(await ctx.bob.syncKeyShares(22, ctx.roomId), { applied: 0, failed: 1, identityChanges: [] });
        assert.ok(await getStored(ctx.bob, 'opk:' + opkId), 'OPK не сожжён поддельным share');
        assert.strictEqual(await getStored(ctx.bob, 'pw2Recv:1'), null);
        // Заголовок PQXDH повторяется в каждой передаче — следующая восстанавливает сессию.
        await ctx.alice.rotateRoomKey(ctx.roomId);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, ctx.roomId)).applied, 1);
        assert.strictEqual(await getStored(ctx.bob, 'opk:' + opkId), null, 'OPK израсходован настоящим share');
        const msg = await ctx.alice.encryptOutgoing(ctx.roomId, 'восстановлено');
        assert.strictEqual((await ctx.bob.decryptIncoming(ctx.roomId, 1, msg, 1)).text, 'восстановлено');
    });

    // ===================== MAX_SKIP =====================

    await test('MAX_SKIP: Sender Key iteration too far ahead is refused without deriving the chain', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const name = 'senderKey:' + ctx.roomId + ':1';
        const state = await getStored(ctx.alice, name);
        state.nextIteration += E2EE._internal.MAX_SKIP + 10;
        await ctx.alice._storage.set(name, state);
        const far = await ctx.alice.encryptOutgoing(ctx.roomId, 'далеко');
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ctx.roomId, 1, far, 1), { ok: false, reason: 'too-far-ahead' });
        assert.strictEqual((await getStored(ctx.bob, name)).nextIteration, 0, 'цепочка получателя не сдвинута');
    });

    await test('MAX_SKIP: pairwise counter too far ahead is refused', async () => {
        const ctx = await setupPair();
        await connectPair(ctx);
        const session = await getStored(ctx.alice, 'pw2Send:2');
        session.n += E2EE._internal.MAX_PW_SKIP + 5;
        await ctx.alice._storage.set('pw2Send:2', session);
        await ctx.alice.rotateRoomKey(ctx.roomId);
        await ctx.alice.ensureRoomSession(11, ctx.roomId, ctx.parts);
        assert.deepStrictEqual(await ctx.bob.syncKeyShares(22, ctx.roomId), { applied: 0, failed: 1, identityChanges: [] });
    });

    // ===================== deleteLocalData =====================

    await test('deleteLocalData deletes IndexedDB "nyxo-e2ee-<userId>" and handles onblocked', async () => {
        const deleted = [];
        try {
            globalThis.indexedDB = {
                deleteDatabase(name) {
                    deleted.push(name);
                    const req = {};
                    setTimeout(() => req.onsuccess(), 0);
                    return req;
                },
            };
            assert.strictEqual(await E2EE.deleteLocalData(42), true);
            assert.deepStrictEqual(deleted, ['nyxo-e2ee-42']);

            globalThis.indexedDB = {
                deleteDatabase() {
                    const req = {};
                    setTimeout(() => { req.onblocked(); setTimeout(() => req.onsuccess(), 5); }, 0);
                    return req;
                },
            };
            assert.strictEqual(await E2EE.deleteLocalData('7'), true, 'blocked, затем удалено');

            globalThis.indexedDB = {
                deleteDatabase() {
                    const req = { error: new Error('boom') };
                    setTimeout(() => req.onerror(), 0);
                    return req;
                },
            };
            await assert.rejects(E2EE.deleteLocalData(7), /boom/);
            await assert.rejects(E2EE.deleteLocalData('../x'), /userId/);
        } finally {
            delete globalThis.indexedDB;
        }
        assert.strictEqual(await E2EE.deleteLocalData(42), false, 'без IndexedDB — false');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
