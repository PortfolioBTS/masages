'use strict';
// Строгий Ed25519 на КАЖДОМ пути проверки подписи (T5.4, docs/security/signed-membership.md 6.1 и 6.6):
// клиент public/e2ee.js (подпись SPK, PQ-prekey last-resort и одноразового, ключ identity из bundle и
// заголовка key-share, ключ подписи в SKDM, конверты Sender Key) и сервер lib/key-store.js (identity_signing_key и
// подписи prekey). Оба отрицательных вектора раздела 6.6 — единичная точка 01 00…00 и 01 00…00 80 с подписью
// R = 01 00…00, S = 0 — платформенный verify принимает под любым сообщением; здесь каждый путь их отвергает.
// Запуск: node test/ed25519-strict-paths.test.js

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const {
    assert, E2EE, makeFakeServer, test, finish, makeUser, makeRoom, chatOf, participantsOf, send, read, stored,
} = require('./sender-keys-helpers');
const strict = require('../public/lib/ed25519-strict.js');
const { createKeyStore, _internal: K } = require('../lib/key-store');
const { makeFakeKeyDb } = require('./fake-key-db');

const I = E2EE._internal;
const { b64encode: b64, b64decode: unb64 } = I;
const subtle = globalThis.crypto.subtle;
const ROOT = path.join(__dirname, '..');

const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const ONE = unhex('0100000000000000000000000000000000000000000000000000000000000000');
const ONE_SIGN = unhex('0100000000000000000000000000000000000000000000000000000000000080');
// Подпись обоих отрицательных векторов: R = 01 00…00, S = 0.
const ZERO_S_SIG = new Uint8Array(64);
ZERO_S_SIG[0] = 1;
const VECTORS = [['01 00…00 (единичная точка, порядок 1)', ONE], ['01 00…00 80 (x = 0 при бите знака 1)', ONE_SIGN]];

// Подпись с S + L вместо S: тот же R и та же проверка уравнения, но S вне канонического диапазона.
function malleated(sig) {
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
    s += strict.L;
    const out = new Uint8Array(sig);
    for (let i = 32; i < 64; i++) { out[i] = Number(s & 255n); s >>= 8n; }
    return out;
}

function realPair() {
    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
    const raw = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
    return { raw, sign: (message) => new Uint8Array(nodeCrypto.sign(null, message, privateKey)) };
}

// Что делает платформа с вектором: печатаем для протокола, не утверждаем (зависит от версии OpenSSL).
async function platformAccepts(key, message) {
    try {
        const imported = await subtle.importKey('raw', key, { name: 'Ed25519' }, false, ['verify']);
        return await subtle.verify({ name: 'Ed25519' }, imported, ZERO_S_SIG, message);
    } catch { return 'ошибка импорта'; }
}

// Клиент Alice (id 1) с bundle Bob (id 2), который правит mutate(bundle). Возвращает { server, warnings }.
async function aliceSeesBundle(mutate, { stripOneTime = false } = {}) {
    const server = makeRoom(100, [1, 2]);
    const bob = makeUser(server, 2);
    await bob.init();
    if (stripOneTime) server.evil.stripPqOneTime(2);
    const transport = server.transportFor(1);
    const realGetBundle = transport.getBundle;
    transport.getBundle = async (id) => {
        const res = await realGetBundle(id);
        if (res.status === 200) mutate(res.data);
        return res;
    };
    const alice = makeUser(server, 1, { transport });
    await alice.init();
    const result = await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
    return { server, result };
}

const sigWith = (bundleKey, fn) => (bundle) => { bundle[bundleKey] = Object.assign({}, bundle[bundleKey], { signature: b64(fn(unb64(bundle[bundleKey].signature))) }); };

(async () => {
    console.log('Строгий Ed25519 на всех путях (клиент и сервер)\n');

    // ===================== Клиент: verify и разбор ключей =====================

    await test('клиент: verify() отвергает оба вектора 6.6, малый порядок R, S + L; настоящие пары проходят', async () => {
        const message = new Uint8Array([9, 8, 7, 6]);
        for (const [label, key] of VECTORS) {
            console.log(`        ${label}: платформенный verify — ${await platformAccepts(key, message)}`);
            assert.strictEqual(await I.verify(key, ZERO_S_SIG, message), false, label);
        }
        const { raw, sign } = realPair();
        const sig = sign(message);
        assert.strictEqual(await I.verify(raw, sig, message), true);
        assert.strictEqual(await I.verify(raw, ZERO_S_SIG, message), false, 'R малого порядка при настоящем ключе');
        assert.strictEqual(await I.verify(raw, malleated(sig), message), false, 'S + L');
        const flipped = new Uint8Array(message);
        flipped[0] ^= 1;
        assert.strictEqual(await I.verify(raw, sig, flipped), false);
        assert.strictEqual(await I.verify(raw.subarray(0, 31), sig, message), false, 'длина ключа');
    });

    await test('клиент: ключ подписи из чужого ввода — восемь точек малого порядка, оба вектора, y >= p, нулевой ключ отвергаются', () => {
        const rejected = [...strict.SMALL_ORDER_ENCODINGS.map(unhex), ONE_SIGN,
            unhex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
            unhex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), new Uint8Array(32)];
        for (const key of rejected) assert.strictEqual(I.canonicalSigningKey(b64(key)), null, Buffer.from(key).toString('hex'));
        assert.strictEqual(I.canonicalSigningKey(b64(realPair().raw)) !== null, true);
        assert.strictEqual(I.canonicalSigningKey(null), null);
        assert.strictEqual(I.canonicalSigningKey('не base64'), null);
    });

    // ===================== Клиент: пути проверки =====================

    for (const [label, key] of VECTORS) {
        await test(`клиент, identity в bundle: ключ ${label} с подписью SPK R = 01 00…00, S = 0 — собеседник отвергнут, key-share не отправлен`, async () => {
            const { server, result } = await aliceSeesBundle((bundle) => {
                bundle.identity_signing_key = b64(key);
                bundle.signed_prekey = Object.assign({}, bundle.signed_prekey, { signature: b64(ZERO_S_SIG) });
            });
            assert.strictEqual(result.warnings.length, 1, JSON.stringify(result));
            assert.strictEqual(result.warnings[0].userId, 2);
            assert.match(result.warnings[0].reason, /identity-ключи/);
            assert.strictEqual(server._keyShares.length, 0);
        });
    }

    await test('клиент, подпись SPK: R малого порядка и S + L отвергаются, настоящая подпись проходит', async () => {
        for (const [what, fn] of [['R малого порядка', () => ZERO_S_SIG], ['S + L', malleated]]) {
            const { server, result } = await aliceSeesBundle(sigWith('signed_prekey', fn));
            assert.strictEqual(result.warnings.length, 1, what);
            assert.match(result.warnings[0].reason, /Signed PreKey/, what);
            assert.strictEqual(server._keyShares.length, 0, what);
        }
        const { server, result } = await aliceSeesBundle(() => {});
        assert.deepStrictEqual(result.warnings, []);
        assert.strictEqual(server._keyShares.length, 1);
    });

    await test('клиент, подпись запасного PQ-prekey (last-resort): R малого порядка и S + L отвергаются', async () => {
        for (const [what, fn] of [['R малого порядка', () => ZERO_S_SIG], ['S + L', malleated]]) {
            const { server, result } = await aliceSeesBundle(sigWith('pq_prekey', fn), { stripOneTime: true });
            assert.strictEqual(result.warnings.length, 1, what);
            assert.match(result.warnings[0].reason, /PQ-prekey/, what);
            assert.strictEqual(server._keyShares.length, 0, what);
        }
    });

    await test('клиент, подпись одноразового PQ-prekey: R малого порядка и S + L отвергаются', async () => {
        for (const [what, fn] of [['R малого порядка', () => ZERO_S_SIG], ['S + L', malleated]]) {
            const { server, result } = await aliceSeesBundle(sigWith('pq_one_time_prekey', fn));
            assert.strictEqual(result.warnings.length, 1, what);
            assert.match(result.warnings[0].reason, /одноразового PQ-prekey/, what);
            assert.strictEqual(server._keyShares.length, 0, what);
        }
    });

    await test('клиент, SKDM: ключ подписи малого порядка или в неканонической кодировке не разбирается', () => {
        const room = 100;
        const skdm = (signingPublicKey) => I.parseSkdm(new TextEncoder().encode(JSON.stringify({
            v: 2, type: 'skdm', roomId: room, senderKeyId: b64(nodeCrypto.randomBytes(16)),
            chainKey: b64(new Uint8Array(32).fill(5)), iteration: 0, signingPublicKey,
        })), room);
        for (const [label, key] of VECTORS) assert.strictEqual(skdm(b64(key)), null, label);
        for (const encoding of strict.SMALL_ORDER_ENCODINGS) assert.strictEqual(skdm(b64(unhex(encoding))), null, encoding);
        assert.ok(skdm(b64(realPair().raw)), 'настоящий ключ разбирается');
    });

    await test('клиент, заголовок key-share: identity-ключ подписи отправителя малого порядка — key-share не применяется', async () => {
        for (const [label, key] of VECTORS) {
            const server = makeRoom(100, [1, 2]);
            const alice = makeUser(server, 1);
            const bob = makeUser(server, 2);
            await alice.init();
            await bob.init();
            await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
            assert.strictEqual(server._keyShares.length, 1);
            const share = server._keyShares[0];
            const env = JSON.parse(share.ciphertext);
            env.init.senderIdentitySignPub = b64(key);
            share.ciphertext = JSON.stringify(env);
            const r = await bob.syncKeyShares(chatOf(2), 100);
            assert.strictEqual(r.applied, 0, label);
            assert.ok(!(await stored(bob, 'senderKey:100:1')), label + ': ключ отправителя не записан');
        }
    });

    for (const [label, key] of VECTORS) {
        await test(`клиент, конверт Sender Key: ключ подписи ${label} в записи и подпись R = 01 00…00, S = 0 — 'bad-signature'`, async () => {
            const server = makeRoom(100, [1, 2]);
            const alice = makeUser(server, 1);
            const bob = makeUser(server, 2);
            await alice.init();
            await bob.init();
            await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
            await bob.syncKeyShares(chatOf(2), 100);
            const message = await send(alice, 100, 'проверка');
            assert.strictEqual((await read(bob, 100, message)).text, 'проверка', 'настоящий конверт читается');

            // Запись ключа Alice у Bob с ключом малого порядка (как после подмены хранилища или старого бага):
            // платформенный verify принял бы пару R = 01 00…00, S = 0 для ЛЮБОГО конверта.
            const name = 'senderKey:100:1';
            const record = await stored(bob, name);
            record.signingPublicKey = b64(key);
            await bob._storage.set(name, record);
            const second = await send(alice, 100, 'вторая');
            const forged = Object.assign(JSON.parse(second.env), { sig: b64(ZERO_S_SIG) });
            const result = await bob.decryptIncoming(100, 1, JSON.stringify(forged), second.id);
            assert.deepStrictEqual(result, { ok: false, reason: 'bad-signature' });
        });
    }

    await test('клиент: подпись Ed25519 проверяется в одном месте — других вызовов subtle.verify и crypto.verify в коде нет', () => {
        const files = [];
        const walk = (dir) => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                if (['node_modules', 'test', '.git', 'vendor', 'wt', 'docs'].includes(entry.name)) continue;
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) walk(full);
                else if (entry.name.endsWith('.js')) files.push(full);
            }
        };
        walk(ROOT);
        const found = {};
        for (const file of files) {
            const matches = fs.readFileSync(file, 'utf8').match(/\b(?:subtle|crypto)\.verify\(/g);
            if (matches) found[path.relative(ROOT, file).split(path.sep).join('/')] = matches.length;
        }
        // e2ee.js: verify() после ed25519Strict; ed25519-strict.js: после своих проверок; key-store.js: после verifySignature.
        assert.deepStrictEqual(found, { 'lib/key-store.js': 1, 'public/e2ee.js': 1, 'public/lib/ed25519-strict.js': 1 });
        const keyStore = fs.readFileSync(path.join(ROOT, 'lib/key-store.js'), 'utf8');
        assert.ok(keyStore.indexOf('ed25519Strict.checkSignature') < keyStore.indexOf('crypto.verify('), 'сервер: строгая проверка раньше crypto.verify');
        const client = fs.readFileSync(path.join(ROOT, 'public/e2ee.js'), 'utf8');
        assert.ok(client.indexOf('ed25519Strict.checkSignature(sig)') < client.indexOf('subtle.verify(\'Ed25519\''), 'клиент: строгая проверка раньше subtle.verify');
    });

    // ===================== Сервер =====================

    const b64s = (bytes) => Buffer.from(bytes).toString('base64');
    const x25519Raw = () => nodeCrypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    function makeStore() {
        const db = makeFakeKeyDb();
        return createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll });
    }
    async function registerIdentity(store, userId) {
        const pair = realPair();
        const r = await store.call(userId, 'PUT', '/internal/v1/keys/identity', {
            identity_signing_key: b64s(pair.raw), identity_dh_key: b64s(x25519Raw()),
        });
        assert.strictEqual(r.status, 200, JSON.stringify(r.data));
        return pair;
    }

    for (const [label, key] of VECTORS) {
        await test(`сервер, identity_signing_key ${label}: 400 с причиной, в базу не попадает`, async () => {
            const db = makeFakeKeyDb();
            const store = createKeyStore({ dbGet: db.dbGet, dbAll: db.dbAll });
            const r = await store.call(1, 'PUT', '/internal/v1/keys/identity', {
                identity_signing_key: b64s(key), identity_dh_key: b64s(x25519Raw()),
            });
            assert.strictEqual(r.status, 400, JSON.stringify(r.data));
            assert.match(r.data.message, /identity_signing_key: invalid Ed25519 key \((small-order|zero-x-sign)\)/);
            assert.ok(!(await db.dbGet('SELECT identity_signing_key FROM identity_keys WHERE user_id = $1', [1])), 'в базу не попало');
        });
    }

    await test('сервер, identity_signing_key: восемь точек малого порядка, x = 0 при бите знака 1, y >= p, точка вне кривой — 400; настоящий ключ — 200', async () => {
        const store = makeStore();
        const bad = [...strict.SMALL_ORDER_ENCODINGS,
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'];
        let offCurve = null;
        for (let y = 2; y < 60 && !offCurve; y++) {
            const bytes = new Uint8Array(32);
            bytes[0] = y;
            if (strict.decodePoint(bytes).error === 'no-square-root') offCurve = Buffer.from(bytes).toString('hex');
        }
        assert.ok(offCurve, 'нашлась точка вне кривой');
        for (const hex of [...bad, offCurve]) {
            const r = await store.call(1, 'PUT', '/internal/v1/keys/identity', {
                identity_signing_key: b64s(Buffer.from(hex, 'hex')), identity_dh_key: b64s(x25519Raw()),
            });
            assert.strictEqual(r.status, 400, hex + ' ' + JSON.stringify(r.data));
        }
        await registerIdentity(store, 1);
    });

    await test('сервер, verifySignature: сохранённый ключ малого порядка (оба вектора) с подписью R = 01 00…00, S = 0 — отказ', () => {
        const message = Buffer.from('любое сообщение');
        for (const [label, key] of VECTORS) {
            assert.throws(() => K.verifySignature('signed prekey', Buffer.from(key), message, Buffer.from(ZERO_S_SIG)),
                /identity_signing_key: invalid Ed25519 point/, label);
        }
    });

    await test('сервер, подпись SPK и PQ last-resort: R малого порядка и S + L — 400 «signature verification failed», настоящая — 200', async () => {
        const store = makeStore();
        const pair = await registerIdentity(store, 1);
        const spk = x25519Raw();
        const good = pair.sign(spk);
        for (const [what, sig] of [['R малого порядка', ZERO_S_SIG], ['S + L', malleated(good)]]) {
            const r = await store.call(1, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1, public_key: b64s(spk), signature: b64s(sig) });
            assert.strictEqual(r.status, 400, what);
            assert.match(r.data.message, /signature verification failed/, what);
        }
        const ok = await store.call(1, 'PUT', '/internal/v1/keys/signed-prekey', { key_id: 1, public_key: b64s(spk), signature: b64s(good) });
        assert.strictEqual(ok.status, 200, JSON.stringify(ok.data));

        const MLKEM = require('../public/mlkem.js');
        const ek = MLKEM.keygen(nodeCrypto.randomBytes(64)).publicKey;
        const goodPq = pair.sign(ek);
        for (const [what, sig] of [['R малого порядка', ZERO_S_SIG], ['S + L', malleated(goodPq)]]) {
            const r = await store.call(1, 'PUT', '/internal/v1/keys/pq-prekey', { key_id: 2, public_key: b64s(ek), signature: b64s(sig) });
            assert.strictEqual(r.status, 400, what);
            assert.match(r.data.message, /signature verification failed/, what);
        }
        const okPq = await store.call(1, 'PUT', '/internal/v1/keys/pq-prekey', { key_id: 2, public_key: b64s(ek), signature: b64s(goodPq) });
        assert.strictEqual(okPq.status, 200, JSON.stringify(okPq.data));
    });

    await test('сервер, подпись одноразового PQ-prekey: R малого порядка и S + L — 400, настоящая — 200', async () => {
        const store = makeStore();
        const pair = await registerIdentity(store, 1);
        const MLKEM = require('../public/mlkem.js');
        const ek = Buffer.from(MLKEM.keygen(nodeCrypto.randomBytes(64)).publicKey);
        const good = pair.sign(K.pqOneTimePrekeyMessage(5, ek));
        for (const [what, sig] of [['R малого порядка', ZERO_S_SIG], ['S + L', malleated(good)]]) {
            const r = await store.call(1, 'POST', '/internal/v1/keys/pq-one-time-prekeys', { keys: [{ key_id: 5, public_key: b64s(ek), signature: b64s(sig) }] });
            assert.strictEqual(r.status, 400, what);
            assert.match(r.data.message, /signature verification failed/, what);
        }
        const ok = await store.call(1, 'POST', '/internal/v1/keys/pq-one-time-prekeys', { keys: [{ key_id: 5, public_key: b64s(ek), signature: b64s(good) }] });
        assert.strictEqual(ok.status, 200, JSON.stringify(ok.data));
    });

    finish();
})().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
