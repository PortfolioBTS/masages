'use strict';
// Строгий Ed25519 на настоящем сервере и Postgres (T5.4, docs/security/signed-membership.md 6.1 и 6.6):
// identity_signing_key малого порядка или в неканонической кодировке и подписи prekey с R малого порядка
// или S >= L отвергаются маршрутами /api/keys/* с 400 и в базу не попадают. Оба вектора раздела 6.6 —
// единичная точка 01 00…00 и 01 00…00 80 с подписью R = 01 00…00, S = 0 — платформенный verify принимает
// под любым сообщением, поэтому без явной проверки сервер сохранил бы такую identity и «подписанные» ею prekey.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const MLKEM = require('../../public/mlkem.js');
const strict = require('../../public/lib/ed25519-strict.js');
const { createSuite } = require('./helpers/scenarios');
const { count } = require('./helpers/anon');

const suite = createSuite('ed25519-strict');

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unhex = (h) => Buffer.from(h, 'hex');
const ZERO_S_SIG = Buffer.alloc(64);
ZERO_S_SIG[0] = 1;
const VECTORS = {
    'единичная точка 01 00…00': unhex('0100000000000000000000000000000000000000000000000000000000000000'),
    '01 00…00 80 (x = 0 при бите знака 1)': unhex('0100000000000000000000000000000000000000000000000000000000000080'),
};
const x25519 = () => crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

// S + L вместо S: тот же R, S вне канонического диапазона.
function malleated(sig) {
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
    s += strict.L;
    const out = Buffer.from(sig);
    for (let i = 32; i < 64; i++) { out[i] = Number(s & 255n); s >>= 8n; }
    return out;
}

const LABEL = Buffer.from('nyxo-pqopk-v1\0', 'utf8');
function labelled(keyId, publicKey) {
    const id = Buffer.alloc(8);
    id.writeBigUInt64BE(BigInt(keyId));
    return Buffer.concat([LABEL, id, publicKey]);
}

test('identity_signing_key: оба вектора 6.6, восемь точек малого порядка, y >= p — 400, в базу не попадает; настоящий ключ — 200', async () => {
    const user = suite.client({ name: 'identity' });
    await user.registerAnon();
    const bad = {
        ...VECTORS,
        'ec ff…ff ff (x = 0 при бите знака 1)': unhex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
        'y >= p': unhex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    };
    for (const hex of strict.SMALL_ORDER_ENCODINGS) bad['малый порядок ' + hex] = unhex(hex);
    for (const [what, key] of Object.entries(bad)) {
        const res = await user.put('/api/keys/identity', { identity_signing_key: b64(key), identity_dh_key: b64(x25519()) });
        assert.strictEqual(res.status, 400, `${what}: ${JSON.stringify(res.body)}`);
        assert.strictEqual(res.body.success, false);
    }
    assert.strictEqual(await count(suite, 'SELECT 1 FROM identity_keys WHERE user_id = $1', [user.user.id]), 0, 'отказы ничего не сохранили');

    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const good = await user.put('/api/keys/identity', {
        identity_signing_key: b64(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)), identity_dh_key: b64(x25519()),
    });
    assert.strictEqual(good.status, 200, JSON.stringify(good.body));
});

test('подписи prekey: R малого порядка (оба вектора как подпись) и S + L — 400 для SPK, last-resort и одноразового PQ; настоящие — 200', async () => {
    const user = suite.client({ name: 'подписи' });
    await user.registerAnon();
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const sign = (msg) => crypto.sign(null, msg, privateKey);
    await user.ok(user.put('/api/keys/identity', {
        identity_signing_key: b64(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)), identity_dh_key: b64(x25519()),
    }), 'identity');

    const spk = x25519();
    const goodSpk = sign(spk);
    for (const [what, sig] of [['R малого порядка', ZERO_S_SIG], ['S + L', malleated(goodSpk)]]) {
        const res = await user.put('/api/keys/signed-prekey', { key_id: 1, public_key: b64(spk), signature: b64(sig) });
        assert.strictEqual(res.status, 400, `SPK, ${what}: ${JSON.stringify(res.body)}`);
        assert.match(res.body.message, /signature verification failed/);
    }
    await user.ok(user.put('/api/keys/signed-prekey', { key_id: 1, public_key: b64(spk), signature: b64(goodSpk) }), 'SPK');

    const ek = Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);
    const goodPq = sign(ek);
    for (const [what, sig] of [['R малого порядка', ZERO_S_SIG], ['S + L', malleated(goodPq)]]) {
        const res = await user.put('/api/keys/pq-prekey', { key_id: 2, public_key: b64(ek), signature: b64(sig) });
        assert.strictEqual(res.status, 400, `PQ last-resort, ${what}: ${JSON.stringify(res.body)}`);
    }
    await user.ok(user.put('/api/keys/pq-prekey', { key_id: 2, public_key: b64(ek), signature: b64(goodPq) }), 'PQ last-resort');

    const otk = Buffer.from(MLKEM.keygen(crypto.randomBytes(64)).publicKey);
    const goodOtk = sign(labelled(3, otk));
    for (const [what, sig] of [['R малого порядка', ZERO_S_SIG], ['S + L', malleated(goodOtk)]]) {
        const res = await user.post('/api/keys/pq-one-time-prekeys', { keys: [{ key_id: 3, public_key: b64(otk), signature: b64(sig) }] });
        assert.strictEqual(res.status, 400, `одноразовый PQ, ${what}: ${JSON.stringify(res.body)}`);
    }
    const ok = await user.post('/api/keys/pq-one-time-prekeys', { keys: [{ key_id: 3, public_key: b64(otk), signature: b64(goodOtk) }] });
    assert.strictEqual(ok.status, 200, JSON.stringify(ok.body));
    assert.strictEqual(await count(suite, 'SELECT 1 FROM pq_one_time_prekeys WHERE user_id = $1', [user.user.id]), 1, 'сохранён только ключ с настоящей подписью');
});
