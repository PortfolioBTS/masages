'use strict';
// Строгая проверка подписи Ed25519 в public/e2ee.js, когда платформенный verify её НЕ отвергает (ревью W7 R5, З-1).
//
// В ed25519-strict-paths.test.js подписи с S + L и с R малого порядка отвергаются на всех путях клиента, но в Node
// это делает уже сам WebCrypto (OpenSSL проверяет S < L и уравнение), поэтому тесты остаются зелёными и без
// `ed25519Strict.checkSignature(sig)` в verify(): удаление этой проверки они не замечали. Строгая проверка нужна
// ровно для платформ, где verify мягче (другие движки, старые версии): договор раздела 6 signed-membership.md - ни
// одна подпись с S >= L или R малого порядка не принимается ни на каком пути.
//
// Здесь платформенный verify заменён на принимающий всё, так что единственным барьером остаётся строгая проверка в
// самом клиенте. Файл запускается отдельным процессом, подмена не задевает другие тесты.
// Запуск: node test/ed25519-strict-permissive-platform.test.js

const nodeCrypto = require('crypto');
const {
    assert, E2EE, makeFakeServer, test, finish, makeUser, makeRoom, chatOf, participantsOf, send, read,
} = require('./sender-keys-helpers');
const strict = require('../public/lib/ed25519-strict.js');

const I = E2EE._internal;
const { b64encode: b64, b64decode: unb64 } = I;
const subtle = globalThis.crypto.subtle;

// Платформа без проверки: любой verify истинен (как у реализации, не проверяющей S < L и R).
const realVerify = subtle.verify.bind(subtle);
let platformCalls = 0;
subtle.verify = async () => { platformCalls++; return true; };

const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
function keyPair() {
    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
    const raw = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
    return { raw, sign: (message) => new Uint8Array(nodeCrypto.sign(null, message, privateKey)) };
}

const sToBig = (sig) => { let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]); return s; };
function withS(sig, s) {
    const out = new Uint8Array(sig);
    for (let i = 32; i < 64; i++) { out[i] = Number(s & 255n); s >>= 8n; }
    return out;
}
const malleated = (sig) => withS(sig, sToBig(sig) + strict.L);

// Подписи, которые настоящий ключ не мог бы поставить, а мягкая платформа приняла бы: имя -> функция от хорошей подписи.
const BAD_SIGNATURES = [
    ['S + L (тот же R, S вне диапазона)', malleated],
    ['S = L', (sig) => withS(sig, strict.L)],
    ['S = 2^256 - 1', (sig) => withS(sig, (1n << 256n) - 1n)],
    ...strict.SMALL_ORDER_ENCODINGS.map((hex, i) => [`R малого порядка №${i} (${hex.slice(0, 8)}…)`, (sig) => {
        const out = new Uint8Array(sig);
        out.set(unhex(hex), 0);
        return out;
    }]),
];

// Клиент Alice с bundle Bob, который правит mutate(bundle).
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
    console.log('Строгий Ed25519 клиента при мягкой платформе\n');

    await test('контроль: подменённый платформенный verify действительно принимает всё (иначе тесты ниже ничего не доказывают)', async () => {
        const { raw, sign } = keyPair();
        const message = new Uint8Array([1, 2, 3]);
        const imported = await subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
        assert.strictEqual(await subtle.verify('Ed25519', imported, malleated(sign(message)), message), true, 'S + L принят платформой');
        assert.strictEqual(await subtle.verify('Ed25519', imported, new Uint8Array(64), message), true, 'нулевая подпись принята платформой');
        // Настоящий verify Node эти подписи отвергает - потому прежние тесты и не видели удаления строгой проверки.
        assert.strictEqual(await realVerify('Ed25519', imported, malleated(sign(message)), message), false, 'настоящая платформа отвергает S + L');
    });

    await test('verify(): все подписи с S >= L и с R малого порядка отвергаются до платформы, хорошая подпись проходит', async () => {
        const { raw, sign } = keyPair();
        const message = new Uint8Array([9, 8, 7, 6, 5]);
        const good = sign(message);
        platformCalls = 0;
        assert.strictEqual(await I.verify(raw, good, message), true, 'настоящая подпись');
        assert.strictEqual(platformCalls, 1);
        for (const [what, make] of BAD_SIGNATURES) {
            platformCalls = 0;
            assert.strictEqual(await I.verify(raw, make(good), message), false, what);
            assert.strictEqual(platformCalls, 0, `${what}: до платформенного verify дело не дошло`);
        }
        // Ключ малого порядка (восемь точек) и неканонические кодировки - тоже не доходят до платформы.
        const weakKeys = [...strict.SMALL_ORDER_ENCODINGS.map(unhex),
            unhex('0100000000000000000000000000000000000000000000000000000000000080'), new Uint8Array(32)];
        for (const key of weakKeys) {
            platformCalls = 0;
            assert.strictEqual(await I.verify(key, good, message), false, Buffer.from(key).toString('hex'));
            assert.strictEqual(platformCalls, 0, 'ключ малого порядка не дошёл до платформенного verify');
        }
    });

    await test('клиент, подпись SPK: S + L и R малого порядка отвергаются строгой проверкой, настоящая проходит', async () => {
        for (const [what, make] of BAD_SIGNATURES) {
            const { server, result } = await aliceSeesBundle(sigWith('signed_prekey', make));
            assert.strictEqual(result.warnings.length, 1, what);
            assert.match(result.warnings[0].reason, /Signed PreKey/, what);
            assert.strictEqual(server._keyShares.length, 0, what);
        }
        const { server, result } = await aliceSeesBundle(() => {});
        assert.deepStrictEqual(result.warnings, []);
        assert.strictEqual(server._keyShares.length, 1);
    });

    await test('клиент, подпись запасного PQ-prekey (last-resort): S + L и R малого порядка отвергаются', async () => {
        for (const [what, make] of BAD_SIGNATURES) {
            const { server, result } = await aliceSeesBundle(sigWith('pq_prekey', make), { stripOneTime: true });
            assert.strictEqual(result.warnings.length, 1, what);
            assert.match(result.warnings[0].reason, /PQ-prekey/, what);
            assert.strictEqual(server._keyShares.length, 0, what);
        }
    });

    await test('клиент, подпись одноразового PQ-prekey: S + L и R малого порядка отвергаются', async () => {
        for (const [what, make] of BAD_SIGNATURES) {
            const { server, result } = await aliceSeesBundle(sigWith('pq_one_time_prekey', make));
            assert.strictEqual(result.warnings.length, 1, what);
            assert.match(result.warnings[0].reason, /одноразового PQ-prekey/, what);
            assert.strictEqual(server._keyShares.length, 0, what);
        }
    });

    await test("клиент, конверт Sender Key: подпись с S + L или R малого порядка - 'bad-signature', настоящая читается", async () => {
        const server = makeRoom(100, [1, 2]);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        await alice.init();
        await bob.init();
        await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
        await bob.syncKeyShares(chatOf(2), 100);
        const message = await send(alice, 100, 'настоящее');
        assert.strictEqual((await read(bob, 100, message)).text, 'настоящее');
        for (const [what, make] of BAD_SIGNATURES) {
            const next = await send(alice, 100, `подделка ${what}`);
            const envelope = JSON.parse(next.env);
            const forged = Object.assign({}, envelope, { sig: b64(make(unb64(envelope.sig))) });
            const result = await bob.decryptIncoming(100, 1, JSON.stringify(forged), next.id);
            assert.deepStrictEqual(result, { ok: false, reason: 'bad-signature' }, what);
        }
    });

    finish();
})().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
