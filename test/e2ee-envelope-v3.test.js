'use strict';
// Конверт сообщения комнаты v3 (T5.4): подпись Sender Key с меткой домена и комнатой.
//   sigInput = "nyxo-skmsg-v3\0" ‖ u32be(roomId) ‖ senderKeyId[16] ‖ u32be(iteration) ‖ iv[12] ‖ ct
// (docs/security/sealed-sender.md, раздел 9.3). Байты собираются здесь независимо от кода клиента и проверяются
// платформенным Ed25519 по открытому ключу из хранилища получателя. Прежний конверт v2 (подпись iv ‖ ct ‖ iteration
// ‖ keyId без метки и комнаты) не принимается: R0, конвертов v2 нет.
// Запуск: node test/e2ee-envelope-v3.test.js

const nodeCrypto = require('crypto');
const {
    assert, E2EE, test, finish, makeUser, makeRoom, chatOf, participantsOf, send, read, stored,
} = require('./sender-keys-helpers');
const { isE2eeEnvelopeShape } = require('../lib/e2ee-envelope');

const { b64encode: b64, b64decode: unb64 } = E2EE._internal;
const subtle = globalThis.crypto.subtle;
const ROOM = 100;

const u32 = (n) => Buffer.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const LABEL = Buffer.from('nyxo-skmsg-v3\0', 'utf8');

// sigInput v3 по определению, независимо от e2ee.js.
function sigInputV3(room, keyId, iteration, iv, ct) {
    return Buffer.concat([LABEL, u32(room), Buffer.from(unb64(keyId)), u32(iteration), Buffer.from(iv), Buffer.from(ct)]);
}

// Прежняя подпись v2: iv ‖ ct ‖ u32be(iteration) ‖ utf8(senderKeyId).
function sigInputV2(keyId, iteration, iv, ct) {
    return Buffer.concat([Buffer.from(iv), Buffer.from(ct), u32(iteration), Buffer.from(keyId, 'utf8')]);
}

function publicKeyObject(raw) {
    return nodeCrypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]), format: 'der', type: 'spki' });
}

const verifies = (rawPub, message, sig) => nodeCrypto.verify(null, message, publicKeyObject(rawPub), Buffer.from(sig));

async function pair() {
    const server = makeRoom(ROOM, [1, 2]);
    const alice = makeUser(server, 1);
    const bob = makeUser(server, 2);
    await alice.init();
    await bob.init();
    await alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(server, ROOM));
    await bob.syncKeyShares(chatOf(2), ROOM);
    const state = await stored(alice, 'senderKey:' + ROOM + ':1');
    return { server, alice, bob, signPub: unb64(state.signingPublicKey), signingPrivateKey: state.signingPrivateKey, state };
}

// Конверт с подписью, посчитанной заданной функцией (приватный ключ Alice — неизвлекаемый CryptoKey, им можно подписывать).
async function resign(ctx, envelopeText, inputOf) {
    const env = JSON.parse(envelopeText);
    const sig = new Uint8Array(await subtle.sign('Ed25519', ctx.signingPrivateKey, inputOf(env)));
    return JSON.stringify({ ...env, sig: b64(sig) });
}

(async () => {
    console.log('Конверт сообщения v3: метка домена и комната в подписи\n');

    await test('форма: v = 3, alg = senderkey-v3; сервер принимает такой конверт', async () => {
        const ctx = await pair();
        const m = await send(ctx.alice, ROOM, 'привет');
        const env = JSON.parse(m.env);
        assert.strictEqual(env.v, 3);
        assert.strictEqual(env.alg, 'senderkey-v3');
        assert.deepStrictEqual(Object.keys(env).sort(), ['alg', 'ct', 'iteration', 'iv', 'senderKeyId', 'sig', 'v']);
        assert.ok(isE2eeEnvelopeShape(m.env));
        assert.strictEqual((await read(ctx.bob, ROOM, m)).text, 'привет');
    });

    await test('подпись = Ed25519(ключ Sender Key, метка ‖ u32be(комната) ‖ keyId[16] ‖ u32be(итерация) ‖ iv ‖ ct), собрана независимо', async () => {
        const ctx = await pair();
        for (const text of ['а', 'б'.repeat(500)]) {
            const m = await send(ctx.alice, ROOM, text);
            const env = JSON.parse(m.env);
            const input = sigInputV3(ROOM, env.senderKeyId, env.iteration, unb64(env.iv), unb64(env.ct));
            assert.ok(verifies(ctx.signPub, input, unb64(env.sig)), 'подпись сходится с независимо собранными байтами');
            assert.strictEqual(input.length, 14 + 4 + 16 + 4 + 12 + unb64(env.ct).length, 'длины полей: 14 + 4 + 16 + 4 + 12 + ct');
            assert.strictEqual(input.subarray(0, 14).toString('hex'), '6e79786f2d736b6d73672d763300', 'метка "nyxo-skmsg-v3" и нулевой разделитель');
        }
    });

    await test('подпись привязана к каждому полю: комната, keyId, итерация, iv, ct, метка', async () => {
        const ctx = await pair();
        const m = await send(ctx.alice, ROOM, 'поле за полем');
        const env = JSON.parse(m.env);
        const iv = unb64(env.iv), ct = unb64(env.ct), sig = unb64(env.sig);
        const good = sigInputV3(ROOM, env.senderKeyId, env.iteration, iv, ct);
        assert.ok(verifies(ctx.signPub, good, sig));
        const flipped = (bytes) => { const copy = Buffer.from(bytes); copy[0] ^= 1; return copy; };
        const otherKeyId = b64(flipped(unb64(env.senderKeyId)));
        const wrong = {
            'другая комната': sigInputV3(ROOM + 1, env.senderKeyId, env.iteration, iv, ct),
            'другой keyId': sigInputV3(ROOM, otherKeyId, env.iteration, iv, ct),
            'другая итерация': sigInputV3(ROOM, env.senderKeyId, env.iteration + 1, iv, ct),
            'другой iv': sigInputV3(ROOM, env.senderKeyId, env.iteration, flipped(iv), ct),
            'другой ct': sigInputV3(ROOM, env.senderKeyId, env.iteration, iv, flipped(ct)),
            'без метки': good.subarray(14),
            'другая метка (v2)': Buffer.concat([Buffer.from('nyxo-skmsg-v2\0'), good.subarray(14)]),
            'метка без нулевого разделителя': Buffer.concat([Buffer.from('nyxo-skmsg-v3'), good.subarray(14)]),
        };
        for (const [what, input] of Object.entries(wrong)) assert.ok(!verifies(ctx.signPub, input, sig), what);
    });

    await test('получатель: подпись, снятая с другой комнаты, не принимается (конверт той же длины и тем же ключом)', async () => {
        const ctx = await pair();
        const m = await send(ctx.alice, ROOM, 'для комнаты 100');
        // Та же запись ключа Alice «в комнате 101» (сервер подсунул индекс): подпись считалась для комнаты 100.
        const state = await stored(ctx.bob, 'senderKey:' + ROOM + ':1');
        const index = await stored(ctx.bob, 'skIndex:' + ROOM + ':' + JSON.parse(m.env).senderKeyId);
        assert.ok(state && index, 'у Bob есть запись ключа и индекс');
        await ctx.bob._storage.set('senderKey:101:1', state);
        await ctx.bob._storage.set('skIndex:101:' + JSON.parse(m.env).senderKeyId, index);
        const result = await ctx.bob.decryptIncoming(101, 1, m.env, m.id);
        assert.deepStrictEqual(result, { ok: false, reason: 'bad-signature' });
        assert.strictEqual((await read(ctx.bob, ROOM, m)).ok, true, 'в своей комнате конверт читается');
    });

    await test('v2 не принимается: конверт v2 — bad-envelope, а подпись в старом формате под v3 — bad-signature', async () => {
        const ctx = await pair();
        const m = await send(ctx.alice, ROOM, 'старый формат');
        const env = JSON.parse(m.env);
        const asV2 = JSON.stringify({ ...env, v: 2, alg: 'senderkey-v2' });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, 1, asV2, m.id), { ok: false, reason: 'bad-envelope' });
        assert.strictEqual(isE2eeEnvelopeShape(asV2), false, 'сервер не пропустит v2 в комнату');
        // Подпись по правилам v2 (без метки и комнаты) при заголовке v3: подпись настоящая, но не та.
        const oldSigned = await resign(ctx, m.env, (e) => sigInputV2(e.senderKeyId, e.iteration, unb64(e.iv), unb64(e.ct)));
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, 1, oldSigned, m.id), { ok: false, reason: 'bad-signature' });
        // И наоборот: подпись по правилам v3 при пересчёте на настоящих полях проходит (контроль самого теста).
        const newSigned = await resign(ctx, m.env, (e) => sigInputV3(ROOM, e.senderKeyId, e.iteration, unb64(e.iv), unb64(e.ct)));
        assert.strictEqual((await ctx.bob.decryptIncoming(ROOM, 1, newSigned, m.id)).ok, true);
    });

    await test('шифрование привязано к версии: конверт v3 с шифротекстом под AAD прежнего вида (senderkey-v2:…) не расшифровывается', async () => {
        const ctx = await pair();
        const hmac = async (key, byte) => new Uint8Array(await subtle.sign('HMAC', await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), new Uint8Array([byte])));
        // Следующее сообщение Alice, собранное вручную: ключ из цепочки, подпись v3 настоящая, AAD — прежнего вида.
        const encryptWithAad = async (aadText) => {
            const state = await stored(ctx.alice, 'senderKey:' + ROOM + ':1');
            const iteration = state.nextIteration;
            const messageKey = await hmac(unb64(state.chainKey), 1);
            const ikm = await subtle.importKey('raw', messageKey, 'HKDF', false, ['deriveBits']);
            const aesRaw = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: Buffer.from('nyxo-e2ee-msgkey-v2') }, ikm, 256));
            const aesKey = await subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['encrypt']);
            const iv = new Uint8Array(nodeCrypto.randomBytes(12));
            const body = E2EE._internal.padMessage(Buffer.from(JSON.stringify({ t: 'text', b: 'AAD', mid: '7000001', ts: 1800000000000 })));
            const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: Buffer.from(aadText + state.senderKeyId) }, aesKey, body));
            const sig = new Uint8Array(await subtle.sign('Ed25519', state.signingPrivateKey, sigInputV3(ROOM, state.senderKeyId, iteration, iv, ct)));
            return JSON.stringify({ v: 3, alg: 'senderkey-v3', senderKeyId: state.senderKeyId, iteration, iv: b64(iv), ct: b64(ct), sig: b64(sig) });
        };
        const oldAad = await encryptWithAad('senderkey-v2:' + ROOM + ':1:');
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, 1, oldAad, '7000001'), { ok: false, reason: 'decrypt-failed' }, 'подпись верна, AAD прежний — расшифровки нет');
        // Контроль самого теста: тот же приём с AAD v3 расшифровывается.
        const newAad = await encryptWithAad('senderkey-v3:' + ROOM + ':1:');
        const ok = await ctx.bob.decryptIncoming(ROOM, 1, newAad, '7000001');
        assert.strictEqual(ok.ok, true, JSON.stringify(ok));
    });

    finish();
})().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
