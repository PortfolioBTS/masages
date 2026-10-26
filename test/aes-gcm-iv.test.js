'use strict';
// Уникальность nonce (IV) AES-GCM (ревью W7 R5, З-2). Контракт R4: IV случайный, 12 байт, на каждое шифрование
// новый. Все три места, где клиент шифрует (key-share, сообщение комнаты, файл), используют одноразовые ключи, поэтому
// нулевой или повторяющийся IV не сломал бы схему мгновенно, но инвариант держался бы только на коде:
// public/lib/e2ee-crypto.js, aesGcmEncrypt (`const iv = randomBytes(12)`). Тест ловит замену на постоянный IV
// на самой функции и на каждом из мест вызова.
// Запуск: node test/aes-gcm-iv.test.js

const nodeCrypto = require('crypto');
const {
    assert, E2EE, test, finish, makeUser, makeRoom, chatOf, participantsOf, send,
} = require('./sender-keys-helpers');

// aesGcmEncrypt живёт в модуле e2ee-crypto.js; e2ee.js берёт его оттуда (e2ee-modules.test.js следит, что копии нет).
const Crypto = require('../public/lib/e2ee-crypto.js');
const { b64decode } = E2EE._internal;

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const allDistinct = (list) => new Set(list).size === list.length;

(async () => {
    console.log('Уникальность IV AES-GCM\n');

    await test('aesGcmEncrypt: два вызова с тем же ключом, текстом и AAD дают разные iv и разный шифротекст', async () => {
        const key = nodeCrypto.randomBytes(32);
        const text = new TextEncoder().encode('один и тот же текст');
        const aad = new TextEncoder().encode('aad');
        const a = await Crypto.aesGcmEncrypt(key, text, aad);
        const b = await Crypto.aesGcmEncrypt(key, text, aad);
        assert.strictEqual(a.iv.length, 12);
        assert.strictEqual(b.iv.length, 12);
        assert.notStrictEqual(hex(a.iv), hex(b.iv), 'iv повторился');
        assert.notStrictEqual(hex(a.ct), hex(b.ct), 'шифротекст повторился');
        // Круг: каждый шифротекст читается со своим iv.
        assert.strictEqual(Buffer.from(await Crypto.aesGcmDecrypt(key, a.iv, a.ct, aad)).toString(), 'один и тот же текст');
        assert.strictEqual(Buffer.from(await Crypto.aesGcmDecrypt(key, b.iv, b.ct, aad)).toString(), 'один и тот же текст');
    });

    await test('aesGcmEncrypt: 1000 вызовов с одним ключом - 1000 разных iv, ни один не нулевой', async () => {
        const key = nodeCrypto.randomBytes(32);
        const text = new Uint8Array(16);
        const ivs = [];
        for (let i = 0; i < 1000; i++) ivs.push(hex((await Crypto.aesGcmEncrypt(key, text, new Uint8Array(0))).iv));
        assert.ok(allDistinct(ivs), 'среди 1000 iv есть повторы');
        assert.ok(!ivs.includes('00'.repeat(12)), 'нулевой iv');
    });

    await test('сообщения комнаты: 90 сообщений подряд (до порога ротации ключа) - 90 разных iv в конвертах', async () => {
        const server = makeRoom(100, [1, 2]);
        const alice = makeUser(server, 1);
        await alice.init();
        await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
        const ivs = [];
        for (let i = 0; i < 90; i++) {
            const message = await send(alice, 100, 'одно и то же сообщение');
            const envelope = JSON.parse(message.env);
            assert.strictEqual(b64decode(envelope.iv).length, 12);
            ivs.push(envelope.iv);
        }
        assert.ok(allDistinct(ivs), 'в конвертах комнаты повторился iv');
    });

    await test('key-share: каждому из пяти получателей и при ротации - свой iv', async () => {
        const server = makeRoom(100, [1, 2, 3, 4, 5, 6]);
        const users = [];
        for (let id = 1; id <= 6; id++) {
            const user = makeUser(server, id);
            await user.init();
            users.push(user);
        }
        await users[0].ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
        await users[0].rotateRoomKey(100);
        const ivs = server._keyShares.map(share => JSON.parse(share.ciphertext).iv);
        assert.ok(ivs.length >= 5, `key-share отправлены: ${ivs.length}`);
        assert.ok(allDistinct(ivs), 'в key-share повторился iv');
        for (const iv of ivs) assert.strictEqual(b64decode(iv).length, 12);
    });

    await test('файлы: один и тот же файл, зашифрованный 200 раз, - 200 разных iv', async () => {
        const server = makeRoom(100, [1, 2]);
        const alice = makeUser(server, 1);
        await alice.init();
        const bytes = nodeCrypto.randomBytes(2000);
        const ivs = [];
        for (let i = 0; i < 200; i++) ivs.push((await alice.encryptFile(bytes)).iv);
        assert.ok(allDistinct(ivs), 'у файлов повторился iv');
        for (const iv of ivs) assert.strictEqual(b64decode(iv).length, 12);
    });

    finish();
})().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
