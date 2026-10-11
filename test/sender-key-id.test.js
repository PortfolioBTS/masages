'use strict';
// Идентификатор ключа отправителя, привязанный к отправителю
// (docs/security/sealed-sender.md, раздел 9.2):
//   senderKeyId = base64( SHA-256( "nyxo-skid-v1" ‖ u32be(roomId) ‖ u32be(senderId) ‖ signingPublicKey[32] )[0..16] )
// Контрольные значения документа (signingPublicKey = 20 21 22 … 3f) сверяются дословно.
// Запуск: node test/sender-key-id.test.js

const assert = require('assert');
const { E2EE, mlkem, makeFakeServer, test, finish, makeUser, makeRoom, chatOf, participantsOf, stored } = require('./sender-keys-helpers');

const I = E2EE._internal;
const { deriveSenderKeyId, b64encode, b64decode } = I;

const PUB = b64encode(new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x20 + i)));
const PUB_OTHER = b64encode(new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x40 + i)));

(async () => {
    console.log('senderKeyId, привязанный к отправителю\n');

    await test('контрольные значения раздела 9.2 (три вектора)', async () => {
        assert.strictEqual(await deriveSenderKeyId(1234567, 7654321, PUB), 'ZHuFfpo0BD+ReBQoWI5sfg==');
        assert.strictEqual(await deriveSenderKeyId(1234567, 7654322, PUB), 'ZEnufpqUbGkHwHMZQRUEow==', 'другой отправитель');
        assert.strictEqual(await deriveSenderKeyId(1234568, 7654321, PUB), '06SfnZGTkJ6dWWT+dzVnYA==', 'другая комната');
    });

    await test('другой подписывающий ключ, комната или отправитель дают другой идентификатор', async () => {
        const base = await deriveSenderKeyId(10, 20, PUB);
        assert.notStrictEqual(await deriveSenderKeyId(10, 20, PUB_OTHER), base);
        assert.notStrictEqual(await deriveSenderKeyId(11, 20, PUB), base);
        assert.notStrictEqual(await deriveSenderKeyId(10, 21, PUB), base);
        // Поля фиксированной длины: перестановка комнаты и отправителя — другое значение.
        assert.notStrictEqual(await deriveSenderKeyId(20, 10, PUB), base);
        // Детерминирован.
        assert.strictEqual(await deriveSenderKeyId(10, 20, PUB), base);
    });

    await test('формат: каноническое base64 ровно 16 байт (isCanonicalKeyId парсера SKDM принимает)', async () => {
        for (const [room, sender] of [[1, 1], [2 ** 31 - 1, 2 ** 31 - 1], [100, 2]]) {
            const id = await deriveSenderKeyId(room, sender, PUB);
            const bytes = b64decode(id);
            assert.strictEqual(bytes.length, 16);
            assert.strictEqual(b64encode(bytes), id, 'каноническая запись');
            const skdm = I.parseSkdm(new TextEncoder().encode(JSON.stringify({
                v: 2, type: 'skdm', roomId: room, senderKeyId: id,
                chainKey: b64encode(new Uint8Array(32).fill(7)), iteration: 0, signingPublicKey: PUB,
            })), room);
            assert.ok(skdm && skdm.senderKeyId === id, 'parseSkdm принимает производный идентификатор');
        }
    });

    await test('нечего выводить — ошибка, а не молчаливое значение: ключ не 32 байта, идентификаторы вне u32', async () => {
        await assert.rejects(deriveSenderKeyId(1, 2, b64encode(new Uint8Array(31))), TypeError);
        await assert.rejects(deriveSenderKeyId(1, 2, 'не base64!'), TypeError);
        await assert.rejects(deriveSenderKeyId(1, 2, null), TypeError);
        await assert.rejects(deriveSenderKeyId(-1, 2, PUB), TypeError);
        await assert.rejects(deriveSenderKeyId(1, 2 ** 32, PUB), TypeError);
        await assert.rejects(deriveSenderKeyId(1.5, 2, PUB), TypeError);
        await assert.rejects(deriveSenderKeyId(1, NaN, PUB), TypeError);
    });

    await test('свой ключ клиента: идентификатор выведен из (комната, я, открытый ключ подписи); ротация даёт новый', async () => {
        const server = makeRoom(100, [1, 2]);
        const alice = makeUser(server, 1);
        await alice.init();
        await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
        const first = await stored(alice, 'senderKey:100:1');
        assert.strictEqual(first.senderKeyId, await deriveSenderKeyId(100, 1, first.signingPublicKey));
        await alice.rotateRoomKey(100);
        const second = await stored(alice, 'senderKey:100:1');
        assert.notStrictEqual(second.signingPublicKey, first.signingPublicKey, 'ротация: новая пара Ed25519');
        assert.notStrictEqual(second.senderKeyId, first.senderKeyId);
        assert.strictEqual(second.senderKeyId, await deriveSenderKeyId(100, 1, second.signingPublicKey));
        // Тот же ключ подписи в другой комнате — другой идентификатор.
        assert.notStrictEqual(await deriveSenderKeyId(101, 1, second.signingPublicKey), second.senderKeyId);
    });

    finish();
})().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
