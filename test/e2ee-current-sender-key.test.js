'use strict';
// currentSenderKeyId (повторное ревью клиента W7, RR-9): идентификатор моего текущего Sender Key в комнате — по нему
// отправка с неизвестным исходом узнаёт, сменился ли ключ с момента шифрования (public/js/14-send.js, sendText).
// Запуск: node test/e2ee-current-sender-key.test.js

const { assert, makeWorld, test, finish } = require('./membership-world');

(async () => {
    await test('ключа нет — null; после сессии — id ключа конверта; после ротации — другой', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        await w.createRoom(alice);
        assert.strictEqual(await alice.client.currentSenderKeyId(alice.room), null);
        await w.approve(alice, bob);
        await w.ensure(alice);
        const first = await alice.client.currentSenderKeyId(alice.room);
        assert.ok(typeof first === 'string' && first.length > 0, String(first));
        const envelope = JSON.parse(await alice.client.encryptOutgoing(alice.room, 'привет', { messageId: '1234567' }));
        assert.strictEqual(envelope.senderKeyId, first, 'конверт зашифрован этим ключом');
        await alice.client.rotateRoomKey(alice.room);
        await w.ensure(alice);
        const second = await alice.client.currentSenderKeyId(alice.room);
        assert.ok(typeof second === 'string' && second !== first, 'после ротации ключ другой');
    });

    finish();
})().catch((err) => { console.error(err); process.exitCode = 1; });
