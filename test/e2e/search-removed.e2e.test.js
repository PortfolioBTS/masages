'use strict';
// Поиск только на устройстве (R6): серверного поиска нет. GET /api/search удалён —
// запросы к нему получают тот же JSON-404, что и любой неизвестный адрес, и не
// выполняют никакого поиска (сервер не видит, что ищет пользователь).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('search-removed');

test('GET /api/search — 404 как у любого неизвестного адреса, и с входом, и без него', async () => {
    const anonymous = suite.client();
    const unknown = await anonymous.get('/api/does-not-exist');
    const guest = await anonymous.get('/api/search?q=привет');
    assert.strictEqual(guest.status, 404);
    assert.deepStrictEqual(guest.body, unknown.body);

    const user = suite.client();
    await user.registerAnon();
    const bot = await user.botChat();
    await user.send(bot.id, 'секретное слово для поиска');
    const found = await user.get('/api/search?q=' + encodeURIComponent('секретное'));
    assert.strictEqual(found.status, 404, JSON.stringify(found.body));
    assert.deepStrictEqual(found.body, { success: false, message: 'Не найдено' }, 'результатов поиска нет, даже по открытому тексту бота');
    assert.strictEqual((await user.get('/api/search')).status, 404);
    assert.strictEqual((await user.get('/api/search?q=a&q=b')).status, 404);
});

test('поиск в комнатах серверу и не нужен: сообщения комнаты — конверты, их текст сервер не видит', async () => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member, { name: 'Поиск' });
    await owner.send(room.ownerChat.id, 'слово которое никто не найдёт на сервере');
    const res = await member.get('/api/search?q=' + encodeURIComponent('слово'));
    assert.strictEqual(res.status, 404);
    const stored = (await suite.query('SELECT text, encrypted FROM messages WHERE room_id = $1', [room.roomId])).rows;
    assert.strictEqual(stored.length, 1);
    assert.strictEqual(stored[0].encrypted, true);
    assert.ok(!stored[0].text.includes('слово'), 'в базе открытого текста комнаты нет');
});
