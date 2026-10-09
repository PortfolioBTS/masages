'use strict';
// Отметки о прочтении (контракт волны 1, §5/§7; roadmap R7): по умолчанию
// выключены. Пока читатель их не включил, собеседник не получает
// messagesRead, а статус его сообщений остаётся «отправлено». Включённые у
// обоих — работают: событие приходит, статус «прочитано».
//
// События смотрим только у комнаты между людьми: чат с ботом отвечает
// «прочитано» сам (бот — не человек, ему нечего скрывать).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('read-receipts');

const status = async (messageId) => (await suite.query('SELECT status FROM messages WHERE id = $1', [messageId])).rows[0].status;

// Владелец и участник комнаты; сокет владельца подключён ДО комнаты (подписка на новые комнаты — через личную комнату).
async function pair(t) {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const sock = await owner.socket();
    t.after(() => sock.close());
    const room = await roomWithMember(owner, member, { name: 'Читаем' });
    return { owner, member, sock, ...room };
}

const setReceipts = async (client, value) => {
    const res = await client.post('/api/user/privacy', { readReceipts: value });
    assert.deepStrictEqual(res.body, { success: true, readReceipts: value });
};

// Участник «открыл чат» двумя способами, как это делает клиент: история и явное «показал до id».
const readByHistory = (p) => p.member.messages(p.memberChat.id);
const readByMarker = async (p, upToId) => {
    const res = await p.member.post(`/api/chats/${p.memberChat.id}/read`, { upToId });
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
};

// События вернулись бы раньше следующего сообщения того же сокета: ждём сообщение-«барьер» и смотрим, что накопилось.
async function receiptsAfterBarrier(p) {
    const barrier = await p.member.send(p.memberChat.id, 'барьер');
    await p.sock.waitFor('newMessage', m => m.id === barrier.id);
    return p.sock.collect('messagesRead').filter(e => e.room_id === p.roomId);
}

test('у нового аккаунта отметки выключены везде: регистрация, /api/auth, /api/user, колонка; прочтение собеседником событий не даёт', async (t) => {
    const p = await pair(t);
    for (const client of [p.owner, p.member]) {
        assert.strictEqual(client.user.readReceipts, false, 'ответ регистрации');
        assert.strictEqual((await client.auth()).user.readReceipts, false, '/api/auth');
        assert.strictEqual((await client.get('/api/user')).body.user.readReceipts, false, '/api/user');
        assert.strictEqual((await suite.query('SELECT read_receipts FROM users WHERE id = $1', [client.user.id])).rows[0].read_receipts, false, 'users.read_receipts');
    }

    const sent = await p.owner.send(p.ownerChat.id, 'прочитай меня');
    await readByHistory(p);
    const events = await receiptsAfterBarrier(p);
    assert.deepStrictEqual(events, [], 'событие messagesRead не должно прийти, пока участник не включил отметки');
    assert.strictEqual(await status(sent.id), 'sent', 'статус сообщения не меняется');

    // Второй способ отметить прочитанное — то же самое.
    const second = await p.owner.send(p.ownerChat.id, 'и ещё одно');
    await readByMarker(p, second.id);
    assert.deepStrictEqual(await receiptsAfterBarrier(p), []);
    assert.strictEqual(await status(second.id), 'sent');
    // Личный маркер читателя двигается: непрочитанных у него нет (отметки скрывают его, а не мешают ему читать).
    const chat = (await p.member.chats()).find(c => c.id === p.memberChat.id);
    assert.strictEqual(Number(chat.unread), 0, 'у читателя непрочитанных нет');
});

test('включены у обоих: событие messagesRead приходит автору, статус «прочитано»; в событии нет данных о читателе', async (t) => {
    const p = await pair(t);
    await setReceipts(p.owner, true);
    await setReceipts(p.member, true);
    assert.strictEqual((await p.owner.get('/api/user')).body.user.readReceipts, true);
    assert.strictEqual((await p.member.auth()).user.readReceipts, true);

    const first = await p.owner.send(p.ownerChat.id, 'первое');
    await readByHistory(p);
    const event = await p.sock.waitFor('messagesRead', e => e.room_id === p.roomId && e.up_to_id >= first.id);
    assert.deepStrictEqual(Object.keys(event).sort(), ['chat_id', 'room_id', 'up_to_id'], 'кто именно прочитал, в событии не раскрывается');
    assert.strictEqual(await status(first.id), 'read');

    // Тот же путь через явный маркер «показал до id».
    const second = await p.owner.send(p.ownerChat.id, 'второе');
    await readByMarker(p, second.id);
    const again = await p.sock.waitFor('messagesRead', e => e.room_id === p.roomId && e.up_to_id >= second.id);
    assert.ok(again.up_to_id >= second.id);
    assert.strictEqual(await status(second.id), 'read');
    const seen = (await p.owner.messages(p.ownerChat.id)).messages.find(m => m.id === second.id);
    assert.strictEqual(seen.status, 'read', 'автор видит «прочитано» в истории');
});

test('решает читатель: у читателя выключено — события нет, даже если у автора включено; включил — события идут', async (t) => {
    const p = await pair(t);
    await setReceipts(p.owner, true);

    const hidden = await p.owner.send(p.ownerChat.id, 'читатель скрывает');
    await readByHistory(p);
    assert.deepStrictEqual(await receiptsAfterBarrier(p), []);
    assert.strictEqual(await status(hidden.id), 'sent');

    await setReceipts(p.member, true);
    const visible = await p.owner.send(p.ownerChat.id, 'теперь видно');
    await readByHistory(p);
    const event = await p.sock.waitFor('messagesRead', e => e.room_id === p.roomId && e.up_to_id >= visible.id);
    assert.ok(event.up_to_id >= visible.id);
    assert.strictEqual(await status(visible.id), 'read');
    // Скрытое ранее прочтение задним числом не раскрывается: оно было до включения.
    assert.strictEqual(await status(hidden.id), 'sent');

    // Выключил обратно — снова тишина.
    await setReceipts(p.member, false);
    const quiet = await p.owner.send(p.ownerChat.id, 'снова скрыто');
    await readByHistory(p);
    const before = p.sock.collect('messagesRead').filter(e => e.room_id === p.roomId).length;
    assert.strictEqual((await receiptsAfterBarrier(p)).length, before, 'после выключения новых событий нет');
    assert.strictEqual(await status(quiet.id), 'sent');
});

test('настройка: только булево значение; без входа — «Не авторизован»; сохраняется в аккаунте', async () => {
    const guest = suite.client();
    assert.deepStrictEqual((await guest.post('/api/user/privacy', { readReceipts: true })).body, { success: false, message: 'Не авторизован' });

    const client = suite.client();
    const user = await client.registerAnon();
    for (const value of ['true', 1, null, undefined, [], {}]) {
        const res = await client.post('/api/user/privacy', { readReceipts: value });
        assert.strictEqual(res.body.success, false, JSON.stringify(value));
    }
    assert.strictEqual((await client.post('/api/user/privacy', {})).body.success, false);
    assert.strictEqual((await client.get('/api/user')).body.user.readReceipts, false, 'отказы ничего не включили');

    await setReceipts(client, true);
    assert.strictEqual((await suite.query('SELECT read_receipts FROM users WHERE id = $1', [user.id])).rows[0].read_receipts, true);
    await suite.server.restart();
    assert.strictEqual((await client.auth()).user.readReceipts, true, 'настройка переживает перезапуск');
    await setReceipts(client, false);
    assert.strictEqual((await client.get('/api/user')).body.user.readReceipts, false);
});
