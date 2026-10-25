'use strict';
// Ответ на сообщение, которое удаляют в этот момент (ревью W7 R2.8; воспроизведение —
// misc.test.js ревьюера): проверка видимости цели прошла, но к вставке её строку уже
// удалили, и внешний ключ reply_to_id давал 23503 → «Ошибка отправки». Теперь сообщение
// уходит без ответа — так же, как если бы цели не было уже при проверке.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

const suite = createSuite('reply-target-gone');

test('цель ответа удаляется во время отправки: сообщение сохранено без ответа, ошибки в логе нет', async () => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const { roomId, ownerChat, memberChat } = await roomWithMember(owner, member);
    const target = await owner.send(ownerChat.id, 'цель');
    await member.isRoomChat(memberChat.id);
    const mark = suite.server.logs.mark();

    // Тест удаляет цель в своей транзакции и держит её: проверка видимости у сервера
    // ещё видит строку, а вставка ответа встаёт на внешнем ключе до COMMIT удаления.
    const hold = await suite.db.connect();
    let response;
    try {
        await hold.query('BEGIN');
        await hold.query('DELETE FROM messages WHERE id = $1', [target.id]);
        const body = await member.messageBody(memberChat.id, 'ответ', { replyToId: target.id });
        const sending = member.post('/api/messages', body);
        await waitUntil(async () => (await suite.query(
            `SELECT count(*)::int AS n FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`
        )).rows[0].n >= 1, { what: 'вставка ответа ждёт внешний ключ' });
        await hold.query('COMMIT');
        response = await sending;
    } finally {
        await hold.query('ROLLBACK').catch(() => {});
        hold.release();
    }
    assert.strictEqual(response.status, 200, JSON.stringify(response.body));
    assert.strictEqual(response.body.success, true, JSON.stringify(response.body));
    assert.ok(!response.body.message.reply_to, 'в ответе нет цитаты удалённого сообщения');
    const rows = (await suite.query('SELECT reply_to_id FROM messages WHERE room_id = $1', [roomId])).rows;
    assert.deepStrictEqual(rows, [{ reply_to_id: null }], 'в базе одно сообщение — ответ без ссылки');
    assert.ok(!/Send message error|23503/.test(suite.server.logs.text({ from: mark })), 'в логе нет ошибки отправки');
    // Получатель видит сообщение в истории.
    const history = await owner.messages(ownerChat.id);
    assert.deepStrictEqual(history.messages.map(m => m.id), [response.body.message.id]);
});
