'use strict';
// Загрузка истории при сбое отметки прочитанного (ревью W7 R2.9): GET /api/messages/:chatId
// на первой странице сдвигает last_read_seq (markChatRead). Раньше сбой этого UPDATE
// (взаимная блокировка с отправкой, таймаут блокировки) ломал саму загрузку истории.
// Теперь он пишется в лог, а история приходит.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

// Короткий lock_timeout: отметка прочитанного не дожидается строки chats, которую держит тест.
const suite = createSuite('history-read-failure', { env: { DB_LOCK_TIMEOUT_MS: '1000' } });

test('сбой отметки прочитанного не ломает загрузку истории', async () => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const { ownerChat, memberChat } = await roomWithMember(owner, member);
    await owner.isRoomChat(ownerChat.id);
    const sent = await owner.send(ownerChat.id, 'непрочитанное');
    const mark = suite.server.logs.mark();

    const hold = await suite.db.connect();
    let history;
    try {
        await hold.query('BEGIN');
        await hold.query('SELECT id FROM chats WHERE id = $1 FOR UPDATE', [memberChat.id]);
        history = await member.get(`/api/messages/${memberChat.id}`);
    } finally {
        await hold.query('ROLLBACK').catch(() => {});
        hold.release();
    }
    assert.strictEqual(history.status, 200, JSON.stringify(history.body));
    assert.strictEqual(history.body.success, true, JSON.stringify(history.body));
    assert.deepStrictEqual(history.body.messages.map(m => m.id), [sent.id]);
    await suite.server.logs.waitFor(/\[Chats\] Не удалось отметить прочитанное при загрузке истории/, { from: mark });

    // Без замка отметка проходит при следующей загрузке.
    await member.messages(memberChat.id);
    await waitUntil(async () => Number((await suite.query('SELECT last_read_seq FROM chats WHERE id = $1', [memberChat.id])).rows[0].last_read_seq) === sent.seq,
        { what: 'отметка прочитанного после снятия замка' });
});
