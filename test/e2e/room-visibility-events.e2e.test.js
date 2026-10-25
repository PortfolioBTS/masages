'use strict';
// Граница видимости и события сокета (ревью W7 R2.3; docs/security/message-ordering.md, О2
// раздел 10): newMessage уходит после COMMIT, и новичок, одобренный между вставкой
// сообщения и рассылкой, уже подписан на room:<id>. Раньше он получал по сокету
// сообщение с seq = своему visible_from_seq — сообщение «до себя», которого нет в его
// истории. Теперь рассылка исключает участников с visible_from_seq >= seq.
//
// Окно между COMMIT и рассылкой расширяется так же, как в воспроизведении ревьюера
// (emit.test.js): тест держит строку chats отправителя, и сдвиг его маркера прочитанного
// (UPDATE chats после COMMIT вставки, до рассылки) ждёт, пока новичка одобряют.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

const suite = createSuite('room-visibility-events');

test('новичок, одобренный между COMMIT сообщения и рассылкой, не получает это сообщение по сокету', async () => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    const newcomer = suite.client({ name: 'новичок' });
    await owner.registerAnon();
    await member.registerAnon();
    await newcomer.registerAnon();
    const { roomId, ownerChat } = await roomWithMember(owner, member);
    const { code } = await owner.invite(ownerChat.id);
    const pending = await newcomer.join(code);
    await owner.isRoomChat(ownerChat.id);
    const memberSocket = await member.socket();
    const newcomerSocket = await newcomer.socket();
    try {
        const memberMark = memberSocket.mark();
        const newcomerMark = newcomerSocket.mark();

        let sent;
        const hold = await suite.db.connect();
        try {
            await hold.query('BEGIN');
            await hold.query('SELECT id FROM chats WHERE id = $1 FOR UPDATE', [ownerChat.id]);
            const body = await owner.messageBody(ownerChat.id, 'до вступления', {});
            const sending = owner.post('/api/messages', body);
            await waitUntil(async () => (await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [roomId])).rows[0].n === 1,
                { what: 'сообщение зафиксировано, рассылки ещё не было' });
            // Новичок вступает, пока событие ещё не отправлено.
            await owner.approve(pending.requestId);
            await hold.query('COMMIT');
            sent = await sending;
        } finally {
            await hold.query('ROLLBACK').catch(() => {});
            hold.release();
        }
        assert.ok(sent.body && sent.body.success, `отправка: ${JSON.stringify(sent.body)}`);
        const first = sent.body.message;
        const boundary = (await suite.query('SELECT visible_from_seq AS v FROM room_participants WHERE room_id = $1 AND user_id = $2', [roomId, newcomer.user.id])).rows[0].v;
        assert.ok(Number(first.seq) <= Number(boundary), `сообщение под границей новичка: seq ${first.seq}, граница ${boundary}`);

        // Старый участник событие получил.
        await memberSocket.waitFor('newMessage', (m) => m.id === first.id, { since: memberMark });

        // Следующее сообщение новичку видно; события сокета приходят по порядку, поэтому
        // когда пришло оно, первое уже пришло бы, если бы его отправили.
        const second = await owner.send(ownerChat.id, 'после вступления');
        await newcomerSocket.waitFor('newMessage', (m) => m.id === second.id, { since: newcomerMark });
        const heard = newcomerSocket.collect('newMessage', { since: newcomerMark }).map(m => m.id);
        assert.deepStrictEqual(heard, [second.id], 'новичку не ушло сообщение под его границей видимости');

        // И в истории новичка его нет — сокет и HTTP согласованы.
        const newcomerChat = (await newcomer.chats()).find(c => c.room_id === roomId);
        const history = await newcomer.messages(newcomerChat.id);
        assert.deepStrictEqual(history.messages.map(m => m.id), [second.id]);
    } finally {
        await memberSocket.close();
        await newcomerSocket.close();
    }
});

// Находка T7.4 (тот же класс, что R2.3): messageDeleted исчезающих сообщений и удаления
// автором уходил всей комнате — новичок узнавал об удалении сообщения, которого для него нет.
test('новичок не получает messageDeleted для сообщений до своего вступления (таймер и удаление автором)', async () => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    const newcomer = suite.client({ name: 'новичок' });
    await owner.registerAnon();
    await member.registerAnon();
    await newcomer.registerAnon();
    const { roomId, ownerChat } = await roomWithMember(owner, member);
    await owner.isRoomChat(ownerChat.id);
    const byTimer = await owner.send(ownerChat.id, 'исчезнет по таймеру');
    const byAuthor = await owner.send(ownerChat.id, 'удалит автор');
    const { code } = await owner.invite(ownerChat.id);
    const pending = await newcomer.join(code);
    await owner.approve(pending.requestId);
    const memberSocket = await member.socket();
    const newcomerSocket = await newcomer.socket();
    try {
        const memberMark = memberSocket.mark();
        const newcomerMark = newcomerSocket.mark();
        const expiry = await owner.post(`/api/messages/${byTimer.id}/set-expiry`, { expirySeconds: 2 });
        assert.strictEqual(expiry.body.success, true, JSON.stringify(expiry.body));
        await owner.ok(owner.del(`/api/messages/${byAuthor.id}`), 'удаление автором');
        // Старый участник получает оба удаления.
        await memberSocket.waitFor('messageDeleted', (m) => m.id === byAuthor.id, { since: memberMark });
        await memberSocket.waitFor('messageDeleted', (m) => m.id === byTimer.id, { since: memberMark, timeoutMs: 15000 });
        // Сообщение после вступления: его удаление новичок получает — и, раз события идут
        // по порядку, к этому моменту получил бы и прежние.
        const after = await owner.send(ownerChat.id, 'после вступления');
        await owner.ok(owner.del(`/api/messages/${after.id}`), 'удаление автором');
        await newcomerSocket.waitFor('messageDeleted', (m) => m.id === after.id, { since: newcomerMark });
        const heard = newcomerSocket.collect('messageDeleted', { since: newcomerMark }).map(m => m.id);
        assert.deepStrictEqual(heard, [after.id], 'новичок не узнал об удалении сообщений до своего вступления');
        assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [roomId])).rows[0].n, 0);
    } finally {
        await memberSocket.close();
        await newcomerSocket.close();
    }
});
