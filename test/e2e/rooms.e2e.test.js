'use strict';
// Комнаты: создание → код приглашения → предпросмотр → заявка → одобрение;
// новичок видит только новые сообщения; выход; последний вышедший удаляет
// комнату со всей историей; события сокета на каждом шаге.
//
// Сокеты подключаются ДО действий, события которых ждут: подписка на новую
// комнату приходит через личную комнату user:<id> (subscribeUserToChat) —
// детерминированно, без гонки с автоподпиской при подключении.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { INVALID_INVITE_MESSAGE } = require('../../lib/invites');

const suite = createSuite('rooms');

test('полный цикл комнаты с сокетами', async (t) => {
    const owner = suite.client({ name: 'владелец' });
    const guest = suite.client({ name: 'гость' });
    await owner.registerAnon();
    await guest.registerAnon();
    const ownerSock = await owner.socket();
    const guestSock = await guest.socket();
    t.after(() => Promise.all([ownerSock.close(), guestSock.close()]));

    // Создание: владелец подписан на комнату сразу.
    const ownerChat = await owner.createRoom('Команда');
    const roomId = ownerChat.room_id;
    assert.ok(roomId);
    assert.strictEqual(ownerChat.name, 'Команда');
    await ownerSock.waitFor('chatListChanged');
    const before = await owner.send(ownerChat.id, 'до вступления гостя');

    // Код и предпросмотр.
    const invite = await owner.invite(ownerChat.id);
    assert.match(invite.code, /^[0-9A-Z]{20,}$/);
    assert.strictEqual(invite.requireApproval, true);
    assert.strictEqual(invite.memberCount, 1);
    const preview = await guest.joinPreview(invite.code);
    assert.deepStrictEqual(preview, { success: true, roomName: 'Команда', memberCount: 1, requireApproval: true });
    const wrong = await guest.post('/api/chats/join/preview', { code: 'Z'.repeat(26) });
    assert.deepStrictEqual(wrong.body, { success: false, message: INVALID_INVITE_MESSAGE });

    // Заявка: участники узнают по сокету, у заявителя — «ожидает одобрения».
    const joinMark = ownerSock.mark();
    const pending = await guest.join(invite.code);
    assert.strictEqual(pending.pending, true);
    assert.strictEqual(pending.roomName, 'Команда');
    assert.deepStrictEqual(await ownerSock.waitFor('joinRequestsChanged', p => p.roomId === roomId, { since: joinMark }), { roomId });
    const mine = await guest.get('/api/join-requests/mine');
    assert.deepStrictEqual(mine.body.requests.map(r => [r.id, r.roomName]), [[pending.requestId, 'Команда']]);
    const requests = await owner.joinRequests(ownerChat.id);
    assert.deepStrictEqual(requests.map(r => [r.id, r.userId, r.username]), [[pending.requestId, guest.user.id, guest.user.username]]);
    // Пока заявка не одобрена, комнаты у гостя нет.
    assert.ok(!(await guest.chats()).some(c => c.room_id === roomId));

    // Одобрение: гостю — решение с чатом, участникам — новый состав.
    const approveMark = ownerSock.mark();
    await owner.approve(pending.requestId);
    const decided = await guestSock.waitFor('joinRequestDecided', p => p.requestId === pending.requestId);
    assert.strictEqual(decided.approved, true);
    assert.strictEqual(decided.chat.room_id, roomId);
    await ownerSock.waitFor('roomMembersChanged', p => p.roomId === roomId, { since: approveMark });
    const guestChat = (await guest.chats()).find(c => c.room_id === roomId);
    assert.ok(guestChat, 'у гостя появился чат комнаты');
    assert.strictEqual(guestChat.member_count, 2);
    assert.deepStrictEqual(await owner.joinRequests(ownerChat.id), []);

    // Новичок видит только новое.
    const after = await owner.send(ownerChat.id, 'после вступления гостя');
    const delivered = await guestSock.waitFor('newMessage', m => m.id === after.id);
    assert.strictEqual(delivered.text, 'после вступления гостя');
    const guestView = await guest.messages(guestChat.id);
    assert.deepStrictEqual(guestView.messages.map(m => m.text), ['после вступления гостя']);
    assert.ok(!guestSock.collect('newMessage').some(m => m.id === before.id), 'старое сообщение гостю не приходило');
    const ownerView = await owner.messages(ownerChat.id);
    assert.deepStrictEqual(ownerView.messages.map(m => m.text), ['до вступления гостя', 'после вступления гостя']);

    // Гость пишет — владелец получает.
    const reply = await guest.send(guestChat.id, 'привет от гостя');
    assert.strictEqual((await ownerSock.waitFor('newMessage', m => m.id === reply.id)).text, 'привет от гостя');

    // Выход гостя: комната живёт, состав обновился.
    const leaveMark = ownerSock.mark();
    await guest.leave(guestChat.id);
    await ownerSock.waitFor('roomMembersChanged', p => p.roomId === roomId, { since: leaveMark });
    assert.ok(!(await guest.chats()).some(c => c.room_id === roomId));
    assert.strictEqual((await owner.chats()).find(c => c.room_id === roomId).member_count, 1);
    const kept = await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [roomId]);
    assert.strictEqual(kept.rows[0].n, 3, 'история комнаты остаётся оставшимся');

    // Последний вышел — комната удалена вместе с историей и кодом.
    await owner.leave(ownerChat.id);
    const rooms = await suite.query('SELECT count(*)::int AS n FROM rooms WHERE id = $1', [roomId]);
    assert.strictEqual(rooms.rows[0].n, 0);
    const messages = await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [roomId]);
    assert.strictEqual(messages.rows[0].n, 0);
    const gone = await guest.post('/api/chats/join/preview', { code: invite.code });
    assert.deepStrictEqual(gone.body, { success: false, message: INVALID_INVITE_MESSAGE });
});

test('отклонённая заявка: заявитель узнаёт по сокету, комнаты у него нет', async (t) => {
    const owner = suite.client();
    const guest = suite.client();
    await owner.registerAnon();
    await guest.registerAnon();
    const guestSock = await guest.socket();
    t.after(() => guestSock.close());

    const chat = await owner.createRoom('Закрытая');
    const { code } = await owner.invite(chat.id);
    const pending = await guest.join(code);
    await owner.deny(pending.requestId);
    const decided = await guestSock.waitFor('joinRequestDecided', p => p.requestId === pending.requestId);
    assert.strictEqual(decided.approved, false);
    assert.ok(!(await guest.chats()).some(c => c.room_id === chat.room_id));
    assert.deepStrictEqual((await guest.get('/api/join-requests/mine')).body.requests, []);
});
