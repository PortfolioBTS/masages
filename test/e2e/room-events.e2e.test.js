'use strict';
// События сокета на границах членства комнаты (ревью W7 R5, В-4):
//   (а) вышедший участник не получает ничего из комнаты - его сокеты отписаны (leave.js: unsubscribeUserFromChat);
//   (б) новичок не получает событий о сообщениях, которые лежат под его границей видимости
//       (events.js: emitRoomMessageEvent, except по hiddenUserIds; sealed-sender.md, 8.1).
//
// «Не получил» доказывается барьером. Сокеты получают события в порядке их отправки сервером, поэтому
// последнее событие, которое сокет точно получит (для вышедшего - chatListChanged от его же действия, для
// новичка - событие по сообщению ПОСЛЕ вступления), означает, что все предыдущие уже дошли или не придут.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');

const suite = createSuite('room-events');

// События комнаты, которые вышедший или скрытый участник получать не должен (chatListChanged - личное, не из комнаты).
const ROOM_EVENTS = ['newMessage', 'messageEdited', 'messageDeleted', 'roomMembersChanged', 'joinRequestsChanged',
    'messagesRead', 'chatExpiryChanged'];

const roomEventsSince = (socket, since) => socket.history.slice(since)
    .filter(entry => ROOM_EVENTS.includes(entry.event))
    .map(entry => `${entry.event}:${JSON.stringify(entry.args[0])}`);

test('после выхода из комнаты сокет участника не получает ни сообщений, ни правок, ни удалений, ни смены состава', async (t) => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member, { name: 'Выход' });
    const ownerSock = await owner.socket();
    const memberSock = await member.socket();
    t.after(() => Promise.all([ownerSock.close(), memberSock.close()]));

    // Контроль: пока участник в комнате, сообщение до него доходит (иначе «ничего не пришло» ничего не значит).
    const before = await owner.send(room.ownerChat.id, 'пока ты в комнате');
    assert.strictEqual((await memberSock.waitFor('newMessage', m => m.id === before.id)).id, before.id);

    const leaveMark = memberSock.mark();
    await member.leave(room.memberChat.id);
    await memberSock.waitFor('chatListChanged', () => true, { since: leaveMark });

    // Всё, что делает владелец после выхода: сообщение, правка, удаление, ещё сообщение, смена таймера.
    const ownerMark = ownerSock.mark();
    const sent = await owner.send(room.ownerChat.id, 'после выхода');
    await owner.edit(sent.id, 'после выхода, правка');
    await owner.ok(owner.del(`/api/messages/${sent.id}`), 'удаление сообщения');
    const last = await owner.send(room.ownerChat.id, 'после выхода, последнее');
    await owner.post(`/api/chats/${room.ownerChat.id}/expiry`, { seconds: 3600 });
    // Владелец события видит (значит, они были отправлены), вышедший - нет.
    await ownerSock.waitFor('messageDeleted', m => m.id === String(sent.id), { since: ownerMark });
    await ownerSock.waitFor('chatExpiryChanged', () => true, { since: ownerMark });

    // Барьер: личное событие самого вышедшего, вызванное ПОСЛЕ всех действий владельца.
    const botChat = await member.botChat();
    const barrierMark = memberSock.mark();
    await member.post(`/api/chats/${botChat.id}/prefs`, { pinned: true });
    await memberSock.waitFor('chatListChanged', () => true, { since: barrierMark });
    // С метки ДО запроса на выход: сюда попадает и roomMembersChanged самого выхода, и всё, что владелец сделал после.
    assert.deepStrictEqual(roomEventsSince(memberSock, leaveMark), [], 'вышедший получил события комнаты');
    assert.ok(last.id, 'последнее сообщение отправлено');
});

// Общая подготовка (б): владелец пишет до вступления гостя, гость вступает с подключённым сокетом, потом
// владелец пишет ещё. Возвращает сообщения до (под границей) и после (видимое) и сокет гостя.
async function guestJoinsAfterMessages(t, name) {
    const owner = suite.client({ name: 'владелец' });
    const guest = suite.client({ name: 'гость' });
    await owner.registerAnon();
    await guest.registerAnon();
    const ownerChat = await owner.createRoom(name);
    const hiddenEdit = await owner.send(ownerChat.id, 'до вступления, будет правка');
    const hiddenDelete = await owner.send(ownerChat.id, 'до вступления, будет удаление');
    const guestSock = await guest.socket();
    t.after(() => guestSock.close());

    const { code } = await owner.invite(ownerChat.id);
    const pending = await guest.join(code);
    await owner.approve(pending.requestId);
    await guestSock.waitFor('joinRequestDecided', p => p.requestId === pending.requestId);
    const guestChat = (await guest.chats()).find(c => c.room_id === ownerChat.room_id);

    // Контроль: сообщение после вступления гость получает - значит, он подписан на комнату.
    const visible = await owner.send(ownerChat.id, 'после вступления');
    await guestSock.waitFor('newMessage', m => m.id === visible.id);
    const bound = (await suite.query('SELECT visible_from_seq FROM room_participants WHERE room_id = $1 AND user_id = $2', [ownerChat.room_id, guest.user.id])).rows[0].visible_from_seq;
    assert.ok(hiddenEdit.seq <= bound && hiddenDelete.seq <= bound, 'сообщения до вступления лежат под границей видимости');
    assert.ok(visible.seq > bound, 'сообщение после вступления выше границы');
    return { owner, guest, ownerChat, guestChat, guestSock, hiddenEdit, hiddenDelete, visible };
}

test('новичок получает правку только сообщения после вступления; правка сообщения под границей до него не доходит', async (t) => {
    const w = await guestJoinsAfterMessages(t, 'Граница правки');
    const mark = w.guestSock.mark();
    // Правка скрытого сообщения - раньше правки видимого; видимая приходит позже и служит барьером.
    await w.owner.edit(w.hiddenEdit.id, 'скрытое, правка');
    await w.owner.edit(w.visible.id, 'видимое, правка');
    await w.guestSock.waitFor('messageEdited', m => m.id === String(w.visible.id), { since: mark });
    const edited = w.guestSock.collect('messageEdited', { since: mark }).map(m => m.id);
    assert.deepStrictEqual(edited, [String(w.visible.id)], 'гость получил правку скрытого сообщения (id, seq, новый шифротекст)');
    // И сама история: скрытого сообщения в ней нет ни в старом, ни в новом виде.
    const history = (await w.guest.messages(w.guestChat.id)).messages.map(m => m.id);
    assert.ok(!history.includes(String(w.hiddenEdit.id)), 'скрытое сообщение попало в историю гостя');
});

// Ошибка продакшен-кода, найденная этим тестом (не пробел тестов): удаление сообщения идёт через
// disappearingMessagesManager.deleteMessages -> onMessagesDeleted (src/services/expiry.js, createExpiry), который шлёт
// messageDeleted ВСЕЙ комнате без except по участникам с visible_from_seq >= seq. sealed-sender.md, строка 272, требует
// того же исключения, что у newMessage и messageEdited. Утечка небольшая (случайный id и room_id чужого для гостя
// сообщения), но граница видимости задумана без исключений. Исправляет владелец src/services/expiry.js.
test('новичок не получает messageDeleted для сообщения под границей видимости', {
    todo: 'src/services/expiry.js, onMessagesDeleted: messageDeleted уходит всей комнате без except по visible_from_seq (sealed-sender.md, 8.1)',
}, async (t) => {
    const w = await guestJoinsAfterMessages(t, 'Граница удаления');
    const mark = w.guestSock.mark();
    await w.owner.ok(w.owner.del(`/api/messages/${w.hiddenDelete.id}`), 'удаление скрытого сообщения');
    await w.owner.ok(w.owner.del(`/api/messages/${w.visible.id}`), 'удаление видимого сообщения');
    await w.guestSock.waitFor('messageDeleted', m => m.id === String(w.visible.id), { since: mark });
    const deleted = w.guestSock.collect('messageDeleted', { since: mark }).map(m => m.id);
    assert.deepStrictEqual(deleted, [String(w.visible.id)], 'гость узнал об удалении сообщения до своего вступления');
});

test('контроль набора: участник, который остался, получает те же события (fakeEnvelope сервера принимает правку)', async (t) => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member, { name: 'Контроль' });
    const memberSock = await member.socket();
    t.after(() => memberSock.close());
    const sent = await owner.send(room.ownerChat.id, 'раз');
    await owner.edit(sent.id, 'два');
    const edited = await memberSock.waitFor('messageEdited', m => m.id === String(sent.id));
    assert.strictEqual(edited.text, fakeEnvelope('два'));
    await owner.ok(owner.del(`/api/messages/${sent.id}`), 'удаление');
    assert.strictEqual((await memberSock.waitFor('messageDeleted', m => m.id === String(sent.id))).room_id, room.roomId);
});
