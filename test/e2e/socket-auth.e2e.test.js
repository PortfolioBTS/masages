'use strict';
// Авторизация подписок socket.io (ревью W7 R5, В-2). Клиент ничего не подписывает сам: обработчика joinChat
// на сервере нет (T7.2), подписку на room:<id> / chat:<id> делает сервер - при подключении по строкам chats
// ПОЛЬЗОВАТЕЛЯ (src/realtime/socket-handlers.js) и при создании чата / входе в комнату (subscribeUserToChat).
// Если когда-нибудь вернётся обработчик подписки без проверки членства - или выборка чатов при подключении
// потеряет фильтр по владельцу, - посторонний начнёт получать шифротекст, время, seq, имена и размеры вложений
// чужих комнат и ответы бота чужого чата. Эти тесты ловят обе поломки.
//
// «Не получил» доказывается барьером: события одного сокета приходят в том порядке, в котором сервер их отправил,
// поэтому личное событие самого постороннего (chatListChanged от его же запроса), вызванное ПОСЛЕ всех действий
// владельца, означает: всё, что было послано раньше, уже дошло - или не придёт.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');
const { PROTO } = require('./helpers/client');

const suite = createSuite('socket-auth');
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Всё, что у сокета в истории после метки, кроме служебных пингов engine.io.
const eventsSince = (socket, since) => socket.history.slice(since).filter(e => e.event !== 'engine:ping');

// Ответ бота приходит не сразу (~0.6 с после сообщения) и уходит по chat:<id> чата с ботом.
const botReply = (socket, botChatId, afterSeq) => socket.waitFor('newMessage', m => m.chat_id === botChatId && m.sent === 0 && m.seq > afterSeq, { timeoutMs: 10000 });

test('посторонний шлёт joinChat на чужие room:/chat:/user: - ничего не подписано, события владельца к нему не доходят', async (t) => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    const stranger = suite.client({ name: 'посторонний' });
    const late = suite.client({ name: 'заявитель' });
    for (const c of [owner, member, stranger, late]) await c.registerAnon();
    const room = await roomWithMember(owner, member, { name: 'Чужая комната' });
    const ownerBot = await owner.botChat();

    const ownerSock = await owner.socket();
    const memberSock = await member.socket();
    const strangerSock = await stranger.socket();
    t.after(() => Promise.all([ownerSock.close(), memberSock.close(), strangerSock.close()]));

    // Посторонний пытается подписаться на всё чужое: комнату, чат комнаты, чат владельца с ботом (chat:<id> -
    // единственный вид ключа с chat_id) и личную комнату владельца (адресные события: key-share, заявки).
    const mark = strangerSock.mark();
    for (const key of [`room:${room.roomId}`, `chat:${room.ownerChat.id}`, `chat:${ownerBot.id}`, `user:${owner.user.id}`]) {
        strangerSock.emit('joinChat', key);
    }
    // Сервер событие отбрасывает без обращений к БД; пауза нужна только для того, чтобы поломка (обработчик с
    // запросом к БД) успела подписать сокет до действий владельца.
    await sleep(300);

    // Комната: отправка, правка, удаление, вложение, заявка и вступление третьего (смена состава).
    const sent = await owner.send(room.ownerChat.id, 'секрет комнаты');
    await owner.edit(sent.id, 'секрет комнаты, правка');
    await owner.ok(owner.del(`/api/messages/${sent.id}`), 'удаление сообщения комнаты');
    const file = await owner.uploadCipher(room.ownerChat.id, { label: 'secret.bin' });
    const { code } = await owner.invite(room.ownerChat.id);
    const pending = await late.join(code);
    await owner.approve(pending.requestId);
    // Чат с ботом: сообщение, ответ бота, правка и удаление своего сообщения.
    const asked = await owner.send(ownerBot.id, 'гайд');
    const reply = await botReply(ownerSock, ownerBot.id, asked.seq);
    const botEdit = await owner.put(`/api/messages/${asked.id}`, { text: 'правка вопроса боту', proto: PROTO });
    assert.strictEqual(botEdit.body.success, true, `правка сообщения в чате с ботом: ${JSON.stringify(botEdit.body)}`);
    await owner.ok(owner.del(`/api/messages/${asked.id}`), 'удаление сообщения в чате с ботом');

    // Контроль: владелец и участник видят свои события - значит, события действительно были отправлены.
    await ownerSock.waitFor('messageEdited', m => m.id === String(asked.id) && m.room_id === null);
    await ownerSock.waitFor('messageDeleted', m => m.id === String(asked.id));
    await memberSock.waitFor('newMessage', m => m.id === file.id);
    await memberSock.waitFor('messageEdited', m => m.id === String(sent.id));
    await memberSock.waitFor('messageDeleted', m => m.id === String(sent.id));
    await memberSock.waitFor('roomMembersChanged', p => p.roomId === room.roomId);
    assert.ok(reply.id, 'ответ бота дошёл владельцу');

    // Барьер: личное событие самого постороннего после всех действий владельца.
    const botChat = await stranger.botChat();
    const barrier = strangerSock.mark();
    await stranger.post(`/api/chats/${botChat.id}/prefs`, { pinned: true });
    await strangerSock.waitFor('chatListChanged', () => true, { since: barrier });

    const got = eventsSince(strangerSock, mark);
    assert.deepStrictEqual([...new Set(got.map(e => e.event))], ['chatListChanged'],
        `посторонний получил чужие события: ${got.map(e => e.event).join(", ")}`);
    // И свои подписки у него на месте: ответ бота ЕГО чата приходит ему (подписка делается сервером).
    const own = await stranger.send(botChat.id, 'гайд');
    const ownReply = await botReply(strangerSock, botChat.id, own.seq);
    assert.strictEqual(ownReply.chat_id, botChat.id);
});

test('вышедший участник: новое подключение не подписывает его на комнату, в которой его больше нет', async (t) => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member, { name: 'Выход и возврат сокета' });
    const memberBot = await member.botChat();
    const ownerSock = await owner.socket();

    // Контроль: пока участник в комнате, его новое подключение подписано на неё сервером при подключении.
    const insideSock = await member.socket();
    t.after(() => Promise.all([ownerSock.close(), insideSock.close()]));
    const inside = await owner.send(room.ownerChat.id, 'пока ты в комнате');
    await insideSock.waitFor('newMessage', m => m.id === inside.id);

    await member.leave(room.memberChat.id);

    // Новое подключение ПОСЛЕ выхода. Автоподписка идёт асинхронно после connect, поэтому ждём её завершения:
    // ответ бота (по chat:<id> чата с ботом) приходит только подписанному сокету.
    const afterSock = await member.socket();
    t.after(() => afterSock.close());
    const mark = afterSock.mark();
    const asked = await member.send(memberBot.id, 'гайд');
    await botReply(afterSock, memberBot.id, asked.seq);

    // Владелец делает в комнате всё, что видят её участники.
    const sent = await owner.send(room.ownerChat.id, 'после выхода');
    await owner.edit(sent.id, 'после выхода, правка');
    await owner.ok(owner.del(`/api/messages/${sent.id}`), 'удаление');
    await ownerSock.waitFor('messageDeleted', m => m.id === String(sent.id));

    const barrier = afterSock.mark();
    await member.post(`/api/chats/${memberBot.id}/prefs`, { pinned: true });
    await afterSock.waitFor('chatListChanged', () => true, { since: barrier });

    const got = eventsSince(afterSock, mark);
    // Допустимо только своё: личный chatListChanged и события чата с ботом (сообщение, ответ, прочитано).
    const foreign = got.filter(e => !(e.event === 'chatListChanged' || e.args[0].chat_id === memberBot.id));
    assert.deepStrictEqual(foreign.map(e => e.event), [],
        'подключение после выхода получило события комнаты');
});
