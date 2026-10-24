'use strict';
// Реакции на сообщения (T7.3, п.2 ревью W7 R3): история отдаёт {emoji, count, mine}, а
// изменение реакции приходит остальным участникам событием reactionChanged — иначе после
// перезагрузки страницы снять свою реакцию нельзя, а собеседник не видит её до перезагрузки.
//
// Что охраняется:
//  * в истории по каждому эмодзи число поставивших и признак «моя» (у читающего);
//  * ответ на POST/DELETE несёт итоговое число (клиент ставит его, а не «+1»);
//  * событие reactionChanged: участникам комнаты без автора реакции, автору (всем его
//    вкладкам) — копия с mine; тем, кто вступил позже сообщения, и посторонним события нет;
//  * в событии нет данных о том, КТО поставил реакцию;
//  * чат с ботом: событие владельцу.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('reactions');

const LIKE = '\u{1F44D}';
const HEART = '❤️';

async function pair(t) {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const ownerSock = await owner.socket();
    const memberSock = await member.socket();
    t.after(() => Promise.all([ownerSock.close(), memberSock.close()]));
    const room = await roomWithMember(owner, member, { name: 'Реакции' });
    return { owner, member, ownerSock, memberSock, ...room };
}

const reactionsOf = async (client, chatId, messageId) =>
    (await client.messages(chatId)).messages.find(m => m.id === messageId).reactions;

// Сервер отдаёт реакции по порядку эмодзи (ORDER BY emoji).
const byEmoji = (list) => [...list].sort((a, b) => (a.emoji < b.emoji ? -1 : 1));

test('история: {emoji, count, mine} у каждого читающего; ответы POST/DELETE несут итоговое число', async (t) => {
    const p = await pair(t);
    const message = await p.owner.send(p.ownerChat.id, 'поставьте реакцию');
    assert.deepStrictEqual(await reactionsOf(p.owner, p.ownerChat.id, message.id), [], 'у нового сообщения реакций нет');

    const first = await p.member.post('/api/reactions', { messageId: message.id, emoji: LIKE });
    assert.deepStrictEqual(first.body, { success: true, count: 1, mine: true });
    const second = await p.owner.post('/api/reactions', { messageId: message.id, emoji: LIKE });
    assert.deepStrictEqual(second.body, { success: true, count: 2, mine: true });
    // Повтор того же — не удваивает (ON CONFLICT DO NOTHING).
    assert.strictEqual((await p.owner.post('/api/reactions', { messageId: message.id, emoji: LIKE })).body.count, 2);
    await p.owner.post('/api/reactions', { messageId: message.id, emoji: HEART });

    assert.deepStrictEqual(await reactionsOf(p.member, p.memberChat.id, message.id), byEmoji([
        { emoji: LIKE, count: 2, mine: true },
        { emoji: HEART, count: 1, mine: false },
    ]), 'участник: свой лайк отмечен, сердце чужое');
    assert.deepStrictEqual(await reactionsOf(p.owner, p.ownerChat.id, message.id), byEmoji([
        { emoji: LIKE, count: 2, mine: true },
        { emoji: HEART, count: 1, mine: true },
    ]), 'владелец: обе реакции его');

    // Снятие: после перезагрузки (новая история) признак «моя» позволяет снять реакцию.
    const removed = await p.member.del(`/api/reactions/${message.id}/${encodeURIComponent(LIKE)}`);
    assert.deepStrictEqual(removed.body, { success: true, count: 1, mine: false });
    const afterMember = await reactionsOf(p.member, p.memberChat.id, message.id);
    assert.deepStrictEqual(afterMember.find(r => r.emoji === LIKE), { emoji: LIKE, count: 1, mine: false });
    const gone = await p.owner.del(`/api/reactions/${message.id}/${encodeURIComponent(HEART)}`);
    assert.deepStrictEqual(gone.body, { success: true, count: 0, mine: false });
    assert.ok(!(await reactionsOf(p.owner, p.ownerChat.id, message.id)).some(r => r.emoji === HEART), 'реакция с нулём не отдаётся');
});

test('reactionChanged: остальным участникам — итог без mine, вкладкам автора — копия с mine', async (t) => {
    const p = await pair(t);
    const memberSecondTab = await p.member.socket();
    t.after(() => memberSecondTab.close());
    const message = await p.owner.send(p.ownerChat.id, 'для реакции');

    await p.member.post('/api/reactions', { messageId: message.id, emoji: LIKE });
    const seen = await p.ownerSock.waitFor('reactionChanged', e => e.id === String(message.id));
    assert.deepStrictEqual(seen, { id: String(message.id), emoji: LIKE, count: 1, room_id: p.roomId },
        'владелец видит итог; кто поставил, в событии не раскрывается, mine отсутствует');
    for (const sock of [p.memberSock, memberSecondTab]) {
        const own = await sock.waitFor('reactionChanged', e => e.id === String(message.id));
        assert.deepStrictEqual(own, { id: String(message.id), emoji: LIKE, count: 1, room_id: p.roomId, mine: true }, 'вкладки автора реакции получают mine: true');
    }

    // Снятие: автор получает mine: false, остальные — новое число.
    const markOwner = p.ownerSock.mark();
    const markMember = p.memberSock.mark();
    await p.member.del(`/api/reactions/${message.id}/${encodeURIComponent(LIKE)}`);
    const goneForOwner = await p.ownerSock.waitFor('reactionChanged', e => e.id === String(message.id), { since: markOwner });
    assert.deepStrictEqual(goneForOwner, { id: String(message.id), emoji: LIKE, count: 0, room_id: p.roomId });
    const goneForMember = await p.memberSock.waitFor('reactionChanged', e => e.id === String(message.id), { since: markMember });
    assert.deepStrictEqual(goneForMember, { id: String(message.id), emoji: LIKE, count: 0, room_id: p.roomId, mine: false });
});

test('событие не уходит тем, кто вступил после сообщения, и посторонним; на новое сообщение — уходит', async (t) => {
    const p = await pair(t);
    const outsider = suite.client();
    await outsider.registerAnon();
    const outsiderSock = await outsider.socket();
    t.after(() => outsiderSock.close());
    const old = await p.owner.send(p.ownerChat.id, 'сообщение до вступления');

    // Третий вступает позже; его сокет подключён заранее.
    const late = suite.client();
    await late.registerAnon();
    const lateSock = await late.socket();
    t.after(() => lateSock.close());
    const { code } = await p.owner.invite(p.ownerChat.id);
    const pending = await late.join(code);
    assert.ok(pending.pending, 'нужна заявка');
    await p.owner.approve(pending.requestId);
    const fresh = await p.owner.send(p.ownerChat.id, 'сообщение после вступления');

    const markOutsider = outsiderSock.mark();
    const markLate = lateSock.mark();
    await p.member.post('/api/reactions', { messageId: old.id, emoji: LIKE });
    await p.member.post('/api/reactions', { messageId: fresh.id, emoji: HEART });

    // Новое сообщение видно позднему участнику: событие по нему приходит; по старому — нет.
    await lateSock.waitFor('reactionChanged', e => e.id === String(fresh.id), { since: markLate });
    const lateEvents = lateSock.collect('reactionChanged', { since: markLate });
    assert.deepStrictEqual(lateEvents.map(e => e.id), [String(fresh.id)], 'о реакции на сообщение до вступления поздний участник не узнаёт');
    // Старое сообщение ему и по API недоступно.
    assert.strictEqual((await late.post('/api/reactions', { messageId: old.id, emoji: LIKE })).body.success, false);

    // Посторонний: дожидаемся своего события-«барьера» и смотрим, что накопилось.
    const own = await outsider.createRoom('барьер');
    await outsider.send(own.id, 'барьер');
    await outsiderSock.waitFor('newMessage', () => true, { since: markOutsider });
    assert.deepStrictEqual(outsiderSock.collect('reactionChanged', { since: markOutsider }), [], 'посторонний событий реакций не получает');
});

test('чат с ботом: событие приходит владельцу с chat_id и mine', async (t) => {
    const user = suite.client();
    await user.registerAnon();
    const sock = await user.socket();
    t.after(() => sock.close());
    const bot = await user.botChat();
    const message = await user.send(bot.id, 'привет');

    const res = await user.post('/api/reactions', { messageId: message.id, emoji: LIKE });
    assert.deepStrictEqual(res.body, { success: true, count: 1, mine: true });
    const event = await sock.waitFor('reactionChanged', e => e.id === String(message.id));
    assert.deepStrictEqual(event, { id: String(message.id), emoji: LIKE, count: 1, chat_id: bot.id, room_id: null, mine: true });
    assert.deepStrictEqual(await reactionsOf(user, bot.id, message.id), [{ emoji: LIKE, count: 1, mine: true }]);
});
