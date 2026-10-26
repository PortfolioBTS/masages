'use strict';
// Права на заявки и реакции (ревью W7 R5, В-5):
//   * отклонить заявку (POST /api/join-requests/:id/deny) может только участник комнаты, в которую она подана;
//   * отозвать заявку (DELETE /api/join-requests/:id) может только сам заявитель;
//   * реакцию на сообщение (POST и DELETE /api/reactions) может поставить только тот, кому сообщение видно:
//     участник комнаты, вступивший ДО сообщения. Посторонний, участник другой комнаты, вышедший и новичок
//     (сообщение под его границей видимости) получают «Сообщение недоступно».
// Везде проверяются и ответ, и таблицы (join_requests, reactions), и то, что событие не ушло заявителю.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');
const { dbSnapshot } = require('./helpers/db-snapshot');

const suite = createSuite('requests-reactions-access');

const REQUEST_NOT_FOUND = { success: false, message: 'Заявка не найдена' };
const MESSAGE_UNAVAILABLE = { success: false, message: 'Сообщение недоступно' };
// Версия итога (RR-6) у каждого ответа своя — сравнение тел без неё.
const withoutV = ({ v, ...rest }) => { assert.ok(Number.isSafeInteger(v) && v > 0, 'версия итога'); return rest; };
const LIKE = '👍';

const reactionRows = async (messageId) => (await suite.query('SELECT user_id, emoji FROM reactions WHERE message_id = $1 ORDER BY user_id', [messageId])).rows;
const requestRow = async (requestId) => (await suite.query('SELECT id, room_id, user_id FROM join_requests WHERE id = $1', [requestId])).rows[0] || null;

let worldPromise = null;
// Один мир на файл: комната владельца с участником, вышедшим и новичком, заявитель, посторонний и хозяин другой комнаты.
function world() {
    if (!worldPromise) {
        worldPromise = (async () => {
            const names = ['владелец', 'участник', 'вышедший', 'новичок', 'заявитель', 'посторонний', 'хозяин другой комнаты'];
            const [owner, member, leaver, newcomer, applicant, stranger, otherOwner] = names.map(name => suite.client({ name }));
            for (const client of [owner, member, leaver, newcomer, applicant, stranger, otherOwner]) await client.registerAnon();
            const room = await roomWithMember(owner, member, { name: 'Права' });
            const withLeaver = await (async () => {
                const { code } = await owner.invite(room.ownerChat.id);
                const pending = await leaver.join(code);
                await owner.approve(pending.requestId);
                return (await leaver.chats()).find(c => c.room_id === room.roomId);
            })();
            // Сообщение ДО вступления новичка и до выхода «вышедшего».
            const early = await owner.send(room.ownerChat.id, 'раннее сообщение');
            await leaver.leave(withLeaver.id);
            const { code } = await owner.invite(room.ownerChat.id);
            const joined = await newcomer.join(code);
            await owner.approve(joined.requestId);
            const late = await owner.send(room.ownerChat.id, 'позднее сообщение');
            const otherRoom = await otherOwner.createRoom('Чужая комната');
            const ownerBot = await owner.botChat();
            const botMessage = (await owner.messages(ownerBot.id)).messages[0];
            return { owner, member, leaver, newcomer, applicant, stranger, otherOwner, room, early, late, otherRoom, ownerBot, botMessage };
        })();
    }
    return worldPromise;
}

// ---------- заявки ----------

test('отклонить чужую заявку (deny) может только участник комнаты: посторонний, хозяин другой комнаты, вышедший, сам заявитель - нет', async (t) => {
    const w = await world();
    const { code } = await w.owner.invite(w.room.ownerChat.id);
    const pending = await w.applicant.join(code);
    assert.strictEqual(pending.pending, true);
    const sock = await w.applicant.socket();
    t.after(() => sock.close());
    const mark = sock.mark();

    const before = await dbSnapshot(suite);
    for (const [title, client] of [['посторонний', w.stranger], ['хозяин другой комнаты', w.otherOwner], ['вышедший', w.leaver]]) {
        const res = await client.post(`/api/join-requests/${pending.requestId}/deny`, {});
        assert.deepStrictEqual(res.body, REQUEST_NOT_FOUND, `${title}: отклонил чужую заявку`);
    }
    // Заявитель не вправе «отклонить» сам себя тем же маршрутом (для этого есть DELETE): он не участник комнаты.
    const self = await w.applicant.post(`/api/join-requests/${pending.requestId}/deny`, {});
    assert.deepStrictEqual(self.body, REQUEST_NOT_FOUND, 'заявитель отклонил свою заявку маршрутом участников');
    assert.deepStrictEqual(await dbSnapshot(suite), before, 'отказ изменил базу');
    assert.ok(await requestRow(pending.requestId), 'заявка на месте');

    // Событие решения заявителю не уходило: барьер - личное chatListChanged самого заявителя после всех попыток.
    const botChat = await w.applicant.botChat();
    const barrierMark = sock.mark();
    await w.applicant.post(`/api/chats/${botChat.id}/prefs`, { pinned: true });
    await sock.waitFor('chatListChanged', () => true, { since: barrierMark });
    assert.deepStrictEqual(sock.collect('joinRequestDecided', { since: mark }), [], 'заявитель получил решение, которого не было');

    // Контроль: участник комнаты отклоняет - и заявка пропадает, а заявитель узнаёт решение.
    const ok = await w.member.post(`/api/join-requests/${pending.requestId}/deny`, {});
    assert.deepStrictEqual(ok.body, { success: true });
    assert.strictEqual(await requestRow(pending.requestId), null);
    const decided = await sock.waitFor('joinRequestDecided', p => p.requestId === pending.requestId);
    assert.strictEqual(decided.approved, false);
});

test('отозвать чужую заявку (DELETE) может только сам заявитель: владелец комнаты, участник, посторонний, хозяин другой комнаты - нет', async () => {
    const w = await world();
    const { code } = await w.owner.invite(w.room.ownerChat.id);
    const pending = await w.applicant.join(code);
    const before = await dbSnapshot(suite);
    for (const [title, client] of [['владелец комнаты', w.owner], ['участник', w.member], ['посторонний', w.stranger], ['хозяин другой комнаты', w.otherOwner], ['вышедший', w.leaver]]) {
        const res = await client.del(`/api/join-requests/${pending.requestId}`);
        assert.deepStrictEqual(res.body, REQUEST_NOT_FOUND, `${title}: отозвал чужую заявку`);
    }
    assert.deepStrictEqual(await dbSnapshot(suite), before, 'отказ изменил базу');
    assert.ok(await requestRow(pending.requestId), 'заявка на месте');
    // Контроль: заявитель отзывает свою - заявка пропадает.
    const own = await w.applicant.del(`/api/join-requests/${pending.requestId}`);
    assert.deepStrictEqual(own.body, { success: true });
    assert.strictEqual(await requestRow(pending.requestId), null);
});

test('несуществующий и некорректный номер заявки - тот же отказ, что и для чужой', async () => {
    const w = await world();
    for (const id of [2147483000, 'abc', 0]) {
        assert.deepStrictEqual((await w.owner.post(`/api/join-requests/${id}/deny`, {})).body, REQUEST_NOT_FOUND, `deny ${id}`);
        assert.deepStrictEqual((await w.applicant.del(`/api/join-requests/${id}`)).body, REQUEST_NOT_FOUND, `DELETE ${id}`);
    }
});

// ---------- реакции ----------

test('реакция на сообщение комнаты: посторонний, хозяин другой комнаты, вышедший и новичок (сообщение до него) получают отказ, таблица не меняется', async () => {
    const w = await world();
    const before = await dbSnapshot(suite);
    const cases = [
        ['посторонний', w.stranger, w.early], ['посторонний', w.stranger, w.late],
        ['хозяин другой комнаты', w.otherOwner, w.early], ['хозяин другой комнаты', w.otherOwner, w.late],
        // Вышедший: оба сообщения были при нём или после, но членства уже нет.
        ['вышедший', w.leaver, w.early], ['вышедший', w.leaver, w.late],
        // Новичок вступил после раннего сообщения: оно под его границей видимости.
        ['новичок', w.newcomer, w.early],
    ];
    for (const [title, client, message] of cases) {
        const add = await client.post('/api/reactions', { messageId: message.id, emoji: LIKE });
        assert.deepStrictEqual(add.body, MESSAGE_UNAVAILABLE, `${title}: поставил реакцию на ${message.id}`);
        const remove = await client.del(`/api/reactions/${message.id}/${encodeURIComponent(LIKE)}`);
        assert.deepStrictEqual(remove.body, MESSAGE_UNAVAILABLE, `${title}: снял реакцию с ${message.id}`);
    }
    assert.deepStrictEqual(await dbSnapshot(suite), before, 'отказ изменил базу');
    assert.deepStrictEqual(await reactionRows(w.early.id), []);
    assert.deepStrictEqual(await reactionRows(w.late.id), []);
    // И участники ничего не видят: реакция не появилась в истории.
    const history = (await w.owner.messages(w.room.ownerChat.id)).messages;
    assert.deepStrictEqual(history.map(m => [m.id, m.reactions]), [[w.early.id, []], [w.late.id, []]]);
});

test('реакция на сообщение чата с ботом: чужому отказ (сообщение видно только владельцу чата)', async () => {
    const w = await world();
    const before = await dbSnapshot(suite);
    for (const [title, client] of [['посторонний', w.stranger], ['участник комнаты владельца', w.member], ['хозяин другой комнаты', w.otherOwner]]) {
        const add = await client.post('/api/reactions', { messageId: w.botMessage.id, emoji: LIKE });
        assert.deepStrictEqual(add.body, MESSAGE_UNAVAILABLE, `${title}: реакция на сообщение бота владельца`);
    }
    assert.deepStrictEqual(await dbSnapshot(suite), before);
});

test('контроль: участник и новичок (на позднее сообщение) ставят и снимают реакцию, она видна в истории', async () => {
    const w = await world();
    // Ответ и история - в форме T7.3 (ревью W7 R3 п.2): сколько поставили эмодзи и стоит ли оно у читающего.
    assert.deepStrictEqual(withoutV((await w.member.post('/api/reactions', { messageId: w.early.id, emoji: LIKE })).body), { success: true, count: 1, mine: true });
    assert.deepStrictEqual(withoutV((await w.newcomer.post('/api/reactions', { messageId: w.late.id, emoji: LIKE })).body), { success: true, count: 1, mine: true });
    assert.deepStrictEqual((await reactionRows(w.early.id)).map(r => Number(r.user_id)), [Number(w.member.user.id)]);
    assert.deepStrictEqual((await reactionRows(w.late.id)).map(r => Number(r.user_id)), [Number(w.newcomer.user.id)]);
    const history = (await w.owner.messages(w.room.ownerChat.id)).messages;
    const notMine = [{ emoji: LIKE, count: 1, mine: false }];
    assert.deepStrictEqual(history.map(m => [m.id, m.reactions]), [[w.early.id, notMine], [w.late.id, notMine]]);
    assert.deepStrictEqual(withoutV((await w.member.del(`/api/reactions/${w.early.id}/${encodeURIComponent(LIKE)}`)).body), { success: true, count: 0, mine: false });
    assert.deepStrictEqual(await reactionRows(w.early.id), []);
    // Владелец ставит на бота-сообщение свою реакцию - у чата с ботом он единственный, кому оно видно.
    assert.deepStrictEqual(withoutV((await w.owner.post('/api/reactions', { messageId: w.botMessage.id, emoji: LIKE })).body), { success: true, count: 1, mine: true });
});
