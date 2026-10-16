'use strict';
// Порядок, идентификаторы и время сообщений (docs/security/message-ordering.md,
// раздел 15, «Сквозные»). Настоящий Postgres: триггеры seq и надгробий, очередь
// на строке комнаты, блокировки.
//
// Порядок в файле: порядок и границы видимости (seq) → идентификаторы клиента,
// идемпотентность, надгробия → файлы → время → блокировки.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');
const { createAuthorTags } = require('../../lib/author-tag');

const suite = createSuite('messages-order');

const MINUTE_MS = 60 * 1000;

// Два аккаунта в одной комнате.
async function pair({ name } = {}) {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member, { name: name || 'Порядок' });
    return { owner, member, ...room };
}

const dbSeqs = async (roomId) => (await suite.query('SELECT seq FROM messages WHERE room_id = $1 ORDER BY seq', [roomId])).rows.map(r => r.seq);

// ---------- seq ----------

test('в ответах id — строка, seq — число; в базе id случайный, а seq растёт от случайной базы', async () => {
    const p = await pair();
    const first = await p.owner.send(p.ownerChat.id, 'раз');
    const second = await p.member.send(p.memberChat.id, 'два');
    for (const m of [first, second]) {
        assert.strictEqual(typeof m.id, 'string', 'id в ответе — строка');
        assert.match(m.id, /^[1-9]\d{6,9}$/);
        assert.strictEqual(typeof m.seq, 'number', 'seq в ответе — число');
    }
    assert.strictEqual(second.seq, first.seq + 1, 'seq подряд в одной комнате');
    const history = await p.member.messages(p.memberChat.id);
    assert.deepStrictEqual(history.messages.map(m => [typeof m.id, typeof m.seq]), [['string', 'number'], ['string', 'number']]);
    assert.deepStrictEqual(history.messages.map(m => m.id), [first.id, second.id]);
    const chats = await p.member.chats();
    const listed = chats.find(c => c.id === p.memberChat.id);
    assert.strictEqual(listed.last_message_id, second.id);
    assert.strictEqual(listed.last_message_seq, second.seq);
});

test('счётчик seq у комнат начинается со случайной базы: базы различаются и не равны нулю, новичок не узнаёт число сообщений до себя', async () => {
    const owner = suite.client();
    await owner.registerAnon();
    const rooms = [];
    for (let i = 0; i < 8; i++) rooms.push(await owner.createRoom(`База ${i}`));
    const bases = (await suite.query('SELECT id, msg_seq FROM rooms WHERE id = ANY($1::int[])', [rooms.map(r => r.room_id)])).rows.map(r => r.msg_seq);
    assert.strictEqual(new Set(bases).size, bases.length, `базы счётчиков различаются: ${bases}`);
    for (const base of bases) assert.ok(base > 0 && base < 2 ** 30, `база в [1; 2^30): ${base}`);
    // Первое сообщение комнаты получает seq = база + 1, а не 1.
    const first = await owner.send(rooms[0].id, 'первое');
    assert.ok(first.seq > 1, `первый seq не 1: ${first.seq}`);
    // Бот: у каждого чата с ботом своя база.
    const botSeqs = [];
    for (let i = 0; i < 4; i++) {
        const fresh = suite.client();
        await fresh.registerAnon();
        const bot = await fresh.botChat();
        botSeqs.push((await fresh.messages(bot.id)).messages[0].seq);
    }
    assert.strictEqual(new Set(botSeqs).size, botSeqs.length, `seq приветствий различаются: ${botSeqs}`);
    for (const seq of botSeqs) assert.ok(seq > 1, `seq приветствия бота не 1: ${seq}`);
});

test('N параллельных отправок в одну комнату: seq уникален, без дыр и без 40P01', async () => {
    const p = await pair();
    const mark = suite.server.logs.mark();
    const N = 24;
    const results = await Promise.all(Array.from({ length: N }, (_, i) => (i % 2 ? p.owner : p.member)
        .send(i % 2 ? p.ownerChat.id : p.memberChat.id, `параллельно ${i}`)));
    const seqs = results.map(m => m.seq);
    assert.strictEqual(new Set(seqs).size, N, 'все seq различны');
    const sorted = [...seqs].sort((a, b) => a - b);
    assert.strictEqual(sorted[N - 1] - sorted[0], N - 1, 'seq идут подряд, без дыр');
    assert.deepStrictEqual(await dbSeqs(p.roomId), sorted, 'в базе те же seq');
    const history = (await p.owner.messages(p.ownerChat.id)).messages;
    assert.deepStrictEqual(history.map(m => m.seq), sorted, 'история — строго по возрастанию seq');
    assert.ok(!suite.server.logs.find(/40P01/, { from: mark }), 'взаимных блокировок не было');
});

test('несколько сообщений за одну минуту от двоих приходят в порядке seq', async () => {
    const p = await pair();
    const order = [];
    for (let i = 0; i < 8; i++) {
        const who = i % 3 === 0 ? 'owner' : 'member';
        const m = who === 'owner'
            ? await p.owner.send(p.ownerChat.id, `№${i}`)
            : await p.member.send(p.memberChat.id, `№${i}`);
        order.push(m.id);
    }
    const history = (await p.member.messages(p.memberChat.id)).messages;
    assert.deepStrictEqual(history.map(m => m.id), order, 'порядок показа = порядок отправки');
    for (let i = 1; i < history.length; i++) assert.ok(history[i].seq > history[i - 1].seq);
    // created_at огрублён до минуты, и в пределах минуты по нему порядок не восстановить: порядок задаёт seq.
    const minutes = new Set(history.map(m => new Date(m.created_at).getTime()));
    for (const t of minutes) assert.strictEqual(t % MINUTE_MS, 0, 'created_at кратно минуте');
});

// ---------- граница видимости ----------

test('вступление и отправка одновременно: новичок видит ровно сообщения после своего visible_from_seq (несколько кругов)', async () => {
    let sawBefore = false;
    let sawAfter = false;
    for (let round = 0; round < 4; round++) {
        const owner = suite.client({ name: 'владелец' });
        const guest = suite.client({ name: 'гость' });
        await owner.registerAnon();
        await guest.registerAnon();
        const ownerChat = await owner.createRoom('Граница');
        const { code } = await owner.invite(ownerChat.id);
        const pending = await guest.join(code);
        for (let i = 0; i < 3; i++) await owner.send(ownerChat.id, `до ${i}`);

        // 12 отправок идут в то же время, что и одобрение заявки.
        const sends = Array.from({ length: 12 }, (_, i) => owner.send(ownerChat.id, `вместе ${i}`));
        const approval = owner.approve(pending.requestId);
        await Promise.all([approval, ...sends]);

        const guestChat = (await guest.chats()).find(c => c.room_id === ownerChat.room_id);
        const bound = (await suite.query('SELECT visible_from_seq FROM room_participants WHERE room_id = $1 AND user_id = $2', [ownerChat.room_id, guest.user.id])).rows[0].visible_from_seq;
        const all = (await suite.query('SELECT id, seq FROM messages WHERE room_id = $1', [ownerChat.room_id])).rows;
        const expected = all.filter(m => m.seq > bound).map(m => String(m.id)).sort();
        // Непрочитанное новичка начинается с той же границы (до открытия истории: она отмечает прочитанным).
        const unread = (await guest.chats()).find(c => c.id === guestChat.id).unread;
        assert.strictEqual(unread, expected.length, 'непрочитанное — только то, что видно');
        const seen = (await guest.messages(guestChat.id)).messages.map(m => m.id).sort();
        assert.deepStrictEqual(seen, expected, 'новичок видит ровно то, что отправлено после вступления');
        assert.ok(all.some(m => m.seq <= bound), 'до границы есть сообщения (по меньшей мере три первых)');
        assert.strictEqual(seen.length, all.length - all.filter(m => m.seq <= bound).length);
        sawBefore = sawBefore || all.filter(m => m.seq <= bound).length > 3;
        sawAfter = sawAfter || expected.length > 0;
    }
    // Не требуем конкретного исхода гонки, но за четыре круга сообщения обычно оказываются по обе стороны границы.
    assert.ok(sawBefore || sawAfter, 'гонка действительно шла');
});

test('граница видимости детерминированно: очередь на строке комнаты — отправка до вступления скрыта, после — видна', async () => {
    const owner = suite.client({ name: 'владелец' });
    const guest = suite.client({ name: 'гость' });
    await owner.registerAnon();
    await guest.registerAnon();
    const ownerChat = await owner.createRoom('Очередь');
    const { code } = await owner.invite(ownerChat.id);
    const pending = await guest.join(code);
    const blocked = async () => Number((await suite.query(
        `SELECT count(*) AS n FROM pg_stat_activity
         WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`)).rows[0].n);

    // Тест держит строку комнаты, как держала бы транзакция отправки: три запроса выстраиваются в очередь в известном порядке.
    const holder = await suite.db.connect();
    let beforeJoin, approval, afterJoin;
    try {
        await holder.query('BEGIN');
        await holder.query('SELECT id FROM rooms WHERE id = $1 FOR NO KEY UPDATE', [ownerChat.room_id]);
        beforeJoin = owner.send(ownerChat.id, 'в очереди до вступления');
        await waitUntil(async () => (await blocked()) >= 1, { what: 'первая отправка встала в очередь' });
        approval = owner.approve(pending.requestId);
        await waitUntil(async () => (await blocked()) >= 2, { what: 'вступление встало в очередь' });
        afterJoin = owner.send(ownerChat.id, 'в очереди после вступления');
        await waitUntil(async () => (await blocked()) >= 3, { what: 'вторая отправка встала в очередь' });
        await holder.query('COMMIT');
    } finally {
        await holder.query('ROLLBACK').catch(() => {});
        holder.release();
    }
    const [first, , second] = await Promise.all([beforeJoin, approval, afterJoin]);
    const bound = (await suite.query('SELECT visible_from_seq FROM room_participants WHERE room_id = $1 AND user_id = $2', [ownerChat.room_id, guest.user.id])).rows[0].visible_from_seq;
    assert.strictEqual(bound, first.seq, 'граница — seq последнего сообщения, зафиксированного до вступления');
    assert.ok(second.seq > bound, 'отправка, вставшая в очередь после вступления, получила seq больше границы');
    const guestChat = (await guest.chats()).find(c => c.room_id === ownerChat.room_id);
    const seen = (await guest.messages(guestChat.id)).messages;
    assert.deepStrictEqual(seen.map(m => m.id), [second.id], 'новичок видит только сообщение после вступления');
});

// ---------- история вверх, непрочитанное, прочтение ----------

test('пагинация вверх по beforeSeq: страницы подряд, без повторов и пропусков', async () => {
    const p = await pair();
    const sent = [];
    for (let i = 0; i < 25; i++) sent.push(await p.owner.send(p.ownerChat.id, `п${i}`));
    const newest = await p.member.get(`/api/messages/${p.memberChat.id}?limit=10`);
    assert.strictEqual(newest.body.hasMore, true);
    assert.deepStrictEqual(newest.body.messages.map(m => m.id), sent.slice(15).map(m => m.id));
    let cursor = newest.body.messages[0].seq;
    const collected = [...newest.body.messages];
    for (;;) {
        const page = await p.member.get(`/api/messages/${p.memberChat.id}?limit=10&beforeSeq=${cursor}`);
        assert.strictEqual(page.status, 200);
        collected.unshift(...page.body.messages);
        if (!page.body.hasMore) break;
        cursor = page.body.messages[0].seq;
    }
    assert.deepStrictEqual(collected.map(m => m.id), sent.map(m => m.id), 'все 25 сообщений ровно по разу и по порядку');
    const bad = await p.member.get(`/api/messages/${p.memberChat.id}?beforeSeq=abc`);
    assert.strictEqual(bad.status, 400);
    assert.strictEqual(bad.body.code, 'bad-seq');
});

test('старый клиент: ?before=<id> и { upToId } отвергаются с 400 client-outdated', async () => {
    const p = await pair();
    const sent = await p.owner.send(p.ownerChat.id, 'сообщение');
    const history = await p.member.get(`/api/messages/${p.memberChat.id}?before=${sent.id}`);
    assert.strictEqual(history.status, 400);
    assert.strictEqual(history.body.success, false);
    assert.strictEqual(history.body.code, 'client-outdated');
    assert.match(history.body.message, /Обновите страницу/);
    const read = await p.member.post(`/api/chats/${p.memberChat.id}/read`, { upToId: sent.id });
    assert.strictEqual(read.status, 400);
    assert.strictEqual(read.body.code, 'client-outdated');
});

test('счётчик непрочитанного и маркер прочтения: markChatRead по seq, больше существующего не отметить', async () => {
    const p = await pair();
    const sent = [];
    for (let i = 0; i < 5; i++) sent.push(await p.owner.send(p.ownerChat.id, `непрочитанное ${i}`));
    const unread = async () => (await p.member.chats()).find(c => c.id === p.memberChat.id).unread;
    assert.strictEqual(await unread(), 5);
    assert.strictEqual((await p.owner.chats()).find(c => c.id === p.ownerChat.id).unread, 0, 'свои сообщения не считаются');

    // Отметить до третьего: осталось два.
    const half = await p.member.post(`/api/chats/${p.memberChat.id}/read`, { upToSeq: sent[2].seq });
    assert.strictEqual(half.body.success, true);
    assert.strictEqual(await unread(), 2);
    // Маркер только растёт: отметка «назад» ничего не меняет.
    await p.member.post(`/api/chats/${p.memberChat.id}/read`, { upToSeq: sent[0].seq });
    assert.strictEqual(await unread(), 2);
    // Больше, чем есть: отмечается фактический максимум.
    const far = await p.member.post(`/api/chats/${p.memberChat.id}/read`, { upToSeq: 2147483647 });
    assert.strictEqual(far.body.success, true);
    assert.strictEqual(await unread(), 0);
    const marker = (await suite.query('SELECT last_read_seq FROM chats WHERE id = $1', [p.memberChat.id])).rows[0].last_read_seq;
    assert.strictEqual(marker, sent[4].seq, 'маркер = seq последнего существующего, а не присланное число');
    // Нечисловой upToSeq.
    const junk = await p.member.post(`/api/chats/${p.memberChat.id}/read`, { upToSeq: 'x' });
    assert.strictEqual(junk.body.success, false);
});

test('messagesRead { up_to_seq }: автору приходит seq, статус сообщений — read', async (t) => {
    const p = await pair();
    await p.owner.post('/api/user/privacy', { readReceipts: true });
    await p.member.post('/api/user/privacy', { readReceipts: true });
    const sock = await p.owner.socket();
    t.after(() => sock.close());
    const sent = await p.owner.send(p.ownerChat.id, 'прочитай');
    await p.member.messages(p.memberChat.id);
    const event = await sock.waitFor('messagesRead', e => e.room_id === p.roomId && e.up_to_seq >= sent.seq);
    assert.deepStrictEqual(Object.keys(event).sort(), ['chat_id', 'room_id', 'up_to_seq']);
    assert.strictEqual(typeof event.up_to_seq, 'number');
    assert.strictEqual((await suite.query('SELECT status FROM messages WHERE id = $1', [sent.id])).rows[0].status, 'read');
});

test('схема: колонок time, deleted, visible_from_id, last_read_message_id нет; seq, надгробия и триггеры есть', async () => {
    const cols = (await suite.query(
        `SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name IN ('messages', 'chats', 'room_participants', 'rooms')`)).rows
        .map(r => `${r.table_name}.${r.column_name}`);
    for (const gone of ['messages.time', 'messages.deleted', 'room_participants.visible_from_id', 'chats.last_read_message_id']) {
        assert.ok(!cols.includes(gone), `${gone} должна отсутствовать`);
    }
    for (const here of ['messages.seq', 'rooms.msg_seq', 'chats.msg_seq', 'chats.last_read_seq', 'room_participants.visible_from_seq']) {
        assert.ok(cols.includes(here), `${here} должна быть`);
    }
    const triggers = (await suite.query(`SELECT tgname FROM pg_trigger WHERE tgrelid = 'messages'::regclass AND NOT tgisinternal ORDER BY tgname`)).rows.map(r => r.tgname);
    assert.deepStrictEqual(triggers, ['messages_10_id_check', 'messages_20_seq', 'messages_90_tombstone']);
    const indexes = (await suite.query(`SELECT indexname FROM pg_indexes WHERE tablename = 'messages'`)).rows.map(r => r.indexname);
    assert.ok(indexes.includes('idx_messages_room_seq') && indexes.includes('idx_messages_chat_seq'));
    const dup = await suite.query(`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_messages_room_seq'`);
    assert.match(dup.rows[0].indexdef, /UNIQUE/);
});

// ---------- идентификаторы клиента ----------

const ID_CONFLICT_BODY = { success: false, code: 'id-conflict', message: 'Идентификатор сообщения занят, повторите отправку' };

const countRows = async (sql, params = []) => Number((await suite.query(sql, params)).rows[0].n);
const messageRows = (roomId) => countRows('SELECT count(*) AS n FROM messages WHERE room_id = $1', [roomId]);

test('сообщение в комнату без clientMessageId — 400 client-outdated; неверный формат — 400 bad-message-id; ничего не записано', async () => {
    const p = await pair();
    const before = await messageRows(p.roomId);
    for (const missing of [undefined, null, '']) {
        const res = await p.owner.sendRaw(p.ownerChat.id, 'без id', { clientMessageId: missing });
        assert.strictEqual(res.status, 400, JSON.stringify(missing));
        assert.strictEqual(res.body.success, false);
        assert.strictEqual(res.body.code, 'client-outdated');
        assert.match(res.body.message, /Обновите страницу/);
    }
    const bad = ['abc', '999999', '2147483648', '01234567', ' 1234567', '1234567 ', '1e7', '-1234567', '12345678901', 1234567, true, ['1234567'], {}];
    for (const value of bad) {
        const res = await p.owner.sendRaw(p.ownerChat.id, 'неверный id', { clientMessageId: value });
        assert.strictEqual(res.status, 400, JSON.stringify(value));
        assert.strictEqual(res.body.code, 'bad-message-id', JSON.stringify(value));
        assert.strictEqual(res.body.success, false);
    }
    assert.strictEqual(await messageRows(p.roomId), before, 'ни одна отправка с плохим id не записалась');
});

test('чат с ботом clientMessageId игнорирует: id выдаёт сервер, мусор в поле не мешает', async () => {
    const client = suite.client();
    await client.registerAnon();
    const bot = await client.botChat();
    const plain = await client.sendRaw(bot.id, 'привет', { clientMessageId: undefined });
    assert.strictEqual(plain.status, 200);
    assert.strictEqual(plain.body.success, true);
    const withJunk = await client.sendRaw(bot.id, 'ещё', { clientMessageId: 'abc' });
    assert.strictEqual(withJunk.status, 200, 'мусорное поле игнорируется');
    const chosen = await client.sendRaw(bot.id, 'и ещё', { clientMessageId: '1234567' });
    assert.notStrictEqual(chosen.body.message.id, '1234567', 'id чата с ботом выбирает сервер, а не клиент');
    assert.match(chosen.body.message.id, /^[1-9]\d{6,9}$/);
});

test('id сообщения комнаты — тот, что выбрал клиент; seq присваивает сервер', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const res = await p.owner.sendRaw(p.ownerChat.id, 'мой id', { clientMessageId: id });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.message.id, id);
    const row = (await suite.query('SELECT id, seq, room_id FROM messages WHERE id = $1', [id])).rows[0];
    assert.strictEqual(String(row.id), id);
    assert.strictEqual(row.seq, res.body.message.seq);
    // Игнорируется и seq, присланный клиентом: его выдаёт только триггер.
    const forged = await p.owner.sendRaw(p.ownerChat.id, 'свой seq', { seq: 1 });
    assert.ok(forged.body.message.seq > 1);
});

test('повтор того же запроса (потерян ответ) — 200 с сохранённой строкой, дубля и второй рассылки нет, seq не тратится', async (t) => {
    const p = await pair();
    const sock = await p.member.socket();
    t.after(() => sock.close());
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const first = await p.owner.sendRaw(p.ownerChat.id, 'один раз', { clientMessageId: id });
    const counterBefore = (await suite.query('SELECT msg_seq FROM rooms WHERE id = $1', [p.roomId])).rows[0].msg_seq;
    const second = await p.owner.sendRaw(p.ownerChat.id, 'один раз', { clientMessageId: id });
    assert.strictEqual(second.status, 200);
    assert.strictEqual(second.body.success, true);
    assert.strictEqual(second.body.message.id, first.body.message.id);
    assert.strictEqual(second.body.message.seq, first.body.message.seq);
    assert.strictEqual(second.body.message.text, fakeEnvelope('один раз'));
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM messages WHERE id = $1', [id]), 1);
    const counterAfter = (await suite.query('SELECT msg_seq FROM rooms WHERE id = $1', [p.roomId])).rows[0].msg_seq;
    assert.strictEqual(counterAfter, counterBefore, 'откат повторной вставки откатил и приращение seq');
    // Событие newMessage для этого id пришло ровно одно.
    const barrier = await p.owner.send(p.ownerChat.id, 'барьер');
    await sock.waitFor('newMessage', m => m.id === barrier.id);
    assert.strictEqual(sock.collect('newMessage').filter(m => m.id === id).length, 1);
});

test('одинаковые запросы одновременно — одна строка, все ответы 200 с одним seq', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const counterBefore = (await suite.query('SELECT msg_seq FROM rooms WHERE id = $1', [p.roomId])).rows[0].msg_seq;
    const mark = suite.server.logs.mark();
    const results = await Promise.all(Array.from({ length: 6 }, () => p.owner.sendRaw(p.ownerChat.id, 'гонка', { clientMessageId: id })));
    for (const res of results) {
        assert.strictEqual(res.status, 200, JSON.stringify(res.body));
        assert.strictEqual(res.body.message.id, id);
    }
    assert.strictEqual(new Set(results.map(r => r.body.message.seq)).size, 1, 'у всех ответов один seq');
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM messages WHERE id = $1', [id]), 1);
    const counterAfter = (await suite.query('SELECT msg_seq FROM rooms WHERE id = $1', [p.roomId])).rows[0].msg_seq;
    assert.strictEqual(counterAfter, counterBefore + 1, 'seq израсходован один раз');
    assert.ok(!suite.server.logs.find(/40P01|Send message error/, { from: mark }), 'ни взаимных блокировок, ни ошибок сервера');
});

test('конфликт id: чужое сообщение, другой текст, другая комната — 409 id-conflict, чужое не меняется, seq не тратится', async () => {
    const p = await pair();
    const other = await pair({ name: 'Другая' });
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const original = await p.owner.send(p.ownerChat.id, 'настоящее', { clientMessageId: id });
    const counterBefore = (await suite.query('SELECT msg_seq FROM rooms WHERE id = $1', [p.roomId])).rows[0].msg_seq;

    // Другой участник той же комнаты занимает id.
    const taken = await p.member.sendRaw(p.memberChat.id, 'настоящее', { clientMessageId: id });
    assert.strictEqual(taken.status, 409);
    assert.deepStrictEqual(taken.body, ID_CONFLICT_BODY);
    // Тот же автор, но другой текст.
    const different = await p.owner.sendRaw(p.ownerChat.id, 'другое содержимое', { clientMessageId: id });
    assert.strictEqual(different.status, 409);
    assert.deepStrictEqual(different.body, ID_CONFLICT_BODY);
    // Тот же id из чужой комнаты.
    const foreign = await other.owner.sendRaw(other.ownerChat.id, 'настоящее', { clientMessageId: id });
    assert.strictEqual(foreign.status, 409);
    assert.deepStrictEqual(foreign.body, ID_CONFLICT_BODY);

    const row = (await suite.query('SELECT room_id, user_id, author_tag, created_at FROM messages WHERE id = $1', [id])).rows[0];
    assert.strictEqual(row.room_id, p.roomId);
    assert.strictEqual(row.user_id, null, 'у строки комнаты автора в user_id нет');
    assert.ok(row.author_tag.equals(tagsLib().tagFor(p.roomId, p.owner.user.id, row.created_at)), 'автор строки - владелец (по тегу)');
    const history = (await p.member.messages(p.memberChat.id)).messages;
    assert.strictEqual(history.find(m => m.id === id).text, fakeEnvelope('настоящее'), 'чужое сообщение не изменилось');
    assert.strictEqual(history.find(m => m.id === id).seq, original.seq);
    const counterAfter = (await suite.query('SELECT msg_seq FROM rooms WHERE id = $1', [p.roomId])).rows[0].msg_seq;
    assert.strictEqual(counterAfter, counterBefore, 'проигравшие вставки откатились вместе с приращением seq');
    // Следующее обычное сообщение получает следующий seq, дыры нет.
    const next = await p.owner.send(p.ownerChat.id, 'после конфликтов');
    assert.strictEqual(next.seq, original.seq + 1);
});

// ---------- надгробия ----------

const tombstone = async (id) => (await suite.query('SELECT id, expires_at FROM message_tombstones WHERE id = $1', [id])).rows[0];

test('удаление автором оставляет надгробие: id занять нельзя, срок — сутки в пределах 30–31 суток; после просрочки и очистки id свободен', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    await p.owner.send(p.ownerChat.id, 'удалю', { clientMessageId: id });
    assert.strictEqual(await tombstone(id), undefined, 'пока сообщение живо, надгробия нет');
    assert.strictEqual((await p.owner.del(`/api/messages/${id}`)).body.success, true);

    const stone = await tombstone(id);
    assert.ok(stone, 'надгробие записано триггером');
    const check = (await suite.query(
        `SELECT date_trunc('day', expires_at) = expires_at AS whole_day,
                expires_at >= now() + interval '30 days' AS long_enough,
                expires_at <= now() + interval '31 days' AS not_too_long
         FROM message_tombstones WHERE id = $1`, [id])).rows[0];
    assert.deepStrictEqual(check, { whole_day: true, long_enough: true, not_too_long: true });
    const cols = (await suite.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'message_tombstones' ORDER BY 1`)).rows.map(r => r.column_name);
    assert.deepStrictEqual(cols, ['expires_at', 'id'], 'в надгробии нет ни комнаты, ни автора, ни точного времени');

    // Тот же автор с тем же текстом: строки нет, но id в надгробии — 409, а не «повтор».
    const reuse = await p.owner.sendRaw(p.ownerChat.id, 'удалю', { clientMessageId: id });
    assert.strictEqual(reuse.status, 409);
    assert.deepStrictEqual(reuse.body, ID_CONFLICT_BODY);
    const stranger = await p.member.sendRaw(p.memberChat.id, 'занять', { clientMessageId: id });
    assert.strictEqual(stranger.status, 409);

    // Сдвиг часов на 31 сутки и очистка надгробий: id принимается.
    await suite.time.rewindTombstone(id, 31 * 24 * 3600 * 1000 + 1000);
    await waitUntil(async () => !(await tombstone(id)), { what: 'очистка надгробий убрала просроченную запись', timeoutMs: 8000 });
    const again = await p.member.sendRaw(p.memberChat.id, 'занять', { clientMessageId: id });
    assert.strictEqual(again.status, 200, JSON.stringify(again.body));
    assert.strictEqual(again.body.message.id, id);
});

test('надгробие оставляют и таймер сообщения, и удаление аккаунта, и каскад комнаты', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    // Таймер: сообщение с коротким сроком исчезает само.
    const timed = await p.owner.send(p.ownerChat.id, 'исчезну', { expirySeconds: 1 });
    await waitUntil(async () => !(await suite.query('SELECT 1 FROM messages WHERE id = $1', [timed.id])).rows[0], { what: 'сообщение исчезло по таймеру', timeoutMs: 8000 });
    assert.ok(await tombstone(timed.id), 'по таймеру: надгробие есть');

    // Удаление аккаунта автора.
    const mine = newClientMessageId();
    const ownerMessage = await p.member.send(p.memberChat.id, 'аккаунт удалят', { clientMessageId: mine });
    await p.member.deleteAccount();
    assert.ok(await tombstone(ownerMessage.id), 'удаление аккаунта: надгробие есть');

    // Каскад комнаты: последний участник выходит, сообщения уходят вместе с комнатой.
    const lone = suite.client();
    await lone.registerAnon();
    const room = await lone.createRoom('Одинокая');
    const kept = await lone.send(room.id, 'уйду с комнатой');
    await lone.leave(room.id);
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM rooms WHERE id = $1', [room.room_id]), 0);
    assert.ok(await tombstone(kept.id), 'каскад комнаты: надгробие есть');
    // Чужой участник того же id занять не может.
    const anyone = await pair({ name: 'Занять' });
    const grab = await anyone.owner.sendRaw(anyone.ownerChat.id, 'занять', { clientMessageId: kept.id });
    assert.strictEqual(grab.status, 409);
});

test('просроченное надгробие, не убранное очисткой, не мешает; повторное удаление начинает срок заново', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    await p.owner.send(p.ownerChat.id, 'первое', { clientMessageId: id });
    await p.owner.del(`/api/messages/${id}`);
    // Срок вышел (очистка могла уже убрать строку, могла ещё нет): id свободен.
    await suite.query(`UPDATE message_tombstones SET expires_at = now() - interval '1 hour' WHERE id = $1`, [id]);
    const reuse = await p.owner.sendRaw(p.ownerChat.id, 'второе', { clientMessageId: id });
    assert.strictEqual(reuse.status, 200, JSON.stringify(reuse.body));
    // Второе удаление снова запрещает id на 30 суток, а не наследует прошлый срок.
    await p.owner.del(`/api/messages/${id}`);
    const stone = (await suite.query(`SELECT expires_at >= now() + interval '30 days' AS ok FROM message_tombstones WHERE id = $1`, [id])).rows[0];
    assert.ok(stone && stone.ok === true, 'срок надгробия начался заново');
});

// ---------- вложения ----------

const dirFiles = () => (fs.existsSync(suite.server.uploadsDir) ? fs.readdirSync(suite.server.uploadsDir).sort() : []);
// Сервер проверяет форму конверта (R7), поэтому нужен конверт правильной формы.
const ENVELOPE = fakeEnvelope('вложение');
const cipherBytes = () => crypto.randomBytes(300);

function uploadForm(fields, order = ['proto', 'chatId', 'encrypted', 'clientMessageId', 'envelope']) {
    const form = new FormData();
    const all = { proto: 4, ...fields };   // признак версии клиента (14.1) - первым полем, до файла
    for (const key of order) if (all[key] !== undefined) form.append(key, String(all[key]));
    form.append('file', new Blob([cipherBytes()], { type: 'application/octet-stream' }), 'file.bin');
    return form;
}
const postForm = (client, form) => client.request('POST', '/api/messages/file', { body: form });

test('вложение: имя файла случайное и без времени, mtime и atime кратны часу, id клиента, E2EE-вложение в комнате', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const message = await p.owner.upload(p.ownerChat.id, cipherBytes(), 'application/octet-stream', { encrypted: true, envelope: ENVELOPE, clientMessageId: id });
    assert.strictEqual(message.id, id);
    assert.strictEqual(typeof message.seq, 'number');
    assert.match(message.file_url, /^\/uploads\/[0-9a-f]{32}\.bin$/, 'имя — только случайные байты, без Date.now()');
    const stat = fs.statSync(path.join(suite.server.uploadsDir, path.basename(message.file_url)));
    assert.strictEqual(stat.mtimeMs % 3600000, 0, 'mtime кратно часу');
    assert.strictEqual(stat.atimeMs % 3600000, 0, 'atime кратно часу');
    assert.ok(stat.mtimeMs <= Date.now() && stat.mtimeMs > Date.now() - 3600000 - 5000, 'округление вниз, не дальше часа');
    // Обычное вложение в чат с ботом: id не нужен.
    const bot = await p.owner.botChat();
    const plain = await p.owner.upload(bot.id, Buffer.from('просто текстовый файл', 'utf8'), 'text/plain', { clientMessageId: undefined });
    assert.match(plain.file_url, /^\/uploads\/[0-9a-f]{32}\.txt$/);
    const statPlain = fs.statSync(path.join(suite.server.uploadsDir, path.basename(plain.file_url)));
    assert.strictEqual(statPlain.mtimeMs % 3600000, 0, 'mtime обработанного файла тоже кратен часу');
});

test('вложение в комнату без clientMessageId или с ним после файла — 400 client-outdated, на диск ничего не пишется', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const before = dirFiles();
    const missing = await postForm(p.owner, uploadForm({ chatId: p.ownerChat.id, encrypted: true, envelope: ENVELOPE }));
    assert.strictEqual(missing.status, 400);
    assert.strictEqual(missing.body.code, 'client-outdated');
    // Поле после файла: при проверке перед приёмом файла его ещё нет.
    const form = new FormData();
    form.append('proto', '4');
    form.append('chatId', String(p.ownerChat.id));
    form.append('encrypted', 'true');
    form.append('envelope', ENVELOPE);
    form.append('file', new Blob([cipherBytes()], { type: 'application/octet-stream' }), 'file.bin');
    form.append('clientMessageId', newClientMessageId());
    const late = await postForm(p.owner, form);
    assert.strictEqual(late.status, 400);
    assert.strictEqual(late.body.code, 'client-outdated');
    const bad = await postForm(p.owner, uploadForm({ chatId: p.ownerChat.id, encrypted: true, envelope: ENVELOPE, clientMessageId: 'abc' }));
    assert.strictEqual(bad.status, 400);
    assert.strictEqual(bad.body.code, 'bad-message-id');
    assert.deepStrictEqual(dirFiles(), before, 'ни один из отказанных запросов не оставил файла');
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM messages WHERE room_id = $1 AND file_url IS NOT NULL', [p.roomId]), 0);
});

test('вложение: занятый id — 409 до приёма файла; повтор той же отправки — 200 без второго файла; одновременные повторы — один файл', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const bytes = cipherBytes();
    const first = await p.owner.upload(p.ownerChat.id, bytes, 'application/octet-stream', { encrypted: true, envelope: ENVELOPE, clientMessageId: id });
    const afterFirst = dirFiles();

    // Повтор после обрыва связи (тот же автор, комната и конверт): 200, второго файла нет.
    const retry = await p.owner.uploadRaw(p.ownerChat.id, bytes, 'application/octet-stream', { encrypted: true, envelope: ENVELOPE, clientMessageId: id });
    assert.strictEqual(retry.status, 200, JSON.stringify(retry.body));
    assert.strictEqual(retry.body.message.id, first.id);
    assert.strictEqual(retry.body.message.seq, first.seq);
    assert.strictEqual(retry.body.message.file_url, first.file_url);
    assert.deepStrictEqual(dirFiles(), afterFirst, 'повтор не сохранил второй файл');
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM messages WHERE id = $1', [id]), 1);

    // Чужой автор и другой конверт — 409, файл на диск не попадает.
    const stolen = await p.member.uploadRaw(p.memberChat.id, bytes, 'application/octet-stream', { encrypted: true, envelope: ENVELOPE, clientMessageId: id });
    assert.strictEqual(stolen.status, 409);
    assert.deepStrictEqual(stolen.body, ID_CONFLICT_BODY);
    const changed = await p.owner.uploadRaw(p.ownerChat.id, bytes, 'application/octet-stream', { encrypted: true, envelope: fakeEnvelope('другое вложение'), clientMessageId: id });
    assert.strictEqual(changed.status, 409);
    assert.deepStrictEqual(dirFiles(), afterFirst, 'при 409 файла на диске нет');

    // Одновременные одинаковые отправки: одна строка, один файл.
    const raceId = newClientMessageId();
    const raceBytes = cipherBytes();
    const results = await Promise.all(Array.from({ length: 4 }, () => p.owner.uploadRaw(p.ownerChat.id, raceBytes, 'application/octet-stream',
        { encrypted: true, envelope: ENVELOPE, clientMessageId: raceId })));
    for (const res of results) assert.strictEqual(res.status, 200, JSON.stringify(res.body));
    assert.strictEqual(new Set(results.map(r => r.body.message.file_url)).size, 1, 'во всех ответах один файл');
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM messages WHERE id = $1', [raceId]), 1);
    await waitUntil(() => dirFiles().length === afterFirst.length + 1, { what: 'лишние файлы одновременных повторов удалены', timeoutMs: 5000 });
});

test('вложение с id из надгробия — 409, файл не сохраняется', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    await p.owner.send(p.ownerChat.id, 'будет удалено', { clientMessageId: id });
    await p.owner.del(`/api/messages/${id}`);
    const before = dirFiles();
    const res = await p.owner.uploadRaw(p.ownerChat.id, cipherBytes(), 'application/octet-stream', { encrypted: true, envelope: ENVELOPE, clientMessageId: id });
    assert.strictEqual(res.status, 409);
    assert.deepStrictEqual(res.body, ID_CONFLICT_BODY);
    assert.deepStrictEqual(dirFiles(), before);
});

// ---------- время ----------

test('время в базе огрублено: created_at и edited_at кратны минуте, в API правка — ISO-8601 UTC с нулевыми секундами', async () => {
    const p = await pair();
    const sent = await p.owner.send(p.ownerChat.id, 'для правки');
    const edit = await p.owner.put(`/api/messages/${sent.id}`, { text: fakeEnvelope('исправлено'), proto: 4 });
    assert.strictEqual(edit.body.success, true);
    assert.match(edit.body.edited_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/, edit.body.edited_at);
    const history = (await p.member.messages(p.memberChat.id)).messages.find(m => m.id === sent.id);
    assert.strictEqual(history.edited_at, edit.body.edited_at, 'история отдаёт то же значение');
    assert.match(history.created_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/);

    const rows = [
        ['messages', 'created_at', 'SELECT created_at AS t FROM messages WHERE room_id = $1', [p.roomId]],
        ['messages', 'edited_at', 'SELECT edited_at AS t FROM messages WHERE id = $1', [sent.id]],
        ['rooms', 'created_at', 'SELECT created_at AS t FROM rooms WHERE id = $1', [p.roomId]],
        ['chats', 'created_at', 'SELECT created_at AS t FROM chats WHERE room_id = $1', [p.roomId]],
        ['users', 'created_at', 'SELECT created_at AS t FROM users WHERE id = ANY($1::int[])', [[p.owner.user.id, p.member.user.id]]],
    ];
    for (const [table, column, sql, params] of rows) {
        const res = await suite.query(sql, params);
        assert.ok(res.rows.length > 0, `${table}.${column}: есть строки`);
        for (const { t } of res.rows) assert.strictEqual(new Date(t).getTime() % MINUTE_MS, 0, `${table}.${column} кратно минуте`);
    }
    // Заявка на вступление.
    const joiner = suite.client();
    await joiner.registerAnon();
    const invite = await p.owner.invite(p.ownerChat.id);
    const pending = await joiner.join(invite.code);
    const request = (await suite.query('SELECT created_at FROM join_requests WHERE id = $1', [pending.requestId])).rows[0];
    assert.strictEqual(new Date(request.created_at).getTime() % MINUTE_MS, 0, 'join_requests.created_at кратно минуте');
    assert.strictEqual((await suite.query(`SELECT 1 FROM information_schema.columns WHERE table_name = 'e2ee_key_shares' AND column_name = 'created_at'`)).rows.length, 0, 'у key-share нет времени создания');
});

test('срок исчезающего сообщения в базе округлён ВВЕРХ до минуты; в памяти точный — не исчезает раньше срока', async () => {
    const p = await pair();
    const sent = await p.owner.send(p.ownerChat.id, 'на пять минут', { expirySeconds: 300 });
    const row = (await suite.query(
        `SELECT date_trunc('minute', expires_at) = expires_at AS whole_minute,
                expires_at >= LOCALTIMESTAMP + interval '300 seconds' - interval '2 seconds' AS not_early,
                expires_at <= LOCALTIMESTAMP + interval '361 seconds' AS not_late
         FROM message_expiry WHERE message_id = $1`, [sent.id])).rows[0];
    assert.deepStrictEqual(row, { whole_minute: true, not_early: true, not_late: true });

    // Короткий срок: сообщение живо через секунду и пропадает по точному таймеру в памяти.
    const short = await p.owner.send(p.ownerChat.id, 'на две секунды', { expirySeconds: 2 });
    const stored = (await suite.query('SELECT expires_at >= LOCALTIMESTAMP + interval \'1 second\' AS late_enough FROM message_expiry WHERE message_id = $1', [short.id])).rows[0];
    assert.strictEqual(stored.late_enough, true, 'в базе срок не раньше обещанного');
    const started = Date.now();
    await new Promise(resolve => setTimeout(resolve, 1000));
    assert.ok((await suite.query('SELECT 1 FROM messages WHERE id = $1', [short.id])).rows[0], 'через секунду сообщение ещё есть');
    await waitUntil(async () => !(await suite.query('SELECT 1 FROM messages WHERE id = $1', [short.id])).rows[0], { what: 'сообщение удалено по таймеру', timeoutMs: 8000 });
    assert.ok(Date.now() - started >= 1900, `не раньше срока (прошло ${Date.now() - started} мс)`);
});

test('после перезапуска сервера сообщение с таймером удаляет фоновый воркер по сроку из базы (не раньше срока)', async () => {
    const p = await pair();
    const sent = await p.owner.send(p.ownerChat.id, 'переживу рестарт', { expirySeconds: 300 });
    await suite.server.restart();
    assert.ok((await suite.query('SELECT 1 FROM messages WHERE id = $1', [sent.id])).rows[0], 'после рестарта сообщение на месте: срок ещё не вышел');
    await suite.time.expireMessage(sent.id);
    await waitUntil(async () => !(await suite.query('SELECT 1 FROM messages WHERE id = $1', [sent.id])).rows[0], { what: 'воркер удалил просроченное', timeoutMs: 8000 });
});

// ---------- блокировки (раздел 8) ----------
//
// Гонки между операциями из таблицы 8.2: порядок users → rooms → room_participants
// → chats → messages плюс один повтор при 40P01. Воспроизвести взаимную блокировку
// по требованию нельзя, поэтому каждая операция идёт несколько кругов подряд. Тест
// считает повторы (строка «Взаимная блокировка (40P01), транзакция повторяется» —
// допустимы, это работа withTransactionRetry) и требует главного: ни одного ответа
// 5xx / 503 busy и ни одной взаимной блокировки, которая повторилась и после повтора.

const LOCK_ROUNDS = 12;
const RETRY_LOG = /Взаимная блокировка \(40P01\), транзакция повторяется/;
const FAILED_LOG = /Взаимная блокировка повторилась|Send message error|Bot error|Delete chat error|Join chat error|Approve join request error|Add reaction error/;

const tagsLib = () => createAuthorTags([Buffer.from(suite.secrets.MESSAGE_ENCRYPTION_KEY, 'base64')]);
// Теги пользователя в комнате за все недели с создания аккаунта (до удаления аккаунта).
async function tagsInRoom(userId, roomId) {
    const created = (await suite.query('SELECT created_at FROM users WHERE id = $1', [userId])).rows[0].created_at;
    return tagsLib().tagsForAccount(roomId, userId, created, Date.now());
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Запуск операции со сдвигом: по кругам сдвиг разный, чтобы запросы пересекались в разных
// местах транзакций, а не всегда в одном и том же порядке.
const later = (ms, operation) => sleep(ms).then(operation);
const jitter = (round) => (round * 7) % 31;

// Все ответы разом; падение самого запроса (сеть) — тоже провал.
async function allResponses(promises) {
    const settled = await Promise.allSettled(promises);
    return settled.map((item) => {
        if (item.status === 'rejected') throw item.reason;
        return item.value;
    });
}

// Главные утверждения набора блокировок. Ответы — {status, body}.
function assertNoLockFailures(label, responses, mark) {
    for (const res of responses) {
        assert.ok(res.status < 500, `${label}: ответ ${res.status}: ${res.text}`);
        assert.notStrictEqual(res.body && res.body.code, 'busy', `${label}: 503 busy после повтора`);
    }
    const failed = suite.server.logs.find(FAILED_LOG, { from: mark });
    assert.ok(!failed, `${label}: в логе сервера: ${failed && failed.text}`);
}

const retriesSince = (mark) => suite.server.logs.count(RETRY_LOG, { from: mark });

test('отправка против удаления своего аккаунта: ни дедлока, ни сообщения без владельца', async (t) => {
    const mark = suite.server.logs.mark();
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const p = await pair({ name: `Отправка и удаление ${round}` });
        const memberId = p.member.user.id;
        const memberTags = await tagsInRoom(memberId, p.roomId);
        const responses = await allResponses([
            p.member.sendRaw(p.memberChat.id, 'раз'),
            p.member.sendRaw(p.memberChat.id, 'два'),
            p.owner.sendRaw(p.ownerChat.id, 'от владельца'),
            later(jitter(round), () => p.member.post('/api/account/delete', {})),
            later(jitter(round) / 2, () => p.member.sendRaw(p.memberChat.id, 'три')),
        ]);
        const user = (await suite.query('SELECT 1 FROM users WHERE id = $1', [memberId])).rows;
        assert.strictEqual(user.length, 0, 'аккаунт удалён');
        const left = (await suite.query('SELECT 1 FROM messages WHERE author_tag = ANY($1::bytea[])', [memberTags])).rows;
        assert.strictEqual(left.length, 0, 'ни одного сообщения удалённого аккаунта (по тегам автора)');
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    t.diagnostic(`повторов при 40P01: ${retriesSince(mark)} за ${LOCK_ROUNDS} кругов`);
});

test('ответ бота против удаления аккаунта (живой дедлок, исправленный явной блокировкой users)', async (t) => {
    const mark = suite.server.logs.mark();
    const rounds = await Promise.all(Array.from({ length: LOCK_ROUNDS }, async (_, round) => {
        const user = suite.client();
        await user.registerAnon();
        const bot = await user.botChat();
        await user.send(bot.id, 'привет');
        // Ответ бота готовится через 600 мс: удаляем аккаунт в окне вокруг этого срока.
        await sleep(520 + round * 15);
        return { userId: user.user.id, response: await user.post('/api/account/delete', {}) };
    }));
    await sleep(1200); // дождаться запоздавших ответов бота
    for (const round of rounds) {
        assert.strictEqual((await suite.query('SELECT 1 FROM users WHERE id = $1', [round.userId])).rows.length, 0);
        assert.strictEqual((await suite.query('SELECT 1 FROM messages WHERE user_id = $1', [round.userId])).rows.length, 0, 'ответ бота не пережил аккаунт');
    }
    assertNoLockFailures('бот', rounds.map(r => r.response), mark);
    t.diagnostic(`повторов при 40P01: ${retriesSince(mark)}`);
});

test('одобрение заявки против удаления заявителя: либо вступил и удалён, либо заявки уже нет; ни дедлока, ни следов', async (t) => {
    const mark = suite.server.logs.mark();
    let approved = 0;
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const owner = suite.client({ name: 'владелец' });
        const applicant = suite.client({ name: 'заявитель' });
        await owner.registerAnon();
        await applicant.registerAnon();
        const ownerChat = await owner.createRoom(`Заявка и удаление ${round}`);
        const { code } = await owner.invite(ownerChat.id);
        const pending = await applicant.join(code);
        const applicantId = applicant.user.id;
        const responses = await allResponses([
            owner.post(`/api/join-requests/${pending.requestId}/approve`, {}),
            later(jitter(round), () => applicant.post('/api/account/delete', {})),
        ]);
        if (responses[0].body && responses[0].body.success) approved++;
        assert.strictEqual((await suite.query('SELECT 1 FROM users WHERE id = $1', [applicantId])).rows.length, 0);
        for (const table of ['room_participants', 'chats', 'join_requests']) {
            const rows = (await suite.query(`SELECT 1 FROM ${table} WHERE user_id = $1`, [applicantId])).rows;
            assert.strictEqual(rows.length, 0, `${table}: следов заявителя нет`);
        }
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    t.diagnostic(`одобрений успело: ${approved} из ${LOCK_ROUNDS}, повторов при 40P01: ${retriesSince(mark)}`);
});

test('вход по коду против выхода последнего участника: комната либо цела с новичком, либо снесена целиком', async (t) => {
    const mark = suite.server.logs.mark();
    let joined = 0;
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const owner = suite.client({ name: 'владелец' });
        const guest = suite.client({ name: 'гость' });
        await owner.registerAnon();
        await guest.registerAnon();
        const ownerChat = await owner.createRoom(`Вход и выход ${round}`);
        // Без одобрения: вход идёт сразу, через addRoomMember под блокировкой комнаты.
        const { code } = await owner.rotateInvite(ownerChat.id, { requireApproval: false });
        await owner.send(ownerChat.id, 'было');
        const responses = await allResponses([
            guest.joinRaw(code),
            later(jitter(round), () => owner.del(`/api/chats/${ownerChat.id}`)),
        ]);
        const room = (await suite.query('SELECT id FROM rooms WHERE id = $1', [ownerChat.room_id])).rows;
        const participants = (await suite.query('SELECT user_id FROM room_participants WHERE room_id = $1', [ownerChat.room_id])).rows;
        const chats = (await suite.query('SELECT user_id FROM chats WHERE room_id = $1', [ownerChat.room_id])).rows;
        const messages = (await suite.query('SELECT 1 FROM messages WHERE room_id = $1', [ownerChat.room_id])).rows;
        if (room.length === 0) {
            assert.deepStrictEqual([participants.length, chats.length, messages.length], [0, 0, 0], 'комната снесена целиком');
        } else {
            joined++;
            assert.deepStrictEqual(participants.map(r => r.user_id), [guest.user.id], 'в комнате остался только гость');
            assert.deepStrictEqual(chats.map(r => r.user_id), [guest.user.id], 'и только его чат');
        }
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    t.diagnostic(`гость успел вступить: ${joined} из ${LOCK_ROUNDS}, повторов при 40P01: ${retriesSince(mark)}`);
});

test('двое последних участников выходят одновременно: комната не остаётся в базе пустой', async (t) => {
    const mark = suite.server.logs.mark();
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const p = await pair({ name: `Двойной выход ${round}` });
        const responses = await allResponses([
            p.owner.del(`/api/chats/${p.ownerChat.id}`),
            later(jitter(round), () => p.member.del(`/api/chats/${p.memberChat.id}`)),
        ]);
        assert.strictEqual((await suite.query('SELECT 1 FROM rooms WHERE id = $1', [p.roomId])).rows.length, 0, 'комната снесена');
        assert.strictEqual((await suite.query('SELECT 1 FROM messages WHERE room_id = $1', [p.roomId])).rows.length, 0);
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    t.diagnostic(`повторов при 40P01: ${retriesSince(mark)}`);
});

test('оба участника комнаты удаляют аккаунты одновременно: комната и история снесены, дедлока нет', async (t) => {
    const mark = suite.server.logs.mark();
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const p = await pair({ name: `Двойное удаление ${round}` });
        await p.owner.send(p.ownerChat.id, 'история');
        await p.member.send(p.memberChat.id, 'ещё');
        const responses = await allResponses([
            p.owner.post('/api/account/delete', {}),
            later(jitter(round), () => p.member.post('/api/account/delete', {})),
        ]);
        assert.strictEqual((await suite.query('SELECT 1 FROM rooms WHERE id = $1', [p.roomId])).rows.length, 0, 'комната снесена');
        assert.strictEqual((await suite.query('SELECT 1 FROM messages WHERE room_id = $1', [p.roomId])).rows.length, 0);
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    t.diagnostic(`повторов при 40P01: ${retriesSince(mark)}`);
});

test('создание комнат против удаления аккаунта создателя: пустых комнат не остаётся', async (t) => {
    const mark = suite.server.logs.mark();
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const user = suite.client();
        await user.registerAnon();
        const responses = await allResponses([
            user.post('/api/chats', { name: `Гонка ${round} а` }),
            later(jitter(round) / 2, () => user.post('/api/chats', { name: `Гонка ${round} б` })),
            later(jitter(round), () => user.post('/api/account/delete', {})),
        ]);
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    const empty = (await suite.query(
        'SELECT r.id FROM rooms r WHERE NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = r.id)'
    )).rows;
    assert.deepStrictEqual(empty, [], 'комнат без участников нет');
    t.diagnostic(`повторов при 40P01: ${retriesSince(mark)}`);
});

test('реакция против удаления аккаунта автора сообщения: ни дедлока, ни 5xx', async (t) => {
    const mark = suite.server.logs.mark();
    for (let round = 0; round < LOCK_ROUNDS; round++) {
        const p = await pair({ name: `Реакция и удаление ${round}` });
        const message = await p.owner.send(p.ownerChat.id, 'поставьте реакцию');
        const responses = await allResponses([
            p.member.post('/api/reactions', { messageId: message.id, emoji: '👍' }),
            later(jitter(round), () => p.owner.post('/api/account/delete', {})),
        ]);
        assertNoLockFailures(`круг ${round}`, responses, mark);
    }
    t.diagnostic(`повторов при 40P01: ${retriesSince(mark)}`);
});
