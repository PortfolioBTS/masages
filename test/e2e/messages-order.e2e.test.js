'use strict';
// Порядок, идентификаторы и время сообщений (docs/security/message-ordering.md,
// раздел 15, «Сквозные»). Настоящий Postgres: триггеры seq и надгробий, очередь
// на строке комнаты, блокировки.
//
// Порядок в файле: порядок и границы видимости (seq) → идентификаторы клиента,
// идемпотентность, надгробия → файлы → время → блокировки.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

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

test('вступление и отправка одновременно: новичок видит ровно сообщения после своего visible_from_seq', async () => {
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
    const seen = (await guest.messages(guestChat.id)).messages.map(m => m.id).sort();
    assert.deepStrictEqual(seen, expected, 'новичок видит ровно то, что отправлено после вступления');
    assert.ok(all.some(m => m.seq <= bound), 'часть сообщений ушла до вступления');
    // Граница точна: ни одно зафиксированное до вступления не видно, ни одно после — не скрыто.
    const hidden = all.filter(m => m.seq <= bound).length;
    assert.strictEqual(seen.length, all.length - hidden);
    // Непрочитанное новичка начинается с той же границы.
    const unread = (await guest.chats()).find(c => c.id === guestChat.id).unread;
    assert.strictEqual(unread, expected.length - 0, 'непрочитанное — только то, что видно');
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
    assert.ok(waitUntil, 'helper подключён');
});
