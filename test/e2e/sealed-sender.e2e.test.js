'use strict';
// Sealed sender на хранении (docs/security/sealed-sender.md, раздел 15, «Сквозные»).
// Настоящий Postgres: CHECK messages_author_scope, теги автора, правка и удаление по
// тегам с границей видимости, выход и удаление аккаунта (в том числе из комнат, откуда
// пользователь вышел), гонка «выход + отправка» в обоих порядках, ответы и события
// без user_id / chat_id / sender_username / sender_avatar, mine, отсутствие дублей
// отправителю, перенос и подмена тега, старая вкладка (proto).
// Квота вложений и смена ключа — в sealed-sender-keys.e2e.test.js.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');
const { createAuthorTags } = require('../../lib/author-tag');

const suite = createSuite('sealed-sender');

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const ikm = () => Buffer.from(suite.secrets.MESSAGE_ENCRYPTION_KEY, 'base64');
const tags = () => createAuthorTags([ikm()]);

async function pair({ name = 'Скрытый автор' } = {}) {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member, { name });
    return { owner, member, ...room };
}

// Теги пользователя в комнате за все недели (как их считает сервер). created_at аккаунта
// запоминается при первом вызове: после удаления аккаунта строки users уже нет, а теги нужны,
// чтобы убедиться, что с ними не осталось ни одной строки.
const createdAtOfUser = new Map();
async function tagsOf(userId, roomId) {
    if (!createdAtOfUser.has(userId)) {
        createdAtOfUser.set(userId, (await suite.query('SELECT created_at FROM users WHERE id = $1', [userId])).rows[0].created_at);
    }
    return tags().tagsForAccount(roomId, userId, createdAtOfUser.get(userId), Date.now());
}

// Строки комнаты, принадлежащие пользователю по тегам.
async function rowsOf(userId, roomId) {
    return (await suite.query('SELECT id, seq, created_at, author_tag FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) ORDER BY seq', [roomId, await tagsOf(userId, roomId)])).rows;
}

const BANNED_KEYS = new Set(['user_id', 'chat_id', 'sender_id', 'sender_username', 'sender_avatar', 'author_tag']);

// Пути всех запрещённых ключей в JSON (рекурсивно).
function bannedPaths(value, at = '$') {
    if (Array.isArray(value)) return value.flatMap((item, i) => bannedPaths(item, `${at}[${i}]`));
    if (value && typeof value === 'object') {
        return Object.entries(value).flatMap(([key, item]) => (BANNED_KEYS.has(key) ? [`${at}.${key}`] : []).concat(bannedPaths(item, `${at}.${key}`)));
    }
    return [];
}

// Блокировка строки комнаты из теста: запросы встают в очередь в том порядке, в каком пришли.
async function holdRoomLock(roomId) {
    const client = await suite.db.connect();
    await client.query('BEGIN');
    await client.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId]);
    return {
        async release() {
            await client.query('COMMIT');
            client.release();
        },
    };
}

const waitingBackends = async () => Number((await suite.query(
    `SELECT count(*) AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`
)).rows[0].n);

// ---------- схема ----------

test('CHECK messages_author_scope: комната - тег 16 байт без user_id и chat_id; бот - наоборот; остальное отвергается', async () => {
    const p = await pair();
    const botChat = await p.owner.botChat();
    const tag = crypto.randomBytes(16);
    const idRoom = () => 1000000 + crypto.randomInt(0, 1e9);

    // Верная строка комнаты проходит.
    await suite.query(`INSERT INTO messages (id, room_id, author_tag, text, encrypted) VALUES ($1, $2, $3, 'x', true)`, [idRoom(), p.roomId, tag]);
    // С user_id, с chat_id, без тега, с коротким тегом - CHECK.
    const bad = [
        ['user_id у строки комнаты', `INSERT INTO messages (id, room_id, user_id, author_tag, text, encrypted) VALUES ($1, $2, $3, $4, 'x', true)`, [idRoom(), p.roomId, p.owner.user.id, tag]],
        ['chat_id у строки комнаты', `INSERT INTO messages (id, room_id, chat_id, author_tag, text, encrypted) VALUES ($1, $2, $3, $4, 'x', true)`, [idRoom(), p.roomId, p.ownerChat.id, tag]],
        ['комната без тега', `INSERT INTO messages (id, room_id, text, encrypted) VALUES ($1, $2, 'x', true)`, [idRoom(), p.roomId]],
        ['тег не 16 байт', `INSERT INTO messages (id, room_id, author_tag, text, encrypted) VALUES ($1, $2, $3, 'x', true)`, [idRoom(), p.roomId, crypto.randomBytes(15)]],
        ['бот без user_id', `INSERT INTO messages (id, chat_id, text) VALUES ($1, $2, 'x')`, [idRoom(), botChat.id]],
        ['бот с тегом', `INSERT INTO messages (id, chat_id, user_id, author_tag, text) VALUES ($1, $2, $3, $4, 'x')`, [idRoom(), botChat.id, p.owner.user.id, tag]],
    ];
    // Строка без области (ни комнаты, ни чата) отвергается ещё триггером seq (нет области для счётчика).
    await assert.rejects(suite.query(`INSERT INTO messages (id, user_id, text) VALUES ($1, $2, 'x')`, [idRoom(), p.owner.user.id]), (err) => err.code === '23503');
    for (const [what, sql, params] of bad) {
        await assert.rejects(suite.query(sql, params), (err) => {
            assert.strictEqual(err.code, '23514', `${what}: ${err.message}`);
            return true;
        }, what);
    }
});

test('схема: в users нет столбцов окна квоты, upload_quota без user_id и внешних ключей, user_left_rooms есть, chat_id - CASCADE', async () => {
    const cols = (table) => suite.query(`SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position`, [table]).then(r => r.rows.map(x => x.column_name));
    assert.ok(!(await cols('users')).some(name => name.startsWith('upload_')), 'users без upload_window_*');
    assert.deepStrictEqual(await cols('upload_quota'), ['qkey', 'window_start', 'bytes']);
    const fks = await suite.query(`SELECT 1 FROM information_schema.table_constraints WHERE table_name = 'upload_quota' AND constraint_type = 'FOREIGN KEY'`);
    assert.strictEqual(fks.rows.length, 0, 'у upload_quota внешних ключей нет');
    assert.deepStrictEqual(await cols('user_left_rooms'), ['user_id', 'room_id']);
    assert.deepStrictEqual(await cols('messages').then(list => list.filter(name => ['author_tag', 'user_id', 'chat_id'].includes(name))), ['chat_id', 'user_id', 'author_tag']);
    const del = await suite.query(`SELECT confdeltype FROM pg_constraint WHERE conname = 'messages_chat_id_fkey'`);
    assert.strictEqual(del.rows[0].confdeltype, 'c', 'messages.chat_id ON DELETE CASCADE');
    const indexes = (await suite.query(`SELECT indexname FROM pg_indexes WHERE tablename = 'messages'`)).rows.map(r => r.indexname);
    assert.ok(indexes.includes('idx_messages_room_author'));
    assert.ok(!indexes.includes('idx_messages_user_files'), 'индекса квоты по сообщениям больше нет');
});

// ---------- теги ----------

test('в строке комнаты нет автора: user_id и chat_id пусты, тег - HMAC от (комната, пользователь, неделя created_at); теги одного автора в неделе совпадают, у разных авторов различны', async () => {
    const p = await pair();
    const a1 = await p.owner.send(p.ownerChat.id, 'раз');
    const a2 = await p.owner.send(p.ownerChat.id, 'два');
    const b1 = await p.member.send(p.memberChat.id, 'три');
    const rows = (await suite.query('SELECT id, user_id, chat_id, author_tag, created_at, encrypted FROM messages WHERE room_id = $1 ORDER BY seq', [p.roomId])).rows;
    assert.strictEqual(rows.length, 3);
    for (const row of rows) {
        assert.strictEqual(row.user_id, null);
        assert.strictEqual(row.chat_id, null);
        assert.strictEqual(row.author_tag.length, 16);
    }
    const byId = new Map(rows.map(r => [r.id, r]));
    assert.ok(byId.get(Number(a1.id)).author_tag.equals(tags().tagFor(p.roomId, p.owner.user.id, byId.get(Number(a1.id)).created_at)), 'тег автора по определению');
    assert.ok(byId.get(Number(a1.id)).author_tag.equals(byId.get(Number(a2.id)).author_tag), 'один автор в неделю - один тег');
    assert.ok(!byId.get(Number(a1.id)).author_tag.equals(byId.get(Number(b1.id)).author_tag), 'разные авторы - разные теги');
    // Теги разных недель и разных комнат одного автора различны.
    const created = byId.get(Number(a1.id)).created_at;
    assert.ok(!tags().tagFor(p.roomId, p.owner.user.id, new Date(created.getTime() + WEEK_MS)).equals(byId.get(Number(a1.id)).author_tag));
    const other = await p.owner.createRoom('Другая');
    const second = await p.owner.send(other.id, 'в другой комнате');
    const secondRow = (await suite.query('SELECT author_tag FROM messages WHERE id = $1', [second.id])).rows[0];
    assert.ok(!secondRow.author_tag.equals(byId.get(Number(a1.id)).author_tag), 'тег зависит от комнаты');
});

// ---------- правка, удаление, таймер ----------

test('правка, удаление, таймер: автору - да; другой участник, посторонний и вышедший - «Сообщение не найдено»', async () => {
    const p = await pair();
    const stranger = suite.client();
    await stranger.registerAnon();
    const m = await p.owner.send(p.ownerChat.id, 'мои слова');

    const notFound = (res) => { assert.strictEqual(res.body.success, false); assert.match(res.body.message, /не найден/i); };
    // Правка
    notFound(await p.member.editRaw(m.id, 'чужая правка'));
    notFound(await stranger.editRaw(m.id, 'правка постороннего'));
    // Таймер
    notFound(await p.member.post(`/api/messages/${m.id}/set-expiry`, { expirySeconds: 60 }));
    notFound(await stranger.post(`/api/messages/${m.id}/set-expiry`, { expirySeconds: 60 }));
    // Удаление
    notFound(await p.member.del(`/api/messages/${m.id}`));
    notFound(await stranger.del(`/api/messages/${m.id}`));
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE id = $1', [m.id])).rows[0].n, 1, 'чужие попытки сообщение не тронули');

    // Автору можно всё.
    const edited = await p.owner.edit(m.id, 'исправлено');
    assert.strictEqual(edited.success, true);
    const timer = await p.owner.post(`/api/messages/${m.id}/set-expiry`, { expirySeconds: 3600 });
    assert.strictEqual(timer.body.success, true, JSON.stringify(timer.body));
    const afterEdit = (await suite.query('SELECT text, author_tag FROM messages WHERE id = $1', [m.id])).rows[0];
    assert.ok(afterEdit.text.startsWith('enc:v3:'), 'после правки строка снова enc:v3');
    const history = (await p.member.messages(p.memberChat.id)).messages.find(x => x.id === m.id);
    assert.strictEqual(history.text, fakeEnvelope('исправлено'), 'сервер расшифровал правку тем же AAD');
    // Вышедший не правит: у него уже нет ни чата, ни строки участника.
    await p.owner.leave(p.ownerChat.id);
    notFound(await p.owner.editRaw(m.id, 'правка после выхода'));
    notFound(await p.owner.del(`/api/messages/${m.id}`));
    notFound(await p.owner.post(`/api/messages/${m.id}/set-expiry`, { expirySeconds: 60 }));
    assert.strictEqual((await p.member.messages(p.memberChat.id)).messages.find(x => x.id === m.id).text, fakeEnvelope('исправлено'));
    assert.strictEqual((await p.member.del(`/api/messages/${m.id}`)).body.success, false, 'и участник чужое сообщение так и не удалил');
});

test('правка на границе недели: тег берётся из строки, а не из текущего времени; тег другой недели права не даёт', async () => {
    const p = await pair();
    const weekAgo = new Date(Date.now() - WEEK_MS - 3600 * 1000);
    weekAgo.setUTCSeconds(0, 0);
    const insertRow = async (id, tag) => (await suite.query(
        `INSERT INTO messages (id, room_id, author_tag, text, encrypted, created_at) VALUES ($1, $2, $3, $4, true, $5) RETURNING id, seq`,
        [id, p.roomId, tag, 'enc:v3:00000000:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAA==:AAAA', weekAgo]
    )).rows[0];
    const myTag = tags().tagFor(p.roomId, p.owner.user.id, weekAgo);
    const staleWeekTag = tags().tagFor(p.roomId, p.owner.user.id, new Date()); // тег ТЕКУЩЕЙ недели на строке прошлой
    assert.ok(!myTag.equals(staleWeekTag), 'неделя действительно другая');
    const mine = await insertRow(2000000001, myTag);
    const wrong = await insertRow(2000000002, staleWeekTag);
    // Автор строки прошлой недели правит и удаляет её: сервер считает тег по created_at строки.
    assert.strictEqual((await p.owner.editRaw(String(mine.id), 'правка старого')).body.success, true);
    // Тег чужой недели для created_at строки не подходит - «не найдено».
    const denied = await p.owner.editRaw(String(wrong.id), 'не моя неделя');
    assert.strictEqual(denied.body.success, false);
    assert.strictEqual((await p.owner.del(`/api/messages/${mine.id}`)).body.success, true);
    assert.strictEqual((await p.owner.del(`/api/messages/${wrong.id}`)).body.success, false);
});

test('граница видимости: вышедший и вернувшийся участник не правит, не удаляет и не ставит таймер на свои старые сообщения; новые - может; удаление аккаунта убирает те и другие', async () => {
    const p = await pair();
    const old = await p.member.send(p.memberChat.id, 'до выхода');
    await p.owner.send(p.ownerChat.id, 'сообщение владельца');
    await p.member.leave(p.memberChat.id);
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [p.member.user.id, p.roomId])).rows[0].n, 1, 'у вышедшего остались сообщения - комната записана');
    // Возвращается через заявку: новая строка участника с новой границей. Код после выхода участника обновлён
    // сервером (поворот приглашения при выходе, signed-membership.md, вопрос 17) - берётся новый.
    const freshCode = (await p.owner.invite(p.ownerChat.id)).code;
    assert.notStrictEqual(freshCode, p.code);
    const pending = await p.member.join(freshCode);
    await p.owner.approve(pending.requestId);
    const memberChat = (await p.member.chats()).find(c => c.room_id === p.roomId);
    const bound = Number((await suite.query('SELECT visible_from_seq FROM room_participants WHERE room_id = $1 AND user_id = $2', [p.roomId, p.member.user.id])).rows[0].visible_from_seq);
    assert.ok(Number(old.seq) <= bound, 'старое сообщение под границей видимости');
    const fresh = await p.member.send(memberChat.id, 'после возвращения');

    const notFound = (res) => { assert.strictEqual(res.body.success, false); assert.match(res.body.message, /не найден/i); };
    notFound(await p.member.editRaw(old.id, 'правка старого'));
    notFound(await p.member.del(`/api/messages/${old.id}`));
    notFound(await p.member.post(`/api/messages/${old.id}/set-expiry`, { expirySeconds: 60 }));
    assert.strictEqual((await p.member.messages(memberChat.id)).messages.some(x => x.id === old.id), false, 'и интерфейс их не показывает');
    assert.strictEqual((await p.member.editRaw(fresh.id, 'правка нового')).body.success, true);
    assert.strictEqual((await rowsOf(p.member.user.id, p.roomId)).length, 2, 'по тегам оба сообщения - его');

    await p.member.deleteAccount();
    assert.strictEqual((await rowsOf(p.member.user.id, p.roomId)).length, 0, 'удаление аккаунта убрало оба');
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [p.roomId])).rows[0].n, 1, 'осталось только сообщение владельца');
});

// ---------- непрочитанное и прочитано ----------

test('своё сообщение не считается непрочитанным; markChatRead не помечает собственные сообщения читателя; read - только чужим', async () => {
    const p = await pair();
    for (const client of [p.owner, p.member]) {
        assert.deepStrictEqual((await client.post('/api/user/privacy', { readReceipts: true })).body, { success: true, readReceipts: true });
    }
    const unread = async (client, chatId) => Number((await client.chats()).find(c => c.id === chatId).unread);
    const fromOwner = await p.owner.send(p.ownerChat.id, 'от владельца');
    assert.strictEqual(await unread(p.owner, p.ownerChat.id), 0, 'отправитель: своё не непрочитанное');
    assert.strictEqual(await unread(p.member, p.memberChat.id), 1, 'получатель: одно непрочитанное');
    const status = async (id) => (await suite.query('SELECT status FROM messages WHERE id = $1', [id])).rows[0].status;
    // Участник открывает историю (как клиент перед ответом): чужое прочитано, маркер двигается.
    await p.member.messages(p.memberChat.id);
    assert.strictEqual(await status(fromOwner.id), 'read');
    assert.strictEqual(await unread(p.member, p.memberChat.id), 0);
    const fromMember = await p.member.send(p.memberChat.id, 'ответ участника');
    assert.strictEqual(await unread(p.member, p.memberChat.id), 0, 'после своей отправки маркер сдвинут (8.3)');
    assert.strictEqual(await unread(p.owner, p.ownerChat.id), 1, 'у владельца ответ непрочитан');
    // Участник снова открывает историю: собственное сообщение читателя статус read не получает.
    await p.member.messages(p.memberChat.id);
    assert.strictEqual(await status(fromMember.id), 'sent', 'собственное сообщение читателя не получает статус read');
    assert.strictEqual(await status(fromOwner.id), 'read');
    // Владелец читает: ответ участника становится прочитанным, своё сообщение владельца не меняется.
    await p.owner.messages(p.ownerChat.id);
    assert.strictEqual(await status(fromMember.id), 'read');
    assert.strictEqual(await unread(p.owner, p.ownerChat.id), 0);
});

// ---------- выход и удаление аккаунта ----------

test('выход без флага оставляет сообщения и пишет user_left_rooms только если они есть; с ?deleteMessages=1 удаляет сразу, оставляя надгробия и убирая файлы', async () => {
    const owner = suite.client();
    const silent = suite.client();
    const talker = suite.client();
    const eraser = suite.client();
    for (const c of [owner, silent, talker, eraser]) await c.registerAnon();
    const ownerChat = await owner.createRoom('Выходы');
    const { code } = await owner.invite(ownerChat.id);
    const chats = {};
    for (const [name, c] of [['silent', silent], ['talker', talker], ['eraser', eraser]]) {
        const pending = await c.join(code);
        await owner.approve(pending.requestId);
        chats[name] = (await c.chats()).find(x => x.room_id === ownerChat.room_id);
    }
    const roomId = ownerChat.room_id;
    await talker.send(chats.talker.id, 'оставлю');
    const kept = await talker.uploadCipher(chats.talker.id, { label: 'мой файл' });
    const erasable = await eraser.send(chats.eraser.id, 'сотру');
    const erasableFile = await eraser.uploadCipher(chats.eraser.id, { label: 'сотру файл' });
    const fileOnDisk = (message) => path.join(suite.server.uploadsDir, path.basename(message.file_url));
    assert.ok(fs.existsSync(fileOnDisk(erasableFile)));
    const ulr = async (user) => (await suite.query('SELECT count(*)::int AS n FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [user.user.id, roomId])).rows[0].n;

    await silent.leave(chats.silent.id);
    assert.strictEqual(await ulr(silent), 0, 'у вышедшего без сообщений записи нет');
    await talker.leave(chats.talker.id);
    assert.strictEqual(await ulr(talker), 1, 'вышел, оставив сообщения - комната записана');
    assert.strictEqual((await rowsOf(talker.user.id, roomId)).length, 2, 'сообщения остались');
    assert.ok(fs.existsSync(fileOnDisk(kept)), 'файл оставленного сообщения на месте');

    const sock = await owner.socket();
    try {
        await eraser.leave(chats.eraser.id, { deleteMessages: true });
        assert.strictEqual(await ulr(eraser), 0);
        assert.strictEqual((await rowsOf(eraser.user.id, roomId)).length, 0, 'свои сообщения удалены сразу');
        const tombstones = await suite.query('SELECT id FROM message_tombstones WHERE id = ANY($1::int[])', [[Number(erasable.id), Number(erasableFile.id)]]);
        assert.strictEqual(tombstones.rows.length, 2, 'надгробия оставлены');
        await waitUntil(() => !fs.existsSync(fileOnDisk(erasableFile)), { what: 'файл удалённого сообщения убран с диска' });
        const events = await sock.waitFor('messageDeleted', e => e.id === erasable.id);
        assert.deepStrictEqual(Object.keys(events).sort(), ['id', 'room_id'], 'событие удаления комнаты без chat_id');
    } finally {
        await sock.close();
    }
    assert.ok(fs.existsSync(fileOnDisk(kept)));
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [roomId])).rows[0].n, 2, 'остались только сообщения вышедшего с оставлением');
});

test('последний участник вышел: комната, сообщения и user_left_rooms исчезли, тегов нигде не осталось', async () => {
    const p = await pair();
    await p.member.send(p.memberChat.id, 'от участника');
    await p.owner.send(p.ownerChat.id, 'от владельца');
    await p.member.leave(p.memberChat.id);
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM user_left_rooms WHERE room_id = $1', [p.roomId])).rows[0].n, 1);
    await p.owner.leave(p.ownerChat.id);
    for (const [table, column] of [['rooms', 'id'], ['messages', 'room_id'], ['user_left_rooms', 'room_id'], ['room_participants', 'room_id']]) {
        assert.strictEqual((await suite.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${column} = $1`, [p.roomId])).rows[0].n, 0, table);
    }
});

test('удаление аккаунта: сообщения в текущих комнатах и в комнатах, откуда вышел оставив сообщения; у вышедшего без сообщений записи нет; следов с его тегами нет нигде', async () => {
    const victim = suite.client();
    const friend = suite.client();
    await victim.registerAnon();
    await friend.registerAnon();
    const current = await roomWithMember(friend, victim, { name: 'Текущая' });
    const left = await roomWithMember(friend, victim, { name: 'Оставленная' });
    const quiet = await roomWithMember(friend, victim, { name: 'Молчаливая' });
    await victim.send(current.memberChat.id, 'в текущей');
    await victim.uploadCipher(current.memberChat.id, { label: 'файл в текущей' });
    await victim.send(left.memberChat.id, 'в оставленной');
    await friend.send(left.ownerChat.id, 'сообщение друга');
    await victim.leave(left.memberChat.id);
    await victim.leave(quiet.memberChat.id);
    const rooms = [current.roomId, left.roomId, quiet.roomId];
    const ulr = async () => (await suite.query('SELECT room_id FROM user_left_rooms WHERE user_id = $1', [victim.user.id])).rows.map(r => r.room_id);
    assert.deepStrictEqual(await ulr(), [left.roomId], 'запись только для комнаты с оставленными сообщениями');
    const allTags = [];
    for (const roomId of rooms) allTags.push(...await tagsOf(victim.user.id, roomId));
    const victimRows = async () => Number((await suite.query('SELECT count(*) AS n FROM messages WHERE author_tag = ANY($1::bytea[]) AND room_id = ANY($2::int[])', [allTags, rooms])).rows[0].n);
    assert.strictEqual(await victimRows(), 3);

    await victim.deleteAccount();
    assert.strictEqual(await victimRows(), 0, 'ни одной строки с его тегами');
    assert.deepStrictEqual(await ulr(), [], 'записей user_left_rooms нет');
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1', [left.roomId])).rows[0].n, 1, 'сообщение друга осталось');
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM users WHERE id = $1', [victim.user.id])).rows[0].n, 0);
});

// ---------- гонки ----------

test('гонка «выход без сообщений + отправка», порядок 1: выход зафиксирован первым - отправка получает 403, строки с тегом пользователя нет', async () => {
    const p = await pair();
    const lock = await holdRoomLock(p.roomId);
    let leave, send;
    try {
        leave = p.member.leave(p.memberChat.id);
        await waitUntil(async () => (await waitingBackends()) >= 1, { what: 'выход встал в очередь на строке комнаты' });
        send = p.member.sendRaw(p.memberChat.id, 'опоздавшее');
        await waitUntil(async () => (await waitingBackends()) >= 2, { what: 'отправка встала в очередь' });
    } finally {
        await lock.release();
    }
    await leave;
    const sent = await send;
    await tagsOf(p.member.user.id, p.roomId); // запомнить created_at до удаления аккаунта
    assert.strictEqual(sent.status, 403, JSON.stringify(sent.body));
    assert.strictEqual((await rowsOf(p.member.user.id, p.roomId)).length, 0, 'строки без владельца не осталось');
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM user_left_rooms WHERE user_id = $1', [p.member.user.id])).rows[0].n, 0);
    await p.member.deleteAccount();
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE author_tag = ANY($1::bytea[])', [await tagsOf(p.member.user.id, p.roomId)])).rows[0].n, 0);
});

test('гонка «выход без сообщений + отправка», порядок 2: отправка зафиксирована первой - выход видит сообщение и пишет user_left_rooms; удаление аккаунта убирает всё', async () => {
    const p = await pair();
    const lock = await holdRoomLock(p.roomId);
    let leave, send;
    try {
        send = p.member.sendRaw(p.memberChat.id, 'успело');
        await waitUntil(async () => (await waitingBackends()) >= 1, { what: 'отправка встала в очередь на строке комнаты' });
        leave = p.member.leave(p.memberChat.id);
        await waitUntil(async () => (await waitingBackends()) >= 2, { what: 'выход встал в очередь' });
    } finally {
        await lock.release();
    }
    const sent = await send;
    await leave;
    await tagsOf(p.member.user.id, p.roomId);
    assert.strictEqual(sent.status, 200, JSON.stringify(sent.body));
    assert.strictEqual((await rowsOf(p.member.user.id, p.roomId)).length, 1);
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [p.member.user.id, p.roomId])).rows[0].n, 1, 'выход увидел сообщение отправки');
    await p.member.deleteAccount();
    assert.strictEqual((await rowsOf(p.member.user.id, p.roomId)).length, 0, 'удаление аккаунта нашло и убрало сообщение');
});

test('параллельно: удаление аккаунта автора, отправки в комнату и выход соседа - без 40P01 в ответах и без строк с тегом автора', async () => {
    const mark = suite.server.logs.mark();
    for (let round = 0; round < 6; round++) {
        const p = await pair();
        const memberTags = await tagsOf(p.member.user.id, p.roomId);
        const results = await Promise.all([
            p.member.deleteAccount().then(() => 'deleted', () => 'deleted-failed'),
            ...Array.from({ length: 4 }, (_, i) => p.member.sendRaw(p.memberChat.id, `гонка ${round}-${i}`).then(r => r.status)),
            p.owner.sendRaw(p.ownerChat.id, `владелец ${round}`).then(r => r.status),
        ]);
        for (const r of results.slice(1)) assert.ok([200, 401, 403, 404].includes(r), `ответ ${r} недопустим (503 busy означал бы 40P01)`);
        assert.strictEqual(results[0], 'deleted');
        assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM messages WHERE author_tag = ANY($1::bytea[])', [memberTags])).rows[0].n, 0);
    }
    assert.ok(!suite.server.logs.find(/40P01|Send message error|Delete chat error/, { from: mark }), 'ни взаимных блокировок, ни ошибок сервера');
});

// ---------- ответы и события ----------

test('ответы и события комнаты без user_id, chat_id, sender_username, sender_avatar и тега; mine - только отправителю; в истории mine нет; цитата - {id, seq, text, encrypted}', async () => {
    const p = await pair();
    const ownerSock = await p.owner.socket();
    const memberSock = await p.member.socket();
    try {
        const first = await p.owner.send(p.ownerChat.id, 'исходное');
        const reply = await p.member.send(p.memberChat.id, 'ответ', { replyToId: first.id });

        // Ответ на отправку
        for (const message of [first, reply]) {
            assert.deepStrictEqual(bannedPaths(message), [], 'ответ API');
            assert.strictEqual(message.mine, true, 'отправителю - mine: true');
            assert.strictEqual(message.room_id, p.roomId);
        }
        assert.deepStrictEqual(Object.keys(reply.reply_to).sort(), ['encrypted', 'id', 'seq', 'text']);
        assert.strictEqual(reply.reply_to.id, first.id);
        assert.strictEqual(reply.reply_to.text, fakeEnvelope('исходное'));

        // Событие: отправителю - копия на user:<id> с mine, остальным - без mine
        const atMember = await memberSock.waitFor('newMessage', m => m.id === first.id);
        const atOwner = await ownerSock.waitFor('newMessage', m => m.id === first.id);
        assert.deepStrictEqual(bannedPaths(atMember), []);
        assert.deepStrictEqual(bannedPaths(atOwner), []);
        assert.strictEqual(atMember.mine, undefined, 'получателю mine не отдаётся');
        assert.strictEqual(atOwner.mine, true, 'копия отправителю');

        // История: поля автора и mine отсутствуют, цитата без автора
        const history = await p.member.messages(p.memberChat.id);
        assert.deepStrictEqual(bannedPaths(history), []);
        assert.ok(history.messages.every(m => m.mine === undefined), 'в истории поля mine нет');
        const quoted = history.messages.find(m => m.id === reply.id).reply_to;
        assert.deepStrictEqual(Object.keys(quoted).sort(), ['encrypted', 'id', 'seq', 'text']);
        assert.strictEqual(quoted.text, fakeEnvelope('исходное'));

        // Правка: событие без автора; после удаления оригинала цитата пропадает
        await p.owner.edit(first.id, 'правлено');
        const edited = await memberSock.waitFor('messageEdited', e => e.id === first.id);
        assert.deepStrictEqual(bannedPaths(edited), []);
        assert.strictEqual(edited.mine, undefined);
        const editedOwn = await ownerSock.waitFor('messageEdited', e => e.id === first.id);
        assert.strictEqual(editedOwn.mine, true);
        await p.owner.del(`/api/messages/${first.id}`);
        const afterDelete = (await p.member.messages(p.memberChat.id)).messages.find(m => m.id === reply.id);
        assert.strictEqual(afterDelete.reply_to, null, 'внешний ключ reply_to_id обнулил ссылку на удалённое сообщение');
        assert.deepStrictEqual(bannedPaths(await p.member.messages(p.memberChat.id)), []);

        // Список чатов: нет полей автора и предпросмотра комнаты
        const list = await p.member.chats();
        assert.deepStrictEqual(bannedPaths(list), []);
        assert.strictEqual(list.find(c => c.id === p.memberChat.id).last_message, null);
    } finally {
        await ownerSock.close();
        await memberSock.close();
    }
});

test('без дублей отправителю: сокет автора (и в room:<id>, и в user:<id>) получает по одному newMessage / messageEdited / messageDeleted; остальные - по одному без mine', async () => {
    const p = await pair();
    const authorSock = await p.owner.socket();
    const authorTab2 = await p.owner.socket();
    const otherSock = await p.member.socket();
    try {
        const m = await p.owner.send(p.ownerChat.id, 'без дублей');
        await p.owner.edit(m.id, 'правка без дублей');
        await p.owner.del(`/api/messages/${m.id}`);
        // «Барьер»: последнее событие второго участника - всё предыдущее уже дошло.
        const barrier = await p.member.send(p.memberChat.id, 'барьер');
        for (const sock of [authorSock, authorTab2, otherSock]) await sock.waitFor('newMessage', e => e.id === barrier.id);
        for (const sock of [authorSock, authorTab2]) {
            for (const event of ['newMessage', 'messageEdited', 'messageDeleted']) {
                assert.strictEqual(sock.collect(event).filter(e => e.id === m.id).length, 1, `вкладка автора: ${event} ровно один раз`);
            }
        }
        for (const event of ['newMessage', 'messageEdited', 'messageDeleted']) {
            const got = otherSock.collect(event).filter(e => e.id === m.id);
            assert.strictEqual(got.length, 1, `другой участник: ${event} ровно один раз`);
            assert.strictEqual(got[0].mine, undefined, `другой участник: ${event} без mine`);
        }
    } finally {
        await authorSock.close();
        await authorTab2.close();
        await otherSock.close();
    }
});

// ---------- перенос и подмена ----------

test('строка enc:v3, перенесённая SQL-запросом в другую комнату или под другой id, и подмена author_tag возвращаются как «[Не удалось расшифровать]»', async () => {
    const p = await pair();
    const other = await pair({ name: 'Соседняя' });
    const a = await p.owner.send(p.ownerChat.id, 'для первой');
    const b = await p.owner.send(p.ownerChat.id, 'для первой, второе');
    const c = await other.owner.send(other.ownerChat.id, 'для соседней');
    const FAILED = '[Не удалось расшифровать]';
    const textOf = async (client, chatId, id) => (await client.messages(chatId)).messages.find(m => m.id === id).text;
    assert.strictEqual(await textOf(p.member, p.memberChat.id, a.id), fakeEnvelope('для первой'), 'до порчи читается');

    // 1) текст строки из другой комнаты
    const foreign = (await suite.query('SELECT text FROM messages WHERE id = $1', [c.id])).rows[0].text;
    await suite.query('UPDATE messages SET text = $1 WHERE id = $2', [foreign, a.id]);
    assert.strictEqual(await textOf(p.member, p.memberChat.id, a.id), FAILED, 'перенос между комнатами');
    // 2) обмен шифротекстами двух строк одной комнаты (другой id в AAD)
    const m1 = await p.owner.send(p.ownerChat.id, 'первое');
    const m2 = await p.owner.send(p.ownerChat.id, 'второе');
    const t1 = (await suite.query('SELECT text FROM messages WHERE id = $1', [m1.id])).rows[0].text;
    const t2 = (await suite.query('SELECT text FROM messages WHERE id = $1', [m2.id])).rows[0].text;
    await suite.query('UPDATE messages SET text = $1 WHERE id = $2', [t2, m1.id]);
    await suite.query('UPDATE messages SET text = $1 WHERE id = $2', [t1, m2.id]);
    assert.strictEqual(await textOf(p.member, p.memberChat.id, m1.id), FAILED, 'обмен внутри комнаты');
    assert.strictEqual(await textOf(p.member, p.memberChat.id, m2.id), FAILED);
    // 3) подмена author_tag при нетронутом тексте
    await suite.query('UPDATE messages SET author_tag = $1 WHERE id = $2', [crypto.randomBytes(16), b.id]);
    assert.strictEqual(await textOf(p.member, p.memberChat.id, b.id), FAILED, 'тег в AAD: подмена тега ломает расшифровку');
    // Соседняя комната не пострадала.
    assert.strictEqual(await textOf(other.member, other.memberChat.id, c.id), fakeEnvelope('для соседней'));
    // Вставленная без префикса строка в комнате тоже нечитаема.
    await suite.query(`UPDATE messages SET text = 'открытый текст' WHERE id = $1`, [m1.id]);
    assert.strictEqual(await textOf(p.member, p.memberChat.id, m1.id), FAILED);
});

// ---------- старая вкладка ----------

test('старая вкладка: отправка, правка и файл без proto или с proto < 4 - 400 client-outdated; proto после файла - тоже; на диск и в базу ничего не попадает', async () => {
    const p = await pair();
    const outdated = (res, what) => {
        assert.strictEqual(res.status, 400, `${what}: ${JSON.stringify(res.body)}`);
        assert.strictEqual(res.body.code, 'client-outdated', what);
        assert.strictEqual(res.body.success, false);
    };
    const m = await p.owner.send(p.ownerChat.id, 'для правки');
    const rowsBefore = Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1', [p.roomId])).rows[0].n);
    const filesBefore = fs.readdirSync(suite.server.uploadsDir).length;

    for (const proto of [undefined, 3, 0, '3', 'x', null, 3.5]) {
        outdated(await p.owner.sendRaw(p.ownerChat.id, 'старая вкладка', { proto }), `отправка, proto=${String(proto)}`);
        outdated(await p.owner.editRaw(m.id, 'правка старой вкладки', { proto }), `правка, proto=${String(proto)}`);
        outdated(await p.owner.uploadCipherRaw(p.ownerChat.id, { proto }), `файл, proto=${String(proto)}`);
    }
    // proto раньше остальных проверок: даже при неверном id вкладка слышит «обновите страницу», а не bad-message-id.
    outdated(await p.owner.sendRaw(p.ownerChat.id, 'x', { proto: undefined, clientMessageId: 'abc' }), 'proto первым, до id');
    // Поле proto после файла: при проверке перед приёмом файла его ещё нет.
    const form = new FormData();
    form.append('chatId', String(p.ownerChat.id));
    form.append('encrypted', 'true');
    form.append('clientMessageId', String(crypto.randomInt(1000000, 2 ** 31 - 1)));
    form.append('envelope', fakeEnvelope('поздний proto'));
    form.append('file', new Blob([crypto.randomBytes(300)], { type: 'application/octet-stream' }), 'file.bin');
    form.append('proto', '4');
    outdated(await p.owner.request('POST', '/api/messages/file', { body: form }), 'proto после файла');
    // Чат с ботом тоже требует признак версии.
    const bot = await p.owner.botChat();
    outdated(await p.owner.sendRaw(bot.id, 'привет', { proto: undefined }), 'бот без proto');
    // Больший proto принимается (в одном выкате такого нет, но будущий клиент не ломается).
    assert.strictEqual((await p.owner.sendRaw(p.ownerChat.id, 'новая вкладка', { proto: 5 })).status, 200);

    assert.strictEqual(Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1', [p.roomId])).rows[0].n), rowsBefore + 1, 'в базе только сообщение с proto 5');
    assert.strictEqual(fs.readdirSync(suite.server.uploadsDir).length, filesBefore, 'на диск ничего не записано');
    // Чтение остаётся доступным старой вкладке.
    assert.strictEqual((await p.owner.get(`/api/messages/${p.ownerChat.id}`)).body.success, true);
});
