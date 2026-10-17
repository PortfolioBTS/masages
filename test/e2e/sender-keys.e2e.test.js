'use strict';
// Sender Key: серверная часть ротации и запросов ключа на настоящем сервере и
// Postgres (план криптографии, раздел 5, «Сервер»; ворота G3).
//
// * key-share: вместо отказа при переполнении очереди вытесняются самые старые
//   строки (200 на отправителя, 1000 на получателя в комнате); не больше 30
//   отправок в час на пару (пользователь, комната);
// * запросы ключа: запись, ретрансляция сокетом, чтение владельцем, снятие своих
//   строк, срок 7 суток, лимиты (10 в час, 50 строк, 20 id), уборка при выходе из
//   комнаты, удалении аккаунта и комнаты.
//
// Клиентская криптография здесь не участвует (её проверяют протокольные тесты
// test/sender-keys-*.test.js): конверты key-share для сервера непрозрачны.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { purgeExpiredKeyRequests, KEY_REQUEST_TTL_HOURS, MAX_PENDING_KEY_REQUESTS } = require('../../lib/e2ee-groups');
const { advisoryLockKey } = require('../../lib/advisory-locks');

const suite = createSuite('sender-keys');

const HOUR_MS = 60 * 60 * 1000;
const keyId = () => crypto.randomBytes(16).toString('base64');
const countRows = async (sql, params = []) => Number((await suite.query(sql, params)).rows[0].n);
const requestRows = (roomId) => countRows('SELECT count(*) AS n FROM e2ee_key_requests WHERE room_id = $1', [roomId]);

// Комната из владельца и members участников; у каждого свой чат.
async function room(members = 2, { name = 'Ключи' } = {}) {
    const owner = suite.client({ name: 'владелец' });
    await owner.registerAnon();
    const ownerChat = await owner.createRoom(name);
    const { code } = await owner.invite(ownerChat.id);
    const users = [];
    for (let i = 0; i < members; i++) {
        const member = suite.client({ name: 'участник ' + (i + 1) });
        await member.registerAnon();
        const pending = await member.join(code);
        await owner.approve(pending.requestId);
        const chat = (await member.chats()).find(c => c.room_id === ownerChat.room_id);
        users.push({ client: member, id: member.user.id, chatId: chat.id });
    }
    return {
        roomId: ownerChat.room_id,
        owner: { client: owner, id: owner.user.id, chatId: ownerChat.id },
        users,
    };
}

const postShares = (who, shares) => who.client.post('/api/keys/key-shares', { chatId: who.chatId, shares });
const share = (recipientUserId, text = 'x') => ({ recipientUserId, ciphertext: `${text}-${crypto.randomBytes(6).toString('hex')}` });
const getShares = async (who) => (await who.client.get(`/api/keys/key-shares/${who.chatId}`)).body;
const askKeys = (who, ids) => who.client.post('/api/keys/key-requests', { chatId: who.chatId, senderKeyIds: ids });
const pending = async (who) => (await who.client.get(`/api/keys/key-requests/${who.chatId}`)).body;

// Пока тест держит блокировку фоновой задачи jobName, её проходы на сервере пропускаются: сервер набора запускает задачи
// обслуживания каждые 300 мс (NYXO_TEST_MAINTENANCE_MS) и под той же advisory-блокировкой (lib/advisory-locks.js, createRunExclusive).
// Без неё уборка просроченных запросов ключа могла удалить строку между шагами теста: проверки стали бы гонкой.
// pg_advisory_lock ждёт, если проход уже идёт, поэтому после возврата своих проходов у задачи нет. Возвращает функцию снятия.
async function holdJobLock(jobName) {
    const key = advisoryLockKey(`job:${jobName}`);
    const client = await suite.db.connect();
    try {
        await client.query('SELECT pg_advisory_lock($1::bigint)', [key]);
    } catch (error) {
        client.release();
        throw error;
    }
    // Контроль самого приёма: с другого соединения блокировку взять нельзя, значит runExclusive сервера её тоже не возьмёт.
    const probe = await suite.db.connect();
    try {
        const taken = (await probe.query('SELECT pg_try_advisory_lock($1::bigint) AS locked', [key])).rows[0].locked;
        if (taken) await probe.query('SELECT pg_advisory_unlock($1::bigint)', [key]);
        assert.strictEqual(taken, false, 'блокировка задачи ' + jobName + ' удержана тестом');
    } finally {
        probe.release();
    }
    return async () => {
        try {
            await client.query('SELECT pg_advisory_unlock($1::bigint)', [key]);
        } finally {
            client.release();
        }
    };
}

test('схема: таблица запросов ключа без точного времени (только час), id ключа — 16 байт', async () => {
    const cols = await suite.query(
        `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'e2ee_key_requests' ORDER BY ordinal_position`);
    assert.deepStrictEqual(cols.rows.map(r => [r.column_name, r.data_type]), [
        ['id', 'integer'], ['room_id', 'integer'], ['requester_id', 'integer'], ['key_id', 'bytea'], ['created_hour', 'integer'],
    ]);
});

test('key-share: переполнение очереди одним отправителем (200) вытесняет самые старые строки, запрос успешен', async () => {
    const r = await room(1);
    const [bob] = r.users;
    const sender = r.owner;
    const first = Array.from({ length: 150 }, (_, i) => share(bob.id, 'a' + i));
    const second = Array.from({ length: 150 }, (_, i) => share(bob.id, 'b' + i));
    assert.strictEqual((await postShares(sender, first)).body.success, true);
    const over = await postShares(sender, second);
    assert.strictEqual(over.status, 200);
    assert.strictEqual(over.body.success, true, JSON.stringify(over.body));
    const got = await getShares(bob);
    assert.strictEqual(got.shares.length, 200, 'в очереди 200 строк от отправителя');
    const texts = got.shares.map(s => s.ciphertext);
    // Вставка идёт по порядку массива: самые старые - a0..a149, затем b0..b149. Вытеснены a0..a99.
    const fromA = texts.filter(t => t.startsWith('a')).map(t => Number(t.slice(1, t.indexOf('-')))).sort((x, y) => x - y);
    assert.deepStrictEqual(fromA, Array.from({ length: 50 }, (_, i) => 100 + i), 'старые строки вытеснены, новые на месте');
    assert.strictEqual(texts.filter(t => t.startsWith('b')).length, 150);
    assert.deepStrictEqual((await getShares(bob)).shares, [], 'очередь забрана');
});

test('key-share: общий потолок получателя 1000 вытесняет самые старые строки; шум одного отправителя чужие ключи не вытесняет', async () => {
    const r = await room(6);
    const [bob, ...others] = r.users;
    const senders = [r.owner, ...others]; // 6 отправителей по 200 строк
    for (const sender of senders) {
        const res = await postShares(sender, Array.from({ length: 200 }, (_, i) => share(bob.id, `s${sender.id}-${i}`)));
        assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
    }
    // 6 x 200 = 1200 > 1000: запрос последнего отправителя прошёл, вытеснены 200 самых старых - строки владельца.
    const queue = (await suite.query('SELECT sender_id, count(*)::int AS n FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2 GROUP BY sender_id', [r.roomId, bob.id])).rows;
    assert.strictEqual(queue.reduce((sum, row) => sum + row.n, 0), 1000);
    assert.ok(!queue.some(row => row.sender_id === r.owner.id), 'самые старые строки (владельца) вытеснены');
    assert.ok(queue.every(row => row.n === 200), 'остальные отправители целы');

    // Шум одного отправителя: ещё 50 строк от последнего вытесняют его же старые (потолок 200), чужие целы.
    const noisy = senders[senders.length - 1];
    const extra = await postShares(noisy, Array.from({ length: 50 }, (_, i) => share(bob.id, `new-${i}`)));
    assert.strictEqual(extra.body.success, true, JSON.stringify(extra.body));
    const got = await getShares(bob);
    assert.strictEqual(got.shares.length, 1000);
    assert.strictEqual(got.shares.filter(s => s.ciphertext.startsWith('new-')).length, 50);
    assert.strictEqual(got.shares.filter(s => s.ciphertext.startsWith(`s${noisy.id}-`)).length, 150, 'у шумного вытеснены его же 50 старых');
    for (const sender of senders.slice(1, -1)) {
        assert.strictEqual(got.shares.filter(s => s.ciphertext.startsWith(`s${sender.id}-`)).length, 200, 'чужие ключи целы');
    }
});

test('key-share: не больше 30 отправок в час на пару (пользователь, комната); другая комната и другой пользователь считаются отдельно', async () => {
    const r = await room(1);
    const [bob] = r.users;
    for (let i = 0; i < 30; i++) {
        const res = await postShares(r.owner, [share(bob.id)]);
        assert.strictEqual(res.body.success, true, 'отправка ' + (i + 1) + ': ' + JSON.stringify(res.body));
    }
    const limited = await postShares(r.owner, [share(bob.id)]);
    assert.strictEqual(limited.status, 429);
    assert.strictEqual(limited.body.success, false);
    assert.ok(Number(limited.headers.get('retry-after')) > 0, 'Retry-After');
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM e2ee_key_shares WHERE room_id = $1 AND sender_id = $2', [r.roomId, r.owner.id]), 30, 'отказанная отправка ничего не записала');
    assert.strictEqual((await postShares(bob, [share(r.owner.id)])).body.success, true, 'другой пользователь — своя квота');
    // Та же пара в другой комнате: своя квота.
    const other = await r.owner.client.createRoom('Вторая');
    const { code } = await r.owner.client.invite(other.id);
    const pendingJoin = await bob.client.join(code);
    await r.owner.client.approve(pendingJoin.requestId);
    const viaOther = await r.owner.client.post('/api/keys/key-shares', { chatId: other.id, shares: [share(bob.id)] });
    assert.strictEqual(viaOther.body.success, true, JSON.stringify(viaOther.body));
});

test('запрос ключа: запись, ретрансляция всем участникам кроме запросившего, чтение владельцем', async () => {
    const r = await room(2);
    const [bob, carol] = r.users;
    const ownerSock = await r.owner.client.socket();
    const carolSock = await carol.client.socket();
    const bobSock = await bob.client.socket();
    try {
        const ids = [keyId(), keyId()];
        const mark = bobSock.mark();
        const res = await askKeys(bob, ids);
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, { success: true, requested: 2 });
        for (const sock of [ownerSock, carolSock]) {
            const event = await sock.waitFor('e2eeKeyRequest');
            assert.deepStrictEqual(event, { roomId: r.roomId, fromUserId: bob.id, senderKeyIds: ids });
        }
        await new Promise(resolve => setTimeout(resolve, 300));
        assert.deepStrictEqual(bobSock.collect('e2eeKeyRequest', { since: mark }), [], 'запросившему сигнал не уходит');

        // Владелец (был бы офлайн) читает ожидающие запросы; свои запросы запросивший не видит.
        const forOwner = await pending(r.owner);
        assert.deepStrictEqual(forOwner.requests, [{ fromUserId: bob.id, senderKeyIds: ids }]);
        assert.deepStrictEqual((await pending(bob)).requests, []);
        assert.strictEqual((await pending(carol)).requests.length, 1);
        // Чтение строк не удаляет.
        assert.strictEqual((await pending(r.owner)).requests.length, 1);
    } finally {
        await Promise.all([ownerSock.close(), carolSock.close(), bobSock.close()]);
    }
});

test('запрос ключа: повтор продлевает срок и не плодит строк; плохие данные — 400; чужой чат и чат с ботом — отказ', async () => {
    const r = await room(1);
    const [bob] = r.users;
    const id = keyId();
    assert.strictEqual((await askKeys(bob, [id, id])).body.success, true);
    assert.strictEqual(await requestRows(r.roomId), 1);
    await suite.query('UPDATE e2ee_key_requests SET created_hour = created_hour - 100 WHERE room_id = $1', [r.roomId]);
    const before = Number((await suite.query('SELECT created_hour FROM e2ee_key_requests WHERE room_id = $1', [r.roomId])).rows[0].created_hour);
    await askKeys(bob, [id]);
    const after = Number((await suite.query('SELECT created_hour FROM e2ee_key_requests WHERE room_id = $1', [r.roomId])).rows[0].created_hour);
    assert.strictEqual(after, before + 100, 'повторный запрос обновил время');
    assert.strictEqual(await requestRows(r.roomId), 1);

    for (const ids of [[], 'abc', ['x'], [crypto.randomBytes(15).toString('base64')], [5], Array.from({ length: 21 }, keyId)]) {
        assert.strictEqual((await askKeys(bob, ids)).status, 400, JSON.stringify(ids).slice(0, 60));
    }
    const stranger = suite.client({ name: 'посторонний' });
    await stranger.registerAnon();
    const foreign = await stranger.post('/api/keys/key-requests', { chatId: bob.chatId, senderKeyIds: [keyId()] });
    assert.strictEqual(foreign.body.success, false, 'чужой чат');
    const bot = await stranger.botChat();
    const viaBot = await stranger.post('/api/keys/key-requests', { chatId: bot.id, senderKeyIds: [keyId()] });
    assert.strictEqual(viaBot.body.success, false, 'у чата с ботом нет комнаты');
    assert.strictEqual(await requestRows(r.roomId), 1);
});

test('запрос ключа: не больше 50 ожидающих строк на пару — лишние старые вытесняются; не больше 10 запросов в час', async () => {
    const r = await room(1);
    const [bob] = r.users;
    const all = [];
    for (let i = 0; i < 3; i++) {
        const ids = Array.from({ length: 20 }, keyId);
        all.push(...ids);
        const res = await askKeys(bob, ids);
        assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
        // Время запроса растёт, чтобы порядок вытеснения был однозначным.
        await suite.query('UPDATE e2ee_key_requests SET created_hour = created_hour - $2 WHERE room_id = $1 AND key_id = ANY($3::bytea[])',
            [r.roomId, 10 - i * 3, ids.map(id => Buffer.from(id, 'base64'))]);
    }
    assert.strictEqual(await requestRows(r.roomId), MAX_PENDING_KEY_REQUESTS);
    const kept = (await pending(r.owner)).requests[0].senderKeyIds;
    assert.ok(all.slice(10).every(id => kept.includes(id)), 'последние 50 на месте');
    assert.ok(all.slice(0, 10).every(id => !kept.includes(id)), 'первые 10 вытеснены');

    // Уже сделано 3 запроса из 10 в час.
    for (let i = 3; i < 10; i++) assert.strictEqual((await askKeys(bob, [keyId()])).body.success, true, 'запрос ' + (i + 1));
    const limited = await askKeys(bob, [keyId()]);
    assert.strictEqual(limited.status, 429);
    assert.ok(Number(limited.headers.get('retry-after')) > 0);
});

test('запрос ключа: done стирает только свои строки; срок 7 суток — просроченные не отдаются и убираются задачей уборки', async () => {
    const r = await room(2);
    const [bob, carol] = r.users;
    const shared = keyId();
    const own = keyId();
    await askKeys(bob, [shared, own]);
    await askKeys(carol, [shared]);
    assert.strictEqual(await requestRows(r.roomId), 3);
    const done = await bob.client.post('/api/keys/key-requests/done', { chatId: bob.chatId, senderKeyIds: [shared, own] });
    assert.strictEqual(done.body.success, true);
    const left = await suite.query('SELECT requester_id FROM e2ee_key_requests WHERE room_id = $1', [r.roomId]);
    assert.deepStrictEqual(left.rows.map(row => row.requester_id), [carol.id], 'строка Кэрол цела');
    assert.strictEqual((await bob.client.post('/api/keys/key-requests/done', { chatId: bob.chatId, senderKeyIds: ['плохой'] })).status, 400);
    assert.strictEqual((await carol.client.post('/api/keys/key-requests/done', { chatId: bob.chatId, senderKeyIds: [shared] })).body.success, false, 'чужой чат');

    // Просроченная строка (старше 7 суток) не отдаётся владельцу и убирается задачей уборки. Фоновые проходы сервера на это
    // время приостановлены (holdJobLock): иначе они удалили бы строку между шагами, и проверки зависели бы от тайминга.
    const release = await holdJobLock('purgeKeyRequests');
    try {
        await suite.query('UPDATE e2ee_key_requests SET created_hour = created_hour - $2 WHERE room_id = $1', [r.roomId, KEY_REQUEST_TTL_HOURS + 1]);
        assert.deepStrictEqual((await pending(r.owner)).requests, []);
        assert.strictEqual(await requestRows(r.roomId), 1, 'просроченная строка ещё в таблице, но не отдаётся');
        const removed = await purgeExpiredKeyRequests(suite.db);
        assert.ok(removed >= 1, 'задача уборки удалила просроченное: ' + removed);
        assert.strictEqual(await requestRows(r.roomId), 0);
        // Свежая строка задачей уборки не трогается.
        await askKeys(carol, [keyId()]);
        await purgeExpiredKeyRequests(suite.db);
        assert.strictEqual(await requestRows(r.roomId), 1);
    } finally {
        await release();
    }

    // Блокировка снята: настоящая фоновая задача сервера (проходы каждые 300 мс) сама убирает просроченную строку,
    // свежие остаются. Так проверено и то, что приём с блокировкой не скрыл неработающую задачу.
    await suite.query('UPDATE e2ee_key_requests SET created_hour = created_hour - $2 WHERE room_id = $1', [r.roomId, KEY_REQUEST_TTL_HOURS + 1]);
    await askKeys(bob, [keyId()]);
    await waitUntil(async () => (await requestRows(r.roomId)) === 1, { timeoutMs: 15000, intervalMs: 100, what: 'фоновая уборка просроченного запроса ключа' });
    const rest = await suite.query('SELECT requester_id FROM e2ee_key_requests WHERE room_id = $1', [r.roomId]);
    assert.deepStrictEqual(rest.rows.map(row => row.requester_id), [bob.id], 'осталась только свежая строка Боба');
});

test('запросы ключа уходят вместе с участием: выход из комнаты, удаление аккаунта и комнаты', async () => {
    const r = await room(2);
    const [bob, carol] = r.users;
    await askKeys(bob, [keyId()]);
    await askKeys(carol, [keyId()]);
    assert.strictEqual(await requestRows(r.roomId), 2);
    await bob.client.leave(bob.chatId);
    assert.strictEqual(await requestRows(r.roomId), 1, 'вышедший: его строки удалены');
    await carol.client.deleteAccount();
    assert.strictEqual(await requestRows(r.roomId), 0, 'удалённый аккаунт: строк нет');

    // Каскад по комнате: последний вышел — комната и все строки пропали.
    const solo = await room(1);
    await askKeys(solo.users[0], [keyId()]);
    await solo.users[0].client.leave(solo.users[0].chatId);
    await solo.owner.client.leave(solo.owner.chatId);
    assert.strictEqual(await requestRows(solo.roomId), 0);
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM rooms WHERE id = $1', [solo.roomId]), 0);
});

test('key-share при переполнении не мешает другим получателям той же рассылки', async () => {
    const r = await room(2);
    const [bob, carol] = r.users;
    // Bob давно не заходил: у него 200 строк от владельца. Рассылка нового ключа обоим проходит.
    assert.strictEqual((await postShares(r.owner, Array.from({ length: 200 }, (_, i) => share(bob.id, 'old' + i)))).body.success, true);
    const res = await postShares(r.owner, [share(bob.id, 'new'), share(carol.id, 'new')]);
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
    assert.strictEqual((await getShares(carol)).shares.length, 1, 'Кэрол получила ключ');
    const bobShares = (await getShares(bob)).shares;
    assert.strictEqual(bobShares.length, 200);
    assert.ok(bobShares.some(s => s.ciphertext.startsWith('new-')), 'новый ключ у Боба есть');
    assert.ok(!bobShares.some(s => s.ciphertext.startsWith('old0-')), 'самый старый вытеснен');
});
