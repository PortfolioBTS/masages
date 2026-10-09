'use strict';
// Удаление аккаунта: POST /api/account/delete и его псевдоним POST /api/logout
// (контракт волны 1, §3). Выйти из временного аккаунта и значит удалить его.
//
//   запрос:  тело {} — пароль не нужен;
//   ответ:   { success:true, message:'Аккаунт и все данные удалены' } и
//            заголовок Clear-Site-Data: "cache";
//   сервер:  удаляет всё (сообщения, файлы, комнаты, где пользователь остался
//            последним, ключи, сессии, заявки), закрывает сокеты, очищает
//            куку сессии и выдаёт новую CSRF-куку.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { setCookies, sessionCookie, userRow, count } = require('./helpers/anon');

const suite = createSuite('account');

const DELETED = { success: true, message: 'Аккаунт и все данные удалены' };
// 1×1 PNG: вложение, которое должно уйти с диска вместе с аккаунтом.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
const KEY_B64 = () => crypto.randomBytes(32).toString('base64');

const uploads = () => (fs.existsSync(suite.server.uploadsDir) ? fs.readdirSync(suite.server.uploadsDir) : []);
const onDisk = (message) => uploads().includes(path.basename(message.file_url));

async function account(lifetime = 'tab') {
    const client = suite.client();
    const user = await client.registerAnon({ lifetime });
    return { client, user };
}

// Копия куки сессии на «втором устройстве».
function secondDevice(client) {
    const copy = suite.client();
    copy.withCookie('connect.sid', sessionCookie(client).value);
    return copy;
}

// Всё, что называется «следами» пользователя в базе: по строке на таблицу.
async function traces(userId) {
    const id = [userId];
    const text = [String(userId)];
    return {
        users: await count(suite, 'SELECT 1 FROM users WHERE id = $1', id),
        chats: await count(suite, 'SELECT 1 FROM chats WHERE user_id = $1', id),
        messages: await count(suite, 'SELECT 1 FROM messages WHERE user_id = $1', id),
        room_participants: await count(suite, 'SELECT 1 FROM room_participants WHERE user_id = $1', id),
        join_requests: await count(suite, 'SELECT 1 FROM join_requests WHERE user_id = $1', id),
        e2ee_key_shares: await count(suite, 'SELECT 1 FROM e2ee_key_shares WHERE sender_id = $1 OR recipient_id = $1', id),
        reactions: await count(suite, 'SELECT 1 FROM reactions WHERE user_id = $1', id),
        identity_keys: await count(suite, 'SELECT 1 FROM identity_keys WHERE user_id = $1', id),
        signed_prekeys: await count(suite, 'SELECT 1 FROM signed_prekeys WHERE user_id = $1', id),
        one_time_prekeys: await count(suite, 'SELECT 1 FROM one_time_prekeys WHERE user_id = $1', id),
        signed_pq_prekeys: await count(suite, 'SELECT 1 FROM signed_pq_prekeys WHERE user_id = $1', id),
        session: await count(suite, `SELECT 1 FROM session WHERE sess->>'userId' = $1`, text),
    };
}
const NO_TRACES = Object.freeze({
    users: 0, chats: 0, messages: 0, room_participants: 0, join_requests: 0, e2ee_key_shares: 0, reactions: 0,
    identity_keys: 0, signed_prekeys: 0, one_time_prekeys: 0, signed_pq_prekeys: 0, session: 0,
});

// Общая часть проверок ответа на удаление: тело, Clear-Site-Data, куки.
function assertDeletionResponse(res, csrfBefore, client, what) {
    assert.strictEqual(res.status, 200, what);
    assert.deepStrictEqual(res.body, DELETED, what);
    assert.strictEqual(res.headers.get('clear-site-data'), '"cache"', `${what}: Clear-Site-Data`);
    // Кука сессии очищена (и в «браузере» её больше нет), CSRF-кука выдана новая.
    const session = setCookies(res);
    assert.ok(session.length >= 1 && session.every(c => c.value === '' && c.expiresAt !== null && c.expiresAt <= Date.now()), `${what}: кука сессии должна быть очищена: ${JSON.stringify(session)}`);
    assert.strictEqual(sessionCookie(client), null, `${what}: в браузере куки сессии не осталось`);
    const csrf = setCookies(res, 'csrf_token');
    assert.strictEqual(csrf.length, 1, `${what}: новая CSRF-кука`);
    assert.notStrictEqual(csrf[0].value, csrfBefore, `${what}: CSRF-токен новый`);
}

test('удаление стирает всё: сообщения, файлы, комнаты, где остался последним, ключи, сессии, заявки; сокеты закрыты', async () => {
    const victim = await account('tab');
    const friend = await account('day');
    const outsider = await account('week');
    const { client: v } = victim;
    const { client: f } = friend;
    const { client: o } = outsider;
    const vId = victim.user.id;
    const logsMark = suite.server.logs.mark();

    // Сокеты — до создания комнат (подписка на новые комнаты идёт через личную комнату пользователя).
    const vSock = await v.socket();
    const friendSock = await f.socket();
    const spy = secondDevice(v);
    assert.strictEqual((await spy.auth()).authenticated, true, 'копия куки до удаления работает');
    const spySock = await spy.socket();

    // Комната, где остаётся друг; комната, где пользователь один, и чужая заявка в неё; своя заявка в чужую комнату.
    const shared = await roomWithMember(v, f, { name: 'Общая' });
    const solo = await v.createRoom('Только я');
    const soloInvite = await v.invite(solo.id);
    const outsiderPending = await o.join(soloInvite.code);
    assert.strictEqual(outsiderPending.pending, true);
    const othersRoom = await o.createRoom('Комната чужая');
    const victimPending = await v.join((await o.invite(othersRoom.id)).code);
    assert.strictEqual(victimPending.pending, true);

    // Сообщения и файлы: бот, одинокая комната, общая комната; у друга — свои.
    const bot = await v.botChat();
    await v.send(bot.id, 'вопрос боту');
    const botFile = await v.upload(bot.id, PNG, 'image/png', { filename: 'bot.png' });
    await v.send(solo.id, 'сообщение в одинокой комнате');
    const sharedFile = await v.upload(shared.ownerChat.id, PNG, 'image/png', { filename: 'shared.png' });
    const victimSharedMessage = await v.send(shared.ownerChat.id, 'сообщение пользователя в общей комнате');
    const friendMessage = await f.send(shared.memberChat.id, 'сообщение друга');
    const friendFile = await f.upload(shared.memberChat.id, PNG, 'image/png', { filename: 'friend.png' });
    // Реакции в обе стороны (прямой вставкой: набор проверяет удаление, а не API реакций).
    await suite.query(`INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, 'like'), ($3, $4, 'like')`,
        [friendMessage.id, vId, victimSharedMessage.id, friend.user.id]);
    // Публичные ключи и key-share в обе стороны.
    for (const client of [v, f]) {
        await client.ok(client.put('/api/keys/identity', { identity_signing_key: KEY_B64(), identity_dh_key: KEY_B64() }), 'публикация ключей');
    }
    // Остальные публичные ключи — прямой вставкой: подпись prekey проверяется по-настоящему, а набору нужны строки.
    await suite.query('INSERT INTO signed_prekeys (user_id, key_id, public_key, signature) VALUES ($1, 1, $2, $3)', [vId, crypto.randomBytes(32), crypto.randomBytes(64)]);
    await suite.query('INSERT INTO signed_pq_prekeys (user_id, key_id, public_key, signature) VALUES ($1, 1, $2, $3)', [vId, crypto.randomBytes(1184), crypto.randomBytes(64)]);
    await suite.query('INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES ($1, 1, $2), ($1, 2, $3)', [vId, crypto.randomBytes(32), crypto.randomBytes(32)]);
    await v.ok(v.post('/api/keys/key-shares', { chatId: shared.ownerChat.id, shares: [{ recipientUserId: friend.user.id, ciphertext: 'c2hhcmUtdjJm' }] }), 'key-share от пользователя');
    await f.ok(f.post('/api/keys/key-shares', { chatId: shared.memberChat.id, shares: [{ recipientUserId: vId, ciphertext: 'c2hhcmUtZjJ2' }] }), 'key-share пользователю');

    // До удаления следы есть везде, где должны быть.
    const before = await traces(vId);
    for (const [table, n] of Object.entries(before)) assert.ok(n >= 1, `до удаления в ${table} ничего нет — проверка была бы пустой`);
    assert.ok(onDisk(botFile) && onDisk(sharedFile) && onDisk(friendFile));
    const csrfBefore = await v.csrfToken();

    // Удаление.
    const res = await v.post('/api/account/delete', {});
    assertDeletionResponse(res, csrfBefore, v, 'account/delete');

    // Сокеты всех устройств закрыты сервером.
    for (const [who, sock] of [['основной', vSock], ['второго устройства', spySock]]) {
        const gone = await sock.waitFor('disconnect');
        assert.strictEqual(gone.reason, 'io server disconnect', `сокет ${who}`);
    }
    // Куки — на втором устройстве и у самого клиента — больше ничего не открывают.
    assert.deepStrictEqual(await spy.auth(), { authenticated: false, onionUrl: null });
    assert.deepStrictEqual(await v.auth(), { authenticated: false, onionUrl: null });

    // В базе пусто; чужие данные целы.
    assert.deepStrictEqual(await traces(vId), NO_TRACES);
    assert.strictEqual(await userRow(suite, vId), null);
    assert.strictEqual(await count(suite, 'SELECT 1 FROM rooms WHERE id = $1', [solo.room_id]), 0, 'комната, где он был один, удалена');
    assert.strictEqual(await count(suite, 'SELECT 1 FROM join_requests WHERE room_id = $1', [solo.room_id]), 0, 'заявки в неё удалены');
    assert.strictEqual(await count(suite, 'SELECT 1 FROM join_requests WHERE room_id = $1', [othersRoom.room_id]), 0, 'его заявка в чужую комнату удалена');
    assert.strictEqual(await count(suite, 'SELECT 1 FROM rooms WHERE id = $1', [othersRoom.room_id]), 1, 'чужая комната на месте');
    assert.strictEqual(await count(suite, 'SELECT 1 FROM rooms WHERE id = $1', [shared.roomId]), 1, 'общая комната на месте');
    assert.deepStrictEqual((await suite.query('SELECT user_id FROM room_participants WHERE room_id = $1', [shared.roomId])).rows.map(r => r.user_id), [friend.user.id]);

    // Друг видит свои сообщения, но не сообщения ушедшего; его реакция на них исчезла вместе с ними.
    const kept = (await f.messages(shared.memberChat.id)).messages.map(m => m.id);
    assert.ok(kept.includes(friendMessage.id));
    assert.ok(!kept.includes(victimSharedMessage.id));
    assert.strictEqual(await count(suite, 'SELECT 1 FROM reactions WHERE message_id = $1', [victimSharedMessage.id]), 0);
    assert.strictEqual(await count(suite, 'SELECT 1 FROM reactions WHERE message_id = $1', [friendMessage.id]), 0, 'реакция ушедшего на сообщение друга удалена');
    // Друг узнаёт, что состав комнаты изменился.
    await friendSock.waitFor('roomMembersChanged', payload => payload.roomId === shared.roomId);

    // Файлы ушедшего убраны с диска, файл друга остался и открывается.
    await waitUntil(() => !onDisk(botFile) && !onDisk(sharedFile), { what: 'файлы удалённого аккаунта убраны с диска' });
    assert.ok(onDisk(friendFile), 'файл друга должен остаться');
    assert.strictEqual((await f.download(friendFile.file_url)).status, 200);
    assert.strictEqual((await o.download(botFile.file_url)).status, 403, 'удалённый файл посторонним не отдаётся');

    // В логе сервера — никаких идентифицирующих данных удалённого аккаунта.
    suite.server.logs.assertNoSensitive({ ids: [vId], usernames: [victim.user.username], codes: [victim.user.uniqueCode, soloInvite.code] }, { from: logsMark });

    // В том же браузере можно зарегистрироваться заново: сессия очищена, CSRF-кука новая, 409 нет.
    const again = await v.registerAnon({ lifetime: 'day' });
    assert.notStrictEqual(again.id, vId);
    assert.strictEqual((await v.auth()).user.id, again.id);
    await friendSock.close();
});

test('POST /api/logout — псевдоним удаления: тот же ответ, Clear-Site-Data, куки, сокет и копия куки', async () => {
    const { client, user } = await account('week');
    const bot = await client.botChat();
    await client.send(bot.id, 'прощальное сообщение');
    const file = await client.upload(bot.id, PNG, 'image/png', { filename: 'x.png' });
    const solo = await client.createRoom('Моя комната');
    await client.send(solo.id, 'в пустоту');
    const sock = await client.socket();
    const spy = secondDevice(client);
    assert.strictEqual((await spy.auth()).authenticated, true);
    const csrfBefore = await client.csrfToken();

    const res = await client.post('/api/logout', {});
    assertDeletionResponse(res, csrfBefore, client, 'logout');
    assert.strictEqual((await sock.waitFor('disconnect')).reason, 'io server disconnect');
    assert.strictEqual((await spy.auth()).authenticated, false, 'копия куки недействительна');
    assert.deepStrictEqual(await traces(user.id), NO_TRACES);
    assert.strictEqual(await count(suite, 'SELECT 1 FROM rooms WHERE id = $1', [solo.room_id]), 0);
    await waitUntil(() => !onDisk(file), { what: 'файл убран с диска' });
});

test('удаление с копии куки на другом устройстве: основной браузер тоже остаётся без аккаунта', async () => {
    const { client, user } = await account('day');
    const sock = await client.socket();
    const other = secondDevice(client);
    const res = await other.post('/api/account/delete', {});
    assert.deepStrictEqual(res.body, DELETED);
    assert.strictEqual((await sock.waitFor('disconnect')).reason, 'io server disconnect');
    assert.strictEqual((await client.auth()).authenticated, false);
    assert.strictEqual(await userRow(suite, user.id), null);
});

test('без входа — «Не авторизован» (оба адреса); без CSRF-токена — 403 и аккаунт цел; лишние поля тела игнорируются', async () => {
    for (const urlPath of ['/api/account/delete', '/api/logout']) {
        const guest = suite.client();
        const res = await guest.post(urlPath, {});
        assert.deepStrictEqual(res.body, { success: false, message: 'Не авторизован' }, urlPath);
        assert.strictEqual(res.headers.get('clear-site-data'), null, `${urlPath}: без аккаунта страницу чистить незачем`);
    }

    const { client, user } = await account('tab');
    for (const urlPath of ['/api/account/delete', '/api/logout']) {
        assert.strictEqual((await client.post(urlPath, {}, { csrf: false })).status, 403, urlPath);
        assert.strictEqual((await client.post(urlPath, {}, { csrf: 'wrong-token' })).status, 403, urlPath);
    }
    assert.ok(await userRow(suite, user.id), 'отказ по CSRF не должен удалять аккаунт');

    // Пароль не нужен и не проверяется: поле, если его прислал старый клиент, ничего не меняет.
    const res = await client.post('/api/account/delete', { password: 'что-угодно', confirm: true });
    assert.deepStrictEqual(res.body, DELETED);
    assert.strictEqual(await userRow(suite, user.id), null);
});
