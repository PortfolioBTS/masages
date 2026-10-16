'use strict';
// Минимизация логов (пункт 4.7 плана, T5.2): после типичного сценария в логе
// процесса сервера нет id созданных сущностей, IP клиентов, имён, кодов
// приглашений, sid, имён файлов, текстов и секретов.
//
// Сценарий: регистрация троих, комната с заявкой и одобрением, сообщения
// (правка и удаление), вложение, запросы с ошибками (битый JSON, чужой Origin,
// неверный код приглашения, запрещённый файл, id вне диапазона int), сбой базы
// с detail, где лежит id пользователя (триггер Postgres), и удаление
// аккаунтов. Проверка идёт по буферу stdout и stderr сервера целиком, с
// самого старта.
//
// Сбой базы нужен, чтобы ловить регресс именно там, где он вероятнее всего: до
// T5.2 обработчики печатали объект ошибки Postgres целиком, и в логе оказывались
// detail («Key (user_id)=(…)»), where и значения параметров.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

const suite = createSuite('logs-clean');

// Любой IPv4 в логе — нарушение: клиентов сервер не пишет, а адреса своих
// интерфейсов в тестовом режиме не печатает.
const IPV4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/;
const IPV6_LOOPBACK = /(?<![\w:])(?:::1|::ffff:\d{1,3}(?:\.\d{1,3}){3})(?![\w:])/i;

const ROOM_NAME = 'Комната-Секретное-Имя-7731';
const MESSAGE_TEXT = 'сообщение-про-Иванова-4417';
const UPLOAD_NAME = 'Ivanov-passport-scan-5521.bin';
const BAD_UPLOAD_NAME = 'evil-name-3390.exe';
const FOREIGN_ORIGIN = 'https://evil-origin-9913.example';
const BROKEN_JSON_SECRET = 'секрет-в-битом-json-8812';
const HUGE_ID = '99999999999';
const WRONG_INVITE = 'Z'.repeat(26);

const TRIGGER_SQL = [
    `CREATE OR REPLACE FUNCTION nyxo_test_fail() RETURNS trigger AS $$
     BEGIN
         RAISE EXCEPTION 'тестовый сбой базы' USING ERRCODE = '23503',
             DETAIL = format('Key (user_id)=(%s) is not present in table "users".', NEW.user_id),
             HINT = format('room %s', NEW.room_id);
     END $$ LANGUAGE plpgsql`,
    'CREATE TRIGGER nyxo_test_fail BEFORE UPDATE OF pinned ON chats FOR EACH ROW EXECUTE FUNCTION nyxo_test_fail()',
];

// sid из значения куки connect.sid: «s:<sid>.<подпись>» в URL-кодировке.
function sidOfCookie(value) {
    const decoded = decodeURIComponent(value);
    return decoded.startsWith('s:') ? decoded.slice(2).split('.')[0] : decoded;
}

test('типичный сценарий не оставляет в логе сервера id, IP, имён, кодов, sid и имён файлов', async (t) => {
    const logs = suite.server.logs;
    const owner = suite.client({ name: 'владелец' });
    const guest = suite.client({ name: 'гость' });
    const stranger = suite.client({ name: 'посторонний' });
    for (const client of [owner, guest, stranger]) await client.registerAnon();
    const ownerSock = await owner.socket();
    const guestSock = await guest.socket();
    t.after(() => Promise.all([ownerSock.close(), guestSock.close()]));

    // Комната: код приглашения, заявка, одобрение.
    const { roomId, code, ownerChat, memberChat, requestId } = await roomWithMember(owner, guest, { name: ROOM_NAME });
    const preview = await stranger.joinPreview(code);
    assert.strictEqual(preview.roomId, roomId);

    // Сообщения: отправка, правка, удаление.
    const first = await owner.send(ownerChat.id, MESSAGE_TEXT);
    const reply = await guest.send(memberChat.id, `${MESSAGE_TEXT}-ответ`);
    await owner.edit(first.id, `${MESSAGE_TEXT}-правка`);
    await guest.ok(guest.del(`/api/messages/${reply.id}`), 'удаление сообщения');

    // Вложение: имя на диске случайное, исходное имя в лог не идёт.
    const file = await owner.uploadCipher(ownerChat.id, { filename: UPLOAD_NAME });
    const diskName = path.basename(file.file_url);
    assert.ok(fs.existsSync(path.join(suite.server.uploadsDir, diskName)), 'вложение лежит на диске');

    // Ошибочные запросы: все должны отвечать отказом, а не падением.
    const bot = await owner.botChat();
    const failures = [
        owner.request('POST', '/api/messages', { body: `{"text": "${BROKEN_JSON_SECRET}", `, headers: { 'Content-Type': 'application/json' } }),
        owner.post('/api/messages', { chatId: ownerChat.id, text: 'x' }, { origin: FOREIGN_ORIGIN }),
        stranger.post('/api/chats/join/preview', { code: WRONG_INVITE }),
        suite.client().get('/api/chats'),
        owner.uploadRaw(bot.id, Buffer.from('MZ-not-allowed'), 'application/x-msdownload', { filename: BAD_UPLOAD_NAME }),
        owner.get(`/api/messages/${HUGE_ID}`),
        owner.get('/api/messages/abc'),
    ];
    for (const res of await Promise.all(failures)) assert.ok(res.status >= 200 && res.status < 600, 'сервер ответил');

    // Сбой базы: в detail и hint лежат id пользователя и комнаты.
    const failMark = logs.mark();
    for (const sql of TRIGGER_SQL) await suite.query(sql);
    let failedPrefs;
    try {
        failedPrefs = await owner.post(`/api/chats/${ownerChat.id}/prefs`, { pinned: true });
    } finally {
        await suite.query('DROP TRIGGER IF EXISTS nyxo_test_fail ON chats');
        await suite.query('DROP FUNCTION IF EXISTS nyxo_test_fail()');
    }
    assert.strictEqual(failedPrefs.body.success, false, 'сбой базы дошёл до обработчика маршрута');
    const prefsLine = await logs.waitFor('Set chat prefs error', { from: failMark });
    assert.match(prefsLine.text, /тестовый сбой базы/, 'причина ошибки в логе осталась');
    assert.match(prefsLine.text, /code=23503/, 'и код ошибки тоже');

    // Всё, что известно тесту, собрано ДО удаления аккаунтов (после него сессий в базе нет).
    const sessions = (await suite.query('SELECT sid FROM session')).rows.map(r => r.sid);
    const cookieSids = [owner, guest, stranger].map(c => sidOfCookie(c.jar.get('connect.sid')));
    assert.ok(sessions.length >= 3, 'в базе есть сессии сценария');
    const ids = {
        users: [owner, guest, stranger].map(c => c.user.id),
        chats: [ownerChat.id, memberChat.id, bot.id],
        room: [roomId],
        request: [requestId],
        messages: [first.id, reply.id, file.id],
    };
    const names = {
        usernames: [owner, guest, stranger].map(c => c.user.username),
        room: [ROOM_NAME],
        files: [UPLOAD_NAME, BAD_UPLOAD_NAME, diskName, file.file_url],
        texts: [MESSAGE_TEXT, BROKEN_JSON_SECRET, FOREIGN_ORIGIN],
    };
    const codes = {
        unique: [owner, guest, stranger].map(c => c.user.uniqueCode),
        invite: [code, WRONG_INVITE],
    };
    const secrets = { ...suite.secrets, databaseUrl: suite.databaseUrl, databasePassword: new URL(suite.databaseUrl).password };

    // Выход из комнаты и удаление аккаунтов.
    await guest.leave(memberChat.id);
    await guest.deleteAccount();
    await owner.deleteAccount();
    await stranger.deleteAccount();
    // Фоновые удаления файлов и уведомления сокетов дописывают строки позже ответа.
    await waitUntil(async () => !fs.existsSync(path.join(suite.server.uploadsDir, diskName)), { what: 'файл вложения удалён с диска' });
    await new Promise(resolve => setTimeout(resolve, 500));

    const all = logs.text();
    assert.ok(all.length > 0, 'лог сервера не пуст');
    assert.ok(logs.find('База данных инициализирована'), 'старт сервера в логе виден (проверка идёт с первой строки)');

    // Идентификаторы созданных сущностей.
    logs.assertNoSensitive({
        userIds: ids.users, chatIds: ids.chats, roomIds: ids.room, requestIds: ids.request, messageIds: ids.messages,
        usernames: names.usernames, roomNames: names.room, fileNames: names.files, texts: names.texts,
        uniqueCodes: codes.unique, inviteCodes: codes.invite,
        sids: [...sessions, ...cookieSids], secrets: Object.values(secrets), hugeId: [HUGE_ID],
        ips: [owner.xff, guest.xff, stranger.xff, '127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost'],
    });

    // Любой IP, а не только известные: адреса интерфейсов, клиентов за прокси, loopback.
    const ipLines = logs.entries().filter(l => IPV4.test(l.text) || IPV6_LOOPBACK.test(l.text)).map(l => l.text);
    assert.deepStrictEqual(ipLines, [], 'в логе сервера нет IP-адресов');

    // Сбой с detail: причина видна, значения строк нет.
    assert.ok(!all.includes('is not present in table'), 'detail ошибки Postgres в лог не попал');
    assert.ok(!all.includes('Key (user_id)'), 'ключ из detail ошибки Postgres в лог не попал');
    assert.ok(!all.includes('SQL statement'), 'where ошибки Postgres в лог не попал');
    assert.ok(!/\n\s+at /.test(`\n${all}`), 'стеков вызовов в логе нет');

    // Ошибка данных (id вне диапазона int): код остаётся, значение из запроса — нет.
    const hugeLine = logs.find('Get messages error');
    assert.ok(hugeLine, 'ошибка запроса с id вне диапазона записана в лог');
    assert.match(hugeLine.text, /code=22003/);
});
