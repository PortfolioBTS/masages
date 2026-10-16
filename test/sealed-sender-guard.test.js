'use strict';
// Тест-запрет sealed sender (docs/security/sealed-sender.md, «Приложение: что менять в коде»):
// в server.js не должно возвращаться то, что связывало строку комнаты с пользователем.
//   * квота «по сумме file_size сообщений» и столбцы окна в users (upload_window): квота
//     ведётся в upload_quota под псевдонимом;
//   * ответы и события сообщений КОМНАТЫ с user_id, chat_id, sender_username, sender_avatar и
//     JOIN users по автору строки;
//   * фильтр «чужих» по user_id в списке чатов и markChatRead для комнат;
//   * рассылка комнатных событий мимо emitRoomMessageEvent (вкладки отправителя получили бы
//     событие дважды).
// Сквозные тесты проверяют то же поведением (test/e2e/sealed-sender.e2e.test.js).
//
// Запуск: node test/sealed-sender-guard.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
// Комментарии вырезаются (в них можно описывать, что именно запрещено).
function stripComments(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, match => match.replace(/[^\n]/g, ' '))
        .split('\n')
        .map(line => line.replace(/^\s*\/\/.*$/, '').replace(/\s\/\/\s.*$/, ''))
        .join('\n');
}
const server = stripComments(fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8').replace(/\r\n/g, '\n'));

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// Текст от маркера до следующего маркера (в пределах from, по умолчанию - весь файл).
function between(startMarker, endMarker, from = server) {
    const a = from.indexOf(startMarker);
    assert.ok(a >= 0, `нет «${startMarker}»`);
    const b = from.indexOf(endMarker, a + startMarker.length);
    assert.ok(b > a, `нет «${endMarker}» после «${startMarker}»`);
    return from.slice(a, b);
}

test('квота: нет суммы file_size по сообщениям, exceedsUploadQuota и столбцов окна в users', () => {
    assert.doesNotMatch(server, /SUM\(\s*file_size\s*\)/i);
    assert.doesNotMatch(server, /\bupload_window/);
    assert.doesNotMatch(server, /\bexceedsUploadQuota\b/);
    assert.doesNotMatch(server, /idx_messages_user_files/);
    assert.match(server, /initUploadQuotaSchema\(pool\)/, 'таблица upload_quota создаётся в initDatabase');
});

test('payload сообщения комнаты (roomMessagePayload) не содержит user_id, chat_id, sender_*, author_tag', () => {
    const body = between('function roomMessagePayload(', 'function messageFromRow(');
    for (const banned of ['user_id', 'chat_id', 'sender_username', 'sender_avatar', 'sender_id', 'author_tag']) {
        assert.ok(!body.includes(banned), `roomMessagePayload: «${banned}»`);
    }
});

test('история и цитата комнаты: запросы без JOIN users, user_id и sender_*; JOIN users по автору строки остался только у чата с ботом', () => {
    const history = between("app.get('/api/messages/:chatId'", "app.post('/api/chats/:chatId/read'");
    const roomStart = history.indexOf('if (chat.room_id) {');
    const botStart = history.indexOf('} else {', roomStart);
    assert.ok(roomStart > 0 && botStart > roomStart, 'ветки комнаты и бота найдены');
    const roomBranch = history.slice(roomStart, botStart);
    assert.ok(roomBranch.length > 100);
    assert.doesNotMatch(roomBranch, /JOIN\s+users|user_id|sender_username|sender_avatar|chat_id/);
    assert.match(history.slice(botStart), /JOIN users u ON u\.id = m\.user_id/);
    // Вне веток бота такого JOIN нет: история бота и цитата ответа в чате с ботом - ровно два.
    assert.strictEqual((server.match(/JOIN users u ON u\.id = m\.user_id/g) || []).length, 2);
    const reply = between('if (replyTargetId) {', 'const expirySeconds = await newMessageExpirySeconds(chat, requestedExpiry)');
    const replyRoom = reply.slice(reply.indexOf('if (chat.room_id) {'), reply.indexOf('} else {'));
    assert.ok(replyRoom.length > 50);
    assert.doesNotMatch(replyRoom, /JOIN\s+users|user_id|sender_/, 'цитата комнаты без автора');
});

test('список чатов и markChatRead: «чужие» в комнате - по тегам автора, а не по user_id', () => {
    const list = between('const CHAT_LIST_SQL = `', "app.get('/api/chats'");
    assert.doesNotMatch(list, /m\.user_id\s*<>\s*c\.user_id/);
    const read = between('async function markChatRead(', 'const MESSAGES_PAGE_SIZE');
    assert.match(read, /NOT \(m\.author_tag = ANY\(\$4::bytea\[\]\)\)/);
    assert.match(read, /authorTags\.tagsForAccount\(/);
});

test('события комнат уходят через emitRoomMessageEvent: прямых комнатных emit сообщений нет, автору - одна копия на user:<id>', () => {
    const direct = server.split('\n').filter(line => /io\.to\(getSocketRoomKey\([^)]*\)\)\.emit\('(newMessage|messageEdited)'/.test(line));
    assert.ok(direct.length >= 2, 'остались события чата с ботом');
    for (const line of direct) assert.match(line, /getSocketRoomKey\((chat\.id|message\.chat_id), (null|message\.room_id)?\)|getSocketRoomKey\(chat\.id, null\)/, line.trim());
    assert.strictEqual(direct.filter(line => /getSocketRoomKey\(chat\.id, roomId\)/.test(line)).length, 0, 'комнатный newMessage без except автора');
    const emit = between('function emitRoomMessageEvent(', 'async function advanceSenderMarker(');
    assert.match(emit, /\.except\('user:' \+ authorId\)/);
    assert.match(emit, /io\.to\('user:' \+ authorId\)\.emit\(event, \{ \.\.\.payload, mine: true \}\)/);
});

test('строка комнаты пишется только транзакцией insertRoomMessage в порядке users, rooms, членство, квота, INSERT; user_id не передаётся', () => {
    // Прямые INSERT INTO messages - только приветствие и ответ бота (chat_id) и общий insertMessageRow.
    const inserts = server.split('\n').filter(line => /INSERT INTO messages/.test(line));
    assert.ok(inserts.length >= 3, inserts.join('\n'));
    for (const line of inserts) assert.ok(/chat_id/.test(line) || line.includes('${names.join'), line.trim());
    const room = between('async function insertRoomMessage(', 'function respondRoomSendError(');
    assert.ok(room.indexOf('FOR KEY SHARE') > 0 && room.indexOf('FOR KEY SHARE') < room.indexOf('FOR NO KEY UPDATE'), 'users раньше rooms');
    assert.ok(room.indexOf('FROM room_participants') < room.indexOf('reserveUploadQuota'), 'членство - до квоты');
    assert.ok(room.indexOf('reserveUploadQuota') < room.indexOf('insertMessageRow('), 'квота - до вставки');
    assert.doesNotMatch(room, /user_id\s*[:,]/, 'в INSERT комнаты user_id не передаётся');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
