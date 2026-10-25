'use strict';
// Ответ на сообщение, которое удаляют в этот момент (ревью W7 R2.8): 23503 по
// messages_reply_to_id_fkey больше не превращается в «Ошибка отправки» — сообщение
// уходит без ответа (lib/message-ids.js insertDroppingGoneReply), как и тогда, когда
// цели нет уже при проверке видимости. Живой сценарий — test/e2e/reply-target-gone.e2e.test.js.
// Запуск: node test/reply-target-gone.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { isReplyTargetGone, insertDroppingGoneReply } = require('../lib/message-ids');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const fkError = (constraint) => Object.assign(new Error('violates foreign key constraint'), { code: '23503', constraint });

async function main() {
    await test('классификатор: только 23503 по messages_reply_to_id_fkey', () => {
        assert.strictEqual(isReplyTargetGone(fkError('messages_reply_to_id_fkey')), true);
        assert.strictEqual(isReplyTargetGone(fkError('messages_room_id_fkey')), false);
        assert.strictEqual(isReplyTargetGone(Object.assign(new Error('x'), { code: '23505', constraint: 'messages_reply_to_id_fkey' })), false);
        assert.strictEqual(isReplyTargetGone(null), false);
    });

    await test('цель удалена — ответ убирается и вставка повторяется один раз', async () => {
        let reply = { id: 5 };
        const seen = [];
        const result = await insertDroppingGoneReply(async () => {
            seen.push(reply && reply.id);
            if (reply) throw fkError('messages_reply_to_id_fkey');
            return 'вставлено';
        }, () => { reply = null; });
        assert.strictEqual(result, 'вставлено');
        assert.deepStrictEqual(seen, [5, null]);
    });

    await test('другие ошибки и повторная неудача уходят наверх', async () => {
        await assert.rejects(insertDroppingGoneReply(async () => { throw fkError('messages_room_id_fkey'); }, () => assert.fail('ответ не трогается')), /foreign key/);
        let calls = 0;
        await assert.rejects(insertDroppingGoneReply(async () => { calls++; throw fkError('messages_reply_to_id_fkey'); }, () => {}), /foreign key/);
        assert.strictEqual(calls, 2, 'не больше одного повтора');
    });

    await test('отправка текста (комната и чат с ботом) вставляет через insertDroppingGoneReply', () => {
        const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'http', 'routes', 'chats.js'), 'utf8');
        assert.match(source, /insertDroppingGoneReply\(\(\) => insertRoomMessage\(/);
        assert.match(source, /insertDroppingGoneReply\(\s*\(\) => withMessageIdRetry\(\(\) => insertChatMessage\(/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
