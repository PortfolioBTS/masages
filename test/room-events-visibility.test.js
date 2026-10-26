'use strict';
// Рассылка событий сообщений комнаты с учётом границы видимости (ревью W7 R2.3):
// emitVisibleRoomMessage (src/services/messages.js) исключает участников с
// visible_from_seq >= seq, а при сбое чтения не рассылает комнате вовсе (только копия
// автору). Все newMessage и messageEdited комнаты идут через неё.
// Живой сценарий гонки «вступление между COMMIT и рассылкой» —
// test/e2e/room-visibility-events.e2e.test.js.
// Запуск: node test/room-events-visibility.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// lib/message-crypto читает ключ при загрузке.
process.env.MESSAGE_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
const { createMessages } = require('../src/services/messages');

const ROOT = path.join(__dirname, '..');

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

function harness(dbAll) {
    const emitted = [];
    const queries = [];
    const messages = createMessages({
        dbAll: async (sql, params) => { queries.push({ sql, params }); return dbAll(sql, params); },
        emitRoomMessageEvent: (...args) => emitted.push(args),
    });
    return { messages, emitted, queries };
}

async function main() {
    await test('новички с visible_from_seq >= seq исключаются из рассылки', async () => {
        const { messages, emitted, queries } = harness(async () => [{ user_id: 7 }, { user_id: 9 }]);
        await messages.emitVisibleRoomMessage('newMessage', 42, 5, 1001, { id: 'x' });
        assert.strictEqual(queries.length, 1);
        assert.match(queries[0].sql, /visible_from_seq >= \$2/);
        assert.deepStrictEqual(queries[0].params, [42, 1001]);
        assert.deepStrictEqual(emitted, [['newMessage', 42, 5, { id: 'x' }, { hiddenUserIds: [7, 9] }]]);
    });

    await test('сбой чтения границ — комнате ничего, автору его копия', async () => {
        const originalError = console.error;
        console.error = () => {};
        try {
            const { messages, emitted } = harness(async () => { throw Object.assign(new Error('lock timeout'), { code: '55P03' }); });
            await messages.emitVisibleRoomMessage('messageEdited', 42, 5, 1001, { id: 'x' });
            assert.deepStrictEqual(emitted, [['messageEdited', 42, 5, { id: 'x' }, { onlyAuthor: true }]]);
        } finally {
            console.error = originalError;
        }
    });

    await test('emitRoomMessageEvent: onlyAuthor — только user:<автор>, комнате ничего', () => {
        const { createEvents } = require('../src/realtime/events');
        const calls = [];
        const chain = (target) => ({
            except: (room) => chain(`${target} -${room}`),
            emit: (event, payload) => calls.push([target, event, payload]),
        });
        const { emitRoomMessageEvent } = createEvents({ io: { to: (room) => chain(room) } });
        emitRoomMessageEvent('newMessage', 42, 5, { id: 'x' }, { onlyAuthor: true });
        assert.deepStrictEqual(calls, [['user:5', 'newMessage', { id: 'x', mine: true }]]);
        calls.length = 0;
        emitRoomMessageEvent('newMessage', 42, 5, { id: 'x' }, { hiddenUserIds: [7] });
        assert.strictEqual(calls.length, 2);
        assert.match(calls[0][0], /-user:5 -user:7$/);
    });

    await test('код маршрутов: события сообщений комнаты — только через emitVisibleRoomMessage', () => {
        const dir = path.join(ROOT, 'src', 'http', 'routes');
        const direct = [];
        let visible = 0;
        for (const name of fs.readdirSync(dir).filter(n => n.endsWith('.js'))) {
            const lines = fs.readFileSync(path.join(dir, name), 'utf8').split('\n');
            lines.forEach((line, i) => {
                if (/emitRoomMessageEvent\(\s*'(newMessage|messageEdited)'/.test(line)) direct.push(`${name}:${i + 1}: ${line.trim()}`);
                if (/emitVisibleRoomMessage\(\s*'(newMessage|messageEdited)'/.test(line)) visible++;
            });
        }
        assert.deepStrictEqual(direct, [], 'прямая рассылка мимо границы видимости:\n' + direct.join('\n'));
        assert.ok(visible >= 3, `ожидались отправка, вложение и правка — найдено ${visible}`);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
