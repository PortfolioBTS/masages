'use strict';
// Исчезающие сообщения и граница видимости (ревью W7 R2.13 и находка T7.4):
//   * messageDeleted комнаты (таймер, удаление автором, выход с удалением своих сообщений)
//     не уходит участникам, вступившим после сообщения (visible_from_seq >= seq) —
//     src/services/expiry.js emitRoomMessagesDeleted;
//   * таймеры в памяти для сообщений, удалённых другими путями (выход, удаление аккаунта,
//     снос комнаты, каскады), снимаются сверкой с message_expiry — lib/disappearing-messages.js.
// Живые сценарии — test/e2e/room-visibility-events.e2e.test.js.
// Запуск: node test/disappearing-visibility.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const DisappearingMessagesManager = require('../lib/disappearing-messages');
const { createExpiry } = require('../src/services/expiry');

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

// io: to(room).except(…).emit(event, payload) → [{ room, except: [...], event, payload }].
function fakeIo() {
    const sent = [];
    const chain = (room, except) => ({
        except: (who) => chain(room, [...except, who]),
        emit: (event, payload) => sent.push({ room, except, event, payload }),
    });
    return { sent, to: (room) => chain(room, []) };
}

async function quietly(fn) {
    const original = console.error;
    const lines = [];
    console.error = (line) => lines.push(String(line));
    try { await fn(); } finally { console.error = original; }
    return lines;
}

async function main() {
    await test('messageDeleted комнаты: кто вступил после сообщения, события не получает', async () => {
        const io = fakeIo();
        const queries = [];
        const pool = {
            query: async (sql, params) => {
                queries.push({ sql, params });
                // Участник 7 вступил после seq 10 (граница 15), участник 8 — после обоих (25).
                return { rows: [{ user_id: 7, visible_from_seq: 15 }, { user_id: 8, visible_from_seq: 25 }] };
            },
        };
        const removed = [];
        const { disappearingMessagesManager } = createExpiry({ io, pool, removeUploadedFiles: (urls) => removed.push(...urls) });
        await disappearingMessagesManager.onMessagesDeleted([
            { id: 101, room_id: 5, chat_id: null, seq: 10, file_url: '/uploads/a.bin' },
            { id: 102, room_id: 5, chat_id: null, seq: 20, file_url: null },
            { id: 201, room_id: null, chat_id: 9, seq: 3, file_url: null },
        ]);
        assert.deepStrictEqual(removed, ['/uploads/a.bin', null, null]);
        assert.strictEqual(queries.length, 1, 'одна выборка границ на комнату');
        assert.deepStrictEqual(queries[0].params, [5, 10]);
        assert.deepStrictEqual(io.sent, [
            { room: 'chat:9', except: [], event: 'messageDeleted', payload: { id: '201', chat_id: 9, room_id: null } },
            { room: 'room:5', except: ['user:7', 'user:8'], event: 'messageDeleted', payload: { id: '101', room_id: 5 } },
            { room: 'room:5', except: ['user:8'], event: 'messageDeleted', payload: { id: '102', room_id: 5 } },
        ]);
    });

    await test('границы не прочитались — комнате событие не уходит (в лог), чату с ботом — уходит', async () => {
        const io = fakeIo();
        const pool = { query: async () => { throw Object.assign(new Error('lock timeout'), { code: '55P03' }); } };
        const { disappearingMessagesManager } = createExpiry({ io, pool, removeUploadedFiles: () => {} });
        const logs = await quietly(() => disappearingMessagesManager.onMessagesDeleted([
            { id: 101, room_id: 5, chat_id: null, seq: 10, file_url: null },
            { id: 201, room_id: null, chat_id: 9, seq: 3, file_url: null },
        ]));
        assert.deepStrictEqual(io.sent.map(e => e.room), ['chat:9']);
        assert.ok(logs.some(l => l.includes('messageDeleted комнате не отправлен')));
    });

    await test('удаление по таймеру возвращает seq; ошибка асинхронного onMessagesDeleted — в лог, не наружу', async () => {
        const queries = [];
        const pool = { query: async (sql) => { queries.push(sql); return { rows: [{ id: 1, chat_id: null, room_id: 5, file_url: null, seq: 10 }] }; } };
        const manager = new DisappearingMessagesManager(pool, { onMessagesDeleted: async () => { throw new Error('сбой рассылки'); } });
        let rows;
        const logs = await quietly(async () => {
            rows = await manager.deleteMessages([1]);
            await new Promise(r => setImmediate(r));
        });
        assert.match(queries[0], /RETURNING id, chat_id, room_id, file_url, seq/);
        assert.strictEqual(rows.length, 1);
        assert.ok(logs.some(l => l.includes('onMessagesDeleted failed')));
    });

    await test('таймеры удалённых другими путями сообщений снимаются сверкой с message_expiry', async () => {
        const pool = {
            query: async (sql, params) => {
                assert.match(sql, /SELECT message_id FROM message_expiry WHERE message_id = ANY/);
                // Живы только 1 и 3: у 2 и 4 строки message_expiry ушли каскадом вместе с сообщениями.
                return { rows: params[0].filter(id => id === 1 || id === 3).map(id => ({ message_id: id })) };
            },
        };
        const manager = new DisappearingMessagesManager(pool);
        try {
            for (const id of [1, 2, 3, 4]) manager.scheduleMessageDeletion(id, 60 * 60 * 1000);
            assert.strictEqual(await manager.forgetDeletedTimers(), 2);
            assert.deepStrictEqual([...manager.scheduledDeletions.keys()].sort(), [1, 3]);
            assert.strictEqual(manager.forget([3, 99]), 1);
            assert.deepStrictEqual([...manager.scheduledDeletions.keys()], [1]);
        } finally {
            manager.forget([...manager.scheduledDeletions.keys()]);
        }
    });

    await test('фоновый проход чистки сверяет таймеры', async () => {
        const calls = [];
        const pool = {
            query: async (sql) => {
                calls.push(sql.split(' ').slice(0, 2).join(' '));
                return { rows: [] };
            },
        };
        const manager = new DisappearingMessagesManager(pool);
        try {
            manager.scheduleMessageDeletion(7, 60 * 60 * 1000);
            await manager.cleanupExpired();
            assert.deepStrictEqual(calls, ['SELECT message_id', 'SELECT message_id']);
            assert.strictEqual(manager.scheduledDeletions.size, 0);
        } finally {
            manager.forget([...manager.scheduledDeletions.keys()]);
        }
    });

    await test('код: messageDeleted комнаты — только через emitRoomMessagesDeleted', () => {
        const direct = [];
        for (const dir of ['src/http/routes', 'src/services', 'src/realtime']) {
            for (const name of fs.readdirSync(path.join(ROOT, dir)).filter(n => n.endsWith('.js'))) {
                const lines = fs.readFileSync(path.join(ROOT, dir, name), 'utf8').split('\n');
                lines.forEach((line, i) => {
                    if (!/emit\('messageDeleted'/.test(line)) return;
                    // Допустимы: внутри emitRoomMessagesDeleted (target с except) и чат с ботом.
                    if (/target\.emit\('messageDeleted'/.test(line) || /getSocketRoomKey\(row\.chat_id, null\)/.test(line)) return;
                    direct.push(`${dir}/${name}:${i + 1}: ${line.trim()}`);
                });
            }
        }
        assert.deepStrictEqual(direct, [], 'messageDeleted мимо границы видимости:\n' + direct.join('\n'));
        const leave = fs.readFileSync(path.join(ROOT, 'src', 'http', 'routes', 'leave.js'), 'utf8');
        assert.match(leave, /await emitRoomMessagesDeleted\(chat\.room_id, outcome\.deletedRows\)/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
