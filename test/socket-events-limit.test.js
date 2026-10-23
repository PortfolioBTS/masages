'use strict';
// Входящие события сокета (W7 R1 п.2): обработчика joinChat нет, частота событий
// ограничена токен-бакетом, превышение - disconnect. Проверка на фейковом io.
// Запуск: node test/socket-events-limit.test.js

const assert = require('assert');
const { createTokenBucket } = require('../lib/token-bucket');
const { registerSocketHandlers } = require('../src/realtime/socket-handlers');

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

// Фейковый io: запоминает обработчик 'connection'; сокет - события, middleware, комнаты.
function connectFakeSocket(env = {}, chatLists = null) {
    const saved = {};
    for (const [k, v] of Object.entries(env)) { saved[k] = process.env[k]; process.env[k] = v; }
    let onConnection = null;
    const io = { use() {}, on: (event, fn) => { if (event === 'connection') onConnection = fn; } };
    const dbCalls = [];
    const counter = () => ({ increment() {}, decrement() {}, get: () => 0 });
    registerSocketHandlers({
        io, userSocketCount: counter(), ipSocketCount: counter(), getClientIp: () => '1.2.3.4',
        dbGet: async (...args) => { dbCalls.push(args); return { id: 1 }; },
        dbAll: async (...args) => { dbCalls.push(args); return chatLists ? (chatLists.shift() || []) : []; },
        sessionMiddleware: (req, res, next) => next(), anonActivity: { noteActivity() {}, validateSession: async () => 'ok' },
    });
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    const handlers = {};
    const middleware = [];
    const socket = {
        request: { session: { userId: 7 } }, data: { clientIp: null }, joined: [], disconnected: false,
        on: (event, fn) => { handlers[event] = fn; },
        use: (fn) => { middleware.push(fn); },
        join(rooms) { this.joined.push(rooms); },
        left: [], leave(room) { this.left.push(room); },
        disconnect() { this.disconnected = true; },
    };
    return { connected: onConnection(socket), socket, handlers, middleware, dbCalls };
}

// Событие через middleware сокета: true - дошло дальше, false - отброшено.
function deliver(middleware, event = ['joinChat', 'room:1']) {
    let passedOn = false;
    for (const fn of middleware) fn(event, () => { passedOn = true; });
    return passedOn;
}

async function main() {
    await test('бакет: всплеск capacity, потом refillPerSecond в секунду', () => {
        let now = 1000;
        const bucket = createTokenBucket({ capacity: 3, refillPerSecond: 2, now: () => now });
        assert.deepStrictEqual([bucket.take(), bucket.take(), bucket.take(), bucket.take()], [true, true, true, false]);
        now += 500; // +1 токен
        assert.deepStrictEqual([bucket.take(), bucket.take()], [true, false]);
        now += 60000; // не больше capacity
        assert.deepStrictEqual([bucket.take(), bucket.take(), bucket.take(), bucket.take()], [true, true, true, false]);
    });

    await test('обработчика joinChat нет; из обработчиков остаётся только disconnect', async () => {
        const { connected, handlers } = connectFakeSocket();
        await connected;
        assert.deepStrictEqual(Object.keys(handlers), ['disconnect']);
    });

    await test('событие joinChat не ходит в базу и не подписывает сокет', async () => {
        const { connected, socket, middleware, dbCalls } = connectFakeSocket();
        await connected;
        const callsAfterConnect = dbCalls.length;
        const joinedAfterConnect = socket.joined.length;
        assert.strictEqual(deliver(middleware, ['joinChat', 'room:1']), true, 'в пределах всплеска событие доходит, но слушателя нет');
        assert.strictEqual(dbCalls.length, callsAfterConnect, 'запросов в БД из-за события нет');
        assert.strictEqual(socket.joined.length, joinedAfterConnect);
    });

    await test('поток событий: после всплеска сокет закрывается, события отбрасываются', async () => {
        const { connected, socket, middleware } = connectFakeSocket({ SOCKET_EVENT_BURST: '5', SOCKET_EVENT_RATE: '1' });
        await connected;
        let delivered = 0;
        for (let i = 0; i < 8000; i++) if (deliver(middleware)) delivered++;
        assert.strictEqual(delivered, 5, 'дошло ровно столько, сколько позволяет всплеск');
        assert.strictEqual(socket.disconnected, true);
    });

    await test('умолчание: всплеск 20 событий, неверные значения окружения игнорируются', async () => {
        const { connected, socket, middleware } = connectFakeSocket({ SOCKET_EVENT_BURST: 'abc', SOCKET_EVENT_RATE: '0' });
        await connected;
        let delivered = 0;
        for (let i = 0; i < 100; i++) if (deliver(middleware)) delivered++;
        assert.strictEqual(delivered, 20);
        assert.strictEqual(socket.disconnected, true);
    });

    await test('гонка с выходом из комнаты (R2.2): после join список читается снова, ушедший чат снимается', async () => {
        // Первый запрос видит оба чата, к повторному пользователь уже вышел из комнаты 9.
        const lists = [[{ id: 1, room_id: null }, { id: 5, room_id: 9 }], [{ id: 1, room_id: null }]];
        const { connected, socket } = connectFakeSocket({}, lists);
        await connected;
        assert.deepStrictEqual(socket.joined, ['user:7', ['chat:1', 'room:9']]);
        assert.deepStrictEqual(socket.left, ['room:9']);
    });

    await test('без выхода повторная проверка ничего не снимает', async () => {
        const chats = [{ id: 1, room_id: null }, { id: 5, room_id: 9 }];
        const { connected, socket } = connectFakeSocket({}, [chats, chats]);
        await connected;
        assert.deepStrictEqual(socket.left, []);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exit(1); });
