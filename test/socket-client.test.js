'use strict';
// Свой клиент Socket.IO сквозных тестов (test/e2e/helpers/socket.js) —
// против настоящего пакета socket.io в памяти: заголовки рукопожатия,
// отказы (Origin, middleware), события, подтверждения, ping/pong,
// отключения с обеих сторон. Без БД.
// Запуск: node test/socket-client.test.js

const assert = require('assert');
const http = require('http');
const { Server } = require('socket.io');
const { connectSocket, parseSioPacket } = require('./e2e/helpers/socket');
const { freePort } = require('./e2e/helpers/server');

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

const GOOD_ORIGIN = 'http://good.example';

// Сервер как у приложения: источник проверяется в allowRequest (CSWSH),
// авторизация — в middleware. pingInterval маленький — проверить pong.
async function startIo() {
    const httpServer = http.createServer();
    const io = new Server(httpServer, {
        pingInterval: 60,
        pingTimeout: 300,
        allowRequest: (req, callback) => (req.headers.origin === GOOD_ORIGIN ? callback(null, true) : callback('Origin not allowed', false)),
    });
    const handshakes = [];
    const disconnects = [];
    let onDisconnect = () => {};
    io.use((socket, next) => {
        if (!/(^|;\s*)session=ok(;|$)/.test(socket.request.headers.cookie || '')) return next(new Error('Не авторизован'));
        next();
    });
    io.on('connection', (socket) => {
        const h = socket.handshake.headers;
        handshakes.push({ xff: h['x-forwarded-for'], cookie: h.cookie, origin: h.origin });
        socket.emit('welcome', { id: socket.id });
        socket.on('echo', (data, ack) => ack({ got: data }));
        socket.on('say', (text) => socket.emit('said', { text }));
        socket.on('multi', () => socket.emit('multi', 1, 'two', { three: 3 }));
        socket.on('kick', () => socket.disconnect(true));
        socket.on('disconnect', (reason) => { disconnects.push(reason); onDisconnect(reason); });
    });
    await new Promise(resolve => httpServer.listen(0, '127.0.0.1', resolve));
    return {
        baseUrl: `http://127.0.0.1:${httpServer.address().port}`,
        handshakes,
        disconnects,
        nextDisconnect: () => new Promise(resolve => { onDisconnect = resolve; }),
        close: () => new Promise(resolve => io.close(() => resolve())),
    };
}

async function main() {
    console.log('Socket client tests\n');
    const srv = await startIo();
    const connect = (extra = {}) => connectSocket({
        baseUrl: srv.baseUrl, origin: GOOD_ORIGIN, cookie: 'session=ok; theme=dark', xff: '10.9.8.7', ...extra,
    });

    try {
        await test('разбор пакетов Socket.IO: событие, подтверждение с пространством имён, ошибка подключения', () => {
            assert.deepStrictEqual(parseSioPacket('2["a",1]'), { type: '2', nsp: '/', id: null, payload: ['a', 1] });
            assert.deepStrictEqual(parseSioPacket('3/admin,12[{"ok":true}]'), { type: '3', nsp: '/admin', id: 12, payload: [{ ok: true }] });
            assert.deepStrictEqual(parseSioPacket('4{"message":"Не авторизован"}'), { type: '4', nsp: '/', id: null, payload: { message: 'Не авторизован' } });
            assert.deepStrictEqual(parseSioPacket('1'), { type: '1', nsp: '/', id: null, payload: undefined });
            assert.throws(() => parseSioPacket('51-["bin",{"_placeholder":true,"num":0}]'), /бинарные/);
        });

        await test('подключение: Cookie, Origin и X-Forwarded-For доходят до сервера; событие при подключении не теряется', async () => {
            const sock = await connect();
            assert.strictEqual(sock.connected, true);
            assert.ok(sock.sid);
            const last = srv.handshakes[srv.handshakes.length - 1];
            assert.deepStrictEqual(last, { xff: '10.9.8.7', cookie: 'session=ok; theme=dark', origin: GOOD_ORIGIN });
            // welcome пришло, возможно, раньше вызова waitFor — оно в истории.
            const welcome = await sock.waitFor('welcome');
            assert.strictEqual(typeof welcome.id, 'string');
            await sock.close();
        });

        await test('emit и emitWithAck; waitFor с предикатом; события с несколькими аргументами', async () => {
            const sock = await connect();
            assert.deepStrictEqual(await sock.emitWithAck('echo', { x: 1 }), { got: { x: 1 } });
            sock.emit('say', 'первое');
            sock.emit('say', 'второе');
            assert.deepStrictEqual(await sock.waitFor('said', p => p.text === 'второе'), { text: 'второе' });
            assert.deepStrictEqual(sock.collect('said').map(p => p.text), ['первое', 'второе']);
            const mark = sock.mark();
            sock.emit('say', 'третье');
            await sock.waitFor('said', () => true, { since: mark });
            assert.deepStrictEqual(sock.collect('said', { since: mark }), [{ text: 'третье' }]);
            sock.emit('multi');
            let args = null;
            await sock.waitFor('multi', (p, all) => { args = all; return true; });
            assert.deepStrictEqual(args, [1, 'two', { three: 3 }]);
            await sock.close();
        });

        await test('ping сервера получает pong: соединение живёт дольше pingTimeout', async () => {
            const sock = await connect();
            // 8 пингов по 60 мс — заметно дольше pingTimeout сервера (300 мс
            // без pong): без ответов сервер отключил бы клиента раньше.
            let pings = 0;
            await sock.waitFor('engine:ping', () => ++pings >= 8, { timeoutMs: 3000 });
            assert.strictEqual(sock.connected, true);
            assert.deepStrictEqual(sock.collect('disconnect'), []);
            await sock.close();
        });

        await test('отключение сервером: событие disconnect, ожидание другого события падает сразу', async () => {
            const sock = await connect();
            const pending = sock.waitFor('never', () => true, { timeoutMs: 10000 });
            sock.emit('kick');
            assert.deepStrictEqual(await sock.waitFor('disconnect'), { reason: 'io server disconnect' });
            await assert.rejects(pending, (err) => err.kind === 'closed');
            await assert.rejects(sock.waitFor('welcome', p => p === 'нет такого'), (err) => err.kind === 'closed');
            assert.throws(() => sock.emit('say', 'после'), (err) => err.kind === 'closed');
        });

        await test('close() клиента: сервер видит отключение', async () => {
            const sock = await connect();
            const serverSide = srv.nextDisconnect();
            await sock.close();
            assert.strictEqual(await serverSide, 'client namespace disconnect');
            assert.deepStrictEqual(sock.collect('disconnect'), [{ reason: 'io client disconnect' }]);
        });

        await test('отказ middleware: CONNECT_ERROR с причиной', async () => {
            await assert.rejects(connect({ cookie: 'session=bad' }), (err) => err.kind === 'connect_error' && err.reason === 'Не авторизован');
        });

        await test('чужой Origin: рукопожатие отклонено, причина и статус известны', async () => {
            await assert.rejects(
                connect({ origin: 'http://evil.example' }),
                (err) => err.kind === 'handshake' && err.reason === 'Origin not allowed' && err.status === 403
            );
            await assert.rejects(connect({ origin: null }), (err) => err.kind === 'handshake');
        });

        await test('сервер недоступен: понятная ошибка, а не зависание', async () => {
            const port = await freePort();
            await assert.rejects(
                connectSocket({ baseUrl: `http://127.0.0.1:${port}`, origin: GOOD_ORIGIN, timeoutMs: 5000 }),
                (err) => err.kind === 'handshake' && /недоступен/.test(err.reason)
            );
        });
    } finally {
        await srv.close();
    }

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
