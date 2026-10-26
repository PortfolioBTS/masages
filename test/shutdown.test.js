'use strict';
// Штатная остановка по SIGTERM/SIGINT (ревью W7 R2.5): src/shutdown.js и подключение в
// src/lifecycle.js. Идущий запрос дорабатывает, новые соединения не принимаются, пул
// закрывается после HTTP, выход 0; не уложились — выход 1; повторный сигнал — сразу 1.
// (Сквозным тестом не проверить: на Windows child.kill() не доставляет SIGTERM.)
// Запуск: node test/shutdown.test.js

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { createShutdown } = require('../src/shutdown');

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

const quiet = () => {};

async function main() {
    await test('идущий запрос дорабатывает, затем пул закрывается и выход 0; новые соединения не принимаются', async () => {
        const order = [];
        let finishRequest;
        const server = http.createServer((req, res) => {
            order.push('запрос начат');
            finishRequest = () => { res.end('готово'); order.push('запрос завершён'); };
        });
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        const port = server.address().port;
        const pending = fetch(`http://127.0.0.1:${port}/`).then(r => r.text());
        while (!finishRequest) await new Promise(r => setTimeout(r, 5));

        let exitCode = null;
        const exited = new Promise((resolve) => {
            const shutdown = createShutdown({
                server,
                io: { close: () => order.push('io.close') },
                pool: { end: async () => order.push('pool.end') },
                jobs: { stop: () => order.push('jobs.stop') },
                exit: (code) => { exitCode = code; resolve(); },
                log: quiet,
            });
            shutdown('SIGTERM');
        });
        // Новые соединения уже не принимаются.
        await assert.rejects(fetch(`http://127.0.0.1:${port}/`), 'после сигнала порт закрыт');
        assert.strictEqual(exitCode, null, 'пока идёт запрос, процесс не выходит');
        assert.ok(!order.includes('pool.end'), 'пул закрывается после HTTP');
        finishRequest();
        assert.strictEqual(await pending, 'готово');
        await exited;
        assert.strictEqual(exitCode, 0);
        assert.deepStrictEqual(order, ['запрос начат', 'jobs.stop', 'io.close', 'запрос завершён', 'pool.end']);
    });

    // Повторное ревью W7, Н4: closeIdleConnections() вызывался один раз, в начале остановки. Соединение, занятое
    // запросом в этот момент, после ответа оставалось простаивающим keep-alive и держало server.close() до своего
    // тайм-аута (keepAliveTimeout, 5 с) — остановка шла дольше нужного или упиралась в общий тайм-аут (выход 1).
    await test('keep-alive, занятый запросом при сигнале: после ответа соединение закрывается, выход 0 без ожидания keep-alive', async () => {
        let finishRequest;
        let requests = 0;
        const server = http.createServer((req, res) => {
            requests++;
            if (requests === 1) { res.end('первый'); return; }
            finishRequest = () => res.end('готово');
        });
        server.keepAliveTimeout = 30000;
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        const port = server.address().port;
        const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
        const get = () => new Promise((resolve, reject) => {
            http.get({ host: '127.0.0.1', port, path: '/', agent }, (res) => {
                let body = '';
                res.on('data', (c) => { body += c; });
                res.on('end', () => resolve({ body, connection: res.headers.connection }));
            }).on('error', reject);
        });
        assert.strictEqual((await get()).body, 'первый');
        const pending = get();
        while (!finishRequest) await new Promise(r => setTimeout(r, 5));

        let exitCode = null;
        const started = Date.now();
        const exited = new Promise((resolve) => {
            createShutdown({
                server, pool: { end: async () => {} }, exit: (code) => { exitCode = code; resolve(); }, log: quiet, timeoutMs: 20000,
            })('SIGTERM');
        });
        await new Promise(r => setTimeout(r, 50));
        finishRequest();
        assert.strictEqual((await pending).body, 'готово');
        await exited;
        agent.destroy();
        assert.strictEqual(exitCode, 0);
        assert.ok(Date.now() - started < 2000, `остановка заняла ${Date.now() - started} мс`);
    });

    await test('запрос по уже открытому соединению во время остановки обслуживается с Connection: close', async () => {
        const net = require('net');
        let finishFirst;
        const server = http.createServer((req, res) => {
            if (req.url === '/first') { finishFirst = () => res.end('1'); return; }
            res.end('2');
        });
        server.keepAliveTimeout = 30000;
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        const socket = net.connect(server.address().port, '127.0.0.1');
        let raw = '';
        socket.on('data', (chunk) => { raw += chunk; });
        const closed = new Promise((resolve) => socket.on('close', resolve));
        socket.write('GET /first HTTP/1.1\r\nHost: x\r\n\r\n');
        while (!finishFirst) await new Promise(r => setTimeout(r, 5));
        let exitCode = null;
        const exited = new Promise((resolve) => {
            createShutdown({ server, pool: { end: async () => {} }, exit: (code) => { exitCode = code; resolve(); }, log: quiet, timeoutMs: 20000 })('SIGTERM');
        });
        // Второй запрос по тому же соединению (конвейер HTTP/1.1) приходит уже во время остановки.
        socket.write('GET /second HTTP/1.1\r\nHost: x\r\n\r\n');
        await new Promise(r => setTimeout(r, 50));
        finishFirst();
        await closed;
        await exited;
        const responses = raw.split('HTTP/1.1 ').filter(Boolean);
        assert.strictEqual(responses.length, 2, raw);
        assert.match(responses[1], /\r\nConnection: close\r\n/i, 'ответ во время остановки закрывает соединение');
        assert.strictEqual(exitCode, 0);
    });

    await test('не уложились в тайм-аут — соединения рвутся, выход 1; повторный сигнал — сразу 1', async () => {
        const codes = [];
        let fire;
        let closedAll = false;
        const shutdown = createShutdown({
            server: { close() {}, closeAllConnections() { closedAll = true; } },
            pool: { end: async () => {} },
            exit: (code) => codes.push(code),
            log: quiet,
            timeoutMs: 1234,
            timers: { setTimeout: (fn, ms) => { assert.strictEqual(ms, 1234); fire = fn; return {}; }, clearTimeout() {} },
        });
        shutdown('SIGTERM');
        shutdown('SIGINT');
        assert.deepStrictEqual(codes, [1], 'повторный сигнал');
        fire();
        assert.ok(closedAll);
        assert.deepStrictEqual(codes, [1, 1]);
    });

    await test('сбой при остановке (pool.end) — в лог и выход 1', async () => {
        const codes = [];
        const reports = [];
        const shutdown = createShutdown({
            pool: { end: async () => { throw new Error('pool'); } },
            exit: (code) => codes.push(code), log: quiet, report: (ctx) => reports.push(ctx),
        });
        await shutdown('SIGINT');
        assert.deepStrictEqual(codes, [1]);
        assert.deepStrictEqual(reports, ['[Process] Ошибка при остановке']);
    });

    await test('src/lifecycle.js подключает остановку к SIGTERM и SIGINT', () => {
        const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'lifecycle.js'), 'utf8');
        assert.match(source, /process\.on\('SIGTERM', \(\) => shutdown\('SIGTERM'\)\)/);
        assert.match(source, /process\.on\('SIGINT', \(\) => shutdown\('SIGINT'\)\)/);
        assert.match(source, /createShutdown\(\{ server, io, pool, jobs,/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
