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
