'use strict';
// Сбои доступности базы → 503 busy с Retry-After (ревью W7 R2.4, R2.10): lib/db-errors.js,
// обработчик ошибок Express (src/http/middleware/error-handler.js) и таймауты сессии
// Postgres (src/db/pool.js resolveDbSessionTimeouts).
// Живые сценарии (зависшая блокировка, недоступная база) — test/e2e/db-resilience.e2e.test.js.
// Запуск: node test/db-errors.test.js

const assert = require('assert');
const express = require('express');
const { isDbUnavailable, respondIfDbBusy, createBusyReporter } = require('../lib/db-errors');
const { BUSY_RESPONSE } = require('../lib/pg-limits');
const { installErrorHandler } = require('../src/http/middleware/error-handler');
const { resolveDbSessionTimeouts, DB_SESSION_OPTIONS } = require('../src/db/pool');

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

const pgError = (code, message = 'ошибка') => Object.assign(new Error(message), { code });

function fakeRes() {
    return {
        statusCode: 200, body: null, headers: {}, headersSent: false,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; this.headersSent = true; return this; },
        set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    };
}

async function main() {
    await test('классификатор: обрыв, пул, слоты, таймауты сессии, взаимная блокировка — «занято»', () => {
        const busy = [
            pgError('57P01', 'terminating connection due to administrator command'),
            pgError('57P03', 'the database system is starting up'),
            pgError('53300', 'sorry, too many clients already'),
            pgError('08006', 'connection failure'),
            pgError('55P03', 'canceling statement due to lock timeout'),
            pgError('57014', 'canceling statement due to statement timeout'),
            pgError('25P03', 'terminating connection due to idle-in-transaction timeout'),
            pgError('40P01', 'deadlock detected'),
            pgError('40001', 'could not serialize access'),
            pgError('ECONNREFUSED', 'connect ECONNREFUSED 127.0.0.1:5432'),
            pgError('ECONNRESET', 'read ECONNRESET'),
            pgError('LIMIT_STORE_UNAVAILABLE', 'Корзины лимитов недоступны'),
            new Error('timeout exceeded when trying to connect'),
            new Error('Connection terminated unexpectedly'),
            new Error('Connection terminated due to connection timeout'),
            new Error('Client has encountered a connection error and is not queryable'),
            pgError('55000', 'database "x" is not currently accepting connections'),
        ];
        for (const err of busy) assert.strictEqual(isDbUnavailable(err), true, `${err.code} ${err.message}`);
    });

    await test('классификатор: ошибки самого запроса и кода — не «занято»', () => {
        const notBusy = [
            pgError('23505', 'duplicate key value violates unique constraint'),
            pgError('23503', 'violates foreign key constraint'),
            pgError('22P02', 'invalid input syntax for type integer'),
            pgError('42P01', 'relation "x" does not exist'),
            pgError('55000', 'object not in prerequisite state'),
            // Повторное ревью W7, Н7: 08P01 (protocol_violation) — класс 08, но это ошибка самого запроса (например,
            // больше 65535 параметров в одном запросе): повтор не поможет, её нужно видеть в логе как 500.
            pgError('08P01', 'bind message supplies 70000 parameters, but prepared statement requires 4464'),
            new TypeError('Cannot read properties of undefined'),
            pgError('ENOENT', 'no such file'),
            null, undefined, 'строка',
        ];
        for (const err of notBusy) assert.strictEqual(isDbUnavailable(err), false, String(err && (err.code || err.message)));
    });

    await test('respondIfDbBusy: 503 busy с Retry-After; не та ошибка — ответа нет', () => {
        const res = fakeRes();
        const reports = [];
        assert.strictEqual(respondIfDbBusy(res, pgError('55P03', 'lock timeout'), { report: (e) => reports.push(e.code) }), true);
        assert.strictEqual(res.statusCode, 503);
        assert.strictEqual(res.headers['retry-after'], '5');
        assert.deepStrictEqual(res.body, BUSY_RESPONSE);
        assert.deepStrictEqual(reports, ['55P03']);

        const other = fakeRes();
        assert.strictEqual(respondIfDbBusy(other, pgError('23505'), { report: () => assert.fail('не должно') }), false);
        assert.strictEqual(other.body, null);
    });

    await test('отчёт о «занято» — не чаще раза в интервал, с числом пропущенных', () => {
        let clock = 0;
        const lines = [];
        const report = createBusyReporter({ log: (line) => lines.push(line), intervalMs: 1000, now: () => clock });
        report(pgError('57P01'));
        report(pgError('57P01'));
        report(pgError('57P01'));
        clock = 1500;
        report(pgError('57P01'));
        assert.strictEqual(lines.length, 2);
        assert.match(lines[1], /и ещё 2 таких ответов/);
    });

    await test('обработчик ошибок Express: сбой базы — 503 busy с Retry-After, остальное — 500', async () => {
        const app = express();
        app.get('/db', (req, res, next) => next(new Error('timeout exceeded when trying to connect')));
        app.get('/bug', (req, res, next) => next(new TypeError('ошибка кода')));
        installErrorHandler(app);
        const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
        const originalError = console.error;
        console.error = () => {};
        try {
            const base = `http://127.0.0.1:${server.address().port}`;
            const db = await fetch(`${base}/db`);
            assert.strictEqual(db.status, 503);
            assert.strictEqual(db.headers.get('retry-after'), '5');
            assert.deepStrictEqual(await db.json(), BUSY_RESPONSE);
            const bug = await fetch(`${base}/bug`);
            assert.strictEqual(bug.status, 500);
        } finally {
            console.error = originalError;
            await new Promise((resolve) => server.close(resolve));
        }
    });

    await test('таймауты сессии Postgres: умолчания, свои значения, вне диапазона — умолчание', () => {
        assert.deepStrictEqual(resolveDbSessionTimeouts({}), {
            statement_timeout: 30000, lock_timeout: 5000, idle_in_transaction_session_timeout: 30000,
        });
        assert.deepStrictEqual(resolveDbSessionTimeouts({ DB_LOCK_TIMEOUT_MS: '1500', DB_STATEMENT_TIMEOUT_MS: ' 60000 ', DB_IDLE_TX_TIMEOUT_MS: '120000' }), {
            statement_timeout: 60000, lock_timeout: 1500, idle_in_transaction_session_timeout: 120000,
        });
        // 0 выключил бы таймаут — не допускается, как и мусор и выход за предел.
        assert.deepStrictEqual(resolveDbSessionTimeouts({ DB_LOCK_TIMEOUT_MS: '0', DB_STATEMENT_TIMEOUT_MS: 'abc', DB_IDLE_TX_TIMEOUT_MS: '99999999' }), {
            statement_timeout: 30000, lock_timeout: 5000, idle_in_transaction_session_timeout: 30000,
        });
    });

    await test('пояс сессии Postgres закреплён: UTC (колонки TIMESTAMP без пояса)', () => {
        assert.strictEqual(DB_SESSION_OPTIONS, '-c TimeZone=UTC');
        const source = require('fs').readFileSync(require('path').join(__dirname, '..', 'src', 'db', 'pool.js'), 'utf8');
        assert.match(source, /options: DB_SESSION_OPTIONS,/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
