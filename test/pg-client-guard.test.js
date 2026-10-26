'use strict';
// Обрыв соединения Postgres у выданного из пула клиента (W7 R2.1): lib/pg-client-guard.js.
// Без слушателя 'error' у выданного соединения обрыв посреди транзакции
// (pg_terminate_backend, рестарт базы) становился необработанным событием и
// ронял процесс. Проверяется:
//   * заглушка ловит 'error', соединение после него закрывается (release(err));
//   * заглушка снимается при возврате — слушатели не копятся при повторных выдачах;
//   * withTransaction (src/db/transactions.js) переживает обрыв и не возвращает в пул
//     соединение, которое не откатилось;
//   * в src/** и lib/** каждый pool.connect() сопровождается guardClient.
// Живой обрыв (pg_terminate_backend) — сквозной набор test/e2e/db-resilience.e2e.test.js.
// Запуск: node test/pg-client-guard.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { guardClient } = require('../lib/pg-client-guard');
const { createTransactions } = require('../src/db/transactions');

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

// Клиент как у pg: EventEmitter, release запоминает аргумент.
function fakeClient() {
    const client = new EventEmitter();
    client.releases = [];
    client.release = (err) => { client.releases.push(err); };
    return client;
}

const terminated = () => Object.assign(new Error('Connection terminated unexpectedly'), {});

async function main() {
    await test('обрыв выданного соединения не бросает, пишет в лог и закрывает соединение', () => {
        const client = fakeClient();
        const reports = [];
        const release = guardClient(client, '[DB] тест', { report: (context, err) => reports.push([context, err.message]) });
        // Без слушателя EventEmitter бросил бы здесь (так падал процесс).
        const err = terminated();
        client.emit('error', err);
        assert.deepStrictEqual(reports, [['[DB] тест', 'Connection terminated unexpectedly']]);
        release();
        assert.strictEqual(client.releases.length, 1);
        assert.strictEqual(client.releases[0], err, 'после обрыва соединение возвращается с ошибкой — пул его закрывает');
        assert.strictEqual(client.listenerCount('error'), 0, 'заглушка снята при возврате');
    });

    await test('без обрыва — обычный возврат в пул, ошибка вызывающего передаётся как есть', () => {
        const ok = fakeClient();
        guardClient(ok, '[DB] тест', { report: () => {} })();
        assert.deepStrictEqual(ok.releases, [undefined]);

        const bad = fakeClient();
        const rollbackErr = new Error('ROLLBACK не прошёл');
        guardClient(bad, '[DB] тест', { report: () => {} })(rollbackErr);
        assert.deepStrictEqual(bad.releases, [rollbackErr]);

        const flagged = fakeClient();
        guardClient(flagged, '[DB] тест', { report: () => {} })(true);
        assert.deepStrictEqual(flagged.releases, [true], 'release(true) у pg-pool тоже закрывает соединение');
    });

    await test('повторные выдачи одного соединения не копят слушателей', () => {
        const client = fakeClient();
        for (let i = 0; i < 50; i++) guardClient(client, '[DB] тест', { report: () => {} })();
        assert.strictEqual(client.listenerCount('error'), 0);
        assert.strictEqual(client.releases.length, 50);
    });

    await test('подставной клиент без EventEmitter (юнит-тесты) не ломается', () => {
        const releases = [];
        const release = guardClient({ release: (err) => releases.push(err) }, '[DB] тест');
        release();
        assert.deepStrictEqual(releases, [undefined]);
    });

    await test('withTransaction: обрыв посреди транзакции — ошибка запроса, соединение закрывается', async () => {
        const client = fakeClient();
        const queries = [];
        client.query = async (sql) => {
            queries.push(sql);
            if (sql === 'ROLLBACK') throw new Error('Client has encountered a connection error and is not queryable');
            return { rows: [] };
        };
        const pool = { connect: async () => client };
        const { withTransaction } = createTransactions({ pool });
        const lost = Object.assign(new Error('terminating connection due to administrator command'), { code: '57P01' });
        await assert.rejects(withTransaction(async () => {
            // Порядок как у pg: ошибка активного запроса, затем 'error' закрытого сокета.
            client.emit('error', terminated());
            throw lost;
        }), (err) => err === lost);
        assert.deepStrictEqual(queries, ['BEGIN', 'ROLLBACK']);
        assert.strictEqual(client.releases.length, 1);
        assert.ok(client.releases[0] instanceof Error, 'соединение не вернулось в пул как исправное');
        assert.strictEqual(client.listenerCount('error'), 0);
    });

    await test('withTransaction: успешная транзакция возвращает соединение в пул', async () => {
        const client = fakeClient();
        client.query = async () => ({ rows: [] });
        const { withTransaction } = createTransactions({ pool: { connect: async () => client } });
        assert.strictEqual(await withTransaction(async () => 42), 42);
        assert.deepStrictEqual(client.releases, [undefined]);
    });

    await test('код сервера: каждый pool.connect() в src/** и lib/** защищён guardClient', () => {
        const files = [];
        const walk = (dir) => {
            for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
                const rel = `${dir}/${entry.name}`;
                if (entry.isDirectory()) walk(rel);
                else if (entry.name.endsWith('.js')) files.push(rel);
            }
        };
        walk('src');
        walk('lib');
        const unguarded = [];
        let connects = 0;
        for (const file of files) {
            if (file === 'lib/pg-client-guard.js') continue;
            const lines = fs.readFileSync(path.join(ROOT, file), 'utf8').split('\n');
            lines.forEach((line, i) => {
                if (/^\s*(\/\/|\*)/.test(line) || !/\.connect\(\)/.test(line)) return;
                connects++;
                // Соединение, которое возвращается только в пул (опоздавшее после
                // тайм-аута ожидания, lib/pg-limits.js acquireClient), не используется.
                if (/const pending = pool\.connect\(\)/.test(line)) return;
                const window = lines.slice(i, i + 12).join('\n');
                if (!/guardClient\(/.test(window)) unguarded.push(`${file}:${i + 1}: ${line.trim()}`);
            });
        }
        assert.ok(connects >= 6, `ожидалось не меньше 6 вызовов connect(), найдено ${connects}`);
        assert.deepStrictEqual(unguarded, [], 'pool.connect() без guardClient:\n' + unguarded.join('\n'));
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
