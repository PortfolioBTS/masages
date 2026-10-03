'use strict';
// Advisory-блокировки миграций и фоновых задач (lib/advisory-locks.js) —
// против поддельного пула: порядок запросов, повторы при lock_timeout,
// снятие блокировки и судьба соединения в любом исходе.
// Настоящий Postgres (две реплики стартуют одновременно) — в сквозном
// наборе test/e2e/smoke.e2e.test.js.
// Запуск: node test/advisory-locks.test.js

const assert = require('assert');
const {
    advisoryLockKey,
    runMigrationsExclusive,
    createRunExclusive,
    MIGRATION_LOCK_KEY,
    LOCK_NOT_AVAILABLE,
} = require('../lib/advisory-locks');

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

// Поддельный пул: каждый connect() — новый клиент; все запросы пишутся в
// calls. tryLock — очередь ответов pg_try_advisory_lock; failOn — ошибка
// на запрос, начинающийся с данной строки.
function makeFakePool({ tryLock = [], failOn = [] } = {}) {
    const calls = [];
    const released = [];
    let nextId = 1;
    const pool = {
        async connect() {
            const id = nextId++;
            return {
                id,
                async query(sql, params) {
                    calls.push({ client: id, sql, params });
                    const failure = failOn.find(f => sql.startsWith(f.prefix) && (f.times === undefined || f.times-- > 0));
                    if (failure) throw failure.error;
                    if (sql.startsWith('SELECT pg_try_advisory_lock')) {
                        return { rows: [{ locked: tryLock.length > 0 ? tryLock.shift() : true }] };
                    }
                    return { rows: [] };
                },
                release(err) { released.push({ id, err }); },
            };
        },
        async query(sql) {
            calls.push({ client: 'pool', sql });
            return { rows: [] };
        },
    };
    return { pool, calls, released };
}

function makeMigrationPoolFactory() {
    const created = [];
    const factory = (options) => {
        const fake = {
            options,
            ended: false,
            listeners: {},
            on(event, fn) { this.listeners[event] = fn; },
            async query(sql) { return { rows: [], via: 'migration-pool', sql }; },
            async connect() { return { via: 'migration-pool' }; },
            async end() { this.ended = true; },
        };
        created.push(fake);
        return fake;
    };
    return { factory, created };
}

const sqlOf = (calls, client) => calls.filter(c => client === undefined || c.client === client).map(c => c.sql);
const lockTimeoutError = () => Object.assign(new Error('canceling statement due to lock timeout'), { code: LOCK_NOT_AVAILABLE });
const quiet = () => {};

async function main() {
    console.log('Advisory locks tests\n');

    await test('ключи блокировок: детерминированы, различны по имени, в диапазоне bigint', () => {
        assert.strictEqual(advisoryLockKey('job:a'), advisoryLockKey('job:a'));
        assert.notStrictEqual(advisoryLockKey('job:a'), advisoryLockKey('job:b'));
        for (const key of [MIGRATION_LOCK_KEY, advisoryLockKey('job:purge')]) {
            assert.match(key, /^-?\d+$/);
            const n = BigInt(key);
            assert.ok(n >= -(2n ** 63n) && n < 2n ** 63n);
        }
        assert.strictEqual(MIGRATION_LOCK_KEY, advisoryLockKey('migrations'));
    });

    await test('миграции: блокировка → lock_timeout → migrate с пулом миграций → RESET и снятие → клиент в пул', async () => {
        const { pool, calls, released } = makeFakePool();
        const originalQuery = pool.query;
        const originalConnect = pool.connect;
        const { factory, created } = makeMigrationPoolFactory();
        let seen = null;
        const result = await runMigrationsExclusive(pool, async (ctx) => {
            seen = { attempt: ctx.attempt, clientId: ctx.client.id, samePool: ctx.pool === pool, via: (await pool.query('SELECT 1')).via };
            return 'готово';
        }, { createMigrationPool: factory, lockTimeoutMs: 2500, log: quiet });

        assert.strictEqual(result, 'готово');
        assert.deepStrictEqual(seen, { attempt: 1, clientId: 1, samePool: true, via: 'migration-pool' });
        assert.deepStrictEqual(sqlOf(calls, 1), [
            'SELECT pg_try_advisory_lock($1::bigint) AS locked',
            'SET lock_timeout = 2500',
            'RESET lock_timeout',
            'SELECT pg_advisory_unlock($1::bigint)',
        ]);
        assert.strictEqual(calls[0].params[0], MIGRATION_LOCK_KEY);
        assert.deepStrictEqual(released, [{ id: 1, err: undefined }]);
        // Маршрутизация снята, пул миграций закрыт; у его соединений — тот же lock_timeout.
        assert.strictEqual(pool.query, originalQuery);
        assert.strictEqual(pool.connect, originalConnect);
        assert.strictEqual(created.length, 1);
        assert.strictEqual(created[0].ended, true);
        assert.strictEqual(created[0].options.max, 2);
        const onConnectSql = [];
        await created[0].options.onConnect({ query: async (sql) => { onConnectSql.push(sql); } });
        assert.deepStrictEqual(onConnectSql, ['SET lock_timeout = 2500']);
    });

    await test('миграции: блокировка занята — сообщение в лог и ожидание pg_advisory_lock', async () => {
        const { pool, calls } = makeFakePool({ tryLock: [false] });
        const { factory } = makeMigrationPoolFactory();
        const logs = [];
        await runMigrationsExclusive(pool, async () => {}, { createMigrationPool: factory, log: (l) => logs.push(l) });
        assert.deepStrictEqual(sqlOf(calls, 1).slice(0, 3), [
            'SELECT pg_try_advisory_lock($1::bigint) AS locked',
            'SELECT pg_advisory_lock($1::bigint)',
            'SET lock_timeout = 2500',
        ]);
        assert.ok(logs.some(l => /другой экземпляр/.test(l)));
    });

    await test('миграции: 55P03 — повтор migrate() целиком, потом успех', async () => {
        const { pool, released } = makeFakePool();
        const { factory } = makeMigrationPoolFactory();
        const attempts = [];
        const logs = [];
        const result = await runMigrationsExclusive(pool, async ({ attempt }) => {
            attempts.push(attempt);
            if (attempt < 3) throw lockTimeoutError();
            return attempt;
        }, { createMigrationPool: factory, attempts: 5, log: (l) => logs.push(l) });
        assert.strictEqual(result, 3);
        assert.deepStrictEqual(attempts, [1, 2, 3]);
        assert.strictEqual(logs.filter(l => /попытка \d из 5/.test(l)).length, 2);
        assert.deepStrictEqual(released, [{ id: 1, err: undefined }]);
    });

    await test('миграции: 55P03 на всех попытках — ошибка наружу, блокировка снята, клиент цел', async () => {
        const { pool, calls, released } = makeFakePool();
        const { factory, created } = makeMigrationPoolFactory();
        let count = 0;
        await assert.rejects(
            runMigrationsExclusive(pool, async () => { count++; throw lockTimeoutError(); }, { createMigrationPool: factory, attempts: 3, log: quiet }),
            (err) => err.code === LOCK_NOT_AVAILABLE
        );
        assert.strictEqual(count, 3);
        assert.ok(sqlOf(calls, 1).includes('SELECT pg_advisory_unlock($1::bigint)'));
        assert.deepStrictEqual(released, [{ id: 1, err: undefined }]);
        assert.strictEqual(created[0].ended, true);
    });

    await test('миграции: другая ошибка migrate() не повторяется', async () => {
        const { pool } = makeFakePool();
        const { factory } = makeMigrationPoolFactory();
        let count = 0;
        await assert.rejects(
            runMigrationsExclusive(pool, async () => { count++; throw new Error('синтаксис'); }, { createMigrationPool: factory, log: quiet }),
            /синтаксис/
        );
        assert.strictEqual(count, 1);
    });

    await test('миграции: сбой на клиенте блокировки — migrate не вызывается, соединение уничтожается', async () => {
        const broken = new Error('Connection terminated');
        const { pool, released } = makeFakePool({ failOn: [{ prefix: 'SELECT pg_try_advisory_lock', error: broken }] });
        const originalQuery = pool.query;
        const { factory, created } = makeMigrationPoolFactory();
        let called = false;
        await assert.rejects(
            runMigrationsExclusive(pool, async () => { called = true; }, { createMigrationPool: factory, log: quiet }),
            /Connection terminated/
        );
        assert.strictEqual(called, false);
        assert.strictEqual(created.length, 0);
        assert.strictEqual(pool.query, originalQuery);
        assert.deepStrictEqual(released, [{ id: 1, err: broken }]);
    });

    await test('миграции: не снялась блокировка — соединение уничтожается (иначе осталась бы в пуле)', async () => {
        const unlockError = new Error('server closed the connection');
        const { pool, released } = makeFakePool({ failOn: [{ prefix: 'SELECT pg_advisory_unlock', error: unlockError }] });
        const { factory } = makeMigrationPoolFactory();
        const reports = [];
        await runMigrationsExclusive(pool, async () => {}, { createMigrationPool: factory, log: quiet, report: (ctx) => reports.push(ctx) });
        assert.deepStrictEqual(released, [{ id: 1, err: unlockError }]);
        assert.deepStrictEqual(reports, ['[DB] Не удалось снять блокировку миграций']);
    });

    await test('миграции: без фабрики пула и с неверным lock_timeout — ошибка до соединения', async () => {
        const { pool, calls } = makeFakePool();
        await assert.rejects(runMigrationsExclusive(pool, async () => {}, {}), TypeError);
        await assert.rejects(runMigrationsExclusive(pool, async () => {}, { createMigrationPool: () => ({}), lockTimeoutMs: 0 }), RangeError);
        assert.strictEqual(calls.length, 0);
    });

    await test('runExclusive: свободно — задача выполняется, блокировка снимается, клиент в пул', async () => {
        const { pool, calls, released } = makeFakePool();
        const runExclusive = createRunExclusive(pool, { report: quiet });
        let ran = 0;
        assert.strictEqual(await runExclusive('purge', async () => { ran++; }), true);
        assert.strictEqual(ran, 1);
        assert.deepStrictEqual(sqlOf(calls), [
            'SELECT pg_try_advisory_lock($1::bigint) AS locked',
            'SELECT pg_advisory_unlock($1::bigint)',
        ]);
        assert.strictEqual(calls[0].params[0], advisoryLockKey('job:purge'));
        assert.strictEqual(calls[1].params[0], advisoryLockKey('job:purge'));
        assert.deepStrictEqual(released, [{ id: 1, err: undefined }]);
    });

    await test('runExclusive: занято — запуск пропускается без разблокировки', async () => {
        const { pool, calls, released } = makeFakePool({ tryLock: [false] });
        const runExclusive = createRunExclusive(pool, { report: quiet });
        let ran = false;
        assert.strictEqual(await runExclusive('purge', async () => { ran = true; }), false);
        assert.strictEqual(ran, false);
        assert.deepStrictEqual(sqlOf(calls), ['SELECT pg_try_advisory_lock($1::bigint) AS locked']);
        assert.deepStrictEqual(released, [{ id: 1, err: undefined }]);
    });

    await test('runExclusive: задача упала — false, ошибка в отчёт, блокировка снята, клиент цел', async () => {
        const { pool, calls, released } = makeFakePool();
        const reports = [];
        const runExclusive = createRunExclusive(pool, { report: (ctx, err) => reports.push([ctx, err.message]) });
        assert.strictEqual(await runExclusive('purge', async () => { throw new Error('сбой'); }), false);
        assert.deepStrictEqual(reports, [['[Jobs] purge', 'сбой']]);
        assert.ok(sqlOf(calls).includes('SELECT pg_advisory_unlock($1::bigint)'));
        assert.deepStrictEqual(released, [{ id: 1, err: undefined }]);
    });

    await test('runExclusive: сбой при взятии или снятии блокировки — соединение уничтожается', async () => {
        const lockErr = new Error('lock query failed');
        const a = makeFakePool({ failOn: [{ prefix: 'SELECT pg_try_advisory_lock', error: lockErr }] });
        let ran = false;
        assert.strictEqual(await createRunExclusive(a.pool, { report: quiet })('purge', async () => { ran = true; }), false);
        assert.strictEqual(ran, false);
        assert.deepStrictEqual(a.released, [{ id: 1, err: lockErr }]);

        const unlockErr = new Error('unlock failed');
        const b = makeFakePool({ failOn: [{ prefix: 'SELECT pg_advisory_unlock', error: unlockErr }] });
        assert.strictEqual(await createRunExclusive(b.pool, { report: quiet })('purge', async () => {}), true);
        assert.deepStrictEqual(b.released, [{ id: 1, err: unlockErr }]);
    });

    await test('runExclusive: нет соединения — false и сообщение', async () => {
        const reports = [];
        const pool = { connect: async () => { throw new Error('timeout exceeded when trying to connect'); } };
        const runExclusive = createRunExclusive(pool, { report: (ctx) => reports.push(ctx) });
        assert.strictEqual(await runExclusive('purge', async () => {}), false);
        assert.deepStrictEqual(reports, ['[Jobs] purge: нет соединения для блокировки']);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
