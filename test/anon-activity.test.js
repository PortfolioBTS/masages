'use strict';
// Активность анонимов и проверка сессий (lib/anon-activity.js) — на
// поддельной БД и подменённых часах: validateSession, запись
// last_active_at корзиной (раз в корзину, только вверх), touch открытых
// сокетов и уборка кэша.
// Запуск: node test/anon-activity.test.js

const assert = require('assert');
const { createAnonActivity, STATE_RELOAD_MS, STATE_STALE_MS } = require('../lib/anon-activity');

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

const MIN = 60 * 1000;
const STEP = 5 * MIN;
const T0 = Date.parse('2026-10-03T12:00:00Z');

// Таблица users в памяти: id -> { anon_lifetime, last_active_at (мс) }.
function makeFakeDb(users = {}) {
    const rows = new Map(Object.entries(users).map(([id, row]) => [Number(id), { ...row }]));
    const calls = [];
    let failNext = null;
    const db = {
        rows,
        calls,
        failNextRun(err) { failNext = err; },
        async dbGet(sql, params) {
            calls.push({ kind: 'get', sql, params });
            const row = rows.get(params[0]);
            if (!row) return null;
            // EXTRACT(EPOCH …) * 1000 приходит из pg строкой (numeric).
            return { anon_lifetime: row.anon_lifetime, last_active_ms: row.last_active_at === null ? null : String(row.last_active_at) };
        },
        async dbRun(sql, params) {
            calls.push({ kind: 'run', sql: sql.replace(/\s+/g, ' ').trim(), params });
            if (failNext) {
                const err = failNext;
                failNext = null;
                throw err;
            }
            const value = params[1].getTime();
            const ids = Array.isArray(params[0]) ? params[0] : [params[0]];
            let rowCount = 0;
            for (const id of ids) {
                const row = rows.get(id);
                // «Только вверх»: AND last_active_at < $2.
                if (row && row.last_active_at < value) {
                    row.last_active_at = value;
                    rowCount++;
                }
            }
            return { rowCount };
        },
    };
    return db;
}

function setup(users, { start = T0 } = {}) {
    const db = makeFakeDb(users);
    const clock = { t: start };
    const logged = [];
    const activity = createAnonActivity({
        dbGet: db.dbGet,
        dbRun: db.dbRun,
        now: () => clock.t,
        report: (context, err) => logged.push(`${context}: ${err.message}`),
    });
    return { db, clock, logged, activity };
}

const gets = (db) => db.calls.filter(c => c.kind === 'get').length;
const runs = (db) => db.calls.filter(c => c.kind === 'run');

async function main() {
    console.log('Anon activity tests\n');

    await test('validateSession: no isAnonymous or a bad user id — invalid, without touching the database', async () => {
        const { db, activity } = setup({ 5: { anon_lifetime: 'tab', last_active_at: T0 } });
        for (const sess of [null, {}, { userId: 5 }, { userId: 5, isAnonymous: false }, { userId: 5, isAnonymous: 'true' }]) {
            assert.strictEqual(await activity.validateSession(sess), 'invalid', JSON.stringify(sess));
        }
        for (const userId of [undefined, 0, -5, 1.5, '5', null]) {
            assert.strictEqual(await activity.validateSession({ userId, isAnonymous: true }), 'invalid', String(userId));
        }
        assert.strictEqual(db.calls.length, 0);
    });

    await test('validateSession: missing user — expired; live user — ok and cached for 60 seconds', async () => {
        const { db, clock, activity } = setup({ 5: { anon_lifetime: 'tab', last_active_at: T0 } });
        assert.strictEqual(await activity.validateSession({ userId: 6, isAnonymous: true }), 'expired');
        const sess = { userId: 5, isAnonymous: true };
        assert.strictEqual(await activity.validateSession(sess), 'ok');
        assert.strictEqual(await activity.validateSession(sess), 'ok');
        assert.strictEqual(gets(db), 2, 'one SELECT for the missing user, one for the live one');
        clock.t += STATE_RELOAD_MS;
        assert.strictEqual(await activity.validateSession(sess), 'ok');
        assert.strictEqual(gets(db), 3, 'an entry older than 60 seconds is re-read');
        assert.strictEqual(activity.lifetimeOf(5), 'tab');
    });

    await test('validateSession: expired by the cache, but another instance recorded activity — ok; expired in the database — expired', async () => {
        const { db, clock, activity } = setup({ 5: { anon_lifetime: 'tab', last_active_at: T0 } });
        const sess = { userId: 5, isAnonymous: true };
        assert.strictEqual(await activity.validateSession(sess), 'ok');
        // Кэш свежий, но по нему срок вышел: перед ответом «expired» — повторное чтение.
        db.rows.get(5).last_active_at = T0 + 25 * MIN; // активность на другом экземпляре
        clock.t = T0 + 30 * MIN + 1;
        activity._states.get(5).loadedAtMs = clock.t; // запись «свежая»
        assert.strictEqual(await activity.validateSession(sess), 'ok');
        // На границе срока (корзина + 30 минут) — уже истёк.
        clock.t = T0 + 25 * MIN + 30 * MIN;
        assert.strictEqual(await activity.validateSession(sess), 'expired');
        // Срок поменяли на другом экземпляре (week) — после перечитывания жив.
        db.rows.get(5).anon_lifetime = 'week';
        clock.t += STATE_RELOAD_MS;
        assert.strictEqual(await activity.validateSession(sess), 'ok');
        assert.strictEqual(activity.lifetimeOf(5), 'week');
    });

    await test('validateSession: no last activity in the database — expired (fail closed)', async () => {
        const { activity } = setup({ 5: { anon_lifetime: 'week', last_active_at: null } });
        assert.strictEqual(await activity.validateSession({ userId: 5, isAnonymous: true }), 'expired');
    });

    await test('noteActivity: the bucket is written once per bucket and only upwards', async () => {
        const { db, clock, activity } = setup({ 5: { anon_lifetime: 'day', last_active_at: T0 } });
        await activity.validateSession({ userId: 5, isAnonymous: true });
        clock.t = T0 + 61 * 1000; // 12:01:01 -> корзина 12:05
        const write = activity.noteActivity(5);
        assert.ok(write && typeof write.then === 'function', 'a write is needed');
        await write;
        assert.strictEqual(db.rows.get(5).last_active_at, T0 + STEP);
        const [call] = runs(db);
        assert.strictEqual(call.sql, 'UPDATE users SET last_active_at = $2 WHERE id = $1 AND last_active_at < $2');
        assert.deepStrictEqual(call.params, [5, new Date(T0 + STEP)]);
        clock.t = T0 + 4 * MIN; // та же корзина
        assert.strictEqual(activity.noteActivity(5), null, 'same bucket — no write');
        clock.t = T0 + STEP + 1; // следующая корзина
        await activity.noteActivity(5);
        assert.strictEqual(db.rows.get(5).last_active_at, T0 + 2 * STEP);
        assert.strictEqual(runs(db).length, 2);
        // Значение в БД выше (другой экземпляр) — запись не опускает его.
        db.rows.get(5).last_active_at = T0 + 10 * STEP;
        clock.t = T0 + 2 * STEP + 1;
        await activity.noteActivity(5);
        assert.strictEqual(db.rows.get(5).last_active_at, T0 + 10 * STEP);
        assert.strictEqual(activity.noteActivity(0), null, 'bad id is ignored');
    });

    await test('noteActivity: a failed write is logged and retried on the next activity', async () => {
        const { db, clock, logged, activity } = setup({ 5: { anon_lifetime: 'tab', last_active_at: T0 } });
        await activity.validateSession({ userId: 5, isAnonymous: true });
        clock.t = T0 + 1;
        db.failNextRun(Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }));
        await activity.noteActivity(5);
        assert.deepStrictEqual(logged, ['[Anon] Не удалось записать активность: connection reset']);
        assert.strictEqual(db.rows.get(5).last_active_at, T0);
        clock.t = T0 + 2;
        await activity.noteActivity(5);
        assert.strictEqual(db.rows.get(5).last_active_at, T0 + STEP, 'retried in the same bucket');
    });

    await test('noteActivity without a cache entry (evicted) still writes — e.g. a socket closing after a long HTTP silence', async () => {
        const { db, clock, activity } = setup({ 5: { anon_lifetime: 'tab', last_active_at: T0 } });
        clock.t = T0 + 3 * STEP + 1;
        await activity.noteActivity(5);
        assert.strictEqual(db.rows.get(5).last_active_at, T0 + 4 * STEP);
        // Такая запись не подменяет проверку сессии: она перечитывается из БД.
        assert.strictEqual(await activity.validateSession({ userId: 5, isAnonymous: true }), 'ok');
        assert.strictEqual(gets(db), 1);
    });

    await test('touch: one UPDATE for all online users; stale offline entries are dropped from the cache', async () => {
        const { db, clock, activity } = setup({
            5: { anon_lifetime: 'tab', last_active_at: T0 },
            6: { anon_lifetime: 'week', last_active_at: T0 },
            7: { anon_lifetime: 'day', last_active_at: T0 },
        });
        for (const userId of [5, 6, 7]) await activity.validateSession({ userId, isAnonymous: true });
        clock.t = T0 + STATE_STALE_MS + 1;
        await activity.touch([5, 6, 6, 0]);
        const [call] = runs(db);
        assert.strictEqual(call.sql, 'UPDATE users SET last_active_at = $2 WHERE id = ANY($1::int[]) AND last_active_at < $2');
        assert.deepStrictEqual(call.params, [[5, 6], new Date(Math.ceil(clock.t / STEP) * STEP)]);
        assert.strictEqual(db.rows.get(5).last_active_at, Math.ceil(clock.t / STEP) * STEP);
        assert.strictEqual(db.rows.get(7).last_active_at, T0, 'offline user is not touched');
        assert.deepStrictEqual([...activity._states.keys()].sort(), [5, 6], 'stale offline entry dropped');
        // Те, кто в сети, после touch не пишутся повторно в той же корзине.
        assert.strictEqual(activity.noteActivity(5), null);
        // Никого в сети — запроса нет.
        await activity.touch([]);
        assert.strictEqual(runs(db).length, 1);
    });

    await test('remember / forget / lifetimeOf', async () => {
        const { db, activity } = setup({});
        activity.remember(9, { lifetime: 'week', lastActiveMs: T0, persistedBucketMs: T0 });
        assert.strictEqual(activity.lifetimeOf(9), 'week');
        assert.strictEqual(await activity.validateSession({ userId: 9, isAnonymous: true }), 'ok', 'no SELECT right after registration');
        assert.strictEqual(gets(db), 0);
        activity.forget(9);
        assert.strictEqual(activity.lifetimeOf(9), null);
        assert.strictEqual(await activity.validateSession({ userId: 9, isAnonymous: true }), 'expired');
        assert.throws(() => createAnonActivity({}), TypeError);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
