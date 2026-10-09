'use strict';
// Тесты lib/pg-limits.js (точные лимиты в Postgres, 7.4) на фейковом пуле:
// пул повторяет SQL-контракт хранилища в памяти, настоящую базу проверяют
// сквозные тесты (test/e2e/security-wave2.e2e.test.js).
//
// Что проверяется: схема (UNLOGGED, без ALTER), ключи (HMAC, без IP и id в
// запросах), стор express-rate-limit, закрытие лимита при сбое хранилища
// (503 {code:'busy'}), скользящее окно bundle, одноразовость PoW через
// хранилище, уборка, подключение bundleLimiter к lib/e2ee-keys.js.
// Запуск: node test/pg-limits.test.js

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const express = require('express');
const { makeFakeKeyDb } = require('./fake-key-db');
const {
    BUSY_RESPONSE,
    LimitStoreError,
    initPgLimitsSchema,
    createLimitKeys,
    createPgLimits,
    createPgRateLimitStore,
    createPgSlidingLimiter,
    createPgPowUsedStore,
    createErrorReporter,
    purgeExpiredLimits,
    jobs,
} = require('../lib/pg-limits');
const { registerE2eeKeyRoutes } = require('../lib/e2ee-keys');
const { logError } = require('../lib/log-error');
const { JOB_MODULES } = require('../lib/jobs');
const { solve } = require('../public/pow-worker.js');

const POW_PATH = path.join(__dirname, '..', 'lib', 'pow.js');
const SECRET = 'test-secret-test-secret-test-secret-0123456789';

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

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

// ---- Фейковый пул: те же таблицы и те же запросы, что в lib/pg-limits.js ----
function makeFakePool() {
    const clock = { now: Date.UTC(2026, 9, 9, 12, 0, 30) };
    const state = {
        counters: new Map(),   // k -> { hits, resetAt }
        buckets: new Map(),    // hex -> Map(bucketMs -> n)
        pow: new Map(),        // hex -> expiresAtMs
        ddl: [],
        calls: [],             // [{ text, params }] — всё, что видела база
        locks: [],
        released: [],
        rollbacks: 0,
    };
    const control = { failure: null, hang: false, rollbackFails: false, connectHangs: false };
    const floorMinute = (ms) => Math.floor(ms / MINUTE) * MINUTE;
    const squash = (text) => text.replace(/\s+/g, ' ').trim();

    function guard() {
        if (control.failure) throw control.failure;
    }

    async function query(text, params = []) {
        state.calls.push({ text, params });
        if (control.hang) return new Promise(() => {});
        guard();
        const t = squash(text);
        if (t.startsWith('CREATE UNLOGGED TABLE')) {
            state.ddl.push(t);
            return { rows: [], rowCount: 0 };
        }
        if (t.startsWith('INSERT INTO rl_counters')) {
            const [k, windowMs] = params;
            const row = state.counters.get(k);
            if (!row || row.resetAt <= clock.now) state.counters.set(k, { hits: 1, resetAt: clock.now + windowMs });
            else row.hits++;
            const cur = state.counters.get(k);
            return { rows: [{ hits: cur.hits, reset_at: new Date(cur.resetAt) }], rowCount: 1 };
        }
        if (t.startsWith('SELECT hits, reset_at FROM rl_counters')) {
            const row = state.counters.get(params[0]);
            return row && row.resetAt > clock.now
                ? { rows: [{ hits: row.hits, reset_at: new Date(row.resetAt) }], rowCount: 1 }
                : { rows: [], rowCount: 0 };
        }
        if (t.startsWith('UPDATE rl_counters SET hits = GREATEST')) {
            const row = state.counters.get(params[0]);
            if (row) row.hits = Math.max(row.hits - 1, 0);
            return { rows: [], rowCount: row ? 1 : 0 };
        }
        if (t.startsWith('DELETE FROM rl_counters WHERE k =')) {
            return { rows: [], rowCount: state.counters.delete(params[0]) ? 1 : 0 };
        }
        if (t.startsWith('DELETE FROM rl_counters WHERE starts_with')) {
            let n = 0;
            for (const k of [...state.counters.keys()]) if (k.startsWith(params[0])) { state.counters.delete(k); n++; }
            return { rows: [], rowCount: n };
        }
        if (t.startsWith('DELETE FROM rl_counters WHERE reset_at')) {
            let n = 0;
            for (const [k, row] of [...state.counters]) if (row.resetAt <= clock.now) { state.counters.delete(k); n++; }
            return { rows: [], rowCount: n };
        }
        if (t.startsWith('DELETE FROM rl_buckets WHERE bucket <')) {
            const limit = floorMinute(clock.now) - params[0];
            let n = 0;
            for (const [hex, map] of state.buckets) {
                for (const bucket of [...map.keys()]) if (bucket < limit) { map.delete(bucket); n++; }
                if (map.size === 0) state.buckets.delete(hex);
            }
            return { rows: [], rowCount: n };
        }
        if (t.startsWith('DELETE FROM pow_used WHERE expires_at <')) {
            const limit = clock.now - params[0];
            let n = 0;
            for (const [hex, expiresAt] of [...state.pow]) if (expiresAt < limit) { state.pow.delete(hex); n++; }
            return { rows: [], rowCount: n };
        }
        if (t.startsWith('INSERT INTO pow_used')) {
            const hex = params[0].toString('hex');
            if (state.pow.has(hex)) return { rows: [], rowCount: 0 };
            state.pow.set(hex, params[1]);
            return { rows: [], rowCount: 1 };
        }
        throw new Error('фейковый пул не знает запроса: ' + t.slice(0, 80));
    }

    function makeClient() {
        let pending = null;
        const client = {
            async query(text, params = []) {
                state.calls.push({ text, params });
                const t = squash(text);
                if (t.startsWith('ROLLBACK')) {
                    state.rollbacks++;
                    pending = null;
                    if (control.rollbackFails) throw new Error('соединение потеряно');
                    return { rows: [] };
                }
                guard();
                if (t.startsWith('BEGIN')) { pending = []; return {}; }
                if (t.startsWith('COMMIT')) {
                    for (const [hex, bucket] of pending) {
                        const map = state.buckets.get(hex) || new Map();
                        state.buckets.set(hex, map);
                        map.set(bucket, (map.get(bucket) || 0) + 1);
                    }
                    pending = null;
                    return {};
                }
                if (t.startsWith('SELECT pg_advisory_xact_lock')) {
                    state.locks.push(params);
                    return { rows: [{}] };
                }
                if (t.startsWith("SELECT encode(k, 'hex') AS k")) {
                    const [hexes, minutes] = params;
                    const lowerExclusive = floorMinute(clock.now) - minutes * MINUTE;
                    const rows = [];
                    for (const hex of hexes) {
                        const inWindow = [...(state.buckets.get(hex) || new Map())].filter(([bucket]) => bucket > lowerExclusive);
                        if (inWindow.length === 0) continue;
                        const oldest = Math.min(...inWindow.map(([bucket]) => bucket));
                        rows.push({
                            k: hex,
                            total: inWindow.reduce((sum, [, n]) => sum + n, 0),
                            wait_ms: oldest + minutes * MINUTE - clock.now,
                        });
                    }
                    return { rows };
                }
                if (t.startsWith('INSERT INTO rl_buckets')) {
                    for (const hex of params[0]) pending.push([hex, floorMinute(clock.now)]);
                    return { rows: [] };
                }
                throw new Error('фейковый клиент не знает запроса: ' + t.slice(0, 80));
            },
            release(arg) { state.released.push(arg); },
        };
        return client;
    }

    const pool = {
        query,
        connect: () => (control.connectHangs ? new Promise(() => {}) : Promise.resolve(makeClient())),
    };
    return { pool, state, control, clock };
}

function listen(app) {
    return new Promise((resolve) => {
        const server = http.createServer(app).listen(0, '127.0.0.1', () => resolve(server));
    });
}

async function withApp(app, fn) {
    const server = await listen(app);
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
        server.closeAllConnections();
    }
}

// Приложение с одним лимитером: клиент — заголовок x-client.
function limitedApp(limiter, onHandler = () => {}) {
    const app = express();
    app.get('/ping', limiter, (req, res) => { onHandler(); res.json({ success: true }); });
    return app;
}

function loadFreshPow() {
    delete require.cache[require.resolve(POW_PATH)];
    return require(POW_PATH);
}

const allParams = (state) => JSON.stringify(state.calls.map(c => c.params.map(p => (Buffer.isBuffer(p) ? p.toString('hex') : p))));

async function main() {
    console.log('PG limits tests\n');

    // ---------------------------------------------------------------- схема
    await test('схема: три UNLOGGED-таблицы, без ALTER', async () => {
        const { pool, state } = makeFakePool();
        await initPgLimitsSchema(pool);
        await initPgLimitsSchema(pool); // идемпотентно (IF NOT EXISTS)
        assert.strictEqual(state.ddl.length, 6);
        for (const table of ['rl_counters', 'rl_buckets', 'pow_used']) {
            assert.ok(state.ddl.some(d => d.startsWith(`CREATE UNLOGGED TABLE IF NOT EXISTS ${table} `)), table);
        }
        assert.ok(state.ddl.every(d => !/ALTER/i.test(d)));
        assert.ok(state.ddl.some(d => /rl_counters .*fillfactor = 70/.test(d)));
    });

    // ---------------------------------------------------------------- ключи
    await test('ключи: HMAC зависит от секрета, имени лимитера и значения; сырое значение в ключ не попадает', () => {
        const a = createLimitKeys(SECRET);
        const b = createLimitKeys(SECRET + 'x');
        const text = a.text('register', '203.0.113.7');
        assert.match(text, /^register:[A-Za-z0-9_-]{43}$/);
        assert.ok(!text.includes('203.0.113.7'));
        assert.strictEqual(a.text('register', '203.0.113.7'), text, 'детерминирован');
        assert.notStrictEqual(a.text('register', '203.0.113.8'), text);
        assert.notStrictEqual(a.text('join-ip', '203.0.113.7').split(':')[1], text.split(':')[1], 'имя лимитера входит в HMAC');
        assert.notStrictEqual(b.text('register', '203.0.113.7'), text, 'другой SESSION_SECRET — другие ключи');
        assert.strictEqual(a.digest('s', 'k').length, 32);
        assert.throws(() => createLimitKeys(''), TypeError);
    });

    // ------------------------------------------------------- стор fixed window
    await test('стор: increment / get / decrement / resetKey / resetAll и перезапуск окна', async () => {
        const { pool, state, clock } = makeFakePool();
        const keys = createLimitKeys(SECRET);
        const store = createPgRateLimitStore({ pool, keys, scope: 'register', windowMs: HOUR });
        const other = createPgRateLimitStore({ pool, keys, scope: 'join-ip', windowMs: HOUR });
        assert.strictEqual(store.localKeys, false);
        assert.strictEqual(store.prefix, 'register:');

        const first = await store.increment('1.2.3.4');
        assert.strictEqual(first.totalHits, 1);
        assert.strictEqual(first.resetTime.getTime(), clock.now + HOUR);
        clock.now += 10 * MINUTE;
        const second = await store.increment('1.2.3.4');
        assert.strictEqual(second.totalHits, 2);
        assert.strictEqual(second.resetTime.getTime(), first.resetTime.getTime(), 'конец окна не двигается');
        assert.strictEqual((await store.get('1.2.3.4')).totalHits, 2);
        assert.strictEqual(await store.get('9.9.9.9'), undefined);

        await store.decrement('1.2.3.4');
        assert.strictEqual((await store.get('1.2.3.4')).totalHits, 1);
        await other.increment('1.2.3.4');
        assert.strictEqual(state.counters.size, 2, 'у лимитеров разные строки для одного клиента');

        await store.resetAll();
        assert.strictEqual(await store.get('1.2.3.4'), undefined);
        assert.strictEqual(state.counters.size, 1, 'resetAll трогает только свой лимитер');
        await other.resetKey('1.2.3.4');
        assert.strictEqual(state.counters.size, 0);

        await store.increment('x');
        clock.now += HOUR + 1;
        assert.strictEqual((await store.increment('x')).totalHits, 1, 'просроченное окно начинается заново');
        assert.throws(() => createPgRateLimitStore({ pool, keys, scope: 'Bad Scope!' }), TypeError);
    });

    await test('стор: init берёт windowMs у express-rate-limit', async () => {
        const { pool, clock } = makeFakePool();
        const store = createPgRateLimitStore({ pool, keys: createLimitKeys(SECRET), scope: 'x' });
        await assert.rejects(store.increment('a'), LimitStoreError);
        store.init({ windowMs: 5000 });
        assert.strictEqual((await store.increment('a')).resetTime.getTime(), clock.now + 5000);
    });

    // --------------------------------------------------------- middleware
    await test('лимитер: 429 после max, заголовки, лимит переживает «рестарт» и обнуляется сменой секрета', async () => {
        const { pool, state } = makeFakePool();
        const hooks = { limited: [], storeError: [] };
        const make = (secret) => createPgLimits({
            pool, secret,
            hooks: { limited: (s) => hooks.limited.push(s), storeError: (s) => hooks.storeError.push(s) },
        }).rateLimiter('register', {
            windowMs: HOUR,
            max: 3,
            keyGenerator: (req) => req.headers['x-client'],
            message: { success: false, message: 'Слишком много регистраций. Попробуйте позже.' },
        });
        const call = (base, client) => fetch(`${base}/ping`, { headers: { 'x-client': client } });

        await withApp(limitedApp(make(SECRET)), async (base) => {
            for (let i = 0; i < 3; i++) assert.strictEqual((await call(base, '203.0.113.7')).status, 200);
            const limited = await call(base, '203.0.113.7');
            assert.strictEqual(limited.status, 429);
            assert.deepStrictEqual(await limited.json(), { success: false, message: 'Слишком много регистраций. Попробуйте позже.' });
            assert.ok(limited.headers.get('ratelimit') || limited.headers.get('ratelimit-policy'), 'стандартные заголовки RateLimit');
            assert.strictEqual((await call(base, '203.0.113.8')).status, 200, 'другой клиент считается отдельно');
        });
        assert.deepStrictEqual(hooks.limited, ['register']);

        // «Рестарт»: новый лимитер на том же хранилище — счётчик на месте.
        await withApp(limitedApp(make(SECRET)), async (base) => {
            assert.strictEqual((await call(base, '203.0.113.7')).status, 429);
        });
        // Другой SESSION_SECRET — другие HMAC-ключи, лимит начинается заново.
        await withApp(limitedApp(make(SECRET + '-rotated')), async (base) => {
            assert.strictEqual((await call(base, '203.0.113.7')).status, 200);
        });

        // В базу не ушли ни адреса, ни имена.
        const seen = allParams(state);
        assert.ok(!seen.includes('203.0.113'), 'IP не должен попадать в запросы');
        for (const k of state.counters.keys()) assert.match(k, /^register:[A-Za-z0-9_-]{43}$/);
    });

    await test('лимитер: skip пропускает запрос без обращения к базе', async () => {
        const { pool, state } = makeFakePool();
        const limiter = createPgLimits({ pool, secret: SECRET }).rateLimiter('join-ip', {
            windowMs: HOUR, max: 1, skip: (req) => req.headers['x-skip'] === '1', keyGenerator: () => 'k',
        });
        await withApp(limitedApp(limiter), async (base) => {
            for (let i = 0; i < 3; i++) assert.strictEqual((await fetch(`${base}/ping`, { headers: { 'x-skip': '1' } })).status, 200);
        });
        assert.strictEqual(state.calls.length, 0);
    });

    await test('сбой хранилища: 503 {code:"busy"}, обработчик не вызывается, после восстановления лимит работает', async () => {
        const { pool, control } = makeFakePool();
        const logs = [];
        const errors = [];
        const limiter = createPgLimits({
            pool, secret: SECRET,
            hooks: { storeError: (s) => errors.push(s) },
            report: createErrorReporter({ log: (context, err) => logError(context, err, { log: (line) => logs.push(line) }), intervalMs: 10_000, now: () => 0 }),
        }).rateLimiter('register', { windowMs: HOUR, max: 1, keyGenerator: () => 'k' });
        let handled = 0;
        await withApp(limitedApp(limiter, () => handled++), async (base) => {
            const err = new Error('relation "rl_counters" does not exist');
            err.code = '42P01';
            control.failure = err;
            for (let i = 0; i < 3; i++) {
                const res = await fetch(`${base}/ping`);
                assert.strictEqual(res.status, 503);
                assert.strictEqual(res.headers.get('retry-after'), '5');
                assert.deepStrictEqual(await res.json(), { success: false, code: 'busy', message: BUSY_RESPONSE.message });
            }
            assert.strictEqual(handled, 0, 'лимит закрывается: запрос не выполнен');
            control.failure = null;
            assert.strictEqual((await fetch(`${base}/ping`)).status, 200);
            assert.strictEqual((await fetch(`${base}/ping`)).status, 429);
        });
        assert.deepStrictEqual(errors, ['register', 'register', 'register']);
        assert.strictEqual(logs.length, 1, 'лог не засоряется повторами: ' + logs.join(' | '));
        assert.match(logs[0], /relation "rl_counters" does not exist \(code=42P01\)/);
        assert.ok(!/register:[A-Za-z0-9_-]{43}/.test(logs[0]), 'ключ клиента в лог не попадает');
    });

    await test('сбой хранилища: зависший запрос отвечает 503 по таймауту', async () => {
        const { pool, control } = makeFakePool();
        control.hang = true;
        const limiter = createPgLimits({ pool, secret: SECRET, timeoutMs: 40, report: () => {} })
            .rateLimiter('register', { windowMs: HOUR, max: 5, keyGenerator: () => 'k' });
        await withApp(limitedApp(limiter), async (base) => {
            const started = Date.now();
            const res = await fetch(`${base}/ping`);
            assert.strictEqual(res.status, 503);
            assert.strictEqual((await res.json()).code, 'busy');
            assert.ok(Date.now() - started < 2000);
        });
    });

    await test('ошибка вне хранилища проходит как обычная (не превращается в busy)', async () => {
        const { pool } = makeFakePool();
        const limiter = createPgLimits({ pool, secret: SECRET }).rateLimiter('x', {
            windowMs: HOUR, max: 5, keyGenerator: () => { throw new Error('boom'); },
        });
        const app = limitedApp(limiter);
        app.use((err, req, res, next) => res.status(500).json({ boom: err.message }));
        await withApp(app, async (base) => {
            const res = await fetch(`${base}/ping`);
            assert.strictEqual(res.status, 500);
            assert.deepStrictEqual(await res.json(), { boom: 'boom' });
        });
    });

    // ------------------------------------------------------ скользящее окно
    await test('скользящее окно: лимиты вызывающего и пары, отказ ничего не тратит, слот освобождается через час', async () => {
        const { pool, state, clock } = makeFakePool();
        const limiter = createPgLimits({ pool, secret: SECRET }).slidingLimiter('bundle');
        const rules = (caller, target) => [
            { key: `caller:${caller}`, max: 60 },
            { key: `pair:${caller}:${target}`, max: 5 },
        ];
        for (let i = 0; i < 5; i++) {
            const res = await limiter.tryConsume('1', rules(1, 2));
            assert.deepStrictEqual(res, { ok: true, waitMs: [0, 0] }, 'запрос ' + (i + 1));
            clock.now += 1000;
        }
        const denied = await limiter.tryConsume('1', rules(1, 2));
        assert.strictEqual(denied.ok, false);
        assert.strictEqual(denied.waitMs[0], 0, 'лимит вызывающего не исчерпан');
        assert.ok(denied.waitMs[1] > 50 * MINUTE && denied.waitMs[1] <= HOUR, 'ждать до выхода старой корзины из окна: ' + denied.waitMs[1]);

        const callerBuckets = () => [...state.buckets.values()].map(m => [...m.values()].reduce((a, b) => a + b, 0));
        assert.deepStrictEqual(callerBuckets().sort(), [5, 5], 'отказанный запрос не потратил квоту ни одного правила');

        // Другая цель — своя пара, общий счёт вызывающего.
        assert.strictEqual((await limiter.tryConsume('1', rules(1, 3))).ok, true);
        assert.strictEqual((await limiter.tryConsume('2', rules(2, 1))).ok, true, 'другой вызывающий');

        // Через час корзина первой минуты выходит из окна.
        clock.now += HOUR;
        assert.strictEqual((await limiter.tryConsume('1', rules(1, 2))).ok, true);

        // Запросы: блокировка в своём пространстве, ключи — только HMAC.
        assert.ok(state.locks.length > 0);
        for (const [namespace, lock] of state.locks) {
            assert.strictEqual(namespace, 0x4e524c31);
            assert.ok(Number.isInteger(lock) && lock >= -(2 ** 31) && lock < 2 ** 31);
        }
        assert.ok(!/caller:|pair:/.test(allParams(state)), 'ключи правил не лежат открыто');
        assert.ok(state.calls.some(c => /statement_timeout = 3000/.test(c.text)));
        assert.ok(state.released.every(arg => arg === undefined), 'исправные соединения возвращаются в пул как обычно');
    });

    await test('скользящее окно: обе квоты исчерпаны — ждать нужно по каждой', async () => {
        const { pool } = makeFakePool();
        const limiter = createPgLimits({ pool, secret: SECRET }).slidingLimiter('bundle');
        const rules = [{ key: 'a', max: 1 }, { key: 'b', max: 1 }];
        assert.strictEqual((await limiter.tryConsume('1', rules)).ok, true);
        const denied = await limiter.tryConsume('1', rules);
        assert.strictEqual(denied.ok, false);
        assert.ok(denied.waitMs[0] >= 1000 && denied.waitMs[1] >= 1000);
    });

    await test('скользящее окно: ошибка — ROLLBACK и LimitStoreError; неудавшийся ROLLBACK уничтожает соединение', async () => {
        const { pool, state, control } = makeFakePool();
        const errors = [];
        const limiter = createPgLimits({ pool, secret: SECRET, hooks: { storeError: (s) => errors.push(s) }, report: () => {} }).slidingLimiter('bundle');
        const rules = [{ key: 'a', max: 5 }];
        control.failure = new Error('база недоступна');
        await assert.rejects(limiter.tryConsume('1', rules), (err) => err instanceof LimitStoreError && err.code === 'LIMIT_STORE_UNAVAILABLE');
        assert.strictEqual(state.rollbacks, 1);
        assert.deepStrictEqual(state.released, [undefined]);
        control.rollbackFails = true;
        await assert.rejects(limiter.tryConsume('1', rules), LimitStoreError);
        assert.deepStrictEqual(state.released, [undefined, true]);
        assert.deepStrictEqual(errors, ['bundle', 'bundle']);
        // Исчерпанный пул: «занято» быстро, не ждём драйвер.
        control.failure = null;
        control.connectHangs = true;
        const quick = createPgLimits({ pool, secret: SECRET, timeoutMs: 30, report: () => {} }).slidingLimiter('bundle');
        await assert.rejects(quick.tryConsume('1', rules), LimitStoreError);
    });

    await test('скользящее окно: неверные параметры', () => {
        const { pool } = makeFakePool();
        const keys = createLimitKeys(SECRET);
        assert.throws(() => createPgSlidingLimiter({ pool, keys, scope: 'Bad!' }), TypeError);
        assert.throws(() => createPgSlidingLimiter({ pool, keys, scope: 'x', windowMs: 90_000 }), RangeError);
        assert.throws(() => createPgSlidingLimiter({ pool, keys, scope: 'x', windowMs: 2 * HOUR }), RangeError);
        const limiter = createPgSlidingLimiter({ pool, keys, scope: 'x' });
        return Promise.all([
            assert.rejects(limiter.tryConsume('1', []), TypeError),
            assert.rejects(limiter.tryConsume('1', [{ key: 'a', max: 1 }, { key: 'a', max: 2 }]), TypeError),
        ]);
    });

    // ------------------------------------------------------- PoW одноразово
    await test('PoW: решение принимается один раз; неверный nonce задачу не сжигает', async () => {
        const { pool, state } = makeFakePool();
        const pow = loadFreshPow();
        pow.setSecret(SECRET);
        const store = createPgLimits({ pool, secret: SECRET }).powUsedStore();
        const { token, difficulty } = pow.createChallenge('register-anon');
        const nonce = String(solve(token, difficulty));

        let wrong = 0;
        for (; String(wrong) === nonce; wrong++);
        assert.strictEqual(await pow.consumeSolution({ token, nonce: String(wrong) }, 'register-anon', store), 'invalid');
        assert.strictEqual(state.pow.size, 0, 'неверный nonce ничего не записал');
        assert.strictEqual(await pow.consumeSolution({ token, nonce }, 'register-anon', store), 'ok');
        assert.strictEqual(await pow.consumeSolution({ token, nonce }, 'register-anon', store), 'replayed');
        assert.strictEqual(await pow.consumeSolution({ token, nonce }, 'register-anon', store), 'replayed');
        assert.strictEqual(await pow.consumeSolution({ token, nonce }, 'login', store), 'invalid', 'чужое назначение');

        const [hex, expiresAt] = [...state.pow][0];
        assert.strictEqual(hex, crypto.createHash('sha256').update(token, 'utf8').digest('hex'), 'в базе — SHA-256 токена');
        assert.strictEqual(expiresAt, JSON.parse(Buffer.from(token.split('.')[0], 'base64url')).e);
    });

    await test('PoW: задача, выданная до рестарта (тот же SESSION_SECRET), принимается; другим секретом — нет; одноразовость общая', async () => {
        const { pool } = makeFakePool();
        const store = createPgLimits({ pool, secret: SECRET }).powUsedStore();
        const before = loadFreshPow();
        before.setSecret(SECRET);
        const { token, difficulty } = before.createChallenge('register-anon');
        const solution = { token, nonce: String(solve(token, difficulty)) };

        const afterRestart = loadFreshPow();
        afterRestart.setSecret(SECRET);
        assert.strictEqual(await afterRestart.consumeSolution(solution, 'register-anon', store), 'ok');
        // «Реплика» с тем же секретом видит то же использование.
        const replica = loadFreshPow();
        replica.setSecret(SECRET);
        assert.strictEqual(await replica.consumeSolution(solution, 'register-anon', store), 'replayed');

        const rotated = loadFreshPow();
        rotated.setSecret(SECRET + '-rotated');
        const fresh = before.createChallenge('register-anon');
        assert.strictEqual(
            await rotated.consumeSolution({ token: fresh.token, nonce: String(solve(fresh.token, fresh.difficulty)) }, 'register-anon', store),
            'invalid',
            'смена SESSION_SECRET делает выданные задачи недействительными'
        );
    });

    await test('PoW: сбой хранилища — ошибка (не «ok»), задача остаётся несожжённой', async () => {
        const { pool, state, control } = makeFakePool();
        const errors = [];
        const store = createPgLimits({ pool, secret: SECRET, hooks: { storeError: (s) => errors.push(s) }, report: () => {} }).powUsedStore();
        const pow = loadFreshPow();
        pow.setSecret(SECRET);
        const { token, difficulty } = pow.createChallenge('register-anon');
        const solution = { token, nonce: String(solve(token, difficulty)) };
        control.failure = new Error('нет прав на таблицу pow_used');
        await assert.rejects(pow.consumeSolution(solution, 'register-anon', store), LimitStoreError);
        assert.deepStrictEqual(errors, ['pow']);
        assert.strictEqual(state.pow.size, 0);
        control.failure = null;
        assert.strictEqual(await pow.consumeSolution(solution, 'register-anon', store), 'ok');
        await assert.rejects(pow.consumeSolution(solution, 'register-anon', {}), TypeError);
    });

    await test('PoW: checkSolution не имеет побочных эффектов и не знает про повторы', () => {
        const pow = loadFreshPow();
        pow.setSecret(SECRET);
        const { token, difficulty } = pow.createChallenge('register-anon');
        const solution = { token, nonce: String(solve(token, difficulty)) };
        const first = pow.checkSolution(solution, 'register-anon');
        assert.strictEqual(first.token, token);
        assert.ok(first.expiresAt > Date.now());
        assert.deepStrictEqual(pow.checkSolution(solution, 'register-anon'), first);
        assert.strictEqual(pow.checkSolution({ token, nonce: 'x' }, 'register-anon'), null);
        assert.strictEqual(pow.checkSolution(null, 'register-anon'), null);
        assert.strictEqual(pow._internal.usedCount(), 0);
    });

    // ---------------------------------------------------------------- уборка
    await test('уборка: убирает просроченные счётчики, корзины старше двух часов и использованные токены с запасом', async () => {
        const { pool, state, clock } = makeFakePool();
        state.counters.set('old', { hits: 1, resetAt: clock.now - 1 });
        state.counters.set('live', { hits: 1, resetAt: clock.now + 1000 });
        const minute = Math.floor(clock.now / MINUTE) * MINUTE;
        state.buckets.set('aa', new Map([[minute - 3 * HOUR, 1], [minute - HOUR, 2], [minute, 1]]));
        state.pow.set('expired', clock.now - 2 * MINUTE);
        state.pow.set('just-expired', clock.now - 10 * 1000);
        state.pow.set('live', clock.now + MINUTE);
        const removed = await purgeExpiredLimits(pool);
        assert.deepStrictEqual(removed, { counters: 1, buckets: 1, pow: 1 });
        assert.deepStrictEqual([...state.counters.keys()], ['live']);
        assert.deepStrictEqual([...state.buckets.get('aa').keys()].sort((a, b) => a - b), [minute - HOUR, minute]);
        assert.deepStrictEqual([...state.pow.keys()].sort(), ['just-expired', 'live']);
    });

    await test('задача уборки зарегистрирована в JOB_MODULES: раз в минуту, под блокировкой, ускоряется тестовой ручкой', () => {
        assert.ok(JOB_MODULES.some(mod => typeof mod.jobs === 'function' && mod.jobs({ pool: {} }).some(job => job.name === 'purgeExpiredLimits')));
        const [job] = jobs({ pool: {} });
        assert.strictEqual(job.intervalMs, 60_000);
        assert.strictEqual(job.maintenance, true);
        assert.notStrictEqual(job.exclusive, false);
    });

    // ---------------------------------------------------- lib/e2ee-keys.js
    await test('e2ee-keys: bundleLimiter получает правила вызывающего и пары; отказ — 429, сбой — 503 busy', async () => {
        const keyDb = makeFakeKeyDb();
        const dbGet = async (sql, params) => (keyDb.isKeySql(sql) ? keyDb.dbGet(sql, params) : { ok: 1 });
        const dbAll = async (sql, params) => (keyDb.isKeySql(sql) ? keyDb.dbAll(sql, params) : []);
        const handlers = {};
        const app = { get: (p, ...h) => { handlers[p] = h; }, put() {}, post() {}, delete() {} };
        const seen = [];
        let mode = 'allow';
        registerE2eeKeyRoutes(app, {
            dbGet, dbAll,
            bundleLimiter: {
                async tryConsume(lockKey, rules) {
                    seen.push({ lockKey, rules });
                    if (mode === 'fail') throw new LimitStoreError('нет базы', null);
                    return mode === 'deny' ? { ok: false, waitMs: [0, 90_000] } : { ok: true, waitMs: [0, 0] };
                },
            },
        });
        const run = async () => {
            const res = { statusCode: 200, body: null, headers: {}, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; }, set(n, v) { this.headers[n.toLowerCase()] = v; return this; } };
            const req = { session: { userId: 1 }, params: { targetUserId: '2' }, query: {}, body: {} };
            for (const h of handlers['/api/keys/bundle/:targetUserId']) { if (res.body === null) await h(req, res, () => {}); }
            return res;
        };
        assert.notStrictEqual((await run()).statusCode, 429);
        assert.deepStrictEqual(seen[0], {
            lockKey: '1',
            rules: [{ key: 'caller:1', max: 60 }, { key: 'pair:1:2', max: 5 }],
        });
        mode = 'deny';
        const denied = await run();
        assert.strictEqual(denied.statusCode, 429);
        assert.strictEqual(denied.headers['retry-after'], '90');
        assert.match(denied.body.message, /этого пользователя/);
        mode = 'fail';
        const busy = await run();
        assert.strictEqual(busy.statusCode, 503);
        assert.deepStrictEqual(busy.body, { success: false, code: 'busy', message: BUSY_RESPONSE.message });
    });

    await test('хранилище PoW: createPgPowUsedStore без hooks и report не падает на ошибке', async () => {
        const { pool, control } = makeFakePool();
        control.failure = new Error('x');
        const quiet = console.error;
        console.error = () => {};
        try {
            await assert.rejects(createPgPowUsedStore({ pool }).consume(Buffer.alloc(32), Date.now() + 1000), LimitStoreError);
        } finally {
            console.error = quiet;
        }
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
