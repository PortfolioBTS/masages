'use strict';
// Лимиты против массовых аккаунтов и разрастания хранилища (W7 R1 п.3): разбор окружения,
// давление регистраций -> сложность PoW, минимальная сложность решения, суточный объём
// текста, порог свободного места. Поведение SQL и маршрутов проверяют сквозные тесты.
// Запуск: node test/account-limits.test.js

// База сложности PoW - до загрузки lib/pow.js: решать задачи в тесте дёшево.
process.env.POW_DIFFICULTY = '8';

const assert = require('assert');
const crypto = require('crypto');
const { resolveAccountLimits, DEFAULTS } = require('../lib/account-limits');
const { createRegistrationPressure, MAX_EXTRA_BITS } = require('../lib/registration-pressure');
const pow = require('../lib/pow');
const { createTextQuota, RESERVE_SQL } = require('../lib/text-quota');
const { LimitStoreError } = require('../lib/pg-limits');
const { createDiskGuard } = require('../lib/disk-space');

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

function solve(token, difficulty) {
    for (let nonce = 0; ; nonce++) {
        const digest = crypto.createHash('sha256').update(`${token}:${nonce}`, 'utf8').digest();
        let bits = 0;
        for (const byte of digest) {
            if (byte === 0) { bits += 8; continue; }
            bits += Math.clz32(byte) - 24;
            break;
        }
        if (bits >= difficulty) return String(nonce);
    }
}

async function main() {
    await test('умолчания лимитов', () => {
        assert.deepStrictEqual({ ...resolveAccountLimits({}) }, {
            registerGlobalPerMin: 120, registerPacePerMin: 20, textQuotaBytesPerDay: 20 * 1024 * 1024,
            roomsPerUserMax: 50, uploadMinFreeBytes: 256 * 1024 * 1024,
        });
        assert.strictEqual(DEFAULTS.ROOMS_PER_USER_MAX, 50);
    });

    await test('значения из окружения; мусор, ноль, отрицательные и экспонента дают умолчание', () => {
        const limits = resolveAccountLimits({
            REGISTER_GLOBAL_PER_MIN: '7', REGISTER_PACE_PER_MIN: '3', TEXT_QUOTA_MB_PER_DAY: '0.5',
            ROOMS_PER_USER_MAX: '4', UPLOAD_MIN_FREE_MB: '1024',
        });
        assert.deepStrictEqual({ ...limits }, {
            registerGlobalPerMin: 7, registerPacePerMin: 3, textQuotaBytesPerDay: 524288,
            roomsPerUserMax: 4, uploadMinFreeBytes: 1024 * 1024 * 1024,
        });
        for (const bad of ['', 'abc', '0', '-5', '1e3', '0x10', ' ', '1.5']) {
            const l = resolveAccountLimits({ REGISTER_GLOBAL_PER_MIN: bad, ROOMS_PER_USER_MAX: bad });
            assert.strictEqual(l.registerGlobalPerMin, 120, `REGISTER_GLOBAL_PER_MIN=${JSON.stringify(bad)}`);
            assert.strictEqual(l.roomsPerUserMax, 50, `ROOMS_PER_USER_MAX=${JSON.stringify(bad)}`);
        }
        for (const bad of ['', 'abc', '0', '-5', '1e3', '0.0']) {
            assert.strictEqual(resolveAccountLimits({ TEXT_QUOTA_MB_PER_DAY: bad }).textQuotaBytesPerDay, 20 * 1024 * 1024, bad);
        }
    });

    await test('суточный объём текста не превышает INT счётчика (2^31-1 байт)', () => {
        assert.strictEqual(resolveAccountLimits({ TEXT_QUOTA_MB_PER_DAY: '999999' }).textQuotaBytesPerDay, 2147483647);
    });

    await test('давление регистраций: ниже темпа 0 бит, на темпе 1, каждое удвоение - ещё бит, потолок +6', () => {
        let now = 1000000;
        const pressure = createRegistrationPressure({ pace: 4, now: () => now });
        const bitsAfter = (n) => { while (pressure.count() < n) pressure.note(); return pressure.extraBits(); };
        assert.strictEqual(pressure.extraBits(), 0);
        assert.strictEqual(bitsAfter(3), 0);
        assert.strictEqual(bitsAfter(4), 1);
        assert.strictEqual(bitsAfter(7), 1);
        assert.strictEqual(bitsAfter(8), 2);
        assert.strictEqual(bitsAfter(16), 3);
        assert.strictEqual(bitsAfter(10000), MAX_EXTRA_BITS);
    });

    await test('давление регистраций: окно в минуту - через минуту после всплеска сложность снова базовая', () => {
        let now = 5000;
        const pressure = createRegistrationPressure({ pace: 2, now: () => now });
        for (let i = 0; i < 8; i++) pressure.note();
        assert.strictEqual(pressure.extraBits(), 3);
        now += 59999;
        assert.strictEqual(pressure.extraBits(), 3);
        now += 2;
        assert.strictEqual(pressure.count(), 0);
        assert.strictEqual(pressure.extraBits(), 0);
    });

    await test('PoW: сложность задачи можно поднять, но не ниже базовой и не выше MAX_DIFFICULTY', () => {
        assert.strictEqual(pow.BASE_DIFFICULTY, 8);
        assert.strictEqual(pow.createChallenge('register-anon').difficulty, 8);
        assert.strictEqual(pow.createChallenge('register-anon', { difficulty: 11 }).difficulty, 11);
        assert.strictEqual(pow.createChallenge('register-anon', { difficulty: 3 }).difficulty, 8);
        assert.strictEqual(pow.createChallenge('register-anon', { difficulty: 99 }).difficulty, pow.MAX_DIFFICULTY);
        assert.strictEqual(pow.createChallenge('register-anon', { difficulty: '12' }).difficulty, 8, 'нечисло игнорируется');
    });

    await test('PoW: решение задачи полегче минимальной сложности не принимается (задача, выданная до наплыва)', () => {
        const easy = pow.createChallenge('register-anon');
        const solution = { token: easy.token, nonce: solve(easy.token, easy.difficulty) };
        assert.ok(pow.checkSolution(solution, 'register-anon'), 'без минимума принимается');
        assert.ok(pow.checkSolution(solution, 'register-anon', { minDifficulty: 8 }));
        assert.strictEqual(pow.checkSolution(solution, 'register-anon', { minDifficulty: 9 }), null);
        const hard = pow.createChallenge('register-anon', { difficulty: 10 });
        const hardSolution = { token: hard.token, nonce: solve(hard.token, hard.difficulty) };
        assert.ok(pow.checkSolution(hardSolution, 'register-anon', { minDifficulty: 10 }));
    });

    await test('PoW: consumeSolution с minDifficulty не сжигает задачу, отвергнутую по сложности', async () => {
        const seen = [];
        const store = { consume: async (hash) => { seen.push(hash); return true; } };
        const easy = pow.createChallenge('register-anon');
        const solution = { token: easy.token, nonce: solve(easy.token, easy.difficulty) };
        assert.strictEqual(await pow.consumeSolution(solution, 'register-anon', store, { minDifficulty: 12 }), 'invalid');
        assert.strictEqual(seen.length, 0, 'задача осталась несожжённой');
        assert.strictEqual(await pow.consumeSolution(solution, 'register-anon', store, { minDifficulty: 8 }), 'ok');
        assert.strictEqual(seen.length, 1);
    });

    await test('текст: резерв пишет в rl_counters под HMAC-ключом без id, учитывает байты и лимит', async () => {
        const calls = [];
        let rows = [{ hits: 10 }];
        const pool = { query: async (sql, params) => { calls.push({ sql, params }); return { rows }; } };
        const quota = createTextQuota({ pool, secret: 'x'.repeat(40), limitBytes: 1000 });
        assert.strictEqual(await quota.reserve(42, 10), true);
        assert.strictEqual(calls[0].sql, RESERVE_SQL);
        assert.match(calls[0].params[0], /^text-quota:[A-Za-z0-9_-]{43}$/, 'ключ - HMAC, а не id');
        assert.ok(!calls[0].params[0].includes('42'));
        assert.deepStrictEqual(calls[0].params.slice(1), [10, 1000]);
        const other = createTextQuota({ pool, secret: 'x'.repeat(40), limitBytes: 1000 });
        await other.reserve(43, 10);
        assert.notStrictEqual(calls[1].params[0], calls[0].params[0], 'у разных аккаунтов разные ключи');
        rows = [];
        assert.strictEqual(await quota.reserve(42, 10), false, 'нет строки в RETURNING - лимит исчерпан');
        const before = calls.length;
        assert.strictEqual(await quota.reserve(42, 1001), false, 'одно сообщение больше суточного объёма');
        assert.strictEqual(await quota.reserve(42, 0), false);
        assert.strictEqual(calls.length, before, 'без запроса к базе');
        assert.match(RESERVE_SQL, /WHERE \(CASE WHEN c\.reset_at <= now\(\)/);
    });

    await test('текст: сбой базы - LimitStoreError (503 busy), а не пропуск лимита', async () => {
        const pool = { query: async () => { throw new Error('connection refused'); } };
        const quota = createTextQuota({ pool, secret: 'y'.repeat(40), limitBytes: 1000 });
        await assert.rejects(quota.reserve(1, 5), (err) => err instanceof LimitStoreError);
    });

    await test('свободное место: порог, кэш statfs, неизвестное место не блокирует', async () => {
        let now = 0;
        let calls = 0;
        let free = 300 * 1024 * 1024;
        const statfs = async () => { calls++; return { bavail: free / 4096, bsize: 4096 }; };
        const guard = createDiskGuard({ dir: '/data', minFreeBytes: 256 * 1024 * 1024, ttlMs: 1000, statfs, now: () => now });
        assert.strictEqual(await guard.hasRoom(), true);
        assert.strictEqual(await guard.hasRoom(40 * 1024 * 1024), true);
        assert.strictEqual(await guard.hasRoom(50 * 1024 * 1024), false, 'с учётом размера файла места не хватает');
        free = 100 * 1024 * 1024;
        assert.strictEqual(await guard.hasRoom(), true, 'внутри TTL берётся кэш');
        assert.strictEqual(calls, 1);
        now += 1001;
        assert.strictEqual(await guard.hasRoom(), false, 'после TTL статистика обновилась');
        assert.strictEqual(calls, 2);

        const broken = createDiskGuard({ dir: '/data', minFreeBytes: 1, statfs: async () => { throw new Error('ENOSYS'); } });
        assert.strictEqual(await broken.hasRoom(), true);
        assert.strictEqual(await broken.hasRoom(), true);
        const off = createDiskGuard({ dir: '/data', minFreeBytes: 0, statfs: async () => { throw new Error('не должен вызываться'); } });
        assert.strictEqual(await off.hasRoom(), true);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exit(1); });
