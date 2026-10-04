'use strict';
// Реестр фоновых задач (lib/jobs/index.js): расписание, тестовая ручка
// NYXO_TEST_MAINTENANCE_MS, «[Test] maintenance tick <n>», exclusive и
// обычные задачи — с поддельными таймерами и runExclusive.
// Запуск: node test/jobs.test.js

const assert = require('assert');
const { createJobScheduler, registerJobModules, JOB_MODULES } = require('../lib/jobs');

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

// Таймеры, которые ничего не ждут: запоминают, что и когда запланировано.
function fakeTimers() {
    const scheduled = [];
    let id = 0;
    const add = (kind) => (fn, ms) => { const h = ++id; scheduled.push({ kind, fn, ms, h, cleared: false }); return h; };
    const clear = (h) => { const s = scheduled.find(x => x.h === h); if (s) s.cleared = true; };
    return {
        scheduled,
        timers: {
            setTimeout: add('timeout'), setInterval: add('interval'), setImmediate: (fn) => add('immediate')(fn, 0),
            clearTimeout: clear, clearInterval: clear, clearImmediate: clear,
        },
    };
}

function standardJobs(scheduler, run = async () => {}) {
    scheduler.register({ name: 'purgeAnons', run, firstDelayMs: 60000, intervalMs: 300000, maintenance: true, testTick: true });
    scheduler.register({ name: 'touchSockets', run, intervalMs: 300000, exclusive: false, maintenance: true });
    scheduler.register({ name: 'purgeLegacy', run, firstDelayMs: 0 });
    scheduler.register({ name: 'tempFiles', run, intervalMs: 3600000, exclusive: false });
}

const plan = (scheduled) => scheduled.map(s => `${s.kind}:${s.ms}`).sort();

async function main() {
    console.log('Jobs registry tests\n');

    await test('без тестовой ручки — расписание как задано', () => {
        const { scheduled, timers } = fakeTimers();
        const jobs = createJobScheduler({ runExclusive: async () => true, timers, log: () => {} });
        standardJobs(jobs);
        jobs.start();
        assert.deepStrictEqual(plan(scheduled), [
            'immediate:0', 'interval:300000', 'interval:300000', 'interval:3600000', 'timeout:60000',
        ].sort());
    });

    await test('NYXO_TEST_MAINTENANCE_MS — задачи maintenance каждые N мс, остальные как были', () => {
        const { scheduled, timers } = fakeTimers();
        const logs = [];
        const jobs = createJobScheduler({ runExclusive: async () => true, maintenanceMs: 300, timers, log: (l) => logs.push(l) });
        standardJobs(jobs);
        jobs.start();
        assert.deepStrictEqual(plan(scheduled), ['immediate:0', 'interval:300', 'interval:300', 'interval:3600000', 'timeout:300'].sort());
        assert.deepStrictEqual(jobs.schedule('purgeAnons'), { first: 300, every: 300 });
        assert.deepStrictEqual(jobs.schedule('touchSockets'), { first: null, every: 300 });
        assert.ok(logs.some(l => /NYXO_TEST_MAINTENANCE_MS=300/.test(l)));
    });

    await test('exclusive-задача — через runExclusive(name, run); tick только в тестовом режиме и только за проход', async () => {
        const calls = [];
        const answers = [true, false, true];
        const runExclusive = async (name, fn) => { calls.push(name); assert.strictEqual(typeof fn, 'function'); return answers.shift(); };
        const logs = [];
        const jobs = createJobScheduler({ runExclusive, maintenanceMs: 300, timers: fakeTimers().timers, log: (l) => logs.push(l) });
        standardJobs(jobs);
        assert.strictEqual(await jobs.runJob('purgeAnons'), true);
        assert.strictEqual(await jobs.runJob('purgeAnons'), false);   // пропущен: блокировку держит другой
        assert.strictEqual(await jobs.runJob('purgeAnons'), true);
        assert.deepStrictEqual(calls, ['purgeAnons', 'purgeAnons', 'purgeAnons']);
        assert.deepStrictEqual(logs, ['[Test] maintenance tick 1', '[Test] maintenance tick 2']);

        const prodLogs = [];
        const prod = createJobScheduler({ runExclusive: async () => true, timers: fakeTimers().timers, log: (l) => prodLogs.push(l) });
        standardJobs(prod);
        await prod.runJob('purgeAnons');
        assert.deepStrictEqual(prodLogs, []);
    });

    await test('обычная задача выполняется без блокировки; её ошибка — в отчёт, не наружу', async () => {
        let lockCalls = 0;
        const reports = [];
        const jobs = createJobScheduler({
            runExclusive: async () => { lockCalls++; return true; },
            timers: fakeTimers().timers, log: () => {}, report: (ctx, err) => reports.push([ctx, err.message]),
        });
        let ran = 0;
        jobs.register({ name: 'local', run: () => { ran++; }, intervalMs: 1000, exclusive: false });
        jobs.register({ name: 'broken', run: async () => { throw new Error('сбой'); }, intervalMs: 1000, exclusive: false });
        assert.strictEqual(await jobs.runJob('local'), true);
        assert.strictEqual(await jobs.runJob('broken'), false);
        assert.strictEqual(ran, 1);
        assert.strictEqual(lockCalls, 0);
        assert.deepStrictEqual(reports, [['[Jobs] broken', 'сбой']]);
    });

    await test('таймер запускает задачу; stop() снимает все таймеры', async () => {
        const { scheduled, timers } = fakeTimers();
        let ran = 0;
        const jobs = createJobScheduler({ runExclusive: async (name, fn) => { await fn(); return true; }, timers, log: () => {} });
        jobs.register({ name: 'a', run: async () => { ran++; }, firstDelayMs: 10, intervalMs: 20 });
        jobs.start();
        scheduled[0].fn();
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ran, 1);
        jobs.stop();
        assert.ok(scheduled.every(s => s.cleared));
    });

    await test('проверки регистрации: имя, run, повтор, задержки, exclusive без runExclusive, после start', () => {
        const jobs = createJobScheduler({ runExclusive: async () => true, timers: fakeTimers().timers, log: () => {} });
        assert.throws(() => jobs.register({ run: () => {} }), /имени/);
        assert.throws(() => jobs.register({ name: 'x' }), /нет функции run/);
        jobs.register({ name: 'x', run: () => {}, intervalMs: 5 });
        assert.throws(() => jobs.register({ name: 'x', run: () => {} }), /уже зарегистрирована/);
        assert.throws(() => jobs.register({ name: 'y', run: () => {}, intervalMs: -1 }), RangeError);
        assert.throws(() => jobs.register({ name: 'z', run: () => {}, firstDelayMs: 1.5 }), RangeError);
        const noLock = createJobScheduler({ timers: fakeTimers().timers });
        assert.throws(() => noLock.register({ name: 'e', run: () => {} }), /runExclusive/);
        noLock.register({ name: 'local', run: () => {}, exclusive: false });
        jobs.start();
        assert.throws(() => jobs.register({ name: 'late', run: () => {} }), /после start/);
        assert.throws(() => jobs.start(), /уже запущен/);
        assert.throws(() => createJobScheduler({ maintenanceMs: 0 }), RangeError);
    });

    await test('задачи lib-модулей регистрируются из JOB_MODULES (пока пустого)', () => {
        assert.ok(Array.isArray(JOB_MODULES));
        const jobs = createJobScheduler({ runExclusive: async () => true, timers: fakeTimers().timers, log: () => {} });
        const ctx = { pool: 'pool' };
        registerJobModules(jobs, ctx, [{ jobs: (c) => [{ name: 'janitor', run: () => {}, intervalMs: 60000, ctxOk: c === ctx }] }]);
        assert.deepStrictEqual(jobs.names(), ['janitor']);
        registerJobModules(jobs, ctx);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
