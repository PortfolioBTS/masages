'use strict';
// Плановое обслуживание ключей E2EE в public/script.js: init() раз в 6 часов и
// при возвращении на вкладку, если прошло больше 6 часов. script.js — большой
// браузерный скрипт с DOM на верхнем уровне, поэтому исполняется только блок
// между метками «>>> e2ee-maintenance» и «<<< e2ee-maintenance» в песочнице с
// подставленными глобалами (currentUser, e2eeState, getE2eeClient, таймеры).
// Запуск: node test/e2ee-maintenance.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { readClientScript } = require('./client-script-source');
const vm = require('vm');

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

const source = readClientScript();
const block = (() => {
    const start = source.indexOf('// >>> e2ee-maintenance');
    const end = source.indexOf('// <<< e2ee-maintenance');
    assert.ok(start > 0 && end > start, 'в script.js нет блока e2ee-maintenance');
    return source.slice(start, end);
})();

const HOUR = 60 * 60 * 1000;

// Песочница: часы и таймеры подставлены, клиент считает вызовы init().
function makeSandbox() {
    const state = { now: 1700000000000, inits: 0, initError: null, intervals: [], warnings: [] };
    const client = {
        init: async () => {
            state.inits++;
            if (state.initError) throw state.initError;
            return {};
        },
    };
    const context = {
        currentUser: { id: 1 },
        e2eeState: 'ready',
        getE2eeClient: () => client,
        Date: { now: () => state.now },
        setInterval: (fn, ms) => { const timer = { fn, ms, cleared: false }; state.intervals.push(timer); return timer; },
        clearInterval: (timer) => { if (timer) timer.cleared = true; },
        console: { warn: (...args) => state.warnings.push(args.join(' ')) },
    };
    vm.createContext(context);
    vm.runInContext(block + '\nthis.api = { startE2eeMaintenance, stopE2eeMaintenance, maintainE2eeKeys, E2EE_MAINTENANCE_MS, E2EE_MAINTENANCE_TICK_MS };', context);
    return { state, context, api: context.api };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

(async () => {
    console.log('E2EE key maintenance (script.js)\n');

    await test('the interval is 6 hours; a check runs every 30 minutes', () => {
        const { api } = makeSandbox();
        assert.strictEqual(api.E2EE_MAINTENANCE_MS, 6 * HOUR);
        assert.strictEqual(api.E2EE_MAINTENANCE_TICK_MS, 30 * 60 * 1000);
    });

    await test('nothing happens in the first 6 hours (the initial init() belongs to the login flow)', async () => {
        const { state, api } = makeSandbox();
        api.startE2eeMaintenance();
        state.now += 5 * HOUR + 59 * 60 * 1000;
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 0);
    });

    await test('after 6 hours init() runs once; the next one only 6 hours after that', async () => {
        const { state, api } = makeSandbox();
        api.startE2eeMaintenance();
        state.now += 6 * HOUR;
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 1);
        state.now += 5 * HOUR;
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 1, 'too early');
        state.now += HOUR;
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 2);
    });

    await test('the timer tick and a return to the tab share one function: repeated calls do not stack runs', async () => {
        const { state, api } = makeSandbox();
        api.startE2eeMaintenance();
        state.now += 7 * HOUR;
        api.maintainE2eeKeys();
        api.maintainE2eeKeys(); // visibilitychange в тот же момент
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 1, 'a run in progress blocks the others');
    });

    await test('the timer is started once, replaced on restart and cleared on stop', () => {
        const { state, api } = makeSandbox();
        api.startE2eeMaintenance();
        api.startE2eeMaintenance();
        assert.strictEqual(state.intervals.length, 2);
        assert.strictEqual(state.intervals[0].cleared, true, 'the old timer was cleared');
        assert.strictEqual(state.intervals[1].cleared, false);
        assert.strictEqual(state.intervals[1].ms, 30 * 60 * 1000);
        api.stopE2eeMaintenance();
        assert.strictEqual(state.intervals[1].cleared, true);
    });

    await test('no run without a user, while E2EE is not ready, or without a client', async () => {
        const { state, context, api } = makeSandbox();
        api.startE2eeMaintenance();
        state.now += 7 * HOUR;
        context.currentUser = null;
        api.maintainE2eeKeys();
        context.currentUser = { id: 1 };
        for (const value of ['pending', 'unavailable', 'off']) {
            context.e2eeState = value;
            api.maintainE2eeKeys();
        }
        context.e2eeState = 'ready';
        context.getE2eeClient = () => null;
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 0);
    });

    await test('a failed init() only warns and is retried on the next call (the E2EE state is not touched)', async () => {
        const { state, context, api } = makeSandbox();
        api.startE2eeMaintenance();
        state.now += 7 * HOUR;
        state.initError = new Error('сеть недоступна');
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 1);
        assert.strictEqual(state.warnings.length, 1);
        assert.match(state.warnings[0], /плановое обслуживание ключей не удалось/);
        assert.strictEqual(context.e2eeState, 'ready');
        state.initError = null;
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 2, 'no 6-hour wait after a failure');
        api.maintainE2eeKeys();
        await settle();
        assert.strictEqual(state.inits, 2, 'but after a success the interval starts again');
    });

    await test('hooks: started on login, stopped on logout, called when the tab becomes visible', () => {
        assert.match(source, /startKeepalive\(\);\n\s*startE2eeMaintenance\(\);/);
        assert.match(source, /stopKeepalive\(\);\n\s*stopE2eeMaintenance\(\);/);
        assert.match(source, /keepaliveOnVisible\(\);\n\s*maintainE2eeKeys\(\);/);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
