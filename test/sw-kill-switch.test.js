'use strict';
// Аварийное снятие service worker (6.2): lib/sw-kill-switch.js, SW_KILL_SWITCH=yes.
//
// Проверяется: по умолчанию переключатель ничего не делает; включённый подменяет
// только GET /sw.js; отданный скрипт не вызывает skipWaiting сам, не имеет fetch-
// обработчика, чистит только кэши nyxo-* и не лезет в IndexedDB/localStorage (ключи
// E2EE); middleware стоит в server.js до статики; env-check предупреждает.
// Запуск: node test/sw-kill-switch.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { createSwKillSwitch, isEnabled, KILL_SCRIPT } = require('../lib/sw-kill-switch');
const { checkEnv } = require('../lib/env-check');
const core = require('../public/lib/sw-core');
const { FakeCacheStorage } = require('./sw-fakes');

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

function call(middleware, { method = 'GET', path: urlPath = '/sw.js' } = {}) {
    const headers = {};
    const result = { nextCalled: false, body: null, headers };
    const res = {
        set: (name, value) => { headers[name.toLowerCase()] = value; },
        send: (body) => { result.body = body; },
    };
    middleware({ method, path: urlPath }, res, () => { result.nextCalled = true; });
    return result;
}

async function main() {
    console.log('SW kill switch tests\n');

    await test('isEnabled: только "yes" (без учёта регистра и пробелов)', () => {
        for (const value of ['yes', 'YES', ' yes ']) assert.strictEqual(isEnabled({ SW_KILL_SWITCH: value }), true, value);
        for (const value of ['', 'no', 'true', '1', 'да', undefined]) assert.strictEqual(isEnabled({ SW_KILL_SWITCH: value }), false, String(value));
        assert.strictEqual(isEnabled({}), false);
        assert.strictEqual(isEnabled(null), false);
    });

    await test('выключен: ни один запрос не перехватывается, предупреждения нет', () => {
        const warnings = [];
        const middleware = createSwKillSwitch({}, { warn: (text) => warnings.push(text) });
        const result = call(middleware);
        assert.strictEqual(result.nextCalled, true);
        assert.strictEqual(result.body, null);
        assert.deepStrictEqual(warnings, []);
    });

    await test('включён: GET /sw.js отдаёт скрипт снятия (без кэша, как JS), остальное идёт дальше; при старте — предупреждение', () => {
        const warnings = [];
        const middleware = createSwKillSwitch({ SW_KILL_SWITCH: 'yes' }, { warn: (text) => warnings.push(text) });
        assert.strictEqual(warnings.length, 1);
        assert.match(warnings[0], /SW_KILL_SWITCH=yes/);

        const hit = call(middleware);
        assert.strictEqual(hit.nextCalled, false);
        assert.strictEqual(hit.body, KILL_SCRIPT);
        assert.match(hit.headers['content-type'], /^text\/javascript/);
        assert.strictEqual(hit.headers['cache-control'], 'no-cache');

        for (const other of [{ path: '/lib/sw-core.js' }, { path: '/' }, { path: '/sw.js.map' }, { path: '/api/auth' }, { method: 'POST' }, { method: 'HEAD' }]) {
            const result = call(middleware, other);
            assert.strictEqual(result.nextCalled, true, JSON.stringify(other));
            assert.strictEqual(result.body, null);
        }
    });

    await test('скрипт снятия: разбирается, без fetch-обработчика, skipWaiting только по сообщению, чужие хранилища не трогает', () => {
        assert.doesNotThrow(() => new vm.Script(KILL_SCRIPT));
        const code = KILL_SCRIPT.replace(/^\s*\/\/.*$/gm, '');
        assert.ok(!/addEventListener\('fetch'/.test(code), 'все запросы должны идти в сеть');
        assert.ok(!/clients\.claim/.test(code));
        assert.strictEqual((code.match(/skipWaiting/g) || []).length, 1);
        assert.match(code, /event\.data\.type === 'SKIP_WAITING'\) self\.skipWaiting\(\)/);
        assert.ok(!/indexedDB|localStorage|sessionStorage|Clear-Site-Data/i.test(code), 'ключи E2EE и история не затрагиваются');
        assert.ok(code.includes(`startsWith('${core.OWN_CACHE_PREFIX}')`), 'префикс кэшей совпадает с префиксом ядра SW');
        assert.match(code, /registration\.unregister\(\)/);
    });

    await test('скрипт снятия в изолированном окружении: activate удаляет только кэши nyxo-* и снимает регистрацию; SKIP_WAITING работает', async () => {
        const listeners = {};
        const caches = new FakeCacheStorage();
        for (const name of ['nyxo-sw-state-v1', 'nyxo-shell-v1-' + 'a'.repeat(64), 'workbox-x', 'nyxo']) await caches.open(name);
        let unregistered = 0, skipped = 0;
        const sandbox = {
            caches, Promise,
            registration: { unregister: async () => { unregistered++; } },
            skipWaiting: () => { skipped++; },
            addEventListener: (type, handler) => { listeners[type] = handler; },
        };
        sandbox.self = sandbox;
        vm.runInNewContext(KILL_SCRIPT, sandbox);
        assert.deepStrictEqual(Object.keys(listeners).sort(), ['activate', 'message']);

        let pending;
        listeners.activate({ waitUntil: (promise) => { pending = promise; } });
        await pending;
        assert.deepStrictEqual((await caches.keys()).sort(), ['nyxo', 'workbox-x']);
        assert.strictEqual(unregistered, 1);

        listeners.message({ data: { type: 'ЧТО-ТО-ЕЩЁ' } });
        listeners.message({ data: null });
        assert.strictEqual(skipped, 0);
        listeners.message({ data: { type: 'SKIP_WAITING' } });
        assert.strictEqual(skipped, 1);
    });

    await test('код сервера: переключатель стоит ДО express.static, иначе статика отдала бы настоящий sw.js', () => {
        const source = require('./server-source').readServerSource();
        const kill = source.indexOf('app.use(createSwKillSwitch(process.env))');
        const statics = source.search(/app\.use\(express\.static\(path\.join\((__dirname|ROOT_DIR), 'public'\)/);
        assert.ok(kill > 0 && statics > 0);
        assert.ok(kill < statics);
    });

    await test('env-check: "yes" — предупреждение о выключенном закреплении, мусор — предупреждение о значении, пусто — тишина', () => {
        const env = (extra) => Object.assign({
            SESSION_SECRET: crypto.randomBytes(48).toString('base64url'),
            MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
            DATABASE_URL: `postgresql://postgres:${crypto.randomBytes(24).toString('base64url')}@postgres.railway.internal:5432/railway`,
            NODE_ENV: 'production',
        }, extra);
        const named = (list) => list.filter((entry) => entry.name === 'SW_KILL_SWITCH');
        assert.strictEqual(named(checkEnv(env({})).warnings).length, 0);
        assert.strictEqual(named(checkEnv(env({ SW_KILL_SWITCH: 'no' })).warnings).length, 0);
        assert.match(named(checkEnv(env({ SW_KILL_SWITCH: 'yes' })).warnings)[0].message, /закрепление кода не работает/);
        assert.match(named(checkEnv(env({ SW_KILL_SWITCH: 'maybe' })).warnings)[0].message, /только "yes"/);
        assert.strictEqual(named(checkEnv(env({ SW_KILL_SWITCH: 'yes' })).errors).length, 0, 'это не ошибка запуска');
    });

    await test('.env.example описывает SW_KILL_SWITCH закомментированной строкой', () => {
        const text = fs.readFileSync(path.join(__dirname, '..', '.env.example'), 'utf8');
        assert.match(text, /^# SW_KILL_SWITCH=yes$/m);
        assert.ok(!/^SW_KILL_SWITCH=/m.test(text), 'по умолчанию выключено');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
