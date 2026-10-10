'use strict';
// Обвязка service worker (6.2): public/sw.js.
//
// Часть 1 — статика: sw.js не входит в манифест клиента, а файлы, которые он
// подключает, входят; skipWaiting() вызывается только по сообщению страницы,
// clients.claim() нет нигде; sw.js не работает с кэшем напрямую (всё через ядро).
// Часть 2 — sw.js целиком в изолированном окружении (node:vm), события шлём сами:
// установка закрепляет версию, API и сокеты SW не трогает, страница отдаётся из
// кэша, сбой хранилища уходит в сеть, SKIP_WAITING и APPLY работают как задумано.
// Запуск: node test/sw-worker.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const manifestLib = require('../lib/client-manifest');
const core = require('../public/lib/sw-core');
const { FakeCacheStorage, startSite, sampleFiles } = require('./sw-fakes');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const SW_SOURCE = fs.readFileSync(path.join(PUBLIC_DIR, 'sw.js'), 'utf8');
const CORE_SOURCE = fs.readFileSync(path.join(PUBLIC_DIR, 'lib', 'sw-core.js'), 'utf8');

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

// Объекты, созданные внутри vm, из другого «мира»: для deepStrictEqual приводим их к обычным.
const plain = (value) => JSON.parse(JSON.stringify(value));

// Без комментариев: проверки «в коде нет вызова X» не должны срабатывать на пояснения.
const withoutComments = (source) => source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

async function main() {
    console.log('SW worker tests\n');

    // ---------- Часть 1. Статика ----------

    const manifest = manifestLib.parseManifest(manifestLib.buildManifestText(PUBLIC_DIR));
    const manifestPaths = manifest.files.map((file) => file.path);

    await test('sw.js лежит в public/, но в манифест клиента не входит; его зависимости входят', () => {
        assert.ok(fs.existsSync(path.join(PUBLIC_DIR, 'sw.js')));
        assert.ok(!manifestPaths.includes('/sw.js'), 'service worker закрепляет хэш манифеста и не может быть его частью');
        for (const dependency of ['/lib/sw-core.js', '/lib/client-verify.js']) {
            assert.ok(manifestPaths.includes(dependency), `${dependency} должен закрепляться вместе с кодом`);
        }
    });

    await test('importScripts: подключаются только файлы из public/, перечисленные в манифесте', () => {
        const calls = [...withoutComments(SW_SOURCE).matchAll(/importScripts\(([^)]*)\)/g)];
        assert.strictEqual(calls.length, 1, 'importScripts должен вызываться один раз, в начале');
        const urls = [...calls[0][1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
        assert.ok(urls.length >= 2);
        for (const url of urls) {
            assert.ok(url.startsWith('/') && !url.includes('..'), url);
            assert.ok(manifestPaths.includes(url), `${url} не входит в манифест: SW исполнял бы незакреплённый код`);
        }
    });

    await test('skipWaiting() — один вызов и только в ответ на SKIP_WAITING; clients.claim() нет ни в sw.js, ни в ядре', () => {
        const sw = withoutComments(SW_SOURCE);
        const coreCode = withoutComments(CORE_SOURCE);
        assert.strictEqual((sw.match(/skipWaiting\s*\(/g) || []).length, 1);
        const branch = /case core\.MSG\.SKIP_WAITING:\s*\n\s*self\.skipWaiting\(\);/;
        assert.match(sw, branch, 'skipWaiting() должен стоять сразу после case SKIP_WAITING');
        assert.ok(!/skipWaiting/.test(coreCode), 'ядро не активирует SW');
        assert.ok(!/clients\.claim/.test(sw + coreCode), 'clients.claim() сделал бы любой SW «контролёром» без перезагрузки');
    });

    await test('sw.js не трогает Cache API сам: ни caches.open, ни put — только через ядро', () => {
        const sw = withoutComments(SW_SOURCE);
        assert.ok(!/caches\.(open|delete|match)|\.put\(|\.addAll\(/.test(sw));
        assert.ok(/caches: self\.caches/.test(sw), 'ядру передаются настоящие caches');
    });

    await test('ядро: в кэш пишутся только файлы манифеста — в коде нет cache.put с адресом запроса', () => {
        const coreCode = withoutComments(CORE_SOURCE);
        const puts = [...coreCode.matchAll(/\.put\(([^,]+),/g)].map((m) => m[1].trim());
        // STATE_PATH, MANIFEST_PATH, file.path, path — всё это пути, известные ядру, а не адрес запроса страницы.
        for (const target of puts) {
            assert.ok(/^(STATE_PATH|MANIFEST_PATH|file\.path)$/.test(target), `cache.put с неожиданным адресом: ${target}`);
        }
        assert.ok(puts.length >= 4);
    });

    await test('sw.js и ядро разбираются как скрипты (синтаксис)', () => {
        assert.doesNotThrow(() => new vm.Script(SW_SOURCE, { filename: 'sw.js' }));
        assert.doesNotThrow(() => new vm.Script(CORE_SOURCE, { filename: 'sw-core.js' }));
    });

    // ---------- Часть 2. sw.js в изолированном окружении ----------

    // Поднимает sw.js как браузер: свой global, importScripts читает файлы из public/.
    async function bootWorker(site, { caches = new FakeCacheStorage() } = {}) {
        const listeners = {};
        const calls = { skipWaiting: 0, postedToClients: [] };
        const sandbox = {
            console: { warn() {}, log() {}, error() {} },
            Response, Request, Headers, URL, TextDecoder, TextEncoder, crypto, Promise, Map, Set, Object, Array, JSON, Number, String, Math, Date, Error, TypeError,
            // В настоящем SW fetch принимает и Request; в тестах «запрос» — простой объект с url.
            fetch: (input, init) => fetch(typeof input === 'string' ? input : input.url, init),
            setTimeout, clearTimeout,
        };
        sandbox.self = sandbox;
        sandbox.location = new URL(site.origin + '/sw.js');
        sandbox.caches = caches;
        sandbox.navigator = {};
        sandbox.clients = { matchAll: async () => [{ postMessage: (message) => calls.postedToClients.push(message) }] };
        sandbox.skipWaiting = () => { calls.skipWaiting++; return Promise.resolve(); };
        sandbox.addEventListener = (type, handler) => { listeners[type] = handler; };
        sandbox.importScripts = (...urls) => {
            for (const url of urls) {
                const file = path.join(PUBLIC_DIR, ...url.split('/').filter(Boolean));
                vm.runInContext(fs.readFileSync(file, 'utf8'), sandbox, { filename: url });
            }
        };
        vm.createContext(sandbox);
        vm.runInContext(SW_SOURCE, sandbox, { filename: 'sw.js' });
        return { listeners, calls, caches, sandbox };
    }

    // Событие с waitUntil: собираем обещания, чтобы дождаться их в тесте.
    function lifecycleEvent(extra = {}) {
        const pending = [];
        return { waitUntil: (promise) => pending.push(promise), settled: () => Promise.all(pending), ...extra };
    }
    function fetchEvent(site, pathname, { method = 'GET', mode = 'no-cors', cache = 'default' } = {}) {
        const state = { responded: false, promise: null };
        const event = lifecycleEvent({
            request: { method, url: site.origin + pathname, mode, cache, headers: new Headers() },
            respondWith: (promise) => { state.responded = true; state.promise = Promise.resolve(promise); },
        });
        return { event, state };
    }

    await test('sw.js: установка закрепляет версию, страница и ресурсы отдаются из кэша', async () => {
        const site = await startSite(sampleFiles());
        try {
            const worker = await bootWorker(site);
            for (const type of ['install', 'activate', 'fetch', 'message']) assert.strictEqual(typeof worker.listeners[type], 'function', type);

            const install = lifecycleEvent();
            worker.listeners.install(install);
            await install.settled();
            const names = await worker.caches.keys();
            assert.ok(names.includes(core.shellCacheName(site.manifestSha256())), 'версия закреплена');
            assert.ok(worker.calls.postedToClients.some((m) => m.nyxoSw === 1 && m.type === 'pinned'), 'окна узнали о закреплении');
            assert.strictEqual(worker.calls.skipWaiting, 0, 'установка не активирует SW сама');

            const activate = lifecycleEvent();
            worker.listeners.activate(activate);
            await activate.settled();

            const page = fetchEvent(site, '/', { mode: 'navigate' });
            worker.listeners.fetch(page.event);
            assert.ok(page.state.responded);
            const response = await page.state.promise;
            assert.strictEqual(await response.text(), fs.readFileSync(path.join(site.dir, 'index.html'), 'utf8'));
            await page.event.settled();
        } finally { await site.close(); }
    });

    await test('sw.js: /api, /socket.io, /uploads, /sw.js, POST и no-store — respondWith не вызывается', async () => {
        const site = await startSite(sampleFiles());
        try {
            const worker = await bootWorker(site);
            const install = lifecycleEvent();
            worker.listeners.install(install);
            await install.settled();
            const cases = [['/api/chats'], ['/api/auth'], ['/socket.io/?EIO=4'], ['/uploads/a.png'], ['/sw.js'], ['/client-manifest.json'], ['/', { method: 'POST' }], ['/app.js', { cache: 'no-store' }]];
            for (const [pathname, extra] of cases) {
                const probe = fetchEvent(site, pathname, extra);
                worker.listeners.fetch(probe.event);
                assert.strictEqual(probe.state.responded, false, `${pathname} ${extra ? JSON.stringify(extra) : ''}`);
            }
        } finally { await site.close(); }
    });

    await test('sw.js: путь вне манифеста уходит в сеть (SW лишь передаёт ответ), сбой хранилища — тоже в сеть', async () => {
        const site = await startSite(sampleFiles({ 'other.txt': 'не из манифеста?\n' }));
        try {
            const worker = await bootWorker(site);
            const install = lifecycleEvent();
            worker.listeners.install(install);
            await install.settled();

            // other.txt в манифесте есть (он лежит в public/), а /nope.txt — нет: 404 с сервера доходит как есть.
            const unknown = fetchEvent(site, '/nope.txt');
            worker.listeners.fetch(unknown.event);
            assert.ok(unknown.state.responded);
            assert.strictEqual((await unknown.state.promise).status, 404);

            worker.caches.failOpen = () => true;
            const broken = fetchEvent(site, '/app.js');
            worker.listeners.fetch(broken.event);
            assert.ok(broken.state.responded);
            const response = await broken.state.promise;
            assert.strictEqual(response.status, 200, 'приложение работает, когда Cache API сломан');
            assert.strictEqual(await response.text(), 'console.log("app v1");\n');
        } finally { await site.close(); }
    });

    await test('sw.js: SKIP_WAITING активирует SW, остальные сообщения skipWaiting не вызывают', async () => {
        const site = await startSite(sampleFiles());
        try {
            const worker = await bootWorker(site);
            const replies = [];
            const message = (data) => {
                const event = lifecycleEvent({ data, ports: [{ postMessage: (payload) => replies.push(payload) }] });
                worker.listeners.message(event);
                return event.settled();
            };
            await message({ type: 'GET_STATE' });
            await message({ type: 'CHECK', force: true });
            await message({ type: 'APPLY' });                        // без отпечатка
            await message({ type: 'НЕИЗВЕСТНО' });
            await message(null);
            await message('строка');
            assert.strictEqual(worker.calls.skipWaiting, 0);
            await message({ type: 'SKIP_WAITING' });
            assert.strictEqual(worker.calls.skipWaiting, 1);

            const [state, check, apply] = replies;
            assert.strictEqual(state.ok, true);
            assert.strictEqual(state.state.pinned, null);
            assert.strictEqual(check.ok, true);
            assert.strictEqual(check.state.pinned.sha256, site.manifestSha256(), 'CHECK на первом визите закрепляет');
            assert.deepStrictEqual(plain(apply), { ok: false, reason: 'no-sha' });
        } finally { await site.close(); }
    });

    await test('sw.js: APPLY с отпечатком переключает закрепление и сообщает окнам; чужой отпечаток — отказ', async () => {
        const site = await startSite(sampleFiles());
        try {
            const worker = await bootWorker(site);
            const replies = [];
            const message = (data) => {
                const event = lifecycleEvent({ data, ports: [{ postMessage: (payload) => replies.push(payload) }] });
                worker.listeners.message(event);
                return event.settled();
            };
            await message({ type: 'CHECK', force: true });
            site.write('style.css', 'body{color:red}\n');
            await message({ type: 'CHECK', force: true });
            const staged = replies[1].state.staged;
            assert.ok(staged, 'новая версия скачана');
            assert.ok(worker.calls.postedToClients.some((m) => m.type === 'staged'));

            await message({ type: 'APPLY', sha256: 'f'.repeat(64) });
            assert.strictEqual(replies[2].ok, false);
            await message({ type: 'APPLY', sha256: staged.sha256 });
            assert.deepStrictEqual(plain(replies[3]), { ok: true, sha256: staged.sha256 });
            assert.ok(worker.calls.postedToClients.some((m) => m.type === 'applied' && m.sha256 === staged.sha256));
        } finally { await site.close(); }
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
