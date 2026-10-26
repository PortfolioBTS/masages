'use strict';
// Ядро service worker (6.2, roadmap R10): public/lib/sw-core.js.
//
// Часть 1 — чистые функции: маршрутизация запросов (что SW не трогает никогда),
// требования к манифесту, решение «обновлять или нет», разбор состояния.
// Часть 2 — контроллер против настоящего HTTP-сайта (test/sw-fakes.js): первый
// визит закрепляет версию, новая версия скачивается в фоне и НЕ подменяет
// закреплённую до согласия, битая версия отвергается, сбои сети молчат, кэш
// хранит только файлы манифеста.
// Запуск: node test/sw-core.test.js

const assert = require('assert');
const core = require('../public/lib/sw-core');
const fs = require('fs');
const path = require('path');
const { FakeCacheStorage, startSite, sampleFiles } = require('./sw-fakes');

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

const ORIGIN = 'https://nyxo.example';
const sha = (ch) => ch.repeat(64);
const req = (url, extra = {}) => ({ method: 'GET', url: ORIGIN + url, cache: 'default', headers: new Headers(), ...extra });

async function main() {
    console.log('SW core tests\n');

    // ---------- Часть 1. Чистые функции ----------

    await test('formatFingerprint: группы по 4, заглавные, по умолчанию 6 групп, мусор отбрасывается', () => {
        const hex = '3f2a91c07b11' + 'ab'.repeat(26);
        assert.strictEqual(core.formatFingerprint(hex), '3F2A 91C0 7B11 ABAB ABAB ABAB');
        assert.strictEqual(core.formatFingerprint(hex, 2), '3F2A 91C0');
        assert.strictEqual(core.formatFingerprint('zz 12-3', 3), '123');
        assert.strictEqual(core.formatFingerprint(''), '');
        assert.strictEqual(core.formatFingerprint(null), '');
    });

    await test('routeFor: API, сокеты, вложения, sw.js и манифест SW не трогает — в любом регистре', () => {
        for (const url of ['/api/chats', '/api', '/API/chats', '/socket.io/?EIO=4', '/socket.io', '/uploads/a.png', '/Uploads/a.png', '/sw.js', '/SW.JS', '/client-manifest.json']) {
            const route = core.routeFor(req(url), ORIGIN);
            assert.strictEqual(route.kind, 'network', url);
        }
        // Похожие, но другие пути — обычные кандидаты на оболочку.
        for (const url of ['/apix', '/uploads-x.js', '/lib/api/x.js']) {
            assert.strictEqual(core.routeFor(req(url), ORIGIN).kind, 'shell', url);
        }
    });

    await test('routeFor: не-GET, чужой origin, no-store (страница сверки) и Range идут в сеть', () => {
        assert.strictEqual(core.routeFor(req('/', { method: 'POST' }), ORIGIN).kind, 'network');
        assert.strictEqual(core.routeFor(req('/', { method: 'HEAD' }), ORIGIN).kind, 'network');
        assert.strictEqual(core.routeFor({ method: 'GET', url: 'https://evil.example/e2ee.js', headers: new Headers() }, ORIGIN).reason, 'origin');
        assert.strictEqual(core.routeFor(req('/e2ee.js', { cache: 'no-store' }), ORIGIN).reason, 'no-store');
        assert.strictEqual(core.routeFor(req('/e2ee.js', { headers: new Headers({ Range: 'bytes=0-9' }) }), ORIGIN).reason, 'range');
        assert.strictEqual(core.routeFor({ method: 'GET', url: 'не адрес', headers: new Headers() }, ORIGIN).kind, 'network');
        assert.strictEqual(core.routeFor(null, ORIGIN).kind, 'network');
    });

    await test('routeFor: страница и ресурсы оболочки — кандидаты; query в путь не входит', () => {
        assert.deepStrictEqual(core.routeFor(req('/'), ORIGIN), { kind: 'shell', pathname: '/' });
        assert.deepStrictEqual(core.routeFor(req('/script.js?v=3', { cache: 'no-cache' }), ORIGIN), { kind: 'shell', pathname: '/script.js' });
    });

    await test('resolveShellPath: алиас «/» и точные пути манифеста; чужие пути — null', () => {
        const manifest = {
            aliases: { '/': '/index.html' },
            files: [{ path: '/index.html' }, { path: '/lib/a.js' }],
        };
        const index = core.indexManifest(manifest);
        assert.strictEqual(core.resolveShellPath('/', index), '/index.html');
        assert.strictEqual(core.resolveShellPath('/index.html', index), '/index.html');
        assert.strictEqual(core.resolveShellPath('/lib/a.js', index), '/lib/a.js');
        for (const other of ['/lib/A.js', '/api/chats', '/uploads/x', '/lib/', '/constructor', '/__proto__', '/hasOwnProperty']) {
            assert.strictEqual(core.resolveShellPath(other, index), null, other);
        }
    });

    const goodFile = (path, bytes = 10) => ({ path, sha256: sha('a'), sri: 'sha384-' + 'A'.repeat(64), bytes });
    const goodManifest = () => ({ format: 'nyxo-client-manifest/1', aliases: { '/': '/index.html' }, files: [goodFile('/index.html'), goodFile('/app.js')] });

    await test('manifestPolicyProblems: честный манифест проходит', () => {
        assert.deepStrictEqual(core.manifestPolicyProblems(goodManifest()), []);
    });

    await test('manifestPolicyProblems: пути API, uploads, sw.js, манифеста и со знаками ?#\\ отвергаются', () => {
        for (const bad of ['/api/x.js', '/uploads/a.png', '/socket.io/x.js', '/sw.js', '/client-manifest.json', '/a?b.js', '/a#b.js', '/a\\b.js']) {
            const manifest = goodManifest();
            manifest.files.push(goodFile(bad));
            assert.ok(core.manifestPolicyProblems(manifest).length > 0, bad);
        }
    });

    await test('manifestPolicyProblems: без алиаса «/», слишком много файлов, большой файл, большой общий размер', () => {
        const noAlias = goodManifest();
        noAlias.aliases = {};
        assert.match(core.manifestPolicyProblems(noAlias).join(), /алиаса/);

        const many = goodManifest();
        for (let i = 0; i < core.LIMITS.files + 1; i++) many.files.push(goodFile(`/f${i}.js`, 1));
        assert.match(core.manifestPolicyProblems(many).join(), /слишком много файлов/);

        const big = goodManifest();
        big.files.push(goodFile('/big.js', core.LIMITS.fileBytes + 1));
        assert.match(core.manifestPolicyProblems(big).join(), /слишком большой/);

        const total = goodManifest();
        for (let i = 0; i < 5; i++) total.files.push(goodFile(`/c${i}.js`, core.LIMITS.fileBytes));
        assert.match(core.manifestPolicyProblems(total).join(), /общий размер/);
    });

    await test('planDownloads: неизменившиеся файлы берутся из прежней версии, остальное качается', () => {
        const file = (path, hash, bytes) => ({ path, sha256: hash, bytes });
        const before = { files: [file('/a.js', sha('1'), 5), file('/b.js', sha('2'), 5), file('/c.js', sha('3'), 5)] };
        const after = { files: [file('/a.js', sha('1'), 5), file('/b.js', sha('9'), 5), file('/c.js', sha('3'), 6), file('/d.js', sha('4'), 1)] };
        assert.deepStrictEqual(core.planDownloads(before, after), { reuse: ['/a.js'], download: ['/b.js', '/c.js', '/d.js'] });
        assert.deepStrictEqual(core.planDownloads(null, after).reuse, []);
    });

    await test('decideUpdate: все ветки решения', () => {
        const base = () => core.emptyState();
        const now = 1_000_000;
        const decide = (extra) => core.decideUpdate({ state: base(), pinIntact: true, stagedIntact: false, observedSha256: sha('b'), now, force: false, ...extra }).action;
        const pinned = (extra = {}) => ({ ...base(), pinned: { sha256: sha('a'), at: 1 }, ...extra });

        assert.strictEqual(decide({}), 'pin', 'нет закрепления — первый визит');
        assert.strictEqual(decide({ state: pinned(), observedSha256: sha('a') }), 'none');
        assert.strictEqual(decide({ state: pinned(), observedSha256: sha('a'), pinIntact: false }), 'restore');
        assert.strictEqual(decide({ state: pinned({ staged: { sha256: sha('c'), at: 1 } }), observedSha256: sha('a') }), 'drop-staged', 'сервер вернулся к закреплённому');
        assert.strictEqual(decide({ state: pinned(), observedSha256: sha('b') }), 'stage');
        assert.strictEqual(decide({ state: pinned({ staged: { sha256: sha('b'), at: 1 } }), stagedIntact: true }), 'wait-user');
        assert.strictEqual(decide({ state: pinned({ staged: { sha256: sha('b'), at: 1 } }), stagedIntact: false }), 'stage', 'скачанное повреждено — качаем заново');
        const failed = pinned({ lastError: { at: now - 1000, sha256: sha('b'), message: 'x' } });
        assert.strictEqual(decide({ state: failed }), 'wait-retry', 'недавняя неудача с той же версией');
        assert.strictEqual(decide({ state: failed, force: true }), 'stage', 'по запросу пользователя — снова');
        const old = pinned({ lastError: { at: now - core.RETRY_FAILED_MS - 1, sha256: sha('b'), message: 'x' } });
        assert.strictEqual(decide({ state: old }), 'stage', 'неудача давно — пробуем снова');
        const other = pinned({ lastError: { at: now - 1000, sha256: sha('d'), message: 'x' } });
        assert.strictEqual(decide({ state: other }), 'stage', 'неудача была с другой версией');
    });

    await test('normalizeState: мусор даёт пустое состояние, стороннее поле отбрасывается, staged = pinned снимается', () => {
        for (const junk of [null, undefined, 5, 'x', [], {}, { v: 2 }, { v: 1, pinned: { sha256: 'нет' } }]) {
            const state = core.normalizeState(junk);
            assert.strictEqual(state.pinned, null);
            assert.strictEqual(state.staged, null);
        }
        const state = core.normalizeState({
            v: 1, pinned: { sha256: sha('a'), at: 5, extra: 'x' }, staged: { sha256: sha('a'), at: 6 },
            lastError: { at: 1, sha256: 'плохой', message: 'm'.repeat(900) }, lastCheckAt: 7, evil: true,
        });
        assert.deepStrictEqual(state.pinned, { sha256: sha('a'), at: 5 });
        assert.strictEqual(state.staged, null, 'staged, равный pinned, бессмыслен');
        assert.strictEqual(state.lastError.sha256, null);
        assert.strictEqual(state.lastError.message.length, 500);
        assert.strictEqual(state.lastCheckAt, 7);
        assert.ok(!('evil' in state));
    });

    await test('summarizeProblems: три первые проблемы и счётчик остальных', () => {
        assert.strictEqual(core.summarizeProblems([]), '');
        assert.strictEqual(core.summarizeProblems(['a', 'b']), 'a; b');
        assert.strictEqual(core.summarizeProblems(['a', 'b', 'c', 'd', 'e']), 'a; b; c; и ещё 2');
    });

    await test('buildFailureResponse: страница — 503 с запретительным CSP и экранированием, остальное — текст', async () => {
        const page = core.buildFailureResponse({ mode: 'navigate' }, '3F2A', '<script>alert(1)</script>');
        assert.strictEqual(page.status, 503);
        assert.match(page.headers.get('content-type'), /text\/html/);
        assert.strictEqual(page.headers.get('content-security-policy'), "default-src 'none'");
        const html = await page.text();
        assert.ok(!html.includes('<script>alert'), 'детали ошибки должны экранироваться');
        assert.ok(html.includes('&lt;script&gt;'));
        const asset = core.buildFailureResponse({ mode: 'no-cors' }, '3F2A', 'x');
        assert.strictEqual(asset.status, 503);
        assert.match(asset.headers.get('content-type'), /text\/plain/);
    });

    // ---------- Часть 2. Контроллер против настоящего сайта ----------

    // Всё окружение теста: сайт, кэши, часы, события, переключатель сети.
    async function setup(files = sampleFiles()) {
        const site = await startSite(files);
        const env = {
            caches: new FakeCacheStorage(),
            clock: { t: 1_000_000 },
            events: [],
            offline: false,
            failStatus: 0,
        };
        const controller = core.createController({
            caches: env.caches,
            origin: site.origin,
            now: () => env.clock.t,
            notify: (event) => env.events.push(event.type),
            fetch: async (url, init) => {
                if (env.offline) throw new TypeError('fetch failed');
                if (env.failStatus) return new Response('сбой', { status: env.failStatus });
                return fetch(url, init);
            },
        });
        const get = (pathname, extra = {}) => controller.respond({ method: 'GET', url: site.origin + pathname, mode: 'no-cors', cache: 'default', headers: new Headers(), ...extra });
        return { site, env, controller, get, state: () => controller._internals.readState() };
    }
    const bodyOf = async (response) => Buffer.from(await response.arrayBuffer()).toString('utf8');
    const cacheKeys = async (env, name) => (await (await env.caches.open(name)).keys()).map((key) => new URL(key.url).pathname).sort();

    await test('первый визит: файлы проверены и закреплены, в кэше ровно файлы манифеста и сам манифест', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const state = await t.state();
            const expected = t.site.manifestSha256();
            assert.strictEqual(state.pinned.sha256, expected, 'закрепляется отпечаток манифеста');
            assert.strictEqual(state.staged, null);
            assert.strictEqual(state.lastError, null);
            assert.deepStrictEqual(await cacheKeys(t.env, core.shellCacheName(expected)),
                ['/app.js', '/client-manifest.json', '/index.html', '/lib/helper.js', '/style.css', '/vendor/socket.io.min.js']);
            assert.deepStrictEqual(t.env.events, ['pinned']);
            assert.deepStrictEqual((await t.env.caches.keys()).sort(), [core.STATE_CACHE, core.shellCacheName(expected)].sort());
        } finally { await t.site.close(); }
    });

    await test('respond: страница и ресурсы — из закреплённого кэша; сеть не нужна', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const hitsBefore = t.site.hits.length;
            const indexHtml = fs.readFileSync(path.join(t.site.dir, 'index.html'), 'utf8');
            assert.strictEqual(await bodyOf(await t.get('/', { mode: 'navigate', cache: 'no-cache' })), indexHtml);
            assert.strictEqual(await bodyOf(await t.get('/index.html', { mode: 'navigate' })), indexHtml);
            assert.strictEqual(await bodyOf(await t.get('/style.css?v=2')), 'body{color:#fff}\n');
            const script = await t.get('/app.js');
            assert.match(script.headers.get('content-type'), /javascript/, 'заголовки версии сохраняются');
            assert.strictEqual(t.site.hits.slice(hitsBefore).filter((hit) => hit !== '/client-manifest.json').length, 0, 'файлы из сети не запрашивались');
        } finally { await t.site.close(); }
    });

    await test('respond: API, сокеты, вложения, sw.js, манифест, POST, no-store, чужие пути — null (в сеть), в кэш ничего не попадает', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const pinnedName = core.shellCacheName(t.site.manifestSha256());
            const before = await cacheKeys(t.env, pinnedName);
            for (const p of ['/api/chats', '/api/auth', '/socket.io/?EIO=4&transport=polling', '/uploads/secret.png', '/sw.js', '/client-manifest.json', '/нет-такого.js', '/lib/', '/verify.html']) {
                assert.strictEqual(await t.get(p), null, p);
            }
            assert.strictEqual(await t.get('/', { method: 'POST' }), null);
            assert.strictEqual(await t.get('/app.js', { cache: 'no-store' }), null, 'сверка с сервером читает сеть');
            assert.deepStrictEqual(await cacheKeys(t.env, pinnedName), before, 'кэш версии не изменился');
            assert.deepStrictEqual((await t.env.caches.keys()).sort(), [core.STATE_CACHE, pinnedName].sort(), 'новых кэшей нет');
        } finally { await t.site.close(); }
    });

    await test('новая версия: скачивается в фоне, закреплённая работает до согласия; «Обновить» переключает; старый кэш удаляется', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();

            t.site.write('style.css', 'body{color:#0f0}\n');       // выкат: изменился один файл
            t.env.events.length = 0;
            t.site.hits.length = 0;
            const result = await t.controller.checkForUpdate({ force: true });
            const v2 = t.site.manifestSha256();
            assert.notStrictEqual(v1, v2);
            assert.strictEqual(result.action, 'stage');

            const state = await t.state();
            assert.strictEqual(state.pinned.sha256, v1, 'закрепление не переключилось само');
            assert.strictEqual(state.staged.sha256, v2);
            assert.deepStrictEqual(t.env.events, ['staged']);
            assert.strictEqual(await bodyOf(await t.get('/style.css')), 'body{color:#fff}\n', 'до согласия — прежняя версия');
            assert.strictEqual(t.site.hitsFor('/style.css'), 1, 'качается только изменившийся файл');
            assert.strictEqual(t.site.hitsFor('/app.js'), 0, 'неизменившиеся берутся из прежнего кэша');
            assert.strictEqual(t.site.hitsFor('/index.html'), 0);

            // Повторная проверка не качает заново.
            t.site.hits.length = 0;
            assert.strictEqual((await t.controller.checkForUpdate({ force: true })).action, 'wait-user');
            assert.strictEqual(t.site.hits.filter((hit) => hit !== '/client-manifest.json').length, 0);

            // Отпечаток из баннера не совпал с тем, что скачано, — не переключаем.
            assert.deepStrictEqual(await t.controller.applyUpdate(sha('f')), { ok: false, reason: 'changed', sha256: v2 });
            assert.strictEqual((await t.state()).pinned.sha256, v1);

            assert.deepStrictEqual(await t.controller.applyUpdate(v2), { ok: true, sha256: v2 });
            const after = await t.state();
            assert.strictEqual(after.pinned.sha256, v2);
            assert.strictEqual(after.staged, null);
            assert.strictEqual(await bodyOf(await t.get('/style.css')), 'body{color:#0f0}\n');
            assert.deepStrictEqual((await t.env.caches.keys()).sort(), [core.STATE_CACHE, core.shellCacheName(v2)].sort(), 'старая версия удалена');
            assert.deepStrictEqual(await t.controller.applyUpdate(v2), { ok: false, reason: 'no-staged' });
        } finally { await t.site.close(); }
    });

    await test('подмена: сервер отдаёт файл не по манифесту — версия отвергнута, закреплённая работает, причина сохранена', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();
            t.site.write('app.js', 'console.log("app v2");\n');
            t.site.overrides.set('/app.js', Buffer.from('console.log("ЧУЖОЙ КОД");\n')); // манифест говорит одно, сервер отдаёт другое
            t.env.events.length = 0;

            const result = await t.controller.checkForUpdate({ force: true });
            assert.strictEqual(result.action, 'failed');
            assert.match(result.message, /\/app\.js/);
            const state = await t.state();
            assert.strictEqual(state.pinned.sha256, v1);
            assert.strictEqual(state.staged, null);
            assert.strictEqual(state.lastError.sha256, t.site.manifestSha256());
            assert.match(state.lastError.message, /не совпали/);
            assert.deepStrictEqual(t.env.events, ['update-failed']);
            assert.deepStrictEqual((await t.env.caches.keys()).sort(), [core.STATE_CACHE, core.shellCacheName(v1)].sort(), 'недособранной версии не осталось');
            assert.strictEqual(await bodyOf(await t.get('/app.js')), 'console.log("app v1");\n');

            // Не долбим сервер: без force повтор ждёт; по запросу пользователя — пробуем снова.
            t.site.hits.length = 0;
            t.env.clock.t += core.CHECK_INTERVAL_MS + 1;
            assert.strictEqual((await t.controller.checkForUpdate({ force: false })).action, 'wait-retry');
            assert.strictEqual(t.site.hits.filter((hit) => hit === '/app.js').length, 0);
            assert.strictEqual((await t.controller.checkForUpdate({ force: true })).action, 'failed');

            // Сервер исправлен — версия принимается, ошибка снимается.
            t.site.overrides.clear();
            assert.strictEqual((await t.controller.checkForUpdate({ force: true })).action, 'stage');
            const fixed = await t.state();
            assert.strictEqual(fixed.lastError, null);
            assert.strictEqual(fixed.staged.sha256, t.site.manifestSha256());
        } finally { await t.site.close(); }
    });

    await test('подмена на первом визите: ничего не закрепляется, причина записана; приложение продолжает работать через сеть', async () => {
        const t = await setup();
        try {
            t.site.overrides.set('/style.css', Buffer.from('body{display:none}\n'));
            await t.controller.install();
            const state = await t.state();
            assert.strictEqual(state.pinned, null);
            assert.match(state.lastError.message, /\/style\.css/);
            assert.strictEqual(await t.get('/'), null, 'без закрепления — в сеть');
            assert.deepStrictEqual(await t.env.caches.keys(), [core.STATE_CACHE]);
        } finally { await t.site.close(); }
    });

    await test('нет сети и ошибки 5xx — молча: ни закрепления, ни lastError; позже закрепляется', async () => {
        const t = await setup();
        try {
            t.env.offline = true;
            await t.controller.install();
            assert.strictEqual((await t.state()).pinned, null);
            assert.strictEqual((await t.state()).lastError, null);

            t.env.offline = false;
            t.env.failStatus = 503;
            await t.controller.install();
            assert.strictEqual((await t.state()).lastError, null, '5xx не причина беспокоить пользователя');

            t.env.failStatus = 0;
            await t.controller.install();
            assert.strictEqual((await t.state()).pinned.sha256, t.site.manifestSha256());
        } finally { await t.site.close(); }
    });

    await test('обрыв сети посреди загрузки новой версии: закреплённая цела, lastError нет, ничего не осталось', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();
            t.site.write('app.js', 'console.log("app v2");\n');
            let manifestFetched = false;
            // Сеть пропадает сразу после получения манифеста.
            const controller = core.createController({
                caches: t.env.caches, origin: t.site.origin, now: () => t.env.clock.t,
                fetch: async (url, init) => {
                    if (manifestFetched) throw new TypeError('fetch failed');
                    if (String(url).endsWith('/client-manifest.json')) manifestFetched = true;
                    return fetch(url, init);
                },
            });
            assert.strictEqual((await controller.checkForUpdate({ force: true })).action, 'offline');
            const state = await controller._internals.readState();
            assert.strictEqual(state.pinned.sha256, v1);
            assert.strictEqual(state.staged, null);
            assert.strictEqual(state.lastError, null);
            assert.deepStrictEqual((await t.env.caches.keys()).sort(), [core.STATE_CACHE, core.shellCacheName(v1)].sort());
        } finally { await t.site.close(); }
    });

    await test('битый манифест, чужие пути в нём, редирект и 404 файла — отказ с понятной причиной', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();

            t.site.overrides.set('/client-manifest.json', Buffer.from('{ это не JSON'));
            let result = await t.controller.checkForUpdate({ force: true });
            assert.strictEqual(result.action, 'failed');
            assert.match(result.message, /манифест не принят/);

            const evil = JSON.parse(t.site.manifestText());
            evil.files.push({ ...evil.files[0], path: '/api/chats' });
            t.site.overrides.set('/client-manifest.json', Buffer.from(JSON.stringify(evil)));
            result = await t.controller.checkForUpdate({ force: true });
            assert.strictEqual(result.action, 'failed');
            assert.match(result.message, /нельзя кэшировать/);

            t.site.overrides.set('/client-manifest.json', { status: 302, headers: { Location: 'https://evil.example/m.json' }, body: '' });
            result = await t.controller.checkForUpdate({ force: true });
            assert.strictEqual(result.action, 'failed');
            assert.match(result.message, /перенаправляет/);

            t.site.overrides.clear();
            t.site.write('app.js', 'console.log("v2");\n');
            t.site.overrides.set('/app.js', { status: 404, headers: {}, body: 'нет' });
            result = await t.controller.checkForUpdate({ force: true });
            assert.strictEqual(result.action, 'failed');
            assert.match(result.message, /\/app\.js: сервер ответил HTTP 404/);

            assert.strictEqual((await t.state()).pinned.sha256, v1, 'всё это время закреплена исходная версия');
            assert.strictEqual(await bodyOf(await t.get('/app.js')), 'console.log("app v1");\n');
        } finally { await t.site.close(); }
    });

    await test('сервер вернулся к закреплённой версии: скачанная новая выбрасывается', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();
            t.site.write('app.js', 'console.log("v2");\n');
            await t.controller.checkForUpdate({ force: true });
            assert.ok((await t.state()).staged);
            t.site.write('app.js', 'console.log("app v1");\n');
            assert.strictEqual(t.site.manifestSha256(), v1);
            assert.strictEqual((await t.controller.checkForUpdate({ force: true })).action, 'drop-staged');
            assert.strictEqual((await t.state()).staged, null);
            assert.deepStrictEqual((await t.env.caches.keys()).sort(), [core.STATE_CACHE, core.shellCacheName(v1)].sort());
        } finally { await t.site.close(); }
    });

    await test('кэш закреплённой версии пропал: страница работает через сеть, сервер прежний — версия восстанавливается без баннера', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();
            await t.env.caches.delete(core.shellCacheName(v1));
            assert.strictEqual(await t.get('/'), null, 'без пригодного кэша приложение не ломается');
            assert.strictEqual((await t.controller._internals.readState()).pinned.sha256, v1, 'закрепление помнится');
            assert.strictEqual((await t.controller.getPublicState()).pinIntact, false);

            assert.strictEqual((await t.controller.checkForUpdate({ force: true })).action, 'restore');
            assert.strictEqual((await t.controller.getPublicState()).pinIntact, true);
            assert.ok(await t.get('/'));
        } finally { await t.site.close(); }
    });

    await test('кэш пропал, а сервер уже другой: это обновление с согласием, а не тихая подмена', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();
            await t.env.caches.delete(core.shellCacheName(v1));
            t.site.write('app.js', 'console.log("v2");\n');
            assert.strictEqual((await t.controller.checkForUpdate({ force: true })).action, 'stage');
            const publicState = await t.controller.getPublicState();
            assert.strictEqual(publicState.pinned.sha256, v1);
            assert.strictEqual(publicState.pinIntact, false, 'баннер скажет, что закреплённая версия недоступна');
            assert.strictEqual(publicState.staged.sha256, t.site.manifestSha256());
        } finally { await t.site.close(); }
    });

    await test('отдельный файл пропал из кэша: докачивается, только если сервер отдаёт закреплённые байты; иначе 503 вместо чужого кода', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const cache = await t.env.caches.open(core.shellCacheName(t.site.manifestSha256()));

            await cache.delete('/app.js');
            const healed = await t.get('/app.js');
            assert.strictEqual(await bodyOf(healed), 'console.log("app v1");\n');
            assert.ok(await cache.match('/app.js'), 'файл возвращён в кэш');

            await cache.delete('/app.js');
            t.site.overrides.set('/app.js', Buffer.from('console.log("ЧУЖОЙ КОД");\n'));
            const refused = await t.get('/app.js');
            assert.strictEqual(refused.status, 503);
            assert.ok(!(await bodyOf(refused)).includes('ЧУЖОЙ КОД'));
            assert.strictEqual(await cache.match('/app.js'), undefined, 'чужие байты в кэш не попали');

            const page = await (async () => { await cache.delete('/index.html'); t.site.overrides.set('/index.html', Buffer.from('<h1>подмена</h1>')); return t.get('/', { mode: 'navigate' }); })();
            assert.strictEqual(page.status, 503);
            assert.match(page.headers.get('content-type'), /text\/html/);
        } finally { await t.site.close(); }
    });

    await test('нет сети и файла нет в кэше: ошибка сети отдаётся браузеру (а не 503 «подмена»)', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const cache = await t.env.caches.open(core.shellCacheName(t.site.manifestSha256()));
            await cache.delete('/app.js');
            t.env.offline = true;
            await assert.rejects(() => t.get('/app.js'), /fetch failed|нет соединения/);
        } finally { await t.site.close(); }
    });

    await test('сбой хранилища при чтении состояния не превращается в «закрепления нет»: повторного TOFU поверх нет', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const v1 = t.site.manifestSha256();
            t.site.write('app.js', 'console.log("v2");\n');
            t.env.caches.failOpen = (name) => name === core.STATE_CACHE;
            await assert.rejects(() => t.controller.checkForUpdate({ force: true }), /хранилище недоступно/);
            await assert.rejects(() => t.get('/'), /хранилище недоступно/, 'sw.js в этом случае отдаст запрос в сеть');
            t.env.caches.failOpen = null;
            assert.strictEqual((await t.state()).pinned.sha256, v1, 'закрепление не затёрто');
        } finally { await t.site.close(); }
    });

    await test('фоновая проверка при навигации: не чаще раза в интервал, без наложения', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            const manifestHits = () => t.site.hitsFor('/client-manifest.json');
            const base = manifestHits();
            const background = [];
            const navigate = () => t.get('/', { mode: 'navigate' }).then(() => null);
            // respond сам запускает maybeCheck через background.
            const run = () => t.controller.respond({ method: 'GET', url: t.site.origin + '/', mode: 'navigate', cache: 'default', headers: new Headers() }, { background: (promise) => background.push(promise) });
            await run();
            await Promise.all(background.splice(0));
            assert.strictEqual(manifestHits(), base, 'сразу после установки проверка не нужна');

            t.env.clock.t += core.CHECK_INTERVAL_MS + 1;
            await Promise.all([run(), run(), run()]);
            await Promise.all(background.splice(0));
            assert.strictEqual(manifestHits(), base + 1, 'три навигации подряд — один запрос манифеста');

            await navigate();
            assert.strictEqual(manifestHits(), base + 1);
        } finally { await t.site.close(); }
    });

    await test('навигация без закрепления запускает закрепление в фоне (SW переустановлен после очистки)', async () => {
        const t = await setup();
        try {
            const background = [];
            const response = await t.controller.respond({ method: 'GET', url: t.site.origin + '/', mode: 'navigate', cache: 'default', headers: new Headers() }, { background: (promise) => background.push(promise) });
            assert.strictEqual(response, null, 'эта страница ещё идёт из сети');
            await Promise.all(background);
            assert.strictEqual((await t.state()).pinned.sha256, t.site.manifestSha256());
        } finally { await t.site.close(); }
    });

    await test('две проверки одновременно не мешают друг другу (общая очередь)', async () => {
        const t = await setup();
        try {
            const results = await Promise.all([t.controller.checkForUpdate({ force: true }), t.controller.checkForUpdate({ force: true })]);
            assert.deepStrictEqual(results.map((r) => r.action).sort(), ['none', 'pin']);
            assert.strictEqual((await t.state()).pinned.sha256, t.site.manifestSha256());
        } finally { await t.site.close(); }
    });

    await test('activate убирает осиротевшие кэши версий и не трогает чужие', async () => {
        const t = await setup();
        try {
            await t.controller.install();
            await t.env.caches.open(core.SHELL_PREFIX + sha('e'));
            await t.env.caches.open('workbox-precache');
            await t.controller.activate();
            const names = await t.env.caches.keys();
            assert.ok(!names.includes(core.SHELL_PREFIX + sha('e')));
            assert.ok(names.includes('workbox-precache'));
            assert.ok(names.includes(core.shellCacheName(t.site.manifestSha256())));
        } finally { await t.site.close(); }
    });

    await test('clearOwnCaches: удаляет только кэши с префиксом nyxo-', async () => {
        const caches = new FakeCacheStorage();
        for (const name of ['nyxo-sw-state-v1', 'nyxo-shell-v1-' + sha('a'), 'nyxo-x', 'other', 'nyxo']) await caches.open(name);
        await core.clearOwnCaches(caches);
        assert.deepStrictEqual((await caches.keys()).sort(), ['nyxo', 'other']);
    });

    await test('настоящий public/: манифест принимается политикой SW, а sw.js и uploads в него не входят', () => {
        const manifestLib = require('../lib/client-manifest');
        const manifest = manifestLib.parseManifest(manifestLib.buildManifestText(path.join(__dirname, '..', 'public')));
        assert.deepStrictEqual(core.manifestPolicyProblems(manifest), []);
        const paths = manifest.files.map((file) => file.path);
        assert.ok(!paths.includes('/sw.js'));
        assert.ok(paths.includes('/lib/sw-core.js'), 'ядро SW закрепляется вместе с остальным кодом');
        for (const p of paths) assert.ok(!core.isNetworkOnlyPath(p), p);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
