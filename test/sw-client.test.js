'use strict';
// Клиентская часть закрепления кода (6.2): public/lib/sw-client.js.
//
// Проверяется то, что нельзя ломать: что показывается при каком состоянии
// (чистая buildView), и порядок действий драйвера на подделках браузерного API —
// регистрация, режим разработки, ручное и аварийное отключение, «Обновить»
// с отпечатком из баннера, ожидающий SW, НЕОЖИДАННЫЙ controllerchange (подмена),
// обновление в соседней вкладке.
// Запуск: node test/sw-client.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { clientScriptFiles } = require('./client-script-source');
const core = require('../public/lib/sw-core');
const client = require('../public/lib/sw-client');
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

const sha = (ch) => ch.repeat(64);
const REGISTER = { hostname: 'nyxo.example', isSecureContext: true, hasServiceWorker: true, disabledByUser: false };
const PIN_A = { sha256: sha('a'), at: 1 };
const PIN_B = { sha256: sha('b'), at: 2 };
const publicState = (extra = {}) => ({ pinned: PIN_A, staged: null, pinIntact: true, lastError: null, lastCheckAt: 1, ...extra });
const view = (extra = {}) => client.buildView({ plan: { mode: 'register' }, state: publicState(), waiting: false, reloadNeeded: false, registerFailed: false, dismissed: new Set(), checkText: '', applyError: '', pendingDisable: false, ...extra });

// ---------- Подделки браузерного окружения ----------

function makeEnv({ hostname = 'nyxo.example', isSecureContext = true, search = '', withSw = true, off = false, state = publicState(), registerFails = false } = {}) {
    const listeners = { controllerchange: [], message: [] };
    const sent = [];                 // сообщения активному SW
    const waitingSent = [];          // сообщения ожидающему SW
    const log = { register: [], reloads: 0, unregistered: 0, updates: 0, warnings: 0, cleaned: 0, renders: [] };
    const store = new Map(off ? [[client.OFF_KEY, '1']] : []);

    const worker = {
        state,
        replies: {},
        postMessage(message, ports) {
            sent.push(message);
            const port = ports[0];
            const reply = this.replies[message.type] ? this.replies[message.type](message) : { ok: true, state: this.state };
            Promise.resolve().then(() => { port.postMessage(reply); port.close(); });
        },
    };
    const waitingWorker = { postMessage: (message) => waitingSent.push(message) };
    const regListeners = {};
    const registration = {
        active: worker,
        waiting: null,
        installing: null,
        addEventListener: (type, handler) => { regListeners[type] = handler; },
        update: async () => { log.updates++; },
        unregister: async () => { log.unregistered++; return true; },
    };
    const serviceWorker = withSw ? {
        controller: worker,
        register: async (url, options) => {
            log.register.push([url, options]);
            if (registerFails) throw new Error('SecurityError');
            return registration;
        },
        getRegistrations: async () => [registration],
        addEventListener: (type, handler) => { listeners[type].push(handler); },
    } : null;

    const timers = {
        pending: [],
        intervals: [],
        setTimeout(fn, ms) { this.pending.push({ fn, ms }); return this.pending.length; },
        clearTimeout() {},
        setInterval(fn, ms) { this.intervals.push({ fn, ms }); return this.intervals.length; },
        runPending() { const due = this.pending.splice(0); due.forEach((entry) => entry.fn()); return due; },
    };
    const caches = new FakeCacheStorage();

    const env = {
        serviceWorker,
        caches,
        hostname,
        isSecureContext,
        storage: { get: (key) => (store.has(key) ? store.get(key) : null), set: (key, value) => store.set(key, value), remove: (key) => store.delete(key) },
        location: { search, reload: () => { log.reloads++; } },
        timers,
        ui: {
            render: (v) => log.renders.push(v),
            showWarning: () => { log.warnings++; },
            cleanUrl: () => { log.cleaned++; },
        },
    };
    const lastView = () => log.renders[log.renders.length - 1];
    const emit = (type, event = {}) => listeners[type].forEach((handler) => handler(event));
    const settle = async () => { for (let i = 0; i < 6; i++) await new Promise((resolve) => setImmediate(resolve)); };
    return { env, worker, waitingWorker, registration, regListeners, log, store, sent, waitingSent, timers, caches, lastView, emit, settle };
}

async function started(options) {
    const t = makeEnv(options);
    t.driver = client.createDriver(t.env);
    await t.driver.start();
    await t.settle();
    return t;
}

async function main() {
    console.log('SW client tests\n');

    // ---------- Чистые функции ----------

    await test('isDevHost: localhost и loopback — разработка; *.localhost и обычные домены — нет', () => {
        for (const host of ['localhost', 'LOCALHOST', '127.0.0.1', '127.1.2.3', '[::1]', '::1']) assert.strictEqual(client.isDevHost(host), true, host);
        for (const host of ['t43.localhost', 'nyxo.example', 'abc.onion', '128.0.0.1', '1127.0.0.1', '', null, undefined]) assert.strictEqual(client.isDevHost(host), false, String(host));
    });

    await test('parseSwFlag: только off и on', () => {
        assert.strictEqual(client.parseSwFlag('?sw=off'), 'off');
        assert.strictEqual(client.parseSwFlag('?x=1&sw=on'), 'on');
        for (const search of ['', '?sw=', '?sw=OFF', '?sw=1', '?other=off', null, undefined]) assert.strictEqual(client.parseSwFlag(search), null, String(search));
    });

    await test('registrationPlan: порядок причин', () => {
        assert.strictEqual(client.registrationPlan(REGISTER).mode, 'register');
        assert.strictEqual(client.registrationPlan({ ...REGISTER, hasServiceWorker: false }).mode, 'unsupported');
        assert.strictEqual(client.registrationPlan({ ...REGISTER, isSecureContext: false }).mode, 'unsupported');
        assert.strictEqual(client.registrationPlan({ ...REGISTER, hostname: 'localhost' }).mode, 'dev');
        assert.strictEqual(client.registrationPlan({ ...REGISTER, disabledByUser: true }).mode, 'disabled');
        assert.strictEqual(client.registrationPlan({ ...REGISTER, hostname: 'localhost', disabledByUser: true }).mode, 'dev');
        assert.strictEqual(client.registrationPlan({ ...REGISTER, hostname: 't43.localhost' }).mode, 'register');
    });

    await test('buildView: закреплено, без новостей — баннера нет, в профиле отпечаток', () => {
        const v = view();
        assert.strictEqual(v.banner, null);
        assert.ok(v.status.includes(core.formatFingerprint(sha('a'))), v.status);
        assert.deepStrictEqual(v.toggle, { label: 'Отключить защиту кода', action: 'disable' });
        assert.strictEqual(v.canCheck, true);
    });

    await test('buildView: скачана новая версия — баннер «Обновить» с обоими отпечатками и пояснением', () => {
        const v = view({ state: publicState({ staged: PIN_B }) });
        assert.strictEqual(v.banner.kind, 'update');
        assert.strictEqual(v.banner.apply, 'Обновить');
        assert.ok(v.banner.dismiss);
        assert.ok(v.banner.text.includes(core.formatFingerprint(sha('b'))));
        assert.ok(v.banner.text.includes(core.formatFingerprint(sha('a'))));
        assert.match(v.banner.text, /Код приложения изменится/);
        assert.match(v.banner.text, /страниц[еа] проверки/);
    });

    await test('buildView: закреплённая версия недоступна, а сервер предлагает другую — баннер «Закрепить», а не тихая замена', () => {
        const v = view({ state: publicState({ staged: PIN_B, pinIntact: false }) });
        assert.strictEqual(v.banner.apply, 'Закрепить');
        assert.match(v.banner.text, /недоступна/);
    });

    await test('buildView: ожидающий SW без новой версии — отдельный баннер; новая версия важнее', () => {
        assert.strictEqual(view({ waiting: true }).banner.kind, 'sw-update');
        assert.strictEqual(view({ waiting: true, state: publicState({ staged: PIN_B }) }).banner.kind, 'update');
    });

    await test('buildView: ошибка проверки — сообщение с причиной и «старая остаётся»; без закрепления — «защита не включена»', () => {
        const failed = view({ state: publicState({ lastError: { at: 1, sha256: sha('b'), message: '/app.js: хэш не совпал с манифестом' } }) });
        assert.strictEqual(failed.banner.kind, 'failed');
        assert.match(failed.banner.text, /не прошла проверку и не установлена/);
        assert.match(failed.banner.text, /\/app\.js: хэш не совпал/);
        assert.match(failed.banner.text, /Продолжает работать закреплённая версия/);
        assert.strictEqual(failed.banner.apply, null);

        const none = view({ state: publicState({ pinned: null, lastError: { at: 1, sha256: null, message: 'сервер ответил HTTP 404' } }) });
        assert.strictEqual(none.banner.kind, 'unprotected');
        assert.match(none.banner.text, /Защита кода не включена/);
        assert.match(none.status, /не включилось/);
    });

    await test('buildView: версия применена в другой вкладке — «Перезагрузить»; закрытый баннер не показывается, новый — показывается', () => {
        assert.strictEqual(view({ reloadNeeded: true }).banner.apply, 'Перезагрузить');
        const state = publicState({ staged: PIN_B });
        const first = view({ state });
        assert.strictEqual(view({ state, dismissed: new Set([first.banner.key]) }).banner, null);
        const next = view({ state: publicState({ staged: { sha256: sha('c'), at: 3 } }), dismissed: new Set([first.banner.key]) });
        assert.ok(next.banner, 'для другой версии баннер снова виден');
    });

    await test('buildView: не register-режимы — только статус; выключенное пользователем можно включить', () => {
        const dev = client.buildView({ plan: { mode: 'dev' }, state: null });
        assert.match(dev.status, /localhost/);
        assert.strictEqual(dev.banner, null);
        assert.strictEqual(dev.toggle, null);
        const off = client.buildView({ plan: { mode: 'disabled' }, state: null });
        assert.deepStrictEqual(off.toggle, { label: 'Включить защиту кода', action: 'enable' });
        const unsupported = client.buildView({ plan: { mode: 'unsupported' }, state: null });
        assert.match(unsupported.status, /Tor Browser/);
        assert.strictEqual(client.buildView({ plan: { mode: 'register' }, state: null, dismissed: new Set() }).status, client.TEXT.firstCheck);
    });

    await test('buildView: результат проверки и ошибка применения дописываются, подтверждение отключения заменяет статус', () => {
        assert.match(view({ checkText: 'Проверка выполнена: новых версий нет.' }).status, /новых версий нет\.$/);
        const withError = view({ state: publicState({ staged: PIN_B }), applyError: 'Повторите попытку.' });
        assert.match(withError.banner.text, /Повторите попытку\.$/);
        const pending = view({ pendingDisable: true });
        assert.match(pending.status, /Нажмите ещё раз/);
        assert.strictEqual(pending.toggle.label, 'Подтвердить отключение');
    });

    await test('index.html: ядро и клиент подключены до script.js; баннер, окно-предупреждение и профиль на месте', () => {
        const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
        const order = ['lib/sw-core.js', 'lib/sw-client.js', clientScriptFiles()[0]].map((src) => html.indexOf(`<script src="${src}"></script>`));
        assert.ok(order.every((position) => position > 0), 'не все скрипты подключены');
        assert.ok(order[0] < order[1] && order[1] < order[2]);
        for (const id of ['code-banner', 'code-banner-text', 'code-banner-apply', 'code-banner-dismiss', 'code-warning-modal', 'code-protection-status', 'code-protection-check', 'code-protection-toggle']) {
            assert.ok(html.includes(`id="${id}"`), id);
        }
        // Предупреждение о подмене нельзя закрыть случайно: фокус сразу на «Сверить отпечаток», закрывает только «Продолжить».
        assert.match(html, /<a class="btn btn-primary" href="\/verify\.html"[^>]*data-autofocus>Сверить отпечаток<\/a>/);
        assert.match(html, /<a class="link-btn" href="\/verify\.html"[^>]*>Проверка кода<\/a>/, 'ссылка на экране входа');
    });

    // ---------- Драйвер ----------

    await test('драйвер: на localhost SW не регистрируется и ничего не снимается', async () => {
        const t = await started({ hostname: 'localhost' });
        assert.strictEqual(t.log.register.length, 0);
        assert.strictEqual(t.log.unregistered, 0);
        assert.match(t.lastView().status, /localhost/);
    });

    await test('драйвер: без поддержки service worker — тихо, только статус', async () => {
        const t = await started({ withSw: false });
        assert.strictEqual(t.log.register.length, 0);
        assert.match(t.lastView().status, /недоступно/);
    });

    await test('драйвер: обычный сайт — регистрация /sw.js со scope «/» и updateViaCache none, опрос состояния и тихая проверка', async () => {
        const t = await started();
        assert.deepStrictEqual(t.log.register, [['/sw.js', { scope: '/', updateViaCache: 'none' }]]);
        assert.deepStrictEqual(t.sent.map((m) => m.type), ['GET_STATE', 'CHECK']);
        assert.strictEqual(t.sent[1].force, false, 'автоматическая проверка не принудительная');
        assert.ok(t.lastView().status.includes(core.formatFingerprint(sha('a'))));
        assert.strictEqual(t.timers.intervals[0].ms, 60 * 60 * 1000, 'раз в час');
    });

    await test('драйвер: ежечасная проверка обновляет регистрацию (новый sw.js) и спрашивает манифест', async () => {
        const t = await started();
        t.sent.length = 0;
        t.timers.intervals[0].fn();
        await t.settle();
        assert.strictEqual(t.log.updates, 1);
        assert.deepStrictEqual(t.sent.map((m) => m.type), ['CHECK']);
    });

    await test('драйвер: отказ в регистрации не ломает страницу — статус объясняет, проверка недоступна', async () => {
        const t = await started({ registerFails: true });
        assert.match(t.lastView().status, /не включилось/);
        assert.strictEqual(t.lastView().canCheck, false);
        assert.strictEqual(t.sent.length, 0);
    });

    await test('драйвер: «выключено пользователем» — регистрации нет, регистрации и кэши nyxo-* снимаются, чужие кэши целы', async () => {
        const t = makeEnv({ off: true });
        await t.caches.open('nyxo-sw-state-v1');
        await t.caches.open('nyxo-shell-v1-' + sha('a'));
        await t.caches.open('чужой-кэш');
        t.driver = client.createDriver(t.env);
        await t.driver.start();
        assert.strictEqual(t.log.register.length, 0);
        assert.strictEqual(t.log.unregistered, 1);
        assert.deepStrictEqual(await t.caches.keys(), ['чужой-кэш']);
        assert.deepStrictEqual(t.lastView().toggle, { label: 'Включить защиту кода', action: 'enable' });
    });

    await test('драйвер: ?sw=off запоминает отключение и чистит адрес; ?sw=on включает обратно', async () => {
        const off = makeEnv({ search: '?sw=off' });
        off.driver = client.createDriver(off.env);
        await off.driver.start();
        assert.strictEqual(off.store.get(client.OFF_KEY), '1');
        assert.strictEqual(off.log.cleaned, 1);
        assert.strictEqual(off.log.register.length, 0);
        assert.strictEqual(off.log.unregistered, 1);

        const on = makeEnv({ search: '?sw=on', off: true });
        on.driver = client.createDriver(on.env);
        await on.driver.start();
        await on.settle();
        assert.strictEqual(on.store.has(client.OFF_KEY), false);
        assert.strictEqual(on.log.register.length, 1);
    });

    await test('драйвер: «Обновить» отправляет SW отпечаток из баннера и перезагружает страницу', async () => {
        const t = await started({ state: publicState({ staged: PIN_B }) });
        assert.strictEqual(t.lastView().banner.kind, 'update');
        t.worker.replies.APPLY = () => ({ ok: true, sha256: sha('b') });
        await t.driver.apply();
        const apply = t.sent.find((m) => m.type === 'APPLY');
        assert.deepStrictEqual(apply, { type: 'APPLY', sha256: sha('b') });
        assert.strictEqual(t.log.reloads, 1);
        assert.strictEqual(t.waitingSent.length, 0);
    });

    await test('драйвер: отказ SW (скачана другая версия) — страница не перезагружается, баннер обновляется и объясняет', async () => {
        const t = await started({ state: publicState({ staged: PIN_B }) });
        t.worker.replies.APPLY = () => ({ ok: false, reason: 'changed', sha256: sha('c') });
        t.worker.state = publicState({ staged: { sha256: sha('c'), at: 3 } });
        await t.driver.apply();
        assert.strictEqual(t.log.reloads, 0);
        const banner = t.lastView().banner;
        assert.match(banner.text, /скачана другая версия/);
        assert.ok(banner.text.includes(core.formatFingerprint(sha('c'))), 'в баннере уже новый отпечаток');
    });

    await test('драйвер: SW не ответил на APPLY — перезагрузки нет, сообщение об ошибке', async () => {
        const t = await started({ state: publicState({ staged: PIN_B }) });
        t.worker.replies.APPLY = () => { throw new Error('SW упал'); };
        await t.driver.apply();
        assert.strictEqual(t.log.reloads, 0);
        assert.match(t.lastView().banner.text, /не ответила/);
    });

    await test('драйвер: ожидающий SW — баннер; «Обновить» шлёт ему SKIP_WAITING, ждёт controllerchange и перезагружает один раз', async () => {
        const t = await started();
        t.registration.waiting = t.waitingWorker;
        // Страница узнаёт об ожидающем SW через statechange установки.
        const installing = { state: 'installed', addEventListener: (type, handler) => { installing.handler = handler; } };
        t.registration.installing = installing;
        t.regListeners.updatefound();
        installing.handler();
        await t.settle();
        assert.strictEqual(t.lastView().banner.kind, 'sw-update');

        await t.driver.apply();
        assert.deepStrictEqual(t.waitingSent, [{ type: 'SKIP_WAITING' }]);
        assert.strictEqual(t.log.reloads, 0, 'пока controllerchange не пришёл, не перезагружаемся');
        t.emit('controllerchange');
        assert.strictEqual(t.log.reloads, 1);
        t.timers.runPending();                       // запасной таймер после controllerchange ничего не добавляет
        assert.strictEqual(t.log.reloads, 1);
        assert.strictEqual(t.log.warnings, 0, 'запрошенная смена SW — не подмена');
    });

    await test('драйвер: если controllerchange не пришёл (страница не под управлением SW), запасной таймер перезагружает', async () => {
        const t = await started();
        t.registration.waiting = t.waitingWorker;
        const installing = { state: 'installed', addEventListener: (type, handler) => { installing.handler = handler; } };
        t.registration.installing = installing;
        t.regListeners.updatefound();
        installing.handler();
        await t.driver.apply();
        t.timers.runPending();
        assert.strictEqual(t.log.reloads, 1);
    });

    await test('драйвер: НЕОЖИДАННЫЙ controllerchange — блокирующее предупреждение, перезагрузки нет', async () => {
        const t = await started();
        t.emit('controllerchange');
        assert.strictEqual(t.log.warnings, 1);
        assert.strictEqual(t.log.reloads, 0);
        t.emit('controllerchange');
        assert.strictEqual(t.log.warnings, 2, 'предупреждение повторяется при каждой смене');
    });

    await test('драйвер: версия применена в другой вкладке — «Перезагрузить»; свои применения этого баннера не вызывают', async () => {
        const t = await started({ state: publicState({ staged: PIN_B }) });
        t.worker.state = publicState({ pinned: PIN_B });
        t.emit('message', { data: { nyxoSw: 1, type: 'applied', sha256: sha('b') } });
        await t.settle();
        assert.strictEqual(t.lastView().banner.kind, 'reload');
        await t.driver.apply();
        assert.strictEqual(t.log.reloads, 1);

        const own = await started({ state: publicState({ staged: PIN_B }) });
        own.worker.replies.APPLY = () => ({ ok: true, sha256: sha('b') });
        own.worker.state = publicState({ pinned: PIN_B });
        await own.driver.apply();
        own.emit('message', { data: { nyxoSw: 1, type: 'applied', sha256: sha('b') } });
        await own.settle();
        assert.notStrictEqual(own.lastView().banner && own.lastView().banner.kind, 'reload');
    });

    await test('драйвер: чужие сообщения (без метки nyxoSw) игнорируются', async () => {
        const t = await started();
        const rendersBefore = t.log.renders.length;
        t.emit('message', { data: { type: 'applied' } });
        t.emit('message', { data: null });
        t.emit('message', {});
        await t.settle();
        assert.strictEqual(t.log.renders.length, rendersBefore);
    });

    await test('драйвер: «Позже» скрывает баннер до следующей версии', async () => {
        const t = await started({ state: publicState({ staged: PIN_B }) });
        assert.ok(t.lastView().banner);
        t.driver.dismiss();
        assert.strictEqual(t.lastView().banner, null);
        t.worker.state = publicState({ staged: { sha256: sha('c'), at: 3 } });
        t.emit('message', { data: { nyxoSw: 1, type: 'staged' } });
        await t.settle();
        assert.ok(t.lastView().banner, 'новая версия — снова баннер');
    });

    await test('драйвер: ручная проверка показывает результат; отказ SW — понятный текст', async () => {
        const t = await started();
        t.worker.replies.CHECK = () => ({ ok: true, result: { action: 'none' }, state: publicState() });
        await t.driver.checkNow();
        assert.match(t.lastView().status, /новых версий нет/);
        t.worker.replies.CHECK = () => ({ ok: true, result: { action: 'stage' }, state: publicState({ staged: PIN_B }) });
        await t.driver.checkNow();
        assert.match(t.lastView().status, /Новая версия скачана и проверена/);
        assert.strictEqual(t.lastView().banner.kind, 'update');
        t.worker.replies.CHECK = () => ({ ok: false, message: 'сбой' });
        await t.driver.checkNow();
        assert.match(t.lastView().status, /Проверка не удалась: сбой/);
    });

    await test('драйвер: отключение защиты — два нажатия; ключи E2EE (IndexedDB, localStorage) не трогаются, снимаются только кэши nyxo-*', async () => {
        const t = await started();
        await t.caches.open('nyxo-shell-v1-' + sha('a'));
        await t.caches.open('прочее');
        await t.driver.toggleProtection();
        assert.match(t.lastView().status, /Нажмите ещё раз/);
        assert.strictEqual(t.log.unregistered, 0);
        assert.strictEqual(t.log.reloads, 0);
        t.timers.runPending();                        // окно подтверждения истекло
        assert.doesNotMatch(t.lastView().status, /Нажмите ещё раз/);

        await t.driver.toggleProtection();
        await t.driver.toggleProtection();
        assert.strictEqual(t.store.get(client.OFF_KEY), '1');
        assert.strictEqual(t.log.unregistered, 1);
        assert.deepStrictEqual(await t.caches.keys(), ['прочее']);
        assert.strictEqual(t.log.reloads, 1);
        t.emit('controllerchange');
        assert.strictEqual(t.log.warnings, 0, 'во время снятия смена контроллера — не подмена');
    });

    await test('драйвер: «Включить» убирает флаг и перезагружает страницу — регистрация пройдёт при загрузке', async () => {
        const t = makeEnv({ off: true });
        t.driver = client.createDriver(t.env);
        await t.driver.start();
        await t.driver.toggleProtection();
        assert.strictEqual(t.store.has(client.OFF_KEY), false);
        assert.strictEqual(t.log.reloads, 1);
    });

    await test('драйвер без активного SW (первая установка): состояние читается из Cache API напрямую', async () => {
        const t = makeEnv();
        t.registration.active = null;
        t.env.serviceWorker.controller = null;
        await core.writeState(t.caches, { ...core.emptyState(), pinned: PIN_A });
        t.driver = client.createDriver(t.env);
        await t.driver.start();
        await t.settle();
        assert.ok(t.lastView().status.includes(core.formatFingerprint(sha('a'))));
        assert.strictEqual(t.sent.length, 0, 'писать некому');
        assert.doesNotMatch(t.lastView().status, /не отвечает/, 'автоматическая проверка молчит, пока SW не активен');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
