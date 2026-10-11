// Клиентская часть закрепления кода (6.2): регистрация service worker, баннер
// «Доступна новая версия», предупреждение о подмене и строка «Защита кода» в
// профиле. Логика service worker — в lib/sw-core.js и sw.js; здесь страница.
//
// Файл делится на три слоя, чтобы важное проверялось без браузера:
//   * чистые функции (isDevHost, parseSwFlag, registrationPlan, buildView) — что
//     показать при каком состоянии;
//   * createDriver — порядок действий (регистрация, опрос, «Обновить», аварийное
//     снятие). Всё внешнее приходит параметрами: navigator.serviceWorker, хранилище,
//     адрес страницы, отрисовка;
//   * bindDom — привязка к разметке index.html (id в test/client-static.test.js).
// Исполняется в браузере (window.NyxoSwClient) и в Node (test/sw-client.test.js).
//
// Главное правило страницы: код, который она показывает пользователю, меняется
// только по его нажатию. Поэтому:
//   * «Обновить» отправляет в SW отпечаток из баннера (APPLY), а не просто команду;
//   * controllerchange, которого страница не запрашивала, — это не обновление, а
//     подмена service worker: показывается блокирующее предупреждение.
// Что это НЕ защищает (первый визит, сам sw.js, очистка данных сайта) — в шапке
// lib/sw-core.js и docs/threat-model.md.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sw-core'));
    } else {
        root.NyxoSwClient = factory(root.NyxoSwCore);
    }
})(typeof self !== 'undefined' ? self : this, function (Core) {
    'use strict';

    const OFF_KEY = 'nyxo.sw.off';
    const VERIFY_URL = '/verify.html';
    const CHECK_EVERY_MS = 60 * 60 * 1000;
    const ASK_TIMEOUT_MS = 15 * 1000;
    // Состояние страница может прочитать и сама (Cache API), поэтому ждать ответ дольше нескольких
    // секунд незачем: активный SW может быть аварийным (SW_KILL_SWITCH) и на GET_STATE не отвечает.
    const STATE_TIMEOUT_MS = 3 * 1000;
    // Проверка включает скачивание файлов: через Tor это заметно дольше обычного.
    const CHECK_TIMEOUT_MS = 3 * 60 * 1000;
    const ACTIVATION_FALLBACK_MS = 5 * 1000;
    const CONFIRM_WINDOW_MS = 6 * 1000;

    // ---------- Тексты ----------

    const TEXT = Object.freeze({
        unsupported: 'Закрепление кода недоступно: браузер не поддерживает service worker или страница открыта не по защищённому соединению (так бывает в Tor Browser и приватных окнах). Файлы можно сверить вручную.',
        dev: 'Закрепление кода выключено на localhost: это режим разработки.',
        disabled: 'Закрепление кода выключено вами на этом устройстве. Страница открывается напрямую с сервера, без проверки.',
        registerFailed: 'Закрепление кода не включилось: браузер отказал в регистрации service worker.',
        firstCheck: 'Закрепление кода ещё не выполнено: идёт первая проверка файлов.',
        confirmDisable: 'Нажмите ещё раз, чтобы отключить защиту кода. Страница будет открываться без проверки.',
    });

    const RESULT_TEXT = Object.freeze({
        none: 'Проверка выполнена: новых версий нет.',
        skipped: 'Проверка выполнялась недавно: новых версий нет.',
        pin: 'Код закреплён.',
        restore: 'Закреплённая версия восстановлена.',
        stage: 'Новая версия скачана и проверена. Она заработает после вашего согласия.',
        'wait-user': 'Новая версия уже скачана и ждёт вашего согласия.',
        'wait-retry': 'Эта версия недавно не прошла проверку. Повторю позже.',
        'drop-staged': 'Сервер вернулся к закреплённой версии.',
        offline: 'Нет связи с сервером: проверка не выполнена.',
        failed: 'Новая версия не прошла проверку.',
    });

    const APPLY_FAILURE_TEXT = Object.freeze({
        changed: 'Пока вы читали сообщение, скачана другая версия. Сверьте новый отпечаток и нажмите «Обновить» снова.',
        'no-staged': 'Скачанной версии больше нет. Повторите проверку.',
        'staged-broken': 'Скачанная версия повреждена. Повторите проверку.',
        'no-reply': 'Служба проверки кода не ответила. Повторите попытку.',
    });

    // ---------- Чистые функции ----------

    // На адресах разработки service worker не регистрируется: файлы там правят на ходу, а закрепление
    // мешало бы. Поддомены *.localhost (например, t43.localhost) — не они: на них SW работает.
    function isDevHost(hostname) {
        const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
        return host === 'localhost' || host === '::1' || /^127(?:\.\d{1,3}){3}$/.test(host);
    }

    // ?sw=off и ?sw=on — ручное отключение и включение закрепления (на случай, когда страница открывается,
    // а профиль недоступен). Остальные значения игнорируются.
    function parseSwFlag(search) {
        let value = null;
        try {
            value = new URLSearchParams(String(search || '')).get('sw');
        } catch {
            value = null;
        }
        return value === 'off' || value === 'on' ? value : null;
    }

    // Что делать при загрузке страницы.
    function registrationPlan({ hostname, isSecureContext, hasServiceWorker, disabledByUser }) {
        if (!hasServiceWorker || !isSecureContext) return { mode: 'unsupported' };
        if (isDevHost(hostname)) return { mode: 'dev' };
        if (disabledByUser) return { mode: 'disabled' };
        return { mode: 'register' };
    }

    const fp = (sha) => Core.formatFingerprint(sha, 6);

    // Что показать. Вход:
    //   plan, state (ответ GET_STATE или null), waiting (есть ожидающий SW), reloadNeeded (версию применили
    //   в другой вкладке), registerFailed, dismissed (Set ключей закрытых баннеров), checkText (результат
    //   ручной проверки), applyError, pendingDisable (ждём второго нажатия «Отключить»).
    // Выход: { banner, status, toggle, canCheck }. banner = null или
    //   { kind, key, text, apply: подпись кнопки | null, dismiss: подпись | null }.
    function buildView(input) {
        const { plan, state, waiting, reloadNeeded, registerFailed, dismissed, checkText, applyError, pendingDisable } = input;
        const active = plan.mode === 'register';
        const view = { banner: null, status: '', toggle: null, canCheck: false };

        if (plan.mode === 'unsupported') view.status = TEXT.unsupported;
        else if (plan.mode === 'dev') view.status = TEXT.dev;
        else if (plan.mode === 'disabled') {
            view.status = TEXT.disabled;
            view.toggle = { label: 'Включить защиту кода', action: 'enable' };
        }
        if (!active) return view;

        view.toggle = { label: pendingDisable ? 'Подтвердить отключение' : 'Отключить защиту кода', action: 'disable' };
        view.canCheck = !registerFailed;

        const pinned = state && state.pinned;
        const staged = state && state.staged;
        const failure = state && state.lastError;
        const pinnedFp = pinned ? fp(pinned.sha256) : '';

        let banner = null;
        if (reloadNeeded) {
            banner = { kind: 'reload', key: 'reload', text: 'Версия Nyxo обновлена в другой вкладке. Перезагрузите страницу, чтобы не смешивать старый и новый код.', apply: 'Перезагрузить', dismiss: null };
        } else if (staged && pinned && state.pinIntact === false) {
            banner = {
                kind: 'update', key: 'update:' + staged.sha256,
                text: `Закреплённая версия кода (отпечаток ${pinnedFp}) недоступна: данные сайта очищены или повреждены. Сервер предлагает версию с отпечатком ${fp(staged.sha256)}. Сверьте её на странице проверки и закрепите.`,
                apply: 'Закрепить', dismiss: 'Позже',
            };
        } else if (staged) {
            banner = {
                kind: 'update', key: 'update:' + staged.sha256,
                text: `Доступна новая версия Nyxo (отпечаток ${fp(staged.sha256)}). Код приложения изменится после обновления; до тех пор работает закреплённая версия ${pinnedFp || 'без отпечатка'}. Сверьте отпечаток на странице проверки.`,
                apply: 'Обновить', dismiss: 'Позже',
            };
        } else if (waiting) {
            banner = {
                kind: 'sw-update', key: 'sw-update',
                text: 'Доступно обновление службы проверки кода. Файлы приложения не меняются. Если вы этого не ждали, сверьте отпечаток на странице проверки.',
                apply: 'Обновить', dismiss: 'Позже',
            };
        } else if (failure) {
            banner = pinned
                ? { kind: 'failed', key: 'failed:' + failure.message, text: `Новая версия Nyxo не прошла проверку и не установлена: ${failure.message}. Продолжает работать закреплённая версия ${pinnedFp}.`, apply: null, dismiss: 'Закрыть' }
                : { kind: 'unprotected', key: 'unprotected:' + failure.message, text: `Защита кода не включена: ${failure.message}. Приложение работает, но подмену кода на сервере оно не заметит.`, apply: null, dismiss: 'Закрыть' };
        }
        if (banner && dismissed && dismissed.has(banner.key)) banner = null;
        if (banner && applyError) banner = Object.assign({}, banner, { text: banner.text + ' ' + applyError });
        view.banner = banner;

        if (registerFailed) view.status = TEXT.registerFailed;
        else if (pinned) {
            view.status = `Код закреплён: отпечаток ${pinnedFp}. Страница открывается из проверенной копии на этом устройстве, об изменении кода на сервере вы узнаете из сообщения. ` +
                'Первое посещение это не проверяет: сверьте отпечаток с опубликованным в релизе.';
        } else if (failure) {
            view.status = `Закрепление не включилось: ${failure.message}.`;
        } else {
            view.status = TEXT.firstCheck;
        }
        if (pendingDisable) view.status = TEXT.confirmDisable;
        if (checkText) view.status += ' ' + checkText;
        return view;
    }

    // ---------- Драйвер ----------

    // env:
    //   serviceWorker  — navigator.serviceWorker или null;
    //   caches         — CacheStorage (для чтения состояния без SW и для аварийной очистки);
    //   hostname, isSecureContext;
    //   storage        — { get(key), set(key, value), remove(key) } (localStorage, любые ошибки глотает);
    //   location       — { search, reload() };
    //   ui             — { render(view), showWarning(), cleanUrl() };
    //   timers         — { setTimeout, clearTimeout, setInterval } (в тестах подменяются);
    //   MessageChannel — конструктор канала (по умолчанию глобальный).
    function createDriver(env) {
        const sw = env.serviceWorker || null;
        const timers = env.timers || {
            setTimeout: (fn, ms) => setTimeout(fn, ms),
            clearTimeout: (id) => clearTimeout(id),
            setInterval: (fn, ms) => setInterval(fn, ms),
        };
        const Channel = env.MessageChannel || (typeof MessageChannel !== 'undefined' ? MessageChannel : null);

        let plan = { mode: 'unsupported' };
        let registration = null;
        let state = null;
        let waiting = null;
        let reloadNeeded = false;
        let registerFailed = false;
        let expectingChange = false;
        let appliedByUs = false;
        let removing = false;
        let reloading = false;
        let pendingDisable = false;
        let checkText = '';
        let applyError = '';
        const dismissed = new Set();

        const view = () => buildView({ plan, state, waiting: Boolean(waiting), reloadNeeded, registerFailed, dismissed, checkText, applyError, pendingDisable });
        const render = () => env.ui.render(view());

        function reload() {
            if (reloading) return;
            reloading = true;
            env.location.reload();
        }

        // Запрос к SW с ответом через MessageChannel. Говорим с активным SW; ожидающему (waiting) пишем
        // только SKIP_WAITING и только после «Обновить».
        function ask(message, timeoutMs) {
            const target = (registration && registration.active) || (sw && sw.controller);
            if (!target || !Channel) return Promise.reject(new Error('service worker ещё не активен'));
            return new Promise((resolve, reject) => {
                const channel = new Channel();
                const timer = timers.setTimeout(() => {
                    channel.port1.close();
                    reject(new Error('service worker не ответил'));
                }, timeoutMs);
                channel.port1.onmessage = (event) => {
                    timers.clearTimeout(timer);
                    channel.port1.close();
                    resolve(event.data);
                };
                try {
                    target.postMessage(message, [channel.port2]);
                } catch (err) {
                    timers.clearTimeout(timer);
                    channel.port1.close();
                    reject(err);
                }
            });
        }

        async function refreshState() {
            try {
                const reply = await ask({ type: Core.MSG.GET_STATE }, STATE_TIMEOUT_MS);
                if (reply && reply.ok) {
                    state = reply.state;
                    return;
                }
            } catch { /* активного SW ещё нет (первая установка) — читаем состояние сами */ }
            try {
                const raw = await Core.readState(env.caches);
                state = { pinned: raw.pinned, staged: raw.staged, pinIntact: null, lastError: raw.lastError, lastCheckAt: raw.lastCheckAt };
            } catch {
                state = null;
            }
        }

        async function refreshAndRender() {
            await refreshState();
            render();
        }

        function trackRegistration(reg) {
            const consider = () => {
                waiting = reg.waiting || null;
                render();
            };
            reg.addEventListener('updatefound', () => {
                const installing = reg.installing;
                if (!installing) return;
                installing.addEventListener('statechange', () => {
                    consider();
                    if (installing.state === 'activated') refreshAndRender();
                });
            });
            consider();
        }

        function watchController() {
            sw.addEventListener('controllerchange', () => {
                if (removing) return;
                if (expectingChange) {
                    expectingChange = false;
                    reload();
                    return;
                }
                // Никто его не просил: новый SW занял место сам (skipWaiting/claim). Это не обновление.
                env.ui.showWarning();
            });
            sw.addEventListener('message', (event) => {
                const data = event && event.data;
                if (!data || data.nyxoSw !== 1) return;
                if (data.type === 'applied' && !appliedByUs) reloadNeeded = true;
                refreshAndRender();
            });
        }

        // silent — автоматическая проверка (при загрузке и раз в час): результат в профиле не пишем,
        // иначе на первом визите, пока SW ещё устанавливается, там появилось бы «служба не отвечает».
        async function checkNow(force, { silent = false } = {}) {
            if (!silent) {
                checkText = 'Проверяю…';
                render();
            }
            try {
                const reply = await ask({ type: Core.MSG.CHECK, force: Boolean(force) }, CHECK_TIMEOUT_MS);
                if (reply && reply.ok) {
                    state = reply.state;
                    if (!silent) checkText = RESULT_TEXT[reply.result && reply.result.action] || '';
                } else if (!silent) {
                    checkText = 'Проверка не удалась' + (reply && reply.message ? ': ' + reply.message : '.');
                }
            } catch {
                if (!silent) checkText = 'Служба проверки кода не отвечает.';
            }
            render();
        }

        // Аварийное снятие: убрать регистрацию и всё, что создал SW. IndexedDB и localStorage (ключи E2EE)
        // не трогаем — только свои кэши.
        async function removeProtection() {
            removing = true;
            try {
                const registrations = sw && sw.getRegistrations ? await sw.getRegistrations() : [];
                await Promise.all(registrations.map((reg) => reg.unregister()));
                if (env.caches) await Core.clearOwnCaches(env.caches);
            } catch { /* что не удалось — снимется при следующей загрузке */ }
        }

        async function registerWorker() {
            try {
                registration = await sw.register('/sw.js', { scope: '/', updateViaCache: 'none' });
            } catch {
                registerFailed = true;
                render();
                return false;
            }
            trackRegistration(registration);
            return true;
        }

        async function start() {
            const flag = parseSwFlag(env.location.search);
            if (flag === 'off') env.storage.set(OFF_KEY, '1');
            if (flag === 'on') env.storage.remove(OFF_KEY);
            if (flag) env.ui.cleanUrl();

            plan = registrationPlan({
                hostname: env.hostname,
                isSecureContext: env.isSecureContext,
                hasServiceWorker: Boolean(sw),
                disabledByUser: env.storage.get(OFF_KEY) === '1',
            });
            if (plan.mode === 'disabled') {
                await removeProtection();
                removing = false;
            }
            render();
            if (plan.mode !== 'register') return;

            watchController();
            if (!(await registerWorker())) return;
            await refreshAndRender();
            checkNow(false, { silent: true });
            timers.setInterval(() => {
                if (registration) registration.update().catch(() => {});
                checkNow(false, { silent: true });
            }, CHECK_EVERY_MS);
        }

        // «Обновить» / «Закрепить» / «Перезагрузить» в баннере.
        async function apply() {
            const banner = view().banner;
            if (!banner) return;
            applyError = '';
            if (banner.kind === 'reload') {
                reload();
                return;
            }
            if (banner.kind === 'update') {
                appliedByUs = true;
                let reply;
                try {
                    // Отпечаток из баннера: согласие относится к ЭТОЙ версии, а не к «чему-то скачанному».
                    reply = await ask({ type: Core.MSG.APPLY, sha256: state.staged.sha256 }, ASK_TIMEOUT_MS);
                } catch {
                    reply = { ok: false, reason: 'no-reply' };
                }
                if (!reply || !reply.ok) {
                    appliedByUs = false;
                    applyError = APPLY_FAILURE_TEXT[reply && reply.reason] || 'Обновить не удалось.';
                    await refreshState();
                    render();
                    return;
                }
            }
            if (waiting) {
                expectingChange = true;
                waiting.postMessage({ type: Core.MSG.SKIP_WAITING });
                // Страница могла быть не под управлением SW — controllerchange тогда не придёт.
                timers.setTimeout(reload, ACTIVATION_FALLBACK_MS);
                return;
            }
            reload();
        }

        function dismiss() {
            const banner = view().banner;
            if (banner) dismissed.add(banner.key);
            render();
        }

        // Кнопка в профиле. Отключение — с подтверждением вторым нажатием, включение — сразу.
        async function toggleProtection() {
            const toggle = view().toggle;
            if (!toggle) return;
            if (toggle.action === 'enable') {
                env.storage.remove(OFF_KEY);
                reload();
                return;
            }
            if (!pendingDisable) {
                pendingDisable = true;
                render();
                timers.setTimeout(() => {
                    pendingDisable = false;
                    render();
                }, CONFIRM_WINDOW_MS);
                return;
            }
            pendingDisable = false;
            env.storage.set(OFF_KEY, '1');
            await removeProtection();
            reload();
        }

        return {
            start, apply, dismiss, toggleProtection,
            checkNow: () => checkNow(true),
            view,
            // Для тестов.
            _state: () => ({ plan, state, waiting, reloadNeeded, expectingChange }),
        };
    }

    // ---------- Привязка к странице ----------

    function safeStorage(storage) {
        return {
            get(key) { try { return storage.getItem(key); } catch { return null; } },
            set(key, value) { try { storage.setItem(key, value); } catch { /* без хранилища флаг не сохранится */ } },
            remove(key) { try { storage.removeItem(key); } catch { /* то же */ } },
        };
    }

    function bindDom(win, doc) {
        const $ = (id) => doc.getElementById(id);
        const banner = $('code-banner');
        const bannerText = $('code-banner-text');
        const bannerApply = $('code-banner-apply');
        const bannerDismiss = $('code-banner-dismiss');
        const warning = $('code-warning-modal');
        const profileStatus = $('code-protection-status');
        const profileCheck = $('code-protection-check');
        const profileToggle = $('code-protection-toggle');
        if (!banner || !bannerText || !bannerApply || !bannerDismiss) return null;

        const driver = createDriver({
            serviceWorker: win.navigator && win.navigator.serviceWorker ? win.navigator.serviceWorker : null,
            caches: win.caches || null,
            hostname: win.location.hostname,
            isSecureContext: win.isSecureContext,
            storage: safeStorage(win.localStorage),
            location: { get search() { return win.location.search; }, reload: () => win.location.reload() },
            ui: {
                render(view) {
                    const shown = Boolean(view.banner);
                    banner.classList.toggle('hidden', !shown);
                    if (shown) {
                        bannerText.textContent = view.banner.text;
                        bannerApply.textContent = view.banner.apply || '';
                        bannerApply.classList.toggle('hidden', !view.banner.apply);
                        bannerDismiss.textContent = view.banner.dismiss || '';
                        bannerDismiss.classList.toggle('hidden', !view.banner.dismiss);
                    }
                    if (profileStatus) profileStatus.textContent = view.status;
                    if (profileCheck) profileCheck.classList.toggle('hidden', !view.canCheck);
                    if (profileToggle) {
                        profileToggle.classList.toggle('hidden', !view.toggle);
                        if (view.toggle) profileToggle.textContent = view.toggle.label;
                    }
                },
                showWarning() {
                    if (!warning) return;
                    if (typeof win.openModal === 'function') win.openModal(warning);
                    else {
                        warning.classList.remove('hidden');
                        const overlay = $('overlay');
                        if (overlay) overlay.classList.remove('hidden');
                    }
                },
                cleanUrl() {
                    // Флаг ?sw=… сделал своё дело — в адресной строке и истории ему не место.
                    try {
                        const url = new URL(win.location.href);
                        url.searchParams.delete('sw');
                        win.history.replaceState(win.history.state, '', url.pathname + url.search + url.hash);
                    } catch { /* адрес останется как есть */ }
                },
            },
        });

        bannerApply.addEventListener('click', () => { driver.apply(); });
        bannerDismiss.addEventListener('click', () => { driver.dismiss(); });
        if (profileCheck) profileCheck.addEventListener('click', () => { driver.checkNow(); });
        if (profileToggle) profileToggle.addEventListener('click', () => { driver.toggleProtection(); });
        return driver;
    }

    function init() {
        if (typeof window === 'undefined' || typeof document === 'undefined') return null;
        const driver = bindDom(window, document);
        if (!driver) return null;
        // Регистрация — после загрузки страницы: скачивание файлов для проверки не должно конкурировать с первым открытием.
        const run = () => { driver.start(); };
        if (document.readyState === 'complete') window.setTimeout(run, 1500);
        else window.addEventListener('load', () => window.setTimeout(run, 1500));
        return driver;
    }

    const api = { OFF_KEY, VERIFY_URL, TEXT, isDevHost, parseSwFlag, registrationPlan, buildView, createDriver, bindDom, init };
    if (typeof window !== 'undefined' && typeof document !== 'undefined' && !(typeof module !== 'undefined' && module.exports)) {
        api.driver = init();
    }
    return api;
});
