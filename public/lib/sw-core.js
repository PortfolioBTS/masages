// Ядро service worker (6.2, roadmap R10): закрепление кода клиента.
//
// Идея. При первом визите service worker скачивает /client-manifest.json и все
// файлы из него, сверяет SHA-256 каждого и кладёт в Cache API только совпавшие.
// Отпечаток версии — SHA-256 самого манифеста — закрепляется (TOFU: доверие к
// первому визиту). Дальше страница и скрипты отдаются из этого кэша, а не с
// сервера. Если сервер начал отдавать другой манифест, SW НЕ подменяет код:
// новая версия скачивается и проверяется в фоне («staged»), пользователь видит
// баннер, и закрепление переключается только по его согласию (сообщение APPLY).
//
// Почему обновление не привязано к версии самого sw.js. Новый sw.js, поставленный
// браузером, становится активным сам, как только закрыты все вкладки. Если бы
// версия кода зависела от версии SW, такое «молчаливое» включение подменило бы
// код без согласия. Поэтому закрепление хранится как данные (кэш состояния), а не
// как свойство скрипта: любой SW отдаёт ту версию, на которую указывает
// состояние, пока пользователь не согласится на другую.
//
// Что хранится (всё в Cache API — одно хранилище, оно же очищается целиком):
//   nyxo-sw-state-v1      запись /__nyxo-sw/state.json: pinned, staged, lastError, lastCheckAt;
//   nyxo-shell-v1-<sha>   файлы версии + её манифест (манифест кладётся ПОСЛЕДНИМ).
//
// Что НИКОГДА не кэшируется: /api/*, /socket.io/*, /uploads/* (личные данные),
// сам /sw.js и /client-manifest.json. Для них SW не вмешивается. А в кэш
// попадают только файлы, перечисленные в проверенном манифесте и совпавшие по
// хэшу и размеру: чужой путь в кэш попасть не может.
//
// Файл исполняется и в service worker (importScripts), и на странице
// (window.NyxoSwCore — чтение состояния), и в Node (test/sw-core.test.js).
// Всё, что зависит от среды (fetch, caches, часы, блокировки), приходит в
// createController параметрами — поэтому логика проверяется юнит-тестами без браузера.
//
// Честные ограничения (подробнее — docs/threat-model.md):
//   * первый визит — доверие без проверки (TOFU);
//   * сервер может выдать новый sw.js, и браузер его поставит: мы лишь
//     добиваемся, чтобы замену увидела уже работающая страница (баннер или
//     предупреждение о неожиданном controllerchange);
//   * очистка данных сайта снимает закрепление.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./client-verify'));
    } else {
        root.NyxoSwCore = factory(root.NyxoClientVerify);
    }
})(typeof self !== 'undefined' ? self : this, function (Verify) {
    'use strict';

    const MANIFEST_PATH = '/client-manifest.json';
    const SW_PATH = '/sw.js';
    const STATE_CACHE = 'nyxo-sw-state-v1';
    const STATE_PATH = '/__nyxo-sw/state.json';
    const SHELL_PREFIX = 'nyxo-shell-v1-';
    // Всё, что создаёт SW, начинается с этого префикса — по нему «аварийное снятие» чистит только своё.
    const OWN_CACHE_PREFIX = 'nyxo-';

    // Адреса, с которыми SW не работает вообще (ответ приходит прямо из сети).
    const NETWORK_ONLY_PREFIXES = Object.freeze(['/api', '/socket.io', '/uploads']);
    const NETWORK_ONLY_PATHS = Object.freeze([SW_PATH, MANIFEST_PATH]);

    // Как часто SW сам спрашивает манифест (при навигации) и через сколько повторяет неудачную проверку.
    const CHECK_INTERVAL_MS = 10 * 60 * 1000;
    const RETRY_FAILED_MS = 15 * 60 * 1000;
    const DOWNLOAD_CONCURRENCY = 4;

    // Защита хранилища от манифеста-«бомбы». Реальный клиент — ~30 файлов и ~1 МБ.
    const LIMITS = Object.freeze({ files: 300, fileBytes: 8 * 1024 * 1024, totalBytes: 32 * 1024 * 1024 });

    const SHA256_RE = /^[0-9a-f]{64}$/;

    // Сообщения страница -> SW (postMessage; ответ приходит в MessageChannel). Одна таблица на обе стороны.
    //   SKIP_WAITING  — активировать ожидающий SW; страница шлёт его только после «Обновить»;
    //   CHECK         — проверить манифест сейчас (по запросу пользователя и раз в час);
    //   APPLY         — переключить закрепление на скачанную версию (с отпечатком из баннера);
    //   GET_STATE     — состояние закрепления для баннера и профиля.
    const MSG = Object.freeze({ SKIP_WAITING: 'SKIP_WAITING', CHECK: 'CHECK', APPLY: 'APPLY', GET_STATE: 'GET_STATE' });

    function requireVerify() {
        if (!Verify) throw new Error('lib/client-verify.js не загружен');
        return Verify;
    }

    // ---------- Чистые функции ----------

    function shellCacheName(sha256) {
        return SHELL_PREFIX + sha256;
    }

    // Отпечаток для людей: первые groups*4 hex-символов группами по 4, заглавными («3F2A 91C0 7B11»).
    function formatFingerprint(hex, groups) {
        const count = Number.isInteger(groups) && groups > 0 ? groups : 6;
        const clean = String(hex || '').toLowerCase().replace(/[^0-9a-f]/g, '');
        const chunks = clean.slice(0, count * 4).toUpperCase().match(/.{1,4}/g);
        return chunks ? chunks.join(' ') : '';
    }

    function isNetworkOnlyPath(pathname) {
        // Регистр не различаем: Express отвечает на /API/... так же, как на /api/....
        const lower = String(pathname).toLowerCase();
        if (NETWORK_ONLY_PATHS.includes(lower)) return true;
        return NETWORK_ONLY_PREFIXES.some((prefix) => lower === prefix || lower.startsWith(prefix + '/'));
    }

    // Решает синхронно (respondWith нельзя вызвать «потом»), вмешиваться ли SW.
    //   { kind: 'network', reason }  — SW не трогает запрос;
    //   { kind: 'shell', pathname }  — кандидат на отдачу из закреплённой оболочки
    //                                  (попадает ли путь в манифест, решает controller.respond).
    // request: { method, url, cache, headers }.
    function routeFor(request, origin) {
        if (!request || request.method !== 'GET') return { kind: 'network', reason: 'method' };
        let url;
        try {
            url = new URL(request.url);
        } catch {
            return { kind: 'network', reason: 'url' };
        }
        if (url.origin !== origin) return { kind: 'network', reason: 'origin' };
        if (isNetworkOnlyPath(url.pathname)) return { kind: 'network', reason: 'network-only' };
        // cache:'no-store' ставит страница сверки (/verify.html): ей нужны байты, которые сервер
        // отдаёт СЕЙЧАС, а не копия из кэша. Решает код страницы, сервер на это не влияет.
        if (request.cache === 'no-store') return { kind: 'network', reason: 'no-store' };
        if (request.headers && typeof request.headers.has === 'function' && request.headers.has('range')) {
            return { kind: 'network', reason: 'range' };
        }
        return { kind: 'shell', pathname: url.pathname };
    }

    // Индекс манифеста для быстрого поиска: путь -> запись файла, алиасы.
    function indexManifest(manifest) {
        const files = new Map(manifest.files.map((file) => [file.path, file]));
        return { files, aliases: Object.assign({}, manifest.aliases || {}) };
    }

    // Файл манифеста, которым отвечает адрес, либо null. Совпадение — только точное: чужой путь
    // (в том числе под /api) отсюда не проходит.
    function resolveShellPath(pathname, index) {
        let target = pathname;
        if (Object.prototype.hasOwnProperty.call(index.aliases, target)) target = index.aliases[target];
        return index.files.has(target) ? target : null;
    }

    // Требования к манифесту сверх формата (client-verify.parseManifest): пути, лимиты, алиас «/».
    // Возвращает список проблем (пустой — манифест годится).
    function manifestPolicyProblems(manifest) {
        const problems = [];
        if (manifest.files.length > LIMITS.files) problems.push(`слишком много файлов (${manifest.files.length})`);
        let total = 0;
        for (const file of manifest.files) {
            total += file.bytes;
            if (/[?#\\]/.test(file.path)) problems.push(`недопустимый путь ${file.path}`);
            else if (isNetworkOnlyPath(file.path)) problems.push(`путь ${file.path} нельзя кэшировать`);
            if (file.bytes > LIMITS.fileBytes) problems.push(`файл ${file.path} слишком большой (${file.bytes} байт)`);
        }
        if (total > LIMITS.totalBytes) problems.push(`общий размер файлов слишком велик (${total} байт)`);
        const aliases = manifest.aliases || {};
        if (aliases['/'] !== '/index.html') problems.push('в манифесте нет алиаса «/» на /index.html');
        return problems;
    }

    // Что можно взять из прежней версии, а что качать: файл с тем же хэшем и размером не качается заново.
    function planDownloads(previousManifest, nextManifest) {
        const previous = new Map(((previousManifest && previousManifest.files) || []).map((file) => [file.path, file]));
        const reuse = [];
        const download = [];
        for (const file of nextManifest.files) {
            const before = previous.get(file.path);
            const same = before && before.sha256 === file.sha256 && before.bytes === file.bytes;
            (same ? reuse : download).push(file.path);
        }
        return { reuse, download };
    }

    // Решение «что делать с манифестом, который сейчас отдаёт сервер».
    //   state          — сохранённое состояние;
    //   pinIntact      — кэш закреплённой версии цел (есть все файлы);
    //   stagedIntact   — кэш скачанной версии цел;
    //   observedSha256 — отпечаток манифеста с сервера.
    // action:
    //   'pin'          закрепить (первый визит или закрепления нет);
    //   'restore'      сервер отдаёт ту же версию, но кэш повреждён — докачать;
    //   'none'         ничего не изменилось;
    //   'drop-staged'  сервер вернулся к закреплённой версии — скачанную новую выбросить;
    //   'wait-user'    новая версия уже скачана, ждём согласия;
    //   'wait-retry'    такая версия недавно не прошла проверку — не долбить сервер;
    //   'stage'        скачать и проверить новую версию.
    function decideUpdate({ state, pinIntact, stagedIntact, observedSha256, now, force }) {
        const pinned = state.pinned;
        if (!pinned) return { action: 'pin' };
        if (observedSha256 === pinned.sha256) {
            if (!pinIntact) return { action: 'restore' };
            return { action: state.staged ? 'drop-staged' : 'none' };
        }
        if (state.staged && state.staged.sha256 === observedSha256 && stagedIntact) return { action: 'wait-user' };
        const failure = state.lastError;
        if (!force && failure && failure.sha256 === observedSha256 && now - failure.at < RETRY_FAILED_MS) {
            return { action: 'wait-retry' };
        }
        return { action: 'stage' };
    }

    // Несколько первых проблем одной строкой для пользователя.
    function summarizeProblems(problems) {
        if (problems.length === 0) return '';
        const head = problems.slice(0, 3).join('; ');
        return problems.length > 3 ? `${head}; и ещё ${problems.length - 3}` : head;
    }

    // ---------- Состояние ----------

    function emptyState() {
        return { v: 1, pinned: null, staged: null, lastError: null, lastCheckAt: 0 };
    }

    function pinOf(raw) {
        return raw && typeof raw.sha256 === 'string' && SHA256_RE.test(raw.sha256)
            ? { sha256: raw.sha256, at: Number(raw.at) || 0 }
            : null;
    }

    // Состояние читается из хранилища, которое мог испортить кто угодно: форма проверяется строго.
    function normalizeState(raw) {
        const state = emptyState();
        if (!raw || typeof raw !== 'object' || raw.v !== 1) return state;
        state.pinned = pinOf(raw.pinned);
        state.staged = pinOf(raw.staged);
        if (state.staged && state.pinned && state.staged.sha256 === state.pinned.sha256) state.staged = null;
        const failure = raw.lastError;
        if (failure && typeof failure.message === 'string') {
            state.lastError = {
                at: Number(failure.at) || 0,
                sha256: typeof failure.sha256 === 'string' && SHA256_RE.test(failure.sha256) ? failure.sha256 : null,
                message: failure.message.slice(0, 500),
            };
        }
        state.lastCheckAt = Number(raw.lastCheckAt) || 0;
        return state;
    }

    // Нет записи или она не разбирается — пустое состояние (закрепления нет). Ошибка самого
    // хранилища НЕ превращается в «пустое состояние»: иначе временный сбой чтения привёл бы к
    // повторному закреплению (TOFU) поверх настоящего. Её бросаем выше.
    async function readState(cachesApi) {
        const cache = await cachesApi.open(STATE_CACHE);
        const response = await cache.match(STATE_PATH);
        if (!response) return emptyState();
        let raw = null;
        try {
            raw = await response.json();
        } catch {
            raw = null;
        }
        return normalizeState(raw);
    }

    async function writeState(cachesApi, state) {
        const cache = await cachesApi.open(STATE_CACHE);
        await cache.put(STATE_PATH, new Response(JSON.stringify(state), {
            status: 200,
            headers: { 'content-type': 'application/json; charset=utf-8' },
        }));
    }

    // Сносит всё, что создано этим SW (аварийное снятие, «Отключить защиту кода»).
    async function clearOwnCaches(cachesApi) {
        const names = await cachesApi.keys();
        await Promise.all(names.filter((name) => name.startsWith(OWN_CACHE_PREFIX)).map((name) => cachesApi.delete(name)));
    }

    // ---------- Ошибки загрузки ----------

    // transient — ошибка, которая пройдёт сама (нет сети, 5xx): о ней пользователю не пишем,
    // проверка повторится позже. Остальное — настоящая причина не принимать версию.
    class SwProblem extends Error {
        constructor(message, { transient = false, sha256 = null } = {}) {
            super(message);
            this.name = 'SwProblem';
            this.transient = transient;
            this.sha256 = sha256;
        }
    }

    // Лёгкий способ ограничить число одновременных загрузок.
    async function runPool(items, limit, worker) {
        let next = 0;
        const run = async () => {
            while (next < items.length) await worker(items[next++]);
        };
        await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
    }

    function makeChain() {
        let tail = Promise.resolve();
        return (fn) => {
            const result = tail.then(fn, fn);
            tail = result.catch(() => {});
            return result;
        };
    }

    // ---------- Контроллер ----------
    //
    // env:
    //   caches   — CacheStorage (в SW — self.caches, в тестах — подделка);
    //   fetch    — fetch (в тестах — настоящий, против локального сервера);
    //   origin   — origin сайта ('https://host'), для routeFor и адресов;
    //   now      — часы (мс);
    //   digest   — async (ArrayBuffer) => hex SHA-256 (по умолчанию crypto.subtle);
    //   lock     — (fn) => Promise: взаимное исключение между экземплярами SW (Web Locks);
    //   notify   — (событие) => void: сообщить открытым страницам, что состояние изменилось;
    //   log      — (...args) => void.
    function createController(env) {
        const cachesApi = env.caches;
        const doFetch = env.fetch;
        const now = env.now || Date.now;
        const origin = env.origin;
        const notify = env.notify || (() => {});
        const log = env.log || (() => {});
        const lock = env.lock || makeChain();
        const digest = env.digest || (async (buffer) => requireVerify().toHex(await crypto.subtle.digest('SHA-256', buffer)));

        // Разобранные манифесты закреплённых версий: чтение и хэширование один раз на жизнь экземпляра SW.
        const indexMemo = new Map();
        let checking = null;

        const absolute = (path) => origin + path;

        // Запрос к серверу «как есть»: без кэша браузера и без кук (оболочка — не личные данные).
        // Редирект не следуем: подмена адреса перенаправлением — тоже расхождение.
        async function request(path) {
            let response;
            try {
                response = await doFetch(absolute(path), { cache: 'no-store', credentials: 'omit', redirect: 'manual' });
            } catch {
                throw new SwProblem('нет соединения с сервером', { transient: true });
            }
            if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
                throw new SwProblem(`${path}: сервер перенаправляет запрос`);
            }
            if (response.status >= 500 || response.status === 429 || response.status === 408) {
                throw new SwProblem(`${path}: сервер ответил HTTP ${response.status}`, { transient: true });
            }
            if (response.status !== 200 || response.type === 'opaque' || response.type === 'error') {
                throw new SwProblem(`${path}: сервер ответил HTTP ${response.status}`);
            }
            return response;
        }

        // Манифест с сервера: исходные байты (кэш хранит именно их, отпечаток считается от них же),
        // отпечаток, разбор. Любая проблема с самим манифестом — SwProblem с отпечатком (чтобы не
        // пытаться снова и снова с тем же).
        async function fetchManifest() {
            const response = await request(MANIFEST_PATH);
            const buffer = await response.arrayBuffer();
            const sha256 = await digest(buffer);
            const text = new TextDecoder().decode(buffer);
            let manifest;
            try {
                manifest = requireVerify().parseManifest(text);
            } catch (err) {
                throw new SwProblem(`манифест не принят: ${err.message}`, { sha256 });
            }
            const policy = manifestPolicyProblems(manifest);
            if (policy.length > 0) throw new SwProblem(`манифест не принят: ${summarizeProblems(policy)}`, { sha256 });
            return { sha256, buffer, manifest };
        }

        // Полнота и целостность кэша версии: манифест в нём хэшируется в имя кэша, все файлы на месте.
        // Содержимое файлов здесь не пересчитывается (оно проверено при записи).
        async function shellStatus(sha256) {
            const name = shellCacheName(sha256);
            if (!(await cachesApi.has(name))) return { intact: false, manifest: null, missing: [] };
            const cache = await cachesApi.open(name);
            const stored = await cache.match(MANIFEST_PATH);
            if (!stored) return { intact: false, manifest: null, missing: [] };
            const bytes = await stored.arrayBuffer();
            if ((await digest(bytes)) !== sha256) return { intact: false, manifest: null, missing: [] };
            let manifest;
            try {
                manifest = requireVerify().parseManifest(new TextDecoder().decode(bytes));
            } catch {
                return { intact: false, manifest: null, missing: [] };
            }
            const present = new Set((await cache.keys()).map((key) => new URL(key.url).pathname));
            const missing = manifest.files.filter((file) => !present.has(file.path)).map((file) => file.path);
            return { intact: missing.length === 0, manifest, missing };
        }

        // Индекс закреплённой версии для отдачи файлов; null — кэш версии непригоден.
        async function pinnedIndex(sha256) {
            if (indexMemo.has(sha256)) return indexMemo.get(sha256);
            const name = shellCacheName(sha256);
            if (!(await cachesApi.has(name))) return null;
            const cache = await cachesApi.open(name);
            const stored = await cache.match(MANIFEST_PATH);
            if (!stored) return null;
            const bytes = await stored.arrayBuffer();
            if ((await digest(bytes)) !== sha256) return null;
            let index;
            try {
                index = indexManifest(requireVerify().parseManifest(new TextDecoder().decode(bytes)));
            } catch {
                return null;
            }
            indexMemo.set(sha256, index);
            return index;
        }

        // Скачивает файл и сверяет хэш и размер. Возвращает нетронутую копию ответа для кэша.
        async function fetchVerified(file) {
            const response = await request(file.path);
            const copy = response.clone();
            const buffer = await response.arrayBuffer();
            return { copy, sha256: await digest(buffer), bytes: buffer.byteLength };
        }

        // Собирает кэш версии: сначала файлы (из прежней версии или из сети), манифест — последним.
        // Любая проблема — кэш удаляется целиком и бросается SwProblem: наполовину собранной версии не бывает.
        async function buildShell({ sha256, buffer, manifest, previous }) {
            const name = shellCacheName(sha256);
            await cachesApi.delete(name);
            const cache = await cachesApi.open(name);
            try {
                const plan = planDownloads(previous && previous.manifest, manifest);
                const byPath = new Map(manifest.files.map((file) => [file.path, file]));
                const seen = {};
                const ready = new Map();
                const issues = [];

                // Файлы, не изменившиеся с прошлой версии, берём из её кэша — но хэш пересчитываем.
                const toDownload = [...plan.download];
                for (const path of plan.reuse) {
                    let taken = false;
                    try {
                        const hit = previous.cache && await previous.cache.match(path);
                        if (hit) {
                            const copy = hit.clone();
                            const buffer = await hit.arrayBuffer();
                            const actual = await digest(buffer);
                            if (actual === byPath.get(path).sha256 && buffer.byteLength === byPath.get(path).bytes) {
                                ready.set(path, copy);
                                seen[path] = { sha256: actual, bytes: buffer.byteLength };
                                taken = true;
                            }
                        }
                    } catch {
                        taken = false;
                    }
                    if (!taken) toDownload.push(path);
                }

                let transientFailure = null;
                await runPool(toDownload, DOWNLOAD_CONCURRENCY, async (path) => {
                    try {
                        const got = await fetchVerified(byPath.get(path));
                        ready.set(path, got.copy);
                        seen[path] = { sha256: got.sha256, bytes: got.bytes };
                    } catch (err) {
                        if (!(err instanceof SwProblem)) throw err;
                        if (err.transient) transientFailure = transientFailure || err;
                        else issues.push(err.message);
                    }
                });

                const compared = requireVerify().compareObserved({ files: manifest.files, aliases: {} }, seen);
                // Файл, которого нет в seen из-за сетевой ошибки, не должен считаться «расхождением».
                for (const entry of compared.entries) {
                    if (entry.state === 'mismatch') issues.push(`${entry.path}: ${entry.detail}`);
                }
                if (issues.length > 0) throw new SwProblem(`файлы не совпали с манифестом: ${summarizeProblems(issues)}`, { sha256 });
                if (transientFailure) throw new SwProblem(transientFailure.message, { transient: true });

                for (const file of manifest.files) await cache.put(file.path, ready.get(file.path));
                await cache.put(MANIFEST_PATH, new Response(buffer, {
                    status: 200,
                    headers: { 'content-type': 'application/json; charset=utf-8' },
                }));
            } catch (err) {
                await cachesApi.delete(name).catch(() => {});
                throw err;
            }
        }

        // Удаляет кэши версий, на которые не указывает состояние. Вызывать под lock.
        async function cleanupShells(state) {
            const keep = new Set();
            if (state.pinned) keep.add(shellCacheName(state.pinned.sha256));
            if (state.staged) keep.add(shellCacheName(state.staged.sha256));
            for (const name of await cachesApi.keys()) {
                if (name.startsWith(SHELL_PREFIX) && !keep.has(name)) await cachesApi.delete(name);
            }
            for (const key of [...indexMemo.keys()]) {
                if (!keep.has(shellCacheName(key))) indexMemo.delete(key);
            }
        }

        async function previousOf(state) {
            if (!state.pinned) return null;
            const status = await shellStatus(state.pinned.sha256);
            if (!status.manifest) return null;
            return { manifest: status.manifest, cache: await cachesApi.open(shellCacheName(state.pinned.sha256)) };
        }

        async function save(state, event) {
            await writeState(cachesApi, state);
            if (event) notify(event);
        }

        async function failWith(state, err, observedSha256) {
            state.lastError = { at: now(), sha256: err.sha256 || observedSha256 || null, message: err.message };
            await save(state, { type: 'update-failed' });
            return { action: 'failed', message: err.message };
        }

        // Одна проверка: спросить манифест, решить, скачать и проверить новую версию. Под lock.
        // force — не пропускать из-за недавней проверки и недавней неудачи (запрос пользователя).
        async function checkOnce({ force }) {
            const state = await readState(cachesApi);
            if (!force && state.pinned && now() - state.lastCheckAt < CHECK_INTERVAL_MS) return { action: 'skipped' };

            let observed;
            try {
                observed = await fetchManifest();
            } catch (err) {
                if (!(err instanceof SwProblem)) throw err;
                if (err.transient) return { action: 'offline' };
                state.lastCheckAt = now();
                return failWith(state, err, err.sha256);
            }

            state.lastCheckAt = now();
            const pinStatus = state.pinned ? await shellStatus(state.pinned.sha256) : null;
            const stagedStatus = state.staged ? await shellStatus(state.staged.sha256) : null;
            const decision = decideUpdate({
                state,
                pinIntact: Boolean(pinStatus && pinStatus.intact),
                stagedIntact: Boolean(stagedStatus && stagedStatus.intact),
                observedSha256: observed.sha256,
                now: now(),
                force,
            });

            try {
                switch (decision.action) {
                case 'none':
                case 'wait-user':
                case 'wait-retry': {
                    // Сервер вернулся к закреплённой версии (или ждёт согласия): прошлую ошибку, если
                    // она была про другую версию, показывать незачем.
                    const stale = decision.action === 'none' && state.lastError;
                    if (stale) state.lastError = null;
                    await save(state, stale ? { type: 'state-changed' } : null);
                    return { action: decision.action };
                }
                case 'drop-staged': {
                    state.staged = null;
                    state.lastError = null;
                    await save(state, { type: 'state-changed' });
                    await cleanupShells(state);
                    return { action: decision.action };
                }
                case 'pin':
                case 'restore': {
                    // Прежний кэш при restore — тот же самый (его пересоздаём), при pin прежней версии нет.
                    await buildShell({ sha256: observed.sha256, buffer: observed.buffer, manifest: observed.manifest, previous: null });
                    indexMemo.delete(observed.sha256);
                    state.pinned = { sha256: observed.sha256, at: now() };
                    state.staged = null;
                    state.lastError = null;
                    await save(state, { type: 'pinned' });
                    await cleanupShells(state);
                    return { action: decision.action, sha256: observed.sha256 };
                }
                case 'stage': {
                    await buildShell({ sha256: observed.sha256, buffer: observed.buffer, manifest: observed.manifest, previous: await previousOf(state) });
                    indexMemo.delete(observed.sha256);
                    state.staged = { sha256: observed.sha256, at: now() };
                    state.lastError = null;
                    await save(state, { type: 'staged' });
                    await cleanupShells(state);
                    return { action: decision.action, sha256: observed.sha256 };
                }
                default:
                    return { action: 'none' };
                }
            } catch (err) {
                if (!(err instanceof SwProblem)) throw err;
                if (err.transient) {
                    // Нет сети посреди загрузки: молча, повторим позже. lastCheckAt сбросим, чтобы не ждать 10 минут.
                    state.lastCheckAt = 0;
                    await writeState(cachesApi, state);
                    return { action: 'offline' };
                }
                return failWith(state, err, observed.sha256);
            }
        }

        function checkForUpdate({ force = false } = {}) {
            return lock(() => checkOnce({ force }));
        }

        // Фоновая проверка при навигации: не чаще раза в CHECK_INTERVAL_MS, без наложения друг на друга.
        function maybeCheck() {
            if (!checking) {
                checking = checkForUpdate({ force: false }).catch((err) => {
                    log('проверка обновления не удалась', err);
                    return { action: 'error' };
                }).finally(() => { checking = null; });
            }
            return checking;
        }

        // Пользователь согласился: переключить закрепление на скачанную версию.
        // expectedSha256 — отпечаток, который человек видел в баннере: если за это время скачана другая версия,
        // молча не переключаем — баннер обновится и покажет новый отпечаток.
        function applyUpdate(expectedSha256) {
            return lock(async () => {
                const state = await readState(cachesApi);
                if (!state.staged) return { ok: false, reason: 'no-staged' };
                if (expectedSha256 && state.staged.sha256 !== expectedSha256) return { ok: false, reason: 'changed', sha256: state.staged.sha256 };
                const status = await shellStatus(state.staged.sha256);
                if (!status.intact) {
                    state.staged = null;
                    await save(state, { type: 'state-changed' });
                    await cleanupShells(state);
                    return { ok: false, reason: 'staged-broken' };
                }
                state.pinned = { sha256: state.staged.sha256, at: now() };
                state.staged = null;
                state.lastError = null;
                await save(state, { type: 'applied', sha256: state.pinned.sha256 });
                await cleanupShells(state);
                return { ok: true, sha256: state.pinned.sha256 };
            });
        }

        // Первая установка SW: закрепить то, что сервер отдаёт сейчас (TOFU). Установка SW никогда не
        // проваливается из-за проверки: без закрепления приложение просто работает как раньше, а
        // причина видна в состоянии (lastError) и повторится при следующей проверке.
        async function install() {
            try {
                await checkForUpdate({ force: true });
            } catch (err) {
                log('установка: закрепление не удалось', err);
            }
        }

        async function activate() {
            try {
                await lock(async () => cleanupShells(await readState(cachesApi)));
            } catch (err) {
                log('активация: уборка кэшей не удалась', err);
            }
        }

        // Состояние для страницы (GET_STATE): то, что видит пользователь в баннере и профиле.
        async function getPublicState() {
            const state = await readState(cachesApi);
            const pinStatus = state.pinned ? await shellStatus(state.pinned.sha256) : null;
            const stagedStatus = state.staged ? await shellStatus(state.staged.sha256) : null;
            return {
                pinned: state.pinned,
                staged: state.staged && stagedStatus && stagedStatus.intact ? state.staged : null,
                pinIntact: pinStatus ? pinStatus.intact : null,
                lastError: state.lastError,
                lastCheckAt: state.lastCheckAt,
            };
        }

        // Ответ на запрос страницы. Возвращает Response из закреплённой оболочки либо null, если
        // запрос надо отправить в сеть (не оболочка, закрепления нет). Исключение — сбой хранилища:
        // sw.js в этом случае отдаёт запрос в сеть, чтобы приложение работало.
        // background(promise) — продлить жизнь SW до конца фоновой проверки (event.waitUntil).
        async function respond(req, { background } = {}) {
            const route = routeFor(req, origin);
            if (route.kind !== 'shell') return null;
            const state = await readState(cachesApi);
            const spawn = (promise) => { if (background) background(promise); };
            if (req.mode === 'navigate') spawn(maybeCheck());
            if (!state.pinned) return null;
            const index = await pinnedIndex(state.pinned.sha256);
            if (!index) return null;
            const file = resolveShellPath(route.pathname, index);
            if (!file) return null;
            const cache = await cachesApi.open(shellCacheName(state.pinned.sha256));
            const hit = await cache.match(file);
            if (hit) return hit;
            return repairFile(cache, index.files.get(file), state.pinned.sha256, req);
        }

        // Файл закреплённой версии пропал из кэша (частичная очистка браузером): докачать, но только если
        // сервер отдаёт ровно те байты, что закреплены. Иначе — понятное сообщение, а не чужой код.
        async function repairFile(cache, file, pinnedSha256, req) {
            let got;
            try {
                got = await fetchVerified(file);
            } catch (err) {
                if (err instanceof SwProblem && !err.transient) return failureResponse(req, pinnedSha256, err.message);
                throw err;
            }
            if (got.sha256 !== file.sha256 || got.bytes !== file.bytes) {
                return failureResponse(req, pinnedSha256, `${file.path}: файл на сервере не совпадает с закреплённым`);
            }
            try {
                await cache.put(file.path, got.copy.clone());
            } catch (err) {
                log('не удалось вернуть файл в кэш', err);
            }
            return got.copy;
        }

        function failureResponse(req, pinnedSha256, detail) {
            return buildFailureResponse(req, formatFingerprint(pinnedSha256), detail);
        }

        return {
            install,
            activate,
            respond,
            checkForUpdate,
            maybeCheck,
            applyUpdate,
            getPublicState,
            // Для тестов и диагностики.
            _internals: { readState: () => readState(cachesApi), shellStatus, request },
        };
    }

    // Ответ, когда закреплённый файл нельзя ни взять из кэша, ни честно докачать. Страница без
    // скриптов: ей нельзя доверять ничего, кроме текста, и она не зависит от оболочки.
    function buildFailureResponse(req, fingerprint, detail) {
        const headers = { 'cache-control': 'no-store' };
        if (req.mode !== 'navigate') {
            headers['content-type'] = 'text/plain; charset=utf-8';
            return new Response(`Nyxo: файл не прошёл проверку закреплённой версии (${detail})`, { status: 503, headers });
        }
        const escape = (text) => String(text).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
        const body = '<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
            '<title>Nyxo — файл не прошёл проверку</title></head><body>' +
            '<h1>Nyxo не открыл страницу: файл не прошёл проверку</h1>' +
            `<p>Закреплена версия кода с отпечатком <strong>${escape(fingerprint)}</strong>. ${escape(detail)}.</p>` +
            '<p>Так бывает, если сервер обновился, а закрепление ещё нет, если браузер частично очистил данные сайта, ' +
            'или если файлы на сервере подменены. Код не загружен, чтобы не запускать непроверенное.</p>' +
            '<ol><li>Загрузите страницу в обход закрепления: Ctrl+Shift+R (на Mac — Cmd+Shift+R).</li>' +
            '<li>Сверьте файлы на странице <a href="/verify.html">проверки</a> и отпечаток с опубликованным в релизе.</li>' +
            '<li>Если всё в порядке, в профиле нажмите «Отключить защиту кода» и включите её снова — закрепится текущая версия.</li></ol>' +
            '</body></html>';
        headers['content-type'] = 'text/html; charset=utf-8';
        headers['content-security-policy'] = "default-src 'none'";
        return new Response(body, { status: 503, headers });
    }

    return {
        MSG,
        MANIFEST_PATH,
        SW_PATH,
        STATE_CACHE,
        STATE_PATH,
        SHELL_PREFIX,
        OWN_CACHE_PREFIX,
        NETWORK_ONLY_PREFIXES,
        CHECK_INTERVAL_MS,
        RETRY_FAILED_MS,
        LIMITS,
        shellCacheName,
        formatFingerprint,
        isNetworkOnlyPath,
        routeFor,
        indexManifest,
        resolveShellPath,
        manifestPolicyProblems,
        planDownloads,
        decideUpdate,
        summarizeProblems,
        emptyState,
        normalizeState,
        readState,
        writeState,
        clearOwnCaches,
        SwProblem,
        createController,
        buildFailureResponse,
    };
});
