'use strict';
// Service worker Nyxo: закрепление кода клиента (6.2, roadmap R10). Здесь только
// подключение к событиям браузера; вся логика и её тесты — в lib/sw-core.js.
// Что именно закрепляется, что не кэшируется никогда и чего это НЕ защищает —
// в шапке lib/sw-core.js и в docs/threat-model.md.
//
// Этот файл в манифест клиента не входит (lib/client-manifest.js): service worker
// закрепляет хэш манифеста и не может включать в него собственный хэш (R10).
// Файлы, которые он подключает, в манифест входят.
//
// Два правила, которые нельзя менять без пересмотра модели угроз:
//   1. skipWaiting() вызывается ТОЛЬКО в ответ на сообщение страницы SKIP_WAITING,
//      то есть после того, как человек нажал «Обновить». Сам по себе новый SW
//      встаёт в очередь и ждёт: страница, увидев ожидающий SW, предупреждает.
//   2. clients.claim() не вызывается. Единственный законный controllerchange —
//      тот, что страница сама запросила; любой другой она считает подменой.

importScripts('/lib/client-verify.js', '/lib/sw-core.js');

const core = self.NyxoSwCore;

// Окна, открытые на сайте, узнают об изменении состояния (скачана новая версия, проверка не прошла).
// Сами данные они читают у SW запросом GET_STATE.
function broadcast(event) {
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
        for (const client of windows) client.postMessage({ nyxoSw: 1, type: event.type, sha256: event.sha256 || null });
    }).catch(() => {});
}

const controller = core.createController({
    caches: self.caches,
    fetch: (url, init) => self.fetch(url, init),
    origin: self.location.origin,
    now: () => Date.now(),
    // Web Locks: старый и новый экземпляры SW не должны одновременно менять закрепление.
    lock: self.navigator && self.navigator.locks ? (fn) => self.navigator.locks.request('nyxo-sw-state', fn) : undefined,
    notify: broadcast,
    log: (...args) => console.warn('[sw]', ...args),
});

self.addEventListener('install', (event) => {
    // Закрепить версию (TOFU) при самой первой установке. Ошибка проверки установку не ломает:
    // приложение работает как без SW, причина видна странице.
    event.waitUntil(controller.install());
});

self.addEventListener('activate', (event) => {
    event.waitUntil(controller.activate());
});

async function answer(event) {
    try {
        const response = await controller.respond(event.request, {
            background: (promise) => {
                try { event.waitUntil(promise); } catch { /* срок жизни события уже вышел — проверка пойдёт без продления */ }
            },
        });
        if (response) return response;
    } catch (err) {
        // Сбой хранилища (не расхождение хэша!): приложение должно работать, поэтому — в сеть.
        console.warn('[sw] ответ из кэша не удался, запрос уходит в сеть', err);
    }
    return fetch(event.request);
}

self.addEventListener('fetch', (event) => {
    // API, сокеты, вложения, чужие адреса, не-GET: SW не вмешивается, ответ приходит прямо из сети.
    if (core.routeFor(event.request, self.location.origin).kind !== 'shell') return;
    event.respondWith(answer(event));
});

self.addEventListener('message', (event) => {
    const message = event.data;
    if (!message || typeof message.type !== 'string') return;
    const reply = (payload) => {
        try {
            (event.ports && event.ports[0] ? event.ports[0] : event.source).postMessage(payload);
        } catch { /* страница уже закрыта */ }
    };
    const fail = (err) => reply({ ok: false, message: err && err.message ? err.message : 'ошибка service worker' });

    switch (message.type) {
    case core.MSG.SKIP_WAITING:
        self.skipWaiting();
        reply({ ok: true });
        break;
    case core.MSG.GET_STATE:
        event.waitUntil(controller.getPublicState().then((state) => reply({ ok: true, state }), fail));
        break;
    case core.MSG.CHECK:
        event.waitUntil(controller.checkForUpdate({ force: message.force === true }).then(
            (result) => controller.getPublicState().then((state) => reply({ ok: true, result, state })),
            fail,
        ));
        break;
    case core.MSG.APPLY:
        // Согласие относится к конкретной версии: без отпечатка из баннера ничего не переключаем.
        if (typeof message.sha256 !== 'string') {
            reply({ ok: false, reason: 'no-sha' });
            break;
        }
        event.waitUntil(controller.applyUpdate(message.sha256).then(reply, fail));
        break;
    default:
        break;
    }
});
