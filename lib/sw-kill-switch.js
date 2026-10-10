'use strict';
// Аварийное снятие service worker оператором (6.2): SW_KILL_SWITCH=yes.
//
// Зачем. Закреплённый клиент работает из кэша service worker. Если закрепление
// само сломалось (ошибка в sw.js, битая версия, которую нельзя ни обновить, ни
// починить у пользователей), нужен способ вернуть людей к обычной работе без
// просьбы «очистите данные сайта». Дать его через Clear-Site-Data нельзя:
// значение "storage" заодно стёрло бы IndexedDB, то есть ключи E2EE и историю, а
// "cache" регистрацию SW не трогает. Поэтому снятие — это обычное обновление
// sw.js: при SW_KILL_SWITCH=yes адрес /sw.js отдаёт скрипт, который удаляет кэши
// закрепления (только с префиксом nyxo-) и снимает регистрацию.
//
// Как это видят пользователи (честно, без тихой подмены):
//   * новый sw.js встаёт в ожидание и не вызывает skipWaiting сам; открытая
//     страница показывает баннер «Доступно обновление службы проверки кода»,
//     кнопка «Обновить» отправляет ему SKIP_WAITING;
//   * если страницу не нажимали, скрипт включится, когда закроются все вкладки Nyxo
//     (обычное поведение ожидающего SW) — если закреплённая страница вообще не
//     открывается, этого достаточно: закрыть вкладки и открыть сайт заново;
//   * после включения при следующем визите страница снова зарегистрирует SW — он
//     снимется снова, пока переменная не убрана. Уберите её, когда причина устранена:
//     закрепление включится заново (первый визит, TOFU).
// Оператор по-прежнему может выдать любой sw.js — это свойство веба, а не этого
// переключателя (docs/threat-model.md); он лишь делает снятие явным и без побочных
// потерь.

const KILL_SCRIPT = `// Nyxo: аварийное снятие service worker (сервер запущен с SW_KILL_SWITCH=yes).
// Удаляет кэши закрепления кода (только с префиксом nyxo-) и снимает регистрацию.
// IndexedDB и localStorage — ключи шифрования и история — не затрагиваются.
// skipWaiting только по сообщению страницы (после «Обновить»); fetch-обработчика нет,
// поэтому все запросы идут в сеть.
'use strict';
self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        const names = await caches.keys();
        await Promise.all(names.filter((name) => name.startsWith('nyxo-')).map((name) => caches.delete(name)));
        await self.registration.unregister();
    })());
});
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
`;

function isEnabled(env) {
    return String((env && env.SW_KILL_SWITCH) || '').trim().toLowerCase() === 'yes';
}

// Middleware: ставить ДО express.static, иначе статика отдаст настоящий public/sw.js.
function createSwKillSwitch(env = process.env, { warn = console.warn } = {}) {
    const enabled = isEnabled(env);
    if (enabled) {
        warn('[SW] SW_KILL_SWITCH=yes: /sw.js снимает service worker у клиентов (кэши nyxo-* и регистрация). ' +
            'Уберите переменную, когда причина устранена.');
    }
    return function swKillSwitch(req, res, next) {
        if (!enabled || req.method !== 'GET' || req.path !== '/sw.js') return next();
        res.set('Content-Type', 'text/javascript; charset=utf-8');
        // Как у настоящего sw.js: браузер сверяет скрипт при каждой проверке обновления.
        res.set('Cache-Control', 'no-cache');
        res.send(KILL_SCRIPT);
    };
}

module.exports = { createSwKillSwitch, isEnabled, KILL_SCRIPT };
