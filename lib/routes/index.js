'use strict';
// Точки регистрации маршрутов, вынесенных из server.js.
//
// server.js вызывает по одной функции в нужном месте цепочки middleware:
//   * registerPreSessionRoutes(app, ctx) — до sessionMiddleware (уже после
//     заголовков, проверки Origin и статики): маршруты, которым сессия не
//     нужна и создаваться не должна, — healthz, readyz, metrics,
//     /.well-known/security.txt, манифест клиента. Проверка CSRF-токена и
//     разбор тела (express.json) идут ПОСЛЕ сессии, поэтому здесь они не
//     действуют: маршрут до сессии — только GET без тела и без кук;
//   * registerApiRoutes(app, ctx) — после sessionMiddleware, проверки
//     анонимной сессии и лимитера /api/: обычные маршруты API;
//   * registerApiNotFound(app) — после ВСЕХ маршрутов, перед обработчиком
//     ошибок: JSON-404 для неизвестных /api/*.
//
// Новый модуль маршрутов — файл lib/routes/<имя>.js с функцией
// register(app, ctx) и ОДНА строка `require('./<имя>'),` в нужном списке
// ниже. Порядок в списке — порядок регистрации в Express. Отдельные модули
// и списки здесь, а не новые строки посреди server.js, — чтобы
// параллельные задачи не правили одни и те же места большого файла.
//
// ctx собирает server.js: pool, dbGet, dbAll, dbRun, withTransaction, io,
// logError, isProduction. Маршруты регистрируются через app.get/post/put/
// delete: server.js оборачивает их обработчики, и ошибка async-обработчика
// уходит в обработчик ошибок, а не роняет процесс; app.use не оборачивается.

const PRE_SESSION_ROUTES = [
    // /healthz, /readyz, /metrics (7.6).
    require('./health'),
];

const API_ROUTES = [
];

function registerAll(modules, app, ctx) {
    for (const mod of modules) mod.register(app, ctx);
}

function registerPreSessionRoutes(app, ctx, modules = PRE_SESSION_ROUTES) {
    registerAll(modules, app, ctx);
}

function registerApiRoutes(app, ctx, modules = API_ROUTES) {
    registerAll(modules, app, ctx);
}

// Неизвестный (или удалённый) маршрут API — JSON, как у остальных ответов
// API, а не HTML-страница Express «Cannot GET»: клиент разбирает ответ как
// JSON. Небезопасный запрос без CSRF-токена сюда не доходит — ему раньше
// отвечает 403.
function registerApiNotFound(app) {
    app.use('/api', (req, res) => {
        res.status(404).json({ success: false, message: 'Не найдено' });
    });
}

module.exports = {
    registerPreSessionRoutes,
    registerApiRoutes,
    registerApiNotFound,
    PRE_SESSION_ROUTES,
    API_ROUTES,
};
