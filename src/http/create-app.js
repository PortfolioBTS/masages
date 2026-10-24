'use strict';
// Экземпляр Express: доверие к одному прокси и оборачивание async-обработчиков маршрутов
// (ошибка async-обработчика уходит в обработчик ошибок, а не роняет процесс).
// Цепочка middleware и маршрутов выстраивается позже, в http/app.js. Вынесено из server.js.

const express = require('express');

// Express 4 не перехватывает отклонённые промисы из async-хендлеров: любое
// исключение вне try (например, text.trim() у числа вместо строки) давало
// unhandledRejection, и Node завершал ВЕСЬ процесс — один кривой запрос от
// любого залогиненного пользователя клал сервер. Оборачиваем все маршруты
// (включая регистрируемые в lib/*), чтобы ошибка ушла в error-middleware.
function wrapAsync(handler) {
    if (typeof handler !== 'function' || handler.length === 4) return handler;
    return function asyncSafeHandler(req, res, next) {
        const result = handler(req, res, next);
        if (result && typeof result.catch === 'function') result.catch(next);
        return result;
    };
}

function createApp() {
    const app = express();
    app.set('trust proxy', 1);
    // Express по умолчанию сообщает в каждом ответе «X-Powered-By: Express»: лишняя подсказка о стеке (R1 п.9).
    app.disable('x-powered-by');

    for (const method of ['get', 'post', 'put', 'delete']) {
        const original = app[method].bind(app);
        // app.get('name') с одним аргументом — это чтение настройки, не маршрут.
        app[method] = (routePath, ...handlers) =>
            handlers.length === 0 ? original(routePath) : original(routePath, ...handlers.map(wrapAsync));
    }

    return { app };
}

module.exports = { createApp };
