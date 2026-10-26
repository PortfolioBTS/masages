'use strict';
// Активность анонимных аккаунтов (lib/anon-activity.js): кэш процесса поверх users.last_active_at.
// Вынесено из server.js.

const { createAnonActivity } = require('../../lib/anon-activity');

function createActivity(ctx) {
    const { dbGet, dbRun } = ctx;

    // ---- Срок жизни анонимного аккаунта (lib/anon-lifetime.js, lib/anon-activity.js) ----
    //
    // Аккаунт удаляется после выбранного срока БЕЗ АКТИВНОСТИ (30 минут /
    // сутки / неделя); потолка от создания нет. Активность — HTTP-запрос
    // (middleware после sessionMiddleware) и открытый сокет: подключение,
    // отключение последнего и touch раз в 2,5 минуты (задача touchOnlineSockets).
    // Источник истины — users.last_active_at (корзина 5 минут, округление
    // вверх): по нему удаляет purgeExpiredAnonymousUsers, его же видят другие
    // экземпляры сервера; anonActivity — кэш процесса поверх него.
    const anonActivity = createAnonActivity({ dbGet, dbRun });

    return { anonActivity };
}

module.exports = { createActivity };
