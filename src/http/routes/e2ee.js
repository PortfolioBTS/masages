'use strict';
// Публичные E2EE-ключи, журнал ключей и групповой E2EE (key-shares, участники, сертификаты состава).
// Регистрируются после сессии, проверки CSRF и лимитера /api. Вынесено из server.js.

// Маршруты /api/keys/* (регистрируются после sessionMiddleware — см. вызов
// registerE2eeKeyRoutes ниже) и встроенное хранилище публичных E2EE-ключей
const { registerE2eeKeyRoutes } = require('../../../lib/e2ee-keys');
const { registerKtRoutes } = require('../../../lib/kt-routes');
// Групповой E2EE: участники чата + попарная доставка Sender Key
// (key-shares). Тоже регистрируется после sessionMiddleware.
const { registerE2eeGroupRoutes } = require('../../../lib/e2ee-groups');
const { JOIN_REQUEST_LIVE_SQL } = require('../../services/rooms');
const { respondIfDeadlock } = require('../../db/transactions');

function register(app, ctx) {
    const {
        io, dbGet, dbAll, dbRun, withTransactionRetry, queryWithRetry, pgLimits, bundleLimiter,
        keyShareLimiter, keyRequestLimiter, memberCertLimiter, kt,
    } = ctx;

    // Публичные E2EE-ключи: /api/keys/* → встроенное хранилище (lib/key-store.js).
    // Регистрируется строго ПОСЛЕ sessionMiddleware — маршрутам нужна сессия.
    // Чужие ключи отдаются только при общей комнате — модулю нужна БД.
    // Регистрация identity — одной транзакцией с записью в журнал ключей; withTransactionRetry
    // (db/transactions.js) вызывается уже при запросах, поэтому передаётся оболочкой.
    registerE2eeKeyRoutes(app, { dbGet, dbAll, bundleLimiter, kt, withTransaction: (work) => withTransactionRetry(work) });
    // Журнал ключей: головы и корни — любому вошедшему, записи — по правилам доступа.
    // JOIN_REQUEST_LIVE_SQL — в services/rooms.js (условие «заявка жива»).
    registerKtRoutes(app, { dbGet, kt, limiter: pgLimits.slidingLimiter('kt'), joinRequestLiveSql: () => JOIN_REQUEST_LIVE_SQL });
    // Групповой E2EE: список участников чата + key-shares (тоже нужна сессия).
    // Транзакция member-certs (7.1) идёт через withTransactionRetry (db/transactions.js): оболочка вызывается при запросах.
    registerE2eeGroupRoutes(app, {
        dbGet, dbAll, dbRun, io, queryWithRetry, respondIfDeadlock, keyShareLimiter, keyRequestLimiter, memberCertLimiter,
        withTransaction: (work) => withTransactionRetry(work),
    });
}

module.exports = { register };
