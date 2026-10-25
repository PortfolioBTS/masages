'use strict';
// Настройки процесса, вычисляемые из окружения: то, что раньше было константами верхнего
// уровня server.js (режим, порт, секрет сессий, срок кода-приглашения, папка вложений и т.п.).
// Чтений process.env рядом с кодом осталось по-прежнему много (логика прежняя, только
// перенесена); здесь собраны именно значения, нужные нескольким модулям сразу.
// ROOT_DIR — корень репозитория (раньше его давал __dirname в server.js).

const path = require('path');
const { positiveNumberOr } = require('../lib/security-utils');
const { sessionRenewIntervalMs, SESSION_RENEW_INTERVAL_MS } = require('../lib/anon-lifetime');
const { resolveAccountLimits } = require('../lib/account-limits');

function loadConfig(rootDir) {
    const IS_PRODUCTION = process.env.NODE_ENV === 'production';
    // HSTS preload включает только владелец домена: HSTS_PRELOAD=yes (см. lib/privacy.js).
    const HSTS_PRELOAD = process.env.HSTS_PRELOAD === 'yes';

    // Лимит на суммарный объём вложений одного пользователя: без него один
    // аккаунт мог забить весь volume (по 50 МБ за запрос, без ограничений).
    const UPLOAD_QUOTA_BYTES = Math.floor(positiveNumberOr(process.env.UPLOAD_QUOTA_MB, 500) * 1024 * 1024);

    // Вложения должны лежать на постоянном диске: файловая система контейнера
    // (Railway и т.п.) очищается при каждом деплое. UPLOADS_DIR — явный путь;
    // RAILWAY_VOLUME_MOUNT_PATH Railway выставляет сам, когда к сервису
    // подключён volume.
    const UPLOADS_DIR = process.env.UPLOADS_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(rootDir, 'uploads');

    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';

    const GLOBAL_DEFAULT_EXPIRY_SECONDS = Math.max(0, Number(process.env.DEFAULT_MESSAGE_EXPIRY_SECONDS) || 0);

    // Инвайт-коды (generateInviteCode) — 130 бит: проверять их на совпадение с
    // уже выданными незачем, а на невероятный случай есть UNIQUE на rooms.code.
    // Срок жизни кода — INVITE_TTL_HOURS (по умолчанию неделя), не больше 10 лет
    // (значение целиком должно помещаться в integer секунд).
    const INVITE_TTL_SECONDS = Math.min(
        Math.round(positiveNumberOr(process.env.INVITE_TTL_HOURS, 168) * 3600),
        10 * 365 * 24 * 3600
    );

    const sessionSecret = process.env.SESSION_SECRET;
    if (!sessionSecret) throw new Error('SESSION_SECRET не задан в переменных окружения');

    // Интервал продления сессии: 5 минут; в сквозных тестах —
    // NYXO_TEST_RENEW_INTERVAL_MS (только при NODE_ENV=test).
    const SESSION_RENEW_MS = sessionRenewIntervalMs(process.env);
    if (SESSION_RENEW_MS !== SESSION_RENEW_INTERVAL_MS) {
        console.log(`[Test] NYXO_TEST_RENEW_INTERVAL_MS=${SESSION_RENEW_MS}: сессии продлеваются каждые ${SESSION_RENEW_MS} мс`);
    }

    // Лимиты против массовых аккаунтов и разрастания хранилища (lib/account-limits.js).
    const ACCOUNT_LIMITS = resolveAccountLimits(process.env);

    return {
        IS_PRODUCTION, HSTS_PRELOAD, UPLOAD_QUOTA_BYTES, UPLOADS_DIR, PORT, HOST, ACCOUNT_LIMITS,
        GLOBAL_DEFAULT_EXPIRY_SECONDS, INVITE_TTL_SECONDS, sessionSecret, SESSION_RENEW_MS, ROOT_DIR: rootDir,
    };
}

module.exports = { loadConfig };
