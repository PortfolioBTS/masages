require('dotenv').config();

// Отчёт о настройках и секретах — первым делом, до модулей, которые могут
// упасть на неверном значении: в логах деплоя будет видно, что именно не так
// (значения не печатаются). То же вручную: npm run check-env.
{
    const { checkEnv, formatEnvReport } = require('./lib/env-check');
    const envReport = checkEnv(process.env);
    (envReport.errors.length > 0 ? console.error : console.log)('[Env] ' + formatEnvReport(envReport));
}

// 1. IMPORTS
const express = require('express');
const { Pool } = require('pg');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const os = require('os');
const net = require('net');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

// Импорт новых модулей безопасности и приватности
const { stripMetadataFromFile, cleanupStaleTempFiles } = require('./lib/metadata-stripper');
const DisappearingMessagesManager = require('./lib/disappearing-messages');
const { encryptText, decryptText, messageAad, encryptRoomText, decryptRoomText, messageAadV3 } = require('./lib/message-crypto');
const { sanitizeText, getPrivacyHeaders, createHstsMiddleware } = require('./lib/privacy');
const { createSwKillSwitch } = require('./lib/sw-kill-switch');
const {
    ALLOWED_MIME_TYPES,
    MIME_EXTENSIONS,
    ENCRYPTED_FILE_MIME,
    ENCRYPTED_FILE_EXTENSION,
    anonymizedFileName,
    checkMagicBytes,
    isInlineUpload,
    randomString,
    generateUniqueCode,
    generateInviteCode,
    normalizeInviteCode,
    isValidInviteCode,
    parseAllowedOrigins,
    isRequestOriginAllowed,
    buildContentSecurityPolicy,
    resolveDbTlsConfig,
    createCounter,
    positiveNumberOr,
} = require('./lib/security-utils');
const {
    JOIN_REQUEST_TTL_SECONDS,
    MAX_PENDING_JOIN_REQUESTS_PER_ROOM,
    INVALID_INVITE_MESSAGE,
    ROOM_FULL_MESSAGE,
    parseInviteSettings,
    isInviteUsable,
    isRoomFull,
    describeInvite
} = require('./lib/invites');
const {
    parseChatExpirySeconds,
    effectiveMessageExpiry,
    parseChatPrefs
} = require('./lib/chat-settings');
const {
    ANON_LIFETIMES,
    ANON_SOCKET_ACTIVITY_INTERVAL_MS,
    SESSION_RENEW_INTERVAL_MS,
    parseAnonLifetime,
    parseAnonLifetimeStrict,
    activityBucketMs,
    sessionRenewIntervalMs,
    renewBucket,
    describeAnonLifetime
} = require('./lib/anon-lifetime');
// Сессии в Postgres с огрублением времени, их продление и активность
// анонимов (контракт этапа 1, §4).
const { createNyxoPgStore, setSessionCookieLifetime, renewSession, extendTabSessions } = require('./lib/session-store');
const { createAnonActivity } = require('./lib/anon-activity');

// Маршруты /api/keys/* (регистрируются после sessionMiddleware — см. вызов
// registerE2eeKeyRoutes ниже) и встроенное хранилище публичных E2EE-ключей
const { registerE2eeKeyRoutes, deleteKeysForUser } = require('./lib/e2ee-keys');
const { initKeyStoreSchema } = require('./lib/key-store');
// Журнал ключей (прозрачность ключей, docs/security/key-transparency.md): сервис с базой,
// маршруты /api/kt/*; задачи эпох регистрируются через JOB_MODULES (lib/jobs).
const { createKtService } = require('./lib/kt-service');
const { registerKtRoutes } = require('./lib/kt-routes');
// Групповой E2EE: участники чата + попарная доставка Sender Key
// (key-shares). Тоже регистрируется после sessionMiddleware.
const { initE2eeGroupsSchema, registerE2eeGroupRoutes } = require('./lib/e2ee-groups');
const { createTransactionRetry } = require('./lib/tx-retry');
const { initUploadQuotaSchema, reserveUploadQuota, deleteQuotaRows } = require('./lib/upload-quota');
const { isClientOutdated: isOutdatedProto } = require('./lib/proto');
// Подписанный состав группы (signed-membership.md): проверки сертификатов на сервере и общий с клиентом разбор.
const MembershipCerts = require('./lib/membership-certs');
const Membership = require('./public/lib/membership.js');

// Бот-помощник: ответ по теме запроса, приветствие нового аккаунта и подписи
// кнопок-подсказок — чистые функции без БД (lib/bot-guide.js).
const botGuide = require('./lib/bot-guide');

// Onion-сервис (контейнер tor-service/) и proof-of-work для регистрации
const { ONION_ADDRESS, ONION_PORT, onionMiddleware, onionUrlFor, isOnionHost, isOnionSocket, listenOnionPort } = require('./lib/tor-support');
const { createChallenge, consumeSolution, setSecret: setPowSecret } = require('./lib/pow');
// Точные лимиты и одноразовость PoW в Postgres (UNLOGGED-таблицы, ключи — HMAC).
const { createPgLimits, initPgLimitsSchema, respondBusy, LimitStoreError } = require('./lib/pg-limits');
// Метрики Prometheus без id и IP; отдаёт их GET /metrics по токену (lib/routes/health.js).
const { createMetrics } = require('./lib/metrics');
// CSRF-токен, привязанный к сессии (кука csrf_token + заголовок X-CSRF-Token).
const { createCsrf } = require('./lib/csrf');

// Несколько экземпляров сервера на одной базе (миграции и фоновые задачи
// под advisory-блокировками) и запись ошибок в лог без id из detail.
const { runMigrationsExclusive, createRunExclusive, LOCK_NOT_AVAILABLE } = require('./lib/advisory-locks');
const { loadMigrations, migrateSchema } = require('./lib/migrations');
// Сброс схемы версии 2.0.0 при первом старте (вызывается из initDatabase).
const { resetLegacyDatabase } = require('./lib/legacy-reset');
const { logError } = require('./lib/log-error');
// Точки регистрации маршрутов вне server.js и JSON-404 для /api.
const { registerPreSessionRoutes, registerApiRoutes, registerApiNotFound } = require('./lib/routes');
// Реестр фоновых задач (под runExclusive) и тестовая ручка NYXO_TEST_MAINTENANCE_MS.
const { createJobScheduler, registerJobModules } = require('./lib/jobs');
// Надгробия id сообщений, триггеры seq и проверки id (initDatabase).
const { initMessageOrderSchema } = require('./lib/message-order-schema');
// Огрубление времени сообщений и файлов (раздел 11 контракта).
const { floorToMinute, floorToHour, orphanAgeThresholdMs } = require('./lib/coarse-time');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const {
    parseClientMessageId,
    parseSeq,
    isMessageIdConflict,
    isDeadlock,
    CLIENT_OUTDATED,
    BAD_MESSAGE_ID,
    ID_CONFLICT,
    BAD_SEQ,
} = require('./lib/message-ids');

// Форма E2EE-конверта и тела отказов 400 для комнат и бота (R7).
const {
    MAX_ENVELOPE_LENGTH,
    isE2eeEnvelopeShape,
    E2EE_REQUIRED,
    BAD_ENVELOPE,
    E2EE_NOT_ALLOWED,
} = require('./lib/e2ee-envelope');

// ---- T6.1, шаг 5 из 6: часть кода вынесена в src/ ----
// Контекст собирается из фабрик в порядке зависимостей (на последнем шаге этот блок станет
// src/create-server.js); всё, что ниже в этом файле, ещё не вынесено.
const { loadConfig } = require('./src/config');
const { createBase, createKtContext } = require('./src/context');
const { createUploads } = require('./src/services/uploads');
const { createApp } = require('./src/http/create-app');
const { createRealIp } = require('./src/http/middleware/real-ip');
const { createOrigin } = require('./src/http/middleware/origin');
const { createHttpServer } = require('./src/http/server');
const { createIo } = require('./src/realtime/io');
const { createEvents } = require('./src/realtime/events');
const { createPool } = require('./src/db/pool');
const { createTransactions } = require('./src/db/transactions');
const { createExpiry } = require('./src/services/expiry');
const { createSchema } = require('./src/db/schema');
const { createMigrations } = require('./src/db/migrate');
const { createRateLimits } = require('./src/http/middleware/rate-limits');
const { createSession } = require('./src/http/middleware/session');
const { createActivity } = require('./src/services/activity');
const { createChats } = require('./src/services/chats');
const { createMessages } = require('./src/services/messages');
const { createPow } = require('./src/services/pow');
const { createRooms } = require('./src/services/rooms');
const { createBot } = require('./src/services/bot');
const { createAccounts } = require('./src/services/accounts');
const { createUploadMiddleware } = require('./src/http/middleware/upload');
const { createJobs } = require('./src/jobs/index');
const { registerSocketHandlers } = require('./src/realtime/socket-handlers');
const { configureApp } = require('./src/http/app');

const ctx = { ...loadConfig(__dirname) };
Object.assign(ctx, createBase());
Object.assign(ctx, createUploads(ctx));
Object.assign(ctx, createApp());
Object.assign(ctx, createRealIp());
Object.assign(ctx, createOrigin());
Object.assign(ctx, createHttpServer(ctx));
Object.assign(ctx, createIo(ctx));
Object.assign(ctx, createEvents(ctx));
Object.assign(ctx, createPool(ctx));
Object.assign(ctx, createTransactions(ctx));
Object.assign(ctx, createExpiry(ctx));
Object.assign(ctx, createSchema(ctx));
Object.assign(ctx, createMigrations(ctx));
Object.assign(ctx, createRateLimits(ctx));
Object.assign(ctx, createSession(ctx));
Object.assign(ctx, createActivity(ctx));
Object.assign(ctx, createChats(ctx));
Object.assign(ctx, createMessages(ctx));
Object.assign(ctx, createPow(ctx));
Object.assign(ctx, createRooms(ctx));
Object.assign(ctx, createBot(ctx));
Object.assign(ctx, createAccounts(ctx));
Object.assign(ctx, createUploadMiddleware(ctx));
Object.assign(ctx, createKtContext(ctx));
Object.assign(ctx, createJobs(ctx));
registerSocketHandlers(ctx);
configureApp(ctx);

const { IS_PRODUCTION, PORT, jobs, initDatabaseExclusive, readiness, server, HOST } = ctx;

function getLocalAddresses() {
    const nets = os.networkInterfaces();
    const addresses = [];
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                addresses.push(net.address);
            }
        }
    }
    return addresses;
}

// Страховка: ошибка в фоновой задаче (таймеры, сокеты) не должна ронять
// весь сервер. Маршруты уже защищены wrapAsync. Причина — через logError:
// объект целиком (console.error(reason)) печатает detail и where ошибок
// Postgres со значениями строк.
process.on('unhandledRejection', (reason) => {
    logError('[Process] Необработанный reject промиса', reason);
});
// Непойманное исключение по-прежнему завершает процесс (состояние после него
// неизвестно, хостинг перезапустит), но без обработчика Node печатает ошибку
// сам — вместе со стеком и полями вроде detail. Здесь пишется то же, что
// и везде, и сразу выходит.
process.on('uncaughtException', (err) => {
    logError('[Process] Необработанное исключение', err);
    process.exit(1);
});

function onServerListening() {
    // Адреса сетевых интерфейсов нужны только при разработке (открыть сервер
    // с телефона); в production и в сквозных тестах IP в лог не пишутся.
    const addresses = IS_PRODUCTION || process.env.NODE_ENV === 'test' ? [] : getLocalAddresses();
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Nyxo Messenger запущен на порту ${PORT}`);
    console.log(`${'='.repeat(60)}\n`);

    if (addresses.length > 0) {
        console.log('Доступен по адресам:');
        addresses.forEach(addr => console.log(`  → http://${addr}:${PORT}`));
        console.log('');
    }

    // Фоновые задачи (реестр — выше, у определения jobs).
    jobs.start();

    // Только то, что действительно включено в этом запуске.
    console.log('Функции безопасности:');
    console.log('  + CSRF-токен и проверка Origin (HTTP и WebSocket)');
    console.log('  + Rate limiting (IP, аккаунт) и proof-of-work при регистрации');
    console.log('  + Очистка метаданных и обезличенные имена вложений');
    console.log('  + Исчезающие сообщения, физическое удаление');
    console.log('  + Шифрование текста сообщений в БД (AES-256-GCM с привязкой к комнате)');
    console.log('  + CSP без inline-кода, заголовки приватности' + (IS_PRODUCTION ? ', HSTS по https' : ''));
    console.log('  + E2EE: ключи во встроенном хранилище (эта же база)');
    if (ONION_ADDRESS && ONION_PORT) console.log(`  + Onion-сервис: http://${ONION_ADDRESS} (внутренний порт ${ONION_PORT})`);
    console.log(`\n${'='.repeat(60)}\n`);
}

// Порт открывается только ПОСЛЕ миграций. Раньше listen() вызывался сразу,
// параллельно с initDatabase(): первые запросы попадали на недомигрированную
// БД и висели на блокировках ALTER TABLE.
initDatabaseExclusive()
    .then(() => {
        readiness.migrated = true;
        server.listen(PORT, HOST, onServerListening);
        // Отдельный внутренний порт для tor-service: соединения с него
        // помечаются как onion (lib/tor-support.js). Наружу его не публиковать.
        listenOnionPort(server, HOST, () => console.log(`[Tor] Onion-порт ${ONION_PORT} слушается`));
    })
    .catch((err) => {
        logError(err && err.code === LOCK_NOT_AVAILABLE
            ? 'Ошибка инициализации БД: миграция не дождалась блокировки таблицы (идут долгие запросы), нужен перезапуск'
            : 'Ошибка инициализации БД', err);
        process.exit(1);
    });
