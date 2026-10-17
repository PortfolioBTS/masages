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

// ---- T6.1, шаг 4 из 6: часть кода вынесена в src/ ----
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
const {
    JOIN_REQUEST_LIVE_SQL, respondCertVerdict, inviteExpiresAtIso, roomChatPayload, JOIN_REQUEST_NOT_FOUND,
    resetInviteAfterLeave,
} = require('./src/services/rooms');
const { respondIfDeadlock, withMessageIdRetry } = require('./src/db/transactions');
const { SAFE_FILENAME_RE, readFileHead, coarsenFileTimes } = require('./src/services/uploads');
const { POW_PURPOSES } = require('./src/services/pow');
const { insertUserWithBotChat, signedOutResponse } = require('./src/services/accounts');
const {
    readMessageText, roomMessagePayload, apiMessage, e2eePolicyViolation, messageFromRow,
    respondRoomSendError, writeMessageText,
} = require('./src/services/messages');
const { toPositiveInt, isNonEmptyString } = require('./src/http/params');
const { chatScope } = require('./src/services/chats');
const { parseRequestedExpiry } = require('./src/services/expiry');
const { getSocketRoomKey } = require('./src/realtime/io');
const { EarlyResponse } = require('./src/http/early-response');

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

const {
    app, metrics, resolveRealIp, IS_PRODUCTION, HSTS_PRELOAD, isTrustedOrigin, serverContext,
    sessionMiddleware, anonActivity, SESSION_RENEW_MS, csrf, apiLimiter, dbGet, dbAll, bundleLimiter, kt,
    withTransactionRetry, pgLimits, dbRun, io, queryWithRetry, keyShareLimiter, keyRequestLimiter,
    memberCertLimiter, userCanAccessFile, UPLOADS_DIR, registerLimiter, checkPow, respondPowFailure,
    generateUniqueCodeAsync, generateAnonymousUsernameAsync, withTransaction, startUserSession,
    deleteUserAccount, endSession, loadAccount, GLOBAL_DEFAULT_EXPIRY_SECONDS, getOwnChat, markChatRead,
    newMessageExpirySeconds, insertRoomMessage, describeMessageIdUse, advanceSenderMarker,
    emitRoomMessageEvent, unarchiveForRecipients, insertChatMessage, scheduleBotReply, INVITE_TTL_SECONDS,
    subscribeUserToChat, notifyChatListChanged, getOwnRoom, identityKeysOf, joinUserLimiter, joinIpLimiter,
    findRoomByInviteCode, createJoinRequest, addRoomMember, notifyJoinRequestDecided,
    notifyJoinRequestsChanged, authorTags, removeUploadedFiles, unsubscribeUserFromChat,
    notifyRoomMembersChanged, findOwnMessage, disappearingMessagesManager, upload, rejectUpload,
    rejectUploadWith, cleanupUploadedFile, UPLOAD_QUOTA_BYTES, userCanAccessMessage, getDefaultExpirySeconds,
    setChatExpiry, PORT, jobs, initDatabaseExclusive, readiness, server, HOST,
} = ctx;

// Самым первым: признак onion-запроса (req.isOnion) нужен лимитерам и
// заголовкам ниже, а у onion-запроса onionMiddleware ещё и вычищает
// присланные клиентом X-Forwarded-* — прокси перед приложением там нет.
// Метрики HTTP — самым первым, чтобы считать и отказы всех проверок ниже.
app.use(metrics.httpMiddleware());
app.use(onionMiddleware);

app.use((req, res, next) => {
    // req.ip уже учитывает 1 доверенный хоп (trust proxy = 1), то есть это IP,
    // который реально подключился к Railway — Cloudflare edge, если трафик шёл
    // через CF, либо настоящий IP клиента, если Railway-домен открыт напрямую.
    // У onion-запроса это адрес контейнера tor — один на всех onion-клиентов,
    // поэтому лимиты ниже для onion по IP не считаются.
    req.realIp = resolveRealIp(req.headers, req.ip);
    next();
});

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

// Заголовки — первыми, чтобы их получил любой ответ, включая отказы
// проверок источника и CSRF ниже.
app.use((req, res, next) => {
    // Усиленные заголовки приватности (nosniff, DENY, no-referrer, COOP/COEP...
    // — см. lib/privacy.js). Здесь они больше не дублируются и не
    // перезаписываются: раньше Referrer-Policy тут же подменялся на
    // strict-origin-when-cross-origin, и на сторонние сайты уходил origin.
    res.set(getPrivacyHeaders());

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
    res.set('X-Robots-Tag', 'noindex, nofollow');
    // Политика — buildContentSecurityPolicy (lib/security-utils.js). Без
    // 'unsafe-inline' в script-src и style-src (инлайн-кода в index.html нет,
    // поэтому nonce не нужен — а значит, нет и шаблонизации страницы: она
    // отдаётся статикой байт-в-байт, и её хэш из манифеста клиента сверяется
    // с релизом) и без "ws: wss:" (любой хост) в connect-src: только
    // WebSocket своего хоста. Схема ws/wss — по тому, как страница открыта:
    // onion-сервис отдаётся по http (TLS там даёт сам Tor), хотя
    // onionMiddleware и помечает такой запрос защищённым.
    res.set('Content-Security-Policy', buildContentSecurityPolicy({
        host: req.headers.host,
        secure: req.secure && !req.isOnion,
    }));
    next();
});
// HSTS — только для настоящего https в production и не для onion; preload — по
// HSTS_PRELOAD=yes (риски — в env-check). См. getHstsHeader в lib/privacy.js.
app.use(createHstsMiddleware({ production: IS_PRODUCTION, preload: HSTS_PRELOAD }));

// Небезопасные методы — только со своих страниц (см. isTrustedOrigin).
// Второй рубеж к CSRF-токену ниже: SameSite=Lax и токен защищают от
// межсайтовых форм, а проверка Origin — ещё и от поддоменов/соседних
// сайтов, которые могут подсадить свою csrf_token-куку.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
app.use((req, res, next) => {
    if (SAFE_METHODS.has(req.method) || isTrustedOrigin(req.headers)) return next();
    metrics.originRejected();
    res.status(403).json({ success: false, message: 'Запрещено: запрос с чужого сайта' });
});

app.use(cookieParser());

// CSRF-токен (lib/csrf.js) проверяется ниже, после sessionMiddleware: токен
// привязан к сессии, и ему нужен её id. Статике (CSS, JS, иконки) токен не
// нужен, поэтому она раздаётся раньше и кук не получает.

// Разрешает браузеру хранить ответ, но перед каждым использованием
// сверяться с сервером (If-None-Match/If-Modified-Since -> 304 без тела).
// Раньше глобальный 'no-store' заставлял заново скачивать CSS/JS и каждую
// картинку чата при каждом открытии.
function setRevalidateCacheHeaders(res, isPrivate) {
    res.set('Cache-Control', isPrivate ? 'private, no-cache' : 'no-cache');
    res.removeHeader('Pragma');
    res.removeHeader('Expires');
    res.removeHeader('Surrogate-Control');
}

// Аварийное снятие service worker (SW_KILL_SWITCH=yes, lib/sw-kill-switch.js):
// подменяет только /sw.js и обязано стоять до статики, иначе та отдаст настоящий файл.
app.use(createSwKillSwitch(process.env));

// Статика раздаётся ДО sessionMiddleware: ей сессия не нужна, а раньше
// каждый запрос за CSS/JS/иконкой ходил в Postgres за сессией.
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res) => setRevalidateCacheHeaders(res, false),
}));

// /link.my раньше отдавал index.html со вставленным nonce. Теперь страница
// всегда статическая, один адрес — «/»; старые закладки уходят туда 301.
// Относительный Location: адрес хоста из запроса в ответ не попадает.
app.get('/link.my', (req, res) => {
    res.redirect(301, '/');
});
registerPreSessionRoutes(app, serverContext);

app.use(sessionMiddleware);

// Сессия проверяется на КАЖДОМ запросе (validateSession). Недействительная
// (без isAnonymous — от прежней версии с постоянными аккаунтами) или истёкшая
// заменяется пустой, а /api/auth сообщит клиенту, что сессия закончилась
// (req.authEnded). Живая — это активность: корзина в БД пишется раз в
// корзину, и запись ждётся, потому что ответы ниже читают last_active_at.
// И продление сессии раз в интервал (renewSession): строка session
// пересохраняется, кука day/week уходит заново с новым Expires. app.use не
// оборачивается wrapAsync, поэтому ошибки — вручную в next.
app.use((req, res, next) => {
    const sess = req.session;
    if (!sess || !sess.userId) return next();
    const userId = sess.userId;
    anonActivity.validateSession(sess).then(async (verdict) => {
        if (verdict !== 'ok') {
            return req.session.regenerate((err) => {
                req.authEnded = verdict;
                next(err);
            });
        }
        await anonActivity.noteActivity(userId);
        renewSession(sess, {
            lifetime: anonActivity.lifetimeOf(userId) || sess.anonLifetime,
            now: Date.now(),
            intervalMs: SESSION_RENEW_MS,
        });
        next();
    }).catch(next);
});

// CSRF: после sessionMiddleware и проверки сессии (привязка — id сессии, а у
// запроса без входа, например регистрации, — кука nyxo_pre) и до разбора тела.
// Источник небезопасного запроса проверен ещё раньше (isTrustedOrigin).
app.use(csrf.middleware);

// Тело парсится только после проверок источника и CSRF. Глобальный лимит
// остаётся маленьким (100 КБ по умолчанию); key-shares — исключение: до 200
// получателей по 8 КБ (x3dh-init с постквантовой частью весит 2.4–4 КБ).
// Специальный парсер стоит раньше: общий видит уже разобранное тело и
// пропускает запрос.
app.use('/api/keys/key-shares', express.json({ limit: '2mb' }));
// Пачка одноразовых PQ-prekey: до 50 ключей по ~1,7 КБ в base64 (ключ ML-KEM
// 1184 байта + подпись 64) — около 90 КБ, впритык к 100 КБ по умолчанию.
app.use('/api/keys/pq-one-time-prekeys', express.json({ limit: '256kb' }));
// Запросы со снимком состава (approve, invite/rotate, member-certs): снимок на 1000 участников - 16 000 байт, в base64
// около 21,3 тыс. символов, плюс сертификат и JSON; общий лимит их не вмещает, но и 100 КБ для них слишком много
// (signed-membership.md, 7.2: 32 КБ). Парсер стоит раньше общего: тот видит разобранное тело и пропускает запрос.
const snapBodyParser = express.json({ limit: MembershipCerts.BODY_LIMIT_WITH_SNAP });
const SNAP_BODY_ROUTES = [/^\/api\/join-requests\/\d+\/approve$/, /^\/api\/chats\/\d+\/invite\/rotate$/, /^\/api\/chats\/\d+\/member-certs$/];
app.use((req, res, next) => (
    req.method === 'POST' && SNAP_BODY_ROUTES.some(re => re.test(req.path)) ? snapBodyParser(req, res, next) : next()
));
app.use(express.json());

// Лимит на /api/ — ДО регистрации маршрутов из lib/: Express применяет
// middleware в порядке регистрации, и раньше /api/keys/* и
// /api/chats/:id/participants шли мимо лимита.
app.use('/api/', apiLimiter);

// Публичные E2EE-ключи: /api/keys/* → встроенное хранилище (lib/key-store.js).
// Регистрируется строго ПОСЛЕ sessionMiddleware — маршрутам нужна сессия.
// Чужие ключи отдаются только при общей комнате — модулю нужна БД.
// Регистрация identity — одной транзакцией с записью в журнал ключей; withTransactionRetry
// определена ниже и вызывается уже при запросах, поэтому передаётся оболочкой.
registerE2eeKeyRoutes(app, { dbGet, dbAll, bundleLimiter, kt, withTransaction: (work) => withTransactionRetry(work) });
// Журнал ключей: головы и корни — любому вошедшему, записи — по правилам доступа.
// JOIN_REQUEST_LIVE_SQL объявлена ниже (условие «заявка жива»).
registerKtRoutes(app, { dbGet, kt, limiter: pgLimits.slidingLimiter('kt'), joinRequestLiveSql: () => JOIN_REQUEST_LIVE_SQL });
// Групповой E2EE: список участников чата + key-shares (тоже нужна сессия).
// Транзакция member-certs (7.1) идёт через withTransactionRetry, объявленный ниже: оболочка вызывается при запросах.
registerE2eeGroupRoutes(app, {
    dbGet, dbAll, dbRun, io, queryWithRetry, respondIfDeadlock, keyShareLimiter, keyRequestLimiter, memberCertLimiter,
    withTransaction: (work) => withTransactionRetry(work),
});
registerApiRoutes(app, serverContext);

app.get('/uploads/:filename', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    const filename = path.basename(req.params.filename);
    if (!SAFE_FILENAME_RE.test(filename)) return res.status(404).json({ success: false, message: 'Файл не найден' });
    const allowed = await userCanAccessFile(req.session.userId, filename);
    if (!allowed) return res.status(403).json({ success: false, message: 'Доступ запрещён' });
    // Вложения переписки не должны оседать в дисковом кэше браузера: после
    // выхода (и после удаления сообщения) их нельзя было бы достать из кэша
    // устройства. no-store сам по себе запрещает хранение — Pragma/Expires
    // от глобального middleware тут лишние. Last-Modified/ETag не отдаём:
    // без кэша они не нужны, а время изменения файла — лишняя метка.
    res.set('Cache-Control', 'no-store, private');
    res.removeHeader('Pragma');
    res.removeHeader('Expires');
    // Прямо на странице показываются только фото и видео. PDF, TXT и
    // шифротекст скачиваются (attachment), а не открываются внутри нашего
    // origin; неизвестное расширение тоже считается скачиваемым.
    if (!isInlineUpload(filename)) res.set('Content-Disposition', 'attachment');
    res.sendFile(path.join(UPLOADS_DIR, filename), { lastModified: false, etag: false, cacheControl: false }, (err) => {
        if (err && !res.headersSent) {
            // JSON с ошибкой не должен уходить как «скачиваемый файл».
            res.removeHeader('Content-Disposition');
            res.status(err.status === 404 ? 404 : 500).json({ success: false, message: 'Файл не найден' });
        }
    });
});

app.get('/api/pow/challenge', (req, res) => {
    const purpose = typeof req.query.purpose === 'string' ? req.query.purpose : '';
    if (!POW_PURPOSES.has(purpose)) {
        return res.status(400).json({ success: false, message: 'Некорректная цель проверки' });
    }
    const { token, difficulty } = createChallenge(purpose);
    res.json({ success: true, token, difficulty });
});

// lifetime: 'tab' | 'day' | 'week' (по умолчанию 'tab') — см.
// lib/anon-lifetime.js. Живая сессия — 409 ещё до PoW: второй аккаунт в
// том же браузере не нужен (клиент в этом случае входит через /api/auth), а
// решение одноразовое. lifetime тоже проверяется до PoW: отказ из-за
// опечатки в параметре не должен заставлять решать задачу заново.
app.post('/api/register/anonymous', registerLimiter, async (req, res) => {
    if (req.session.userId) {
        return res.status(409).json({ success: false, code: 'already-authenticated', message: 'Вы уже вошли в аккаунт' });
    }
    let lifetime;
    try {
        lifetime = parseAnonLifetime(req.body?.lifetime);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    const powVerdict = await checkPow(req, 'register-anon');
    if (powVerdict !== 'ok') return respondPowFailure(res, powVerdict);
    try {
        const uniqueCode = await generateUniqueCodeAsync();
        const username = await generateAnonymousUsernameAsync();
        // Регистрация — первая активность; в БД — её корзина.
        const now = Date.now();
        const lastActiveMs = activityBucketMs(now);

        const { userId, botChatId } = await withMessageIdRetry(() => withTransaction(client => insertUserWithBotChat(client, {
            uniqueCode, username, anonLifetime: lifetime, lastActiveAt: new Date(lastActiveMs),
            welcomeText: botGuide.welcomeText(lifetime),
        })));

        await startUserSession(req, {
            userId, username, uniqueCode, avatar: '#667EEA',
            isAnonymous: true, anonLifetime: lifetime, renewBucket: renewBucket(now, SESSION_RENEW_MS),
        });
        // 'tab' — кука без срока (до закрытия браузера), 'day'/'week' — срок
        // + 15 минут; она продлевается вместе с сессией.
        setSessionCookieLifetime(req.session.cookie, lifetime);
        anonActivity.remember(userId, { lifetime, lastActiveMs: now, persistedBucketMs: lastActiveMs });

        // Имя и id анонимного пользователя в лог не пишутся: связка "время
        // создания — id — имя" в логах хостинга как раз и деанонимизирует.

        metrics.registered();
        res.json({
            success: true,
            user: {
                id: userId,
                username,
                uniqueCode,
                isAnonymous: true,
                readReceipts: false,
                ...describeAnonLifetime({ lifetime, lastActiveMs }),
            },
            botChatId,
        });
    } catch (error) {
        logError('[Anon] Не удалось зарегистрировать аккаунт', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

// Удаление аккаунта со всеми данными (см. deleteUserAccount). Подтверждения
// не нужно: аккаунт временный, и войти в него иначе, чем этой сессией, нельзя.
// POST /api/logout — псевдоним: выйти из такого аккаунта и значит удалить его.
async function deleteOwnAccount(req, res) {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        await deleteUserAccount(userId);
    } catch (error) {
        logError('[Account] Не удалось удалить аккаунт', error);
        return res.json({ success: false, message: 'Ошибка удаления аккаунта' });
    }
    metrics.accountsDeleted('user');
    endSession(req, res, 'Аккаунт и все данные удалены');
}
app.post('/api/account/delete', deleteOwnAccount);
app.post('/api/logout', deleteOwnAccount);

// Состояние входа. Сам запрос — активность и продление сессии (middleware
// после sessionMiddleware); CSRF-куку, если её нет, выдаёт middleware CSRF.
// onionUrl — адрес onion-зеркала при тех же условиях, что заголовок
// Onion-Location (lib/tor-support.js), иначе null.
app.get('/api/auth', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json(signedOutResponse(req));
    const account = await loadAccount(userId);
    if (!account) {
        // Аккаунт удалён между проверкой сессии и этим запросом.
        anonActivity.forget(userId);
        req.authEnded = 'expired';
        return req.session.destroy(() => res.json(signedOutResponse(req)));
    }
    res.json({
        authenticated: true,
        user: {
            id: account.id,
            username: account.username,
            uniqueCode: account.uniqueCode,
            isAnonymous: true,
            readReceipts: account.readReceipts,
            anonLifetime: account.anonLifetime,
            anonInactivitySeconds: account.anonInactivitySeconds,
            anonExpiresAt: account.anonExpiresAt,
        },
        onionUrl: onionUrlFor(req),
    });
});

// Отметки прочтения: выключенные — собеседники не видят ✓✓ и не получают
// messagesRead от этого пользователя (см. markChatRead).
app.post('/api/user/privacy', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const readReceipts = req.body?.readReceipts;
    if (typeof readReceipts !== 'boolean') return res.json({ success: false, message: 'Некорректные параметры' });
    try {
        const row = await dbGet('UPDATE users SET read_receipts = $1 WHERE id = $2 RETURNING read_receipts', [readReceipts, userId]);
        if (!row) return res.json({ success: false, message: 'Пользователь не найден' });
        res.json({ success: true, readReceipts: row.read_receipts });
    } catch (error) {
        logError('Update privacy error', error);
        res.json({ success: false, message: 'Ошибка сохранения настроек' });
    }
});

app.get('/api/user', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const account = await loadAccount(userId);
    if (!account) return res.json({ success: false, message: 'Пользователь не найден' });
    res.json({ success: true, user: account });
});

// Смена срока жизни аккаунта (контракт этапа 1, §3). Срок обязателен и без
// значения по умолчанию (parseAnonLifetimeStrict): пустой или кривой запрос
// не должен молча превращать неделю в 30 минут. Новый срок отсчитывается от
// момента смены: last_active_at — текущая корзина (только вверх, как и любая
// запись активности). Сессия пересоздаётся с новым sid: у новой куки другой
// срок (tab — без Expires, day/week — с Expires), а копия прежней куки,
// которая жила бы по старому сроку, больше ничего не открывает. Сокет
// держится на прежней сессии — клиент после ответа переподключает его.
app.post('/api/user/lifetime', async (req, res) => {
    const sess = req.session;
    const userId = sess.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    let lifetime;
    try {
        lifetime = parseAnonLifetimeStrict(req.body?.lifetime);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    const now = Date.now();
    const row = await dbGet(
        `UPDATE users SET anon_lifetime = $2, last_active_at = GREATEST(last_active_at, $3)
         WHERE id = $1
         RETURNING EXTRACT(EPOCH FROM last_active_at) * 1000 AS last_active_ms`,
        [userId, lifetime, new Date(activityBucketMs(now))]
    );
    if (!row) {
        // Аккаунт удалён между проверкой сессии и этим запросом: следующая
        // проверка перечитает БД и закончит сессию.
        anonActivity.forget(userId);
        return res.json({ success: false, message: 'Пользователь не найден' });
    }
    const lastActiveMs = Number(row.last_active_ms);
    // Кэш — сразу после записи в БД: даже если пересоздать сессию не выйдет,
    // срок аккаунта уже новый, и прежнюю сессию middleware приведёт к нему
    // при следующем продлении (renewSession).
    anonActivity.remember(userId, { lifetime, lastActiveMs: now, persistedBucketMs: lastActiveMs });
    await startUserSession(req, {
        userId, username: sess.username, uniqueCode: sess.uniqueCode, avatar: sess.avatar,
        isAnonymous: true, anonLifetime: lifetime, renewBucket: renewBucket(now, SESSION_RENEW_MS),
    });
    setSessionCookieLifetime(req.session.cookie, lifetime);
    // Новый CSRF-токен для новой сессии уже выдан в startUserSession: токен,
    // который видели вместе с прежней кукой, дальше не действует.
    res.json({ success: true, ...describeAnonLifetime({ lifetime, lastActiveMs }) });
});

// Список чатов с последним сообщением и числом непрочитанных.
//
// Раньше это были ПЯТЬ коррелированных подзапросов на каждый чат, каждый с
// условием вида (room_id = X) OR (chat_id = Y). Такое OR не может
// использовать индекс, поэтому каждый подзапрос проходил ВСЮ таблицу
// messages: чатов × 5 полных проходов на каждое открытие приложения, и ещё
// раз — на каждое входящее сообщение в любом другом чате. С ростом таблицы
// это и было главным источником "всё очень медленно".
//
// Теперь для каждого чата работает только одна из двух веток (вторая
// отсекается условием на c.room_id), и обе идут по уникальным индексам
// порядка idx_messages_room_seq/idx_messages_chat_seq: последнее сообщение —
// одна запись индекса от конца (ORDER BY seq DESC LIMIT 1), непрочитанные —
// только записи после last_read_seq (не больше 100). Сравнение seq — только
// внутри области (комнаты или чата с ботом).
//
// Последнее сообщение комнаты — только из видимых участнику (seq больше его
// visible_from_seq); непрочитанные и так начинаются после last_read_seq,
// который при вступлении ставится на ту же границу.
// lm_room_id/lm_chat_id/lm_user_id нужны только для AAD расшифровки (чат с ботом)
// и клиенту не отдаются; предпросмотр комнаты не расшифровывается вовсе (там
// всегда E2EE-конверт).
//
// Непрочитанное: в комнате — всё после личного маркера last_read_seq (своих
// сообщений в нём нет: отправитель сдвигает маркер сам, sealed-sender.md, 8.3, а
// автора в строке комнаты нет — отфильтровать «свои» по user_id нечем); у чата с
// ботом — ответы бота (sent = 0). Закреплённые — сверху; дальше по времени последнего
// сообщения (оно хранится с точностью до минуты, так что при равных минутах
// порядок стабилен, но произволен); чаты без сообщений — по времени создания
// (id случайные и порядка не несут). Архивные остаются в списке — клиент
// показывает их отдельным разделом.
//
// member_count и expiry_seconds — в этом же запросе, без запроса на
// каждый чат: число участников — index-only scan по уникальному индексу
// room_participants (room_id, user_id), таймер — по первичным
// ключам room_settings/chat_settings. expiry_seconds — действующий срок:
// общий таймер комнаты (для бота — личный), иначе DEFAULT_MESSAGE_EXPIRY_SECONDS
// ($2), иначе 0. Код выключенного приглашения не отдаётся.
const CHAT_LIST_SQL = `
    SELECT c.id, c.name, c.avatar, c.online, c.is_bot, c.room_id,
           CASE WHEN r.invite_disabled THEN NULL ELSE r.code END AS invite_code,
           c.pinned, c.muted, c.archived,
           mc.cnt AS member_count,
           COALESCE(CASE WHEN c.room_id IS NOT NULL THEN rs.default_message_expiry ELSE cs.default_message_expiry END, $2::numeric) AS expiry_seconds,
           lm.id AS last_message_id, lm.seq AS last_message_seq,
           lm.text AS last_message, lm.encrypted AS last_message_encrypted,
           lm.message_type AS last_message_type, lm.created_at AS last_created_at,
           lm.room_id AS lm_room_id, lm.chat_id AS lm_chat_id, lm.user_id AS lm_user_id,
           COALESCE(uc.cnt, 0) AS unread
    FROM chats c
    LEFT JOIN rooms r ON r.id = c.room_id
    LEFT JOIN room_participants rp ON rp.room_id = c.room_id AND rp.user_id = c.user_id
    LEFT JOIN room_settings rs ON rs.room_id = c.room_id
    LEFT JOIN chat_settings cs ON cs.chat_id = c.id AND c.room_id IS NULL
    LEFT JOIN LATERAL (
        SELECT COUNT(*)::int AS cnt FROM room_participants p WHERE p.room_id = c.room_id
    ) mc ON c.room_id IS NOT NULL
    LEFT JOIN LATERAL (
        SELECT * FROM (
            (SELECT x.id, x.seq, x.text, x.encrypted, x.message_type, x.created_at, x.room_id, x.chat_id, x.user_id
               FROM messages x
              WHERE c.room_id IS NOT NULL AND x.room_id = c.room_id AND x.seq > COALESCE(rp.visible_from_seq, 0)
              ORDER BY x.seq DESC LIMIT 1)
            UNION ALL
            (SELECT x.id, x.seq, x.text, x.encrypted, x.message_type, x.created_at, x.room_id, x.chat_id, x.user_id
               FROM messages x
              WHERE c.room_id IS NULL AND x.chat_id = c.id AND x.room_id IS NULL
              ORDER BY x.seq DESC LIMIT 1)
        ) last_rows LIMIT 1
    ) lm ON TRUE
    LEFT JOIN LATERAL (
        SELECT COUNT(*) AS cnt FROM (
            (SELECT 1 FROM messages m
              WHERE c.room_id IS NOT NULL AND m.room_id = c.room_id
                AND m.seq > c.last_read_seq
              LIMIT 100)
            UNION ALL
            (SELECT 1 FROM messages m
              WHERE c.room_id IS NULL AND m.chat_id = c.id AND m.room_id IS NULL
                AND m.seq > c.last_read_seq AND m.sent = 0
              LIMIT 100)
        ) unread_rows
    ) uc ON TRUE
    WHERE c.user_id = $1
    ORDER BY c.pinned DESC, lm.created_at DESC NULLS LAST, c.created_at DESC NULLS LAST, c.id DESC
`;

app.get('/api/chats', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chats = await dbAll(CHAT_LIST_SQL, [req.session.userId, GLOBAL_DEFAULT_EXPIRY_SECONDS]);
        // Предпросмотр E2EE-сообщения в списке чатов не расшифровываем —
        // это потребовало бы Sender Key каждого отправителя каждого чата
        // ещё до открытия чата. Показываем нейтральную подпись, конверт
        // клиенту не отдаём вовсе (script.js подставляет плейсхолдер).
        res.json({
            success: true,
            chats: chats.map(({ lm_room_id, lm_chat_id, lm_user_id, ...c }) => ({
                ...c,
                last_message_id: c.last_message_id === null ? null : String(c.last_message_id),
                last_message_seq: c.last_message_seq === null ? null : Number(c.last_message_seq),
                unread: Number(c.unread),
                expiry_seconds: Number(c.expiry_seconds) || 0,
                // Строка комнаты - всегда E2EE-конверт (CHECK messages_room_e2ee), её
                // предпросмотр не отдаётся; у чата с ботом - открытый текст.
                last_message: c.last_message_encrypted || lm_room_id
                    ? null
                    : readMessageText(c.last_message, { room_id: lm_room_id, chat_id: lm_chat_id, user_id: lm_user_id }),
            })),
        });
    } catch (error) {
        logError('Get chats error', error);
        res.json({ success: false, message: 'Ошибка загрузки чатов' });
    }
});

const MESSAGES_PAGE_SIZE = 100;
const MAX_MESSAGES_PAGE_SIZE = 200;

// История чата постранично: последние MESSAGES_PAGE_SIZE сообщений, более
// старые — через ?beforeSeq=<seq самого старого из загруженных>. Раньше
// отдавалась вся история целиком (плюс IN-список из всех её id для
// реакций), и открытие большого чата становилось всё медленнее.
// Старый параметр ?before=<id> — 400 client-outdated: id порядка не задаёт
// (раздел 14 контракта).
app.get('/api/messages/:chatId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    if (req.query.before !== undefined) return res.status(400).json(CLIENT_OUTDATED);
    let beforeSeq = null;
    if (req.query.beforeSeq !== undefined) {
        beforeSeq = parseSeq(req.query.beforeSeq);
        if (!beforeSeq) return res.status(400).json(BAD_SEQ);
    }
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        const limit = Math.min(toPositiveInt(req.query.limit) || MESSAGES_PAGE_SIZE, MAX_MESSAGES_PAGE_SIZE);
        const scope = chatScope(chat);
        const params = [scope.value, limit + 1, Number(chat.visible_from_seq) || 0];
        if (beforeSeq) params.push(beforeSeq);

        // Цитата ответа берётся только из ТОГО ЖЕ чата, только если она не
        // удалена и видна участнику (seq новее его visible_from_seq). Раньше
        // reply_to_id не проверялся при отправке, и подставив чужой id,
        // можно было получить расшифрованный текст сообщения из любого
        // чужого чата; удалённые сообщения тоже продолжали "светиться" в
        // цитатах, а новичок комнаты видел в цитатах историю до вступления.
        // Сначала id страницы (index-only scan по idx_messages_*_seq), потом
        // сами строки по первичному ключу.
        //
        // Сообщения КОМНАТЫ отдаются без автора (sealed-sender.md, 8.1): без JOIN
        // users, без user_id, chat_id, sender_username, sender_avatar и без поля
        // mine — сервер не считает тег на каждую строку, а сторону пузыря не
        // расшифрованного сообщения клиент определяет по умолчанию как «чужое».
        // author_tag нужен только для AAD расшифровки строки и наружу не уходит.
        // Цитата комнаты — { id, seq, text (конверт), encrypted }: автора цитаты
        // клиент узнаёт, расшифровав её.
        const pageCte = `
            WITH page AS MATERIALIZED (
                SELECT m.id, m.seq FROM messages m
                WHERE ${scope.where('m')} AND m.seq > $3 ${beforeSeq ? 'AND m.seq < $4' : ''}
                ORDER BY m.seq DESC
                LIMIT $2
            )`;
        let rows;
        if (chat.room_id) {
            rows = await dbAll(`${pageCte}
                SELECT m.id, m.seq, m.room_id, m.author_tag, m.text, m.file_url, m.file_name, m.file_type,
                       m.message_type, m.sent, m.status, m.edited_at, m.encrypted, m.created_at,
                       m.reply_to_id AS reply_target_id,
                       rt.id AS reply_to_id, rt.seq AS reply_to_seq, rt.text AS reply_to_text,
                       rt.author_tag AS reply_to_author_tag, rt.room_id AS reply_to_room_id,
                       rt.encrypted AS reply_to_encrypted
                FROM page
                JOIN messages m ON m.id = page.id
                LEFT JOIN messages rt ON rt.id = m.reply_to_id AND ${scope.where('rt')} AND rt.seq > $3
                ORDER BY m.seq DESC
            `, params);
        } else {
            rows = await dbAll(`${pageCte}
                SELECT m.id, m.seq, m.chat_id, m.room_id, m.user_id, m.text, m.file_url, m.file_name, m.file_type,
                       m.message_type, m.sent, m.status, m.edited_at, m.encrypted, m.created_at,
                       m.reply_to_id AS reply_target_id,
                       u.username AS sender_username, u.avatar AS sender_avatar,
                       rt.id AS reply_to_id, rt.text AS reply_to_text, rt.user_id AS reply_to_sender_id,
                       rt.room_id AS reply_to_room_id, rt.chat_id AS reply_to_chat_id,
                       rt.encrypted AS reply_to_encrypted,
                       ru.username AS reply_to_sender_username, ru.avatar AS reply_to_sender_avatar
                FROM page
                JOIN messages m ON m.id = page.id
                JOIN users u ON u.id = m.user_id
                LEFT JOIN messages rt ON rt.id = m.reply_to_id AND ${scope.where('rt')} AND rt.seq > $3
                LEFT JOIN users ru ON ru.id = rt.user_id
                ORDER BY m.seq DESC
            `, params);
        }

        const hasMore = rows.length > limit;
        if (hasMore) rows.length = limit;
        rows.reverse();

        const reactionsMap = {};
        if (rows.length > 0) {
            const reactions = await dbAll(
                'SELECT message_id, ARRAY_AGG(DISTINCT emoji) AS emojis FROM reactions WHERE message_id = ANY($1::int[]) GROUP BY message_id',
                [rows.map(m => m.id)]
            );
            reactions.forEach(r => { reactionsMap[r.message_id] = r.emojis; });
        }

        const messages = chat.room_id
            ? rows.map(row => {
                const text = readMessageText(row.text, row);
                const replyTo = row.reply_to_id
                    ? {
                        id: row.reply_to_id, seq: Number(row.reply_to_seq),
                        text: readMessageText(row.reply_to_text, { room_id: row.reply_to_room_id, id: row.reply_to_id, author_tag: row.reply_to_author_tag }),
                        encrypted: row.reply_to_encrypted,
                    }
                    : (row.reply_target_id ? { id: row.reply_target_id, deleted: true } : null);
                return { ...roomMessagePayload(row, text, { replyTo }), reactions: reactionsMap[row.id] || [] };
            })
            : rows.map(({ reply_target_id, reply_to_text, reply_to_sender_id, reply_to_room_id, reply_to_chat_id,
                reply_to_encrypted, reply_to_sender_username, reply_to_sender_avatar, ...m }) => apiMessage({
                ...m,
                text: readMessageText(m.text, m),
                reactions: reactionsMap[m.id] || [],
                reply_to: m.reply_to_id ? {
                    id: m.reply_to_id,
                    text: readMessageText(reply_to_text, { room_id: reply_to_room_id, chat_id: reply_to_chat_id, user_id: reply_to_sender_id }),
                    sender_id: reply_to_sender_id, encrypted: reply_to_encrypted,
                    sender_username: reply_to_sender_username, sender_avatar: reply_to_sender_avatar
                } : (reply_target_id ? { id: reply_target_id, deleted: true } : null)
            }));

        // Первая (самая свежая) страница = пользователь видит конец чата.
        if (!beforeSeq && messages.length > 0) {
            await markChatRead(chat, userId, messages[messages.length - 1].seq);
        }

        res.json({
            success: true,
            messages,
            hasMore,
            chat: {
                id: chat.id, room_id: chat.room_id, name: chat.name, avatar: chat.avatar, is_bot: chat.is_bot,
                // Подписи кнопок-подсказок — только у чата с ботом. Их отдаёт сервер,
                // чтобы кнопки и ключевые слова бота не расходились (lib/bot-guide.js).
                ...(chat.is_bot ? { quickReplies: [...botGuide.QUICK_REPLIES] } : {}),
            },
        });
    } catch (error) {
        logError('Get messages error', error);
        res.json({ success: false, message: 'Ошибка загрузки сообщений' });
    }
});

// Клиент сообщает, что показал пользователю новые сообщения открытого чата
// (пришедшие по сокету), — иначе они считались бы непрочитанными. Тело —
// { upToSeq }; старое { upToId } — 400 client-outdated.
app.post('/api/chats/:chatId/read', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    if (req.body?.upToSeq === undefined && req.body?.upToId !== undefined) return res.status(400).json(CLIENT_OUTDATED);
    const upToSeq = parseSeq(req.body?.upToSeq);
    if (!upToSeq) return res.json({ success: false, message: 'Некорректный upToSeq' });
    const chat = await getOwnChat(req.params.chatId, userId);
    if (!chat) return res.json({ success: false, message: 'Чат не найден' });
    // Не даём отметить прочитанным больше, чем реально есть (и видно
    // участнику) в этом чате.
    const scope = chatScope(chat);
    const latest = await dbGet(
        `SELECT MAX(m.seq) AS seq FROM messages m WHERE ${scope.where('m')} AND m.seq <= $2 AND m.seq > $3`,
        [scope.value, upToSeq, Number(chat.visible_from_seq) || 0]
    );
    await markChatRead(chat, userId, latest && latest.seq);
    res.json({ success: true });
});

app.post('/api/messages', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    // Общий признак версии клиента (message-ordering.md, 14.1) — первая проверка
    // запроса, до остальных: устаревшая вкладка получает одну понятную ошибку.
    if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
    const { chatId, text, replyToId } = req.body || {};
    const encrypted = req.body?.encrypted === true;
    if (!isNonEmptyString(text) || !toPositiveInt(chatId)) return res.json({ success: false, message: 'Введите текст сообщения' });
    // У E2EE-сообщений text — это JSON-конверт (senderKeyId/iv/ct/подпись,
    // см. public/e2ee.js), а не читаемый текст: он больше обычного
    // сообщения той же "длины" за счёт base64 и служебных полей.
    const maxLen = encrypted ? MAX_ENVELOPE_LENGTH : 4000;
    if (text.length > maxLen) return res.json({ success: false, message: `Сообщение не может быть длиннее ${maxLen} символов` });
    let requestedExpiry;
    try {
        requestedExpiry = parseRequestedExpiry(req.body?.expirySeconds);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }

    try {
        const chat = await getOwnChat(chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        // Сообщение комнаты без clientMessageId — устаревшая вкладка: 400
        // client-outdated; неверный формат — ошибка клиента: 400 bad-message-id.
        // Чат с ботом поле игнорирует: id выдаёт DEFAULT.
        let clientId = null;
        if (chat.room_id) {
            const raw = req.body.clientMessageId;
            if (raw === undefined || raw === null || raw === '') return res.status(400).json(CLIENT_OUTDATED);
            clientId = parseClientMessageId(raw);
            if (clientId === null) return res.status(400).json(BAD_MESSAGE_ID);
        }

        // Комната — только конверт правильной формы, бот — только открытый текст
        // (старая вкладка, не знающая про обязательное шифрование, получит
        // просьбу обновить страницу).
        const violation = e2eePolicyViolation(chat, encrypted, text.trim());
        if (violation) return res.status(400).json(violation);

        // Для E2EE-конверта sanitizeText не нужен и вреден по смыслу: это
        // не человеческий текст, а base64/JSON, который клиент должен
        // получить обратно байт-в-байт для расшифровки.
        const safeText = encrypted ? text.trim() : sanitizeText(text.trim());
        if (!safeText) return res.json({ success: false, message: 'Введите текст сообщения' });

        // Отвечать можно только на видимое отправителю сообщение из ЭТОГО же
        // чата (иначе ответ на старый id вытащил бы в цитату текст из истории
        // до вступления). Удалённое сообщение строки уже не имеет. Цитата
        // комнаты — { id, seq, text (конверт), encrypted }: автора клиент узнаёт
        // сам, расшифровав цитату (sealed-sender.md, 8.1); у чата с ботом — как раньше.
        const scope = chatScope(chat);
        let replyTo = null;
        const replyTargetId = toPositiveInt(replyToId);
        if (replyTargetId) {
            const visibleFrom = Number(chat.visible_from_seq) || 0;
            if (chat.room_id) {
                const target = await dbGet(
                    `SELECT m.id, m.seq, m.text, m.room_id, m.author_tag, m.encrypted
                     FROM messages m WHERE m.id = $1 AND ${scope.where('m', '$2')} AND m.seq > $3`,
                    [replyTargetId, scope.value, visibleFrom]
                );
                if (target) {
                    replyTo = { id: target.id, seq: Number(target.seq), text: readMessageText(target.text, target), encrypted: target.encrypted };
                }
            } else {
                const target = await dbGet(
                    `SELECT m.id, m.text, m.room_id, m.chat_id, m.user_id, m.encrypted, u.username, u.avatar
                     FROM messages m JOIN users u ON u.id = m.user_id
                     WHERE m.id = $1 AND ${scope.where('m', '$2')} AND m.seq > $3`,
                    [replyTargetId, scope.value, visibleFrom]
                );
                if (target) {
                    replyTo = {
                        id: target.id, text: readMessageText(target.text, target), sender_id: target.user_id,
                        encrypted: target.encrypted, sender_username: target.username, sender_avatar: target.avatar,
                    };
                }
            }
        }

        const expirySeconds = await newMessageExpirySeconds(chat, requestedExpiry);

        if (chat.room_id) {
            const roomId = chat.room_id;
            let outcome;
            try {
                outcome = await insertRoomMessage({
                    userId, roomId, id: clientId, plainText: safeText, expirySeconds,
                    fields: { message_type: 'text', sent: 1, status: 'sent', reply_to_id: replyTo ? replyTo.id : null, encrypted },
                });
            } catch (err) {
                if (isMessageIdConflict(err)) {
                    // Вставка откатилась целиком (в том числе приращение seq). Тот же
                    // запрос — 200 с сохранённой строкой, без повторной рассылки; иначе 409.
                    const use = await describeMessageIdUse({ id: clientId, roomId, userId, expectedText: safeText, file: false });
                    if (use.status === 'duplicate') {
                        return res.json({ success: true, message: messageFromRow(use.row, safeText, replyTo) });
                    }
                    return res.status(409).json(ID_CONFLICT);
                }
                throw err;
            }
            if (outcome.error) return respondRoomSendError(res, outcome.error);

            // text уже известен в открытом виде (safeText) — не расшифровываем то,
            // что сами только что зашифровали, и не перечитываем строку из БД.
            const row = {
                id: outcome.row.id, seq: outcome.row.seq, room_id: roomId, file_url: null, file_name: null, file_type: null,
                message_type: 'text', sent: 1, status: 'sent', edited_at: null, encrypted, created_at: outcome.row.created_at,
            };
            await advanceSenderMarker(chat, row.seq);
            emitRoomMessageEvent('newMessage', roomId, userId, roomMessagePayload(row, safeText, { replyTo }));
            res.json({ success: true, message: roomMessagePayload(row, safeText, { replyTo, mine: true }) });
            unarchiveForRecipients(chat, userId);
            return;
        }

        // Чат с ботом: id по DEFAULT, при гонке или попадании в надгробие — один повтор.
        const fields = {
            chat_id: chat.id, room_id: null, user_id: userId,
            text: writeMessageText(safeText, { room_id: null, chat_id: chat.id, user_id: userId }),
            message_type: 'text', sent: 1, status: 'sent',
            reply_to_id: replyTo ? replyTo.id : null, encrypted,
        };
        const inserted = await withMessageIdRetry(() => insertChatMessage(userId, fields, expirySeconds));
        // Нет строки пользователя: аккаунт удалён, пока шёл запрос.
        if (!inserted) return res.status(401).json({ success: false, message: 'Не авторизован' });

        // text уже известен в открытом виде (safeText) — не расшифровываем то,
        // что сами только что зашифровали, и не перечитываем строку из БД.
        const message = apiMessage({
            id: inserted.id, seq: inserted.seq, chat_id: chat.id, room_id: null, user_id: userId,
            text: safeText, file_url: null, file_name: null, file_type: null,
            message_type: 'text', sent: 1, status: 'sent', edited_at: null,
            encrypted, created_at: inserted.created_at,
            reply_to_id: replyTo ? replyTo.id : null, reply_to: replyTo, reactions: [],
            sender_username: req.session.username, sender_avatar: req.session.avatar || '',
        });
        io.to(getSocketRoomKey(chat.id, null)).emit('newMessage', message);
        res.json({ success: true, message });

        // Чат с ботом ходит открытым текстом: конверт сюда не принимается (выше).
        if (chat.is_bot) scheduleBotReply(chat, safeText);
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Send message error', error);
        res.json({ success: false, message: 'Ошибка отправки' });
    }
});

app.post('/api/chats', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    if (!name) return res.json({ success: false, message: 'Введите имя чата' });
    if (name.length > 64) return res.json({ success: false, message: 'Название чата не может быть длиннее 64 символов' });

    const avatar = name.charAt(0).toUpperCase();
    try {
        const roomCode = generateInviteCode();
        // Порядок блокировок users → rooms → room_participants → chats
        // (message-ordering.md, раздел 8): строку создателя берём явно и
        // первой. Иначе внешние ключи room_participants и chats проверяли бы
        // users после rooms — в обратном порядке, чем удаление аккаунта.
        const created = await withTransactionRetry(async (client) => {
            const owner = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
            if (owner.rows.length === 0) return null; // аккаунт удалён между проверкой сессии и этим запросом
            const roomResult = await client.query(
                `INSERT INTO rooms (name, code, code_expires_at) VALUES ($1, $2, NOW() + $3::integer * INTERVAL '1 second')
                 RETURNING id, msg_seq`,
                [name, roomCode, INVITE_TTL_SECONDS]
            );
            const newRoomId = roomResult.rows[0].id;
            // Создатель видит всю историю (seq комнаты всегда больше 0), а
            // непрочитанного у пустой комнаты нет: маркер — её счётчик сейчас.
            await client.query('INSERT INTO room_participants (room_id, user_id, visible_from_seq) VALUES ($1, $2, 0)', [newRoomId, userId]);
            const chatResult = await client.query(
                'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_seq) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
                [userId, newRoomId, name, avatar, 0, 0, roomResult.rows[0].msg_seq]
            );
            return { roomId: newRoomId, chatId: chatResult.rows[0].id };
        });
        if (!created) return res.json({ success: false, message: 'Не авторизован' });
        const { roomId, chatId } = created;
        subscribeUserToChat(userId, chatId, roomId);
        notifyChatListChanged(userId);
        res.json({ success: true, chat: { id: chatId, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Create chat error', error);
        res.json({ success: false, message: 'Ошибка создания чата' });
    }
});

app.get('/api/chats/invite/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const own = await getOwnRoom(req.params.chatId, req.session.userId);
        if (own.error) return res.json({ success: false, message: own.error });
        res.json({ success: true, ...describeInvite(own.room, own.room.member_count) });
    } catch (error) {
        logError('Get invite error', error);
        res.json({ success: false, message: 'Ошибка получения кода' });
    }
});

// Новый код приглашения с параметрами { ttlSeconds, maxMembers,
// requireApproval } — любой участник комнаты. Старый код перестаёт
// действовать сразу (так закрывается утёкшая ссылка); выключенный код
// перевыпуск снова включает.
//
// Подписанное приглашение (signed-membership.md, 5.3, 7.2): вход без одобрения возможен только
// по ссылке с секретом, поэтому при requireApproval = false обязательны inviteCert (сертификат
// приглашения, подписанный автором и ключом приглашения) и inviteSnap (снимок состава автора);
// срок такого приглашения не больше 720 часов (INVITE_MAX), а сервер сверяет длительность
// сертификата с выбранным сроком, а не абсолютное время. При requireApproval = true сертификата
// нет: код принимает только заявки, а invite_* обнуляются.
app.post('/api/chats/:chatId/invite/rotate', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
    let settings;
    try {
        settings = parseInviteSettings(req.body, { defaultTtlSeconds: INVITE_TTL_SECONDS });
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    const signed = !settings.requireApproval;
    // Срок подписанного приглашения клиент кладёт в сертификат сам, поэтому он обязан его назвать.
    if (signed && (req.body.ttlSeconds === undefined || req.body.ttlSeconds === null || req.body.ttlSeconds === '')) {
        return res.status(400).json({ success: false, code: 'bad-request', message: 'Не задан срок действия кода' });
    }
    const ttlSeconds = signed ? Math.min(settings.ttlSeconds, Membership.INVITE_MAX_MIN * 60) : settings.ttlSeconds;
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        let verdict = null;
        if (signed) {
            verdict = await MembershipCerts.verifyInvite({
                certB64: req.body.inviteCert, snapB64: req.body.inviteSnap, roomId: chat.room_id, actorId: userId,
                actorKeys: await identityKeysOf(null, userId), ttlSeconds,
            });
            if (!verdict.ok) return respondCertVerdict(res, verdict);
        }
        // Порядок блокировок users → rooms → room_participants: автор приглашения обязан быть участником
        // ПОСЛЕ блокировки комнаты, иначе выход или удаление аккаунта автора между проверкой и записью
        // оставили бы invite_actor_id несуществующего пользователя (его выход обнуляет invite_*).
        const room = await withTransactionRetry(async (client) => {
            const me = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
            if (me.rows.length === 0) return null;
            const locked = await client.query('SELECT id FROM rooms WHERE id = $1 FOR NO KEY UPDATE', [chat.room_id]);
            if (locked.rows.length === 0) return null;
            const member = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, userId]);
            if (member.rows.length === 0) return null;
            const updated = await client.query(
                `UPDATE rooms SET code = $1, code_expires_at = NOW() + $2::integer * INTERVAL '1 second',
                        invite_max_members = $4, invite_require_approval = $5, invite_disabled = FALSE,
                        invite_cert = $6, invite_snap = $7, invite_actor_id = $8
                 WHERE id = $3
                 RETURNING code, code_expires_at, invite_max_members, invite_require_approval`,
                [generateInviteCode(), ttlSeconds, chat.room_id, settings.maxMembers, settings.requireApproval,
                    verdict ? Buffer.from(verdict.raw) : null, verdict ? Buffer.from(verdict.snap) : null, verdict ? userId : null]
            );
            return updated.rows[0];
        });
        if (!room) return res.json({ success: false, message: 'Чат не найден' });
        res.json({
            success: true,
            code: room.code,
            expiresAt: inviteExpiresAtIso(room.code_expires_at),
            maxMembers: room.invite_max_members,
            requireApproval: room.invite_require_approval,
        });
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Rotate invite error', error);
        res.json({ success: false, message: 'Ошибка обновления кода' });
    }
});

// Выключить приглашение. Сам код тоже заменяется случайным, нигде не
// показанным: выключенный код не оживёт, даже если флаг где-то забудут
// проверить. Сертификат приглашения и его снимок обнуляются (уже сохранённые join остаются:
// у них копия в aux). Уже поданные заявки остаются — их можно рассмотреть.
app.post('/api/chats/:chatId/invite/disable', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        const room = await dbGet(
            `UPDATE rooms SET code = $1, invite_disabled = TRUE, invite_cert = NULL, invite_snap = NULL, invite_actor_id = NULL
             WHERE id = $2 AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $2 AND user_id = $3)
             RETURNING id`,
            [generateInviteCode(), chat.room_id, userId]
        );
        if (!room) return res.json({ success: false, message: 'Чат не найден' });
        res.json({ success: true });
    } catch (error) {
        logError('Disable invite error', error);
        res.json({ success: false, message: 'Ошибка отключения кода' });
    }
});

// Что за группа по коду — до вступления. Тот же лимитер, что у входа по
// коду (общий счётчик): иначе предпросмотр стал бы бесплатным способом
// перебирать коды.
app.post('/api/chats/join/preview', joinUserLimiter, joinIpLimiter, async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const code = normalizeInviteCode(req.body?.code);
    if (!code) return res.json({ success: false, message: 'Введите код приглашения' });
    try {
        const room = await findRoomByInviteCode(code);
        if (!room) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });
        // roomId и сертификат приглашения (signed-membership.md, 7.2): выдаются по КОДУ, то есть и тому, кто секрета не
        // знает, - раскрывают пригласившего (id, identity-ключ), число участников его V и хэш снимка (раздел 3). Сам
        // снимок по коду не отдаётся: он приходит в ответе на POST /join владельцу join-сертификата.
        res.json({
            success: true,
            roomId: room.id,
            roomName: room.name,
            memberCount: room.member_count,
            requireApproval: room.invite_require_approval !== false,
            inviteCert: room.invite_cert ? Membership.toB64(new Uint8Array(room.invite_cert)) : null,
        });
    } catch (error) {
        logError('Join preview error', error);
        res.json({ success: false, message: 'Ошибка проверки кода' });
    }
});

// Вход по коду (signed-membership.md, 5.3-5.4, 7.2). Без joinCert - всегда заявка, даже если в комнате
// requireApproval = false: код без секрета (набран руками, утёк в логи) не впускает. Вход без одобрения - только с
// joinCert, подписанным ключом приглашения (его знает владелец ссылки с секретом) и identity-ключом входящего.
// Ответ при успехе несёт inviteSnap - снимок приглашения: его получает только тот, чей joinCert прошёл проверку.
app.post('/api/chats/join', joinUserLimiter, joinIpLimiter, async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
    const code = normalizeInviteCode(req.body?.code);
    if (!code) return res.json({ success: false, message: 'Введите код приглашения' });
    let joinRaw = null;
    if (req.body.joinCert !== undefined && req.body.joinCert !== null) {
        joinRaw = MembershipCerts.decodeField(req.body.joinCert, { min: 335, max: 335 });
        if (!joinRaw) return respondCertVerdict(res, MembershipCerts.BAD_CERT());
    }

    try {
        const room = await findRoomByInviteCode(code);
        if (!room) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });

        const existingChat = await dbGet('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
        if (existingChat) {
            if (!joinRaw) return res.json({ success: true, chat: roomChatPayload(existingChat, room) });
            // Повторный запрос после потери ответа: тот же joinCert от уже вошедшего даёт тот же ответ, пока приглашение
            // не повернули; иначе - 409 (снимок получает только владелец действующего приглашения).
            const stored = await dbGet('SELECT cert FROM room_member_certs WHERE room_id = $1 AND subject_id = $2 AND kind = 3', [room.id, userId]);
            const current = await dbGet('SELECT invite_cert, invite_snap FROM rooms WHERE id = $1', [room.id]);
            const same = stored && Buffer.from(stored.cert).equals(Buffer.from(joinRaw));
            let unchanged = false;
            if (same && current && current.invite_cert) {
                const ref = new Uint8Array(stored.cert).subarray(Membership.OFF.ref, Membership.OFF.ref + 32);
                unchanged = Membership.bytesEqual(await Membership.certHash(new Uint8Array(current.invite_cert)), ref);
            }
            if (!unchanged) return res.status(409).json({ success: false, code: 'already-member', message: 'Вы уже состоите в этой группе' });
            return res.json({
                success: true, chat: roomChatPayload(existingChat, room),
                inviteSnap: Membership.toB64(new Uint8Array(current.invite_snap)),
            });
        }
        if (isRoomFull(room.member_count, room.invite_max_members)) {
            return res.json({ success: false, message: ROOM_FULL_MESSAGE });
        }

        const pendingResponse = async () => {
            const request = await createJoinRequest(room.id, userId);
            if (request.error) return res.json({ success: false, message: request.error });
            res.json({ success: true, pending: true, requestId: request.id, roomName: room.name });
        };
        // Без сертификата, в комнате с одобрением и в комнате без подписанного приглашения (его обнулил выход участника
        // или выключение) - заявка. Секрет ссылки в этом случае игнорируется.
        if (!joinRaw || room.invite_require_approval !== false || !room.invite_cert) return pendingResponse();

        // Код и сертификат перепроверяются под блокировкой комнаты: пока шли запросы выше, код могли сменить или
        // выключить, приглашение - повернуть, а одобрение - включить.
        const result = await addRoomMember(room.id, userId, async (locked, client) => {
            if (locked.code !== code || !locked.code_live || locked.invite_disabled) return 'invalid';
            if (locked.invite_require_approval !== false || !locked.invite_cert) return 'approval';
            const verdict = await MembershipCerts.verifyJoin({
                joinRaw, inviteRaw: new Uint8Array(locked.invite_cert), roomId: room.id, userId,
                userKeys: await identityKeysOf(client, userId),
            });
            return verdict.ok ? null : { reply: verdict };
        }, async (client, locked) => {
            await client.query(
                'INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, aux) VALUES ($1, $2, 0, 3, $3, $4)',
                [room.id, userId, Buffer.from(joinRaw), Buffer.from(locked.invite_cert)]
            );
            return { inviteSnap: locked.invite_snap ? Membership.toB64(new Uint8Array(locked.invite_snap)) : null };
        });
        if (result.error === 'approval') return pendingResponse();
        if (result.error === 'full') return res.json({ success: false, message: ROOM_FULL_MESSAGE });
        if (result.error && result.error.reply) return respondCertVerdict(res, result.error.reply);
        if (result.error) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });
        const reply = { success: true, chat: result.chat };
        if (result.extra && result.extra.inviteSnap) reply.inviteSnap = result.extra.inviteSnap;
        res.json(reply);
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Join chat error', error);
        res.json({ success: false, message: 'Ошибка входа в чат' });
    }
});

// Живые заявки комнаты — любому её участнику. У заявителя — его identity-ключи и kt из
// журнала ключей: одобряющий поручается за ключ заявителя до вступления, и проверить его по
// журналу можно, пока заявитель ещё не в комнате (key-transparency.md, 6.5, GET /api/kt/proof).
app.get('/api/chats/:chatId/join-requests', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: true, requests: [] });
        const rows = await dbAll(
            `SELECT jr.id, jr.user_id, u.username, jr.created_at
             FROM join_requests jr JOIN users u ON u.id = jr.user_id
             WHERE jr.room_id = $1 AND jr.${JOIN_REQUEST_LIVE_SQL}
               AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2)
             ORDER BY jr.created_at, jr.id`,
            [chat.room_id, userId]
        );
        const identities = new Map();
        if (rows.length > 0) {
            const keyRows = await dbAll(
                `SELECT user_id, identity_signing_key, identity_dh_key, kt_nonce, kt_gen, kt_epoch, kt_skt
                 FROM identity_keys WHERE user_id = ANY($1::bigint[])`,
                [rows.map(r => r.user_id)]
            );
            for (const k of keyRows) {
                identities.set(Number(k.user_id), {
                    signingKey: k.identity_signing_key.toString('base64'),
                    dhKey: k.identity_dh_key.toString('base64'),
                    kt: kt.hintOf(k),
                });
            }
        }
        res.json({
            success: true,
            requests: rows.map(r => ({
                id: r.id, userId: r.user_id, username: r.username, createdAt: r.created_at,
                identity: identities.get(Number(r.user_id)) || null,
            })),
        });
    } catch (error) {
        logError('Get join requests error', error);
        res.json({ success: false, message: 'Ошибка загрузки заявок' });
    }
});

// Свои живые заявки (у заявителя: "ожидает одобрения").
app.get('/api/join-requests/mine', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const rows = await dbAll(
            `SELECT jr.id, r.name AS room_name, jr.created_at
             FROM join_requests jr JOIN rooms r ON r.id = jr.room_id
             WHERE jr.user_id = $1 AND jr.${JOIN_REQUEST_LIVE_SQL}
             ORDER BY jr.created_at DESC, jr.id`,
            [userId]
        );
        res.json({ success: true, requests: rows.map(r => ({ id: r.id, roomName: r.room_name, createdAt: r.created_at })) });
    } catch (error) {
        logError('Get own join requests error', error);
        res.json({ success: false, message: 'Ошибка загрузки заявок' });
    }
});

// Одобрить заявку — любой участник той же комнаты. Заявки чужих комнат
// неотличимы от несуществующих. Вступление — тем же addRoomMember, что и
// вход по коду без одобрения (лимит участников, visible_from_seq на момент
// одобрения, подписка сокетов заявителя, roomMembersChanged).
//
// Одобрение подписывается (signed-membership.md, 5.2, 7.2): тело { cert, snap } - сертификат допуска
// (vouch) от одобряющего заявителю и снимок состава одобряющего; без них - 400 cert-required /
// snap-required. Сертификат и участие одобряющего проверяются ПОСЛЕ блокировки комнаты (7.1):
// одобряющий мог выйти между проверкой подписи и вставкой, и сертификат с несуществующим подписавшим
// остался бы навсегда.
app.post('/api/join-requests/:id/approve', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
    const requestId = toPositiveInt(req.params.id);
    if (!requestId) return res.json(JOIN_REQUEST_NOT_FOUND);
    try {
        const request = await dbGet(
            `SELECT jr.id, jr.room_id, jr.user_id FROM join_requests jr
             JOIN room_participants rp ON rp.room_id = jr.room_id AND rp.user_id = $2
             WHERE jr.id = $1 AND jr.${JOIN_REQUEST_LIVE_SQL}`,
            [requestId, userId]
        );
        if (!request) return res.json(JOIN_REQUEST_NOT_FOUND);
        const applicantKeys = await identityKeysOf(null, request.user_id);
        if (!applicantKeys) {
            return res.status(409).json({ success: false, code: 'applicant-no-keys', message: 'Пользователь ещё не настроил шифрование' });
        }
        const verdict = await MembershipCerts.verifyVouch({
            certB64: req.body.cert, snapB64: req.body.snap, allowedKinds: [Membership.KIND.vouch],
            roomId: request.room_id, actorId: userId, subjectId: request.user_id,
            actorKeys: await identityKeysOf(null, userId), subjectKeys: applicantKeys,
        });
        if (!verdict.ok) return respondCertVerdict(res, verdict);
        // Под блокировкой комнаты — заявка всё ещё жива (её не отклонили и не
        // отозвали параллельно; FOR UPDATE — чтобы и не успели), а
        // одобряющий всё ещё участник. Строку заявителя addRoomMember берёт
        // самой первой (users → rooms), в том же порядке, что и
        // deleteUserAccount: одновременное удаление его аккаунта не даст
        // взаимной блокировки, заявка просто окажется удалённой.
        const result = await addRoomMember(request.room_id, request.user_id, async (room, client) => {
            const actor = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
            if (actor.rows.length === 0) return 'not-participant';
            const live = await client.query(
                `SELECT jr.id FROM join_requests jr
                 WHERE jr.id = $1 AND jr.user_id = $2 AND jr.room_id = $3 AND jr.${JOIN_REQUEST_LIVE_SQL}
                 FOR UPDATE OF jr`,
                [requestId, request.user_id, room.id]
            );
            return live.rows.length > 0 ? null : 'not-found';
        }, async (client, room) => {
            await client.query(
                'INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, snap) VALUES ($1, $2, $3, 1, $4, $5)',
                [room.id, request.user_id, userId, Buffer.from(verdict.raw), Buffer.from(verdict.snap)]
            );
            return null;
        });
        if (result.error === 'full') return res.json({ success: false, message: ROOM_FULL_MESSAGE });
        if (result.error === 'not-participant') {
            return res.status(404).json({ success: false, code: 'not-participant', message: 'Вы больше не состоите в этой группе' });
        }
        if (result.error) return res.json(JOIN_REQUEST_NOT_FOUND);
        notifyJoinRequestDecided(request.user_id, { requestId, approved: true, chat: result.chat });
        res.json({ success: true });
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Approve join request error', error);
        res.json({ success: false, message: 'Ошибка одобрения заявки' });
    }
});

app.post('/api/join-requests/:id/deny', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const requestId = toPositiveInt(req.params.id);
    if (!requestId) return res.json(JOIN_REQUEST_NOT_FOUND);
    try {
        const removed = await dbGet(
            `DELETE FROM join_requests jr USING room_participants rp
             WHERE jr.id = $1 AND rp.room_id = jr.room_id AND rp.user_id = $2 AND jr.${JOIN_REQUEST_LIVE_SQL}
             RETURNING jr.id, jr.room_id, jr.user_id`,
            [requestId, userId]
        );
        if (!removed) return res.json(JOIN_REQUEST_NOT_FOUND);
        notifyJoinRequestsChanged(removed.room_id);
        notifyJoinRequestDecided(removed.user_id, { requestId: removed.id, approved: false });
        res.json({ success: true });
    } catch (error) {
        logError('Deny join request error', error);
        res.json({ success: false, message: 'Ошибка отклонения заявки' });
    }
});

// Заявитель отзывает свою заявку.
app.delete('/api/join-requests/:id', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const requestId = toPositiveInt(req.params.id);
    if (!requestId) return res.json(JOIN_REQUEST_NOT_FOUND);
    try {
        const removed = await dbGet('DELETE FROM join_requests WHERE id = $1 AND user_id = $2 RETURNING room_id', [requestId, userId]);
        if (!removed) return res.json(JOIN_REQUEST_NOT_FOUND);
        notifyJoinRequestsChanged(removed.room_id);
        res.json({ success: true });
    } catch (error) {
        logError('Cancel join request error', error);
        res.json({ success: false, message: 'Ошибка отмены заявки' });
    }
});

// Выход из комнаты или удаление чата с ботом. Для комнаты сообщения выходящего
// остаются (тег автора на них сохраняется), а комната записывается в
// user_left_rooms, если у него там есть сообщения: удаление аккаунта удалит их во
// всех таких комнатах (sealed-sender.md, 12.1). ?deleteMessages=1 - удалить свои
// сообщения сразу (параметр строки запроса: тело у DELETE клиентская функция
// api() не отправляет); для чата с ботом параметр ничего не значит.
app.delete('/api/chats/:chatId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const deleteOwnMessages = req.query.deleteMessages === '1';
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        // Всё удаление — одной транзакцией (раньше — серия независимых
        // запросов: сбой посередине оставлял полуудалённый чат), файлы
        // удаляемых сообщений убираются с диска после COMMIT. Порядок
        // блокировок users → rooms → room_participants → chats → user_left_rooms →
        // messages (message-ordering.md, раздел 8.1): сначала строка выходящего,
        // потом комната, потому что одновременно идут отправки (users → rooms),
        // вступления и удаление аккаунта. При взаимной блокировке (40P01)
        // транзакция повторяется один раз.
        const outcome = await withTransactionRetry(async (client) => {
            const me = await client.query('SELECT id, created_at FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
            if (me.rows.length === 0) return null; // аккаунт удалён между проверкой сессии и этим запросом
            const state = { fileUrls: [], roomSurvived: false, droppedRequests: [], deletedIds: [] };
            if (chat.room_id) {
                // Блокировка комнаты: два последних участника, выходящих
                // одновременно, иначе оба видели бы "остался ещё один" и
                // комната оставалась бы в БД навсегда. Она же упорядочивает выход
                // с отправкой (8.5): отправка проверяет членство под
                // rooms FOR NO KEY UPDATE.
                await client.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [chat.room_id]);
                await client.query('DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM e2ee_key_requests WHERE room_id = $1 AND requester_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
                // Сертификаты состава, где он субъект или подписавший (после chats, до user_left_rooms и messages -
                // порядок message-ordering.md, 8.1). Выход не подписывается: управляет сервер (signed-membership.md, 5.6).
                await client.query(
                    'DELETE FROM room_member_certs WHERE room_id = $1 AND (subject_id = $2 OR actor_id = $2)',
                    [chat.room_id, userId]
                );
                const remaining = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 LIMIT 1', [chat.room_id]);
                if (remaining.rows.length === 0) {
                    // Последний участник вышел — сносим комнату целиком (запись
                    // user_left_rooms уходит каскадом от rooms).
                    // Заявки ушли бы и каскадом, но заявителям надо сказать,
                    // что рассматривать их больше некому.
                    const deleted = await client.query('DELETE FROM messages WHERE room_id = $1 RETURNING file_url', [chat.room_id]);
                    state.fileUrls = deleted.rows.map(r => r.file_url);
                    const requests = await client.query('DELETE FROM join_requests WHERE room_id = $1 RETURNING id, user_id', [chat.room_id]);
                    state.droppedRequests = requests.rows;
                    await client.query('DELETE FROM rooms WHERE id = $1', [chat.room_id]);
                } else {
                    state.roomSurvived = true;
                    // Решение владельца (signed-membership.md, вопрос 17): при выходе любого участника подписанное
                    // приглашение обнуляется, а код заменяется новым - старая ссылка и старый код перестают работать.
                    await resetInviteAfterLeave(client, chat.room_id);
                    const tags = authorTags.tagsForAccount(chat.room_id, userId, me.rows[0].created_at, Date.now());
                    if (deleteOwnMessages) {
                        const deleted = await client.query(
                            'DELETE FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) RETURNING id, file_url',
                            [chat.room_id, tags]
                        );
                        state.fileUrls = deleted.rows.map(r => r.file_url);
                        state.deletedIds = deleted.rows.map(r => r.id);
                        await client.query('DELETE FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [userId, chat.room_id]);
                    } else {
                        const own = await client.query(
                            'SELECT 1 FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) LIMIT 1',
                            [chat.room_id, tags]
                        );
                        if (own.rows.length > 0) {
                            await client.query(
                                'INSERT INTO user_left_rooms (user_id, room_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                                [userId, chat.room_id]
                            );
                        } else {
                            // Сообщений нет (в том числе после срока): отслеживать нечего.
                            await client.query('DELETE FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [userId, chat.room_id]);
                        }
                    }
                }
                // Если участники остались — история остаётся у них: сообщения
                // выходящего хранятся под тегом, а удалить их он вправе только
                // сейчас (?deleteMessages=1) или вместе с аккаунтом.
            } else {
                // Строка чата с ботом блокируется раньше его сообщений (как у
                // ответа бота и отправки): chats → messages.
                await client.query('SELECT id FROM chats WHERE id = $1 AND user_id = $2 FOR UPDATE', [chat.id, userId]);
                const deleted = await client.query('DELETE FROM messages WHERE chat_id = $1 AND room_id IS NULL RETURNING file_url', [chat.id]);
                state.fileUrls = deleted.rows.map(r => r.file_url);
                await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
            }
            return state;
        });
        if (!outcome) return res.json({ success: false, message: 'Не авторизован' });
        removeUploadedFiles(outcome.fileUrls);
        unsubscribeUserFromChat(userId, chat.id, chat.room_id);
        // Удалённые при выходе сообщения исчезают у остальных сразу.
        for (const id of outcome.deletedIds) {
            io.to(getSocketRoomKey(null, chat.room_id)).emit('messageDeleted', { id: String(id), room_id: chat.room_id });
        }
        if (outcome.roomSurvived) notifyRoomMembersChanged(chat.room_id, { inviteRotated: true });
        for (const request of outcome.droppedRequests) notifyJoinRequestDecided(request.user_id, { requestId: request.id, approved: false });
        notifyChatListChanged(userId);
        res.json({ success: true });
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Delete chat error', error);
        res.json({ success: false, message: 'Ошибка удаления чата' });
    }
});

app.put('/api/messages/:messageId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    // Общий признак версии клиента (message-ordering.md, 14.1) - первая проверка.
    if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
    const messageId = toPositiveInt(req.params.messageId);
    const { text } = req.body || {};
    if (!messageId || !isNonEmptyString(text)) return res.json({ success: false, message: 'Текст не может быть пустым' });

    try {
        // Правятся только текстовые сообщения: у вложения подпись внутри
        // E2EE-конверта (или имя файла), и менять её задним числом нельзя.
        const message = await findOwnMessage(messageId, userId, { sentOnly: true });
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        if (message.file_url) return res.json({ success: false, message: 'Сообщение с вложением нельзя изменить' });
        // Правка E2EE-сообщения — это новый конверт: клиент сам шифрует новый
        // текст перед PUT, флаг encrypted при редактировании не меняется.
        // Сообщение комнаты без шифрования (в базе его быть не должно) править
        // нельзя, а новый конверт обязан иметь правильную форму — иначе правкой
        // можно было бы подменить шифротекст открытым текстом.
        if (message.room_id) {
            const violation = e2eePolicyViolation({ room_id: message.room_id }, Boolean(message.encrypted), text.trim());
            if (violation) return res.status(400).json(violation);
        }
        const maxLen = message.encrypted ? MAX_ENVELOPE_LENGTH : 4000;
        if (text.length > maxLen) return res.json({ success: false, message: `Сообщение не может быть длиннее ${maxLen} символов` });

        // Та же очистка, что и при отправке (раньше правкой её можно было обойти).
        const newText = message.encrypted ? text.trim() : sanitizeText(text.trim());
        if (!newText) return res.json({ success: false, message: 'Текст не может быть пустым' });
        // Время правки хранится с точностью до минуты (вниз), в API — ISO-8601 UTC.
        const editedAt = floorToMinute(new Date()).toISOString();
        // AAD — от исходной строки: комната, id и тег (у бота - чат и владелец) при
        // правке не меняются, тег берётся ИЗ строки, а не пересчитывается по
        // текущей неделе (правка на границе недели - тот же тег).
        //
        // Запись условна по тегу строки: пока шла правка, scripts/retag-messages.js мог
        // перетегировать строку (смена MESSAGE_ENCRYPTION_KEY, 14.1), и текст с AAD старого
        // тега под новым тегом не читался бы. Тогда правку нужно повторить.
        const written = message.room_id
            ? await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3 AND author_tag = $4', [writeMessageText(newText, message), editedAt, messageId, message.author_tag])
            : await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [writeMessageText(newText, message), editedAt, messageId]);
        if (written.rowCount === 0) return res.json({ success: false, message: 'Сообщение изменилось, попробуйте ещё раз' });

        if (message.room_id) {
            // Тем, кто вступил в комнату после этого сообщения, новый текст не
            // уходит: для них этого сообщения нет (visible_from_seq >= seq).
            const hidden = await dbAll(
                'SELECT user_id FROM room_participants WHERE room_id = $1 AND visible_from_seq >= $2',
                [message.room_id, message.seq]
            );
            emitRoomMessageEvent('messageEdited', message.room_id, userId, {
                id: String(messageId), seq: Number(message.seq), text: newText, edited_at: editedAt,
                room_id: message.room_id, encrypted: message.encrypted,
            }, { hiddenUserIds: hidden.map(row => row.user_id) });
        } else {
            io.to(getSocketRoomKey(message.chat_id, null)).emit('messageEdited', {
                id: String(messageId), seq: Number(message.seq), text: newText, edited_at: editedAt,
                chat_id: message.chat_id, room_id: null, encrypted: message.encrypted, user_id: message.user_id
            });
        }

        res.json({ success: true, edited_at: editedAt, text: newText });
    } catch (error) {
        logError('Edit message error', error);
        res.json({ success: false, message: 'Ошибка редактирования' });
    }
});

app.delete('/api/messages/:messageId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = toPositiveInt(req.params.messageId);
    if (!messageId) return res.json({ success: false, message: 'Сообщение не найдено' });
    try {
        const message = await findOwnMessage(messageId, userId);
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        // Тот же путь, что и у disappearing messages: строка удаляется из БД
        // физически (триггер оставляет надгробие id), вложение — с диска (раньше
        // файл удалённого сообщения оставался доступен по прямой ссылке),
        // участникам уходит 'messageDeleted' (в комнате - одно событие всем сокетам
        // комнаты, включая вкладки автора, и без chat_id). Пустой результат — ошибка
        // БД (она уже в логе).
        const deleted = await disappearingMessagesManager.deleteMessages([messageId]);
        if (deleted.length === 0) return res.json({ success: false, message: 'Ошибка удаления' });
        res.json({ success: true });
    } catch (error) {
        logError('Delete message error', error);
        res.json({ success: false, message: 'Ошибка удаления' });
    }
});

// Квота вложений (sealed-sender.md, раздел 13): объём ЗАГРУЗОК ЗА ОКНО В 30 ДНЕЙ,
// а не сумма размеров сообщений (у строки комнаты нет user_id). Строка квоты лежит
// в upload_quota под псевдонимом qkey и резервируется в транзакции вставки
// сообщения (lib/upload-quota.js); удаление сообщения квоту не возвращает. До
// транзакции отсеивается только файл, который не поместился бы в квоту вовсе.

// Два вида вложений:
//   * обычное — только в чате с ботом: проверка сигнатуры, снятие метаданных
//     (все типы, fail closed), имя по типу вместо исходного (anonymizedFileName);
//   * E2EE (encrypted=true) — единственный вид в комнатах (R7): сервер получает
//     лишь шифротекст (.bin) и E2EE-конверт с типом, именем и ключом файла;
//     сигнатуры и метаданные тут проверять не у чего — это случайные байты.
//     Открытое вложение в комнате и конверт неверной формы — 400
//     (e2ee-required, bad-envelope), шифротекст в чате с ботом — 400 e2ee-not-allowed.
// Сообщение комнаты несёт clientMessageId (раздел 6 контракта порядка сообщений):
// его формат и занятость проверяет fileFilter ещё до приёма файла
// (acceptUpload), здесь — повторно и для случая, когда chatId пришёл позже
// файла. При 409 и при повторе той же отправки файл удаляется с диска.
app.post('/api/messages/file', upload.single('file'), async (req, res) => {
    const file = req.file;
    const userId = req.session.userId;
    if (!userId) return rejectUpload(res, file, 401, 'Не авторизован');
    const body = req.body || {};
    // Общий признак версии клиента — первая проверка запроса (14.1); обычно её
    // делает fileFilter ещё до приёма файла, здесь — на случай, когда поле пришло
    // после файла или файла нет.
    if (isOutdatedProto(body.proto)) return rejectUploadWith(res, file, 400, CLIENT_OUTDATED);
    if (!file) return res.status(400).json({ success: false, message: 'Файл не выбран' });

    // Перепроверка fileFilter в обе стороны: шифротекст — только с флагом
    // encrypted, флаг — только с шифротекстом (поле encrypted могло прийти
    // после файла, когда fileFilter его ещё не видел).
    const encrypted = body.encrypted === 'true';
    if (encrypted !== (file.mimetype === ENCRYPTED_FILE_MIME)) {
        return rejectUpload(res, file, 400, 'Неподдерживаемый тип файла');
    }
    if (!toPositiveInt(body.chatId)) return rejectUpload(res, file, 400, 'Не указан чат');

    let caption = '';
    let envelope = null;
    if (encrypted) {
        // Форму конверта проверяет e2eePolicyViolation, когда известен чат.
        envelope = typeof body.envelope === 'string' ? body.envelope.trim() : '';
    } else {
        caption = typeof body.text === 'string' ? sanitizeText(body.text.trim()) : '';
        if (caption.length > 4000) return rejectUpload(res, file, 400, 'Подпись слишком длинная');
    }

    // Сначала проверка чата, id и квоты (дёшево), потом обработка файла (дорого).
    let chat;
    let clientId = null;
    const fileType = file.mimetype;
    // Исходное имя файла (file.originalname) не хранится и не логируется.
    const fileName = encrypted ? null : anonymizedFileName(fileType);
    const messageText = encrypted ? envelope : (caption || fileName);
    try {
        chat = await getOwnChat(body.chatId, userId);
        if (!chat) return rejectUpload(res, file, 404, 'Чат не найден');
        if (chat.room_id) {
            const raw = body.clientMessageId;
            if (raw === undefined || raw === null || raw === '') return rejectUploadWith(res, file, 400, CLIENT_OUTDATED);
            clientId = parseClientMessageId(raw);
            if (clientId === null) return rejectUploadWith(res, file, 400, BAD_MESSAGE_ID);
        }
        // Открытое вложение в комнате, неверный конверт и шифротекст в чате с
        // ботом (то же правило, что в fileFilter: поля могли прийти после файла).
        const violation = e2eePolicyViolation(chat, encrypted, envelope);
        if (violation) return rejectUploadWith(res, file, 400, violation);
        if (chat.room_id) {
            const use = await describeMessageIdUse({ id: clientId, roomId: chat.room_id, userId, expectedText: messageText, file: true });
            if (use.status === 'duplicate') {
                cleanupUploadedFile(file);
                return res.json({ success: true, message: messageFromRow(use.row, messageText) });
            }
            if (use.status === 'conflict') return rejectUploadWith(res, file, 409, ID_CONFLICT);
        }
        if (file.size > UPLOAD_QUOTA_BYTES) {
            return rejectUpload(res, file, 413, 'Превышена квота хранилища вложений');
        }
    } catch (err) {
        cleanupUploadedFile(file);
        throw err;
    }

    const uploadedFilePath = path.join(UPLOADS_DIR, file.filename);
    let fileSize = file.size;
    if (!encrypted) {
        try {
            const head = await readFileHead(uploadedFilePath, 12);
            if (!checkMagicBytes(head, file.mimetype)) {
                return rejectUpload(res, file, 400, 'Содержимое файла не соответствует его типу');
            }
            // Метаданные (EXIF/GPS, автор PDF, теги видео...) снимаются
            // у ВСЕХ типов — раньше только у картинок и PDF.
            await stripMetadataFromFile(uploadedFilePath, file.mimetype);
            fileSize = (await fs.promises.stat(uploadedFilePath)).size;
        } catch (magicErr) {
            // Раньше при исключении здесь проверка молча пропускалась и файл
            // проходил дальше — теоретическая лазейка мимо проверки типа файла.
            // Теперь любая ошибка проверки = отказ (fail closed), а не fail open.
            logError('Upload processing error', magicErr);
            // Отказ санитайзера с понятной причиной (userFacing) отдаётся как есть:
            // в нём нет данных файла, только что сделать пользователю.
            return rejectUpload(res, file, 400, magicErr && magicErr.userFacing ? magicErr.message : 'Не удалось проверить содержимое файла');
        }
    }
    await coarsenFileTimes(uploadedFilePath);

    try {
        const roomId = chat.room_id || null;
        const fileUrl = `/uploads/${file.filename}`;
        const messageType = encrypted ? 'file'
            : fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : 'file';

        const fileFields = {
            file_url: fileUrl, file_name: fileName, file_type: fileType, message_type: messageType,
            sent: 1, status: 'sent', encrypted, file_size: fileSize,
        };
        const expirySeconds = await newMessageExpirySeconds(chat);
        // Квота резервируется в той же транзакции, что и вставка: откат (409,
        // ошибка) возвращает и её, а неудачная вставка квоту не расходует.
        const quotaUpload = { bytes: fileSize };

        if (roomId) {
            let outcome;
            try {
                outcome = await insertRoomMessage({
                    userId, roomId, id: clientId, plainText: messageText, fields: fileFields, expirySeconds, upload: quotaUpload,
                });
            } catch (err) {
                if (isMessageIdConflict(err)) {
                    // Параллельная такая же отправка успела раньше: файл этой
                    // не нужен ни при повторе (200), ни при конфликте (409).
                    cleanupUploadedFile(file);
                    const use = await describeMessageIdUse({ id: clientId, roomId, userId, expectedText: messageText, file: true });
                    if (use.status === 'duplicate') {
                        return res.json({ success: true, message: messageFromRow(use.row, messageText) });
                    }
                    return res.status(409).json(ID_CONFLICT);
                }
                throw err;
            }
            if (outcome.error) {
                cleanupUploadedFile(file);
                return respondRoomSendError(res, outcome.error);
            }
            // Раньше здесь по setTimeout статус "доставлено"/"прочитано"
            // выставлялся через 1 и 2 секунды независимо от реальности (и без
            // обработки ошибок — сбой БД ронял процесс). Теперь 'read' ставит
            // только markChatRead, когда получатель действительно открыл чат.
            const row = {
                id: outcome.row.id, seq: outcome.row.seq, room_id: roomId, file_url: fileUrl, file_name: fileName,
                file_type: fileType, message_type: messageType, sent: 1, status: 'sent', edited_at: null, encrypted,
                created_at: outcome.row.created_at,
            };
            await advanceSenderMarker(chat, row.seq);
            emitRoomMessageEvent('newMessage', roomId, userId, roomMessagePayload(row, messageText));
            res.json({ success: true, message: roomMessagePayload(row, messageText, { mine: true }) });
            unarchiveForRecipients(chat, userId);
            return;
        }

        // Чат с ботом: id по DEFAULT, при гонке или попадании в надгробие — один повтор.
        const fields = {
            chat_id: chat.id, room_id: null, user_id: userId,
            text: writeMessageText(messageText, { room_id: null, chat_id: chat.id, user_id: userId }),
            ...fileFields,
        };
        const inserted = await withMessageIdRetry(() => insertChatMessage(userId, fields, expirySeconds, quotaUpload));
        if (!inserted) return rejectUpload(res, file, 401, 'Не авторизован');
        if (inserted.error) return rejectUpload(res, file, 413, 'Превышена квота хранилища вложений');

        const fileMessage = apiMessage({
            id: inserted.id, seq: inserted.seq, chat_id: chat.id, room_id: null, user_id: userId,
            sender_username: req.session.username, sender_avatar: req.session.avatar || '',
            text: messageText, file_url: fileUrl, file_name: fileName,
            file_type: fileType, message_type: messageType, sent: 1, status: 'sent',
            edited_at: null, encrypted, created_at: inserted.created_at,
            reply_to: null, reactions: [],
        });
        io.to(getSocketRoomKey(chat.id, null)).emit('newMessage', fileMessage);
        res.json({ success: true, message: fileMessage });
    } catch (error) {
        cleanupUploadedFile(file);
        if (respondIfDeadlock(res, error)) return;
        logError('Upload file error', error);
        res.status(500).json({ success: false, message: 'Ошибка отправки файла' });
    }
});

// В UI предлагается фиксированный набор из 5 эмодзи для реакций. Раньше на
// бэке проверялась только длина строки (≤10 символов), а не содержимое — это
// пропускало вход в message.reactions, который на фронте рендерится в
// innerHTML без escapeHtml (см. п.3 аудита). Теперь бэк принимает только
// эмодзи из этого списка.
const ALLOWED_REACTION_EMOJIS = new Set(['👍', '❤️', '😂', '😢', '🔥']);

app.post('/api/reactions', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { emoji } = req.body || {};
    const messageId = toPositiveInt(req.body?.messageId);
    if (!messageId || !emoji) return res.json({ success: false, message: 'Параметры отсутствуют' });
    if (typeof emoji !== 'string' || !ALLOWED_REACTION_EMOJIS.has(emoji)) return res.json({ success: false, message: 'Недопустимый emoji' });

    try {
        if (!(await userCanAccessMessage(req.session.userId, messageId))) {
            return res.json({ success: false, message: 'Сообщение недоступно' });
        }
        await queryWithRetry('INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [messageId, req.session.userId, emoji]);
        res.json({ success: true });
    } catch (error) {
        if (respondIfDeadlock(res, error)) return;
        logError('Add reaction error', error);
        res.json({ success: false, message: 'Ошибка добавления реакции' });
    }
});

app.delete('/api/reactions/:messageId/:emoji', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = toPositiveInt(req.params.messageId);
    // req.params уже декодирован Express'ом. Повторный decodeURIComponent
    // падал с URIError на любом '%' в параметре — вне try, т.е. ронял процесс.
    const emoji = req.params.emoji;
    if (!messageId || !ALLOWED_REACTION_EMOJIS.has(emoji)) {
        return res.json({ success: false, message: 'Недопустимые параметры' });
    }

    try {
        if (!(await userCanAccessMessage(req.session.userId, messageId))) {
            return res.json({ success: false, message: 'Сообщение недоступно' });
        }
        await dbRun(
            'DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
            [messageId, req.session.userId, emoji]
        );
        res.json({ success: true });
    } catch (error) {
        logError('Remove reaction error', error);
        res.json({ success: false, message: 'Ошибка удаления реакции' });
    }
});

// API для disappearing messages
app.post('/api/messages/:messageId/set-expiry', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = toPositiveInt(req.params.messageId);
    const { autoDeleteOnRead } = req.body || {};
    let expirySeconds;
    try {
        expirySeconds = DisappearingMessagesManager.normalizeExpirySeconds(req.body?.expirySeconds);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    if (!messageId) return res.json({ success: false, message: 'Неверные параметры' });

    try {
        // Проверка доступа к сообщению: свои, видимые, по тегу автора (8.2)
        const message = await findOwnMessage(messageId, req.session.userId);
        if (!message) {
            return res.json({ success: false, message: 'Сообщение не найдено или нет доступа' });
        }

        // Общий таймер чата — верхняя граница: автор может ускорить
        // исчезновение своего сообщения, но не продлить его сверх того, о чём
        // договорилась комната (уже назначенный срок только приближается).
        const chatDefault = await getDefaultExpirySeconds({ id: message.chat_id, room_id: message.room_id });
        await disappearingMessagesManager.setMessageExpiry(
            messageId, effectiveMessageExpiry(expirySeconds, chatDefault), autoDeleteOnRead === true,
            { shortenOnly: Boolean(chatDefault) }
        );

        res.json({ success: true, message: 'Таймер самоуничтожения установлен' });
    } catch (error) {
        logError('Set expiry error', error);
        res.json({ success: false, message: 'Ошибка установки таймера' });
    }
});

app.post('/api/chats/:chatId/expiry', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    let seconds;
    try {
        seconds = parseChatExpirySeconds(req.body?.seconds);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        res.json({ success: true, seconds: await setChatExpiry(chat, seconds) });
    } catch (error) {
        logError('Set chat expiry error', error);
        res.json({ success: false, message: 'Ошибка настройки автоудаления' });
    }
});

// Старый маршрут ({ expirySeconds }) — тот же общий таймер и тот же набор
// допустимых сроков, что и POST /api/chats/:chatId/expiry.
app.post('/api/chats/:chatId/set-default-expiry', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    let seconds;
    try {
        seconds = parseChatExpirySeconds(req.body?.expirySeconds);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }

    try {
        // Проверка доступа к чату
        const chat = await getOwnChat(req.params.chatId, req.session.userId);
        if (!chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const effective = await setChatExpiry(chat, seconds);
        res.json({
            success: true,
            seconds: effective,
            message: seconds > 0 ? 'Автоудаление сообщений настроено для чата' : 'Автоудаление сообщений выключено',
        });
    } catch (error) {
        logError('Set chat default expiry error', error);
        res.json({ success: false, message: 'Ошибка настройки автоудаления' });
    }
});

app.get('/api/chats/:chatId/settings', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });

    try {
        const chat = await getOwnChat(req.params.chatId, req.session.userId);
        if (!chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const expiry = await getDefaultExpirySeconds(chat);
        res.json({ success: true, settings: expiry ? { default_message_expiry: expiry } : {} });
    } catch (error) {
        logError('Get chat settings error', error);
        res.json({ success: false, message: 'Ошибка получения настроек' });
    }
});

// Личные флаги чата: закреплён, без звука, в архиве. Хранятся в строке
// chats самого пользователя — собеседники их не видят. Остальным вкладкам
// и устройствам пользователя — chatListChanged.
app.post('/api/chats/:chatId/prefs', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    let prefs;
    try {
        prefs = parseChatPrefs(req.body);
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    const chatId = toPositiveInt(req.params.chatId);
    if (!chatId) return res.json({ success: false, message: 'Чат не найден' });
    try {
        const row = await dbGet(
            `UPDATE chats SET pinned = COALESCE($3, pinned), muted = COALESCE($4, muted), archived = COALESCE($5, archived)
             WHERE id = $1 AND user_id = $2
             RETURNING pinned, muted, archived`,
            [chatId, userId, prefs.pinned, prefs.muted, prefs.archived]
        );
        if (!row) return res.json({ success: false, message: 'Чат не найден' });
        notifyChatListChanged(userId);
        res.json({ success: true, pinned: row.pinned, muted: row.muted, archived: row.archived });
    } catch (error) {
        logError('Set chat prefs error', error);
        res.json({ success: false, message: 'Ошибка сохранения настроек чата' });
    }
});

// После ВСЕХ маршрутов: неизвестный /api/* — JSON-404.
registerApiNotFound(app);

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    // Ответ из fileFilter multer: 400/409 с кодом контракта порядка сообщений
    // или 200 с уже сохранённым сообщением (повтор отправки).
    if (err instanceof EarlyResponse) return res.status(err.status).json(err.body);
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ success: false, message: 'Файл слишком большой (макс. 50 МБ)' });
        }
        return res.status(400).json({ success: false, message: `Ошибка загрузки: ${err.message}` });
    }
    if (err.message === 'Неподдерживаемый тип файла') {
        return res.status(400).json({ success: false, message: 'Разрешены только фото, видео, PDF и TXT' });
    }
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ success: false, message: 'Некорректный JSON в запросе' });
    }
    if (err.type === 'entity.too.large') {
        return res.status(413).json({ success: false, message: 'Слишком большой запрос' });
    }
    logError('Unhandled error', err);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

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
