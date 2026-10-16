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
const { ipKeyGenerator } = rateLimit;

// Импорт новых модулей безопасности и приватности
const { stripMetadataFromFile, cleanupStaleTempFiles } = require('./lib/metadata-stripper');
const DisappearingMessagesManager = require('./lib/disappearing-messages');
const { encryptText, decryptText, messageAad, encryptRoomText, decryptRoomText, messageAadV3 } = require('./lib/message-crypto');
// Тег автора сообщения комнаты и псевдоним квоты (docs/security/sealed-sender.md):
// ключи те же, что у message-crypto (MESSAGE_ENCRYPTION_KEY и …_PREVIOUS).
const authorTags = require('./lib/author-tag').createAuthorTagsFromEnvironment();
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

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// HSTS preload включает только владелец домена: HSTS_PRELOAD=yes (см. lib/privacy.js).
const HSTS_PRELOAD = process.env.HSTS_PRELOAD === 'yes';

// ALLOWED_MIME_TYPES и MIME_EXTENSIONS (жёсткий маппинг mimetype ->
// расширение на диске, расширение никогда не берётся из имени файла) —
// в lib/security-utils.js, рядом с обезличенными именами вложений.

// Лимит на суммарный объём вложений одного пользователя: без него один
// аккаунт мог забить весь volume (по 50 МБ за запрос, без ограничений).
const UPLOAD_QUOTA_BYTES = Math.floor(positiveNumberOr(process.env.UPLOAD_QUOTA_MB, 500) * 1024 * 1024);

// '.svg' явно в блок-листе как доп. защита (defense-in-depth, п.7 аудита):
// image/svg+xml и так не входит в ALLOWED_MIME_TYPES, но SVG может нести
// <script>, поэтому расширение блокируется отдельно на случай, если формат
// когда-либо попадёт в разрешённый список по ошибке.
const BLOCKED_EXTENSIONS = new Set(['.html', '.htm', '.php', '.exe', '.js', '.sh', '.py', '.rb', '.pl', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.msi', '.svg']);

// Итоговое имя файла на диске должно состоять только из "безопасных" для
// файловой системы символов — доп. страховка на случай, если MIME_EXTENSIONS
// когда-нибудь получит некорректное значение (п.2 аудита, "валидировать
// итоговое имя файла регуляркой").
const SAFE_FILENAME_RE = /^[\w.-]+$/;

// checkMagicBytes (сигнатура файла против заявленного типа) — в
// lib/security-utils.js: чистая функция, её проверяют юнит-тесты.

// Вложения должны лежать на постоянном диске: файловая система контейнера
// (Railway и т.п.) очищается при каждом деплое. UPLOADS_DIR — явный путь;
// RAILWAY_VOLUME_MOUNT_PATH Railway выставляет сам, когда к сервису
// подключён volume.
const UPLOADS_DIR = process.env.UPLOADS_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
try {
    const probe = path.join(UPLOADS_DIR, `.write-test-${process.pid}`);
    fs.writeFileSync(probe, '');
    fs.unlinkSync(probe);
    console.log(`[Uploads] Папка вложений: ${UPLOADS_DIR}`);
} catch (err) {
    logError(`[Uploads] Нет доступа на запись в ${UPLOADS_DIR}, загрузка файлов работать не будет`, err);
}

// Удаляет файлы вложений с диска по их file_url ("/uploads/<name>").
// Вызывается после того, как ссылающиеся на них сообщения удалены из БД.
function removeUploadedFiles(fileUrls) {
    for (const url of fileUrls) {
        if (typeof url !== 'string' || !url.startsWith('/uploads/')) continue;
        const filename = path.basename(url);
        if (!SAFE_FILENAME_RE.test(filename)) continue;
        fs.promises.unlink(path.join(UPLOADS_DIR, filename)).catch(err => {
            // Имя файла в лог не идёт (по нему находят сообщение): logError убирает
            // путь и из текста системной ошибки.
            if (err.code !== 'ENOENT') logError('[Uploads] Не удалось удалить файл вложения', err);
        });
    }
}

// Ответ, который отдаёт обработчик ошибок Express вместо ошибки: так из
// fileFilter multer уходят 400/409 с телом { success, code, message } и даже 200
// с уже сохранённым сообщением (повтор отправки), не принимая файл на диск.
class EarlyResponse extends Error {
    constructor(status, body) {
        super(body && body.message ? body.message : 'early response');
        this.status = status;
        this.body = body;
    }
}

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, UPLOADS_DIR),
        filename: (req, file, cb) => {
            // Расширение — только из MIME_EXTENSIONS (жёсткий маппинг по
            // уже проверенному в fileFilter mimetype), никогда из
            // file.originalname — см. комментарий у MIME_EXTENSIONS.
            // Шифротекст E2EE-вложения — всегда .bin.
            const ext = file.mimetype === ENCRYPTED_FILE_MIME ? ENCRYPTED_FILE_EXTENSION : (MIME_EXTENSIONS[file.mimetype] || '');
            // Имя — только случайное, без Date.now(): время загрузки в имени файла
            // (message-ordering.md, раздел 11) вернуло бы секунды, которые мы
            // огрубили в базе. 16 случайных байт: перебрать нельзя.
            const safeName = `${crypto.randomBytes(16).toString('hex')}${ext}`;
            if (!SAFE_FILENAME_RE.test(safeName)) {
                return cb(new Error('Не удалось сформировать безопасное имя файла'));
            }
            cb(null, safeName);
        }
    }),
    limits: { fileSize: 50 * 1024 * 1024, files: 1, fields: 10 },
    // Имя файла в multipart — UTF-8 (по умолчанию busboy декодировал его как
    // latin1). Само имя больше нигде не хранится, но BLOCKED_EXTENSIONS
    // ниже смотрит на его расширение.
    defParamCharset: 'utf8',
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (BLOCKED_EXTENSIONS.has(ext)) {
            return cb(new Error('Неподдерживаемый тип файла'), false);
        }
        // Поля формы (chatId, encrypted, envelope) клиент шлёт ДО файла,
        // поэтому к этому моменту они уже в req.body. application/octet-stream
        // — это шифротекст E2EE-вложения, и принимается он только с явным
        // encrypted=true: иначе под видом "шифротекста" можно было бы залить
        // любой файл без проверки сигнатуры и очистки метаданных. И наоборот,
        // encrypted=true с обычным типом — тоже отказ.
        const wantsEncrypted = Boolean(req.body) && req.body.encrypted === 'true';
        if (file.mimetype === ENCRYPTED_FILE_MIME) {
            return wantsEncrypted ? acceptUpload(req, file, cb) : cb(new Error('Неподдерживаемый тип файла'), false);
        }
        if (wantsEncrypted || !ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error('Неподдерживаемый тип файла'), false);
        }
        acceptUpload(req, file, cb);
    }
});

// Проверки запроса ДО приёма файла (message-ordering.md, раздел 6.3). multer
// уже разобрал поля формы, пришедшие раньше файла (proto, chatId, encrypted,
// clientMessageId, envelope), а тело файла ещё не читал: заведомо ненужный файл
// на диск не пишется. Клиент обязан класть эти поля в FormData ДО поля file;
// если proto или clientMessageId пришли позже, здесь их ещё нет и ответ — 400
// client-outdated.
//
//   * нет сессии — 401;
//   * нет proto или proto < 4 — 400 client-outdated (14.1);
//   * чат с ботом — clientMessageId игнорируется (id выдаёт DEFAULT);
//   * комната: нет id — 400 client-outdated, неверный формат — 400 bad-message-id;
//   * id занят чужим сообщением или стоит в надгробии — 409 id-conflict;
//   * тот же автор, комната и конверт (повтор после обрыва связи) — 200 с уже
//     сохранённым сообщением, второй файл не принимается.
// Если чата нет среди разобранных полей (chatId пришёл позже файла или чат
// неизвестен), остальное проверит обработчик после приёма файла.
function acceptUpload(req, file, cb) {
    // Поля снимаются СЕЙЧАС, синхронно: fileFilter вызывается в тот момент,
    // когда разобрано всё, что стоит до файла. Пока идёт запрос в базу, парсер
    // может успеть разобрать и поля после небольшого файла, но «после файла»
    // для проверки по-прежнему значит «нет».
    const body = { ...req.body };
    checkUploadBeforeStore(req.session, body, file).then(() => cb(null, true), (err) => cb(err, false));
}

async function checkUploadBeforeStore(session, body, file) {
    const userId = session && session.userId;
    if (!userId) throw new EarlyResponse(401, { success: false, message: 'Не авторизован' });
    // Общий признак версии клиента (message-ordering.md, 14.1) — первая проверка
    // запроса после сессии. Поле proto лежит в FormData ДО файла; пришло позже —
    // здесь его ещё нет, и ответ — client-outdated.
    if (isOutdatedProto(body.proto)) throw new EarlyResponse(400, CLIENT_OUTDATED);
    const chat = toPositiveInt(body.chatId) ? await getOwnChat(body.chatId, userId) : null;
    if (chat && !chat.room_id) {
        // Чат с ботом: шифротекст читать некому — отказ до записи файла на диск.
        const violation = e2eePolicyViolation(chat, body.encrypted === 'true', null);
        if (violation) throw new EarlyResponse(400, violation);
        return;
    }
    const raw = body.clientMessageId;
    if (raw === undefined || raw === null || raw === '') {
        // Чат назван, но такого нет: ответит обработчик («Чат не найден»).
        if (!chat && toPositiveInt(body.chatId)) return;
        throw new EarlyResponse(400, CLIENT_OUTDATED);
    }
    const id = parseClientMessageId(raw);
    if (id === null) throw new EarlyResponse(400, BAD_MESSAGE_ID);
    if (!chat) return;
    // Открытое вложение в комнате и неверный конверт — тоже до записи файла.
    const violation = e2eePolicyViolation(chat, body.encrypted === 'true', typeof body.envelope === 'string' ? body.envelope.trim() : '');
    if (violation) throw new EarlyResponse(400, violation);
    const expectedText = expectedFileMessageText(body, file.mimetype);
    const use = await describeMessageIdUse({ id, roomId: chat.room_id, userId, expectedText, file: true });
    if (use.status === 'duplicate') {
        throw new EarlyResponse(200, { success: true, message: messageFromRow(use.row, expectedText) });
    }
    if (use.status === 'conflict') throw new EarlyResponse(409, ID_CONFLICT);
}

// === Верификация CF-Connecting-IP (см. https://www.cloudflare.com/ips/) ===
// Список подтверждён на 2026-08-10. CF-Connecting-IP — это просто HTTP-заголовок,
// который любой клиент может подставить сам. Доверять ему можно только если сам
// запрос физически пришёл с IP-адреса Cloudflare — иначе, обращаясь напрямую на
// публичный *.up.railway.app домен, атакующий получает "новый IP" на каждый
// запрос и обнуляет все rate-limit'ы по IP (регистрация, вход в комнаты, API).
// Список можно переопределить через переменную окружения CF_IP_RANGES
// (через запятую), если Cloudflare обновит диапазоны.
const DEFAULT_CLOUDFLARE_IP_RANGES = [
    // IPv4
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    // IPv6
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

const cloudflareBlockList = new net.BlockList();
(function loadCloudflareRanges() {
    const ranges = process.env.CF_IP_RANGES
        ? process.env.CF_IP_RANGES.split(',').map(s => s.trim()).filter(Boolean)
        : DEFAULT_CLOUDFLARE_IP_RANGES;
    for (const cidr of ranges) {
        const [addr, prefixStr] = cidr.split('/');
        const type = net.isIP(addr);
        if (!type || !prefixStr) {
            console.warn('[CF] Пропущен некорректный диапазон:', cidr);
            continue;
        }
        cloudflareBlockList.addSubnet(addr, Number(prefixStr), type === 6 ? 'ipv6' : 'ipv4');
    }
})();

function isFromCloudflare(ip) {
    if (!ip) return false;
    const clean = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    const type = net.isIP(clean);
    if (!type) return false;
    try {
        return cloudflareBlockList.check(clean, type === 6 ? 'ipv6' : 'ipv4');
    } catch (e) {
        return false;
    }
}

// connectingIp — адрес, с которого запрос физически пришёл на наш доверенный
// прокси (Railway), а не значение из легко подделываемых заголовков.
function resolveRealIp(headers, connectingIp) {
    const cfIp = headers['cf-connecting-ip'];
    if (cfIp && isFromCloudflare(connectingIp)) {
        return cfIp.split(',')[0].trim();
    }
    return connectingIp;
}

// Метрики процесса: счётчики событий и HTTP по шаблону маршрута (lib/metrics.js).
const metrics = createMetrics();
// Готовность для GET /readyz: порт открывается только после миграций, но флаг
// явный — проба не должна зависеть от порядка запуска.
const readiness = { migrated: false };

const app = express();
app.set('trust proxy', 1);

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
for (const method of ['get', 'post', 'put', 'delete']) {
    const original = app[method].bind(app);
    // app.get('name') с одним аргументом — это чтение настройки, не маршрут.
    app[method] = (routePath, ...handlers) =>
        handlers.length === 0 ? original(routePath) : original(routePath, ...handlers.map(wrapAsync));
}

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';
const toPositiveInt = (value) => {
    const n = Number(value);
    return Number.isInteger(n) && n > 0 ? n : null;
};

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

const rateLimitKeyGenerator = (req) => ipKeyGenerator(req.realIp || req.ip);
const sessionUserId = (req) => (req.session && req.session.userId) || null;
const RATE_LIMIT_DEFAULTS = { standardHeaders: true, legacyHeaders: false };

// Точные лимиты (регистрация, вход по коду, выдача ключей) и одноразовость PoW
// живут в Postgres и создаются ниже, рядом с пулом и SESSION_SECRET
// (lib/pg-limits.js). Здесь — общий лимит /api, он только в памяти.

// 300 запросов за 15 минут (~1 в 3 секунды) активный пользователь чата
// выбирал за несколько минут — особенно когда клиент перезапрашивал
// список чатов на каждое входящее сообщение — после чего всё приложение
// "висло" с ошибкой на 15 минут. Залогиненных считаем по аккаунту (за
// одним NAT или onion-адресом их много), остальных — по IP. Неавторизованные
// onion-запросы не считаются: у них один IP на всех, и любой исчерпал бы
// общую квоту за всех onion-посетителей. Их открытый маршрут (регистрация)
// защищён proof-of-work, а от флуда — защита самого onion-сервиса (см.
// tor-service/README.md).
const apiLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 15 * 60 * 1000,
    max: 1000,
    skip: (req) => req.isOnion && !sessionUserId(req),
    keyGenerator: (req) => (sessionUserId(req) ? `user:${sessionUserId(req)}` : rateLimitKeyGenerator(req)),
    message: { success: false, message: 'Слишком много запросов. Попробуйте позже.' }
});

// Разрешённые "чужие" источники (свои домены-зеркала). Свой хост и
// onion-адрес разрешены и без этого списка.
const ALLOWED_ORIGINS = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
if (ALLOWED_ORIGINS.invalid.length > 0) {
    console.warn('[Origin] ALLOWED_ORIGINS: пропущены некорректные записи:', ALLOWED_ORIGINS.invalid.join(', '));
}

// Запрос пришёл со страницы самого мессенджера (см. isRequestOriginAllowed).
function isTrustedOrigin(headers) {
    return isRequestOriginAllowed({
        origin: headers.origin,
        host: headers.host,
        forwardedHost: headers['x-forwarded-host'],
        secFetchSite: headers['sec-fetch-site'],
        allowed: ALLOWED_ORIGINS,
        isOnionHost,
    });
}

let server;
if (process.env.NODE_ENV === 'production') {
    server = http.createServer(app);
} else {
    const sslOptions = {
        key: fs.existsSync('./localhost+1-key.pem') ? fs.readFileSync('./localhost+1-key.pem') : null,
        cert: fs.existsSync('./localhost+1.pem') ? fs.readFileSync('./localhost+1.pem') : null,
    };
    if (sslOptions.key && sslOptions.cert) {
        server = https.createServer(sslOptions, app);
    } else {
        console.warn('SSL сертификаты не найдены. Запуск HTTP сервера.');
        server = http.createServer(app);
    }
}

// Cross-Site WebSocket Hijacking: сессионная кука уходит и в рукопожатии,
// которое открыла ЧУЖАЯ страница (CORS на WebSocket не действует), — и
// любой сайт, открытый у залогиненного пользователя, мог подключиться к
// сокету от его имени и читать входящие сообщения в реальном времени.
// Рукопожатие (и polling, и websocket) пускаем только со своего источника.
const io = new Server(server, {
    // Клиент socket.io лежит в public/vendor/ и входит в манифест клиента
    // (lib/client-manifest.js): его хэш сверяется с релизом, как у любого
    // другого файла. Раньше сервер сам отдавал /socket.io/socket.io.js из
    // node_modules — мимо статики, и в манифест этот файл не попал бы.
    serveClient: false,
    allowRequest: (req, callback) => {
        if (isTrustedOrigin(req.headers)) return callback(null, true);
        callback('Origin not allowed', false);
    },
});
// Лимиты одновременных сокетов: на аккаунт — всегда, на IP — только для
// clearnet (у всех onion-клиентов один IP — контейнер tor).
const MAX_SOCKETS_PER_USER = 10;
const MAX_SOCKETS_PER_IP = 20;
const userSocketCount = createCounter();
const ipSocketCount = createCounter();

function getClientIp(handshake) {
    const headers = handshake.headers || {};
    // Тот же принцип, что и в HTTP-мидлваре: сначала находим адрес, который
    // реально подключился к нашему прокси (последний хоп X-Forwarded-For —
    // соответствует "доверяем 1 прокси" из app.set('trust proxy', 1)), и только
    // если ЭТОТ адрес принадлежит Cloudflare — доверяем CF-Connecting-IP.
    const xff = headers['x-forwarded-for'];
    const connectingIp = xff
        ? xff.split(',').map(s => s.trim()).filter(Boolean).pop()
        : handshake.address;
    return resolveRealIp(headers, connectingIp);
}

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

async function maybeDumpCa() {
    if (process.env.DUMP_CA !== 'true') return;
    const tls = require('tls');
    const net = require('net');
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) { console.error('DATABASE_URL не задан'); process.exit(1); }
    const parsed = new URL(dbUrl);
    const host = parsed.hostname;
    const port = parseInt(parsed.port) || 5432;
    console.log(`[DUMP_CA] Подключаемся к ${host}:${port}...`);
    await new Promise((resolve, reject) => {
        const socket = net.createConnection(port, host, () => {
            socket.write(Buffer.from([0x00,0x00,0x00,0x08,0x04,0xd2,0x16,0x2f]));
        });
        socket.once('data', (data) => {
            if (data[0] !== 0x53) { reject(new Error('Сервер не поддерживает SSL')); return; }
            const tlsSocket = tls.connect({ socket, host, rejectUnauthorized: false }, () => {
                const chain = [];
                let current = tlsSocket.getPeerCertificate(true);
                const seen = new Set();
                while (current && !seen.has(current.fingerprint)) {
                    seen.add(current.fingerprint);
                    chain.push(current);
                    if (!current.issuerCertificate || current.issuerCertificate === current) break;
                    current = current.issuerCertificate;
                }
                const pemChain = chain.map(c => [
                    '-----BEGIN CERTIFICATE-----',
                    c.raw.toString('base64').match(/.{1,64}/g).join('\n'),
                    '-----END CERTIFICATE-----'
                ].join('\n')).join('\n');
                console.log('\n[DUMP_CA] Найдено сертификатов в цепочке: ' + chain.length);
                chain.forEach((c, i) => {
                    console.log('[DUMP_CA] [' + i + '] subject:', JSON.stringify(c.subject));
                    console.log('[DUMP_CA] [' + i + '] issuer:', JSON.stringify(c.issuer));
                });
                console.log('\n[DUMP_CA] ========= СКОПИРУЙ ВСЁ ЭТО В ПЕРЕМЕННУЮ DB_CA_CERT =========');
                console.log(pemChain);
                console.log('[DUMP_CA] ===================== КОНЕЦ =====================\n');
                tlsSocket.destroy();
                resolve();
            });
            tlsSocket.on('error', reject);
        });
        socket.on('error', reject);
        socket.setTimeout(10000, () => { socket.destroy(); reject(new Error('Таймаут')); });
    });
    process.exit(0);
}

// TLS до Postgres (см. resolveDbTlsConfig): в production без DB_CA_CERT
// сервер стартует только в приватной сети Railway или с явным
// DB_TLS_INSECURE=true. Исключение — DUMP_CA=true: этот режим как раз и
// нужен, чтобы получить цепочку для DB_CA_CERT, и пулом он не пользуется.
const dbTls = resolveDbTlsConfig({
    nodeEnv: process.env.NODE_ENV,
    databaseUrl: process.env.DATABASE_URL,
    caCert: process.env.DB_CA_CERT,
    insecure: process.env.DB_TLS_INSECURE === 'true',
});
if (dbTls.error && process.env.DUMP_CA !== 'true') {
    console.error(dbTls.error);
    process.exit(1);
}
if (dbTls.info) console.log(dbTls.info);
if (dbTls.warning) console.warn(dbTls.warning);
const sslConfig = dbTls.ssl;

// Параметры подключения — общие для основного пула и служебных (пул
// миграций и пул блокировок фоновых задач, см. lib/advisory-locks.js).
const DB_POOL_CONFIG = {
    connectionString: process.env.DATABASE_URL,
    ssl: sslConfig,
    max: Number(process.env.PG_POOL_MAX) || 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
};
const pool = new Pool(DB_POOL_CONFIG);
metrics.attachRuntime({ pool, io });
// Без обработчика 'error' обрыв простаивающего соединения (рестарт или
// failover Postgres, сетевой сбой) — необработанное событие 'error',
// которое завершает весь процесс.
pool.on('error', (err) => {
    logError('[DB] Ошибка простаивающего соединения', err);
});

async function dbGet(query, params = []) {
    const result = await pool.query(query, params);
    return result.rows[0] || null;
}

async function dbAll(query, params = []) {
    const result = await pool.query(query, params);
    return result.rows;
}

async function dbRun(query, params = []) {
    const result = await pool.query(query, params);
    return result;
}
// Менеджер исчезающих сообщений. Удалённые им сообщения сразу пропадают
// и у открытых клиентов (раньше — только после перезагрузки страницы), а
// их вложения удаляются с диска.
const disappearingMessagesManager = new DisappearingMessagesManager(pool, {
    cleanupIntervalMs: process.env.CLEANUP_INTERVAL_MS,
    onMessagesDeleted: (rows) => {
        removeUploadedFiles(rows.map(r => r.file_url));
        for (const row of rows) {
            // У строки комнаты chat_id нет (sealed-sender.md, 8.1): событие несёт только room_id.
            io.to(getSocketRoomKey(row.chat_id, row.room_id)).emit('messageDeleted', row.room_id
                ? { id: String(row.id), room_id: row.room_id }
                : { id: String(row.id), chat_id: row.chat_id, room_id: null });
        }
    },
});
const GLOBAL_DEFAULT_EXPIRY_SECONDS = Math.max(0, Number(process.env.DEFAULT_MESSAGE_EXPIRY_SECONDS) || 0);

// ---- Итоговая схема базы (roadmap R0) ----
//
// Пока новая версия не выкачена, схема описана прямо в DDL initDatabase: все
// изменения волн вносятся в эти CREATE TABLE, без ALTER-миграций, а после
// выката схему меняют только файлы lib/migrations/ (docs/dev/migrations.md).
// Шагов совместимости со старыми схемами здесь нет: схема версии 2.0.0 при
// первом старте сбрасывается целиком (lib/legacy-reset.js), а локальные и
// тестовые базы создаются заново.
//
// initDatabase идемпотентна и идёт под блокировкой миграций на каждом старте:
// CREATE ... IF NOT EXISTS по готовой схеме ничего не меняет. Внешние ключи и
// их ON DELETE заданы прямо в CREATE TABLE. Ключи на users — без каскада:
// deleteUserAccount удаляет строки пользователя сам, в нужном порядке, одной
// транзакцией. Таблицы со своими init*Schema (ключи E2EE, key-share, таймеры
// исчезающих сообщений) создаются в lib/ рядом с кодом, который ими владеет.
async function initDatabase() {
    await maybeDumpCa().catch(err => { logError('[DUMP_CA] Ошибка', err); process.exit(1); });

    // Схема версии 2.0.0 (аккаунты с email и паролем) — сбросить до создания
    // таблиц: реальных пользователей нет, а переносить тестовые данные незачем.
    await resetLegacyDatabase({ pool, uploadsDir: UPLOADS_DIR });

    // Аккаунты только временные (roadmap R2): срок жизни и последняя активность
    // обязательны, по ним чистка удаляет неактивных. created_at — до минуты:
    // точное время регистрации никому не нужно и лишь помогает сопоставить
    // аккаунт с логами. Отметки прочтения выключены, пока пользователь их не
    // включит (POST /api/user/privacy).
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            unique_code TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            avatar TEXT DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            read_receipts BOOLEAN NOT NULL DEFAULT FALSE,
            anon_lifetime TEXT NOT NULL CHECK (anon_lifetime IN ('tab', 'day', 'week')),
            last_active_at TIMESTAMPTZ NOT NULL
        )
    `);
    // Чистка неактивных аккаунтов (раз в несколько минут) идёт по сроку жизни и
    // последней активности, без прохода по всей таблице users.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_lifetime ON users(anon_lifetime, last_active_at)');

    // База счётчиков seq комнат и чатов с ботом (DEFAULT rooms.msg_seq и
    // chats.msg_seq): равномерно из [0; 2^30). 2^32 делится на 2^30 без
    // остатка, поэтому смещения нет, а запас до переполнения INTEGER — 2^30
    // сообщений в одной области. Функция нужна до CREATE TABLE rooms/chats.
    await pool.query(`
        CREATE OR REPLACE FUNCTION nyxo_random_seq_base() RETURNS integer
        LANGUAGE sql VOLATILE AS $fn$
          SELECT (('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8))::bit(32)::bigint % 1073741824)::integer
        $fn$
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            -- последний выданный seq сообщений комнаты (триггер nyxo_message_seq).
            -- Начинается со случайной базы: новичок по seq не узнает, сколько
            -- сообщений было до него
            msg_seq INTEGER NOT NULL DEFAULT nyxo_random_seq_base(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            -- срок жизни кода приглашения (INVITE_TTL_HOURS)
            code_expires_at TIMESTAMPTZ,
            -- параметры кода (POST /api/chats/:chatId/invite/rotate): лимит
            -- участников (NULL — без лимита), вступление только с одобрения
            -- участника, выключенный код
            invite_max_members INTEGER,
            invite_require_approval BOOLEAN NOT NULL DEFAULT TRUE,
            invite_disabled BOOLEAN NOT NULL DEFAULT FALSE,
            -- подписанное приглашение (signed-membership.md, 7.1): сертификат
            -- приглашения (335 байт), снимок состава автора (16 байт на участника)
            -- и автор приглашения (без внешнего ключа: выход или удаление аккаунта
            -- автора обнуляет все три столбца). NULL - код принимает только заявки
            invite_cert BYTEA CHECK (invite_cert IS NULL OR octet_length(invite_cert) = 335),
            invite_snap BYTEA CHECK (invite_snap IS NULL OR (octet_length(invite_snap) % 16 = 0 AND octet_length(invite_snap) <= 16384)),
            invite_actor_id INTEGER,
            CONSTRAINT rooms_invite_signed CHECK (
                (invite_cert IS NULL) = (invite_snap IS NULL) AND (invite_cert IS NULL) = (invite_actor_id IS NULL)
            )
        )
    `);

    // chats.id у каждого участника своя (личная строка), общий для всех —
    // room_id. Комната удаляется целиком — строки chats уходят вместе с ней.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            avatar TEXT NOT NULL,
            online INTEGER DEFAULT 0,
            is_bot INTEGER DEFAULT 0,
            -- счётчик seq чата с ботом (у комнаты он в rooms.msg_seq)
            msg_seq INTEGER NOT NULL DEFAULT nyxo_random_seq_base(),
            -- непрочитанные: seq последнего прочитанного сообщения в личной
            -- строке chats каждого участника. Задаёт приложение при создании
            -- строки (счётчик области на этот момент): «фантомно непрочитанных»
            -- нет, а колонка без DEFAULT не даст забыть об этом
            last_read_seq INTEGER NOT NULL,
            -- порядок чатов без сообщений: id случайные и порядка не несут
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            -- личные флаги чата (POST /api/chats/:chatId/prefs): собеседники их
            -- не видят
            pinned BOOLEAN NOT NULL DEFAULT FALSE,
            muted BOOLEAN NOT NULL DEFAULT FALSE,
            archived BOOLEAN NOT NULL DEFAULT FALSE
        )
    `);

    // Sealed sender на хранении (docs/security/sealed-sender.md): в строке
    // сообщения КОМНАТЫ нет ни user_id, ни chat_id (личная строка отправителя) —
    // вместо них author_tag, псевдоним автора на неделю (lib/author-tag.js).
    // Строка чата с БОТОМ наоборот: chat_id и user_id (владелец; у ответов бота
    // тоже), без тега. Взаимоисключение держит CHECK messages_author_scope.
    // chat_id ... ON DELETE CASCADE: SET NULL нарушил бы CHECK для строк бота при
    // удалении строки chats; файлы каскадно удалённых строк убирает уборщик
    // файлов-сирот. Комната удаляется — сообщения уходят каскадом; ответ на
    // удалённое сообщение теряет связь с оригиналом (SET NULL), а не блокирует
    // удаление. Приложение и так удаляет в правильном порядке (DELETE
    // /api/chats/:chatId, deleteUserAccount), каскады — страховка на случай,
    // если порядок там по ошибке изменят.
    //
    // Порядок сообщений внутри области (комнаты или чата с ботом) задаёт seq, а
    // не id и не created_at (docs/security/message-ordering.md): id случайный
    // (комнатные сообщения его выбирает клиент до шифрования, остальным id
    // выдаёт DEFAULT), created_at огрублён до минуты. seq выдаёт триггер
    // nyxo_message_seq из счётчика строки области; значение из INSERT он
    // игнорирует. Колонки time (HH:MM в часовом поясе сервера) и deleted
    // (удаление физическое) не нужны: клиент форматирует created_at сам.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            seq INTEGER NOT NULL,
            chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            author_tag BYTEA,
            text TEXT NOT NULL,
            file_url TEXT,
            file_name TEXT,
            file_type TEXT,
            message_type TEXT DEFAULT 'text',
            sent INTEGER DEFAULT 1,
            status TEXT DEFAULT 'sent',
            edited_at TIMESTAMPTZ,
            reply_to_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
            -- E2EE: text хранит клиентский шифроконверт вместо обычного текста
            -- (public/e2ee.js). Серверное шифрование "at rest" (lib/message-crypto.js)
            -- применяется поверх в обоих случаях — флаг только про то, что лежит
            -- ВНУТРИ после его снятия.
            encrypted BOOLEAN NOT NULL DEFAULT FALSE,
            -- время хранится с точностью до минуты (раздел 11 контракта):
            -- порядок задаёт seq, точное время лежит только внутри E2EE-конверта
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            -- размер вложения — для квоты UPLOAD_QUOTA_MB
            file_size BIGINT,
            -- В комнате только E2EE-конверты (roadmap R7). Маршруты это уже
            -- проверяют (lib/e2ee-envelope.js); ограничение — второй рубеж на
            -- случай ошибки в коде: открытый текст комнаты не ляжет в базу вовсе.
            CONSTRAINT messages_room_e2ee CHECK (room_id IS NULL OR encrypted),
            CONSTRAINT messages_author_scope CHECK (
                   (room_id IS NULL     AND chat_id IS NOT NULL AND user_id IS NOT NULL AND author_tag IS NULL)
                OR (room_id IS NOT NULL AND chat_id IS NULL     AND user_id IS NULL     AND author_tag IS NOT NULL
                    AND octet_length(author_tag) = 16)
            )
        )
    `);

    // Новичок видит только сообщения комнаты, отправленные ПОСЛЕ его вступления
    // (visible_from_seq — seq последнего сообщения на тот момент; видно
    // сообщения с seq > visible_from_seq). Уникальный (room_id, user_id):
    // проверка "участник ли комнаты" идёт на каждый файл, реакцию и joinChat, и
    // один пользователь не может оказаться в комнате дважды (с двумя
    // visible_from_seq).
    await pool.query(`
        CREATE TABLE IF NOT EXISTS room_participants (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            visible_from_seq INTEGER NOT NULL,
            UNIQUE (room_id, user_id)
        )
    `);

    // Сертификаты состава группы (signed-membership.md, 7.1): допуск (vouch, 1), вход по
    // приглашению (join, 3) и повторный допуск (revouch, 4); приглашение (invite) лежит
    // в rooms. Времени создания нет: минута допуска внутри сертификата. Субъекта нет
    // среди внешних ключей: строки удаляет приложение вместе с выходом или удалением
    // аккаунта субъекта и подписавшего (порядок блокировок message-ordering.md, 8.1:
    // после chats, до user_left_rooms), комната - каскадом.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS room_member_certs (
            room_id    INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            subject_id INTEGER NOT NULL,
            actor_id   INTEGER NOT NULL,
            kind       SMALLINT NOT NULL CHECK (kind IN (1, 3, 4)),
            cert       BYTEA NOT NULL CHECK (octet_length(cert) IN (271, 335)),
            aux        BYTEA CHECK (aux IS NULL OR octet_length(aux) = 335),
            snap       BYTEA CHECK (snap IS NULL OR (octet_length(snap) % 16 = 0 AND octet_length(snap) <= 16384)),
            PRIMARY KEY (room_id, subject_id, actor_id, kind),
            CONSTRAINT room_member_certs_length CHECK (octet_length(cert) = CASE kind WHEN 3 THEN 335 ELSE 271 END)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_rmc_subject ON room_member_certs(subject_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_rmc_actor ON room_member_certs(actor_id)');

    // Комнаты, откуда пользователь вышел, оставив там сообщения (sealed-sender.md,
    // 5 и 12): удаление аккаунта удаляет их во всех таких комнатах, а теги без
    // этой записи найти было бы негде. Запись создаётся только если у пользователя
    // там остались сообщения. Ключ на users - без каскада (как у остальных таблиц
    // пользователя: deleteUserAccount удаляет строки сам), на rooms - с каскадом.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_left_rooms (
            user_id INTEGER NOT NULL REFERENCES users(id),
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, room_id)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_user_left_rooms_room ON user_left_rooms(room_id)');
    // Квота вложений под псевдонимом qkey (lib/upload-quota.js): в users столбцов
    // окна нет, а в самой таблице нет user_id.
    await initUploadQuotaSchema(pool);

    // Реакции исчезают вместе со своим сообщением: иначе снос всех сообщений
    // комнаты падал бы на внешнем ключе, как только у любого есть реакция.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS reactions (
            id SERIAL PRIMARY KEY,
            message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            emoji TEXT NOT NULL,
            UNIQUE (message_id, user_id, emoji)
        )
    `);
    await initJoinRequests();

    // Сессии: тот же DDL, что у connect-pg-simple (его table.sql). Стор создал
    // бы таблицу сам при первом запросе, но индекс по пользователю нужен сразу:
    // выход и удаление аккаунта сбрасывают все его сессии (sess->>'userId'), и
    // без индекса это проход по всей таблице.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS session (
            sid VARCHAR NOT NULL COLLATE "default",
            sess JSON NOT NULL,
            expire TIMESTAMP(6) NOT NULL,
            CONSTRAINT session_pkey PRIMARY KEY (sid)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON session(expire)');
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_session_user ON session((sess->>'userId'))`);

    await initE2eeGroupsSchema(pool);
    // Лимиты и использованные решения PoW (UNLOGGED, lib/pg-limits.js).
    await initPgLimitsSchema(pool);
    // Публичные E2EE-ключи хранятся в этой же базе (lib/key-store.js).
    await initKeyStoreSchema(pool);
    // Таблицы message_expiry/chat_settings/room_settings ссылаются на
    // messages/chats/rooms, поэтому создаются только после них.
    await disappearingMessagesManager.initialize();

    // Индексы для выборок "сообщения области по seq". Это же уникальные
    // индексы порядка (O1 контракта): пара (область, seq) не повторяется, а
    // seq растёт в порядке фиксации вставок. Включённые колонки позволяют
    // последнему сообщению, счётчику непрочитанного, странице истории и
    // кандидатам поиска читаться index-only scan'ом: без них планировщик
    // выбирал бы обратный проход по первичному ключу с фильтром по room_id —
    // для "тихой" комнаты это просмотр почти всей таблицы. В списке INCLUDE нет
    // ни id, ни seq: они уже в ключе или в первичном ключе. Каскад удаления
    // комнаты обслуживает префикс (room_id).
    await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_room_seq ON messages(room_id, seq) INCLUDE (sent, encrypted) WHERE room_id IS NOT NULL');
    await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_chat_seq ON messages(chat_id, seq) INCLUDE (user_id, sent, encrypted) WHERE room_id IS NULL');
    // Внешний ключ messages.chat_id ... ON DELETE CASCADE: частичный индекс
    // выше по условию запроса RI (chat_id = $1, без room_id IS NULL) не
    // применим, и без этого индекса удаление каждой строки chats сканировало бы
    // всю таблицу messages (выход из комнаты, удаление аккаунта).
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id) WHERE chat_id IS NOT NULL');
    // Внешний ключ messages.user_id (только чат с ботом): запрос RI при удалении
    // users - `WHERE user_id = $1`, и частичный индекс с условием по room_id он
    // бы не использовал. Условие user_id IS NOT NULL следует из равенства, а
    // строки комнат (user_id NULL) в индекс не попадают.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id) WHERE user_id IS NOT NULL');
    // Тег автора: правка, удаление, прочитано, выход и удаление аккаунта ищут
    // строки комнаты по (комната, набор тегов).
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_room_author ON messages(room_id, author_tag) WHERE room_id IS NOT NULL');
    // Каждая картинка/файл в чате проверяет доступ поиском по file_url —
    // без индекса это был бы полный проход по всей таблице messages на КАЖДЫЙ
    // запрос /uploads/*.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_file_url ON messages(file_url) WHERE file_url IS NOT NULL');
    // Для ON DELETE SET NULL по reply_to_id: без индекса удаление каждого
    // сообщения сканировало бы всю таблицу в поисках ответов на него (снос
    // комнаты с N сообщениями — N полных проходов).
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_reply_to_id ON messages(reply_to_id) WHERE reply_to_id IS NOT NULL');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_room_id ON chats(room_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_room_participants_user ON room_participants(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id)');
    // Авто-разархивация получателей идёт на КАЖДОЕ новое сообщение комнаты;
    // по частичному индексу она читает только архивные строки комнаты
    // (обычно ни одной), а не строки всех её участников.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_archived ON chats(room_id) WHERE archived');

    await setRandomIdDefaults();
    // Надгробия id, триггеры seq и проверки id (lib/message-order-schema.js):
    // нужны messages, rooms, chats и DEFAULT id выше.
    await initMessageOrderSchema(pool);

    console.log('База данных инициализирована');
}

// ---- Случайные id для users, rooms, chats, join_requests, messages ----
//
// Последовательные id выдавали размер и темп роста сервиса (id свежей
// регистрации = число пользователей) и порядок событий: по id комнаты или
// чата было видно, кто и когда создал её раньше. Поэтому id этих таблиц —
// случайные из [1 000 000, 2^31 - 1]: 48 бит из gen_random_uuid() (PG 13+,
// внутри pg_strong_random — криптостойкий ГСЧ; первые 12 hex-цифр UUIDv4
// случайны целиком) по модулю размера диапазона (смещение ~2^-17 — не
// различимо), с перепроверкой занятости в цикле. У messages порядок и
// непрочитанное держатся не на id, а на seq (message-ordering.md); id
// сообщений комнаты выбирает клиент, DEFAULT нужен чату с ботом.
//
// Тело функции — константа: database.sql содержит ту же функцию.
const RANDOM_ID_FUNCTION_BODY = `
DECLARE
    candidate integer;
    taken boolean;
BEGIN
    LOOP
        candidate := (1000000 + ('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 12))::bit(48)::bigint % 2146483648)::integer;
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE id = $1)', target) INTO taken USING candidate;
        IF NOT taken THEN
            RETURN candidate;
        END IF;
    END LOOP;
END
`;
const RANDOM_ID_TABLES = ['users', 'rooms', 'chats', 'join_requests', 'messages'];

// DEFAULT со ссылкой на таблицу (nyxo_random_id('users'::regclass)) можно
// задать только после CREATE TABLE: внутри него таблицы ещё нет, поэтому
// отдельным ALTER. ALTER берёт ACCESS EXCLUSIVE блокировку, и повторять его на
// каждом старте незачем: он выполняется только там, где DEFAULT ещё не задан.
async function setRandomIdDefaults() {
    await pool.query(`
        CREATE OR REPLACE FUNCTION nyxo_random_id(target regclass) RETURNS integer
        LANGUAGE plpgsql VOLATILE AS $fn$${RANDOM_ID_FUNCTION_BODY}$fn$
    `);
    const current = await dbAll(
        `SELECT table_name, column_default FROM information_schema.columns
         WHERE table_schema = current_schema() AND column_name = 'id' AND table_name = ANY($1::text[])`,
        [RANDOM_ID_TABLES]
    );
    for (const table of RANDOM_ID_TABLES) {
        const row = current.find(r => r.table_name === table);
        if (!String((row && row.column_default) || '').includes('nyxo_random_id(')) {
            await pool.query(`ALTER TABLE ${table} ALTER COLUMN id SET DEFAULT nyxo_random_id('${table}'::regclass)`);
        }
    }
}

// Заявки на вступление (комнаты с одобрением). join_requests.id виден
// заявителю и участникам комнаты — он случайный, как id пользователей и
// комнат (DEFAULT ставит setRandomIdDefaults), чтобы по нему нельзя было
// судить, сколько заявок подают по всему сервису. Внешний ключ на users без
// каскада — как у остальных таблиц: deleteUserAccount удаляет строки сам.
async function initJoinRequests() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS join_requests (
            id INTEGER PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            UNIQUE (room_id, user_id)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_join_requests_user ON join_requests(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_join_requests_created ON join_requests(created_at)');
}

function getSocketRoomKey(chatId, roomId) {
    return roomId ? `room:${roomId}` : `chat:${chatId}`;
}

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

// Коды без смещения распределения — см. randomString в lib/security-utils.js.
async function generateUniqueCodeAsync() {
    for (let attempts = 0; attempts < 100; attempts++) {
        const code = generateUniqueCode();
        const row = await dbGet('SELECT id FROM users WHERE unique_code = $1', [code]);
        if (!row) return code;
    }
    throw new Error('Could not generate unique code');
}

async function generateAnonymousUsernameAsync() {
    for (let attempts = 0; attempts < 100; attempts++) {
        const username = `Гость-${randomString('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 4)}`;
        const row = await dbGet('SELECT id FROM users WHERE username = $1', [username]);
        if (!row) return username;
    }
    throw new Error('Could not generate anonymous username');
}

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

// ---- Точные лимиты в Postgres (lib/pg-limits.js, roadmap R11) ----
//
// Регистрация, вход по коду, выдача bundle ключей и одноразовость решений PoW
// переживают рестарт: счётчики лежат в UNLOGGED-таблицах, ключи клиентов (IP,
// id) — только как HMAC от SESSION_SECRET. Ошибка хранилища закрывает лимит:
// 503 {success:false, code:'busy'}. Ключ PoW тоже выводится из SESSION_SECRET,
// чтобы выданные задачи действовали и после рестарта.
setPowSecret(sessionSecret);
const pgLimits = createPgLimits({
    pool,
    secret: sessionSecret,
    hooks: { limited: metrics.rateLimited, storeError: metrics.limitStoreError },
});
const powUsedStore = pgLimits.powUsedStore();
const bundleLimiter = pgLimits.slidingLimiter('bundle');
// Отправки key-share (30 в час на пару «пользователь, комната») и запросы ключа (10 в час).
const keyShareLimiter = pgLimits.slidingLimiter('keyshare');
const keyRequestLimiter = pgLimits.slidingLimiter('keyreq');
// Публикация и чтение сертификатов состава (signed-membership.md, 7.2).
const memberCertLimiter = pgLimits.slidingLimiter('memcert');

// CSRF-токен привязан к сессии: ключ выводится из SESSION_SECRET (HKDF), так что
// смена секрета заодно сбрасывает все выданные токены.
const csrf = createCsrf({ secret: sessionSecret, onRejected: metrics.csrfRejected });

// Массовую регистрацию сдерживает proof-of-work (lib/pow.js). IP-лимит остался
// мягким и только для clearnet: для onion он запер бы регистрацию всем сразу
// (общий IP контейнера tor).
const registerLimiter = pgLimits.rateLimiter('register', {
    windowMs: 60 * 60 * 1000,
    max: 10,
    skip: (req) => req.isOnion,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много регистраций. Попробуйте позже.' }
});

// Вход в комнату по коду: даже 130-битный код не должен перебираться
// с бесконечной скоростью, и утёкший список кодов — массово проверяться.
const joinUserLimiter = pgLimits.rateLimiter('join-user', {
    windowMs: 15 * 60 * 1000,
    max: 20,
    skip: (req) => !sessionUserId(req),
    keyGenerator: (req) => `user:${sessionUserId(req)}`,
    message: { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' }
});
const joinIpLimiter = pgLimits.rateLimiter('join-ip', {
    windowMs: 15 * 60 * 1000,
    max: 60,
    skip: (req) => req.isOnion,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' }
});

// Интервал продления сессии: 5 минут; в сквозных тестах —
// NYXO_TEST_RENEW_INTERVAL_MS (только при NODE_ENV=test).
const SESSION_RENEW_MS = sessionRenewIntervalMs(process.env);
if (SESSION_RENEW_MS !== SESSION_RENEW_INTERVAL_MS) {
    console.log(`[Test] NYXO_TEST_RENEW_INTERVAL_MS=${SESSION_RENEW_MS}: сессии продлеваются каждые ${SESSION_RENEW_MS} мс`);
}

// NyxoPgStore (lib/session-store.js) — стор connect-pg-simple, который пишет
// время в таблицу session огрублённым до 5 минут и без createdAt.
const NyxoPgStore = createNyxoPgStore(session);
const sessionMiddleware = session({
    store: new NyxoPgStore({
        pool: pool,
        tableName: 'session',
        createTableIfMissing: true,
        // touch стора писал бы строку session на КАЖДЫЙ запрос. Сессия
        // продлевается явно: маркером renewSession не чаще раза в интервал
        // (middleware после sessionMiddleware) и touch открытых сокетов.
        disableTouch: true
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        // 'auto' — Secure по фактическому протоколу запроса (req.secure с
        // учётом X-Forwarded-Proto от доверенного прокси; для .onion его
        // выставляет onionMiddleware). Жёсткий secure: true ломал вход везде,
        // где до приложения доходит plain http.
        secure: IS_PRODUCTION ? 'auto' : false,
        // Раньше в production было 'none' — кука уходила с любого сайта, в том
        // числе в межсайтовое WebSocket-рукопожатие и POST-формы. 'lax'
        // оставляет её только своим запросам и переходам по ссылке.
        sameSite: 'lax'
    }
});

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

// Socket.io: источник (allowRequest выше) -> сессия -> авторизация ->
// лимит подключений на аккаунт и (для clearnet) на IP.
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});
io.use((socket, next) => {
    const sess = socket.request.session;
    // Раньше неавторизованный сокет принимался и тут же отключался уже в
    // 'connection' — клиент после этого сам не переподключался, и после
    // входа в аккаунт realtime не работал до перезагрузки страницы.
    if (!sess || !sess.userId) return next(new Error('Не авторизован'));
    // Та же проверка, что у HTTP-запросов. Продлить куку сокет не может —
    // её ставит только HTTP-ответ (клиент для этого вызывает /api/auth).
    anonActivity.validateSession(sess).then((verdict) => {
        if (verdict !== 'ok') return next(new Error('Не авторизован'));
        if (userSocketCount.get(sess.userId) >= MAX_SOCKETS_PER_USER) {
            return next(new Error('Слишком много подключений'));
        }
        // Onion-рукопожатие (сокет принят на ONION_PORT) приходит с адреса
        // контейнера tor — одного на всех, а его X-Forwarded-For присылает сам
        // клиент: IP тут ничего не значит.
        const ip = isOnionSocket(socket.request.socket) ? null : getClientIp(socket.handshake);
        if (ip && ipSocketCount.get(ip) >= MAX_SOCKETS_PER_IP) {
            return next(new Error('Слишком много подключений с вашего IP'));
        }
        socket.data.clientIp = ip;
        next();
    }, (err) => {
        logError('[Socket] Ошибка проверки сессии', err);
        next(new Error('Ошибка сервера'));
    });
});

io.on('connection', async (socket) => {
    const userId = socket.request.session.userId;

    // Счётчики растут только для реально установленных соединений. Раньше
    // счётчик IP увеличивался ещё в middleware, а единственное место
    // уменьшения — 'disconnect' — для отклонённого рукопожатия не наступает:
    // IP мог навсегда упереться в лимит. userSocketCount заодно — признак
    // «в сети на этом экземпляре» для touch и чистки неактивных.
    const ip = socket.data.clientIp;
    userSocketCount.increment(userId);
    if (ip) ipSocketCount.increment(ip);
    // Подключение — активность (в БД — не чаще раза за корзину).
    anonActivity.noteActivity(userId);
    socket.on('disconnect', () => {
        userSocketCount.decrement(userId);
        if (ip) ipSocketCount.decrement(ip);
        // Закрылся последний сокет — отсчёт неактивности начинается отсюда:
        // корзина этого момента попадает в БД.
        if (userSocketCount.get(userId) === 0) anonActivity.noteActivity(userId);
    });

    // Личная комната пользователя (на всех его вкладках/устройствах) —
    // адресная доставка событий конкретному человеку (E2EE key-share,
    // подписка на новый чат, принудительный выход).
    socket.join('user:' + userId);

    socket.on('joinChat', async (roomKey) => {
        if (typeof roomKey !== 'string' || roomKey.length === 0) return;
        try {
            if (roomKey.startsWith('room:')) {
                const roomId = parseInt(roomKey.slice(5), 10);
                if (!Number.isFinite(roomId)) return;
                const participant = await dbGet(
                    'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2',
                    [roomId, userId]
                );
                if (!participant) return;
            } else if (roomKey.startsWith('chat:')) {
                const chatId = parseInt(roomKey.slice(5), 10);
                if (!Number.isFinite(chatId)) return;
                const chat = await dbGet(
                    'SELECT id FROM chats WHERE id = $1 AND user_id = $2',
                    [chatId, userId]
                );
                if (!chat) return;
            } else {
                return;
            }
            socket.join(roomKey);
        } catch (err) {
            logError('joinChat error', err);
        }
    });

    // Сразу подписываем сокет на ВСЕ чаты пользователя. Раньше подписка
    // появлялась только при открытии конкретного чата, поэтому новые
    // сообщения в остальных чатах не обновляли ни список, ни счётчики.
    try {
        const chats = await dbAll('SELECT id, room_id FROM chats WHERE user_id = $1', [userId]);
        socket.join(chats.map(c => getSocketRoomKey(c.id, c.room_id)));
    } catch (err) {
        logError('Socket auto-join error', err);
    }
});

// Подписать/отписать все сокеты пользователя (все вкладки) на чат.
function subscribeUserToChat(userId, chatId, roomId) {
    io.in('user:' + userId).socketsJoin(getSocketRoomKey(chatId, roomId));
}
function unsubscribeUserFromChat(userId, chatId, roomId) {
    io.in('user:' + userId).socketsLeave(getSocketRoomKey(chatId, roomId));
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

// Маршруты из lib/routes/ (см. lib/routes/index.js): здесь — те, которым
// сессия не нужна; ниже, после лимитера /api/, — обычные маршруты API.
// Журнал ключей: без KT_SIGNING_KEY сервис выключен (kt.enabled = false) — регистраций
// и задачи эпох нет, kt в ответах null, /api/kt/* отвечает 503. Длина эпохи и поколения —
// константы протокола; тестовые ручки KT_* действуют только при NODE_ENV=test.
const kt = createKtService({ pool, withTransaction, onEpochClosed: metrics.ktEpochClosed });
metrics.attachKt(() => kt.stats());

// serverContext — общий контекст маршрутов и задач из lib/ (lib/jobs).
const serverContext = Object.freeze({
    pool, dbGet, dbAll, dbRun, withTransaction, io, logError, isProduction: IS_PRODUCTION, kt,
    // Мониторинг и security.txt (lib/routes/health.js, lib/routes/well-known.js).
    metrics, readiness, env: process.env,
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

// ---- Текст сообщения в БД: шифрование at rest с AAD ----
//
// Строка КОМНАТЫ шифруется enc:v3 (lib/message-crypto.js): AAD привязывает
// шифротекст к комнате, к id сообщения и к author_tag строки (пользователя в AAD
// нет: в строке комнаты нет user_id, sealed-sender.md, раздел 7). Шифротекст,
// перенесённый в другую комнату, под другой id или под другой тег, не
// расшифруется. Строка чата с БОТОМ — enc:v2 с AAD из чата и владельца.
// Поэтому везде, где читается или пишется messages.text, выбираются поля этой же
// строки: room_id, id, author_tag (комната) или chat_id, user_id (бот).
const UNREADABLE_TEXT = '[Не удалось расшифровать]';

function writeMessageText(text, row) {
    if (row.room_id) return encryptRoomText(text, messageAadV3(row));
    return encryptText(text, messageAad(row));
}

function readMessageText(stored, row) {
    if (stored === null || stored === undefined) return stored;
    try {
        return row.room_id ? decryptRoomText(stored, messageAadV3(row)) : decryptText(stored, messageAad(row));
    } catch (err) {
        // AAD не собирается только у строки без обязательных полей (комната без
        // id или тега, чат без владельца, осиротевшее сообщение) — показать её
        // всё равно некому и нечем.
        logError('[MessageCrypto] Нет AAD для сообщения', err);
        return UNREADABLE_TEXT;
    }
}

// Новая сессия с защитой от фиксации (regenerate): id сессии, который был
// у браузера до регистрации, к аккаунту не привязывается.
function startUserSession(req, fields) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
            if (err) return reject(err);
            Object.assign(req.session, fields);
            // Новая сессия — новая привязка CSRF-токена: токен «до входа» или от
            // прежней сессии больше не подходит, клиент получает новый в этом же ответе.
            csrf.issue(req, req.res);
            resolve();
        });
    });
}

// Proof-of-work (lib/pow.js): решение одноразовое и привязано к цели.
// Цель одна — регистрация временного аккаунта; ?purpose=register — 400.
const POW_PURPOSES = new Set(['register-anon']);
const POW_FAILED_RESPONSE = { success: false, message: 'Не пройдена проверка proof-of-work', powRequired: true };

// 'ok' | 'invalid' | 'replayed' | 'busy'. Задача сжигается в Postgres
// (pow_used) только у решения, прошедшего проверку, — неверный nonce её не
// тратит. Хранилище не отвечает — 'busy': регистрацию без проверки
// одноразовости не пропускаем (лимит закрывается), а решение остаётся
// несожжённым — клиент повторит его позже.
async function checkPow(req, purpose) {
    const solution = req.body && req.body.pow;
    if (!solution || typeof solution !== 'object') return 'invalid';
    try {
        return await consumeSolution(solution, purpose, powUsedStore);
    } catch (err) {
        // Сбой хранилища уже записан в лог самим хранилищем.
        if (!(err instanceof LimitStoreError)) logError('[PoW] Ошибка проверки решения', err);
        return 'busy';
    }
}

function respondPowFailure(res, verdict) {
    metrics.powRejected(verdict);
    if (verdict === 'busy') return respondBusy(res);
    return res.json(POW_FAILED_RESPONSE);
}

app.get('/api/pow/challenge', (req, res) => {
    const purpose = typeof req.query.purpose === 'string' ? req.query.purpose : '';
    if (!POW_PURPOSES.has(purpose)) {
        return res.status(400).json({ success: false, message: 'Некорректная цель проверки' });
    }
    const { token, difficulty } = createChallenge(purpose);
    res.json({ success: true, token, difficulty });
});

// Новый аккаунт и его чат с ботом с приветствием — внутри транзакции client.
// lastActiveAt — корзина активности момента регистрации (lib/anon-lifetime.js).
// Отметки о прочтении у нового аккаунта выключены явно, а не через DEFAULT
// колонки: ответ регистрации обещает readReceipts: false. Текст приветствия
// выбирает вызывающий. Возвращает { userId, botChatId } — id чата с ботом
// уходит клиенту.
async function insertUserWithBotChat(client, { uniqueCode, username, anonLifetime, lastActiveAt, welcomeText }) {
    const userResult = await client.query(
        `INSERT INTO users (unique_code, username, avatar, anon_lifetime, last_active_at, read_receipts)
         VALUES ($1, $2, $3, $4, $5, FALSE)
         RETURNING id`,
        [uniqueCode, username, '#667EEA', anonLifetime, lastActiveAt]
    );
    const userId = userResult.rows[0].id;
    // Счётчик seq чата с ботом и маркер прочитанного начинаются с одной и той
    // же случайной базы: непрочитанным станет только приветствие, которое
    // вставляется следом.
    const botResult = await client.query(
        `WITH base AS (SELECT nyxo_random_seq_base() AS seq)
         INSERT INTO chats (user_id, name, avatar, online, is_bot, msg_seq, last_read_seq)
         SELECT $1::int, $2::text, $3::text, $4::int, $5::int, base.seq, base.seq FROM base
         RETURNING id`,
        [userId, 'Бот Помощник', 'Б', 1, 1]
    );
    const botChatId = botResult.rows[0].id;
    await client.query(
        `INSERT INTO messages (chat_id, user_id, text, sent, status) VALUES ($1, $2, $3, 0, 'read')`,
        [botChatId, userId, writeMessageText(welcomeText, { room_id: null, chat_id: botChatId, user_id: userId })]
    );
    return { userId, botChatId };
}

async function withTransaction(work) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await work(client);
        await client.query('COMMIT');
        return result;
    } catch (txErr) {
        // Исходная ошибка важнее: сбой самого ROLLBACK её не затирает.
        await client.query('ROLLBACK').catch(() => {});
        throw txErr;
    } finally {
        client.release();
    }
}

// Транзакция с одним повтором при взаимной блокировке (40P01, раздел 8.3
// контракта порядка сообщений; lib/tx-retry.js). Первая попытка откатилась
// целиком, поэтому повтор безопасен: work() обязана не иметь побочных эффектов
// вне БД и читать всё заново (вставка сообщения идемпотентна по clientMessageId).
// Если вторая попытка тоже упала с 40P01, ошибка уходит вызывающему, а он
// отвечает 503 busy (respondIfDeadlock). В лог — только код ошибки, без id.
// Строка предупреждения нужна сквозным тестам блокировок: они считают повторы.
const withTransactionRetry = createTransactionRetry({ withTransaction, warn: (message) => console.warn(message) });

// Один оператор с повтором при 40P01: для записей, которые не вошли в порядок
// блокировок целиком (реакции, заявки, key-share — раздел 8.2), но ссылаются на
// users и rooms внешними ключами и потому могут сойтись с удалением аккаунта.
function queryWithRetry(sql, params) {
    return withTransactionRetry((client) => client.query(sql, params));
}

// Ответ на взаимную блокировку, которая повторилась и после повтора
// (withTransactionRetry): 503 { code:'busy' } с Retry-After. В лог — только
// код ошибки, без id. true — ошибка обработана, ответ отправлен.
function respondIfDeadlock(res, err) {
    if (!isDeadlock(err)) return false;
    logError('[DB] Взаимная блокировка повторилась, клиенту 503', err);
    respondBusy(res);
    return true;
}

// Вставки, где id выдаёт DEFAULT (чат с ботом, приветствие): два одинаковых
// случайных id в одну минуту или попадание в надгробие — один повтор на 23505
// по id сообщения (message-ids.js: isMessageIdConflict).
async function withMessageIdRetry(work) {
    try {
        return await work();
    } catch (err) {
        if (!isMessageIdConflict(err)) throw err;
        return work();
    }
}

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

// Завершает сессию после удаления аккаунта. Clear-Site-Data: "cache" —
// браузер выбрасывает кэш сайта (страницы, вложения), чтобы на общем
// устройстве не оставалось следов переписки.
function endSession(req, res, message) {
    req.session.destroy((err) => {
        if (err) logError('[Account] Не удалось удалить сессию', err);
        res.clearCookie('connect.sid');
        // CSRF-куку не удаляем, а выдаём новую (под привязку «до входа», с новым
        // nyxo_pre): страница после удаления не перезагружается, и следующая
        // регистрация без куки получила бы 403 «неверный CSRF-токен».
        csrf.issue(req, res, { freshPre: true });
        res.set('Clear-Site-Data', '"cache"');
        res.json({ success: true, message });
    });
}

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

// Поля аккаунта для ответов API — из строки users: срок и корзина последней
// активности (её только что записал middleware после sessionMiddleware,
// если корзина сменилась). anonExpiresAt — «когда удалится, если больше не
// будет активности».
async function loadAccount(userId) {
    const row = await dbGet(
        `SELECT username, unique_code, read_receipts, anon_lifetime,
                EXTRACT(EPOCH FROM last_active_at) * 1000 AS last_active_ms
         FROM users WHERE id = $1`,
        [userId]
    );
    if (!row) return null;
    return {
        id: userId,
        username: row.username,
        uniqueCode: row.unique_code,
        readReceipts: row.read_receipts,
        ...describeAnonLifetime({
            lifetime: row.anon_lifetime,
            lastActiveMs: row.last_active_ms === null ? null : Number(row.last_active_ms),
        }),
    };
}

// «Не вошёл» (контракт этапа 1, §3): reason/expired — только если сессия
// была, но аккаунт удалён по сроку или сессия недействительна. Клиент
// покажет «данные удалены по сроку», а не просто экран входа.
function signedOutResponse(req) {
    const body = { authenticated: false };
    if (req.authEnded) {
        body.reason = 'expired';
        body.expired = true;
    }
    body.onionUrl = onionUrlFor(req);
    return body;
}

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

// Личная строка chats вызывающего (chats.id — у каждого участника своя) и
// граница видимости истории: visible_from_seq — seq последнего сообщения
// комнаты на момент вступления, видно только то, что новее, то есть с
// seq > visible_from_seq (для чата с ботом и создателя комнаты — 0, то есть
// всё: seq всегда не меньше 1).
async function getOwnChat(chatId, userId) {
    const id = toPositiveInt(chatId);
    if (!id) return null;
    return dbGet(
        `SELECT c.*, COALESCE(rp.visible_from_seq, 0) AS visible_from_seq
         FROM chats c
         LEFT JOIN room_participants rp ON rp.room_id = c.room_id AND rp.user_id = c.user_id
         WHERE c.id = $1 AND c.user_id = $2`,
        [id, userId]
    );
}

// Сообщения чата лежат либо по room_id (групповая комната), либо по
// chat_id (личный чат с ботом). where(alias, param) — условие WHERE для таблицы
// messages под этим псевдонимом, param (по умолчанию $1) — номер параметра со value. У чата с ботом условие
// содержит и room_id IS NULL: так запрос ложится на частичный уникальный
// индекс idx_messages_chat_seq (у сообщений комнаты chat_id — личная строка
// их автора, а не область). Сравнивать seq можно только внутри одной области.
function chatScope(chat) {
    const room = Boolean(chat.room_id);
    return {
        column: room ? 'room_id' : 'chat_id',
        value: room ? chat.room_id : chat.id,
        where: (alias = 'm', param = '$1') => (room ? `${alias}.room_id = ${param}` : `${alias}.chat_id = ${param} AND ${alias}.room_id IS NULL`),
    };
}

// Сообщение в ответах и событиях API: id — всегда строка, seq — число
// (message-ordering.md, 6.1). Остальные поля как были.
function apiMessage(message) {
    const out = { ...message };
    if (out.id !== undefined && out.id !== null) out.id = String(out.id);
    if (out.seq !== undefined && out.seq !== null) out.seq = Number(out.seq);
    if (out.reply_to_id !== undefined && out.reply_to_id !== null) out.reply_to_id = String(out.reply_to_id);
    if (out.reply_to && out.reply_to.id !== undefined && out.reply_to.id !== null) {
        out.reply_to = { ...out.reply_to, id: String(out.reply_to.id) };
    }
    return out;
}

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

// Отмечает сообщения чата прочитанными вплоть до upToSeq: двигает личный
// маркер непрочитанного (last_read_seq только растёт), ставит статус 'read'
// чужим сообщениям (у отправителя появляются ✓✓) и запускает
// auto-delete-on-read.
//
// «Чужие» в комнате — строки, чей author_tag не входит в теги читателя
// (sealed-sender.md, 8.4): сервер вычисляет их из сессии (комната, пользователь,
// все недели с создания аккаунта, все ключи сообщений). В чате с ботом — по
// user_id, как раньше.
//
// Если читатель выключил отметки прочтения (users.read_receipts), двигается
// только его личный маркер: статус сообщений не меняется и messagesRead не
// рассылается. Auto-delete-on-read срабатывает всё равно — это обещание
// отправителя, а не отметка для него.
//
// Два оператора, не одна транзакция (раздел 8.2 контракта): сначала UPDATE
// chats, затем UPDATE messages SET status — порядок блокировок chats → messages.
async function markChatRead(chat, userId, upToSeq) {
    const previous = Number(chat.last_read_seq) || 0;
    if (!upToSeq || upToSeq <= previous) return;
    const moved = await dbGet(
        `UPDATE chats c SET last_read_seq = $1
         FROM users u
         WHERE c.id = $2 AND c.last_read_seq < $1 AND u.id = c.user_id
         RETURNING u.read_receipts, u.created_at AS user_created_at`,
        [upToSeq, chat.id]
    );
    if (!moved) return; // уже отмечено (например, из другой вкладки)
    chat.last_read_seq = upToSeq;

    // Только сообщения после предыдущего маркера — раньше при КАЖДОМ
    // открытии чата UPDATE переписывал статус всех сообщений чата заново.
    const scope = chatScope(chat);
    const notMine = chat.room_id
        ? { sql: 'NOT (m.author_tag = ANY($4::bytea[]))', value: authorTags.tagsForAccount(chat.room_id, userId, moved.user_created_at, Date.now()) }
        : { sql: 'm.user_id <> $4', value: userId };
    if (!moved.read_receipts) {
        const autoDelete = await dbAll(
            `SELECT m.id FROM messages m
             JOIN message_expiry e ON e.message_id = m.id AND e.auto_delete_on_read = TRUE
             WHERE ${scope.where('m')} AND m.seq > $2 AND m.seq <= $3
               AND ${notMine.sql}`,
            [scope.value, previous, upToSeq, notMine.value]
        );
        disappearingMessagesManager.handleMessagesRead(autoDelete.map(r => r.id));
        return;
    }
    const readRows = await dbAll(
        `UPDATE messages m SET status = 'read'
         WHERE ${scope.where('m')} AND m.seq > $2 AND m.seq <= $3
           AND ${notMine.sql} AND m.status <> 'read'
         RETURNING m.id`,
        [scope.value, previous, upToSeq, notMine.value]
    );
    if (readRows.length > 0) {
        // Без reader_id: кто именно прочитал, остальным участникам знать не
        // нужно. Сокетам самого читателя событие не шлётся — иначе его
        // клиент принял бы его за прочтение своих же сообщений.
        io.to(getSocketRoomKey(chat.id, chat.room_id)).except('user:' + userId).emit('messagesRead', {
            chat_id: chat.room_id ? null : chat.id, room_id: chat.room_id, up_to_seq: upToSeq,
        });
        disappearingMessagesManager.handleMessagesRead(readRows.map(r => r.id));
    }
}

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

// Действующий срок новых сообщений чата: общий таймер комнаты (для чата с
// ботом — личный), иначе DEFAULT_MESSAGE_EXPIRY_SECONDS; null — не исчезают.
async function getDefaultExpirySeconds(chat) {
    const settings = chat.room_id
        ? await disappearingMessagesManager.getRoomSettings(chat.room_id)
        : await disappearingMessagesManager.getChatSettings(chat.id);
    return (settings && settings.default_message_expiry) || GLOBAL_DEFAULT_EXPIRY_SECONDS || null;
}

// Срок жизни только что созданного сообщения (текст или файл, E2EE или
// нет, от любого участника): общий таймер чата; личный срок из запроса
// отправителя — только если он не длиннее общего (effectiveMessageExpiry).
async function applyNewMessageExpiry(chat, messageId, requestedSeconds = null) {
    const expiry = effectiveMessageExpiry(requestedSeconds, await getDefaultExpirySeconds(chat));
    if (expiry) await disappearingMessagesManager.setMessageExpiry(messageId, expiry, false);
}

// Синхронизация списка чатов между вкладками/устройствами пользователя.
function notifyChatListChanged(userId) {
    io.to('user:' + userId).emit('chatListChanged', {});
}

// Новое сообщение возвращает архивный чат из архива — у получателей и
// только если чат не "без звука" (заглушённый архивный чат так и лежит в
// архиве). senderId = null — ответ бота владельцу чата. Не на пути ответа
// отправителю: сбой здесь только логируется. По частичному индексу
// idx_chats_archived запрос обычно не находит ни одной строки.
function unarchiveForRecipients(chat, senderId) {
    const query = chat.room_id
        ? dbAll(
            'UPDATE chats SET archived = FALSE WHERE room_id = $1 AND archived AND NOT muted AND user_id <> $2 RETURNING user_id',
            [chat.room_id, senderId]
        )
        : dbAll('UPDATE chats SET archived = FALSE WHERE id = $1 AND archived AND NOT muted RETURNING user_id', [chat.id]);
    query.then(
        (rows) => { for (const row of rows) notifyChatListChanged(row.user_id); },
        (err) => logError('[Chats] Не удалось вернуть чат из архива', err)
    );
}

// expirySeconds из тела запроса: null — не задан, число — валидный срок;
// некорректное значение бросает RangeError с текстом для пользователя.
function parseRequestedExpiry(value) {
    if (value === undefined || value === null || value === '' || Number(value) === 0) return null;
    return DisappearingMessagesManager.normalizeExpirySeconds(value);
}

// Небольшая пауза перед ответом: он должен выглядеть ответом на сообщение, а
// не выскакивать одновременно с ним.
const BOT_REPLY_DELAY_MS = 600;

// userText — открытый текст сообщения пользователя (чат с ботом не
// шифруется). Что ответить, решает lib/bot-guide.js по теме запроса.
function scheduleBotReply(chat, userText) {
    const socketRoomKey = getSocketRoomKey(chat.id, null);
    setTimeout(async () => {
        // Весь колбэк в try: раньше ошибка БД в первом же запросе здесь
        // была необработанным reject'ом и роняла процесс.
        try {
            const replyText = botGuide.botReply(userText).text;
            // Порядок блокировок users → chats → messages
            // (docs/security/message-ordering.md, §8): строку владельца
            // берём явно и первой. Иначе INSERT сам проверял бы внешние
            // ключи — сначала chats, потом users — и сходился во взаимной
            // блокировке с удалением аккаунта (users FOR UPDATE, затем
            // DELETE FROM chats), если пользователь удаляет аккаунт, пока
            // бот готовит ответ. Аккаунта или чата уже нет — отвечать некому.
            const botMessage = await withMessageIdRetry(() => withTransactionRetry(async (client) => {
                const owner = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [chat.user_id]);
                if (owner.rows.length === 0) return null;
                // Строку чата блокируем сразу так, как её всё равно обновит
                // триггер seq (счётчик msg_seq), без повышения блокировки.
                const alive = await client.query('SELECT id FROM chats WHERE id = $1 AND is_bot = 1 FOR NO KEY UPDATE', [chat.id]);
                if (alive.rows.length === 0) return null;
                // Сообщения бота хранятся от имени владельца чата (sent = 0).
                // INSERT — последний оператор транзакции: окно блокировки
                // строки области — один INSERT и COMMIT.
                const inserted = await client.query(
                    `INSERT INTO messages (chat_id, room_id, user_id, text, sent, status)
                     VALUES ($1, NULL, $2, $3, 0, 'read')
                     RETURNING id, seq, chat_id, room_id, user_id, sent, status, created_at, message_type, encrypted`,
                    [chat.id, chat.user_id, writeMessageText(replyText, { room_id: null, chat_id: chat.id, user_id: chat.user_id })]
                );
                return inserted.rows[0];
            }));
            if (!botMessage) return;
            // Личный таймер чата с ботом действует и на ответы бота.
            await applyNewMessageExpiry(chat, botMessage.id);
            // Бот "прочитал" сообщения пользователя.
            const read = await dbAll(
                `UPDATE messages SET status = 'read' WHERE chat_id = $1 AND room_id IS NULL AND sent = 1 AND status <> 'read' RETURNING id`,
                [chat.id]
            );
            io.to(socketRoomKey).emit('newMessage', apiMessage({
                ...botMessage, text: replyText, reactions: [], reply_to: null,
                sender_username: 'Бот Помощник', sender_avatar: '',
            }));
            if (read.length > 0) {
                io.to(socketRoomKey).emit('messagesRead', { chat_id: chat.id, room_id: null, up_to_seq: Number(botMessage.seq) });
            }
            unarchiveForRecipients(chat, null);
        } catch (e) {
            logError('Bot error', e);
        }
    }, BOT_REPLY_DELAY_MS);
}

// ---- Вставка сообщения: id клиента, блокировки, повторы ----
//
// id сообщения комнаты выбирает клиент (clientMessageId) ДО шифрования и кладёт
// его внутрь E2EE-содержимого (mid): сервер не может выдать правку одного
// сообщения за другое. Чат с ботом id не присылает: его выдаёт DEFAULT.
// Конфликт id (первичный ключ или надгробие) и повтор запроса после обрыва связи
// разбирает describeMessageIdUse (раздел 6.4 контракта порядка сообщений).

// Колонки, которые разрешено вставлять через insertMessageRow: имена идут в
// текст SQL, поэтому только из этого списка.
const MESSAGE_INSERT_COLUMNS = new Set([
    'id', 'chat_id', 'room_id', 'user_id', 'author_tag', 'text', 'file_url', 'file_name', 'file_type',
    'message_type', 'sent', 'status', 'reply_to_id', 'encrypted', 'file_size', 'created_at',
]);

// INSERT сообщения; если задан срок жизни — тем же оператором и запись
// message_expiry (раздел 8.4): сообщение не остаётся без срока при сбое между
// операторами. Время удаления в базе округлено вверх до минуты. Возвращает
// { id, seq, created_at }.
async function insertMessageRow(client, fields, expirySeconds) {
    const names = Object.keys(fields);
    for (const name of names) {
        if (!MESSAGE_INSERT_COLUMNS.has(name)) throw new Error(`insertMessageRow: неизвестная колонка ${name}`);
    }
    const values = names.map(name => fields[name]);
    const insert = `INSERT INTO messages (${names.join(', ')}) VALUES (${names.map((_, i) => `$${i + 1}`).join(', ')})`;
    if (!expirySeconds) {
        const result = await client.query(`${insert} RETURNING id, seq, created_at`, values);
        return result.rows[0];
    }
    values.push(expirySeconds);
    const result = await client.query(
        `WITH m AS (${insert} RETURNING id, seq, created_at),
              e AS (INSERT INTO message_expiry (message_id, expires_at, auto_delete_on_read)
                    SELECT m.id, ${DisappearingMessagesManager.expiresAtSql(`$${values.length}`)}, FALSE FROM m)
         SELECT id, seq, created_at FROM m`,
        values
    );
    return result.rows[0];
}

// Вставка сообщения ЧАТА С БОТОМ от пользователя userId. Порядок блокировок
// users → rooms → room_participants → chats → … → upload_quota → messages
// (message-ordering.md, раздел 8.1): строка отправителя берётся явно ПЕРВОЙ
// (FOR KEY SHARE), и только потом INSERT, у которого триггер seq блокирует строку
// чата, а внешние ключи — chats и снова users. Без явного шага INSERT проверял бы
// внешние ключи в порядке их создания, и отправка сходилась бы во взаимной
// блокировке с удалением аккаунта. Нет строки users — аккаунт удалён: null.
// upload = { bytes } — вложение: квота резервируется в той же транзакции, строка
// чата берётся раньше строки квоты. { error: 'quota' } — квота исчерпана.
// INSERT — последний оператор транзакции. При 40P01 транзакция повторяется один
// раз.
async function insertChatMessage(userId, fields, expirySeconds, upload = null) {
    const row = await withTransactionRetry(async (client) => {
        const sender = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
        if (sender.rows.length === 0) return null;
        if (upload) {
            await client.query('SELECT id FROM chats WHERE id = $1 FOR NO KEY UPDATE', [fields.chat_id]);
            if (!(await reserveUploadQuota(client, authorTags.qkey(userId), upload.bytes, UPLOAD_QUOTA_BYTES))) {
                return { error: 'quota' };
            }
        }
        return insertMessageRow(client, fields, expirySeconds);
    });
    // Таймер в памяти — точный; в базе срок округлён вверх до минуты.
    if (row && !row.error && expirySeconds) disappearingMessagesManager.scheduleNewMessage(row.id, expirySeconds);
    return row;
}

// Транзакция отправки в КОМНАТУ (sealed-sender.md, 8.5): членство отправителя
// проверяется внутри неё, под блокировкой строки комнаты. Выход из комнаты берёт
// rooms FOR UPDATE и решает, писать ли user_left_rooms, по тому, есть ли у
// пользователя сообщения; без блокировки «выход без сообщений + отправка» оставили
// бы строку с тегом пользователя, которой удаление аккаунта не найдёт.
//
//   BEGIN
//     users(я) FOR KEY SHARE                 → { error: 'no-user' }   (401)
//     rooms    FOR NO KEY UPDATE             → { error: 'no-room' }   (404)
//     room_participants                      → { error: 'not-member' } (403)
//     [вложение] резервирование квоты        → { error: 'quota' }     (413)
//     INSERT messages (последний оператор)   — триггер seq: UPDATE rooms SET msg_seq
//   COMMIT
//
// created_at — минута, которую приложение передаёт в INSERT и от которой считает
// тег (неделя): строка и тег согласованы. id выбирает клиент (clientMessageId) и
// известен до вставки, поэтому AAD enc:v3 собирается заранее. Откат (409, ошибка)
// откатывает и резервирование квоты. Возвращает { row: { id, seq, created_at } }
// или { error }.
async function insertRoomMessage({ userId, roomId, id, plainText, fields, expirySeconds, upload = null }) {
    const outcome = await withTransactionRetry(async (client) => {
        const sender = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
        if (sender.rows.length === 0) return { error: 'no-user' };
        const room = await client.query('SELECT id FROM rooms WHERE id = $1 FOR NO KEY UPDATE', [roomId]);
        if (room.rows.length === 0) return { error: 'no-room' };
        const member = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
        if (member.rows.length === 0) return { error: 'not-member' };
        if (upload && !(await reserveUploadQuota(client, authorTags.qkey(userId), upload.bytes, UPLOAD_QUOTA_BYTES))) {
            return { error: 'quota' };
        }
        const createdAt = floorToMinute(new Date());
        const authorTag = authorTags.tagFor(roomId, userId, createdAt);
        const text = writeMessageText(plainText, { room_id: roomId, id, author_tag: authorTag });
        const row = await insertMessageRow(client, {
            id, room_id: roomId, author_tag: authorTag, created_at: createdAt, text, ...fields,
        }, expirySeconds);
        return { row };
    });
    if (outcome.row && expirySeconds) disappearingMessagesManager.scheduleNewMessage(outcome.row.id, expirySeconds);
    return outcome;
}

// Ответ на отказ транзакции отправки в комнату.
function respondRoomSendError(res, error) {
    if (error === 'no-user') return res.status(401).json({ success: false, message: 'Не авторизован' });
    if (error === 'no-room') return res.status(404).json({ success: false, message: 'Комната не найдена' });
    if (error === 'not-member') return res.status(403).json({ success: false, message: 'Вы не участник этой комнаты' });
    return res.status(413).json({ success: false, message: 'Превышена квота хранилища вложений' });
}

// Срок жизни нового сообщения в секундах (общий таймер чата; личный срок из
// запроса — только если он не длиннее общего) или null — не исчезает.
async function newMessageExpirySeconds(chat, requestedSeconds = null) {
    return effectiveMessageExpiry(requestedSeconds, await getDefaultExpirySeconds(chat)) || null;
}

// Правило R7: в комнате принимается только E2EE-конверт правильной формы, в чате с
// ботом — только открытый текст (расшифровать конверт там некому). null — запрос
// допустим, иначе тело ответа 400 { success:false, code, message }. Проверка
// формы не заменяет проверки подписи на стороне получателей, но не даёт
// «шифрованным» назвать открытый текст или произвольные данные.
function e2eePolicyViolation(chat, encrypted, envelope) {
    if (!chat.room_id) return encrypted ? E2EE_NOT_ALLOWED : null;
    if (!encrypted) return E2EE_REQUIRED;
    return isE2eeEnvelopeShape(envelope) ? null : BAD_ENVELOPE;
}

// Текст сообщения-вложения, как он хранится в messages.text: для E2EE — конверт,
// иначе подпись или обезличенное имя по типу. null — конверта нет (так сравнить
// с сохранённой строкой нечем).
function expectedFileMessageText(body, mimetype) {
    if (body.encrypted === 'true') return typeof body.envelope === 'string' ? body.envelope.trim() : null;
    const caption = typeof body.text === 'string' ? sanitizeText(body.text.trim()) : '';
    return caption || anonymizedFileName(mimetype);
}

// Что сейчас с id сообщения КОМНАТЫ (раздел 6.4 контракта порядка сообщений):
//   free      — свободен;
//   duplicate — строка уже есть, и это тот же запрос: та же комната, тот же автор
//               (тег строки входит в теги пользователя за неделю её created_at),
//               расшифрованный на сервере текст равен присланному, а у вложения
//               file_url задан. Повтор после обрыва связи идемпотентен: клиент
//               получает уже сохранённое сообщение (row);
//   conflict  — id занят другим сообщением либо стоит в надгробии: 409, клиент
//               выберет новый id и зашифрует содержимое заново.
async function describeMessageIdUse({ id, roomId, userId, expectedText, file }) {
    const row = await dbGet(
        `SELECT id, seq, room_id, author_tag, text, file_url, file_name, file_type, message_type,
                sent, status, edited_at, encrypted, created_at, reply_to_id
         FROM messages WHERE id = $1`,
        [id]
    );
    if (row) {
        const same = row.room_id === roomId
            && authorTags.ownsTag(row.author_tag, authorTags.tagsForRow(row.room_id, userId, row.created_at))
            && Boolean(row.file_url) === Boolean(file)
            && expectedText !== null && expectedText !== undefined
            && readMessageText(row.text, row) === expectedText;
        return same ? { status: 'duplicate', row } : { status: 'conflict' };
    }
    const retired = await dbGet('SELECT 1 AS retired FROM message_tombstones WHERE id = $1 AND expires_at > now()', [id]);
    return retired ? { status: 'conflict' } : { status: 'free' };
}

// ---- Сообщение комнаты в ответах и событиях (sealed-sender.md, 8.1) ----
//
// Без user_id, chat_id (личная строка отправителя), sender_username,
// sender_avatar и author_tag: автора знает только клиент (по E2EE-конверту).
// Сторона пузыря не расшифрованного сообщения — подсказка mine: она есть только в
// ответе отправителю и в копии события на user:<id> отправителя; остальным
// участникам и в истории её нет. Клиент никогда не передаёт её в расшифровку.
function roomMessagePayload(row, text, { replyTo = null, mine = false } = {}) {
    const message = {
        id: row.id, seq: row.seq, room_id: row.room_id,
        text, file_url: row.file_url, file_name: row.file_name, file_type: row.file_type,
        message_type: row.message_type, sent: row.sent, status: row.status, edited_at: row.edited_at,
        encrypted: row.encrypted, created_at: row.created_at,
        reply_to_id: replyTo ? replyTo.id : null, reply_to: replyTo, reactions: [],
    };
    if (mine) message.mine = true;
    return apiMessage(message);
}

// Сообщение для ответа клиенту по уже сохранённой строке (повтор запроса): то же,
// что вернула бы первая отправка. Повторяет её только автор, поэтому mine: true.
function messageFromRow(row, text, replyTo = null) {
    return roomMessagePayload(row, text, { replyTo, mine: true });
}

// Рассылка события сообщения комнаты. Сокеты отправителя состоят и в room:<id>, и
// в user:<id>: без except комнатное событие пришло бы его вкладке дважды (с mine и
// без). Поэтому комнате — except автора (и тех, для кого сообщение под границей
// видимости), а автору — одна копия на user:<id> с mine: true.
function emitRoomMessageEvent(event, roomId, authorId, payload, { hiddenUserIds = [], toAuthor = true } = {}) {
    let target = io.to(getSocketRoomKey(null, roomId)).except('user:' + authorId);
    for (const id of hiddenUserIds) target = target.except('user:' + id);
    target.emit(event, payload);
    if (toAuthor) io.to('user:' + authorId).emit(event, { ...payload, mine: true });
}

// Отправитель сам не считает свои сообщения непрочитанными: после COMMIT вставки
// его личный маркер двигается к seq сообщения (sealed-sender.md, 8.3). Маркер
// только растёт, поэтому по порядку блокировок отдельным оператором безопасно.
// Упрощение документа: чужие сообщения со seq меньше нового тоже перестают быть
// непрочитанными. Сбой только логируется - сообщение уже сохранено.
async function advanceSenderMarker(chat, seq) {
    try {
        await dbRun('UPDATE chats SET last_read_seq = $1 WHERE id = $2 AND last_read_seq < $1', [seq, chat.id]);
        chat.last_read_seq = Math.max(Number(chat.last_read_seq) || 0, Number(seq));
    } catch (err) {
        logError('[Chats] Не удалось сдвинуть маркер отправителя', err);
    }
}

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

// ---- Приглашения и заявки на вступление ----
//
// Код приглашения (rooms.code, 26 символов) видят и меняют все участники
// комнаты. Параметры кода (lib/invites.js): срок, лимит участников
// (invite_max_members, NULL — без лимита), вступление только с одобрения
// любого участника (invite_require_approval, по умолчанию включено) и
// выключенный код (invite_disabled). Несуществующий, истёкший и
// выключенный код снаружи неразличимы: везде INVALID_INVITE_MESSAGE.

function inviteExpiresAtIso(expiresAt) {
    return expiresAt ? new Date(expiresAt).toISOString() : null;
}

// Состав комнаты изменился: клиенты участников перечитывают список
// участников (E2EE: новичку — Sender Key, после ухода — ротация ключа).
// inviteRotated: true - из-за выхода участника сервер обнулил подписанное приглашение и выдал новый код
// (решение владельца, signed-membership.md, вопрос 17): клиенты показывают «Ссылка-приглашение обновлена».
function notifyRoomMembersChanged(roomId, extra) {
    io.to(`room:${roomId}`).emit('roomMembersChanged', { roomId, ...extra });
}

// Новый код приглашения без подписанного сертификата: код остаётся и принимает только заявки, пока кто-то не создаст
// новую подписанную ссылку («Пригласить»). Вызывается внутри транзакции выхода или удаления аккаунта, под блокировкой
// комнаты. Срок и лимит участников прежние.
async function resetInviteAfterLeave(client, roomId) {
    await client.query(
        'UPDATE rooms SET invite_cert = NULL, invite_snap = NULL, invite_actor_id = NULL, code = $2 WHERE id = $1',
        [roomId, generateInviteCode()]
    );
}

// Список заявок комнаты изменился — только участникам (заявитель в
// room:<id> не подписан и чужих заявок не видит).
function notifyJoinRequestsChanged(roomId) {
    io.to(`room:${roomId}`).emit('joinRequestsChanged', { roomId });
}

function notifyJoinRequestDecided(userId, payload) {
    io.to('user:' + userId).emit('joinRequestDecided', payload);
}

const JOIN_REQUEST_LIVE_SQL = `created_at > NOW() - ${JOIN_REQUEST_TTL_SECONDS} * INTERVAL '1 second'`;
const JOIN_REQUEST_NOT_FOUND = { success: false, message: 'Заявка не найдена' };

// Строка списка чатов для только что вошедшего (как в POST /api/chats).
function roomChatPayload(chat, room) {
    return {
        id: chat.id, name: chat.name, avatar: chat.avatar, online: 0, is_bot: 0,
        room_id: room.id, invite_code: room.invite_disabled ? null : room.code,
    };
}

// Комната вызывающего по его личному чату — с проверкой участия.
async function getOwnRoom(chatIdParam, userId) {
    const chat = await getOwnChat(chatIdParam, userId);
    if (!chat) return { error: 'Чат не найден' };
    if (!chat.room_id) return { error: 'У этого чата нет кода приглашения' };
    const room = await dbGet(
        `SELECT r.id, r.name, r.code, r.code_expires_at, r.invite_max_members, r.invite_require_approval, r.invite_disabled,
                (r.invite_cert IS NOT NULL) AS invite_signed,
                (SELECT COUNT(*)::int FROM room_participants p WHERE p.room_id = r.id) AS member_count
         FROM rooms r
         JOIN room_participants rp ON rp.room_id = r.id AND rp.user_id = $2
         WHERE r.id = $1`,
        [chat.room_id, userId]
    );
    if (!room) return { error: 'Чат не найден' };
    return { chat, room };
}

// Комната по коду приглашения, если код можно использовать; иначе null —
// одинаково для несуществующего, истёкшего и выключенного кода. Всё, что не
// похоже на код нынешнего формата, в БД даже не ищется.
async function findRoomByInviteCode(code) {
    if (!isValidInviteCode(code)) return null;
    const room = await dbGet(
        `SELECT r.id, r.name, r.code, r.code_expires_at, r.invite_max_members, r.invite_require_approval, r.invite_disabled,
                r.invite_cert,
                (SELECT COUNT(*)::int FROM room_participants p WHERE p.room_id = r.id) AS member_count
         FROM rooms r WHERE r.code = $1`,
        [code]
    );
    return room && isInviteUsable(room) ? room : null;
}

// Вступление в комнату — общий путь для входа по коду без одобрения и для
// одобрения заявки. Участник + личная строка chats — одной транзакцией под
// блокировкой строки комнаты (FOR NO KEY UPDATE):
//   * вступления в одну комнату идут по очереди — два одновременных
//     запроса не превысят лимит участников;
//   * последний участник не может одновременно выйти и снести комнату
//     вместе с новичком (DELETE /api/chats берёт FOR UPDATE);
//   * отправка сообщений тоже встаёт в эту очередь: триггер seq обновляет
//     rooms.msg_seq, и NO KEY UPDATE конфликтует с NO KEY UPDATE. Поэтому
//     граница видимости новичка точна (инвариант О2 контракта порядка
//     сообщений): отправка либо уже зафиксирована и её seq не больше
//     прочитанного ниже rooms.msg_seq, либо ждёт и получит seq больше него.
//     FOR UPDATE здесь не нужен и вреден: он блокировал бы и внешние ключи
//     (KEY SHARE) всех вставок, ссылающихся на комнату.
// Порядок блокировок users → rooms → room_participants → chats (раздел 8):
// строка новичка берётся первой, до комнаты.
// check(room, client) под блокировкой перепроверяет основание для
// вступления (код — для входа по коду, живую заявку — для одобрения) и
// возвращает код ошибки (строку), объект-ответ { reply: { status, body } } или null.
// afterJoin(client, room) — в той же транзакции, только для нового участника: вставка
// сертификата допуска или входа (signed-membership.md, 7.1). Прочитанные здесь
// значения комнаты (invite_cert, invite_snap) принадлежат моменту блокировки: поворот
// приглашения не успевает между проверкой сертификата и вставкой.
// Новичок видит только сообщения после вступления: visible_from_seq —
// rooms.msg_seq на этот момент (у заявки — на момент ОДОБРЕНИЯ, а не
// подачи); та же граница — у непрочитанного (last_read_seq).
async function addRoomMember(roomId, userId, check, afterJoin) {
    const result = await withTransactionRetry(async (client) => {
        const newcomer = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
        if (newcomer.rows.length === 0) return { error: 'not-found' };
        const locked = await client.query(
            `SELECT id, name, code, invite_max_members, invite_require_approval, invite_disabled, msg_seq,
                    invite_cert, invite_snap,
                    (code_expires_at IS NOT NULL AND code_expires_at > NOW()) AS code_live
             FROM rooms WHERE id = $1 FOR NO KEY UPDATE`,
            [roomId]
        );
        const room = locked.rows[0];
        if (!room) return { error: 'gone' };
        const checkError = check ? await check(room, client) : null;
        if (checkError) return { error: checkError };

        const existing = await client.query('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
        if (existing.rows[0]) {
            const dropped = await client.query('DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
            return { chat: existing.rows[0], room, joined: false, requestRemoved: dropped.rowCount > 0 };
        }
        const members = await client.query('SELECT COUNT(*)::int AS n FROM room_participants WHERE room_id = $1', [roomId]);
        if (isRoomFull(members.rows[0].n, room.invite_max_members)) return { error: 'full' };

        // Новичок видит группу под её названием — тем же, что в предпросмотре
        // приглашения. Раньше строка называлась «Чат с <имя первого
        // участника>»: в группе это неверно и лишний раз показывает имя.
        const name = room.name;
        const avatar = name.charAt(0).toUpperCase();
        await client.query(
            `INSERT INTO room_participants (room_id, user_id, visible_from_seq)
             VALUES ($1, $2, $3)
             ON CONFLICT (room_id, user_id) DO NOTHING`,
            [roomId, userId, room.msg_seq]
        );
        const chatResult = await client.query(
            `INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_seq)
             VALUES ($1, $2, $3, $4, 0, 0,
                     (SELECT visible_from_seq FROM room_participants WHERE room_id = $2 AND user_id = $1))
             RETURNING id`,
            [userId, roomId, name, avatar]
        );
        const dropped = await client.query('DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
        const extra = afterJoin ? await afterJoin(client, room) : null;
        return { chat: { id: chatResult.rows[0].id, name, avatar }, room, joined: true, requestRemoved: dropped.rowCount > 0, extra };
    });
    if (result.error) return result;

    const chat = roomChatPayload(result.chat, result.room);
    if (result.joined) {
        subscribeUserToChat(userId, chat.id, roomId);
        notifyRoomMembersChanged(roomId);
        notifyChatListChanged(userId);
    }
    if (result.requestRemoved) notifyJoinRequestsChanged(roomId);
    return { chat, joined: result.joined, extra: result.extra || null };
}

// Ответ на отказ addRoomMember с подробным вердиктом проверки сертификата.
function respondCertVerdict(res, verdict) {
    return res.status(verdict.status).json({ success: false, code: verdict.code, message: verdict.message });
}

// Ключи участника из хранилища ключей (identity_keys) - для проверки сертификатов.
function identityKeysOf(client, userId) {
    const run = client ? (sql, params) => client.query(sql, params).then(r => r.rows[0] || null) : dbGet;
    return run('SELECT identity_signing_key, identity_dh_key FROM identity_keys WHERE user_id = $1', [userId]);
}

// Заявка на вступление в комнату с одобрением. Повторный запрос возвращает
// ту же заявку; просроченная (старше недели — фоновая чистка до неё ещё не
// дошла) заменяется новой. Живых заявок в комнате — не больше
// MAX_PENDING_JOIN_REQUESTS_PER_ROOM.
async function createJoinRequest(roomId, userId) {
    await dbRun(`DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2 AND NOT (${JOIN_REQUEST_LIVE_SQL})`, [roomId, userId]);
    const existing = await dbGet('SELECT id FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
    if (existing) return { id: existing.id };
    const pending = await dbGet(`SELECT COUNT(*)::int AS n FROM join_requests WHERE room_id = $1 AND ${JOIN_REQUEST_LIVE_SQL}`, [roomId]);
    if (pending.n >= MAX_PENDING_JOIN_REQUESTS_PER_ROOM) {
        return { error: 'В эту группу слишком много заявок. Попробуйте позже.' };
    }
    let inserted;
    try {
        inserted = (await queryWithRetry(
            'INSERT INTO join_requests (room_id, user_id) VALUES ($1, $2) ON CONFLICT (room_id, user_id) DO NOTHING RETURNING id',
            [roomId, userId]
        )).rows[0];
    } catch (err) {
        // Комнату снесли между проверкой кода и заявкой (вышел последний участник): код больше не действует.
        if (err && err.code === '23503') return { error: INVALID_INVITE_MESSAGE };
        throw err;
    }
    if (!inserted) {
        // Параллельный такой же запрос успел раньше — это та же заявка.
        const concurrent = await dbGet('SELECT id FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
        return concurrent ? { id: concurrent.id } : { error: 'Не удалось отправить заявку. Попробуйте ещё раз.' };
    }
    notifyJoinRequestsChanged(roomId);
    return { id: inserted.id };
}

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

// Сообщение, которое пользователь вправе менять или удалять (sealed-sender.md,
// 8.2). В комнате автора в строке нет, поэтому: пользователь - ТЕКУЩИЙ участник
// комнаты, сообщение для него ВИДНО (seq > visible_from_seq) и тег строки входит
// в его теги за неделю created_at строки. Вышедший и вернувшийся участник со
// своими старыми сообщениями под границей видимости их не меняет и не удаляет
// (он удалит их вместе с аккаунтом). Нет строки, граница, чужой тег - один и тот же
// ответ null: чужое, невидимое и несуществующее неразличимы. В чате с ботом -
// по user_id, как раньше. Выбираются поля для AAD (writeMessageText).
async function findOwnMessage(messageId, userId, { sentOnly = false } = {}) {
    const inRoom = await dbGet(
        `SELECT m.id, m.seq, m.room_id, m.author_tag, m.created_at, m.encrypted, m.file_url, m.sent
         FROM messages m
         JOIN room_participants rp ON rp.room_id = m.room_id AND rp.user_id = $2
         WHERE m.id = $1 AND m.room_id IS NOT NULL AND m.seq > rp.visible_from_seq`,
        [messageId, userId]
    );
    if (inRoom) {
        const mine = authorTags.ownsTag(inRoom.author_tag, authorTags.tagsForRow(inRoom.room_id, userId, inRoom.created_at));
        return mine && (!sentOnly || Number(inRoom.sent) === 1) ? inRoom : null;
    }
    const inBotChat = await dbGet(
        `SELECT id, seq, chat_id, room_id, user_id, encrypted, file_url, sent
         FROM messages WHERE id = $1 AND room_id IS NULL AND user_id = $2`,
        [messageId, userId]
    );
    return inBotChat && (!sentOnly || Number(inBotChat.sent) === 1) ? inBotChat : null;
}

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

// multer(upload.single('file')) уже записал файл на диск ДО этого хендлера —
// значит, ранние return (401/400/404) должны сами убирать за собой, иначе
// каждая неудачная/подделанная попытка загрузки будет накапливать файлы-сироты.
function cleanupUploadedFile(file) {
    if (!file) return;
    fs.promises.unlink(path.join(UPLOADS_DIR, file.filename)).catch(() => {});
}

async function readFileHead(filePath, length) {
    const handle = await fs.promises.open(filePath, 'r');
    try {
        const buffer = Buffer.alloc(length);
        const { bytesRead } = await handle.read(buffer, 0, length, 0);
        return buffer.subarray(0, bytesRead);
    } finally {
        await handle.close();
    }
}

function rejectUpload(res, file, status, message) {
    cleanupUploadedFile(file);
    return res.status(status).json({ success: false, message });
}

// То же с готовым телом ответа (коды ошибок контракта порядка сообщений).
function rejectUploadWith(res, file, status, body) {
    cleanupUploadedFile(file);
    return res.status(status).json(body);
}

// mtime и atime файла вложения — с точностью до часа, вниз: по времени
// изменения файла иначе восстанавливалось бы время сообщения до секунды
// (раздел 11 контракта). Уборщик файлов-сирот учитывает округление: его порог
// возраста не меньше двух часов (lib/coarse-time.js). Сбой не фатален.
async function coarsenFileTimes(filePath) {
    try {
        const hour = floorToHour();
        await fs.promises.utimes(filePath, hour, hour);
    } catch (err) {
        logError('[Uploads] Не удалось округлить время файла', err);
    }
}

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

async function userCanAccessMessage(userId, messageId) {
    // LEFT JOIN, не INNER JOIN (см. п.3 аудита): если автор сообщения вышел
    // из групповой комнаты, его персональная строка в chats удаляется и
    // m.chat_id уходит в NULL (ON DELETE SET NULL). INNER JOIN на chats
    // тогда терял строку сообщения целиком, и функция возвращала false для
    // абсолютно любого пользователя — файл переставал открываться вообще
    // всем, включая оставшихся участников комнаты. m.room_id при этом всегда
    // записан прямо на сообщении в момент отправки (см. /api/messages,
    // /api/messages/file) и не зависит от того, жива ли ещё запись chats
    // автора, поэтому для групповых чатов JOIN для доступа не обязателен.
    const row = await dbGet(
        `SELECT m.seq, m.room_id, c.room_id AS chat_room_id, c.user_id AS chat_owner_id
         FROM messages m
         LEFT JOIN chats c ON m.chat_id = c.id
         WHERE m.id = $1`,
        [messageId]
    );
    if (!row) return false;
    const roomId = row.room_id || row.chat_room_id;
    if (!roomId) {
        // Не групповой (1:1) чат — доступ только у владельца самой записи
        // chats. Если chat_id уже NULL, значит запись chats удалена вместе
        // со всем DM-чатом (см. DELETE /api/chats/:chatId, ветка без
        // room_id — там messages удаляются явно перед чатом), и доступа ни
        // у кого больше нет.
        return row.chat_owner_id != null && row.chat_owner_id === userId;
    }
    // Участник, вступивший после этого сообщения, его не видит — ни файл,
    // ни реакции (граница visible_from_seq, см. addRoomMember).
    const participant = await dbGet(
        'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2 AND visible_from_seq < $3',
        [roomId, userId, row.seq]
    );
    return Boolean(participant);
}

// Файлы отдаются только тому, кто реально является участником чата/комнаты,
// к которому относится сообщение с этим файлом — а не просто "залогинен ли
// кто-то вообще" (см. п.1 аудита). Имя файла уникально (случайное),
// поэтому джойн messages.file_url -> chats/room_participants однозначно
// определяет владельца. Поиск идёт по индексу idx_messages_file_url.
async function userCanAccessFile(userId, filename) {
    const fileUrl = `/uploads/${filename}`;
    const message = await dbGet('SELECT id FROM messages WHERE file_url = $1 LIMIT 1', [fileUrl]);
    if (!message) return false;
    return userCanAccessMessage(userId, message.id);
}

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

// Таймер исчезающих сообщений чата. В комнате — общий для всех участников
// (room_settings), и менять его может любой участник, как и код
// приглашения; в чате с ботом — личный (chat_settings). Действует на
// сообщения, отправленные после изменения. Возвращается действующий срок
// (выключенный таймер — DEFAULT_MESSAGE_EXPIRY_SECONDS, если он задан).
async function setChatExpiry(chat, seconds) {
    if (chat.room_id) await disappearingMessagesManager.setRoomDefaultExpiry(chat.room_id, seconds);
    else await disappearingMessagesManager.setChatDefaultExpiry(chat.id, seconds);
    const effective = seconds || GLOBAL_DEFAULT_EXPIRY_SECONDS || 0;
    // В комнате chatId не отправляется: у каждого участника он свой.
    io.to(getSocketRoomKey(chat.id, chat.room_id)).emit('chatExpiryChanged', {
        roomId: chat.room_id || null,
        chatId: chat.room_id ? null : chat.id,
        seconds: effective,
    });
    return effective;
}

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

// Полное удаление пользователя (POST /api/account/delete и его псевдоним
// /api/logout, чистка по сроку): его сообщения (и их файлы) во ВСЕХ комнатах,
// где он состоит, и в тех, откуда вышел, оставив там сообщения (user_left_rooms),
// реакции, E2EE key-shares, участие в комнатах, его заявки на вступление,
// опустевшие комнаты со всей историей и заявками в них, окна квоты вложений,
// chats (chat_settings — каскадом), unread, сама строка users;
// message_expiry и реакции на его сообщения уходят каскадом. Сообщения комнат
// находятся по тегам автора (sealed-sender.md, 12.2): для каждой комнаты - теги
// пользователя за все недели с создания аккаунта, по всем ключам сообщений. Одной
// транзакцией — раньше это была серия отдельных DELETE, и первая же ошибка
// FK (например, из e2ee_key_shares, который ссылается на users без каскада)
// оставляла пользователя в БД навсегда. После COMMIT — файлы с диска,
// сессии на всех устройствах, сокеты, публичные E2EE-ключи (встроенное
// хранилище) и уведомление оставшимся участникам комнат.
//
// Порядок блокировок users → rooms → room_participants → chats → user_left_rooms →
// upload_quota → messages (message-ordering.md, раздел 8.1) — тот же, что у
// отправки, вступления и выхода из комнаты. При взаимной блокировке (40P01) транзакция повторяется
// один раз (withTransactionRetry), поэтому результаты собираются заново на
// каждой попытке.
async function deleteUserAccount(userId) {
    const outcome = await withTransactionRetry(async (client) => {
        const result = { fileUrls: [], survivingRoomIds: [], requestRoomIds: [], droppedRequests: [] };
        // Блокировка строки пользователя: параллельная отправка сообщения
        // (она берёт users FOR KEY SHARE первым оператором) дождётся конца
        // удаления и получит «нет пользователя», а не оставит сообщение, которое
        // уже никто не удалит.
        const user = await client.query('SELECT id, created_at FROM users WHERE id = $1 FOR UPDATE', [userId]);
        if (user.rows.length === 0) return null;
        const rooms = await client.query('SELECT DISTINCT room_id FROM room_participants WHERE user_id = $1 ORDER BY room_id', [userId]);
        const roomIds = rooms.rows.map(r => r.room_id);
        // Комнаты, откуда он вышел, оставив там сообщения: их тоже надо почистить.
        const left = await client.query('SELECT room_id FROM user_left_rooms WHERE user_id = $1', [userId]);
        const messageRoomIds = [...new Set([...roomIds, ...left.rows.map(r => r.room_id)])].sort((a, b) => a - b);
        // Комнаты блокируются так же, как при выходе из чата (DELETE
        // /api/chats/:chatId): иначе одновременный выход последнего другого
        // участника оставил бы пустую комнату навсегда. Порядок по id — без
        // взаимных блокировок между двумя такими удалениями.
        if (messageRoomIds.length > 0) {
            await client.query('SELECT id FROM rooms WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE', [messageRoomIds]);
        }
        await client.query('DELETE FROM e2ee_key_shares WHERE sender_id = $1 OR recipient_id = $1', [userId]);
        await client.query('DELETE FROM e2ee_key_requests WHERE requester_id = $1', [userId]);
        await client.query('DELETE FROM room_participants WHERE user_id = $1', [userId]);
        // Сообщения бота уходят каскадом от своей строки chats (messages.chat_id ON DELETE
        // CASCADE), и RETURNING у явного DELETE ниже уже ничего не вернул бы: адреса
        // файлов снимаются ДО удаления чатов. Пока users заблокирована FOR UPDATE, новые
        // сообщения бота с файлами вставить некому.
        const botFiles = await client.query(
            'SELECT file_url FROM messages WHERE room_id IS NULL AND user_id = $1 AND file_url IS NOT NULL',
            [userId]
        );
        result.fileUrls.push(...botFiles.rows.map(r => r.file_url));
        await client.query('DELETE FROM chats WHERE user_id = $1', [userId]);
        // Сертификаты состава, где он субъект или подписавший, и подписанные приглашения комнат, из которых он уходит
        // (решение владельца, вопрос 17): код заменяется новым. Комнаты уже заблокированы выше.
        await client.query('DELETE FROM room_member_certs WHERE subject_id = $1 OR actor_id = $1', [userId]);
        for (const roomId of roomIds) await resetInviteAfterLeave(client, roomId);
        await client.query('DELETE FROM user_left_rooms WHERE user_id = $1', [userId]);
        // Окна квоты - по псевдонимам от текущего и всех прежних ключей сообщений.
        await deleteQuotaRows(client, authorTags.qkeysFor(userId));
        // Сообщения комнат - по (комната, теги): в строке user_id нет. Запросы по
        // комнате, а не одним массивом пар: у старого аккаунта тегов до 600 недель
        // на ключ, и массив из всех комнат сразу получился бы огромным.
        const now = Date.now();
        for (const roomId of messageRoomIds) {
            const tags = authorTags.tagsForAccount(roomId, userId, user.rows[0].created_at, now);
            const roomMessages = await client.query(
                'DELETE FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) RETURNING file_url',
                [roomId, tags]
            );
            result.fileUrls.push(...roomMessages.rows.map(r => r.file_url));
        }
        // Чат с ботом: сообщения владельца (в том числе ответы бота) каскадом уже ушли вместе
        // с чатом; это страховка на случай строки без чата.
        const botMessages = await client.query('DELETE FROM messages WHERE room_id IS NULL AND user_id = $1 RETURNING file_url', [userId]);
        result.fileUrls.push(...botMessages.rows.map(r => r.file_url));
        await client.query('DELETE FROM reactions WHERE user_id = $1', [userId]);
        const ownRequests = await client.query('DELETE FROM join_requests WHERE user_id = $1 RETURNING room_id', [userId]);
        result.requestRoomIds = [...new Set(ownRequests.rows.map(r => r.room_id))];

        if (messageRoomIds.length > 0) {
            const orphaned = await client.query(
                `DELETE FROM messages m WHERE m.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = m.room_id)
                 RETURNING file_url`,
                [messageRoomIds]
            );
            result.fileUrls.push(...orphaned.rows.map(r => r.file_url));
            // Заявки в опустевшие комнаты ушли бы и каскадом, но заявителям
            // надо сказать, что рассматривать их больше некому.
            const orphanedRequests = await client.query(
                `DELETE FROM join_requests jr WHERE jr.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = jr.room_id)
                 RETURNING id, user_id`,
                [messageRoomIds]
            );
            result.droppedRequests = orphanedRequests.rows;
            const removedRooms = await client.query(
                `DELETE FROM rooms r WHERE r.id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = r.id)
                 RETURNING id`,
                [messageRoomIds]
            );
            const removed = new Set(removedRooms.rows.map(r => r.id));
            result.survivingRoomIds = roomIds.filter(id => !removed.has(id));
        }
        await client.query('DELETE FROM users WHERE id = $1', [userId]);
        // Домен журнала ключей — после основного, в его порядке: kt_state FOR SHARE → identity_keys →
        // kt_pending (message-ordering.md, 8.1). Регистрация ключа и закрытие эпохи берут их так же,
        // поэтому взаимных блокировок нет. Prekey пользователя уходят следом за identity_keys, как
        // и в регистрации; nonce обязательства удаляется вместе со строкой identity_keys, и записи
        // журнала перестают связываться с ключами. Запись kt_pending в эпоху уже не попадёт.
        await client.query('SELECT 1 FROM kt_state FOR SHARE');
        await client.query('DELETE FROM identity_keys WHERE user_id = $1', [userId]);
        for (const table of ['pq_one_time_prekeys', 'one_time_prekeys', 'signed_pq_prekeys', 'signed_prekeys']) {
            await client.query(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
        }
        await client.query('DELETE FROM kt_pending WHERE user_id = $1', [userId]);
        return result;
    });
    if (!outcome) return false;
    const { fileUrls, survivingRoomIds, requestRoomIds, droppedRequests } = outcome;

    removeUploadedFiles(fileUrls);
    anonActivity.forget(userId);
    io.in('user:' + userId).disconnectSockets(true);
    for (const roomId of survivingRoomIds) notifyRoomMembersChanged(roomId, { inviteRotated: true });
    for (const roomId of requestRoomIds) notifyJoinRequestsChanged(roomId);
    for (const request of droppedRequests) notifyJoinRequestDecided(request.user_id, { requestId: request.id, approved: false });
    deleteKeysForUser(userId);
    // Сессии на других устройствах. После COMMIT и отдельно: таблицы session
    // может ещё не быть (42P01), а ошибка внутри транзакции откатила бы всё.
    try {
        await dbRun(`DELETE FROM session WHERE sess->>'userId' = $1`, [String(userId)]);
    } catch (error) {
        if (error.code !== '42P01') logError('[Account] Не удалось удалить сессии', error);
    }
    return true;
}

// Анонимные аккаунты, срок которых вышел (lib/anon-lifetime.js): выбранный
// срок без активности по users.last_active_at (корзина, округлённая вверх,
// — граница та же, что у isAnonExpired). Потолка от создания нет. Раньше
// удаление шло только через 5 часов после создания и откладывалось, пока
// жива строка в таблице session, — даже если вкладку давно закрыли.
// Пользователи с открытым сокетом на этом экземпляре не трогаются: их
// активность продлевает touch, а сокеты других экземпляров продлевают
// last_active_at в БД сами. Время — часы сервера, как у записи корзин.
// Ошибка выборки — наверх, в runExclusive (lib/jobs): такой проход не
// засчитывается.
async function purgeExpiredAnonymousUsers() {
    const now = Date.now();
    const deadline = (lifetime) => new Date(now - ANON_LIFETIMES[lifetime] * 1000);
    const rows = await dbAll(`
        SELECT id FROM users
        WHERE ((anon_lifetime = 'tab' AND last_active_at <= $1)
            OR (anon_lifetime = 'day' AND last_active_at <= $2)
            OR (anon_lifetime = 'week' AND last_active_at <= $3))
          AND NOT (id = ANY($4::int[]))
        ORDER BY last_active_at
        LIMIT 200
    `, [deadline('tab'), deadline('day'), deadline('week'), userSocketCount.keys()]);
    // В лог — только счётчики, без id анонимных аккаунтов.
    let failed = 0;
    for (const row of rows) {
        try {
            await deleteUserAccount(row.id);
        } catch (err) {
            failed++;
            logError('[Anon] Не удалось удалить просроченный аккаунт', err);
        }
    }
    metrics.accountsDeleted('expired', rows.length - failed);
    if (rows.length > 0) console.log(`[Anon] Удалено просроченных анонимных аккаунтов: ${rows.length - failed}`);
}

// Заявки на вступление старше недели: заявителю — "отклонена", участникам
// — обновить список (в выборках просроченные заявки и так не видны).
async function purgeExpiredJoinRequests() {
    try {
        const rows = await dbAll(`DELETE FROM join_requests WHERE NOT (${JOIN_REQUEST_LIVE_SQL}) RETURNING id, room_id, user_id`);
        for (const roomId of new Set(rows.map(r => r.room_id))) notifyJoinRequestsChanged(roomId);
        for (const row of rows) notifyJoinRequestDecided(row.user_id, { requestId: row.id, approved: false });
        if (rows.length > 0) console.log(`[Invites] Удалено просроченных заявок на вступление: ${rows.length}`);
    } catch (error) {
        logError('[Invites] Purge error', error);
    }
}

// ---- Фоновые задачи (lib/jobs/index.js) ----
//
// По умолчанию задача идёт под runExclusive (lib/advisory-locks.js): в
// каждый момент её выполняет один экземпляр сервера на базу, у остальных
// запуск пропускается. Клиенты блокировок — из отдельного маленького пула:
// блокировка держит соединение всю задачу, а в основном пуле (в тестах
// PG_POOL_MAX=3) они отнимали бы соединения у самих задач.
const jobLockPool = new Pool({ ...DB_POOL_CONFIG, max: 4 });
jobLockPool.on('error', (err) => logError('[DB] Ошибка простаивающего соединения блокировок', err));

// Тестовые ручки сквозных тестов (NYXO_TEST_*, docs/dev/testing.md):
// действуют ТОЛЬКО при NODE_ENV=test, в production env-check считает их
// ошибкой. Целое число мс > 0, иначе null.
function testKnobMs(name) {
    if (process.env.NODE_ENV !== 'test') return null;
    const value = Number(process.env[name]);
    return Number.isInteger(value) && value > 0 ? value : null;
}

const jobs = createJobScheduler({
    runExclusive: createRunExclusive(jobLockPool),
    // Задачи с maintenance: true — каждые N мс вместо минут.
    maintenanceMs: testKnobMs('NYXO_TEST_MAINTENANCE_MS'),
    onRun: metrics.jobRan,
});
// Анонимы проверяются каждые 5 минут: самый короткий срок — 30 минут
// без активности, и опоздание с удалением не должно быть сравнимо с ним.
jobs.register({
    name: 'purgeExpiredAnonymousUsers', run: purgeExpiredAnonymousUsers,
    firstDelayMs: 60 * 1000, intervalMs: 5 * 60 * 1000, maintenance: true, testTick: true,
});
// Открытые сокеты ЭТОГО процесса (у каждого экземпляра свои, поэтому без
// блокировки), раз в 2,5 минуты: активность их пользователей одним UPDATE и
// строки tab-сессий (кука без срока) — ещё 24 часа: HTTP-ответа, который
// пересохранил бы строку, может не быть часами, пока вкладка открыта.
jobs.register({
    name: 'touchOnlineSockets',
    run: async () => {
        const online = userSocketCount.keys();
        await anonActivity.touch(online);
        await extendTabSessions(dbRun, online);
    },
    intervalMs: ANON_SOCKET_ACTIVITY_INTERVAL_MS, exclusive: false, maintenance: true,
});
jobs.register({
    name: 'purgeExpiredJoinRequests', run: purgeExpiredJoinRequests,
    firstDelayMs: 90 * 1000, intervalMs: 60 * 60 * 1000, maintenance: true,
});
// Брошенные временные файлы обработки вложений — в папке этого процесса.
// Порог возраста — не меньше двух часов: mtime файлов округлён вниз до часа
// (coarsenFileTimes), и свежий файл выглядит старше настоящего возраста.
jobs.register({
    name: 'cleanupStaleTempFiles', run: () => cleanupStaleTempFiles(UPLOADS_DIR, orphanAgeThresholdMs(60 * 60 * 1000)),
    intervalMs: 60 * 60 * 1000, exclusive: false,
});
// Задачи lib-модулей (JOB_MODULES в lib/jobs/index.js).
registerJobModules(jobs, serverContext);

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

// Миграции — под advisory-блокировкой (lib/advisory-locks.js): два
// одновременно стартующих экземпляра (реплики, деплой без простоя) раньше
// выполняли DDL наперегонки, и один из них падал. На время миграций у их
// запросов короткий lock_timeout: DDL, не дождавшийся блокировки таблицы
// (её держат запросы работающего экземпляра), не стоит в очереди,
// задерживая за собой все запросы к этой таблице, а падает, и миграции
// повторяются целиком (они идемпотентны). Не помогли и повторы — сервер
// выходит с ошибкой, хостинг его перезапускает.
//
// Новые изменения схемы — не в initDatabase, а файлами lib/migrations/
// (см. lib/migrations/index.js): они выполняются после initDatabase, а
// версия схемы в schema_meta не даёт старому коду стартовать на новой схеме.
async function initDatabaseExclusive() {
    // DUMP_CA=true — служебный режим (TLS к базе ещё не настроен): он
    // завершает процесс в начале initDatabase и не должен ждать соединения.
    if (process.env.DUMP_CA === 'true') return initDatabase();
    // Файлы миграций читаются до первого соединения: ошибка в них — сразу.
    const migrations = loadMigrations();
    return runMigrationsExclusive(pool, ({ client }) => migrateSchema({
        pool,
        client,
        migrations,
        initialSteps: initDatabase,
        config: Object.freeze({ isProduction: IS_PRODUCTION, uploadsDir: UPLOADS_DIR, env: process.env }),
    }), {
        createMigrationPool: (options) => new Pool({ ...DB_POOL_CONFIG, ...options }),
    });
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
