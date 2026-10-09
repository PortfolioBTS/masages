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
const { encryptText, decryptText, messageAad } = require('./lib/message-crypto');
const { sanitizeText, getPrivacyHeaders, createHstsMiddleware } = require('./lib/privacy');
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
// Групповой E2EE: участники чата + попарная доставка Sender Key
// (key-shares). Тоже регистрируется после sessionMiddleware.
const { initE2eeGroupsSchema, registerE2eeGroupRoutes } = require('./lib/e2ee-groups');

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

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// HSTS preload включает только владелец домена: HSTS_PRELOAD=yes (см. lib/privacy.js).
const HSTS_PRELOAD = process.env.HSTS_PRELOAD === 'yes';

// ALLOWED_MIME_TYPES и MIME_EXTENSIONS (жёсткий маппинг mimetype ->
// расширение на диске, расширение никогда не берётся из имени файла) —
// в lib/security-utils.js, рядом с обезличенными именами вложений.

// Лимит на суммарный объём вложений одного пользователя: без него один
// аккаунт мог забить весь volume (по 50 МБ за запрос, без ограничений).
const UPLOAD_QUOTA_BYTES = Math.floor(positiveNumberOr(process.env.UPLOAD_QUOTA_MB, 500) * 1024 * 1024);
// Длина E2EE-конверта (текст сообщения или описание зашифрованного файла).
const MAX_ENVELOPE_LENGTH = 12000;

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
    console.error(`[Uploads] Нет доступа на запись в ${UPLOADS_DIR}: ${err.message} — загрузка файлов работать не будет`);
}

// Удаляет файлы вложений с диска по их file_url ("/uploads/<name>").
// Вызывается после того, как ссылающиеся на них сообщения удалены из БД.
function removeUploadedFiles(fileUrls) {
    for (const url of fileUrls) {
        if (typeof url !== 'string' || !url.startsWith('/uploads/')) continue;
        const filename = path.basename(url);
        if (!SAFE_FILENAME_RE.test(filename)) continue;
        fs.promises.unlink(path.join(UPLOADS_DIR, filename)).catch(err => {
            if (err.code !== 'ENOENT') console.error('[Uploads] Не удалось удалить файл', filename, '-', err.message);
        });
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
            const safeName = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${ext}`;
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
            return wantsEncrypted ? cb(null, true) : cb(new Error('Неподдерживаемый тип файла'), false);
        }
        if (wantsEncrypted || !ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error('Неподдерживаемый тип файла'), false);
        }
        cb(null, true);
    }
});

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
    console.error('[DB] Ошибка простаивающего соединения:', err.message);
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
            io.to(getSocketRoomKey(row.chat_id, row.room_id)).emit('messageDeleted', {
                id: row.id, chat_id: row.chat_id, room_id: row.room_id
            });
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
    await maybeDumpCa().catch(err => { console.error('[DUMP_CA] Ошибка:', err.message); process.exit(1); });

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

    await pool.query(`
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            -- срок жизни кода приглашения (INVITE_TTL_HOURS)
            code_expires_at TIMESTAMPTZ,
            -- параметры кода (POST /api/chats/:chatId/invite/rotate): лимит
            -- участников (NULL — без лимита), вступление только с одобрения
            -- участника, выключенный код
            invite_max_members INTEGER,
            invite_require_approval BOOLEAN NOT NULL DEFAULT TRUE,
            invite_disabled BOOLEAN NOT NULL DEFAULT FALSE
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
            -- непрочитанные: id последнего прочитанного сообщения в личной строке
            -- chats каждого участника
            last_read_message_id INTEGER NOT NULL DEFAULT 0,
            -- порядок чатов без сообщений: id случайные и порядка не несут
            created_at TIMESTAMPTZ DEFAULT NOW(),
            -- личные флаги чата (POST /api/chats/:chatId/prefs): собеседники их
            -- не видят
            pinned BOOLEAN NOT NULL DEFAULT FALSE,
            muted BOOLEAN NOT NULL DEFAULT FALSE,
            archived BOOLEAN NOT NULL DEFAULT FALSE
        )
    `);

    // chat_id может стать NULL (ON DELETE SET NULL): когда участник выходит из
    // комнаты, его строка chats удаляется, а история остаётся видна остальным
    // по room_id. Комната удаляется — сообщения уходят каскадом; ответ на
    // удалённое сообщение теряет связь с оригиналом (SET NULL), а не блокирует
    // удаление. Приложение и так удаляет в правильном порядке (DELETE
    // /api/chats/:chatId, deleteUserAccount), каскады — страховка на случай,
    // если порядок там по ошибке изменят.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER REFERENCES chats(id) ON DELETE SET NULL,
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            text TEXT NOT NULL,
            file_url TEXT,
            file_name TEXT,
            file_type TEXT,
            message_type TEXT DEFAULT 'text',
            sent INTEGER DEFAULT 1,
            time TEXT NOT NULL,
            status TEXT DEFAULT 'sent',
            edited_at TEXT,
            deleted INTEGER DEFAULT 0,
            reply_to_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
            -- E2EE: text хранит клиентский шифроконверт вместо обычного текста
            -- (public/e2ee.js). Серверное шифрование "at rest" (lib/message-crypto.js)
            -- применяется поверх в обоих случаях — флаг только про то, что лежит
            -- ВНУТРИ после его снятия.
            encrypted BOOLEAN NOT NULL DEFAULT FALSE,
            -- точное время отправки: поле time ('HH:MM') считается в часовом поясе
            -- СЕРВЕРА, и пользователи из других поясов видели бы сдвиг — клиент
            -- форматирует created_at сам
            created_at TIMESTAMPTZ DEFAULT NOW(),
            -- размер вложения — для квоты UPLOAD_QUOTA_MB
            file_size BIGINT
        )
    `);

    // Новичок видит только сообщения комнаты, отправленные ПОСЛЕ его вступления
    // (visible_from_id — id последнего сообщения на тот момент). Уникальный
    // (room_id, user_id): проверка "участник ли комнаты" идёт на каждый файл,
    // реакцию и joinChat, и один пользователь не может оказаться в комнате
    // дважды (с двумя visible_from_id).
    await pool.query(`
        CREATE TABLE IF NOT EXISTS room_participants (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            visible_from_id INTEGER NOT NULL DEFAULT 0,
            UNIQUE (room_id, user_id)
        )
    `);

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

    // Индексы для выборок "сообщения чата по id". Включённые колонки
    // позволяют последнему сообщению, счётчику непрочитанного, странице
    // истории и кандидатам поиска читаться index-only scan'ом. Без них
    // планировщик выбирал обратный проход по первичному ключу с фильтром
    // по room_id — для "тихой" комнаты это просмотр почти всей таблицы.
    // Префикс (room_id)/(chat_id) заодно обслуживает удаление комнаты/чата
    // и каскады внешних ключей, так что одноколоночные индексы не нужны.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_room_live ON messages(room_id, deleted, id) INCLUDE (user_id, sent, encrypted)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_chat_live ON messages(chat_id, deleted, id) INCLUDE (user_id, sent, encrypted)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id)');
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
    // Сумма размеров вложений пользователя (квота) — index-only scan по
    // его файлам, а не проход по всем его сообщениям.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_user_files ON messages(user_id) INCLUDE (file_size) WHERE file_size IS NOT NULL');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_room_participants_user ON room_participants(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id)');
    // Авто-разархивация получателей идёт на КАЖДОЕ новое сообщение комнаты;
    // по частичному индексу она читает только архивные строки комнаты
    // (обычно ни одной), а не строки всех её участников.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_archived ON chats(room_id) WHERE archived');

    await setRandomIdDefaults();

    console.log('База данных инициализирована');
}

// ---- Случайные id для users, rooms, chats, join_requests ----
//
// Последовательные id выдавали размер и темп роста сервиса (id свежей
// регистрации = число пользователей) и порядок событий: по id комнаты или
// чата было видно, кто и когда создал её раньше. Поэтому id этих таблиц —
// случайные из [1 000 000, 2^31 - 1]: 48 бит из gen_random_uuid() (PG 13+,
// внутри pg_strong_random — криптостойкий ГСЧ; первые 12 hex-цифр UUIDv4
// случайны целиком) по модулю размера диапазона (смещение ~2^-17 — не
// различимо), с перепроверкой занятости в цикле. messages.id остаётся
// последовательным намеренно: на порядке сообщений держатся история,
// непрочитанное и visible_from_id.
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
const RANDOM_ID_TABLES = ['users', 'rooms', 'chats', 'join_requests'];

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
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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

function getCurrentTime() {
    const now = new Date();
    return `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
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
            console.error('joinChat error:', err);
        }
    });

    // Сразу подписываем сокет на ВСЕ чаты пользователя. Раньше подписка
    // появлялась только при открытии конкретного чата, поэтому новые
    // сообщения в остальных чатах не обновляли ни список, ни счётчики.
    try {
        const chats = await dbAll('SELECT id, room_id FROM chats WHERE user_id = $1', [userId]);
        socket.join(chats.map(c => getSocketRoomKey(c.id, c.room_id)));
    } catch (err) {
        console.error('Socket auto-join error:', err.message);
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
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.cspNonce = nonce;
    // Политика — buildContentSecurityPolicy (lib/security-utils.js). Без
    // 'unsafe-inline' в style-src и без "ws: wss:" (любой хост) в
    // connect-src: только WebSocket своего хоста. Схема ws/wss — по тому,
    // как страница открыта: onion-сервис отдаётся по http (TLS там даёт сам
    // Tor), хотя onionMiddleware и помечает такой запрос защищённым.
    res.set('Content-Security-Policy', buildContentSecurityPolicy({
        nonce,
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

// Статика раздаётся ДО sessionMiddleware: ей сессия не нужна, а раньше
// каждый запрос за CSS/JS/иконкой ходил в Postgres за сессией.
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res) => setRevalidateCacheHeaders(res, false),
}));

// Маршруты из lib/routes/ (см. lib/routes/index.js): здесь — те, которым
// сессия не нужна; ниже, после лимитера /api/, — обычные маршруты API.
// serverContext — общий контекст маршрутов и задач из lib/ (lib/jobs).
const serverContext = Object.freeze({
    pool, dbGet, dbAll, dbRun, withTransaction, io, logError, isProduction: IS_PRODUCTION,
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
app.use(express.json());

// Лимит на /api/ — ДО регистрации маршрутов из lib/: Express применяет
// middleware в порядке регистрации, и раньше /api/keys/* и
// /api/chats/:id/participants шли мимо лимита.
app.use('/api/', apiLimiter);

// Публичные E2EE-ключи: /api/keys/* → встроенное хранилище (lib/key-store.js).
// Регистрируется строго ПОСЛЕ sessionMiddleware — маршрутам нужна сессия.
// Чужие ключи отдаются только при общей комнате — модулю нужна БД.
registerE2eeKeyRoutes(app, { dbGet, dbAll, bundleLimiter });
// Групповой E2EE: список участников чата + key-shares (тоже нужна сессия).
registerE2eeGroupRoutes(app, { dbGet, dbAll, dbRun, io });
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

app.get('/link.my', (req, res) => {
    serveIndexWithNonce(req, res);
});

function serveIndexWithNonce(req, res) {
    const nonce = res.locals.cspNonce || '';
    const indexPath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(indexPath, 'utf8', (err, html) => {
        if (err) return res.status(500).send('Server error');
        const injected = html
            .replace(/<script(?![^>]*\bnonce=)/g, `<script nonce="${nonce}"`)
            .replace(/<style(?![^>]*\bnonce=)/g, `<style nonce="${nonce}"`)
            .replace(/<link([^>]*rel=["']stylesheet["'][^>]*)(?![^>]*\bnonce=)>/g, `<link$1 nonce="${nonce}">`);
        res.setHeader('Content-Type', 'text/html');
        res.send(injected);
    });
}

// ---- Текст сообщения в БД: шифрование at rest с AAD ----
//
// AAD (messageAad из lib/message-crypto.js) привязывает шифротекст к месту
// хранения — комнате (для личного чата с ботом — чату) и отправителю:
// строка, перенесённая в чужую комнату или под чужое имя, не
// расшифруется. Поэтому везде, где читается или пишется messages.text,
// выбираются и room_id, chat_id, user_id этой же строки.
const UNREADABLE_TEXT = '[Не удалось расшифровать]';

function writeMessageText(text, row) {
    return encryptText(text, messageAad(row));
}

function readMessageText(stored, row) {
    if (stored === null || stored === undefined) return stored;
    try {
        return decryptText(stored, messageAad(row));
    } catch (err) {
        // messageAad бросает только на строке без комнаты и без чата
        // (осиротевшее сообщение) — показать её всё равно некому и нечем.
        console.error('[MessageCrypto] Нет AAD для сообщения:', err.message);
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
    const botResult = await client.query(
        'INSERT INTO chats (user_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [userId, 'Бот Помощник', 'Б', 1, 1]
    );
    const botChatId = botResult.rows[0].id;
    await client.query(
        'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6)',
        [botChatId, userId, writeMessageText(welcomeText, { room_id: null, chat_id: botChatId, user_id: userId }), 0, getCurrentTime(), 'read']
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
        await client.query('ROLLBACK');
        throw txErr;
    } finally {
        client.release();
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

        const { userId, botChatId } = await withTransaction(client => insertUserWithBotChat(client, {
            uniqueCode, username, anonLifetime: lifetime, lastActiveAt: new Date(lastActiveMs),
            welcomeText: botGuide.welcomeText(lifetime),
        }));

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

// Удаление аккаунта со всеми данными (см. deleteUserAccount). Пароля нет:
// аккаунт временный, и войти в него иначе, чем этой сессией, нельзя.
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
        console.error('Update privacy error:', error);
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
// граница видимости истории: visible_from_id — id последнего сообщения
// комнаты на момент вступления, видно только то, что новее (для чата с
// ботом и старых участников — 0, то есть всё).
async function getOwnChat(chatId, userId) {
    const id = toPositiveInt(chatId);
    if (!id) return null;
    return dbGet(
        `SELECT c.*, COALESCE(rp.visible_from_id, 0) AS visible_from_id
         FROM chats c
         LEFT JOIN room_participants rp ON rp.room_id = c.room_id AND rp.user_id = c.user_id
         WHERE c.id = $1 AND c.user_id = $2`,
        [id, userId]
    );
}

// Сообщения чата лежат либо по room_id (групповая комната), либо по
// chat_id (личный чат с ботом). Возвращает колонку и значение для WHERE.
function chatScope(chat) {
    return chat.room_id ? { column: 'room_id', value: chat.room_id } : { column: 'chat_id', value: chat.id };
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
// отсекается условием на c.room_id), и обе читаются index-only scan'ом по
// idx_messages_room_live/idx_messages_chat_live: последнее сообщение —
// одна запись индекса, непрочитанные — только записи после
// last_read_message_id (не больше 100).
//
// Последнее сообщение комнаты — только из видимых участнику (новее его
// visible_from_id); непрочитанные и так начинаются после
// last_read_message_id, который при вступлении ставится на ту же границу.
// lm_room_id/lm_chat_id/lm_user_id нужны только для AAD расшифровки и
// клиенту не отдаются. Закреплённые — сверху; дальше по последнему
// сообщению; чаты без сообщений — по времени создания (id теперь
// случайные), старые строки без created_at — по id, как раньше. Архивные
// остаются в списке — клиент показывает их отдельным разделом.
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
           lm.id AS last_message_id, lm.text AS last_message, lm.encrypted AS last_message_encrypted,
           lm.message_type AS last_message_type, lm.time AS last_time, lm.created_at AS last_created_at,
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
        SELECT CASE WHEN c.room_id IS NOT NULL
            THEN (SELECT MAX(x.id) FROM messages x
                  WHERE x.room_id = c.room_id AND x.deleted = 0 AND x.id > COALESCE(rp.visible_from_id, 0))
            ELSE (SELECT MAX(x.id) FROM messages x WHERE x.chat_id = c.id AND x.deleted = 0)
        END AS id
    ) last ON TRUE
    LEFT JOIN messages lm ON lm.id = last.id
    LEFT JOIN LATERAL (
        SELECT COUNT(*) AS cnt FROM (
            (SELECT 1 FROM messages m
              WHERE c.room_id IS NOT NULL AND m.room_id = c.room_id AND m.deleted = 0
                AND m.id > c.last_read_message_id AND (m.user_id <> c.user_id OR m.sent = 0)
              LIMIT 100)
            UNION ALL
            (SELECT 1 FROM messages m
              WHERE c.room_id IS NULL AND m.chat_id = c.id AND m.deleted = 0
                AND m.id > c.last_read_message_id AND (m.user_id <> c.user_id OR m.sent = 0)
              LIMIT 100)
        ) unread_rows
    ) uc ON TRUE
    WHERE c.user_id = $1
    ORDER BY c.pinned DESC, lm.id DESC NULLS LAST, c.created_at DESC NULLS LAST, c.id DESC
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
                unread: Number(c.unread),
                expiry_seconds: Number(c.expiry_seconds) || 0,
                last_message: c.last_message_encrypted
                    ? null
                    : readMessageText(c.last_message, { room_id: lm_room_id, chat_id: lm_chat_id, user_id: lm_user_id }),
            })),
        });
    } catch (error) {
        console.error('Get chats error:', error);
        res.json({ success: false, message: 'Ошибка загрузки чатов' });
    }
});

// Отмечает сообщения чата прочитанными вплоть до upToId: двигает личный
// маркер непрочитанного, ставит статус 'read' чужим сообщениям (у
// отправителя появляются ✓✓) и запускает auto-delete-on-read.
//
// Если читатель выключил отметки прочтения (users.read_receipts), двигается
// только его личный маркер: статус сообщений не меняется и messagesRead не
// рассылается. Auto-delete-on-read срабатывает всё равно — это обещание
// отправителя, а не отметка для него.
async function markChatRead(chat, userId, upToId) {
    const previous = Number(chat.last_read_message_id) || 0;
    if (!upToId || upToId <= previous) return;
    const moved = await dbGet(
        `UPDATE chats c SET last_read_message_id = $1
         FROM users u
         WHERE c.id = $2 AND c.last_read_message_id < $1 AND u.id = c.user_id
         RETURNING u.read_receipts`,
        [upToId, chat.id]
    );
    if (!moved) return; // уже отмечено (например, из другой вкладки)
    chat.last_read_message_id = upToId;

    // Только сообщения после предыдущего маркера — раньше при КАЖДОМ
    // открытии чата UPDATE переписывал статус всех сообщений чата заново.
    const scope = chatScope(chat);
    if (!moved.read_receipts) {
        const autoDelete = await dbAll(
            `SELECT m.id FROM messages m
             JOIN message_expiry e ON e.message_id = m.id AND e.auto_delete_on_read = TRUE
             WHERE m.${scope.column} = $1 AND m.id > $2 AND m.id <= $3
               AND m.user_id <> $4 AND m.deleted = 0`,
            [scope.value, previous, upToId, userId]
        );
        disappearingMessagesManager.handleMessagesRead(autoDelete.map(r => r.id));
        return;
    }
    const readRows = await dbAll(
        `UPDATE messages SET status = 'read'
         WHERE ${scope.column} = $1 AND id > $2 AND id <= $3
           AND user_id <> $4 AND deleted = 0 AND status <> 'read'
         RETURNING id`,
        [scope.value, previous, upToId, userId]
    );
    if (readRows.length > 0) {
        // Без reader_id: кто именно прочитал, остальным участникам знать не
        // нужно. Сокетам самого читателя событие не шлётся — иначе его
        // клиент принял бы его за прочтение своих же сообщений.
        io.to(getSocketRoomKey(chat.id, chat.room_id)).except('user:' + userId).emit('messagesRead', {
            chat_id: chat.id, room_id: chat.room_id, up_to_id: upToId,
        });
        disappearingMessagesManager.handleMessagesRead(readRows.map(r => r.id));
    }
}

const MESSAGES_PAGE_SIZE = 100;
const MAX_MESSAGES_PAGE_SIZE = 200;

// История чата постранично: последние MESSAGES_PAGE_SIZE сообщений, более
// старые — через ?before=<id самого старого из загруженных>. Раньше
// отдавалась вся история целиком (плюс IN-список из всех её id для
// реакций), и открытие большого чата становилось всё медленнее.
app.get('/api/messages/:chatId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        const limit = Math.min(toPositiveInt(req.query.limit) || MESSAGES_PAGE_SIZE, MAX_MESSAGES_PAGE_SIZE);
        const before = toPositiveInt(req.query.before);
        const scope = chatScope(chat);
        const params = [scope.value, limit + 1, Number(chat.visible_from_id) || 0];
        if (before) params.push(before);

        // Цитата ответа берётся только из ТОГО ЖЕ чата, только если она не
        // удалена и видна участнику (новее его visible_from_id). Раньше
        // reply_to_id не проверялся при отправке, и подставив чужой id,
        // можно было получить расшифрованный текст сообщения из любого
        // чужого чата; удалённые сообщения тоже продолжали "светиться" в
        // цитатах, а новичок комнаты видел в цитатах историю до вступления.
        // Сначала id страницы (index-only scan по idx_messages_*_live), потом
        // сами строки по первичному ключу.
        const rows = await dbAll(`
            WITH page AS MATERIALIZED (
                SELECT id FROM messages
                WHERE ${scope.column} = $1 AND deleted = 0 AND id > $3 ${before ? 'AND id < $4' : ''}
                ORDER BY id DESC
                LIMIT $2
            )
            SELECT m.id, m.chat_id, m.room_id, m.user_id, m.text, m.file_url, m.file_name, m.file_type,
                   m.message_type, m.sent, m.time, m.status, m.edited_at, m.deleted, m.encrypted, m.created_at,
                   m.reply_to_id AS reply_target_id,
                   u.username AS sender_username, u.avatar AS sender_avatar,
                   rt.id AS reply_to_id, rt.text AS reply_to_text, rt.user_id AS reply_to_sender_id,
                   rt.room_id AS reply_to_room_id, rt.chat_id AS reply_to_chat_id,
                   rt.encrypted AS reply_to_encrypted,
                   ru.username AS reply_to_sender_username, ru.avatar AS reply_to_sender_avatar
            FROM page
            JOIN messages m ON m.id = page.id
            JOIN users u ON u.id = m.user_id
            LEFT JOIN messages rt ON rt.id = m.reply_to_id AND rt.${scope.column} = m.${scope.column}
                                 AND rt.deleted = 0 AND rt.id > $3
            LEFT JOIN users ru ON ru.id = rt.user_id
            ORDER BY m.id DESC
        `, params);

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

        const messages = rows.map(({ reply_target_id, reply_to_text, reply_to_sender_id, reply_to_room_id, reply_to_chat_id,
            reply_to_encrypted, reply_to_sender_username, reply_to_sender_avatar, ...m }) => ({
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
        if (!before && messages.length > 0) {
            await markChatRead(chat, userId, messages[messages.length - 1].id);
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
        console.error('Get messages error:', error);
        res.json({ success: false, message: 'Ошибка загрузки сообщений' });
    }
});

// Клиент сообщает, что показал пользователю новые сообщения открытого чата
// (пришедшие по сокету), — иначе они считались бы непрочитанными.
app.post('/api/chats/:chatId/read', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const upToId = toPositiveInt(req.body?.upToId);
    if (!upToId) return res.json({ success: false, message: 'Некорректный upToId' });
    const chat = await getOwnChat(req.params.chatId, userId);
    if (!chat) return res.json({ success: false, message: 'Чат не найден' });
    // Не даём отметить прочитанным больше, чем реально есть (и видно
    // участнику) в этом чате.
    const scope = chatScope(chat);
    const latest = await dbGet(
        `SELECT MAX(id) AS id FROM messages WHERE ${scope.column} = $1 AND deleted = 0 AND id <= $2 AND id > $3`,
        [scope.value, upToId, Number(chat.visible_from_id) || 0]
    );
    await markChatRead(chat, userId, latest && latest.id);
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
        (err) => console.error('[Chats] Не удалось вернуть чат из архива:', err.message)
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
            const stillExists = await dbGet('SELECT id FROM chats WHERE id = $1 AND is_bot = 1', [chat.id]);
            if (!stillExists) return;

            const replyText = botGuide.botReply(userText).text;
            // Сообщения бота хранятся от имени владельца чата (sent = 0).
            const botMessage = await dbGet(
                `INSERT INTO messages (chat_id, room_id, user_id, text, sent, time, status)
                 VALUES ($1, NULL, $2, $3, 0, $4, 'read')
                 RETURNING id, chat_id, room_id, user_id, sent, time, status, created_at, message_type, encrypted`,
                [chat.id, chat.user_id, writeMessageText(replyText, { room_id: null, chat_id: chat.id, user_id: chat.user_id }), getCurrentTime()]
            );
            // Личный таймер чата с ботом действует и на ответы бота.
            await applyNewMessageExpiry(chat, botMessage.id);
            // Бот "прочитал" сообщения пользователя.
            const read = await dbAll(
                `UPDATE messages SET status = 'read' WHERE chat_id = $1 AND sent = 1 AND status <> 'read' RETURNING id`,
                [chat.id]
            );
            io.to(socketRoomKey).emit('newMessage', {
                ...botMessage, text: replyText, deleted: 0, reactions: [], reply_to: null,
                sender_username: 'Бот Помощник', sender_avatar: '',
            });
            if (read.length > 0) {
                io.to(socketRoomKey).emit('messagesRead', { chat_id: chat.id, room_id: null, up_to_id: botMessage.id });
            }
            unarchiveForRecipients(chat, null);
        } catch (e) {
            console.error('Bot error:', e);
        }
    }, BOT_REPLY_DELAY_MS);
}

app.post('/api/messages', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
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

        // Для E2EE-конверта sanitizeText не нужен и вреден по смыслу: это
        // не человеческий текст, а base64/JSON, который клиент должен
        // получить обратно байт-в-байт для расшифровки.
        const safeText = encrypted ? text.trim() : sanitizeText(text.trim());
        if (!safeText) return res.json({ success: false, message: 'Введите текст сообщения' });

        // Отвечать можно только на неудалённое и видимое отправителю
        // сообщение из ЭТОГО же чата (иначе ответ на старый id вытащил бы
        // в цитату текст из истории до вступления).
        const scope = chatScope(chat);
        let replyTo = null;
        const replyTargetId = toPositiveInt(replyToId);
        if (replyTargetId) {
            const target = await dbGet(
                `SELECT m.id, m.text, m.room_id, m.chat_id, m.user_id, m.encrypted, u.username, u.avatar
                 FROM messages m JOIN users u ON u.id = m.user_id
                 WHERE m.id = $1 AND m.${scope.column} = $2 AND m.deleted = 0 AND m.id > $3`,
                [replyTargetId, scope.value, Number(chat.visible_from_id) || 0]
            );
            if (target) {
                replyTo = {
                    id: target.id, text: readMessageText(target.text, target), sender_id: target.user_id,
                    encrypted: target.encrypted, sender_username: target.username, sender_avatar: target.avatar,
                };
            }
        }

        const time = getCurrentTime();
        const roomId = chat.room_id || null;
        const inserted = await dbGet(
            `INSERT INTO messages (chat_id, room_id, user_id, text, message_type, sent, time, status, reply_to_id, encrypted)
             VALUES ($1, $2, $3, $4, 'text', 1, $5, 'sent', $6, $7)
             RETURNING id, created_at`,
            [chat.id, roomId, userId, writeMessageText(safeText, { room_id: roomId, chat_id: chat.id, user_id: userId }),
                time, replyTo ? replyTo.id : null, encrypted]
        );

        await applyNewMessageExpiry(chat, inserted.id, requestedExpiry);

        // text уже известен в открытом виде (safeText) — не расшифровываем то,
        // что сами только что зашифровали, и не перечитываем строку из БД.
        const message = {
            id: inserted.id, chat_id: chat.id, room_id: roomId, user_id: userId,
            text: safeText, file_url: null, file_name: null, file_type: null,
            message_type: 'text', sent: 1, time, status: 'sent', edited_at: null, deleted: 0,
            encrypted, created_at: inserted.created_at,
            reply_to_id: replyTo ? replyTo.id : null, reply_to: replyTo, reactions: [],
            sender_username: req.session.username, sender_avatar: req.session.avatar || '',
        };
        io.to(getSocketRoomKey(chat.id, roomId)).emit('newMessage', message);
        res.json({ success: true, message });

        if (roomId) unarchiveForRecipients(chat, userId);
        // Чат с ботом ходит открытым текстом. Конверт E2EE сюда слать незачем, а
        // если он всё же пришёл, прочитать его бот не может — ответит подсказкой.
        if (chat.is_bot) scheduleBotReply(chat, encrypted ? '' : safeText);
    } catch (error) {
        console.error('Send message error:', error);
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
        const { roomId, chatId } = await withTransaction(async (client) => {
            const roomResult = await client.query(
                `INSERT INTO rooms (name, code, code_expires_at) VALUES ($1, $2, NOW() + $3::integer * INTERVAL '1 second') RETURNING id`,
                [name, roomCode, INVITE_TTL_SECONDS]
            );
            const newRoomId = roomResult.rows[0].id;
            await client.query('INSERT INTO room_participants (room_id, user_id, visible_from_id) VALUES ($1, $2, 0)', [newRoomId, userId]);
            const chatResult = await client.query(
                'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [userId, newRoomId, name, avatar, 0, 0]
            );
            return { roomId: newRoomId, chatId: chatResult.rows[0].id };
        });
        subscribeUserToChat(userId, chatId, roomId);
        notifyChatListChanged(userId);
        res.json({ success: true, chat: { id: chatId, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
    } catch (error) {
        console.error('Create chat error:', error);
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
function notifyRoomMembersChanged(roomId) {
    io.to(`room:${roomId}`).emit('roomMembersChanged', { roomId });
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
//   * отправку сообщений блокировка не задерживает: внешний ключ
//     messages.room_id берёт FOR KEY SHARE, совместимый с NO KEY UPDATE.
// check(room, client) под блокировкой перепроверяет основание для
// вступления (код — для входа по коду, живую заявку — для одобрения) и
// возвращает код ошибки или null.
// Новичок видит только сообщения после вступления: visible_from_id —
// MAX(id) сообщений комнаты на этот момент (у заявки — на момент ОДОБРЕНИЯ,
// а не подачи); та же граница — у непрочитанного.
async function addRoomMember(roomId, userId, check) {
    const result = await withTransaction(async (client) => {
        const locked = await client.query(
            `SELECT id, name, code, invite_max_members, invite_require_approval, invite_disabled,
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

        const other = await client.query(
            `SELECT u.username FROM room_participants rp JOIN users u ON u.id = rp.user_id
             WHERE rp.room_id = $1 AND rp.user_id <> $2 ORDER BY rp.id LIMIT 1`,
            [roomId, userId]
        );
        const name = other.rows[0] ? `Чат с ${other.rows[0].username}` : room.name;
        const avatar = name.charAt(0).toUpperCase();
        await client.query(
            `INSERT INTO room_participants (room_id, user_id, visible_from_id)
             VALUES ($1, $2, COALESCE((SELECT MAX(id) FROM messages WHERE room_id = $1), 0))
             ON CONFLICT (room_id, user_id) DO NOTHING`,
            [roomId, userId]
        );
        const chatResult = await client.query(
            `INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_message_id)
             VALUES ($1, $2, $3, $4, 0, 0,
                     (SELECT visible_from_id FROM room_participants WHERE room_id = $2 AND user_id = $1))
             RETURNING id`,
            [userId, roomId, name, avatar]
        );
        const dropped = await client.query('DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
        return { chat: { id: chatResult.rows[0].id, name, avatar }, room, joined: true, requestRemoved: dropped.rowCount > 0 };
    });
    if (result.error) return result;

    const chat = roomChatPayload(result.chat, result.room);
    if (result.joined) {
        subscribeUserToChat(userId, chat.id, roomId);
        notifyRoomMembersChanged(roomId);
        notifyChatListChanged(userId);
    }
    if (result.requestRemoved) notifyJoinRequestsChanged(roomId);
    return { chat, joined: result.joined };
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
    const inserted = await dbGet(
        'INSERT INTO join_requests (room_id, user_id) VALUES ($1, $2) ON CONFLICT (room_id, user_id) DO NOTHING RETURNING id',
        [roomId, userId]
    );
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
        console.error('Get invite error:', error);
        res.json({ success: false, message: 'Ошибка получения кода' });
    }
});

// Новый код приглашения с параметрами { ttlSeconds, maxMembers,
// requireApproval } — любой участник комнаты. Старый код перестаёт
// действовать сразу (так закрывается утёкшая ссылка); выключенный код
// перевыпуск снова включает.
app.post('/api/chats/:chatId/invite/rotate', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    let settings;
    try {
        settings = parseInviteSettings(req.body, { defaultTtlSeconds: INVITE_TTL_SECONDS });
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        const room = await dbGet(
            `UPDATE rooms SET code = $1, code_expires_at = NOW() + $2::integer * INTERVAL '1 second',
                    invite_max_members = $5, invite_require_approval = $6, invite_disabled = FALSE
             WHERE id = $3 AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $3 AND user_id = $4)
             RETURNING code, code_expires_at, invite_max_members, invite_require_approval`,
            [generateInviteCode(), settings.ttlSeconds, chat.room_id, userId, settings.maxMembers, settings.requireApproval]
        );
        if (!room) return res.json({ success: false, message: 'Чат не найден' });
        res.json({
            success: true,
            code: room.code,
            expiresAt: inviteExpiresAtIso(room.code_expires_at),
            maxMembers: room.invite_max_members,
            requireApproval: room.invite_require_approval,
        });
    } catch (error) {
        console.error('Rotate invite error:', error);
        res.json({ success: false, message: 'Ошибка обновления кода' });
    }
});

// Выключить приглашение. Сам код тоже заменяется случайным, нигде не
// показанным: выключенный код не оживёт, даже если флаг где-то забудут
// проверить. Уже поданные заявки остаются — их можно рассмотреть.
app.post('/api/chats/:chatId/invite/disable', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        const room = await dbGet(
            `UPDATE rooms SET code = $1, invite_disabled = TRUE
             WHERE id = $2 AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $2 AND user_id = $3)
             RETURNING id`,
            [generateInviteCode(), chat.room_id, userId]
        );
        if (!room) return res.json({ success: false, message: 'Чат не найден' });
        res.json({ success: true });
    } catch (error) {
        console.error('Disable invite error:', error);
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
        res.json({
            success: true,
            roomName: room.name,
            memberCount: room.member_count,
            requireApproval: room.invite_require_approval !== false,
        });
    } catch (error) {
        console.error('Join preview error:', error);
        res.json({ success: false, message: 'Ошибка проверки кода' });
    }
});

app.post('/api/chats/join', joinUserLimiter, joinIpLimiter, async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const code = normalizeInviteCode(req.body?.code);
    if (!code) return res.json({ success: false, message: 'Введите код приглашения' });

    try {
        const room = await findRoomByInviteCode(code);
        if (!room) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });

        const existingChat = await dbGet('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
        if (existingChat) return res.json({ success: true, chat: roomChatPayload(existingChat, room) });
        if (isRoomFull(room.member_count, room.invite_max_members)) {
            return res.json({ success: false, message: ROOM_FULL_MESSAGE });
        }

        const pendingResponse = async () => {
            const request = await createJoinRequest(room.id, userId);
            if (request.error) return res.json({ success: false, message: request.error });
            res.json({ success: true, pending: true, requestId: request.id, roomName: room.name });
        };
        if (room.invite_require_approval !== false) return pendingResponse();

        // Код перепроверяется под блокировкой комнаты: пока шли запросы выше,
        // его могли сменить или выключить, а могли и включить одобрение.
        const result = await addRoomMember(room.id, userId, (locked) => {
            if (locked.code !== code || !locked.code_live || locked.invite_disabled) return 'invalid';
            return locked.invite_require_approval === false ? null : 'approval';
        });
        if (result.error === 'approval') return pendingResponse();
        if (result.error === 'full') return res.json({ success: false, message: ROOM_FULL_MESSAGE });
        if (result.error) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });
        res.json({ success: true, chat: result.chat });
    } catch (error) {
        console.error('Join chat error:', error);
        res.json({ success: false, message: 'Ошибка входа в чат' });
    }
});

// Живые заявки комнаты — любому её участнику.
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
        res.json({
            success: true,
            requests: rows.map(r => ({ id: r.id, userId: r.user_id, username: r.username, createdAt: r.created_at })),
        });
    } catch (error) {
        console.error('Get join requests error:', error);
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
        console.error('Get own join requests error:', error);
        res.json({ success: false, message: 'Ошибка загрузки заявок' });
    }
});

// Одобрить заявку — любой участник той же комнаты. Заявки чужих комнат
// неотличимы от несуществующих. Вступление — тем же addRoomMember, что и
// вход по коду без одобрения (лимит участников, visible_from_id на момент
// одобрения, подписка сокетов заявителя, roomMembersChanged).
app.post('/api/join-requests/:id/approve', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
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
        // Под блокировкой комнаты — заявка всё ещё жива (её не отклонили и не
        // отозвали параллельно; FOR UPDATE — чтобы и не успели), а
        // одобряющий всё ещё участник. Строка заявителя блокируется раньше
        // заявки — в том же порядке, что и в deleteUserAccount (сначала
        // users, потом join_requests): одновременное удаление его аккаунта
        // не даст взаимной блокировки, заявка просто окажется удалённой.
        const result = await addRoomMember(request.room_id, request.user_id, async (room, client) => {
            const applicant = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [request.user_id]);
            if (applicant.rows.length === 0) return 'not-found';
            const live = await client.query(
                `SELECT jr.id FROM join_requests jr
                 JOIN room_participants rp ON rp.room_id = jr.room_id AND rp.user_id = $3
                 WHERE jr.id = $1 AND jr.user_id = $2 AND jr.room_id = $4 AND jr.${JOIN_REQUEST_LIVE_SQL}
                 FOR UPDATE OF jr`,
                [requestId, request.user_id, userId, room.id]
            );
            return live.rows.length > 0 ? null : 'not-found';
        });
        if (result.error === 'full') return res.json({ success: false, message: ROOM_FULL_MESSAGE });
        if (result.error) return res.json(JOIN_REQUEST_NOT_FOUND);
        notifyJoinRequestDecided(request.user_id, { requestId, approved: true, chat: result.chat });
        res.json({ success: true });
    } catch (error) {
        console.error('Approve join request error:', error);
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
        console.error('Deny join request error:', error);
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
        console.error('Cancel join request error:', error);
        res.json({ success: false, message: 'Ошибка отмены заявки' });
    }
});

app.delete('/api/chats/:chatId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        // Всё удаление — одной транзакцией (раньше — серия независимых
        // запросов: сбой посередине оставлял полуудалённый чат), файлы
        // удаляемых сообщений убираются с диска после COMMIT.
        const client = await pool.connect();
        let fileUrls = [];
        let roomSurvived = false;
        let droppedRequests = [];
        try {
            await client.query('BEGIN');
            if (chat.room_id) {
                // Блокировка комнаты: два последних участника, выходящих
                // одновременно, иначе оба видели бы "остался ещё один" и
                // комната оставалась бы в БД навсегда.
                await client.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [chat.room_id]);
                await client.query('DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
                const remaining = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 LIMIT 1', [chat.room_id]);
                if (remaining.rows.length === 0) {
                    // Последний участник вышел — сносим комнату целиком.
                    // Заявки ушли бы и каскадом, но заявителям надо сказать,
                    // что рассматривать их больше некому.
                    const deleted = await client.query('DELETE FROM messages WHERE room_id = $1 RETURNING file_url', [chat.room_id]);
                    fileUrls = deleted.rows.map(r => r.file_url);
                    const requests = await client.query('DELETE FROM join_requests WHERE room_id = $1 RETURNING id, user_id', [chat.room_id]);
                    droppedRequests = requests.rows;
                    await client.query('DELETE FROM rooms WHERE id = $1', [chat.room_id]);
                } else {
                    roomSurvived = true;
                }
                // Если участники остались — историю не трогаем, она у них
                // по-прежнему доступна по room_id (chat_id этого сообщения,
                // если оно было отправлено уходящим, просто станет NULL).
            } else {
                const deleted = await client.query('DELETE FROM messages WHERE chat_id = $1 RETURNING file_url', [chat.id]);
                fileUrls = deleted.rows.map(r => r.file_url);
                await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
            }
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }
        removeUploadedFiles(fileUrls);
        unsubscribeUserFromChat(userId, chat.id, chat.room_id);
        if (roomSurvived) notifyRoomMembersChanged(chat.room_id);
        for (const request of droppedRequests) notifyJoinRequestDecided(request.user_id, { requestId: request.id, approved: false });
        notifyChatListChanged(userId);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete chat error:', error);
        res.json({ success: false, message: 'Ошибка удаления чата' });
    }
});

app.put('/api/messages/:messageId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = toPositiveInt(req.params.messageId);
    const { text } = req.body || {};
    if (!messageId || !isNonEmptyString(text)) return res.json({ success: false, message: 'Текст не может быть пустым' });

    try {
        const message = await dbGet(
            'SELECT id, chat_id, room_id, user_id, encrypted FROM messages WHERE id = $1 AND user_id = $2 AND sent = 1 AND deleted = 0',
            [messageId, userId]
        );
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        // Правка E2EE-сообщения — это новый конверт того же (по флагу)
        // типа: клиент сам шифрует новый текст перед PUT, флаг при
        // редактировании не меняется (encrypted не пришло — просто он же).
        const maxLen = message.encrypted ? MAX_ENVELOPE_LENGTH : 4000;
        if (text.length > maxLen) return res.json({ success: false, message: `Сообщение не может быть длиннее ${maxLen} символов` });

        // Та же очистка, что и при отправке (раньше правкой её можно было обойти).
        const newText = message.encrypted ? text.trim() : sanitizeText(text.trim());
        if (!newText) return res.json({ success: false, message: 'Текст не может быть пустым' });
        const editedAt = new Date().toISOString();
        // AAD — от исходной строки: комната/чат и автор при правке не меняются.
        await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [writeMessageText(newText, message), editedAt, messageId]);

        // Раньше правки не рассылались по сокету — у остальных участников
        // комнаты изменение не появлялось без перезагрузки (см. "Мелочи").
        // Тем, кто вступил в комнату после этого сообщения, новый текст не
        // уходит: для них этого сообщения нет (visible_from_id).
        let target = io.to(getSocketRoomKey(message.chat_id, message.room_id));
        if (message.room_id) {
            const hidden = await dbAll(
                'SELECT user_id FROM room_participants WHERE room_id = $1 AND visible_from_id >= $2',
                [message.room_id, messageId]
            );
            for (const row of hidden) target = target.except('user:' + row.user_id);
        }
        target.emit('messageEdited', {
            id: messageId, text: newText, edited_at: editedAt,
            chat_id: message.chat_id, room_id: message.room_id, encrypted: message.encrypted, user_id: message.user_id
        });

        res.json({ success: true, edited_at: editedAt, text: newText });
    } catch (error) {
        console.error('Edit message error:', error);
        res.json({ success: false, message: 'Ошибка редактирования' });
    }
});

app.delete('/api/messages/:messageId', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = toPositiveInt(req.params.messageId);
    if (!messageId) return res.json({ success: false, message: 'Сообщение не найдено' });
    try {
        const message = await dbGet('SELECT id FROM messages WHERE id = $1 AND user_id = $2 AND deleted = 0', [messageId, userId]);
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        // Тот же путь, что и у disappearing messages: строка удаляется из БД
        // физически, вложение — с диска (раньше файл удалённого сообщения
        // оставался доступен по прямой ссылке), участникам уходит
        // 'messageDeleted'. Пустой результат — ошибка БД (она уже в логе).
        const deleted = await disappearingMessagesManager.deleteMessages([messageId]);
        if (deleted.length === 0) return res.json({ success: false, message: 'Ошибка удаления' });
        res.json({ success: true });
    } catch (error) {
        console.error('Delete message error:', error);
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

// Квота вложений: сумма file_size всех сообщений пользователя плюс новый
// файл (index-only scan по idx_messages_user_files).
async function exceedsUploadQuota(userId, incomingBytes) {
    const row = await dbGet(
        'SELECT COALESCE(SUM(file_size), 0) AS used FROM messages WHERE user_id = $1 AND file_size IS NOT NULL',
        [userId]
    );
    return Number(row && row.used) + incomingBytes > UPLOAD_QUOTA_BYTES;
}

// Два вида вложений:
//   * обычное — проверка сигнатуры, снятие метаданных (все типы, fail
//     closed), имя по типу вместо исходного (anonymizedFileName);
//   * E2EE (encrypted=true, только в комнатах) — сервер получает лишь
//     шифротекст (.bin) и E2EE-конверт с типом, именем и ключом файла;
//     сигнатуры и метаданные тут проверять не у чего — это случайные байты.
app.post('/api/messages/file', upload.single('file'), async (req, res) => {
    const file = req.file;
    const userId = req.session.userId;
    if (!userId) return rejectUpload(res, file, 401, 'Не авторизован');
    if (!file) return res.status(400).json({ success: false, message: 'Файл не выбран' });

    const body = req.body || {};
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
        envelope = typeof body.envelope === 'string' ? body.envelope.trim() : '';
        if (!envelope || envelope.length > MAX_ENVELOPE_LENGTH) {
            return rejectUpload(res, file, 400, 'Некорректный E2EE-конверт вложения');
        }
    } else {
        caption = typeof body.text === 'string' ? sanitizeText(body.text.trim()) : '';
        if (caption.length > 4000) return rejectUpload(res, file, 400, 'Подпись слишком длинная');
    }

    // Сначала проверка чата и квоты (дёшево), потом обработка файла (дорого).
    let chat;
    try {
        chat = await getOwnChat(body.chatId, userId);
        if (!chat) return rejectUpload(res, file, 404, 'Чат не найден');
        if (encrypted && !chat.room_id) {
            return rejectUpload(res, file, 400, 'Зашифрованные вложения доступны только в групповых чатах');
        }
        if (await exceedsUploadQuota(userId, file.size)) {
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
            console.error('Upload processing error:', magicErr.message);
            return rejectUpload(res, file, 400, 'Не удалось проверить содержимое файла');
        }
    }

    try {
        const time = getCurrentTime();
        const roomId = chat.room_id || null;
        const fileUrl = `/uploads/${file.filename}`;
        const fileType = file.mimetype;
        // Исходное имя файла (file.originalname) не хранится и не логируется.
        const fileName = encrypted ? null : anonymizedFileName(fileType);

        const messageType = encrypted ? 'file'
            : fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : 'file';
        const messageText = encrypted ? envelope : (caption || fileName);

        const inserted = await dbGet(
            `INSERT INTO messages (chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, time, status, encrypted, file_size)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, 'sent', $10, $11)
             RETURNING id, created_at`,
            [chat.id, roomId, userId, writeMessageText(messageText, { room_id: roomId, chat_id: chat.id, user_id: userId }),
                fileUrl, fileName, fileType, messageType, time, encrypted, fileSize]
        );

        await applyNewMessageExpiry(chat, inserted.id);

        // Раньше здесь по setTimeout статус "доставлено"/"прочитано"
        // выставлялся через 1 и 2 секунды независимо от реальности (и без
        // обработки ошибок — сбой БД ронял процесс). Теперь 'read' ставит
        // только markChatRead, когда получатель действительно открыл чат.
        const fileMessage = {
            id: inserted.id, chat_id: chat.id, room_id: roomId, user_id: userId,
            sender_username: req.session.username, sender_avatar: req.session.avatar || '',
            text: messageText, file_url: fileUrl, file_name: fileName,
            file_type: fileType, message_type: messageType, sent: 1, time, status: 'sent',
            edited_at: null, deleted: 0, encrypted, created_at: inserted.created_at,
            reply_to: null, reactions: [],
        };
        io.to(getSocketRoomKey(chat.id, roomId)).emit('newMessage', fileMessage);
        res.json({ success: true, message: fileMessage });
        if (roomId) unarchiveForRecipients(chat, userId);
    } catch (error) {
        console.error('Upload file error:', error);
        cleanupUploadedFile(file);
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
        `SELECT m.room_id, c.room_id AS chat_room_id, c.user_id AS chat_owner_id
         FROM messages m
         LEFT JOIN chats c ON m.chat_id = c.id
         WHERE m.id = $1 AND m.deleted = 0`,
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
    // ни реакции (граница visible_from_id, см. /api/chats/join).
    const participant = await dbGet(
        'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2 AND visible_from_id < $3',
        [roomId, userId, messageId]
    );
    return Boolean(participant);
}

// Файлы отдаются только тому, кто реально является участником чата/комнаты,
// к которому относится сообщение с этим файлом — а не просто "залогинен ли
// кто-то вообще" (см. п.1 аудита). Имя файла уникально (Date.now() + random),
// поэтому джойн messages.file_url -> chats/room_participants однозначно
// определяет владельца. Поиск идёт по индексу idx_messages_file_url.
async function userCanAccessFile(userId, filename) {
    const fileUrl = `/uploads/${filename}`;
    const message = await dbGet('SELECT id FROM messages WHERE file_url = $1 AND deleted = 0 LIMIT 1', [fileUrl]);
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
        await pool.query('INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [messageId, req.session.userId, emoji]);
        res.json({ success: true });
    } catch (error) {
        console.error('Add reaction error:', error);
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
        console.error('Remove reaction error:', error);
        res.json({ success: false, message: 'Ошибка удаления реакции' });
    }
});

app.get('/api/search', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    // ?q=a&q=b приходит массивом — раньше query.replace() на массиве падал
    // вне try и ронял процесс.
    const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    if (!query) return res.json({ success: true, results: { chats: [], messages: [] } });
    if (query.length > 100) return res.json({ success: false, message: 'Запрос слишком длинный' });

    const safeTerm = query.replace(/[%_\\]/g, '\\$&');
    const searchTerm = `%${safeTerm}%`;
    try {
        // Порядок — по времени создания: id чатов теперь случайные.
        const chats = await dbAll(
            `SELECT id, name, avatar, room_id, online, is_bot FROM chats
             WHERE user_id = $1 AND name ILIKE $2
             ORDER BY created_at DESC NULLS LAST, id DESC
             LIMIT 10`,
            [req.session.userId, searchTerm]
        );
        // Текст сообщений хранится зашифрованным, поэтому ILIKE по m.text на
        // стороне БД не работает (шифротекст с одним и тем же IV никогда не
        // повторяется, даже для одинакового исходного текста). Забираем
        // кандидатов (последние сообщения по всем чатам искателя) и
        // фильтруем уже после расшифровки на стороне приложения.
        //
        // Раньше кандидаты выбирались JOIN'ом с условием (room_id = ..) OR
        // (chat_id = ..), который не использует индексы. Теперь id
        // кандидатов берутся index-only scan'ом (не больше 500 на чат), и
        // только 500 самых свежих дочитываются из таблицы.
        // encrypted = FALSE — E2EE-сообщения (см. public/e2ee.js) сервер
        // расшифровать в принципе не может, это не баг поиска, а прямое
        // следствие сквозного шифрования.
        // В комнатах — только сообщения, видимые искателю (после его
        // вступления). msg_* — собственные room/chat/user строки сообщения,
        // нужны для AAD и клиенту не отдаются.
        const candidates = await dbAll(`
            SELECT m.id, m.text, m.created_at, m.time, uc.id AS chat_id, uc.name AS chat_name,
                   uc.room_id, uc.avatar, uc.online, uc.is_bot,
                   m.room_id AS msg_room_id, m.chat_id AS msg_chat_id, m.user_id AS msg_user_id
            FROM (
                SELECT ids.id, uc.id AS chat_id
                FROM chats uc
                LEFT JOIN room_participants rp ON rp.room_id = uc.room_id AND rp.user_id = uc.user_id
                CROSS JOIN LATERAL (
                    (SELECT id FROM messages
                      WHERE uc.room_id IS NOT NULL AND room_id = uc.room_id AND deleted = 0 AND encrypted = FALSE
                        AND id > COALESCE(rp.visible_from_id, 0)
                      ORDER BY id DESC LIMIT 500)
                    UNION ALL
                    (SELECT id FROM messages
                      WHERE uc.room_id IS NULL AND chat_id = uc.id AND deleted = 0 AND encrypted = FALSE
                      ORDER BY id DESC LIMIT 500)
                ) ids
                WHERE uc.user_id = $1
                ORDER BY ids.id DESC
                LIMIT 500
            ) cand
            JOIN messages m ON m.id = cand.id
            JOIN chats uc ON uc.id = cand.chat_id
            ORDER BY m.id DESC
        `, [req.session.userId]);
        const needle = query.toLowerCase();
        const messages = [];
        for (const { msg_room_id, msg_chat_id, msg_user_id, ...m } of candidates) {
            const text = readMessageText(m.text, { room_id: msg_room_id, chat_id: msg_chat_id, user_id: msg_user_id });
            if (typeof text === 'string' && text.toLowerCase().includes(needle)) {
                messages.push({ ...m, text });
                if (messages.length >= 20) break;
            }
        }
        res.json({ success: true, results: { chats, messages } });
    } catch (error) {
        console.error('Search error:', error);
        res.json({ success: false, message: 'Ошибка поиска' });
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
        // Проверка доступа к сообщению
        const message = await dbGet('SELECT user_id, room_id, chat_id FROM messages WHERE id = $1 AND deleted = 0', [messageId]);
        if (!message || message.user_id !== req.session.userId) {
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
        console.error('Set expiry error:', error);
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
        console.error('Set chat expiry error:', error);
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
        console.error('Set chat default expiry error:', error);
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
        console.error('Get chat settings error:', error);
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
        console.error('Set chat prefs error:', error);
        res.json({ success: false, message: 'Ошибка сохранения настроек чата' });
    }
});

// После ВСЕХ маршрутов: неизвестный /api/* — JSON-404.
registerApiNotFound(app);

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
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
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

// Полное удаление пользователя (POST /api/account/delete и его псевдоним
// /api/logout, чистка по сроку): его сообщения (и их файлы), реакции, E2EE
// key-shares, участие в комнатах, его заявки на вступление, опустевшие
// комнаты со всей историей и заявками в них,
// chats (chat_settings — каскадом), unread, сама строка users;
// message_expiry и реакции на его сообщения уходят каскадом. Одной
// транзакцией — раньше это была серия отдельных DELETE, и первая же ошибка
// FK (например, из e2ee_key_shares, который ссылается на users без каскада)
// оставляла пользователя в БД навсегда. После COMMIT — файлы с диска,
// сессии на всех устройствах, сокеты, публичные E2EE-ключи (встроенное
// хранилище) и уведомление оставшимся участникам комнат.
async function deleteUserAccount(userId) {
    let fileUrls = [];
    let survivingRoomIds = [];
    let requestRoomIds = [];
    let droppedRequests = [];
    const deleted = await withTransaction(async (client) => {
        // Блокировка строки пользователя: параллельная отправка сообщения
        // (FK на users) дождётся конца удаления и получит ошибку, а не
        // оставит сообщение, которое уже никто не удалит.
        const user = await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [userId]);
        if (user.rows.length === 0) return false;
        const rooms = await client.query('SELECT DISTINCT room_id FROM room_participants WHERE user_id = $1 ORDER BY room_id', [userId]);
        const roomIds = rooms.rows.map(r => r.room_id);
        // Комнаты блокируются так же, как при выходе из чата (DELETE
        // /api/chats/:chatId): иначе одновременный выход последнего другого
        // участника оставил бы пустую комнату навсегда. Порядок по id — без
        // взаимных блокировок между двумя такими удалениями.
        if (roomIds.length > 0) {
            await client.query('SELECT id FROM rooms WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE', [roomIds]);
        }
        const ownMessages = await client.query('DELETE FROM messages WHERE user_id = $1 RETURNING file_url', [userId]);
        fileUrls = ownMessages.rows.map(r => r.file_url);
        await client.query('DELETE FROM reactions WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM e2ee_key_shares WHERE sender_id = $1 OR recipient_id = $1', [userId]);
        await client.query('DELETE FROM room_participants WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM chats WHERE user_id = $1', [userId]);
        const ownRequests = await client.query('DELETE FROM join_requests WHERE user_id = $1 RETURNING room_id', [userId]);
        requestRoomIds = [...new Set(ownRequests.rows.map(r => r.room_id))];

        if (roomIds.length > 0) {
            const orphaned = await client.query(
                `DELETE FROM messages m WHERE m.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = m.room_id)
                 RETURNING file_url`,
                [roomIds]
            );
            fileUrls.push(...orphaned.rows.map(r => r.file_url));
            // Заявки в опустевшие комнаты ушли бы и каскадом, но заявителям
            // надо сказать, что рассматривать их больше некому.
            const orphanedRequests = await client.query(
                `DELETE FROM join_requests jr WHERE jr.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = jr.room_id)
                 RETURNING id, user_id`,
                [roomIds]
            );
            droppedRequests = orphanedRequests.rows;
            const removedRooms = await client.query(
                `DELETE FROM rooms r WHERE r.id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = r.id)
                 RETURNING id`,
                [roomIds]
            );
            const removed = new Set(removedRooms.rows.map(r => r.id));
            survivingRoomIds = roomIds.filter(id => !removed.has(id));
        }
        await client.query('DELETE FROM users WHERE id = $1', [userId]);
        return true;
    });
    if (!deleted) return false;

    removeUploadedFiles(fileUrls);
    anonActivity.forget(userId);
    io.in('user:' + userId).disconnectSockets(true);
    for (const roomId of survivingRoomIds) notifyRoomMembersChanged(roomId);
    for (const roomId of requestRoomIds) notifyJoinRequestsChanged(roomId);
    for (const request of droppedRequests) notifyJoinRequestDecided(request.user_id, { requestId: request.id, approved: false });
    deleteKeysForUser(userId);
    // Сессии на других устройствах. После COMMIT и отдельно: таблицы session
    // может ещё не быть (42P01), а ошибка внутри транзакции откатила бы всё.
    try {
        await dbRun(`DELETE FROM session WHERE sess->>'userId' = $1`, [String(userId)]);
    } catch (error) {
        if (error.code !== '42P01') console.error('[Account] Не удалось удалить сессии:', error.message);
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
jobs.register({
    name: 'cleanupStaleTempFiles', run: () => cleanupStaleTempFiles(UPLOADS_DIR, 60 * 60 * 1000),
    intervalMs: 60 * 60 * 1000, exclusive: false,
});
// Задачи lib-модулей (JOB_MODULES в lib/jobs/index.js).
registerJobModules(jobs, serverContext);

// Страховка: ошибка в фоновой задаче (таймеры, сокеты) не должна ронять
// весь сервер. Маршруты уже защищены wrapAsync.
process.on('unhandledRejection', (reason) => {
    console.error('[Process] Необработанный reject промиса:', reason);
});

function onServerListening() {
    const addresses = getLocalAddresses();
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
    console.log('  + CSP с nonce, заголовки приватности' + (IS_PRODUCTION ? ', HSTS по https' : ''));
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
