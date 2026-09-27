require('dotenv').config();

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
const pgSession = require('connect-pg-simple')(session);
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = rateLimit;

// Импорт новых модулей безопасности и приватности
const { stripMetadataFromFile, cleanupStaleTempFiles } = require('./lib/metadata-stripper');
const DisappearingMessagesManager = require('./lib/disappearing-messages');
const { encryptText, decryptText, messageAad } = require('./lib/message-crypto');
const { addRandomDelay, sanitizeText, getPrivacyHeaders } = require('./lib/privacy');
const {
    hashPassword,
    verifyPassword,
    needsRehash,
    checkPasswordPolicy,
    DUMMY_PASSWORD_HASH
} = require('./lib/passwords');
const {
    ALLOWED_MIME_TYPES,
    MIME_EXTENSIONS,
    ENCRYPTED_FILE_MIME,
    ENCRYPTED_FILE_EXTENSION,
    ALL_ANONYMIZED_FILE_NAMES,
    anonymizedFileName,
    randomString,
    generateUniqueCode,
    generateInviteCode,
    normalizeInviteCode,
    isValidInviteCode,
    isInviteExpired,
    parseAllowedOrigins,
    isRequestOriginAllowed,
    buildContentSecurityPolicy,
    resolveDbTlsConfig,
    createCounter,
    normalizeEmail,
    positiveNumberOr
} = require('./lib/security-utils');

// Импорт E2EE прокси (маршруты регистрируются после sessionMiddleware —
// см. вызов registerE2eeProxyRoutes ниже)
const { registerE2eeProxyRoutes, deleteKeysForUser } = require('./lib/e2ee-proxy');
// Групповой E2EE: участники чата + попарная доставка Sender Key
// (key-shares). Тоже регистрируется после sessionMiddleware.
const { initE2eeGroupsSchema, registerE2eeGroupRoutes } = require('./lib/e2ee-groups');

// Onion-сервис (контейнер tor-service/) и proof-of-work для регистрации
const { ONION_ADDRESS, ONION_PORT, onionMiddleware, isOnionHost, isOnionSocket, listenOnionPort } = require('./lib/tor-support');
const { createChallenge, verifySolution } = require('./lib/pow');

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// === RUST ANON SERVICE INTEGRATION ===
// Только если адрес задан явно. Раньше по умолчанию был 127.0.0.1:8080 — а
// на Railway PORT=8080, и анонимная регистрация стучалась в сам же сервер.
const ANON_SERVICE_URL = process.env.ANON_SERVICE_URL || null;
// Общий секрет с anon-service: без него любой, кто достучится до сервиса
// по внутренней сети, мог бы сам выпрашивать у него "анонимные" личности.
const ANON_SERVICE_SECRET = process.env.ANON_SERVICE_SECRET || null;

async function fetchAnonymousIdentity() {
    if (!ANON_SERVICE_URL) return null;
    try {
        const res = await fetch(`${ANON_SERVICE_URL}/generate`, {
            method: 'POST',
            headers: ANON_SERVICE_SECRET ? { 'X-Internal-Secret': ANON_SERVICE_SECRET } : {},
            signal: AbortSignal.timeout(2000)
        });
        if (res.ok) {
            const data = await res.json();
            if (data.unique_code && data.username) return data;
        }
    } catch (e) {
        console.warn('[Anon] Rust service unavailable, using fallback:', e.message);
    }
    return null;
}

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

function checkMagicBytes(buffer, mimetype) {
    if (!buffer || buffer.length < 4) return false;
    const b = buffer;
    if (mimetype === 'image/jpeg') return b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF;
    if (mimetype === 'image/png')  return b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47;
    if (mimetype === 'image/gif')  return b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46;
    if (mimetype === 'image/webp') return b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46;
    if (mimetype === 'application/pdf') return b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46;
    // Единственная надёжная сигнатура MP4/ISO-BMFF — 'ftyp' на смещении 4-7.
    // Раньше был ещё fallback b[0]===0 && b[1]===0 — под него подходит куча
    // произвольных бинарных форматов, так что от него больше вреда, чем пользы.
    if (mimetype === 'video/mp4')  return b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70;
    if (mimetype === 'audio/mpeg') return (b[0] === 0xFF && (b[1] & 0xE0) === 0xE0) || (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33);
    if (mimetype === 'audio/ogg' || mimetype === 'video/webm' || mimetype === 'audio/webm') {
        return (b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67) || (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3);
    }
    // WAV — RIFF-контейнер: контейнер сам по себе (байты 0-3 'RIFF') общий с
    // любым другим RIFF-форматом (в т.ч. WebP/AVI), поэтому дополнительно
    // проверяем 'WAVE' на смещении 8-11, как и положено для формата WAVE.
    if (mimetype === 'audio/wav') {
        return buffer.length >= 12
            && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46
            && b[8] === 0x57 && b[9] === 0x41 && b[10] === 0x56 && b[11] === 0x45;
    }
    if (mimetype === 'text/plain') return true;
    if (mimetype === 'video/quicktime') return b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70;
    return false;
}

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
// запрос и обнуляет все rate-limit'ы (login/register/change-password).
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

// Вход: для clearnet — по IP; для onion IP общий у всех, поэтому ключ —
// email (перебор паролей одного аккаунта через Tor всё равно упирается
// в loginAccountLimiter ниже).
const loginLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyGenerator: (req) => (req.isOnion ? `onion:${normalizeEmail(req.body && req.body.email)}` : rateLimitKeyGenerator(req)),
    message: { success: false, message: 'Слишком много попыток входа. Попробуйте позже.' }
});

// Лимит на аккаунт для всех: смена IP (ботнет, новые цепочки Tor) не даёт
// перебирать пароль одного пользователя быстрее 10 попыток в час.
const loginAccountLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 60 * 60 * 1000,
    max: 10,
    keyGenerator: (req) => `account:${normalizeEmail(req.body && req.body.email)}`,
    message: { success: false, message: 'Слишком много попыток входа в этот аккаунт. Попробуйте позже.' }
});

// Массовую регистрацию теперь сдерживает proof-of-work (lib/pow.js). IP-лимит
// остался мягким и только для clearnet: для onion он запер бы регистрацию
// всем сразу (общий IP контейнера tor).
const registerLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 60 * 60 * 1000,
    max: 10,
    skip: (req) => req.isOnion,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много регистраций. Попробуйте позже.' }
});

// Смена пароля и удаление аккаунта (оба — только для залогиненных). Ключ —
// пользователь: угадывать пароль по украденной сессии можно только в
// рамках её аккаунта, а onion-пользователи не делят один счётчик на всех.
const passwordLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 15 * 60 * 1000,
    max: 3,
    keyGenerator: (req) => (sessionUserId(req) ? `user:${sessionUserId(req)}` : rateLimitKeyGenerator(req)),
    message: { success: false, message: 'Слишком много попыток ввода пароля. Попробуйте позже.' }
});

// Вход в комнату по коду: даже 130-битный код не должен перебираться
// с бесконечной скоростью, и утёкший список кодов — массово проверяться.
const joinUserLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 15 * 60 * 1000,
    max: 20,
    skip: (req) => !sessionUserId(req),
    keyGenerator: (req) => `user:${sessionUserId(req)}`,
    message: { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' }
});
const joinIpLimiter = rateLimit({
    ...RATE_LIMIT_DEFAULTS,
    windowMs: 15 * 60 * 1000,
    max: 60,
    skip: (req) => req.isOnion,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' }
});

// 300 запросов за 15 минут (~1 в 3 секунды) активный пользователь чата
// выбирал за несколько минут — особенно когда клиент перезапрашивал
// список чатов на каждое входящее сообщение — после чего всё приложение
// "висло" с ошибкой на 15 минут. Залогиненных считаем по аккаунту (за
// одним NAT или onion-адресом их много), остальных — по IP. Неавторизованные
// onion-запросы не считаются: у них один IP на всех, и любой исчерпал бы
// общую квоту за всех onion-посетителей. Их открытые маршруты (вход,
// регистрация) защищены лимитом на аккаунт и proof-of-work, а от флуда —
// защита самого onion-сервиса (см. tor-service/README.md).
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

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: sslConfig,
    max: Number(process.env.PG_POOL_MAX) || 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});
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

// Пересоздаёт внешний ключ, только если его нет или у него другое
// ON DELETE-поведение. Раньше КАЖДЫЙ старт делал DROP + ADD CONSTRAINT для
// восьми FK: ADD CONSTRAINT перепроверяет всю таблицу под ACCESS EXCLUSIVE
// блокировкой — на большой БД запуск шёл минутами, и всё это время любые
// запросы к messages/chats висели.
const FK_DELETE_ACTIONS = { 'NO ACTION': 'a', 'RESTRICT': 'r', 'CASCADE': 'c', 'SET NULL': 'n' };
async function ensureForeignKey(table, constraint, column, refTable, onDelete) {
    const existing = await dbGet(
        'SELECT confdeltype FROM pg_constraint WHERE conname = $1 AND conrelid = $2::regclass',
        [constraint, table]
    );
    if (existing && existing.confdeltype === FK_DELETE_ACTIONS[onDelete]) return;
    await pool.query(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${constraint}`);
    await pool.query(`ALTER TABLE ${table} ADD CONSTRAINT ${constraint} FOREIGN KEY (${column}) REFERENCES ${refTable}(id) ON DELETE ${onDelete}`);
}

async function initDatabase() {
    await maybeDumpCa().catch(err => { console.error('[DUMP_CA] Ошибка:', err.message); process.exit(1); });

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            unique_code TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT,
            avatar TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS rooms (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS chats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            room_id INTEGER REFERENCES rooms(id),
            name TEXT NOT NULL,
            avatar TEXT NOT NULL,
            online INTEGER DEFAULT 0,
            is_bot INTEGER DEFAULT 0
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER NOT NULL REFERENCES chats(id),
            room_id INTEGER REFERENCES rooms(id),
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
            reply_to_id INTEGER REFERENCES messages(id)
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS unread (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER NOT NULL REFERENCES chats(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            count INTEGER DEFAULT 0
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS room_participants (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id),
            user_id INTEGER NOT NULL REFERENCES users(id)
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS reactions (
            id SERIAL PRIMARY KEY,
            message_id INTEGER NOT NULL REFERENCES messages(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            emoji TEXT NOT NULL,
            UNIQUE(message_id, user_id, emoji)
        )
    `);

    // Текущее состояние колонок — одним запросом. ALTER TABLE ... IF NOT
    // EXISTS всё равно берёт ACCESS EXCLUSIVE блокировку таблицы, поэтому
    // миграции ниже выполняются только если они действительно нужны.
    const columns = await dbAll(`
        SELECT table_name, column_name, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name IN ('users', 'chats', 'messages', 'rooms', 'room_participants')
    `);
    const column = (table, name) => columns.find(c => c.table_name === table && c.column_name === name);

    // Миграция: если таблицы chats/messages были созданы ДО появления комнат,
    // CREATE TABLE IF NOT EXISTS их не тронет и колонки room_id не будет.
    if (!column('chats', 'room_id')) await pool.query('ALTER TABLE chats ADD COLUMN room_id INTEGER REFERENCES rooms(id)');
    if (!column('messages', 'room_id')) await pool.query('ALTER TABLE messages ADD COLUMN room_id INTEGER REFERENCES rooms(id)');
    // E2EE: сообщение хранит клиентский шифроконверт вместо обычного
    // текста (см. public/e2ee.js). Серверное шифрование "at rest" из
    // lib/message-crypto.js применяется поверх в обоих случаях —
    // этот флаг только про то, что лежит ВНУТРИ, после его снятия.
    if (!column('messages', 'encrypted')) await pool.query('ALTER TABLE messages ADD COLUMN encrypted BOOLEAN NOT NULL DEFAULT FALSE');
    // Точное время отправки. Поле time ('HH:MM') формируется в часовом
    // поясе СЕРВЕРА (на хостинге это UTC), и пользователи из других поясов
    // видели время со сдвигом. Клиент теперь форматирует created_at сам.
    // Колонка добавляется без DEFAULT, чтобы у старых сообщений было NULL
    // (клиент покажет их time), а не момент миграции.
    if (!column('messages', 'created_at')) {
        await pool.query('ALTER TABLE messages ADD COLUMN created_at TIMESTAMPTZ');
        await pool.query('ALTER TABLE messages ALTER COLUMN created_at SET DEFAULT NOW()');
    }
    // Непрочитанные: id последнего прочитанного сообщения в личной строке
    // chats каждого участника. Раньше счётчик считал только сообщения с
    // sent = 0 (их пишет лишь бот, и сразу со статусом 'read'), т.е. всегда 0.
    const lastReadColumn = column('chats', 'last_read_message_id');
    if (!lastReadColumn) await pool.query('ALTER TABLE chats ADD COLUMN last_read_message_id INTEGER');

    // Все ADD COLUMN ниже — с NULL или константой по умолчанию: в PG 11+
    // это правка только метаданных, без перезаписи таблицы.
    //
    // Отметки прочтения можно выключить (POST /api/user/privacy).
    if (!column('users', 'read_receipts')) {
        await pool.query('ALTER TABLE users ADD COLUMN read_receipts BOOLEAN NOT NULL DEFAULT TRUE');
    }
    // Срок жизни инвайт-кода; коды старых комнат перевыпускаются ниже
    // (regenerateLegacyInviteCodes).
    if (!column('rooms', 'code_expires_at')) {
        await pool.query('ALTER TABLE rooms ADD COLUMN code_expires_at TIMESTAMPTZ');
    }
    // С какого сообщения участник видит историю комнаты: новичок видит
    // только то, что отправлено ПОСЛЕ его вступления (раньше код приглашения
    // открывал всю переписку с самого начала). Уже состоящие участники — 0,
    // то есть всё, как и раньше.
    if (!column('room_participants', 'visible_from_id')) {
        await pool.query('ALTER TABLE room_participants ADD COLUMN visible_from_id INTEGER NOT NULL DEFAULT 0');
    }
    // Размер вложения — для квоты UPLOAD_QUOTA_MB. У старых вложений NULL
    // (в квоту не засчитываются).
    if (!column('messages', 'file_size')) {
        await pool.query('ALTER TABLE messages ADD COLUMN file_size BIGINT');
    }
    // Порядок чатов без сообщений раньше давал chats.id DESC — с случайными
    // id (ensureRandomIdDefaults) он больше ничего не значит. У старых
    // строк NULL: между собой они по-прежнему упорядочены по id.
    if (!column('chats', 'created_at')) {
        await pool.query('ALTER TABLE chats ADD COLUMN created_at TIMESTAMPTZ');
        await pool.query('ALTER TABLE chats ALTER COLUMN created_at SET DEFAULT NOW()');
    }

    await ensureRandomIdDefaults(column);

    // Миграция: удаление чата/выход из комнаты падало с нарушением FK —
    // messages.chat_id (NOT NULL, без ON DELETE) не давал снести свою же
    // запись в chats, если пользователь уже что-то написал, а chats.room_id
    // не давал снести саму комнату, пока на неё ссылалась хоть одна запись в
    // chats. Разрешаем chat_id уходить в NULL (история комнаты остаётся
    // видна остальным по room_id) и каскадно чистим осиротевшие chats при
    // удалении room.
    if (column('messages', 'chat_id')?.is_nullable === 'NO') {
        await pool.query('ALTER TABLE messages ALTER COLUMN chat_id DROP NOT NULL');
    }
    await ensureForeignKey('messages', 'messages_chat_id_fkey', 'chat_id', 'chats', 'SET NULL');
    await ensureForeignKey('chats', 'chats_room_id_fkey', 'room_id', 'rooms', 'CASCADE');
    // Реакции должны исчезать вместе со своим сообщением (иначе снос всех
    // сообщений комнаты падает с reactions_message_id_fkey, как только у
    // любого из них есть хоть одна реакция).
    await ensureForeignKey('reactions', 'reactions_message_id_fkey', 'message_id', 'messages', 'CASCADE');
    // Ответ на удалённое сообщение просто теряет связь с оригиналом, а не
    // блокирует его удаление и не удаляется сам.
    await ensureForeignKey('messages', 'messages_reply_to_id_fkey', 'reply_to_id', 'messages', 'SET NULL');
    // Остальное уже удаляется в правильном порядке на уровне приложения
    // (см. DELETE /api/chats/:chatId), но каскад добавлен как страховка на
    // случай, если порядок операций там в будущем изменят по ошибке.
    await ensureForeignKey('messages', 'messages_room_id_fkey', 'room_id', 'rooms', 'CASCADE');
    await ensureForeignKey('unread', 'unread_chat_id_fkey', 'chat_id', 'chats', 'CASCADE');
    await ensureForeignKey('room_participants', 'room_participants_room_id_fkey', 'room_id', 'rooms', 'CASCADE');

    await initE2eeGroupsSchema(pool);
    // Таблицы message_expiry/chat_settings ссылаются на messages/chats,
    // поэтому создаются только после них. Раньше initialize() вызывался в
    // самом начале — на пустой БД сервер падал с "relation messages does
    // not exist" и не запускался вообще.
    await disappearingMessagesManager.initialize();

    // Индексы для выборок "сообщения чата по id". Включённые колонки
    // позволяют последнему сообщению, счётчику непрочитанного, странице
    // истории и кандидатам поиска читаться index-only scan'ом. Без них
    // планировщик выбирал обратный проход по первичному ключу с фильтром
    // по room_id — для "тихой" комнаты это просмотр почти всей таблицы.
    // Префикс (room_id)/(chat_id) заодно обслуживает удаление комнаты/чата
    // и каскады внешних ключей, так что старые одноколоночные индексы не нужны.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_room_live ON messages(room_id, deleted, id) INCLUDE (user_id, sent, encrypted)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_chat_live ON messages(chat_id, deleted, id) INCLUDE (user_id, sent, encrypted)');
    await pool.query('DROP INDEX IF EXISTS idx_messages_room_id');
    await pool.query('DROP INDEX IF EXISTS idx_messages_chat_id');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id)');
    // Каждая картинка/файл в чате проверяет доступ поиском по file_url —
    // без индекса это был полный проход по всей таблице messages на КАЖДЫЙ
    // запрос /uploads/*.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_file_url ON messages(file_url) WHERE file_url IS NOT NULL');
    // Для ON DELETE SET NULL по reply_to_id: без индекса удаление каждого
    // сообщения сканировало всю таблицу в поисках ответов на него (снос
    // комнаты с N сообщениями — N полных проходов).
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_reply_to_id ON messages(reply_to_id) WHERE reply_to_id IS NOT NULL');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_room_id ON chats(room_id)');
    // Сумма размеров вложений пользователя (квота) — index-only scan по
    // его файлам, а не проход по всем его сообщениям.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_user_files ON messages(user_id) INCLUDE (file_size) WHERE file_size IS NOT NULL');
    // Проверка "участник ли комнаты" выполняется на каждый файл, реакцию и
    // joinChat. Уникальный (room_id, user_id) заодно не даёт одному
    // пользователю оказаться в комнате дважды (с двумя visible_from_id).
    await ensureUniqueRoomParticipants();
    await pool.query('CREATE INDEX IF NOT EXISTS idx_room_participants_user ON room_participants(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id)');

    // Разовое заполнение last_read_message_id для существующих чатов (все
    // старые сообщения считаются прочитанными, чтобы после обновления у
    // всех не "загорелись" бейджи на всю историю).
    if (!lastReadColumn || lastReadColumn.is_nullable === 'YES') {
        await pool.query(`
            UPDATE chats c SET last_read_message_id = COALESCE(CASE
                WHEN c.room_id IS NOT NULL THEN (SELECT MAX(m.id) FROM messages m WHERE m.room_id = c.room_id)
                ELSE (SELECT MAX(m.id) FROM messages m WHERE m.chat_id = c.id)
            END, 0)
            WHERE c.last_read_message_id IS NULL
        `);
        await pool.query('ALTER TABLE chats ALTER COLUMN last_read_message_id SET DEFAULT 0');
        await pool.query('ALTER TABLE chats ALTER COLUMN last_read_message_id SET NOT NULL');
    }

    if (column('users', 'email')?.is_nullable === 'NO') {
        await pool.query('ALTER TABLE users ALTER COLUMN email DROP NOT NULL');
    }
    if (column('users', 'password')?.is_nullable === 'NO') {
        await pool.query('ALTER TABLE users ALTER COLUMN password DROP NOT NULL');
    }

    await regenerateLegacyInviteCodes();
    await anonymizeLegacyFileNames();

    console.log('База данных инициализирована');
}

// ---- Случайные id для users, rooms, chats ----
//
// Последовательные id выдавали размер и темп роста сервиса (id свежей
// регистрации = число пользователей) и порядок событий: по id комнаты или
// чата было видно, кто и когда создал её раньше. Новые строки получают
// случайный id из [1 000 000, 2^31 - 1]: 48 бит из gen_random_uuid() (PG 13+,
// внутри pg_strong_random — криптостойкий ГСЧ; первые 12 hex-цифр UUIDv4
// случайны целиком) по модулю размера диапазона (смещение ~2^-17 — не
// различимо), с перепроверкой занятости в цикле. Существующие id не
// меняются. messages.id остаётся последовательным намеренно: на порядке
// сообщений держатся история, непрочитанное и visible_from_id.
//
// Тело функции — константа: по ней же при старте видно, что в БД уже
// нужная версия, и CREATE OR REPLACE не выполняется лишний раз (два
// одновременно стартующих экземпляра иначе ловили бы "tuple concurrently
// updated").
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

async function ensureRandomIdDefaults(column) {
    const existing = await dbGet(
        `SELECT p.prosrc FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE p.proname = 'nyxo_random_id' AND n.nspname = current_schema()`
    );
    if (!existing || existing.prosrc !== RANDOM_ID_FUNCTION_BODY) {
        await pool.query(`
            CREATE OR REPLACE FUNCTION nyxo_random_id(target regclass) RETURNS integer
            LANGUAGE plpgsql VOLATILE AS $fn$${RANDOM_ID_FUNCTION_BODY}$fn$
        `);
    }
    for (const table of ['users', 'rooms', 'chats']) {
        const current = String(column(table, 'id')?.column_default || '');
        if (!current.includes('nyxo_random_id(')) {
            await pool.query(`ALTER TABLE ${table} ALTER COLUMN id SET DEFAULT nyxo_random_id('${table}'::regclass)`);
        }
    }
}

// Уникальный индекс (room_id, user_id) вместо прежнего неуникального.
// Дубли (гонка двух одновременных "войти по коду" до этой версии) чистятся
// в той же транзакции, под блокировкой записи в таблицу: иначе между
// чисткой и CREATE UNIQUE INDEX старый экземпляр сервера (деплой без
// простоя) мог вставить новый дубль, и старт упал бы.
async function ensureUniqueRoomParticipants() {
    const existing = await dbGet("SELECT to_regclass('idx_room_participants_unique') AS idx");
    if (!existing || !existing.idx) {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query('LOCK TABLE room_participants IN SHARE ROW EXCLUSIVE MODE');
            const removed = await client.query(`
                DELETE FROM room_participants a USING room_participants b
                WHERE a.room_id = b.room_id AND a.user_id = b.user_id AND a.id > b.id
            `);
            await client.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_room_participants_unique ON room_participants(room_id, user_id)');
            await client.query('COMMIT');
            if (removed.rowCount > 0) console.log(`[DB] Удалено дублей участников комнат: ${removed.rowCount}`);
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    }
    await pool.query('DROP INDEX IF EXISTS idx_room_participants_room_user');
}

const MIGRATION_BATCH = 500;

// Коды приглашения старого формата (6 символов, ~30 бит, бессрочные)
// перевыпускаются в новом формате со сроком жизни: старые ссылки перестают
// работать — это и есть цель. Повторный старт ничего не трогает: коротких
// кодов и NULL-сроков после первого прохода не остаётся.
async function regenerateLegacyInviteCodes() {
    const legacy = await dbAll('SELECT id FROM rooms WHERE length(code) < 20 ORDER BY id');
    for (let i = 0; i < legacy.length; i += MIGRATION_BATCH) {
        const ids = legacy.slice(i, i + MIGRATION_BATCH).map(r => r.id);
        await pool.query(
            `UPDATE rooms r SET code = v.code, code_expires_at = NOW() + $3::integer * INTERVAL '1 second'
             FROM unnest($1::int[], $2::text[]) AS v(id, code)
             WHERE r.id = v.id`,
            [ids, ids.map(() => generateInviteCode()), INVITE_TTL_SECONDS]
        );
    }
    const withoutExpiry = await pool.query(
        `UPDATE rooms SET code_expires_at = NOW() + $1::integer * INTERVAL '1 second' WHERE code_expires_at IS NULL`,
        [INVITE_TTL_SECONDS]
    );
    if (legacy.length > 0 || withoutExpiry.rowCount > 0) {
        console.log(`[Invites] Перевыпущено старых кодов приглашения: ${legacy.length}, выставлен срок: ${withoutExpiry.rowCount}`);
    }
}

// Старые вложения хранили исходное имя файла ("IMG_20260914_Ivanov.png"),
// а у вложений без подписи оно же было и текстом сообщения. Имя заменяется
// обезличенным по типу (anonymizedFileName), текст — тоже, если он
// совпадал с именем. Выбираются только строки с ещё не обезличенным
// именем, так что повторный старт ничего не меняет.
async function anonymizeLegacyFileNames() {
    let total = 0;
    for (;;) {
        const rows = await dbAll(
            `SELECT id, room_id, chat_id, user_id, text, file_name, file_type FROM messages
             WHERE file_url IS NOT NULL AND encrypted = FALSE AND file_name IS NOT NULL
               AND file_name <> ALL($1::text[])
             ORDER BY id
             LIMIT $2`,
            [ALL_ANONYMIZED_FILE_NAMES, MIGRATION_BATCH]
        );
        if (rows.length === 0) break;
        const names = [];
        const texts = [];
        for (const row of rows) {
            const name = anonymizedFileName(row.file_type);
            names.push(name);
            texts.push(readMessageText(row.text, row) === row.file_name ? writeMessageText(name, row) : null);
        }
        await pool.query(
            `UPDATE messages m SET file_name = v.name, text = COALESCE(v.text, m.text)
             FROM unnest($1::int[], $2::text[], $3::text[]) AS v(id, name, text)
             WHERE m.id = v.id`,
            [rows.map(r => r.id), names, texts]
        );
        total += rows.length;
        if (rows.length < MIGRATION_BATCH) break;
    }
    if (total > 0) console.log(`[Uploads] Обезличены имена старых вложений: ${total}`);
}

// Раньше удаление сообщения было soft-delete: строка (автор, время,
// комната, шифротекст) оставалась в БД навсегда. Теперь удаление
// физическое, а оставшиеся от старой схемы строки удаляются один раз после
// старта — в фоне и пачками, чтобы не держать блокировки и не задерживать
// открытие порта (поиск по deleted <> 0 — проход по всей таблице).
async function purgeLegacySoftDeletedMessages() {
    let total = 0;
    try {
        for (;;) {
            const rows = await dbAll(
                `DELETE FROM messages WHERE id IN (
                     SELECT id FROM messages WHERE deleted <> 0 LIMIT $1
                 ) RETURNING file_url`,
                [MIGRATION_BATCH]
            );
            removeUploadedFiles(rows.map(r => r.file_url));
            total += rows.length;
            if (rows.length < MIGRATION_BATCH) break;
        }
        if (total > 0) console.log(`[DB] Удалено сообщений, помеченных удалёнными в старой схеме: ${total}`);
    } catch (err) {
        console.error('[DB] Не удалось удалить старые soft-deleted сообщения:', err.message);
    }
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

function normalizeAvatarColor(value) {
    const color = String(value || '').trim();
    return /^#[0-9a-fA-F]{6}$/.test(color) ? color.toUpperCase() : '#667EEA';
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

// Длина пароля: при регистрации и смене — не больше 256 символов (политика
// в lib/passwords.js); при входе — лишь анти-DoS порог, чтобы мегабайтная
// строка не уходила в HMAC/bcrypt, но и пароль, заданный по старым
// правилам, не отвергался заранее.
const MAX_PASSWORD_LENGTH = 256;
const MAX_LOGIN_PASSWORD_LENGTH = 1024;

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) throw new Error('SESSION_SECRET не задан в переменных окружения');

const ANON_SESSION_MAX_AGE_MS = 4 * 60 * 60 * 1000;

const sessionMiddleware = session({
    store: new pgSession({
        pool: pool,
        tableName: 'session',
        createTableIfMissing: true,
        // Без rolling кука сессии перевыставляется браузеру только при
        // изменении сессии, так что продлевать expire строки в БД на каждом
        // запросе бессмысленно — а это был лишний UPDATE session на КАЖДЫЙ
        // HTTP-запрос (включая, раньше, каждый CSS/JS-файл).
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

function isExpiredAnonymousSession(sess) {
    return Boolean(sess && sess.isAnonymous && sess.createdAt && Date.now() - sess.createdAt > ANON_SESSION_MAX_AGE_MS);
}

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
    if (!sess || !sess.userId || isExpiredAnonymousSession(sess)) {
        return next(new Error('Не авторизован'));
    }
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
});

io.on('connection', async (socket) => {
    const userId = socket.request.session.userId;

    // Счётчики растут только для реально установленных соединений. Раньше
    // счётчик IP увеличивался ещё в middleware, а единственное место
    // уменьшения — 'disconnect' — для отклонённого рукопожатия не наступает:
    // IP мог навсегда упереться в лимит.
    const ip = socket.data.clientIp;
    userSocketCount.increment(userId);
    if (ip) ipSocketCount.increment(ip);
    socket.on('disconnect', () => {
        userSocketCount.decrement(userId);
        if (ip) ipSocketCount.decrement(ip);
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
    // HSTS — только для настоящего https в production: по http браузер его
    // всё равно игнорирует, а в разработке он "залипал" бы на localhost.
    if (IS_PRODUCTION && req.secure && !req.isOnion) {
        res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
});

// Небезопасные методы — только со своих страниц (см. isTrustedOrigin).
// Второй рубеж к CSRF-токену ниже: SameSite=Lax и токен защищают от
// межсайтовых форм, а проверка Origin — ещё и от поддоменов/соседних
// сайтов, которые могут подсадить свою csrf_token-куку.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
app.use((req, res, next) => {
    if (SAFE_METHODS.has(req.method) || isTrustedOrigin(req.headers)) return next();
    res.status(403).json({ success: false, message: 'Запрещено: запрос с чужого сайта' });
});

app.use(cookieParser());

function issueCsrfCookie(req, res) {
    const token = crypto.randomBytes(32).toString('hex');
    res.cookie('csrf_token', token, {
        httpOnly: false,
        // Раньше в production — 'none' (кука уходила и на межсайтовые
        // запросы). Secure — по фактическому протоколу: .onion и локальная
        // разработка по http иначе не получили бы куку вовсе.
        sameSite: 'lax',
        secure: Boolean(req.secure),
        maxAge: 24 * 60 * 60 * 1000
    });
    return token;
}

app.use((req, res, next) => {
    if (req.path.startsWith('/socket.io')) return next();

    // Раньше кука csrf_token выставлялась только на небезопасных методах, а
    // безопасные (GET) сразу пропускались без неё — значит самая первая
    // загрузка страницы (GET /) никогда не сеяла куку, и когда фронт слал
    // первый POST (обычно /api/login или /api/register), проверка ниже
    // видела отсутствие куки и просто выставляла её "на лету", пропуская
    // САМ этот запрос без проверки (см. п.11 аудита). Теперь кука сеется на
    // любом запросе, включая GET — к моменту первого POST от SPA (после
    // того как браузер уже загрузил index.html/script.js через GET) она уже
    // гарантированно на месте.
    const cookieToken = req.cookies['csrf_token'];
    const cookieWasMissing = !cookieToken;
    const issuedToken = cookieWasMissing ? issueCsrfCookie(req, res) : cookieToken;

    if (SAFE_METHODS.has(req.method)) return next();

    // Небезопасный метод: токен обязателен и должен совпадать с уже
    // существовавшей (не только что выставленной в этом же запросе) кукой —
    // иначе это тот самый bootstrap-обход, который раньше пропускал первый
    // POST без проверки.
    const headerToken = req.headers['x-csrf-token'];
    if (cookieWasMissing || !headerToken || issuedToken !== headerToken) {
        return res.status(403).json({ success: false, message: 'Запрещено: неверный CSRF-токен' });
    }
    next();
});

// Тело парсится только после проверок источника и CSRF. Глобальный лимит
// остаётся маленьким (100 КБ по умолчанию); key-shares — исключение: до 200
// получателей по 8 КБ (x3dh-init с постквантовой частью весит 2.4–4 КБ).
// Специальный парсер стоит раньше: общий видит уже разобранное тело и
// пропускает запрос.
app.use('/api/keys/key-shares', express.json({ limit: '2mb' }));
app.use(express.json());

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

app.use(sessionMiddleware);

// Анонимная сессия живёт не дольше 4 часов с момента создания. Раньше это
// проверял только /api/auth, а все остальные маршруты продолжали её
// принимать (и сессия могла продлеваться при любом её изменении).
app.use((req, res, next) => {
    if (!isExpiredAnonymousSession(req.session)) return next();
    req.session.regenerate((err) => next(err));
});

// Лимит на /api/ — ДО регистрации маршрутов из lib/: Express применяет
// middleware в порядке регистрации, и раньше /api/keys/* и
// /api/chats/:id/participants шли мимо лимита.
app.use('/api/', apiLimiter);

// E2EE key-server proxy: /api/keys/* → Rust key-server по loopback.
// Регистрируется строго ПОСЛЕ sessionMiddleware — маршрутам нужна сессия.
// Чужие ключи отдаются только при общей комнате — прокси нужна БД.
registerE2eeProxyRoutes(app, { dbGet, dbAll });
// Групповой E2EE: список участников чата + key-shares (тоже нужна сессия).
registerE2eeGroupRoutes(app, { dbGet, dbAll, dbRun, io });

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
    res.sendFile(path.join(UPLOADS_DIR, filename), { lastModified: false, etag: false, cacheControl: false }, (err) => {
        if (err && !res.headersSent) {
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

// Новая сессия с защитой от фиксации (regenerate) — и при входе, и при
// регистрации (раньше при регистрации id сессии не менялся).
function startUserSession(req, fields) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
            if (err) return reject(err);
            Object.assign(req.session, fields);
            resolve();
        });
    });
}

// Proof-of-work (lib/pow.js): решение одноразовое и привязано к цели
// (register / register-anon).
const POW_PURPOSES = new Set(['register', 'register-anon']);
const POW_FAILED_RESPONSE = { success: false, message: 'Не пройдена проверка proof-of-work', powRequired: true };

function checkPow(req, purpose) {
    const solution = req.body && req.body.pow;
    if (!solution || typeof solution !== 'object') return false;
    try {
        return verifySolution(solution, purpose) === true;
    } catch (err) {
        console.error('[PoW] Ошибка проверки решения:', err.message);
        return false;
    }
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
async function insertUserWithBotChat(client, { uniqueCode, username, email, passwordHash, welcomeText }) {
    const userResult = await client.query(
        'INSERT INTO users (unique_code, username, email, password, avatar) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [uniqueCode, username, email, passwordHash, '#667EEA']
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
    return userId;
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

app.post('/api/register', registerLimiter, async (req, res) => {
    const { email, password, confirmPassword } = req.body || {};
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    if (!username || !isNonEmptyString(email) || !isNonEmptyString(password) || typeof confirmPassword !== 'string')
        return res.json({ success: false, message: 'Заполните все поля' });
    if (username.length > 32)
        return res.json({ success: false, message: 'Имя не может быть длиннее 32 символов' });
    if (email.length > 254)
        return res.json({ success: false, message: 'Email слишком длинный' });
    if (password.length > MAX_PASSWORD_LENGTH)
        return res.json({ success: false, message: `Пароль не может быть длиннее ${MAX_PASSWORD_LENGTH} символов` });
    if (password !== confirmPassword)
        return res.json({ success: false, message: 'Пароли не совпадают' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.json({ success: false, message: 'Введите корректный email' });

    try {
        // Политика — до PoW: решение одноразовое, и отказ из-за слабого
        // пароля не должен заставлять решать задачу заново.
        const policyError = await checkPasswordPolicy(password, { username, email });
        if (policyError) return res.json({ success: false, message: policyError });
        // PoW — до любых обращений к users: иначе ответ "такие данные уже
        // заняты" можно было бы получать бесплатно, перебирая email.
        if (!checkPow(req, 'register')) return res.json(POW_FAILED_RESPONSE);

        const existing = await dbGet('SELECT id FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (existing) return res.json({ success: false, message: 'Ошибка регистрации. Проверьте введённые данные.' });

        const uniqueCode = await generateUniqueCodeAsync();
        const passwordHash = await hashPassword(password);
        const userId = await withTransaction(client => insertUserWithBotChat(client, {
            uniqueCode, username, email, passwordHash,
            welcomeText: 'Привет! Я бот-помощник. Чем могу помочь?',
        }));

        await startUserSession(req, { userId, username, uniqueCode, avatar: '#667EEA' });
        res.json({ success: true, message: 'Регистрация успешна!', user: { id: userId, username, uniqueCode, avatar: '#667EEA', readReceipts: true } });
    } catch (error) {
        console.error('Register error:', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

const ANON_WELCOME_TEXT = '🔒 Приватный режим активирован!\n\nВаши данные:\n• Хранятся только в этой сессии\n• Будут удалены при выходе (или автоматически через 4 часа)\n• Не связаны с email или телефоном\n\nДля максимальной анонимности:\n• Используйте Tor Browser\n• Не делитесь личной информацией\n• Включите disappearing messages';

app.post('/api/register/anonymous', registerLimiter, async (req, res) => {
    if (!checkPow(req, 'register-anon')) return res.json(POW_FAILED_RESPONSE);
    try {
        let uniqueCode, username;
        const rustIdentity = await fetchAnonymousIdentity();
        if (rustIdentity) {
            uniqueCode = rustIdentity.unique_code;
            username = rustIdentity.username;
            const existing = await dbGet('SELECT id FROM users WHERE unique_code = $1 OR username = $2', [uniqueCode, username]);
            if (existing) {
                console.warn('[Anon] Rust-generated identity collision, using fallback');
                uniqueCode = await generateUniqueCodeAsync();
                username = await generateAnonymousUsernameAsync();
            }
        } else {
            uniqueCode = await generateUniqueCodeAsync();
            username = await generateAnonymousUsernameAsync();
        }

        const userId = await withTransaction(client => insertUserWithBotChat(client, {
            uniqueCode, username, email: null, passwordHash: null, welcomeText: ANON_WELCOME_TEXT,
        }));

        await startUserSession(req, {
            userId, username, uniqueCode, avatar: '#667EEA',
            isAnonymous: true, createdAt: Date.now(),
        });
        // Короткий срок жизни сессии для анонимных пользователей
        req.session.cookie.maxAge = ANON_SESSION_MAX_AGE_MS;

        // Имя и id анонимного пользователя в лог не пишутся: связка "время
        // создания — id — имя" в логах хостинга как раз и деанонимизирует.

        res.json({
            success: true,
            message: 'Приватный режим активирован!',
            user: {
                id: userId,
                username,
                uniqueCode,
                avatar: '#667EEA',
                isAnonymous: true,
                readReceipts: true,
                sessionExpiresIn: ANON_SESSION_MAX_AGE_MS / 1000 // секунды
            }
        });
    } catch (error) {
        console.error('Anonymous register error:', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

app.post('/api/login', loginLimiter, loginAccountLimiter, async (req, res) => {
    const { email, password } = req.body || {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) return res.json({ success: false, message: 'Введите email и пароль' });
    if (email.length > 254 || password.length > MAX_LOGIN_PASSWORD_LENGTH) return res.json({ success: false, message: 'Неверный email или пароль' });

    try {
        // Добавляем случайную задержку для защиты от timing attacks
        await addRandomDelay(50, 150);

        const user = await dbGet('SELECT id, username, unique_code, avatar, password, read_receipts FROM users WHERE email = $1', [email]);
        // Проверка пароля выполняется независимо от того, найден ли юзер —
        // это убирает разницу во времени ответа между "нет такого email"
        // и "неверный пароль" (см. п.4 аудита).
        const hashToCheck = (user && user.password) ? user.password : DUMMY_PASSWORD_HASH;
        const validPassword = await verifyPassword(password, hashToCheck);

        // Дополнительная случайная задержка
        await addRandomDelay(20, 80);

        if (!user || !user.password || !validPassword) {
            return res.json({ success: false, message: 'Неверный email или пароль' });
        }

        // Хэш старого формата (bcrypt без предхэша обрезал пароль на 72
        // байтах) или с устаревшей стоимостью — перехэшируем, пока пароль
        // известен. Условие на старый хэш: параллельная смена пароля важнее.
        if (needsRehash(user.password)) {
            try {
                await dbRun('UPDATE users SET password = $1 WHERE id = $2 AND password = $3', [await hashPassword(password), user.id, user.password]);
            } catch (rehashError) {
                console.error('[Auth] Не удалось обновить хэш пароля:', rehashError.message);
            }
        }

        await startUserSession(req, {
            userId: user.id, username: user.username, uniqueCode: user.unique_code, avatar: user.avatar || '',
        });
        res.json({
            success: true, message: 'Вход выполнен!',
            user: { id: user.id, username: user.username, uniqueCode: user.unique_code, avatar: user.avatar || '', readReceipts: user.read_receipts },
        });
    } catch (error) {
        console.error('Login error:', error);
        res.json({ success: false, message: 'Ошибка базы данных' });
    }
});

// Завершает сессию после выхода/удаления аккаунта. clearSiteCache —
// Clear-Site-Data: "cache": браузер выбрасывает кэш сайта (страницы,
// вложения), чтобы на общем устройстве не оставалось следов переписки.
function endSession(req, res, { clearSiteCache, message }) {
    req.session.destroy((err) => {
        res.clearCookie('connect.sid');
        // CSRF-куку НЕ удаляем, а выдаём новую: после выхода страница не
        // перезагружается, и следующий POST /api/login без куки получал
        // 403 "неверный CSRF-токен" — войти снова можно было только после F5.
        issueCsrfCookie(req, res);
        if (clearSiteCache) res.set('Clear-Site-Data', '"cache"');
        if (err) console.error('Session destroy error:', err);
        res.json({ success: true, message });
    });
}

app.post('/api/logout', async (req, res) => {
    const isAnonymous = Boolean(req.session?.isAnonymous);
    const userId = req.session?.userId;

    // Для анонимных пользователей удаляем все данные
    if (isAnonymous && userId) {
        try {
            await deleteUserAccount(userId);
        } catch (error) {
            console.error('[Anon] Ошибка удаления данных при выходе:', error.message);
        }
    }

    endSession(req, res, { clearSiteCache: isAnonymous, message: isAnonymous ? 'Данные удалены' : 'Выход выполнен' });
});

// Удаление аккаунта со всеми данными (см. deleteUserAccount). Обычному
// аккаунту нужен пароль — украденной сессии (или забытой открытой вкладки)
// недостаточно; анонимный аккаунт пароля не имеет и удаляется сразу.
app.post('/api/account/delete', passwordLimiter, async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const user = await dbGet('SELECT password FROM users WHERE id = $1', [userId]);
        if (!user) return res.json({ success: false, message: 'Пользователь не найден' });
        if (user.password) {
            const password = req.body?.password;
            if (!isNonEmptyString(password) || password.length > MAX_LOGIN_PASSWORD_LENGTH) {
                return res.json({ success: false, message: 'Введите пароль' });
            }
            if (!(await verifyPassword(password, user.password))) {
                return res.json({ success: false, message: 'Неверный пароль' });
            }
        }
        await deleteUserAccount(userId);
        endSession(req, res, { clearSiteCache: true, message: 'Аккаунт и все данные удалены' });
    } catch (error) {
        console.error('Delete account error:', error);
        res.json({ success: false, message: 'Ошибка удаления аккаунта' });
    }
});

app.get('/api/auth', async (req, res) => {
    if (!req.session.userId) return res.json({ authenticated: false });
    try {
        const row = await dbGet('SELECT avatar, read_receipts FROM users WHERE id = $1', [req.session.userId]);
        if (!row) {
            // Пользователь удалён (например, анонимный после выхода) — сессия больше не нужна
            req.session.destroy(() => {});
            return res.json({ authenticated: false, expired: true });
        }

        const avatar = row.avatar || '';
        req.session.avatar = avatar;

        res.json({
            authenticated: true,
            user: {
                id: req.session.userId,
                username: req.session.username,
                uniqueCode: req.session.uniqueCode,
                avatar,
                isAnonymous: req.session.isAnonymous || false,
                readReceipts: row.read_receipts
            }
        });
    } catch (error) {
        res.json({ authenticated: false });
    }
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
    if (!req.session.userId) return res.json({ success: false });
    try {
        const user = await dbGet('SELECT id, unique_code, username, email, avatar, created_at FROM users WHERE id = $1', [req.session.userId]);
        if (!user) return res.json({ success: false });
        res.json({ success: true, user: { id: user.id, uniqueCode: user.unique_code, username: user.username, avatar: user.avatar || '', email: user.email, createdAt: user.created_at } });
    } catch (error) {
        res.json({ success: false });
    }
});

app.post('/api/user/avatar-color', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const avatarColor = normalizeAvatarColor(req.body && req.body.avatarColor);
    try {
        await dbRun('UPDATE users SET avatar = $1 WHERE id = $2', [avatarColor, req.session.userId]);
        req.session.avatar = avatarColor;
        res.json({ success: true, avatar: avatarColor });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка обновления цвета аватара' });
    }
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
// клиенту не отдаются. Чаты без сообщений — по времени создания (id
// теперь случайные), старые строки без created_at — по id, как раньше.
const CHAT_LIST_SQL = `
    SELECT c.id, c.name, c.avatar, c.online, c.is_bot, c.room_id, r.code AS invite_code,
           lm.id AS last_message_id, lm.text AS last_message, lm.encrypted AS last_message_encrypted,
           lm.message_type AS last_message_type, lm.time AS last_time, lm.created_at AS last_created_at,
           lm.room_id AS lm_room_id, lm.chat_id AS lm_chat_id, lm.user_id AS lm_user_id,
           COALESCE(uc.cnt, 0) AS unread
    FROM chats c
    LEFT JOIN rooms r ON r.id = c.room_id
    LEFT JOIN room_participants rp ON rp.room_id = c.room_id AND rp.user_id = c.user_id
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
    ORDER BY lm.id DESC NULLS LAST, c.created_at DESC NULLS LAST, c.id DESC
`;

app.get('/api/chats', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chats = await dbAll(CHAT_LIST_SQL, [req.session.userId]);
        // Предпросмотр E2EE-сообщения в списке чатов не расшифровываем —
        // это потребовало бы Sender Key каждого отправителя каждого чата
        // ещё до открытия чата. Показываем нейтральную подпись, конверт
        // клиенту не отдаём вовсе (script.js подставляет плейсхолдер).
        res.json({
            success: true,
            chats: chats.map(({ lm_room_id, lm_chat_id, lm_user_id, ...c }) => ({
                ...c,
                unread: Number(c.unread),
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
            chat: { id: chat.id, room_id: chat.room_id, name: chat.name, avatar: chat.avatar, is_bot: chat.is_bot },
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

async function getDefaultExpirySeconds(chatId) {
    const settings = await disappearingMessagesManager.getChatSettings(chatId);
    return (settings && settings.default_message_expiry) || GLOBAL_DEFAULT_EXPIRY_SECONDS || null;
}

// expirySeconds из тела запроса: null — не задан, число — валидный срок;
// некорректное значение бросает RangeError с текстом для пользователя.
function parseRequestedExpiry(value) {
    if (value === undefined || value === null || value === '' || Number(value) === 0) return null;
    return DisappearingMessagesManager.normalizeExpirySeconds(value);
}

const BOT_RESPONSES = ['Интересный вопрос! Расскажите подробнее.', 'Я получил ваше сообщение!', 'Хмм, дайте подумать...', 'Отличное сообщение! Продолжайте.', 'Я бот, но стараюсь быть полезным!', 'Можете уточнить, что именно вас интересует?'];

function scheduleBotReply(chat) {
    const socketRoomKey = getSocketRoomKey(chat.id, null);
    setTimeout(async () => {
        // Весь колбэк в try: раньше ошибка БД в первом же запросе здесь
        // была необработанным reject'ом и роняла процесс.
        try {
            const stillExists = await dbGet('SELECT id FROM chats WHERE id = $1 AND is_bot = 1', [chat.id]);
            if (!stillExists) return;

            const replyText = BOT_RESPONSES[Math.floor(Math.random() * BOT_RESPONSES.length)];
            // Сообщения бота хранятся от имени владельца чата (sent = 0).
            const botMessage = await dbGet(
                `INSERT INTO messages (chat_id, room_id, user_id, text, sent, time, status)
                 VALUES ($1, NULL, $2, $3, 0, $4, 'read')
                 RETURNING id, chat_id, room_id, user_id, sent, time, status, created_at, message_type, encrypted`,
                [chat.id, chat.user_id, writeMessageText(replyText, { room_id: null, chat_id: chat.id, user_id: chat.user_id }), getCurrentTime()]
            );
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
        } catch (e) {
            console.error('Bot error:', e);
        }
    }, 1500);
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

        const expiry = requestedExpiry || await getDefaultExpirySeconds(chat.id);
        if (expiry) await disappearingMessagesManager.setMessageExpiry(inserted.id, expiry, false);

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

        if (chat.is_bot) scheduleBotReply(chat);
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
        res.json({ success: true, chat: { id: chatId, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
    } catch (error) {
        console.error('Create chat error:', error);
        res.json({ success: false, message: 'Ошибка создания чата' });
    }
});

function inviteExpiresAtIso(expiresAt) {
    return expiresAt ? new Date(expiresAt).toISOString() : null;
}

app.get('/api/chats/invite/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, req.session.userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        const room = await dbGet(
            `SELECT r.code, r.code_expires_at FROM rooms r
             JOIN room_participants rp ON rp.room_id = r.id AND rp.user_id = $2
             WHERE r.id = $1`,
            [chat.room_id, req.session.userId]
        );
        if (!room) return res.json({ success: false, message: 'Код не найден' });
        res.json({
            success: true,
            code: room.code,
            expiresAt: inviteExpiresAtIso(room.code_expires_at),
            expired: isInviteExpired(room.code_expires_at),
        });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка получения кода' });
    }
});

// Новый код приглашения (и новый срок) — любой участник комнаты. Старый
// код перестаёт действовать сразу: так закрывается утёкшая ссылка.
app.post('/api/chats/:chatId/invite/rotate', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        const room = await dbGet(
            `UPDATE rooms SET code = $1, code_expires_at = NOW() + $2::integer * INTERVAL '1 second'
             WHERE id = $3 AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $3 AND user_id = $4)
             RETURNING code, code_expires_at`,
            [generateInviteCode(), INVITE_TTL_SECONDS, chat.room_id, userId]
        );
        if (!room) return res.json({ success: false, message: 'Чат не найден' });
        res.json({ success: true, code: room.code, expiresAt: inviteExpiresAtIso(room.code_expires_at) });
    } catch (error) {
        console.error('Rotate invite error:', error);
        res.json({ success: false, message: 'Ошибка обновления кода' });
    }
});

// Состав комнаты изменился: клиенты участников перечитывают список
// участников (E2EE: новичку — Sender Key, после ухода — ротация ключа).
function notifyRoomMembersChanged(roomId) {
    io.to(`room:${roomId}`).emit('roomMembersChanged', { roomId });
}

app.post('/api/chats/join', joinUserLimiter, joinIpLimiter, async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const code = normalizeInviteCode(req.body?.code);
    if (!code) return res.json({ success: false, message: 'Введите код приглашения' });
    // Всё, что не похоже на код нынешнего формата, в БД даже не ищем.
    if (!isValidInviteCode(code)) return res.json({ success: false, message: 'Чат по этому коду не найден' });

    try {
        const room = await dbGet('SELECT id, name, code, code_expires_at FROM rooms WHERE code = $1', [code]);
        if (!room) return res.json({ success: false, message: 'Чат по этому коду не найден' });
        if (isInviteExpired(room.code_expires_at)) return res.json({ success: false, message: 'Код приглашения истёк' });

        const existingChat = await dbGet('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
        if (existingChat) {
            return res.json({ success: true, chat: { ...existingChat, online: 0, is_bot: 0, room_id: room.id, invite_code: room.code } });
        }

        const otherUser = await dbGet('SELECT u.username FROM users u JOIN room_participants rp ON u.id = rp.user_id WHERE rp.room_id = $1 AND u.id != $2 LIMIT 1', [room.id, userId]);
        const chatName = otherUser ? `Чат с ${otherUser.username}` : room.name;
        const avatar = chatName.charAt(0).toUpperCase();

        // Участник + личная строка chats — атомарно. FOR SHARE на комнате:
        // код перепроверяется под блокировкой (его могли сменить или комнату
        // удалить, пока шли запросы выше), и последний участник не может
        // одновременно выйти и снести комнату вместе с новичком.
        // Новичок видит только сообщения после вступления (visible_from_id),
        // они же — граница непрочитанного.
        const chatId = await withTransaction(async (client) => {
            const locked = await client.query(
                'SELECT id FROM rooms WHERE id = $1 AND code = $2 AND code_expires_at > NOW() FOR SHARE',
                [room.id, code]
            );
            if (locked.rows.length === 0) return null;
            await client.query(
                `INSERT INTO room_participants (room_id, user_id, visible_from_id)
                 VALUES ($1, $2, COALESCE((SELECT MAX(id) FROM messages WHERE room_id = $1), 0))
                 ON CONFLICT (room_id, user_id) DO NOTHING`,
                [room.id, userId]
            );
            const chatResult = await client.query(
                `INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_message_id)
                 VALUES ($1, $2, $3, $4, 0, 0,
                         (SELECT visible_from_id FROM room_participants WHERE room_id = $2 AND user_id = $1))
                 RETURNING id`,
                [userId, room.id, chatName, avatar]
            );
            return chatResult.rows[0].id;
        });
        if (!chatId) return res.json({ success: false, message: 'Чат по этому коду не найден' });

        subscribeUserToChat(userId, chatId, room.id);
        notifyRoomMembersChanged(room.id);
        res.json({ success: true, chat: { id: chatId, name: chatName, avatar, online: 0, is_bot: 0, room_id: room.id, invite_code: room.code } });
    } catch (error) {
        console.error('Join chat error:', error);
        res.json({ success: false, message: 'Ошибка входа в чат' });
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
        try {
            await client.query('BEGIN');
            if (chat.room_id) {
                // Блокировка комнаты: два последних участника, выходящих
                // одновременно, иначе оба видели бы "остался ещё один" и
                // комната оставалась бы в БД навсегда.
                await client.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [chat.room_id]);
                await client.query('DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2', [chat.room_id, userId]);
                await client.query('DELETE FROM unread WHERE chat_id = $1', [chat.id]);
                await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
                const remaining = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 LIMIT 1', [chat.room_id]);
                if (remaining.rows.length === 0) {
                    // Последний участник вышел — сносим комнату целиком.
                    const deleted = await client.query('DELETE FROM messages WHERE room_id = $1 RETURNING file_url', [chat.room_id]);
                    fileUrls = deleted.rows.map(r => r.file_url);
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
                await client.query('DELETE FROM unread WHERE chat_id = $1', [chat.id]);
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
            // Метаданные (EXIF/GPS, автор PDF, теги аудио/видео...) снимаются
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
            : fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : fileType.startsWith('audio/') ? 'audio' : 'file';
        const messageText = encrypted ? envelope : (caption || (messageType === 'audio' ? 'Голосовое сообщение' : fileName));

        const inserted = await dbGet(
            `INSERT INTO messages (chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, time, status, encrypted, file_size)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, 'sent', $10, $11)
             RETURNING id, created_at`,
            [chat.id, roomId, userId, writeMessageText(messageText, { room_id: roomId, chat_id: chat.id, user_id: userId }),
                fileUrl, fileName, fileType, messageType, time, encrypted, fileSize]
        );

        const expiry = await getDefaultExpirySeconds(chat.id);
        if (expiry) await disappearingMessagesManager.setMessageExpiry(inserted.id, expiry, false);

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
        const message = await dbGet('SELECT user_id FROM messages WHERE id = $1 AND deleted = 0', [messageId]);
        if (!message || message.user_id !== req.session.userId) {
            return res.json({ success: false, message: 'Сообщение не найдено или нет доступа' });
        }

        await disappearingMessagesManager.setMessageExpiry(messageId, expirySeconds, autoDeleteOnRead === true);

        res.json({ success: true, message: 'Таймер самоуничтожения установлен' });
    } catch (error) {
        console.error('Set expiry error:', error);
        res.json({ success: false, message: 'Ошибка установки таймера' });
    }
});

app.post('/api/chats/:chatId/set-default-expiry', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const expirySeconds = Number(req.body?.expirySeconds);
    if (!Number.isFinite(expirySeconds)) {
        return res.json({ success: false, message: 'Неверные параметры' });
    }

    try {
        // Проверка доступа к чату
        const chat = await getOwnChat(req.params.chatId, req.session.userId);
        if (!chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        await disappearingMessagesManager.setChatDefaultExpiry(chat.id, expirySeconds);

        res.json({ success: true, message: expirySeconds > 0 ? 'Автоудаление сообщений настроено для чата' : 'Автоудаление сообщений выключено' });
    } catch (error) {
        if (error instanceof RangeError) return res.json({ success: false, message: error.message });
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

        const settings = await disappearingMessagesManager.getChatSettings(chat.id);
        res.json({ success: true, settings: settings || {} });
    } catch (error) {
        console.error('Get chat settings error:', error);
        res.json({ success: false, message: 'Ошибка получения настроек' });
    }
});

app.post('/api/change-password', passwordLimiter, async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const { currentPassword, newPassword, confirmPassword } = req.body || {};
    if (!isNonEmptyString(currentPassword) || !isNonEmptyString(newPassword) || typeof confirmPassword !== 'string') return res.json({ success: false, message: 'Заполните все поля' });
    if (newPassword !== confirmPassword) return res.json({ success: false, message: 'Новые пароли не совпадают' });
    if (newPassword.length > MAX_PASSWORD_LENGTH) return res.json({ success: false, message: `Пароль не может быть длиннее ${MAX_PASSWORD_LENGTH} символов` });
    if (currentPassword.length > MAX_LOGIN_PASSWORD_LENGTH) return res.json({ success: false, message: 'Неверный текущий пароль' });

    try {
        const user = await dbGet('SELECT username, email, password FROM users WHERE id = $1', [userId]);
        if (!user) return res.json({ success: false, message: 'Пользователь не найден' });
        if (!user.password) return res.json({ success: false, message: 'У этого аккаунта нет пароля (приватный режим)' });
        const validPassword = await verifyPassword(currentPassword, user.password);
        if (!validPassword) return res.json({ success: false, message: 'Неверный текущий пароль' });
        // Та же политика, что и при регистрации (длина, блок-лист, не
        // содержит имя/почту — поэтому они и выбираются выше).
        const policyError = await checkPasswordPolicy(newPassword, { username: user.username, email: user.email });
        if (policyError) return res.json({ success: false, message: policyError });
        const hashedPassword = await hashPassword(newPassword);

        await dbRun('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);
        // Смена пароля завершает ВСЕ сессии пользователя (другие устройства,
        // в т.ч. того, кто мог узнать старый пароль), а не только текущую.
        await dbRun(`DELETE FROM session WHERE sess->>'userId' = $1`, [String(userId)]);
        io.in('user:' + userId).disconnectSockets(true);

        req.session.destroy((err) => {
            res.clearCookie('connect.sid');
            if (err) console.error('Session destroy error on password change:', err);
            res.json({ success: true, message: 'Пароль успешно изменён. Войдите заново.' });
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.json({ success: false, message: 'Ошибка изменения пароля' });
    }
});

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ success: false, message: 'Файл слишком большой (макс. 50 МБ)' });
        }
        return res.status(400).json({ success: false, message: `Ошибка загрузки: ${err.message}` });
    }
    if (err.message === 'Неподдерживаемый тип файла') {
        return res.status(400).json({ success: false, message: 'Разрешены только фото, видео, аудио, PDF и TXT' });
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

// Полное удаление пользователя (анонимного при выходе/по сроку или любого
// по POST /api/account/delete): его сообщения (и их файлы), реакции, E2EE
// key-shares, участие в комнатах, опустевшие комнаты со всей историей,
// chats (chat_settings — каскадом), unread, сама строка users;
// message_expiry и реакции на его сообщения уходят каскадом. Одной
// транзакцией — раньше это была серия отдельных DELETE, и первая же ошибка
// FK (например, из e2ee_key_shares, который ссылается на users без каскада)
// оставляла пользователя в БД навсегда. После COMMIT — файлы с диска,
// сессии на всех устройствах, сокеты, ключи в key-server и уведомление
// оставшимся участникам комнат.
async function deleteUserAccount(userId) {
    let fileUrls = [];
    let survivingRoomIds = [];
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
        await client.query('DELETE FROM unread WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM chats WHERE user_id = $1', [userId]);

        if (roomIds.length > 0) {
            const orphaned = await client.query(
                `DELETE FROM messages m WHERE m.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = m.room_id)
                 RETURNING file_url`,
                [roomIds]
            );
            fileUrls.push(...orphaned.rows.map(r => r.file_url));
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
    io.in('user:' + userId).disconnectSockets(true);
    for (const roomId of survivingRoomIds) notifyRoomMembersChanged(roomId);
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

// Анонимные аккаунты, чья сессия уже истекла (вкладку просто закрыли, не
// нажав "Выйти"), раньше оставались в БД навсегда — вопреки обещанию
// "данные удалятся". Сессия анонима живёт максимум 4 часа (см.
// isExpiredAnonymousSession), так что через 5 часов после создания его
// можно удалять; живую сессию дополнительно проверяем по таблице session.
async function purgeExpiredAnonymousUsers() {
    try {
        const rows = await dbAll(`
            SELECT u.id FROM users u
            WHERE u.email IS NULL AND u.password IS NULL
              AND u.created_at < NOW() - INTERVAL '5 hours'
              AND NOT EXISTS (
                  SELECT 1 FROM session s
                  WHERE s.expire > NOW() AND s.sess->>'userId' = u.id::text
              )
            ORDER BY u.created_at
            LIMIT 200
        `);
        // В лог — только счётчики, без id анонимных аккаунтов.
        let failed = 0;
        for (const row of rows) {
            try {
                await deleteUserAccount(row.id);
            } catch (err) {
                failed++;
                console.error('[Anon] Не удалось удалить просроченный аккаунт:', err.message);
            }
        }
        if (rows.length > 0) console.log(`[Anon] Удалено просроченных анонимных аккаунтов: ${rows.length - failed}`);
    } catch (error) {
        // 42P01 — таблица session ещё не создана (ни одного входа с запуска БД)
        if (error.code !== '42P01') console.error('[Anon] Purge error:', error.message);
    }
}

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

    // Фоновые задачи: брошенные временные файлы обработки вложений,
    // просроченные анонимные аккаунты и (однократно) строки, оставшиеся от
    // soft-delete старой схемы.
    setInterval(() => cleanupStaleTempFiles(UPLOADS_DIR, 60 * 60 * 1000), 60 * 60 * 1000);
    setTimeout(purgeExpiredAnonymousUsers, 60 * 1000);
    setInterval(purgeExpiredAnonymousUsers, 30 * 60 * 1000);
    setImmediate(purgeLegacySoftDeletedMessages);

    // Только то, что действительно включено в этом запуске.
    console.log('Функции безопасности:');
    console.log('  ✓ CSRF-токен и проверка Origin (HTTP и WebSocket)');
    console.log('  ✓ Rate limiting (IP, аккаунт) и proof-of-work при регистрации');
    console.log('  ✓ Очистка метаданных и обезличенные имена вложений');
    console.log('  ✓ Исчезающие сообщения, физическое удаление');
    console.log('  ✓ Шифрование текста сообщений в БД (AES-256-GCM с привязкой к комнате)');
    console.log('  ✓ CSP с nonce, заголовки приватности' + (IS_PRODUCTION ? ', HSTS по https' : ''));
    console.log('  ✓ Выравнивание времени ответа при входе');
    if (process.env.INTERNAL_KEY_SERVER_SECRET) console.log('  ✓ E2EE key server (прокси /api/keys)');
    if (ONION_ADDRESS && ONION_PORT) console.log(`  ✓ Onion-сервис: http://${ONION_ADDRESS} (внутренний порт ${ONION_PORT})`);
    console.log(`\n${'='.repeat(60)}\n`);
}

// Порт открывается только ПОСЛЕ миграций. Раньше listen() вызывался сразу,
// параллельно с initDatabase(): первые запросы попадали на недомигрированную
// БД и висели на блокировках ALTER TABLE.
initDatabase()
    .then(() => {
        server.listen(PORT, HOST, onServerListening);
        // Отдельный внутренний порт для tor-service: соединения с него
        // помечаются как onion (lib/tor-support.js). Наружу его не публиковать.
        listenOnionPort(server, HOST, () => console.log(`[Tor] Onion-порт ${ONION_PORT} слушается`));
    })
    .catch((err) => {
        console.error('Ошибка инициализации БД:', err);
        process.exit(1);
    });
