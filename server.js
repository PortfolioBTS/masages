require('dotenv').config();

// 1. IMPORTS
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
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
const { encryptText, decryptText } = require('./lib/message-crypto');
const {
    addRandomDelay,
    sanitizeText,
    getPrivacyHeaders,
    generateSecureToken
} = require('./lib/privacy');

// Импорт E2EE прокси (маршруты регистрируются после sessionMiddleware —
// см. вызов registerE2eeProxyRoutes ниже)
const { registerE2eeProxyRoutes, deleteKeysForUser } = require('./lib/e2ee-proxy');
// Групповой E2EE: участники чата + попарная доставка Sender Key
// (key-shares). Тоже регистрируется после sessionMiddleware.
const { initE2eeGroupsSchema, registerE2eeGroupRoutes } = require('./lib/e2ee-groups');

// Импорт Tor support
const {
    checkTorConnection,
    getTorHiddenServiceConfig,
    torConnectionLogger,
    ENABLE_TOR_ROUTING
} = require('./lib/tor-support');

// === RUST ANON SERVICE INTEGRATION ===
const ANON_SERVICE_URL = process.env.ANON_SERVICE_URL || 'http://127.0.0.1:8080';

async function fetchAnonymousIdentity() {
    try {
        const res = await fetch(`${ANON_SERVICE_URL}/generate`, {
            method: 'POST',
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

const ALLOWED_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/webm', 'video/quicktime',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
    'application/pdf', 'text/plain',
];

// Жёсткий маппинг mimetype -> расширение на диске. Расширение НИКОГДА не
// берётся из file.originalname (см. п.2 аудита): имя, присланное клиентом —
// это просто строка, и path.extname() от неё может вернуть что угодно вплоть
// до '.png"><svg onload=alert(1)>', что затем всплывает в file_url и рискует
// быть вставлено как HTML. Здесь расширение выбирается только из этого
// фиксированного списка по уже провалидированному через ALLOWED_MIME_TYPES
// mimetype, так что итоговое имя файла всегда полностью предсказуемо.
const MIME_EXTENSIONS = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'video/mp4': '.mp4',
    'video/webm': '.webm',
    'video/quicktime': '.mov',
    'audio/mpeg': '.mp3',
    'audio/ogg': '.ogg',
    'audio/wav': '.wav',
    'audio/webm': '.weba',
    'application/pdf': '.pdf',
    'text/plain': '.txt',
};

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

const UPLOADS_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

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
            // file.originalname — см. комментарий у MIME_EXTENSIONS выше.
            const ext = MIME_EXTENSIONS[file.mimetype] || '';
            const safeName = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${ext}`;
            if (!SAFE_FILENAME_RE.test(safeName)) {
                return cb(new Error('Не удалось сформировать безопасное имя файла'));
            }
            cb(null, safeName);
        }
    }),
    limits: { fileSize: 50 * 1024 * 1024, files: 1, fields: 10 },
    // Имя файла в multipart — UTF-8 (по умолчанию busboy декодировал его как
    // latin1, и русские имена файлов превращались в "Ð¤Ð°Ð¹Ð»").
    defParamCharset: 'utf8',
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (BLOCKED_EXTENSIONS.has(ext)) {
            return cb(new Error('Неподдерживаемый тип файла'), false);
        }
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
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

app.use((req, res, next) => {
    // req.ip уже учитывает 1 доверенный хоп (trust proxy = 1), то есть это IP,
    // который реально подключился к Railway — Cloudflare edge, если трафик шёл
    // через CF, либо настоящий IP клиента, если Railway-домен открыт напрямую.
    req.realIp = resolveRealIp(req.headers, req.ip);
    next();
});

const rateLimitKeyGenerator = (req) => ipKeyGenerator(req.realIp || req.ip);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много попыток входа. Попробуйте позже.' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много регистраций. Попробуйте позже.' }
});

const passwordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много попыток смены пароля. Попробуйте позже.' }
});

// 300 запросов за 15 минут (~1 в 3 секунды) активный пользователь чата
// выбирал за несколько минут — особенно когда клиент перезапрашивал
// список чатов на каждое входящее сообщение — после чего всё приложение
// "висло" с ошибкой на 15 минут.
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много запросов. Попробуйте позже.' }
});

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

const io = new Server(server);
const ipConnectionCount = new Map();
const MAX_SOCKETS_PER_IP = 20;

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

const sslConfig = (() => {
    if (process.env.NODE_ENV !== 'production') return false;
    if (process.env.DB_CA_CERT) {
        console.log('[SSL] production: rejectUnauthorized=true, CA закреплён через DB_CA_CERT');
        return { ca: process.env.DB_CA_CERT, rejectUnauthorized: true };
    }
    console.warn('[SSL] production: DB_CA_CERT не задан — используется rejectUnauthorized=false ' +
        '(осознанный компромисс под Railway internal network). Чтобы включить полную проверку ' +
        'сертификата, запустите сервер один раз с DUMP_CA=true, скопируйте цепочку сертификатов ' +
        'в переменную DB_CA_CERT и перезапустите.');
    return { rejectUnauthorized: false };
})();

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
        SELECT table_name, column_name, is_nullable
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name IN ('users', 'chats', 'messages')
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
    // Проверка "участник ли комнаты" выполняется на каждый файл, реакцию и
    // joinChat — раньше по room_participants вообще не было индексов.
    await pool.query('CREATE INDEX IF NOT EXISTS idx_room_participants_room_user ON room_participants(room_id, user_id)');
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

    console.log('База данных инициализирована');
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

async function generateUniqueCodeAsync() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let attempts = 0; attempts < 100; attempts++) {
        const bytes = crypto.randomBytes(8);
        const code = Array.from(bytes).map(b => chars[b % chars.length]).join('');
        const row = await dbGet('SELECT id FROM users WHERE unique_code = $1', [code]);
        if (!row) return code;
    }
    throw new Error('Could not generate unique code');
}

async function generateAnonymousUsernameAsync() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (let attempts = 0; attempts < 100; attempts++) {
        const bytes = crypto.randomBytes(4);
        const suffix = Array.from(bytes).map(b => chars[b % chars.length]).join('');
        const username = `Гость-${suffix}`;
        const row = await dbGet('SELECT id FROM users WHERE username = $1', [username]);
        if (!row) return username;
    }
    throw new Error('Could not generate anonymous username');
}

function generateInviteCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.randomBytes(6);
    return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

async function generateInviteCodeAsync() {
    for (let attempts = 0; attempts < 100; attempts++) {
        const code = generateInviteCode();
        const row = await dbGet('SELECT id FROM rooms WHERE code = $1', [code]);
        if (!row) return code;
    }
    throw new Error('Could not generate invite code');
}

// Фиктивный bcrypt-хэш без известного пароля. Используется в /api/login, чтобы
// bcrypt.compare выполнялся ВСЕГДА — и когда юзер найден, и когда нет — с
// одинаковой стоимостью (~100мс), иначе разница во времени ответа позволяет
// перебором узнавать зарегистрированные email.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12);

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
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    }
});

function isExpiredAnonymousSession(sess) {
    return Boolean(sess && sess.isAnonymous && sess.createdAt && Date.now() - sess.createdAt > ANON_SESSION_MAX_AGE_MS);
}

// Socket.io: сессия -> авторизация -> лимит подключений с одного IP.
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
    const ip = getClientIp(socket.handshake);
    if ((ipConnectionCount.get(ip) || 0) >= MAX_SOCKETS_PER_IP) {
        return next(new Error('Слишком много подключений с вашего IP'));
    }
    socket.data.clientIp = ip;
    next();
});

io.on('connection', async (socket) => {
    const userId = socket.request.session.userId;

    // Счётчик растёт только для реально установленных соединений. Раньше он
    // увеличивался ещё в middleware, а единственное место уменьшения —
    // 'disconnect' — для отклонённого рукопожатия не наступает: IP мог
    // навсегда упереться в лимит.
    const ip = socket.data.clientIp;
    ipConnectionCount.set(ip, (ipConnectionCount.get(ip) || 0) + 1);
    socket.on('disconnect', () => {
        const current = (ipConnectionCount.get(ip) || 1) - 1;
        if (current <= 0) ipConnectionCount.delete(ip);
        else ipConnectionCount.set(ip, current);
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

app.use(express.json());
app.use(cookieParser());

// Tor connection logger
app.use(torConnectionLogger);

function issueCsrfCookie(res) {
    const token = crypto.randomBytes(32).toString('hex');
    res.cookie('csrf_token', token, {
        httpOnly: false,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        secure: process.env.NODE_ENV === 'production',
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
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    const cookieToken = req.cookies['csrf_token'];
    const cookieWasMissing = !cookieToken;
    const issuedToken = cookieWasMissing ? issueCsrfCookie(res) : cookieToken;

    if (safeMethods.includes(req.method)) return next();

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

app.use((req, res, next) => {
    // Усиленные заголовки приватности
    const privacyHeaders = getPrivacyHeaders();
    Object.entries(privacyHeaders).forEach(([key, value]) => {
        res.set(key, value);
    });

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
    res.set('X-Robots-Tag', 'noindex, nofollow');
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.cspNonce = nonce;
    // base-uri и object-src не наследуются из default-src, поэтому заданы
    // явно (п.8 аудита): без base-uri инъекция тега <base> (если когда-либо
    // станет достижима) не блокируется текущей политикой; object-src явно
    // запрещён, хотя и так по умолчанию блокируется отсутствием в списке.
    res.set('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'`);
    res.set('X-Frame-Options', 'DENY');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

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
registerE2eeProxyRoutes(app);
// Групповой E2EE: список участников чата + key-shares (тоже нужна сессия).
registerE2eeGroupRoutes(app, { dbGet, dbAll, dbRun, io });

app.get('/uploads/:filename', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    const filename = path.basename(req.params.filename);
    if (!SAFE_FILENAME_RE.test(filename)) return res.status(404).json({ success: false, message: 'Файл не найден' });
    const allowed = await userCanAccessFile(req.session.userId, filename);
    if (!allowed) return res.status(403).json({ success: false, message: 'Доступ запрещён' });
    setRevalidateCacheHeaders(res, true);
    res.sendFile(path.join(UPLOADS_DIR, filename), (err) => {
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

app.post('/api/register', registerLimiter, async (req, res) => {
    const { email, password, confirmPassword } = req.body || {};
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    if (!username || !isNonEmptyString(email) || !isNonEmptyString(password) || typeof confirmPassword !== 'string')
        return res.json({ success: false, message: 'Заполните все поля' });
    if (username.length > 32)
        return res.json({ success: false, message: 'Имя не может быть длиннее 32 символов' });
    if (email.length > 254)
        return res.json({ success: false, message: 'Email слишком длинный' });
    if (password.length > 128)
        return res.json({ success: false, message: 'Пароль не может быть длиннее 128 символов' });
    if (password !== confirmPassword)
        return res.json({ success: false, message: 'Пароли не совпадают' });
    if (password.length < 8)
        return res.json({ success: false, message: 'Пароль должен быть не менее 8 символов' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.json({ success: false, message: 'Введите корректный email' });

    try {
        const existing = await dbGet('SELECT id FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (existing) return res.json({ success: false, message: 'Ошибка регистрации. Проверьте введённые данные.' });

        const uniqueCode = await generateUniqueCodeAsync();
        const hashedPassword = await bcrypt.hash(password, 12);

        const client = await pool.connect();
        let userId;
        try {
            await client.query('BEGIN');
            const userResult = await client.query(
                'INSERT INTO users (unique_code, username, email, password, avatar) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                [uniqueCode, username, email, hashedPassword, '#667EEA']
            );
            userId = userResult.rows[0].id;

            const botResult = await client.query(
                'INSERT INTO chats (user_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                [userId, 'Бот Помощник', 'Б', 1, 1]
            );
            const botChatId = botResult.rows[0].id;
            await client.query(
                'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6)',
                [botChatId, userId, encryptText('Привет! Я бот-помощник. Чем могу помочь?'), 0, getCurrentTime(), 'read']
            );
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }

        await startUserSession(req, { userId, username, uniqueCode, avatar: '#667EEA' });
        res.json({ success: true, message: 'Регистрация успешна!', user: { id: userId, username, uniqueCode, avatar: '#667EEA' } });
    } catch (error) {
        console.error('Register error:', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

app.post('/api/register/anonymous', registerLimiter, async (req, res) => {
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

        // Генерация уникального session fingerprint для анонимного пользователя
        const sessionFingerprint = generateSecureToken(32);

        const client = await pool.connect();
        let userId;
        try {
            await client.query('BEGIN');
            const userResult = await client.query(
                'INSERT INTO users (unique_code, username, email, password, avatar) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                [uniqueCode, username, null, null, '#667EEA']
            );
            userId = userResult.rows[0].id;

            const botResult = await client.query(
                'INSERT INTO chats (user_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                [userId, 'Бот Помощник', 'Б', 1, 1]
            );
            const botChatId = botResult.rows[0].id;
            await client.query(
                'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6)',
                [botChatId, userId, encryptText('🔒 Приватный режим активирован!\n\nВаши данные:\n• Хранятся только в этой сессии\n• Будут удалены при выходе (или автоматически через 4 часа)\n• Не связаны с email или телефоном\n\nДля максимальной анонимности:\n• Используйте Tor Browser\n• Не делитесь личной информацией\n• Включите disappearing messages'), 0, getCurrentTime(), 'read']
            );
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }

        await startUserSession(req, {
            userId, username, uniqueCode, avatar: '#667EEA',
            isAnonymous: true, sessionFingerprint, createdAt: Date.now(),
        });
        // Короткий срок жизни сессии для анонимных пользователей
        req.session.cookie.maxAge = ANON_SESSION_MAX_AGE_MS;

        console.log(`[Anon] New anonymous user created: ${username} (ID: ${userId})`);

        res.json({
            success: true,
            message: 'Приватный режим активирован!',
            user: {
                id: userId,
                username,
                uniqueCode,
                avatar: '#667EEA',
                isAnonymous: true,
                sessionExpiresIn: ANON_SESSION_MAX_AGE_MS / 1000 // секунды
            }
        });
    } catch (error) {
        console.error('Anonymous register error:', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body || {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) return res.json({ success: false, message: 'Введите email и пароль' });
    if (email.length > 254 || password.length > 128) return res.json({ success: false, message: 'Неверный email или пароль' });

    try {
        // Добавляем случайную задержку для защиты от timing attacks
        await addRandomDelay(50, 150);

        const user = await dbGet('SELECT id, username, unique_code, avatar, password FROM users WHERE email = $1', [email]);
        // bcrypt.compare выполняется независимо от того, найден ли юзер —
        // это убирает разницу во времени ответа между "нет такого email"
        // и "неверный пароль" (см. п.4 аудита).
        const hashToCheck = (user && user.password) ? user.password : DUMMY_PASSWORD_HASH;
        const validPassword = await bcrypt.compare(password, hashToCheck);

        // Дополнительная случайная задержка
        await addRandomDelay(20, 80);

        if (!user || !user.password || !validPassword) {
            return res.json({ success: false, message: 'Неверный email или пароль' });
        }

        await startUserSession(req, {
            userId: user.id, username: user.username, uniqueCode: user.unique_code, avatar: user.avatar || '',
        });
        res.json({ success: true, message: 'Вход выполнен!', user: { id: user.id, username: user.username, uniqueCode: user.unique_code, avatar: user.avatar || '' } });
    } catch (error) {
        console.error('Login error:', error);
        res.json({ success: false, message: 'Ошибка базы данных' });
    }
});

app.post('/api/logout', async (req, res) => {
    const isAnonymous = req.session?.isAnonymous;
    const userId = req.session?.userId;

    // Для анонимных пользователей удаляем все данные
    if (isAnonymous && userId) {
        try {
            await deleteAnonymousUser(userId);
        } catch (error) {
            console.error('[Anon] Cleanup error:', error);
        }
    }

    req.session.destroy((err) => {
        res.clearCookie('connect.sid');
        // CSRF-куку НЕ удаляем, а выдаём новую: после выхода страница не
        // перезагружается, и следующий POST /api/login без куки получал
        // 403 "неверный CSRF-токен" — войти снова можно было только после F5.
        issueCsrfCookie(res);
        if (err) console.error('Logout session destroy error:', err);
        res.json({ success: true, message: isAnonymous ? 'Данные удалены' : 'Выход выполнен' });
    });
});

app.get('/api/auth', async (req, res) => {
    if (!req.session.userId) return res.json({ authenticated: false });
    try {
        const row = await dbGet('SELECT avatar FROM users WHERE id = $1', [req.session.userId]);
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
                isAnonymous: req.session.isAnonymous || false
            }
        });
    } catch (error) {
        res.json({ authenticated: false });
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

// Личная строка chats вызывающего (chats.id — у каждого участника своя).
async function getOwnChat(chatId, userId) {
    const id = toPositiveInt(chatId);
    if (!id) return null;
    return dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [id, userId]);
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
const CHAT_LIST_SQL = `
    SELECT c.id, c.name, c.avatar, c.online, c.is_bot, c.room_id, r.code AS invite_code,
           lm.id AS last_message_id, lm.text AS last_message, lm.encrypted AS last_message_encrypted,
           lm.message_type AS last_message_type, lm.time AS last_time, lm.created_at AS last_created_at,
           COALESCE(uc.cnt, 0) AS unread
    FROM chats c
    LEFT JOIN rooms r ON r.id = c.room_id
    LEFT JOIN LATERAL (
        SELECT CASE WHEN c.room_id IS NOT NULL
            THEN (SELECT MAX(x.id) FROM messages x WHERE x.room_id = c.room_id AND x.deleted = 0)
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
    ORDER BY lm.id DESC NULLS LAST, c.id DESC
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
            chats: chats.map(c => ({
                ...c,
                unread: Number(c.unread),
                last_message: c.last_message_encrypted ? null : decryptText(c.last_message),
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
async function markChatRead(chat, userId, upToId) {
    const previous = Number(chat.last_read_message_id) || 0;
    if (!upToId || upToId <= previous) return;
    const moved = await dbGet(
        'UPDATE chats SET last_read_message_id = $1 WHERE id = $2 AND last_read_message_id < $1 RETURNING id',
        [upToId, chat.id]
    );
    if (!moved) return; // уже отмечено (например, из другой вкладки)
    chat.last_read_message_id = upToId;

    // Только сообщения после предыдущего маркера — раньше при КАЖДОМ
    // открытии чата UPDATE переписывал статус всех сообщений чата заново.
    const scope = chatScope(chat);
    const readRows = await dbAll(
        `UPDATE messages SET status = 'read'
         WHERE ${scope.column} = $1 AND id > $2 AND id <= $3
           AND user_id <> $4 AND deleted = 0 AND status <> 'read'
         RETURNING id`,
        [scope.value, previous, upToId, userId]
    );
    if (readRows.length > 0) {
        io.to(getSocketRoomKey(chat.id, chat.room_id)).emit('messagesRead', {
            chat_id: chat.id, room_id: chat.room_id, up_to_id: upToId, reader_id: userId,
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
        const params = [scope.value, limit + 1];
        if (before) params.push(before);

        // Цитата ответа берётся только из ТОГО ЖЕ чата и только если она не
        // удалена. Раньше reply_to_id не проверялся при отправке, и
        // подставив чужой id, можно было получить расшифрованный текст
        // сообщения из любого чужого чата; удалённые сообщения тоже
        // продолжали "светиться" в цитатах.
        // Сначала id страницы (index-only scan по idx_messages_*_live), потом
        // сами строки по первичному ключу.
        const rows = await dbAll(`
            WITH page AS MATERIALIZED (
                SELECT id FROM messages
                WHERE ${scope.column} = $1 AND deleted = 0 ${before ? 'AND id < $3' : ''}
                ORDER BY id DESC
                LIMIT $2
            )
            SELECT m.id, m.chat_id, m.room_id, m.user_id, m.text, m.file_url, m.file_name, m.file_type,
                   m.message_type, m.sent, m.time, m.status, m.edited_at, m.deleted, m.encrypted, m.created_at,
                   m.reply_to_id AS reply_target_id,
                   u.username AS sender_username, u.avatar AS sender_avatar,
                   rt.id AS reply_to_id, rt.text AS reply_to_text, rt.user_id AS reply_to_sender_id,
                   rt.encrypted AS reply_to_encrypted,
                   ru.username AS reply_to_sender_username, ru.avatar AS reply_to_sender_avatar
            FROM page
            JOIN messages m ON m.id = page.id
            JOIN users u ON u.id = m.user_id
            LEFT JOIN messages rt ON rt.id = m.reply_to_id AND rt.${scope.column} = m.${scope.column} AND rt.deleted = 0
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

        const messages = rows.map(({ reply_target_id, reply_to_text, reply_to_sender_id, reply_to_encrypted,
            reply_to_sender_username, reply_to_sender_avatar, ...m }) => ({
            ...m,
            text: decryptText(m.text),
            reactions: reactionsMap[m.id] || [],
            reply_to: m.reply_to_id ? {
                id: m.reply_to_id, text: decryptText(reply_to_text),
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
    // Не даём отметить прочитанным больше, чем реально есть в этом чате.
    const scope = chatScope(chat);
    const latest = await dbGet(
        `SELECT MAX(id) AS id FROM messages WHERE ${scope.column} = $1 AND deleted = 0 AND id <= $2`,
        [scope.value, upToId]
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
            const botMessage = await dbGet(
                `INSERT INTO messages (chat_id, room_id, user_id, text, sent, time, status)
                 VALUES ($1, NULL, $2, $3, 0, $4, 'read')
                 RETURNING id, chat_id, room_id, user_id, sent, time, status, created_at, message_type, encrypted`,
                [chat.id, chat.user_id, encryptText(replyText), getCurrentTime()]
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
    const maxLen = encrypted ? 12000 : 4000;
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

        // Отвечать можно только на неудалённое сообщение из ЭТОГО же чата.
        const scope = chatScope(chat);
        let replyTo = null;
        const replyTargetId = toPositiveInt(replyToId);
        if (replyTargetId) {
            const target = await dbGet(
                `SELECT m.id, m.text, m.user_id, m.encrypted, u.username, u.avatar
                 FROM messages m JOIN users u ON u.id = m.user_id
                 WHERE m.id = $1 AND m.${scope.column} = $2 AND m.deleted = 0`,
                [replyTargetId, scope.value]
            );
            if (target) {
                replyTo = {
                    id: target.id, text: decryptText(target.text), sender_id: target.user_id,
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
            [chat.id, roomId, userId, encryptText(safeText), time, replyTo ? replyTo.id : null, encrypted]
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
        const roomCode = await generateInviteCodeAsync();
        const client = await pool.connect();
        let roomId, chatId;
        try {
            await client.query('BEGIN');
            const roomResult = await client.query('INSERT INTO rooms (name, code) VALUES ($1, $2) RETURNING id', [name, roomCode]);
            roomId = roomResult.rows[0].id;
            await client.query('INSERT INTO room_participants (room_id, user_id) VALUES ($1, $2)', [roomId, userId]);
            const chatResult = await client.query(
                'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [userId, roomId, name, avatar, 0, 0]
            );
            chatId = chatResult.rows[0].id;
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }
        subscribeUserToChat(userId, chatId, roomId);
        res.json({ success: true, chat: { id: chatId, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
    } catch (error) {
        console.error('Create chat error:', error);
        res.json({ success: false, message: 'Ошибка создания чата' });
    }
});

app.get('/api/chats/invite/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chat = await getOwnChat(req.params.chatId, req.session.userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        const room = await dbGet('SELECT code FROM rooms WHERE id = $1', [chat.room_id]);
        if (!room) return res.json({ success: false, message: 'Код не найден' });
        res.json({ success: true, code: room.code });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка получения кода' });
    }
});

app.post('/api/chats/join', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.json({ success: false, message: 'Не авторизован' });
    const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
    if (!code || code.length > 32) return res.json({ success: false, message: 'Введите код приглашения' });

    try {
        const room = await dbGet('SELECT * FROM rooms WHERE code = $1', [code]);
        if (!room) return res.json({ success: false, message: 'Чат по этому коду не найден' });

        const existingChat = await dbGet('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
        if (existingChat) {
            return res.json({ success: true, chat: { ...existingChat, online: 0, is_bot: 0, room_id: room.id, invite_code: room.code } });
        }

        const otherUser = await dbGet('SELECT u.username FROM users u JOIN room_participants rp ON u.id = rp.user_id WHERE rp.room_id = $1 AND u.id != $2 LIMIT 1', [room.id, userId]);
        const chatName = otherUser ? `Чат с ${otherUser.username}` : room.name;
        const avatar = chatName.charAt(0).toUpperCase();

        // Участник + личная строка chats — атомарно. История комнаты до
        // момента вступления не считается непрочитанной.
        const client = await pool.connect();
        let chatId;
        try {
            await client.query('BEGIN');
            const already = await client.query('SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2 FOR UPDATE', [room.id, userId]);
            if (already.rows.length === 0) {
                await client.query('INSERT INTO room_participants (room_id, user_id) VALUES ($1, $2)', [room.id, userId]);
            }
            const chatResult = await client.query(
                `INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_message_id)
                 VALUES ($1, $2, $3, $4, 0, 0, COALESCE((SELECT MAX(id) FROM messages WHERE room_id = $2), 0))
                 RETURNING id`,
                [userId, room.id, chatName, avatar]
            );
            chatId = chatResult.rows[0].id;
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }
        subscribeUserToChat(userId, chatId, room.id);
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
        const maxLen = message.encrypted ? 12000 : 4000;
        if (text.length > maxLen) return res.json({ success: false, message: `Сообщение не может быть длиннее ${maxLen} символов` });

        // Та же очистка, что и при отправке (раньше правкой её можно было обойти).
        const newText = message.encrypted ? text.trim() : sanitizeText(text.trim());
        if (!newText) return res.json({ success: false, message: 'Текст не может быть пустым' });
        const editedAt = new Date().toISOString();
        await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [encryptText(newText), editedAt, messageId]);

        // Раньше правки не рассылались по сокету — у остальных участников
        // комнаты изменение не появлялось без перезагрузки (см. "Мелочи").
        io.to(getSocketRoomKey(message.chat_id, message.room_id)).emit('messageEdited', {
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
        // Тот же путь, что и у disappearing messages: текст затирается,
        // вложение удаляется с диска (раньше файл удалённого сообщения
        // оставался доступен по прямой ссылке), участникам уходит
        // 'messageDeleted'.
        await disappearingMessagesManager.deleteMessages([messageId]);
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

app.post('/api/messages/file', upload.single('file'), async (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        cleanupUploadedFile(req.file);
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    const { chatId, text } = req.body || {};
    const file = req.file;

    if (!file) return res.status(400).json({ success: false, message: 'Файл не выбран' });
    const caption = typeof text === 'string' ? sanitizeText(text.trim()) : '';
    if (!toPositiveInt(chatId) || caption.length > 4000) {
        cleanupUploadedFile(file);
        return res.status(400).json({ success: false, message: !toPositiveInt(chatId) ? 'Не указан чат' : 'Подпись слишком длинная' });
    }

    // Сначала проверка чата (дёшево), потом обработка файла (дорого).
    const chat = await getOwnChat(chatId, userId).catch((err) => {
        cleanupUploadedFile(file);
        throw err;
    });
    if (!chat) {
        cleanupUploadedFile(file);
        return res.status(404).json({ success: false, message: 'Чат не найден' });
    }

    const uploadedFilePath = path.join(UPLOADS_DIR, file.filename);
    try {
        const head = await readFileHead(uploadedFilePath, 12);
        if (!checkMagicBytes(head, file.mimetype)) {
            cleanupUploadedFile(file);
            return res.status(400).json({ success: false, message: 'Содержимое файла не соответствует его типу' });
        }

        // Удаление метаданных из файла для защиты приватности
        if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
            await stripMetadataFromFile(uploadedFilePath, file.mimetype);
        }
    } catch (magicErr) {
        // Раньше при исключении здесь проверка молча пропускалась и файл
        // проходил дальше — теоретическая лазейка мимо проверки типа файла.
        // Теперь любая ошибка проверки = отказ (fail closed), а не fail open.
        console.error('Magic bytes check error:', magicErr);
        cleanupUploadedFile(file);
        return res.status(400).json({ success: false, message: 'Не удалось проверить содержимое файла' });
    }

    try {
        const time = getCurrentTime();
        const roomId = chat.room_id || null;
        const fileUrl = `/uploads/${file.filename}`;
        const fileType = file.mimetype;
        const sanitizedFileName = path.basename(file.originalname || '').slice(0, 200).replace(/[<>&"']/g, '') || 'file';

        const messageType = fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : fileType.startsWith('audio/') ? 'audio' : 'file';
        const messageText = caption || (messageType === 'audio' ? 'Голосовое сообщение' : sanitizedFileName);

        const inserted = await dbGet(
            `INSERT INTO messages (chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, time, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, 'sent')
             RETURNING id, created_at`,
            [chat.id, roomId, userId, encryptText(messageText), fileUrl, sanitizedFileName, fileType, messageType, time]
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
            text: messageText, file_url: fileUrl, file_name: sanitizedFileName,
            file_type: fileType, message_type: messageType, sent: 1, time, status: 'sent',
            edited_at: null, deleted: 0, encrypted: false, created_at: inserted.created_at,
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
    const participant = await dbGet(
        'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2',
        [roomId, userId]
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
        const chats = await dbAll(
            'SELECT id, name, avatar, room_id, online, is_bot FROM chats WHERE user_id = $1 AND name ILIKE $2 ORDER BY id DESC LIMIT 10',
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
        const candidates = await dbAll(`
            SELECT m.id, m.text, m.created_at, m.time, uc.id AS chat_id, uc.name AS chat_name,
                   uc.room_id, uc.avatar, uc.online, uc.is_bot
            FROM (
                SELECT ids.id, uc.id AS chat_id
                FROM chats uc
                CROSS JOIN LATERAL (
                    (SELECT id FROM messages
                      WHERE uc.room_id IS NOT NULL AND room_id = uc.room_id AND deleted = 0 AND encrypted = FALSE
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
        for (const m of candidates) {
            const text = decryptText(m.text);
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
    if (newPassword.length < 8) return res.json({ success: false, message: 'Пароль должен быть не менее 8 символов' });
    if (newPassword.length > 128 || currentPassword.length > 128) return res.json({ success: false, message: 'Пароль не может быть длиннее 128 символов' });

    try {
        const user = await dbGet('SELECT password FROM users WHERE id = $1', [userId]);
        if (!user) return res.json({ success: false, message: 'Пользователь не найден' });
        if (!user.password) return res.json({ success: false, message: 'У этого аккаунта нет пароля (приватный режим)' });
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) return res.json({ success: false, message: 'Неверный текущий пароль' });
        const hashedPassword = await bcrypt.hash(newPassword, 12);

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

// Полное удаление анонимного пользователя: сообщения (и их файлы),
// реакции, E2EE key-shares и ключи, участие в комнатах, опустевшие комнаты,
// сама строка users. Одной транзакцией — раньше это была серия отдельных
// DELETE, и первая же ошибка FK (например, из e2ee_key_shares, который
// ссылается на users без каскада) оставляла пользователя в БД навсегда.
async function deleteAnonymousUser(userId) {
    const client = await pool.connect();
    let fileUrls = [];
    try {
        await client.query('BEGIN');
        const rooms = await client.query('SELECT DISTINCT room_id FROM room_participants WHERE user_id = $1', [userId]);
        const ownMessages = await client.query('DELETE FROM messages WHERE user_id = $1 RETURNING file_url', [userId]);
        fileUrls = ownMessages.rows.map(r => r.file_url);
        await client.query('DELETE FROM reactions WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM e2ee_key_shares WHERE sender_id = $1 OR recipient_id = $1', [userId]);
        await client.query('DELETE FROM room_participants WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM unread WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM chats WHERE user_id = $1', [userId]);

        const roomIds = rooms.rows.map(r => r.room_id);
        if (roomIds.length > 0) {
            const orphaned = await client.query(
                `DELETE FROM messages m WHERE m.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = m.room_id)
                 RETURNING file_url`,
                [roomIds]
            );
            fileUrls.push(...orphaned.rows.map(r => r.file_url));
            await client.query(
                `DELETE FROM rooms r WHERE r.id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = r.id)`,
                [roomIds]
            );
        }
        await client.query('DELETE FROM users WHERE id = $1', [userId]);
        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
    removeUploadedFiles(fileUrls);
    io.in('user:' + userId).disconnectSockets(true);
    deleteKeysForUser(userId);
    console.log(`[Anon] Successfully cleaned up anonymous user ${userId}`);
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
            ORDER BY u.id
            LIMIT 200
        `);
        for (const row of rows) {
            try {
                await deleteAnonymousUser(row.id);
            } catch (err) {
                console.error('[Anon] Не удалось удалить пользователя', row.id, '-', err.message);
            }
        }
        if (rows.length > 0) console.log(`[Anon] Удалено просроченных анонимных аккаунтов: ${rows.length}`);
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

    // Проверка Tor подключения (не блокирует запуск)
    if (ENABLE_TOR_ROUTING) {
        checkTorConnection().then((torStatus) => {
            if (torStatus.available && torStatus.isTor) {
                console.log('✓ Tor успешно подключен');
                console.log(`  IP через Tor: ${torStatus.ip}`);
                console.log('\nДля настройки Hidden Service добавьте в torrc:');
                console.log(getTorHiddenServiceConfig().hiddenServiceConfig);
            } else {
                console.warn('⚠ Tor не доступен:', torStatus.message || 'трафик идёт не через Tor');
                console.warn('  Сервер работает без Tor routing');
            }
        });
    }

    // Фоновые задачи: брошенные временные файлы обработки вложений и
    // просроченные анонимные аккаунты.
    setInterval(() => cleanupStaleTempFiles(UPLOADS_DIR, 60 * 60 * 1000), 60 * 60 * 1000);
    setTimeout(purgeExpiredAnonymousUsers, 60 * 1000);
    setInterval(purgeExpiredAnonymousUsers, 30 * 60 * 1000);

    console.log('Функции безопасности:');
    console.log('  ✓ CSRF Protection');
    console.log('  ✓ Rate Limiting');
    console.log('  ✓ Metadata Stripping');
    console.log('  ✓ Disappearing Messages');
    console.log('  ✓ Enhanced Privacy Headers');
    console.log('  ✓ Timing Attack Protection');
    if (ENABLE_TOR_ROUTING) console.log('  ✓ Tor Hidden Service Support');
    console.log(`\n${'='.repeat(60)}\n`);
}

// Порт открывается только ПОСЛЕ миграций. Раньше listen() вызывался сразу,
// параллельно с initDatabase(): первые запросы попадали на недомигрированную
// БД и висели на блокировках ALTER TABLE.
initDatabase()
    .then(() => server.listen(PORT, HOST, onServerListening))
    .catch((err) => {
        console.error('Ошибка инициализации БД:', err);
        process.exit(1);
    });
