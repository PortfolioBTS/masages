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
const { stripMetadataFromFile, cleanupOldFiles } = require('./lib/metadata-stripper');
const DisappearingMessagesManager = require('./lib/disappearing-messages');
const {
    addRandomDelay,
    padMessage,
    unpadMessage,
    addTimingNoise,
    sanitizeText,
    getPrivacyHeaders,
    anonymizeIP,
    generateSecureToken
} = require('./lib/privacy');

// Импорт E2EE прокси
const e2eeProxy = require('./lib/e2ee-proxy');

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
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const dir = path.join(__dirname, 'uploads');
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            cb(null, dir);
        },
        filename: (req, file, cb) => {
            // Расширение — только из MIME_EXTENSIONS (жёсткий маппинг по
            // уже проверенному в fileFilter mimetype), никогда из
            // file.originalname — см. комментарий у MIME_EXTENSIONS выше.
            const ext = MIME_EXTENSIONS[file.mimetype] || '';
            const safeName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
            if (!SAFE_FILENAME_RE.test(safeName)) {
                return cb(new Error('Не удалось сформировать безопасное имя файла'));
            }
            cb(null, safeName);
        }
    }),
    limits: { fileSize: 50 * 1024 * 1024 },
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

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
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

setInterval(() => {
    for (const [ip, count] of ipConnectionCount.entries()) {
        if (count <= 0) ipConnectionCount.delete(ip);
    }
}, 10 * 60 * 1000);

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
io.use((socket, next) => {
    const ip = getClientIp(socket.handshake);
    const count = ipConnectionCount.get(ip) || 0;
    if (count >= 5) {
        return next(new Error('Слишком много подключений с вашего IP'));
    }
    ipConnectionCount.set(ip, count + 1);
    socket.on('disconnect', () => {
        const current = ipConnectionCount.get(ip) || 1;
        if (current <= 1) {
            ipConnectionCount.delete(ip);
        } else {
            ipConnectionCount.set(ip, current - 1);
        }
    });
    next();
});

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
// Инициализация менеджера исчезающих сообщений
let disappearingMessagesManager;

async function initDatabase() {
    await maybeDumpCa().catch(err => { console.error('[DUMP_CA] Ошибка:', err.message); process.exit(1); });

    // Инициализация disappearing messages
    disappearingMessagesManager = new DisappearingMessagesManager(pool);
    await disappearingMessagesManager.initialize();

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

    // Миграция: если таблицы chats/messages были созданы ДО появления комнат,
    // CREATE TABLE IF NOT EXISTS их не тронет и колонки room_id не будет.
    // Добавляем её вручную, иначе следующий CREATE INDEX ON messages(room_id) упадёт с 42703.
    await pool.query(`ALTER TABLE chats ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id);`);
    await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id);`);

    // Миграция: удаление чата/выход из комнаты падало с нарушением FK —
    // messages.chat_id (NOT NULL, без ON DELETE) не давал снести свою же
    // запись в chats, если пользователь уже что-то написал, а chats.room_id
    // не давал снести саму комнату, пока на неё ссылалась хоть одна запись в
    // chats. Разрешаем chat_id уходить в NULL (история комнаты остаётся
    // видна остальным по room_id) и каскадно чистим осиротевшие chats при
    // удалении room.
    await pool.query(`ALTER TABLE messages ALTER COLUMN chat_id DROP NOT NULL;`);
    await pool.query(`ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_chat_id_fkey;`);
    await pool.query(`ALTER TABLE messages ADD CONSTRAINT messages_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE SET NULL;`);
    await pool.query(`ALTER TABLE chats DROP CONSTRAINT IF EXISTS chats_room_id_fkey;`);
    await pool.query(`ALTER TABLE chats ADD CONSTRAINT chats_room_id_fkey FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE;`);

    // Реакции должны исчезать вместе со своим сообщением (иначе снос всех
    // сообщений комнаты падает с reactions_message_id_fkey, как только у
    // любого из них есть хоть одна реакция).
    await pool.query(`ALTER TABLE reactions DROP CONSTRAINT IF EXISTS reactions_message_id_fkey;`);
    await pool.query(`ALTER TABLE reactions ADD CONSTRAINT reactions_message_id_fkey FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE;`);
    // Ответ на удалённое сообщение просто теряет связь с оригиналом, а не
    // блокирует его удаление и не удаляется сам.
    await pool.query(`ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_reply_to_id_fkey;`);
    await pool.query(`ALTER TABLE messages ADD CONSTRAINT messages_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES messages(id) ON DELETE SET NULL;`);
    // Остальное уже удаляется в правильном порядке на уровне приложения
    // (см. DELETE /api/chats/:chatId), но каскад добавлен как страховка на
    // случай, если порядок операций там в будущем изменят по ошибке.
    await pool.query(`ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_room_id_fkey;`);
    await pool.query(`ALTER TABLE messages ADD CONSTRAINT messages_room_id_fkey FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE;`);
    await pool.query(`ALTER TABLE unread DROP CONSTRAINT IF EXISTS unread_chat_id_fkey;`);
    await pool.query(`ALTER TABLE unread ADD CONSTRAINT unread_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE;`);
    await pool.query(`ALTER TABLE room_participants DROP CONSTRAINT IF EXISTS room_participants_room_id_fkey;`);
    await pool.query(`ALTER TABLE room_participants ADD CONSTRAINT room_participants_room_id_fkey FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE;`);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id);`);

    const cols = await dbAll(`
        SELECT column_name, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'users' AND column_name IN ('email', 'password')
    `);
    const colMap = {};
    cols.forEach(c => { colMap[c.column_name] = c.is_nullable; });
    if (colMap.email === 'NO') {
        await pool.query('ALTER TABLE users ALTER COLUMN email DROP NOT NULL');
    }
    if (colMap.password === 'NO') {
        await pool.query('ALTER TABLE users ALTER COLUMN password DROP NOT NULL');
    }

    console.log('База данных инициализирована');
}

initDatabase().catch(err => {
    console.error('Ошибка инициализации БД:', err);
    process.exit(1);
});
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

const sessionMiddleware = session({
    store: new pgSession({
        pool: pool,
        tableName: 'session',
        createTableIfMissing: true
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

io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});

io.on('connection', (socket) => {
    const userId = socket.request.session?.userId;
    if (!userId) {
        socket.disconnect(true);
        return;
    }
    console.log('Пользователь подключился через WebSocket, userId:', userId);

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

    socket.on('disconnect', () => {
        console.log('Пользователь отключился, userId:', userId);
    });
});
app.use(express.json());
app.use(cookieParser());

// Tor connection logger
app.use(torConnectionLogger);

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
    const issuedToken = cookieWasMissing ? crypto.randomBytes(32).toString('hex') : cookieToken;

    if (cookieWasMissing) {
        res.cookie('csrf_token', issuedToken, {
            httpOnly: false,
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000
        });
    }

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

app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/uploads/:filename', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    const filename = path.basename(req.params.filename);
    const filePath = path.join(__dirname, 'uploads', filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'Файл не найден' });
    try {
        const allowed = await userCanAccessFile(req.session.userId, filename);
        if (!allowed) return res.status(403).json({ success: false, message: 'Доступ запрещён' });
    } catch (err) {
        console.error('Uploads access check error:', err);
        return res.status(500).json({ success: false, message: 'Ошибка проверки доступа' });
    }
    res.sendFile(filePath);
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

app.use('/api/', apiLimiter);
app.post('/api/register', registerLimiter, async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;
    if (!username || !email || !password || !confirmPassword)
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
                [botChatId, userId, 'Привет! Я бот-помощник. Чем могу помочь?', 0, getCurrentTime(), 'read']
            );
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }

        req.session.userId = userId;
        req.session.username = username;
        req.session.uniqueCode = uniqueCode;
        req.session.avatar = '#667EEA';

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
            const existingCode = await dbGet('SELECT id FROM users WHERE unique_code = $1', [uniqueCode]);
            const existingName = await dbGet('SELECT id FROM users WHERE username = $1', [username]);
            if (existingCode || existingName) {
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
                [botChatId, userId, '🔒 Приватный режим активирован!\n\nВаши данные:\n• Хранятся только в этой сессии\n• Будут удалены при выходе\n• Не связаны с email или телефоном\n\nДля максимальной анонимности:\n• Используйте Tor Browser\n• Не делитесь личной информацией\n• Включите disappearing messages', 0, getCurrentTime(), 'read']
            );
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }

        req.session.userId = userId;
        req.session.username = username;
        req.session.uniqueCode = uniqueCode;
        req.session.avatar = '#667EEA';
        req.session.isAnonymous = true;
        req.session.sessionFingerprint = sessionFingerprint;
        req.session.createdAt = Date.now();

        // Устанавливаем короткий срок жизни сессии для анонимных пользователей
        req.session.cookie.maxAge = 4 * 60 * 60 * 1000; // 4 часа

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
                sessionExpiresIn: 4 * 60 * 60 // секунды
            }
        });
    } catch (error) {
        console.error('Anonymous register error:', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Введите email и пароль' });
    if (email.length > 254 || password.length > 128) return res.json({ success: false, message: 'Неверный email или пароль' });

    try {
        // Добавляем случайную задержку для защиты от timing attacks
        await addRandomDelay(50, 150);

        const user = await dbGet('SELECT * FROM users WHERE email = $1', [email]);
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

        req.session.regenerate((err) => {
            if (err) return res.json({ success: false, message: 'Ошибка инициализации сессии' });
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.uniqueCode = user.unique_code;
            req.session.avatar = user.avatar || '';
            res.json({ success: true, message: 'Вход выполнен!', user: { id: user.id, username: user.username, uniqueCode: user.unique_code, avatar: user.avatar || '' } });
        });
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
            console.log(`[Anon] Cleaning up data for anonymous user ${userId}`);

            // Удаляем все чаты пользователя
            await dbRun('DELETE FROM messages WHERE user_id = $1', [userId]);
            await dbRun('DELETE FROM chats WHERE user_id = $1', [userId]);
            await dbRun('DELETE FROM room_participants WHERE user_id = $1', [userId]);
            await dbRun('DELETE FROM reactions WHERE user_id = $1', [userId]);

            // Удаляем самого пользователя
            await dbRun('DELETE FROM users WHERE id = $1', [userId]);

            console.log(`[Anon] Successfully cleaned up anonymous user ${userId}`);
        } catch (error) {
            console.error('[Anon] Cleanup error:', error);
        }
    }

    req.session.destroy((err) => {
        res.clearCookie('connect.sid');
        res.clearCookie('csrf_token');
        if (err) console.error('Logout session destroy error:', err);
        res.json({ success: true, message: isAnonymous ? 'Данные удалены' : 'Выход выполнен' });
    });
});

app.get('/api/auth', async (req, res) => {
    if (!req.session.userId) return res.json({ authenticated: false });
    try {
        const row = await dbGet('SELECT avatar FROM users WHERE id = $1', [req.session.userId]);
        if (!row && req.session.isAnonymous) {
            // Анонимный пользователь был удален, очищаем сессию
            req.session.destroy(() => {});
            return res.json({ authenticated: false, expired: true });
        }
        if (!row) return res.json({ authenticated: false });

        const avatar = row ? (row.avatar || '') : (req.session.avatar || '');
        req.session.avatar = avatar;

        // Проверка времени жизни анонимной сессии
        if (req.session.isAnonymous && req.session.createdAt) {
            const sessionAge = Date.now() - req.session.createdAt;
            const maxAge = 4 * 60 * 60 * 1000; // 4 часа
            if (sessionAge > maxAge) {
                return res.json({
                    authenticated: false,
                    expired: true,
                    message: 'Анонимная сессия истекла'
                });
            }
        }

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
app.get('/api/chats', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chats = await dbAll(`
            SELECT c.id, c.name, c.avatar, c.online, c.is_bot, c.room_id, r.code as invite_code,
                   (SELECT text FROM messages WHERE ((c.room_id IS NOT NULL AND room_id = c.room_id) OR (c.room_id IS NULL AND chat_id = c.id)) ORDER BY id DESC LIMIT 1) as last_message,
                   (SELECT time FROM messages WHERE ((c.room_id IS NOT NULL AND room_id = c.room_id) OR (c.room_id IS NULL AND chat_id = c.id)) ORDER BY id DESC LIMIT 1) as last_time,
                   (SELECT COUNT(*) FROM messages m WHERE ((c.room_id IS NOT NULL AND m.room_id = c.room_id) OR (c.room_id IS NULL AND m.chat_id = c.id)) AND m.sent = 0 AND m.status != 'read') as unread
            FROM chats c
            LEFT JOIN rooms r ON c.room_id = r.id
            WHERE c.user_id = $1
            ORDER BY (SELECT MAX(id) FROM messages WHERE ((c.room_id IS NOT NULL AND room_id = c.room_id) OR (c.room_id IS NULL AND chat_id = c.id))) DESC NULLS LAST
        `, [req.session.userId]);
        res.json({ success: true, chats: chats.map(c => ({ ...c, unread: Number(c.unread) })) });
    } catch (error) {
        console.error('Get chats error:', error);
        res.json({ success: false, message: 'Ошибка загрузки чатов' });
    }
});

app.get('/api/messages/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = req.params.chatId;
    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        const selectParam = chat.room_id || chatId;
        const selectQuery = chat.room_id
            ? `SELECT m.*, u.username as sender_username, u.avatar as sender_avatar,
                      rt.id as reply_to_id, rt.text as reply_to_text, ru.username as reply_to_sender_username, ru.avatar as reply_to_sender_avatar
               FROM messages m
               JOIN users u ON m.user_id = u.id
               LEFT JOIN messages rt ON m.reply_to_id = rt.id
               LEFT JOIN users ru ON rt.user_id = ru.id
               WHERE m.room_id = $1 AND m.deleted = 0
               ORDER BY m.id ASC`
            : `SELECT m.*, u.username as sender_username, u.avatar as sender_avatar,
                      rt.id as reply_to_id, rt.text as reply_to_text, ru.username as reply_to_sender_username, ru.avatar as reply_to_sender_avatar
               FROM messages m
               JOIN users u ON m.user_id = u.id
               LEFT JOIN messages rt ON m.reply_to_id = rt.id
               LEFT JOIN users ru ON rt.user_id = ru.id
               WHERE m.chat_id = $1 AND m.deleted = 0
               ORDER BY m.id ASC`;

        let messages = await dbAll(selectQuery, [selectParam]);

        if (messages.length === 0) {
            const updateQuery = chat.room_id
                ? 'UPDATE messages SET status = $1 WHERE room_id = $2 AND sent = 0'
                : 'UPDATE messages SET status = $1 WHERE chat_id = $2 AND sent = 0';
            await dbRun(updateQuery, ['read', selectParam]);
            return res.json({ success: true, messages: [], chat });
        }

        const messageIds = messages.map(m => m.id);
        const placeholders = messageIds.map((_, i) => `$${i + 1}`).join(',');
        const reactions = await dbAll(
            `SELECT message_id, STRING_AGG(DISTINCT emoji, ',') as emojis FROM reactions WHERE message_id IN (${placeholders}) GROUP BY message_id`,
            messageIds
        );

        const reactionsMap = {};
        reactions.forEach(r => { reactionsMap[r.message_id] = r.emojis.split(','); });

        messages = messages.map(m => ({
            ...m,
            reactions: reactionsMap[m.id] || [],
            reply_to: m.reply_to_id ? { id: m.reply_to_id, text: m.reply_to_text, sender_username: m.reply_to_sender_username, sender_avatar: m.reply_to_sender_avatar } : null
        }));

        const updateQuery = chat.room_id
            ? 'UPDATE messages SET status = $1 WHERE room_id = $2 AND sent = 0'
            : 'UPDATE messages SET status = $1 WHERE chat_id = $2 AND sent = 0';
        await dbRun(updateQuery, ['read', selectParam]);

        res.json({ success: true, messages, chat });
    } catch (error) {
        console.error('Get messages error:', error);
        res.json({ success: false, message: 'Ошибка загрузки сообщений' });
    }
});

app.post('/api/messages', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { chatId, text, replyToId, expirySeconds } = req.body;
    const replyTo = Number(replyToId) || null;
    if (!text || text.trim() === '' || !chatId) return res.json({ success: false, message: 'Введите текст сообщения' });
    if (text.length > 4000) return res.json({ success: false, message: 'Сообщение не может быть длиннее 4000 символов' });

    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        const time = getCurrentTime();
        const roomId = chat.room_id || null;
        const socketRoomKey = getSocketRoomKey(chatId, roomId);

        // Очистка текста от опасных метаданных
        const safeText = sanitizeText(text.trim());

        const result = await pool.query(
            'INSERT INTO messages (chat_id, room_id, user_id, text, message_type, sent, time, status, reply_to_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
            [chatId, roomId, req.session.userId, safeText, 'text', 1, time, 'sent', replyTo]
        );
        const messageId = result.rows[0].id;

        // Установка времени жизни сообщения если указано
        if (expirySeconds && Number(expirySeconds) > 0) {
            await disappearingMessagesManager.setMessageExpiry(messageId, Number(expirySeconds), false);
        } else {
            // Проверка настроек чата на автоудаление
            const chatSettings = await disappearingMessagesManager.getChatSettings(chatId);
            if (chatSettings && chatSettings.default_message_expiry) {
                await disappearingMessagesManager.setMessageExpiry(messageId, chatSettings.default_message_expiry, false);
            }
        }

        const fullMessage = await dbGet(
            'SELECT m.*, u.username, u.avatar as user_avatar FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $1',
            [messageId]
        );

        const messageForSocket = { ...fullMessage, sender_username: fullMessage.username, sender_avatar: fullMessage.user_avatar };
        io.to(socketRoomKey).emit('newMessage', messageForSocket);
        res.json({ success: true, message: messageForSocket });

        if (chat.is_bot) {
            const botUserId = req.session.userId;
            setTimeout(async () => {
                const stillExists = await dbGet(
                    'SELECT id FROM chats WHERE id = $1 AND user_id = $2 AND is_bot = 1',
                    [chatId, botUserId]
                );
                if (!stillExists) return;

                const botResponses = ['Интересный вопрос! Расскажите подробнее.', 'Я получил ваше сообщение!', 'Хмм, дайте подумать...', 'Отличное сообщение! Продолжайте.', 'Я бот, но стараюсь быть полезным!', 'Можете уточнить, что именно вас интересует?'];
                const randomResponse = botResponses[Math.floor(Math.random() * botResponses.length)];
                const botTime = getCurrentTime();
                try {
                    const botResult = await pool.query(
                        'INSERT INTO messages (chat_id, room_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
                        [chatId, roomId, botUserId, randomResponse, 0, botTime, 'read']
                    );
                    const botMessageId = botResult.rows[0].id;
                    const botMessage = await dbGet(
                        'SELECT m.*, u.username, u.avatar as user_avatar FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $1',
                        [botMessageId]
                    );
                    if (botMessage) {
                        io.to(socketRoomKey).emit('newMessage', { ...botMessage, sender_username: botMessage.username, sender_avatar: botMessage.user_avatar });
                    }
                } catch (e) { console.error('Bot error:', e); }
            }, 1500);
        }
    } catch (error) {
        console.error('Send message error:', error);
        res.json({ success: false, message: 'Ошибка отправки' });
    }
});

app.post('/api/chats', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { name } = req.body;
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
            await client.query('INSERT INTO room_participants (room_id, user_id) VALUES ($1, $2)', [roomId, req.session.userId]);
            const chatResult = await client.query(
                'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [req.session.userId, roomId, name, avatar, 0, 0]
            );
            chatId = chatResult.rows[0].id;
            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK');
            throw txErr;
        } finally {
            client.release();
        }
        res.json({ success: true, chat: { id: chatId, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
    } catch (error) {
        console.error('Create chat error:', error);
        res.json({ success: false, message: 'Ошибка создания чата' });
    }
});

app.get('/api/chats/invite/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = req.params.chatId;
    try {
        const chat = await dbGet('SELECT room_id FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
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
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { code } = req.body;
    if (!code) return res.json({ success: false, message: 'Введите код приглашения' });

    try {
        const room = await dbGet('SELECT * FROM rooms WHERE code = $1', [code]);
        if (!room) return res.json({ success: false, message: 'Чат по этому коду не найден' });

        const participant = await dbGet('SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2', [room.id, req.session.userId]);
        if (participant) {
            const chat = await dbGet('SELECT id FROM chats WHERE room_id = $1 AND user_id = $2', [room.id, req.session.userId]);
            if (!chat) return res.json({ success: false, message: 'Чат уже добавлен' });
            return res.json({ success: true, chat: { id: chat.id } });
        }

        const otherUser = await dbGet('SELECT u.username FROM users u JOIN room_participants rp ON u.id = rp.user_id WHERE rp.room_id = $1 AND u.id != $2 LIMIT 1', [room.id, req.session.userId]);
        const chatName = otherUser ? `Чат с ${otherUser.username}` : room.name;
        const avatar = chatName.charAt(0).toUpperCase();

        await pool.query('INSERT INTO room_participants (room_id, user_id) VALUES ($1, $2)', [room.id, req.session.userId]);
        const chatResult = await pool.query(
            'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [req.session.userId, room.id, chatName, avatar, 0, 0]
        );
        res.json({ success: true, chat: { id: chatResult.rows[0].id, name: chatName, avatar, online: 0, is_bot: 0, room_id: room.id, invite_code: room.code } });
    } catch (error) {
        console.error('Join chat error:', error);
        res.json({ success: false, message: 'Ошибка входа в чат' });
    }
});

app.delete('/api/chats/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = req.params.chatId;
    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        if (chat.room_id) {
            await dbRun('DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, req.session.userId]);
            const remaining = await dbGet('SELECT COUNT(*) as cnt FROM room_participants WHERE room_id = $1', [chat.room_id]);
            await dbRun('DELETE FROM unread WHERE chat_id = $1', [chatId]);
            await dbRun('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
            if (!remaining || Number(remaining.cnt) === 0) {
                // Последний участник вышел — сносим комнату целиком.
                await dbRun('DELETE FROM messages WHERE room_id = $1', [chat.room_id]);
                await dbRun('DELETE FROM rooms WHERE id = $1', [chat.room_id]);
            }
            // Если участники остались — историю не трогаем, она у них
            // по-прежнему доступна по room_id (chat_id этого сообщения,
            // если оно было отправлено уходящим, просто станет NULL).
        } else {
            await dbRun('DELETE FROM messages WHERE chat_id = $1', [chatId]);
            await dbRun('DELETE FROM unread WHERE chat_id = $1', [chatId]);
            await dbRun('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Delete chat error:', error);
        res.json({ success: false, message: 'Ошибка удаления чата' });
    }
});

app.put('/api/messages/:messageId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId } = req.params;
    const { text } = req.body;
    if (!text || text.trim() === '') return res.json({ success: false, message: 'Текст не может быть пустым' });
    if (text.length > 4000) return res.json({ success: false, message: 'Сообщение не может быть длиннее 4000 символов' });

    try {
        const message = await dbGet('SELECT * FROM messages WHERE id = $1 AND user_id = $2', [messageId, req.session.userId]);
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        const editedAt = new Date().toISOString();
        const trimmedText = text.trim();
        await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [trimmedText, editedAt, messageId]);

        // Раньше правки не рассылались по сокету — у остальных участников
        // комнаты изменение не появлялось без перезагрузки (см. "Мелочи").
        const socketRoomKey = getSocketRoomKey(message.chat_id, message.room_id);
        io.to(socketRoomKey).emit('messageEdited', {
            id: Number(messageId), text: trimmedText, edited_at: editedAt,
            chat_id: message.chat_id, room_id: message.room_id
        });

        res.json({ success: true, edited_at: editedAt });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка редактирования' });
    }
});

app.delete('/api/messages/:messageId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId } = req.params;
    try {
        const message = await dbGet('SELECT * FROM messages WHERE id = $1 AND user_id = $2', [messageId, req.session.userId]);
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        await dbRun('UPDATE messages SET deleted = 1 WHERE id = $1', [messageId]);

        const socketRoomKey = getSocketRoomKey(message.chat_id, message.room_id);
        io.to(socketRoomKey).emit('messageDeleted', {
            id: Number(messageId), chat_id: message.chat_id, room_id: message.room_id
        });

        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка удаления' });
    }
});
// multer(upload.single('file')) уже записал файл на диск ДО этого хендлера —
// значит, ранние return (401/400/404) должны сами убирать за собой, иначе
// каждая неудачная/подделанная попытка загрузки будет накапливать файлы-сироты.
function cleanupUploadedFile(file) {
    if (!file) return;
    try {
        const p = path.join(__dirname, 'uploads', file.filename);
        if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch (e) { /* ignore */ }
}

app.post('/api/messages/file', upload.single('file'), async (req, res) => {
    if (!req.session.userId) {
        cleanupUploadedFile(req.file);
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    const { chatId, text } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ success: false, message: 'Файл не выбран' });
    if (!chatId) {
        cleanupUploadedFile(file);
        return res.status(400).json({ success: false, message: 'Указан чат' });
    }

    const uploadedFilePath = path.join(__dirname, 'uploads', file.filename);
    try {
        const buffer = Buffer.alloc(12);
        const fd = fs.openSync(uploadedFilePath, 'r');
        fs.readSync(fd, buffer, 0, 12, 0);
        fs.closeSync(fd);
        if (!checkMagicBytes(buffer, file.mimetype)) {
            fs.unlinkSync(uploadedFilePath);
            return res.status(400).json({ success: false, message: 'Содержимое файла не соответствует его типу' });
        }

        // Удаление метаданных из файла для защиты приватности
        if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
            await stripMetadataFromFile(uploadedFilePath, file.mimetype);
            console.log('[Privacy] Stripped metadata from uploaded file:', file.filename);
        }
    } catch (magicErr) {
        // Раньше при исключении здесь проверка молча пропускалась и файл
        // проходил дальше — теоретическая лазейка мимо проверки типа файла.
        // Теперь любая ошибка проверки = отказ (fail closed), а не fail open.
        console.error('Magic bytes check error:', magicErr);
        try { if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath); } catch (_) { /* ignore */ }
        return res.status(400).json({ success: false, message: 'Не удалось проверить содержимое файла' });
    }

    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) {
            cleanupUploadedFile(file);
            return res.status(404).json({ success: false, message: 'Чат не найден' });
        }

        const time = getCurrentTime();
        const roomId = chat.room_id || null;
        const socketRoomKey = getSocketRoomKey(chatId, roomId);
        const fileUrl = `/uploads/${file.filename}`;
        const fileType = file.mimetype;
        const sanitizedFileName = path.basename(file.originalname).slice(0, 200).replace(/[<>&"']/g, '');

        const messageType = fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : fileType.startsWith('audio/') ? 'audio' : 'file';
        const messageText = text ? String(text).trim() : (messageType === 'audio' ? 'Голосовое сообщение' : file.originalname);

        const result = await pool.query(
            'INSERT INTO messages (chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id',
            [chatId, roomId, req.session.userId, messageText, fileUrl, sanitizedFileName, fileType, messageType, 1, time, 'sent']
        );
        const messageId = result.rows[0].id;

        const senderUser = await dbGet('SELECT username, avatar FROM users WHERE id = $1', [req.session.userId]);
        const senderUsername = senderUser ? senderUser.username : '';
        const senderAvatar = senderUser ? (senderUser.avatar || '') : '';

        setTimeout(() => dbRun('UPDATE messages SET status = $1 WHERE id = $2', ['delivered', messageId]), 1000);
        setTimeout(() => dbRun('UPDATE messages SET status = $1 WHERE id = $2', ['read', messageId]), 2000);

        const fileMessage = {
            id: messageId, chat_id: Number(chatId), room_id: roomId, user_id: req.session.userId,
            sender_username: senderUsername, sender_avatar: senderAvatar,
            text: messageText, file_url: fileUrl, file_name: sanitizedFileName,
            file_type: fileType, message_type: messageType, sent: true, time, status: 'sent'
        };
        io.to(socketRoomKey).emit('newMessage', fileMessage);
        res.json({ success: true, message: fileMessage });
    } catch (error) {
        console.error('Upload file error:', error);
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
// определяет владельца.
// В UI предлагается фиксированный набор из 5 эмодзи для реакций. Раньше на
// бэке проверялась только длина строки (≤10 символов), а не содержимое — это
// пропускало вход в message.reactions, который на фронте рендерится в
// innerHTML без escapeHtml (см. п.3 аудита). Теперь бэк принимает только
// эмодзи из этого списка.
const ALLOWED_REACTION_EMOJIS = new Set(['👍', '❤️', '😂', '😢', '🔥']);

async function userCanAccessFile(userId, filename) {
    const fileUrl = `/uploads/${filename}`;
    const message = await dbGet('SELECT id FROM messages WHERE file_url = $1 LIMIT 1', [fileUrl]);
    if (!message) return false;
    return userCanAccessMessage(userId, message.id);
}

app.post('/api/reactions', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId, emoji } = req.body;
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
    const messageId = Number(req.params.messageId);
    const emoji = decodeURIComponent(req.params.emoji);
    if (!Number.isFinite(messageId) || !ALLOWED_REACTION_EMOJIS.has(emoji)) {
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
    const query = req.query.q || '';
    if (!query || query.length < 1) return res.json({ success: true, results: [] });
    if (query.length > 100) return res.json({ success: false, message: 'Запрос слишком длинный' });

    const safeTerm = query.replace(/[%_\\]/g, '\\$&');
    const searchTerm = `%${safeTerm}%`;
    try {
        const chats = await dbAll('SELECT id, name, avatar FROM chats WHERE user_id = $1 AND name ILIKE $2 LIMIT 10', [req.session.userId, searchTerm]);
        // Раньше джойн был m.chat_id = c.id, а m.chat_id всегда указывает на
        // строку chats её АВТОРА, а не читающего — у каждого участника
        // групповой комнаты своя запись chats. В итоге поиск находил только
        // сообщения самого искателя (см. п.4 аудита). Джойним на СОБСТВЕННУЮ
        // запись chats искателя (uc) по тому же паттерну room_id/chat_id,
        // что уже используется в /api/chats: для групповых чатов сравниваем
        // m.room_id с room_id этой записи (не зависит от того, кто автор), а
        // для обычных 1:1 чатов — как и раньше, m.chat_id = uc.id.
        const messages = await dbAll(
            `SELECT m.id, m.text, uc.id AS chat_id, uc.name AS chat_name FROM messages m
             JOIN chats uc ON (
                 (uc.room_id IS NOT NULL AND m.room_id = uc.room_id)
                 OR (uc.room_id IS NULL AND m.chat_id = uc.id)
             )
             WHERE uc.user_id = $1 AND m.text ILIKE $2 AND m.deleted = 0 LIMIT 20`,
            [req.session.userId, searchTerm]
        );
        res.json({ success: true, results: { chats, messages } });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка поиска' });
    }
});

// API для disappearing messages
app.post('/api/messages/:messageId/set-expiry', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = Number(req.params.messageId);
    const { expirySeconds, autoDeleteOnRead } = req.body;

    if (!Number.isFinite(messageId) || !Number.isFinite(expirySeconds)) {
        return res.json({ success: false, message: 'Неверные параметры' });
    }

    try {
        // Проверка доступа к сообщению
        const message = await dbGet('SELECT user_id FROM messages WHERE id = $1', [messageId]);
        if (!message || message.user_id !== req.session.userId) {
            return res.json({ success: false, message: 'Сообщение не найдено или нет доступа' });
        }

        await disappearingMessagesManager.setMessageExpiry(
            messageId,
            expirySeconds,
            autoDeleteOnRead || false
        );

        res.json({ success: true, message: 'Таймер самоуничтожения установлен' });
    } catch (error) {
        console.error('Set expiry error:', error);
        res.json({ success: false, message: 'Ошибка установки таймера' });
    }
});

app.post('/api/chats/:chatId/set-default-expiry', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = Number(req.params.chatId);
    const { expirySeconds } = req.body;

    if (!Number.isFinite(chatId) || !Number.isFinite(expirySeconds)) {
        return res.json({ success: false, message: 'Неверные параметры' });
    }

    try {
        // Проверка доступа к чату
        const chat = await dbGet('SELECT id FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        await disappearingMessagesManager.setChatDefaultExpiry(chatId, expirySeconds);

        res.json({ success: true, message: 'Автоудаление сообщений настроено для чата' });
    } catch (error) {
        console.error('Set chat default expiry error:', error);
        res.json({ success: false, message: 'Ошибка настройки автоудаления' });
    }
});

app.get('/api/chats/:chatId/settings', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = Number(req.params.chatId);

    try {
        const chat = await dbGet('SELECT id FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const settings = await disappearingMessagesManager.getChatSettings(chatId);
        res.json({ success: true, settings: settings || {} });
    } catch (error) {
        console.error('Get chat settings error:', error);
        res.json({ success: false, message: 'Ошибка получения настроек' });
    }
});

app.post('/api/change-password', passwordLimiter, async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) return res.json({ success: false, message: 'Заполните все поля' });
    if (newPassword !== confirmPassword) return res.json({ success: false, message: 'Новые пароли не совпадают' });
    if (newPassword.length < 8) return res.json({ success: false, message: 'Пароль должен быть не менее 8 символов' });

    try {
        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.session.userId]);
        if (!user) return res.json({ success: false, message: 'Пользователь не найден' });
        if (!user.password) return res.json({ success: false, message: 'У этого аккаунта нет пароля (приватный режим)' });
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) return res.json({ success: false, message: 'Неверный текущий пароль' });
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        const userId = req.session.userId;

        await dbRun('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

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
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ success: false, message: 'Файл слишком большой (макс. 50 МБ)' });
        }
        return res.status(400).json({ success: false, message: `Ошибка загрузки: ${err.message}` });
    }
    if (err.message === 'Неподдерживаемый тип файла') {
        return res.status(400).json({ success: false, message: 'Разрешены только фото, видео, аудио и PDF' });
    }
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

server.listen(PORT, HOST, async () => {
    const addresses = getLocalAddresses();
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Nyxo Messenger запущен на порту ${PORT}`);
    console.log(`${'='.repeat(60)}\n`);

    if (addresses.length > 0) {
        console.log('Доступен по адресам:');
        addresses.forEach(addr => console.log(`  → http://${addr}:${PORT}`));
        console.log('');
    }

    // Проверка Tor подключения
    if (ENABLE_TOR_ROUTING) {
        console.log('Проверка Tor подключения...');
        const torStatus = await checkTorConnection();
        if (torStatus.available && torStatus.isTor) {
            console.log('✓ Tor успешно подключен');
            console.log(`  IP через Tor: ${torStatus.ip}`);

            const hiddenServiceConfig = getTorHiddenServiceConfig();
            console.log('\nДля настройки Hidden Service добавьте в torrc:');
            console.log(hiddenServiceConfig.hiddenServiceConfig);
        } else {
            console.warn('⚠ Tor не доступен:', torStatus.message);
            console.warn('  Сервер работает без Tor routing');
        }
        console.log('');
    }

    // Запуск фоновой очистки старых файлов
    setInterval(() => {
        const uploadsDir = path.join(__dirname, 'uploads');
        cleanupOldFiles(uploadsDir, 24 * 60 * 60 * 1000); // 24 часа
    }, 60 * 60 * 1000); // Каждый час

    console.log('Функции безопасности:');
    console.log('  ✓ CSRF Protection');
    console.log('  ✓ Rate Limiting');
    console.log('  ✓ Metadata Stripping');
    console.log('  ✓ Disappearing Messages');
    console.log('  ✓ Enhanced Privacy Headers');
    console.log('  ✓ Timing Attack Protection');
    if (ENABLE_TOR_ROUTING) console.log('  ✓ Tor Hidden Service Support');
    console.log(`\n${'='.repeat(60)}\n`);
});
