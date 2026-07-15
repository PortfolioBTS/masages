require('dotenv').config();

// 1. ИМПОРТЫ
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const multer = require('multer');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const https = require('https'); // Изменено: явный импорт https
const fs = require('fs');
const { Server } = require('socket.io');
const pgSession = require('connect-pg-simple')(session);
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');


// Конфигурация загрузки файлов
const ALLOWED_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/webm', 'video/quicktime',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
    'application/pdf', 'text/plain',
];

// Запрещённые расширения (независимо от MIME-типа)
const BLOCKED_EXTENSIONS = new Set(['.html', '.htm', '.php', '.exe', '.js', '.sh', '.py', '.rb', '.pl', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.msi']);

// Magic bytes для проверки реального типа содержимого
function checkMagicBytes(buffer, mimetype) {
    if (!buffer || buffer.length < 4) return false;
    const b = buffer;
    if (mimetype === 'image/jpeg') return b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF;
    if (mimetype === 'image/png')  return b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47;
    if (mimetype === 'image/gif')  return b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46;
    if (mimetype === 'image/webp') return b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46;
    if (mimetype === 'application/pdf') return b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46;
    if (mimetype === 'video/mp4')  return (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) || (b[0] === 0x00 && b[1] === 0x00);
    if (mimetype === 'audio/mpeg') return (b[0] === 0xFF && (b[1] & 0xE0) === 0xE0) || (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33);
    if (mimetype === 'audio/ogg' || mimetype === 'video/webm' || mimetype === 'audio/webm') {
        return (b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67) || (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3);
    }
    if (mimetype === 'audio/wav') return b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46;
    if (mimetype === 'text/plain') return true; // текст не имеет фиксированной сигнатуры
    if (mimetype === 'video/quicktime') return b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70;
    // По умолчанию ОТКАЗЫВАЕМ: MIME-заголовок клиент подделывает, поэтому всё,
    // что не распознали явно, считаем подозрительным. Раньше здесь было `return true`,
    // что пропускало любой бинарник с подменённым типом.
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
            const ext = path.extname(file.originalname).toLowerCase();
            const safeName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
            cb(null, safeName);
        }
    }),
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        // 1. Проверяем расширение
        const ext = path.extname(file.originalname).toLowerCase();
        if (BLOCKED_EXTENSIONS.has(ext)) {
            return cb(new Error('Неподдерживаемый тип файла'), false);
        }
        // 2. Проверяем MIME-тип из заголовка (первичная фильтрация)
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error('Неподдерживаемый тип файла'), false);
        }
        cb(null, true);
    }
});

// 2. ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЙ
const app = express();
app.set('trust proxy', 1);

// Если сайт стоит за Cloudflare (Security → Proxied/оранжевое облачко),
// Cloudflare добавляет ещё один хоп перед хостинг-платформой, из-за чего
// req.ip может показывать IP хостинга, а не реального клиента.
// CF-Connecting-IP — это заголовок, который выставляет сам Cloudflare
// (клиент не может его подделать, Cloudflare перезаписывает его на границе
// своей сети), поэтому это самый надёжный источник настоящего IP.
app.use((req, res, next) => {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) {
        req.realIp = cfIp;
    } else {
        req.realIp = req.ip;
    }
    next();
});

// === RATE LIMITING ===
// За Cloudflare/Railway req.ip = адрес прокси, поэтому ключуемся по реальному
// клиентскому IP (cf-connecting-ip → x-forwarded-for → req.ip), который middleware
// выше уже положил в req.realIp. Без этого весь сайт получит один общий лимит.
const rateLimitKeyGenerator = (req) => req.realIp || req.ip;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,     // 15 минут
    max: 5,                        // 5 попыток входа
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много попыток входа. Попробуйте позже.' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,     // 1 час
    max: 3,                        // 3 регистрации
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много регистраций. Попробуйте позже.' }
});

const passwordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,     // 15 минут
    max: 3,                        // 3 смены пароля
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много попыток смены пароля. Попробуйте позже.' }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,     // 15 минут
    max: 300,                     // 300 запросов на произвольный /api/* (защита от спама)
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: rateLimitKeyGenerator,
    message: { success: false, message: 'Слишком много запросов. Попробуйте позже.' }
});

 
let server;
if (process.env.NODE_ENV === 'production') {
    server = http.createServer(app);
} else {
    // Проверка существования файлов SSL для dev-режима
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
// Максимум 5 одновременных WebSocket-соединений с одного IP
const ipConnectionCount = new Map();

// Очищаем записи с нулевым счётчиком каждые 10 минут, чтобы не копился мусор
setInterval(() => {
    for (const [ip, count] of ipConnectionCount.entries()) {
        if (count <= 0) ipConnectionCount.delete(ip);
    }
}, 10 * 60 * 1000);

// Извлекает настоящий клиентский IP из заголовков прокси-цепочки.
// За Cloudflare+Railway socket.handshake.address показывает адрес прокси, а не клиента.
// Порядок: cf-connecting-ip (Cloudflare, перезаписывается на границе сети) →
// x-forwarded-for (стандартный заголовок прокси, берём первый = исходный клиент) →
// handshake.address (TCP-сокет, фоллбэк для прямого подключения).
function getClientIp(handshake) {
    const headers = handshake.headers || {};
    if (headers['cf-connecting-ip']) {
        return headers['cf-connecting-ip'].trim().split(',')[0];
    }
    if (headers['x-forwarded-for']) {
        return headers['x-forwarded-for'].trim().split(',')[0];
    }
    return handshake.address;
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

// Внутренний сервис ① — E2EE Key Exchange (Rust, отдельный процесс на loopback).
// Node сюда не подключается напрямую к БД сервиса — только HTTP по localhost,
// после того как сам уже проверил req.session.userId как обычно.
const KEY_SERVER_URL = process.env.KEY_SERVER_URL || 'http://127.0.0.1:7420';
const KEY_SERVER_SECRET = process.env.INTERNAL_KEY_SERVER_SECRET;
if (!KEY_SERVER_SECRET) {
    console.warn('[keys] INTERNAL_KEY_SERVER_SECRET не задан — роуты /api/keys/* будут возвращать 503');
}
 
// 3. ПОДКЛЮЧЕНИЕ К POSTGRESQL

// Если установлена переменная DUMP_CA=true — выводим ВСЮ цепочку сертификатов и завершаем работу
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
                // Собираем ВСЮ цепочку сертификатов (leaf → intermediate → root)
                const chain = [];
                let current = tlsSocket.getPeerCertificate(true);
                const seen = new Set();
                while (current && !seen.has(current.fingerprint)) {
                    seen.add(current.fingerprint);
                    chain.push(current);
                    if (!current.issuerCertificate || current.issuerCertificate === current) break;
                    current = current.issuerCertificate;
                }

                // Конвертируем каждый сертификат в PEM
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

    // Railway использует self-signed сертификат в цепочке — стандартная конфигурация для этого хостинга.
    // TLS-шифрование активно, трафик не покидает внутреннюю сеть Railway.
    // Источник: https://docs.railway.com/guides/postgresql
    console.log('[SSL] production: rejectUnauthorized=false (Railway internal network)');
    return { rejectUnauthorized: false };
})();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: sslConfig,
});
 
// Вспомогательная функция — аналог db.get (одна строка)
async function dbGet(query, params = []) {
    const result = await pool.query(query, params);
    return result.rows[0] || null;
}
 
// Вспомогательная функция — аналог db.all (все строки)
async function dbAll(query, params = []) {
    const result = await pool.query(query, params);
    return result.rows;
}
 
// Вспомогательная функция — аналог db.run (INSERT/UPDATE/DELETE)
async function dbRun(query, params = []) {
    const result = await pool.query(query, params);
    return result;
}


// 4. СОЗДАНИЕ ТАБЛИЦ
async function initDatabase() {
    // Если DUMP_CA=true — выводим сертификат в лог и выходим
    await maybeDumpCa().catch(err => { console.error('[DUMP_CA] Ошибка:', err.message); process.exit(1); });

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            unique_code TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
 
    await pool.query(`
        CREATE TABLE IF NOT EXISTS chats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
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
        CREATE TABLE IF NOT EXISTS reactions (
            id SERIAL PRIMARY KEY,
            message_id INTEGER NOT NULL REFERENCES messages(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            emoji TEXT NOT NULL,
            UNIQUE(message_id, user_id, emoji)
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id);`);

    // Миграция: удаление rooms-инфраструктуры (переход на модель 1-на-1).
    // Idempotent — IF EXISTS/COLUMN IF EXISTS позволяют запускать многократно.
    // Бета: прод-данных нет, поэтому деструктивный DROP приемлем.
    await pool.query(`DROP INDEX IF EXISTS idx_messages_room_id;`);
    await pool.query(`DROP TABLE IF EXISTS room_participants CASCADE;`);
    await pool.query(`DROP TABLE IF EXISTS rooms CASCADE;`);
    await pool.query(`ALTER TABLE messages DROP COLUMN IF EXISTS room_id;`);
    await pool.query(`ALTER TABLE chats DROP COLUMN IF EXISTS room_id;`);

    // Миграция: поддержка анонимных аккаунтов (без email/пароля).
    // Idempotent — проверяем текущую nullability через information_schema и
    // выполняем DROP NOT NULL только один раз. UNIQUE на email при этом остаётся,
    // но PostgreSQL разрешает несколько NULL в UNIQUE-колонке (в отличие от SQLite).
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
 
// 5. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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

// Генерирует уникальное анонимное имя вида «Гость-AB3X9». Коллизии маловероятны,
// но проверяем на всякий случай, т.к. username = UNIQUE.
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
        if (!roomKey.startsWith('chat:')) return; // Поддерживается только личный чат (1-на-1)

        try {
            const chatId = parseInt(roomKey.slice(5), 10);
            if (!Number.isFinite(chatId)) return;
            const chat = await dbGet(
                'SELECT id FROM chats WHERE id = $1 AND user_id = $2',
                [chatId, userId]
            );
            if (!chat) return; // Чат не принадлежит пользователю
            socket.join(roomKey);
        } catch (err) {
            console.error('joinChat error:', err);
        }
    });

    socket.on('disconnect', () => {
        console.log('Пользователь отключился, userId:', userId);
    });
});
 
// 7. MIDDLEWARE
app.use(express.json());
app.use(cookieParser()); // Нужен для чтения req.cookies в CSRF middleware

 
// CSRF-защита через double-submit cookie pattern
// Клиент должен отправлять заголовок X-CSRF-Token со значением cookie csrf_token
app.use((req, res, next) => {
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(req.method)) return next();
    if (req.path.startsWith('/socket.io')) return next();

    // Генерируем и выставляем CSRF-cookie если его нет
    if (!req.cookies['csrf_token']) {
        const csrfToken = crypto.randomBytes(32).toString('hex');
        res.cookie('csrf_token', csrfToken, {
            httpOnly: false, // должен быть доступен JS для отправки в заголовке
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000
        });
        return next(); // первый запрос пропускаем, cookie только что установлено
    }

    const cookieToken = req.cookies['csrf_token'];
    const headerToken = req.headers['x-csrf-token'];

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        return res.status(403).json({ success: false, message: 'Запрещено: неверный CSRF-токен' });
    }
    next();
});
 
// Middleware безопасности (ИСПРАВЛЕНО: Обновлен CSP и добавлен Nonce)
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
    res.set('X-Robots-Tag', 'noindex, nofollow');
    
    // Генерация Nonce для CSP
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.cspNonce = nonce;

    // Обновленная политика безопасности: убраны unsafe-inline там где можно, добавлен nonce
    // style-src: 'unsafe-inline' нужен, потому что script.js генерирует HTML с
    // динамическими inline style="..." (цвет аватарки/пузырька сообщения — свой
    // для каждого юзера/сообщения, поэтому nonce/hash сюда не подходят: они
    // считаются от точного статичного содержимого). script-src при этом
    // остаётся строгим (только 'self' + nonce) — это где XSS реально опасен.
    res.set('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:; frame-ancestors 'none'`);
    
    res.set('X-Frame-Options', 'DENY');
    res.set('X-Content-Type-Options', 'nosniff');
    // Устаревший заголовок убран, так как он не работает в современных браузерах и может мешать CSP
    // res.set('X-XSS-Protection', '1; mode=block'); 
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    next();
});


app.use(sessionMiddleware);
// Защищённая раздача файлов — только для авторизованных
// 1. Глобально раздача статики (ДО роутов)
app.use(express.static(path.join(__dirname, 'public')));




 

 


 

// 2. Защищённый роут
app.get('/uploads/:filename', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    const filename = path.basename(req.params.filename);
    const filePath = path.join(__dirname, 'uploads', filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'Файл не найден' });
    res.sendFile(filePath);
});







app.get('/link.my', (req, res) => {
    serveIndexWithNonce(req, res);
});

// 8. API МАРШРУТЫ
// Глобальный лимит на все /api/* — защита от спама/абуза (поверх точечных лимитов ниже).
// Устанавливается ДО первого api-роута.
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
    if (password.length < 6)
        return res.json({ success: false, message: 'Пароль должен быть не менее 6 символов' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.json({ success: false, message: 'Введите корректный email' });
 
    try {
        const existing = await dbGet('SELECT id FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (existing) return res.json({ success: false, message: 'Ошибка регистрации. Проверьте введённые данные.' });

        const uniqueCode = await generateUniqueCodeAsync();
        const hashedPassword = await bcrypt.hash(password, 12);

        // Транзакция: пользователь + чат бота + приветственное сообщение — атомарны.
        // Если хоть один INSERT упадёт, откатятся все, не останется «пользователя без бота».
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

// Anonymous registration — без email и пароля, только unique_code + случайное имя.
// Аккаунт «привязан» к текущей сессии/браузеру; восстановить доступ с другого
// устройства нельзя (нет email для сброса). Это и есть «анонимность».
app.post('/api/register/anonymous', registerLimiter, async (req, res) => {
    try {
        const username = await generateAnonymousUsernameAsync();
        const uniqueCode = await generateUniqueCodeAsync();

        // Та же транзакция, что и в обычной регистрации: пользователь + чат бота + приветствие.
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
                [botChatId, userId, 'Привет! Ты вошёл как анонимный гость. Чаты доступны, пока активна эта сессия.', 0, getCurrentTime(), 'read']
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

        res.json({ success: true, message: 'Анонимная регистрация успешна!', user: { id: userId, username, uniqueCode, avatar: '#667EEA', isAnonymous: true } });
    } catch (error) {
        console.error('Anonymous register error:', error);
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

// Login (ИСПРАВЛЕНО: Добавлена регенерация сессии)
app.post('/api/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Введите email и пароль' });
    if (email.length > 254 || password.length > 128) return res.json({ success: false, message: 'Неверный email или пароль' });
 
    try {
        const user = await dbGet('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) return res.json({ success: false, message: 'Неверный email или пароль' });
 
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.json({ success: false, message: 'Неверный email или пароль' });
 
        // Регенерация сессии для защиты от Session Fixation
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
 
// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie('connect.sid');
        if (err) {
            console.error('Logout session destroy error:', err);
        }
        res.json({ success: true });
    });
});
 
// Check auth
app.get('/api/auth', async (req, res) => {
    if (!req.session.userId) return res.json({ authenticated: false });
    try {
        const row = await dbGet('SELECT avatar FROM users WHERE id = $1', [req.session.userId]);
        const avatar = row ? (row.avatar || '') : (req.session.avatar || '');
        req.session.avatar = avatar;
        res.json({ authenticated: true, user: { id: req.session.userId, username: req.session.username, uniqueCode: req.session.uniqueCode, avatar } });
    } catch (error) {
        res.json({ authenticated: false });
    }
});
 
// Get user
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
 
// Update avatar color
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

// ===== E2EE Key Exchange (сервис ①, отдельный Rust-процесс на loopback) =====
// Node здесь только проверяет сессию как обычно и форвардит запрос дальше,
// подставляя X-Internal-Secret и X-User-Id. Сам key-server из интернета
// не виден — единственная точка входа для браузера это роуты ниже.
// Криптографии тут нет: Node просто перекладывает JSON туда-обратно.
async function forwardToKeyServer(req, res, method, internalPath) {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }
    if (!KEY_SERVER_SECRET) {
        return res.status(503).json({ success: false, message: 'Сервис обмена ключами временно недоступен' });
    }

    try {
        const fetchOptions = {
            method,
            headers: {
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
        };
        if (method === 'PUT' || method === 'POST') {
            fetchOptions.headers['Content-Type'] = 'application/json';
            fetchOptions.body = JSON.stringify(req.body || {});
        }

        const upstream = await fetch(`${KEY_SERVER_URL}${internalPath}`, fetchOptions);
        const data = await upstream.json().catch(() => ({ success: false, message: 'Некорректный ответ сервиса ключей' }));
        res.status(upstream.status).json(data);
    } catch (error) {
        console.error('[keys] key-server unreachable:', error.message);
        res.status(502).json({ success: false, message: 'Сервис обмена ключами недоступен' });
    }
}

// Зарегистрировать/заменить identity-ключи (Ed25519 signing + X25519 DH, base64).
// Приватные ключи сюда не попадают — только публичные, генерируются на клиенте.
app.put('/api/keys/identity', (req, res) =>
    forwardToKeyServer(req, res, 'PUT', '/internal/v1/keys/identity'));

// Ротация Signed PreKey (подпись проверяется на key-server).
app.put('/api/keys/signed-prekey', (req, res) =>
    forwardToKeyServer(req, res, 'PUT', '/internal/v1/keys/signed-prekey'));

// Пополнение пула one-time prekeys батчем.
app.post('/api/keys/one-time-prekeys', (req, res) =>
    forwardToKeyServer(req, res, 'POST', '/internal/v1/keys/one-time-prekeys'));

// Сколько one-time prekeys осталось у себя — клиент решает, пора ли пополнять.
app.get('/api/keys/one-time-prekeys/count', (req, res) =>
    forwardToKeyServer(req, res, 'GET', '/internal/v1/keys/one-time-prekeys/count'));

// Забрать bundle собеседника, чтобы начать X3DH-сессию с ним.
app.get('/api/keys/bundle/:targetUserId', (req, res) => {
    const targetUserId = Number.parseInt(req.params.targetUserId, 10);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
        return res.status(400).json({ success: false, message: 'Некорректный targetUserId' });
    }
    return forwardToKeyServer(req, res, 'GET', `/internal/v1/keys/bundle/${targetUserId}`);
});

// Полностью стереть свой ключевой материал (например, перед удалением аккаунта).
app.delete('/api/keys', (req, res) =>
    forwardToKeyServer(req, res, 'DELETE', '/internal/v1/keys'));
// ===== конец E2EE Key Exchange =====

// Get chats
app.get('/api/chats', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    try {
        const chats = await dbAll(`
            SELECT c.id, c.name, c.avatar, c.online, c.is_bot,
                   (SELECT text FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_message,
                   (SELECT time FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_time,
                   (SELECT COUNT(*) FROM messages m WHERE m.chat_id = c.id AND m.sent = 0 AND m.status != 'read') as unread
            FROM chats c
            WHERE c.user_id = $1
            ORDER BY (SELECT MAX(id) FROM messages WHERE chat_id = c.id) DESC NULLS LAST
        `, [req.session.userId]);
        res.json({ success: true, chats: chats.map(c => ({ ...c, unread: Number(c.unread) })) });
    } catch (error) {
        console.error('Get chats error:', error);
        res.json({ success: false, message: 'Ошибка загрузки чатов' });
    }
});
 
// Get messages
app.get('/api/messages/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = req.params.chatId;
    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        const selectQuery = `SELECT m.*, u.username as sender_username, u.avatar as sender_avatar,
                      rt.id as reply_to_id, rt.text as reply_to_text, ru.username as reply_to_sender_username, ru.avatar as reply_to_sender_avatar
               FROM messages m
               JOIN users u ON m.user_id = u.id
               LEFT JOIN messages rt ON m.reply_to_id = rt.id
               LEFT JOIN users ru ON rt.user_id = ru.id
               WHERE m.chat_id = $1 AND m.deleted = 0
               ORDER BY m.id ASC`;

        let messages = await dbAll(selectQuery, [chatId]);

        if (messages.length === 0) {
            await dbRun('UPDATE messages SET status = $1 WHERE chat_id = $2 AND sent = 0', ['read', chatId]);
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

        await dbRun('UPDATE messages SET status = $1 WHERE chat_id = $2 AND sent = 0', ['read', chatId]);
 
        res.json({ success: true, messages, chat });
    } catch (error) {
        console.error('Get messages error:', error);
        res.json({ success: false, message: 'Ошибка загрузки сообщений' });
    }
});
 
// Send message (ИСПРАВЛЕНО: Санитизация ввода)
app.post('/api/messages', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { chatId, text, replyToId } = req.body;
    const replyTo = Number(replyToId) || null;
    if (!text || text.trim() === '' || !chatId) return res.json({ success: false, message: 'Введите текст сообщения' });
    if (text.length > 4000) return res.json({ success: false, message: 'Сообщение не может быть длиннее 4000 символов' });
 
    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        const time = getCurrentTime();
        const socketRoomKey = `chat:${chatId}`;

        const safeText = text.trim();

        const result = await pool.query(
            'INSERT INTO messages (chat_id, user_id, text, message_type, sent, time, status, reply_to_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id',
            [chatId, req.session.userId, safeText, 'text', 1, time, 'sent', replyTo]
        );
        const messageId = result.rows[0].id;

        const fullMessage = await dbGet(
            'SELECT m.*, u.username, u.avatar as user_avatar FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $1',
            [messageId]
        );

        const messageForSocket = { ...fullMessage, sender_username: fullMessage.username, sender_avatar: fullMessage.user_avatar };
        io.to(socketRoomKey).emit('newMessage', messageForSocket);
        res.json({ success: true, message: messageForSocket });

        // Ответ бота
        if (chat.is_bot) {
            const botUserId = req.session.userId;
            setTimeout(async () => {
                // За 1.5с чат могли удалить — проверяем, что он ещё существует и принадлежит тому же юзеру,
                // иначе INSERT ответа упадёт в несуществующий/чужой chat_id (нарушение FK или мусор).
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
                        'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                        [chatId, botUserId, randomResponse, 0, botTime, 'read']
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


// Delete chat
app.delete('/api/chats/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = req.params.chatId;
    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });

        await dbRun('DELETE FROM messages WHERE chat_id = $1', [chatId]);
        await dbRun('DELETE FROM unread WHERE chat_id = $1', [chatId]);
        await dbRun('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete chat error:', error);
        res.json({ success: false, message: 'Ошибка удаления чата' });
    }
});
 
// Edit message
app.put('/api/messages/:messageId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId } = req.params;
    const { text } = req.body;
    if (!text || text.trim() === '') return res.json({ success: false, message: 'Текст не может быть пустым' });
 
    try {
        const message = await dbGet('SELECT * FROM messages WHERE id = $1 AND user_id = $2', [messageId, req.session.userId]);
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        const editedAt = new Date().toISOString();
        await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [text.trim(), editedAt, messageId]);
        res.json({ success: true, edited_at: editedAt });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка редактирования' });
    }
});
 
// Delete message
app.delete('/api/messages/:messageId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId } = req.params;
    try {
        const message = await dbGet('SELECT * FROM messages WHERE id = $1 AND user_id = $2', [messageId, req.session.userId]);
        if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
        await dbRun('UPDATE messages SET deleted = 1 WHERE id = $1', [messageId]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка удаления' });
    }
});
// Загрузка фото/видео/аудио
app.post('/api/messages/file', upload.single('file'), async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    
    const { chatId, text } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ success: false, message: 'Файл не выбран' });
    if (!chatId) return res.status(400).json({ success: false, message: 'Указан чат' });

    // Проверяем magic bytes сохранённого файла
    try {
        const filePath = path.join(__dirname, 'uploads', file.filename);
        const buffer = Buffer.alloc(8);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buffer, 0, 8, 0);
        fs.closeSync(fd);
        if (!checkMagicBytes(buffer, file.mimetype)) {
            fs.unlinkSync(filePath); // удаляем подозрительный файл
            return res.status(400).json({ success: false, message: 'Содержимое файла не соответствует его типу' });
        }
    } catch (magicErr) {
        console.error('Magic bytes check error:', magicErr);
    }

    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.status(404).json({ success: false, message: 'Чат не найден' });

        const time = getCurrentTime();
        const socketRoomKey = `chat:${chatId}`;
        const fileUrl = `/uploads/${file.filename}`;
        const fileType = file.mimetype;
        const sanitizedFileName = path.basename(file.originalname).slice(0, 200).replace(/[<>&"']/g, '');

        const messageType = fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : fileType.startsWith('audio/') ? 'audio' : 'file';
        const messageText = text ? String(text).trim() : (messageType === 'audio' ? 'Голосовое сообщение' : file.originalname);

        const result = await pool.query(
            'INSERT INTO messages (chat_id, user_id, text, file_url, file_name, file_type, message_type, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id',
            [chatId, req.session.userId, messageText, fileUrl, sanitizedFileName, fileType, messageType, 1, time, 'sent']
        );
        const messageId = result.rows[0].id;

        // Берём username и avatar из БД, а не из сессии
        const senderUser = await dbGet('SELECT username, avatar FROM users WHERE id = $1', [req.session.userId]);
        const senderUsername = senderUser ? senderUser.username : '';
        const senderAvatar = senderUser ? (senderUser.avatar || '') : '';

        setTimeout(() => dbRun('UPDATE messages SET status = $1 WHERE id = $2', ['delivered', messageId]), 1000);
        setTimeout(() => dbRun('UPDATE messages SET status = $1 WHERE id = $2', ['read', messageId]), 2000);

        const fileMessage = {
            id: messageId, chat_id: Number(chatId), user_id: req.session.userId,
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


// Проверяет, что пользователь является владельцем чата, к которому
// относится сообщение. Без этой проверки любой авторизованный мог бы ставить
// реакции на чужие сообщения по id.
async function userCanAccessMessage(userId, messageId) {
    const row = await dbGet(
        `SELECT c.user_id AS chat_owner_id
         FROM messages m
         JOIN chats c ON m.chat_id = c.id
         WHERE m.id = $1`,
        [messageId]
    );
    if (!row) return false;
    return row.chat_owner_id === userId;
}

// Add reaction
app.post('/api/reactions', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId, emoji } = req.body;
    if (!messageId || !emoji) return res.json({ success: false, message: 'Параметры отсутствуют' });
    if (typeof emoji !== 'string' || emoji.length > 10) return res.json({ success: false, message: 'Недопустимый emoji' });

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

// Remove reaction
app.delete('/api/reactions/:messageId/:emoji', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const messageId = Number(req.params.messageId);
    const emoji = decodeURIComponent(req.params.emoji);
    if (!Number.isFinite(messageId) || !emoji || emoji.length > 10) {
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

// Search chats and messages
app.get('/api/search', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const query = req.query.q || '';
    if (!query || query.length < 1) return res.json({ success: true, results: [] });
    if (query.length > 100) return res.json({ success: false, message: 'Запрос слишком длинный' });

    // Экранируем спецсимволы LIKE: % и _ имеют особое значение
    const safeTerm = query.replace(/[%_\\]/g, '\\$&');
    const searchTerm = `%${safeTerm}%`;
    try {
        const chats = await dbAll('SELECT id, name, avatar FROM chats WHERE user_id = $1 AND name ILIKE $2 LIMIT 10', [req.session.userId, searchTerm]);
        const messages = await dbAll(
            `SELECT m.id, m.text, m.chat_id, c.name as chat_name FROM messages m 
             JOIN chats c ON m.chat_id = c.id 
             WHERE c.user_id = $1 AND m.text ILIKE $2 AND m.deleted = 0 LIMIT 20`,
            [req.session.userId, searchTerm]
        );
        res.json({ success: true, results: { chats, messages } });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка поиска' });
    }
});
 
// Change password (ИСПРАВЛЕНО: Добавлен Rate Limiting + фикс бага с userId)
app.post('/api/change-password', passwordLimiter, async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) return res.json({ success: false, message: 'Заполните все поля' });
    if (newPassword !== confirmPassword) return res.json({ success: false, message: 'Новые пароли не совпадают' });
    if (newPassword.length < 6) return res.json({ success: false, message: 'Пароль должен быть не менее 6 символов' });

    try {
        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.session.userId]);
        if (!user) return res.json({ success: false, message: 'Пользователь не найден' });
        // Анонимные аккаунты не имеют пароля
        if (!user.password) return res.json({ success: false, message: 'У этого аккаунта нет пароля (анонимный режим)' });
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) return res.json({ success: false, message: 'Неверный текущий пароль' });
        const hashedPassword = await bcrypt.hash(newPassword, 12);

        // ВАЖНО: сохраняем userId ДО destroy(), потому что после destroy()
        // req.session.userId становится undefined и UPDATE падал в никуда (WHERE id = NULL).
        const userId = req.session.userId;

        // Сначала обновляем пароль (пока сессия ещё жива и userId валиден), потом уничтожаем сессию.
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


// Обработка ошибок загрузки файлов
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
    // Глобальный обработчик — скрываем детали ошибки от клиента
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

// Вспомогательная функция: отдаёт index.html с подставленным CSP-nonce
function serveIndexWithNonce(req, res) {
    const nonce = res.locals.cspNonce || '';
    const indexPath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(indexPath, 'utf8', (err, html) => {
        if (err) return res.status(500).send('Server error');
        // Вставляем nonce во все теги <script> и <link rel="stylesheet"> / <style>
        const injected = html
            .replace(/<script(?![^>]*\bnonce=)/g, `<script nonce="${nonce}"`)
            .replace(/<style(?![^>]*\bnonce=)/g, `<style nonce="${nonce}"`)
            .replace(/<link([^>]*rel=["']stylesheet["'][^>]*)(?![^>]*\bnonce=)>/g, `<link$1 nonce="${nonce}">`);
        res.setHeader('Content-Type', 'text/html');
        res.send(injected);
    });
}

app.get('*', (req, res) => {
    serveIndexWithNonce(req, res);
});
 
server.listen(PORT, HOST, () => {
    const addresses = getLocalAddresses();
    console.log('Сервер запущен на следующих адресах:');
    addresses.forEach(addr => {
        console.log(`Доступен в сети: https://${addr}:${PORT}`);
    });
    console.log(`  https://localhost:${PORT}`);
});