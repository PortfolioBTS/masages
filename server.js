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
const rateLimit = require('express-rate-limit');
const pgSession = require('connect-pg-simple')(session);
const cookieParser = require('cookie-parser');


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
    return true; // если тип не в списке проверки — разрешаем (уже отфильтровано по MIME)
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

io.use((socket, next) => {
    const ip = socket.handshake.address;
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
 
// 3. ПОДКЛЮЧЕНИЕ К POSTGRESQL

// Если установлена переменная DUMP_CA=true — выводим сертификат в лог и завершаем работу
async function maybeDumpCa() {
    if (process.env.DUMP_CA !== 'true') return;
    const tls = require('tls');
    const net = require('net');
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) { console.error('DATABASE_URL не задан'); process.exit(1); }
    const parsed = new URL(dbUrl);
    const host = parsed.hostname;
    const port = parseInt(parsed.port) || 5432;
    console.log(`[DUMP_CA] Подключаемся к ${host}:${port} для получения сертификата...`);
    await new Promise((resolve, reject) => {
        const socket = net.createConnection(port, host, () => {
            socket.write(Buffer.from([0x00,0x00,0x00,0x08,0x04,0xd2,0x16,0x2f]));
        });
        socket.once('data', (data) => {
            if (data[0] !== 0x53) { reject(new Error('Сервер не поддерживает SSL')); return; }
            const tlsSocket = tls.connect({ socket, host, rejectUnauthorized: false }, () => {
                const cert = tlsSocket.getPeerCertificate(true);
                let root = cert;
                const seen = new Set();
                while (root.issuerCertificate && root.issuerCertificate !== root) {
                    if (seen.has(root.fingerprint)) break;
                    seen.add(root.fingerprint);
                    root = root.issuerCertificate;
                }
                const pem = [
                    '-----BEGIN CERTIFICATE-----',
                    root.raw.toString('base64').match(/.{1,64}/g).join('\n'),
                    '-----END CERTIFICATE-----'
                ].join('\n');
                console.log('\n[DUMP_CA] ========= СКОПИРУЙ ЭТО В ПЕРЕМЕННУЮ DB_CA_CERT =========');
                console.log(pem);
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

    // Если задан CA-сертификат — используем его (самый безопасный вариант)
    if (process.env.DB_CA_CERT) {
        console.log('[SSL] Используем кастомный CA-сертификат из DB_CA_CERT');
        return { rejectUnauthorized: true, ca: process.env.DB_CA_CERT };
    }

    // Разрешаем self-signed через явную переменную
    if (process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false') {
        console.warn('[SSL] rejectUnauthorized=false — TLS шифруется, но сертификат не проверяется.');
        return { rejectUnauthorized: false };
    }

    return { rejectUnauthorized: true };
})();

// Запускаем дамп сертификата до создания пула (если DUMP_CA=true)
await maybeDumpCa().catch(err => { console.error('[DUMP_CA] Ошибка:', err.message); process.exit(1); });

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
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id);`);

 
    console.log('База данных инициализирована');
}
 
initDatabase().catch(err => {
    console.error('Ошибка инициализации БД:', err);
    process.exit(1);
});
 
// 5. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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
            // Проверяем принадлежность комнаты/чата текущему пользователю
            if (roomKey.startsWith('room:')) {
                const roomId = parseInt(roomKey.slice(5), 10);
                if (!Number.isFinite(roomId)) return;
                const participant = await dbGet(
                    'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2',
                    [roomId, userId]
                );
                if (!participant) return; // Пользователь не участник этой комнаты
            } else if (roomKey.startsWith('chat:')) {
                const chatId = parseInt(roomKey.slice(5), 10);
                if (!Number.isFinite(chatId)) return;
                const chat = await dbGet(
                    'SELECT id FROM chats WHERE id = $1 AND user_id = $2',
                    [chatId, userId]
                );
                if (!chat) return; // Чат не принадлежит пользователю
            } else {
                return; // Неизвестный формат ключа
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
    res.set('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:; frame-ancestors 'none'`);
    
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
 
// Register (ИСПРАВЛЕНО: Добавлен Rate Limiting)
const generalLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 минут
    max: 20,
    message: { success: false, message: 'Слишком много запросов. Подождите.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Применяем лимитер глобально ко всем /api/ маршрутам
app.use('/api/', generalLimiter);

app.post('/api/register', generalLimiter, async (req, res) => {
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
 
        const userResult = await pool.query(
            'INSERT INTO users (unique_code, username, email, password, avatar) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [uniqueCode, username, email, hashedPassword, '#667EEA']
        );
        const userId = userResult.rows[0].id;
 
        // Создать бота для нового пользователя
        const botResult = await pool.query(
            'INSERT INTO chats (user_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [userId, 'Бот Помощник', 'Б', 1, 1]
        );
        const botChatId = botResult.rows[0].id;
        await pool.query(
            'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [botChatId, userId, 'Привет! Я бот-помощник. Чем могу помочь?', 0, getCurrentTime(), 'read']
        );
 
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
 
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Слишком много попыток. Подождите 15 минут.' },
    standardHeaders: true,
    legacyHeaders: false,
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
 
// Get chats
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
 
// Get messages
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
        const roomId = chat.room_id || null;
        const socketRoomKey = getSocketRoomKey(chatId, roomId);
        
        
        const safeText = text.trim();
 
        const result = await pool.query(
            'INSERT INTO messages (chat_id, room_id, user_id, text, message_type, sent, time, status, reply_to_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
            [chatId, roomId, req.session.userId, safeText, 'text', 1, time, 'sent', replyTo]
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
            setTimeout(async () => {
                const botResponses = ['Интересный вопрос! Расскажите подробнее.', 'Я получил ваше сообщение!', 'Хмм, дайте подумать...', 'Отличное сообщение! Продолжайте.', 'Я бот, но стараюсь быть полезным!', 'Можете уточнить, что именно вас интересует?'];
                const randomResponse = botResponses[Math.floor(Math.random() * botResponses.length)];
                const botTime = getCurrentTime();
                try {
                    const botResult = await pool.query(
                        'INSERT INTO messages (chat_id, room_id, user_id, text, sent, time, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
                        [chatId, roomId, req.session.userId, randomResponse, 0, botTime, 'read']
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
 

 
// Create chat
app.post('/api/chats', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { name } = req.body;
    if (!name) return res.json({ success: false, message: 'Введите имя чата' });
    if (name.length > 64) return res.json({ success: false, message: 'Название чата не может быть длиннее 64 символов' });
 
    const avatar = name.charAt(0).toUpperCase();
    try {
        const roomCode = await generateInviteCodeAsync();
        const roomResult = await pool.query('INSERT INTO rooms (name, code) VALUES ($1, $2) RETURNING id', [name, roomCode]);
        const roomId = roomResult.rows[0].id;
        await pool.query('INSERT INTO room_participants (room_id, user_id) VALUES ($1, $2)', [roomId, req.session.userId]);
        const chatResult = await pool.query(
            'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [req.session.userId, roomId, name, avatar, 0, 0]
        );
        res.json({ success: true, chat: { id: chatResult.rows[0].id, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
    } catch (error) {
        console.error('Create chat error:', error);
        res.json({ success: false, message: 'Ошибка создания чата' });
    }
});
 
// Get invite code
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
 
// Join chat by code
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
 
// Delete chat
app.delete('/api/chats/:chatId', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const chatId = req.params.chatId;
    try {
        const chat = await dbGet('SELECT * FROM chats WHERE id = $1 AND user_id = $2', [chatId, req.session.userId]);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
 
        if (chat.room_id) {
            // Удаляем запись участника
            await dbRun('DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, req.session.userId]);
            // Проверяем, остались ли ещё участники в комнате
            const remaining = await dbGet('SELECT COUNT(*) as cnt FROM room_participants WHERE room_id = $1', [chat.room_id]);
            if (!remaining || Number(remaining.cnt) === 0) {
                // Последний участник вышел — удаляем сообщения и комнату
                await dbRun('DELETE FROM messages WHERE room_id = $1', [chat.room_id]);
                await dbRun('DELETE FROM rooms WHERE id = $1', [chat.room_id]);
            }
        } else {
            await dbRun('DELETE FROM messages WHERE chat_id = $1', [chatId]);
        }
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
app.post('/api/messages/file', generalLimiter, upload.single('file'), async (req, res) => {
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

        // Берём username и avatar из БД, а не из сессии
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

 
// Add reaction
app.post('/api/reactions', async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { messageId, emoji } = req.body;
    if (!messageId || !emoji) return res.json({ success: false, message: 'Параметры отсутствуют' });
    if (typeof emoji !== 'string' || emoji.length > 10) return res.json({ success: false, message: 'Недопустимый emoji' });
 
    try {
        await pool.query('INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [messageId, req.session.userId, emoji]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка добавления реакции' });
    }
});
 
// Remove reaction
app.get('/api/search', generalLimiter, async (req, res) => {
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
 
// Change password (ИСПРАВЛЕНО: Добавлен Rate Limiting)
app.post('/api/change-password', generalLimiter, async (req, res) => {
    if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) return res.json({ success: false, message: 'Заполните все поля' });
    if (newPassword !== confirmPassword) return res.json({ success: false, message: 'Новые пароли не совпадают' });
    if (newPassword.length < 6) return res.json({ success: false, message: 'Пароль должен быть не менее 6 символов' });
 
    try {
        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.session.userId]);
        if (!user) return res.json({ success: false, message: 'Пользователь не найден' });
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) return res.json({ success: false, message: 'Неверный текущий пароль' });
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        // Сначала уничтожаем сессию, потом обновляем пароль
        req.session.destroy(async (err) => {
            res.clearCookie('connect.sid');
            if (err) console.error('Session destroy error on password change:', err);
            try {
                await dbRun('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.session.userId]);
            } catch (dbErr) {
                console.error('Password update error:', dbErr);
            }
            res.json({ success: true, message: 'Пароль успешно изменён. Войдите заново.' });
        });
    } catch (error) {
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