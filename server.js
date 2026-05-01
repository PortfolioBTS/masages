const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

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

// Initialize SQLite database
const db = new sqlite3.Database('./messenger.db', (err) => {
    if (err) console.error('Database error:', err.message);
    else console.log('Connected to SQLite database');
});

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        unique_code TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatar TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Chats table
    db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        room_id INTEGER,
        name TEXT NOT NULL,
        avatar TEXT NOT NULL,
        online INTEGER DEFAULT 0,
        is_bot INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (room_id) REFERENCES rooms(id)
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        room_id INTEGER,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        file_url TEXT,
        file_name TEXT,
        file_type TEXT,
        message_type TEXT DEFAULT 'text',
        sent INTEGER DEFAULT 1,
        time TEXT NOT NULL,
        status TEXT DEFAULT 'sent',
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (room_id) REFERENCES rooms(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Migrate existing messages table if needed
    db.get("PRAGMA table_info(messages)", (err, row) => {
        if (!err && row) {
            db.all("PRAGMA table_info(messages)", (err, columns) => {
                if (!err) {
                    if (!columns.some(col => col.name === 'file_url')) {
                        db.run('ALTER TABLE messages ADD COLUMN file_url TEXT');
                    }
                    if (!columns.some(col => col.name === 'file_name')) {
                        db.run('ALTER TABLE messages ADD COLUMN file_name TEXT');
                    }
                    if (!columns.some(col => col.name === 'file_type')) {
                        db.run('ALTER TABLE messages ADD COLUMN file_type TEXT');
                    }
                    if (!columns.some(col => col.name === 'message_type')) {
                        db.run("ALTER TABLE messages ADD COLUMN message_type TEXT DEFAULT 'text'");
                    }
                }
            });
        }
    });

    // Unread messages table
    db.run(`CREATE TABLE IF NOT EXISTS unread (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        count INTEGER DEFAULT 0,
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Rooms for shared chats
    db.run(`CREATE TABLE IF NOT EXISTS rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Room participants
    db.run(`CREATE TABLE IF NOT EXISTS room_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (room_id) REFERENCES rooms(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.get("PRAGMA table_info(chats)", (err, row) => {
        if (!err && row) {
            db.all("PRAGMA table_info(chats)", (err, columns) => {
                if (!err && !columns.some(col => col.name === 'room_id')) {
                    db.run('ALTER TABLE chats ADD COLUMN room_id INTEGER');
                }
            });
        }
    });

    db.get("PRAGMA table_info(users)", (err, row) => {
        if (!err && row) {
            db.all("PRAGMA table_info(users)", (err, columns) => {
                if (!err && !columns.some(col => col.name === 'avatar')) {
                    db.run("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''");
                }
            });
        }
    });

    db.get("PRAGMA table_info(messages)", (err, row) => {
        if (!err && row) {
            db.all("PRAGMA table_info(messages)", (err, columns) => {
                if (!err && !columns.some(col => col.name === 'room_id')) {
                    db.run('ALTER TABLE messages ADD COLUMN room_id INTEGER');
                }
            });
        }
    });
});

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const upload = multer({ dest: path.join(__dirname, 'uploads') });

app.use(session({
    secret: 'messenger-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Simple public link route
app.get('/link.my', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Fallback for other non-API routes
app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) {
        return next();
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Generate unique 8-character code
function generateUniqueCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// Check if code is unique, if not generate again
function generateUniqueCodeAsync() {
    return new Promise((resolve, reject) => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        
        function tryGenerate(attempts = 0) {
            if (attempts > 100) {
                reject(new Error('Could not generate unique code'));
                return;
            }
            
            let code = '';
            for (let i = 0; i < 8; i++) {
                code += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            
            db.get('SELECT id FROM users WHERE unique_code = ?', [code], (err, row) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (row) {
                    tryGenerate(attempts + 1);
                } else {
                    resolve(code);
                }
            });
        }
        
        tryGenerate();
    });
}

// Generate invite code for shared chat rooms
function generateInviteCode() {
    const chars = '0123456789';
    let code = '';
    for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

function generateInviteCodeAsync() {
    return new Promise((resolve, reject) => {
        function tryGenerate(attempts = 0) {
            if (attempts > 100) {
                reject(new Error('Could not generate invite code'));
                return;
            }

            const code = generateInviteCode();
            db.get('SELECT id FROM rooms WHERE code = ?', [code], (err, row) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (row) {
                    tryGenerate(attempts + 1);
                } else {
                    resolve(code);
                }
            });
        }

        tryGenerate();
    });
}

// Register endpoint
app.post('/api/register', async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // Validation
    if (!username || !email || !password || !confirmPassword) {
        return res.json({ success: false, message: 'Заполните все поля' });
    }

    if (password !== confirmPassword) {
        return res.json({ success: false, message: 'Пароли не совпадают' });
    }

    if (password.length < 6) {
        return res.json({ success: false, message: 'Пароль должен быть не менее 6 символов' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.json({ success: false, message: 'Введите корректный email' });
    }

    try {
        // Check if user exists
        db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
            if (err) {
                return res.json({ success: false, message: 'Ошибка базы данных' });
            }

            if (row) {
                return res.json({ success: false, message: 'Пользователь с таким email или именем уже существует' });
            }

            // Generate unique code
            const uniqueCode = await generateUniqueCodeAsync();

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert user
            db.run(
                'INSERT INTO users (unique_code, username, email, password, avatar) VALUES (?, ?, ?, ?, ?)',
                [uniqueCode, username, email, hashedPassword, ''],
                function(err) {
                    if (err) {
                        return res.json({ success: false, message: 'Ошибка при создании пользователя' });
                    }

                    const userId = this.lastID;

                    // Create bot chat for new user
                    db.run(
                        'INSERT INTO chats (user_id, name, avatar, online, is_bot) VALUES (?, ?, ?, ?, ?)',
                        [userId, 'Бот Помощник', 'Б', 1, 1],
                        function(err) {
                            if (!err) {
                                const botChatId = this.lastID;
                                db.run(
                                    'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES (?, ?, ?, ?, ?, ?)',
                                    [botChatId, userId, 'Привет! Я бот-помощник. Чем могу помочь?', 0, getCurrentTime(), 'read']
                                );
                            }
                        }
                    );

                    // Set session
                    req.session.userId = userId;
                    req.session.username = username;
                    req.session.uniqueCode = uniqueCode;
                    req.session.avatar = '';

                    res.json({ 
                        success: true, 
                        message: 'Регистрация успешна!',
                        user: { id: userId, username, uniqueCode, avatar: '' }
                    });
                }
            );
        });
    } catch (error) {
        res.json({ success: false, message: 'Ошибка сервера' });
    }
});

// Login endpoint
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'Введите email и пароль' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.json({ success: false, message: 'Ошибка базы данных' });
        }

        if (!user) {
            return res.json({ success: false, message: 'Пользователь не найден' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.json({ success: false, message: 'Неверный пароль' });
        }

        // Set session
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.uniqueCode = user.unique_code;
        req.session.avatar = user.avatar || '';

        res.json({ 
            success: true, 
            message: 'Вход выполнен!',
            user: { id: user.id, username: user.username, uniqueCode: user.unique_code, avatar: user.avatar || '' }
        });
    });
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check auth status
app.get('/api/auth', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            authenticated: true, 
            user: { 
                id: req.session.userId, 
                username: req.session.username,
                uniqueCode: req.session.uniqueCode,
                avatar: req.session.avatar || ''
            } 
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Get user data
app.get('/api/user', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false });
    }

    db.get('SELECT id, unique_code, username, email, avatar, created_at FROM users WHERE id = ?', 
        [req.session.userId], 
        (err, user) => {
            if (err || !user) {
                return res.json({ success: false });
            }
            res.json({ 
                success: true, 
                user: {
                    id: user.id,
                    uniqueCode: user.unique_code,
                    username: user.username,
                    avatar: user.avatar || '',
                    email: user.email,
                    createdAt: user.created_at
                }
            });
        }
    );
});

// Update current user's avatar
app.post('/api/user/avatar', upload.single('avatar'), (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const file = req.file;
    if (!file) {
        return res.json({ success: false, message: 'Файл не выбран' });
    }

    const sanitizedAvatar = `/uploads/${file.filename}`;

    db.run('UPDATE users SET avatar = ? WHERE id = ?', [sanitizedAvatar, req.session.userId], function(err) {
        if (err) {
            return res.json({ success: false, message: 'Ошибка обновления аватара' });
        }

        req.session.avatar = sanitizedAvatar;
        res.json({ success: true, avatar: sanitizedAvatar });
    });
});

// Get chats
app.get('/api/chats', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    db.all(`
        SELECT c.id, c.name, c.avatar, c.online, c.is_bot, c.room_id, r.code as invite_code,
               (SELECT text FROM messages WHERE ((c.room_id IS NOT NULL AND room_id = c.room_id) OR (c.room_id IS NULL AND chat_id = c.id)) ORDER BY id DESC LIMIT 1) as last_message,
               (SELECT time FROM messages WHERE ((c.room_id IS NOT NULL AND room_id = c.room_id) OR (c.room_id IS NULL AND chat_id = c.id)) ORDER BY id DESC LIMIT 1) as last_time,
               (SELECT COUNT(*) FROM messages m WHERE ((c.room_id IS NOT NULL AND m.room_id = c.room_id) OR (c.room_id IS NULL AND m.chat_id = c.id)) AND m.sent = 0 AND m.status != 'read') as unread
        FROM chats c
        LEFT JOIN rooms r ON c.room_id = r.id
        WHERE c.user_id = ?
        ORDER BY (SELECT MAX(id) FROM messages WHERE ((c.room_id IS NOT NULL AND room_id = c.room_id) OR (c.room_id IS NULL AND chat_id = c.id))) DESC
    `, [req.session.userId], (err, chats) => {
        if (err) {
            return res.json({ success: false, message: 'Ошибка загрузки чатов' });
        }
        res.json({ success: true, chats });
    });
});

// Get messages for a chat
app.get('/api/messages/:chatId', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const chatId = req.params.chatId;

    // Verify chat belongs to user
    db.get('SELECT * FROM chats WHERE id = ? AND user_id = ?', [chatId, req.session.userId], (err, chat) => {
        if (err || !chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const selectQuery = chat.room_id
            ? 'SELECT m.*, u.username as sender_username, u.avatar as sender_avatar FROM messages m JOIN users u ON m.user_id = u.id WHERE m.room_id = ? ORDER BY m.id ASC'
            : 'SELECT m.*, u.username as sender_username, u.avatar as sender_avatar FROM messages m JOIN users u ON m.user_id = u.id WHERE m.chat_id = ? ORDER BY m.id ASC';
        const selectParam = chat.room_id || chatId;

        db.all(selectQuery, [selectParam], (err, messages) => {
            if (err) {
                return res.json({ success: false, message: 'Ошибка загрузки сообщений' });
            }

            const updateQuery = chat.room_id
                ? 'UPDATE messages SET status = ? WHERE room_id = ? AND sent = 0'
                : 'UPDATE messages SET status = ? WHERE chat_id = ? AND sent = 0';

            db.run(updateQuery, ['read', selectParam]);

            res.json({ success: true, messages, chat });
        });
    });
});

// Send text message
app.post('/api/messages', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const { chatId, text } = req.body;

    if ((!text || text.trim() === '') || !chatId) {
        return res.json({ success: false, message: 'Введите текст сообщения' });
    }

    // Verify chat belongs to user
    db.get('SELECT * FROM chats WHERE id = ? AND user_id = ?', [chatId, req.session.userId], (err, chat) => {
        if (err || !chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const time = getCurrentTime();
        const roomId = chat.room_id || null;

        db.run(
            'INSERT INTO messages (chat_id, room_id, user_id, text, message_type, sent, time, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [chatId, roomId, req.session.userId, text.trim(), 'text', 1, time, 'sent'],
            function(err) {
                if (err) {
                    return res.json({ success: false, message: 'Ошибка отправки' });
                }

                const messageId = this.lastID;

                // Bot response for bot chat
                if (chat.is_bot) {
                    setTimeout(() => {
                        const botResponses = [
                            'Интересный вопрос! Расскажите подробнее.',
                            'Я получил ваше сообщение!',
                            'Хмм, дайте подумать...',
                            'Отличное сообщение! Продолжайте.',
                            'Я бот, но стараюсь быть полезным!',
                            'Можете уточнить, что именно вас интересует?'
                        ];
                        const randomResponse = botResponses[Math.floor(Math.random() * botResponses.length)];
                        const botTime = getCurrentTime();

                        db.run(
                            'INSERT INTO messages (chat_id, room_id, user_id, text, sent, time, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                            [chatId, roomId, req.session.userId, randomResponse, 0, botTime, 'read']
                        );
                    }, 1500);
                }

                // Simulate status updates
                setTimeout(() => {
                    db.run('UPDATE messages SET status = ? WHERE id = ?', ['delivered', messageId]);
                }, 1000);

                setTimeout(() => {
                    db.run('UPDATE messages SET status = ? WHERE id = ?', ['read', messageId]);
                }, 2000);

                res.json({ 
                    success: true, 
                    message: { id: messageId, text: text.trim(), message_type: 'text', sent: true, time, status: 'sent' }
                });
            }
        );
    });
});

// Upload file message
app.post('/api/messages/file', upload.single('file'), (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const { chatId, text } = req.body;
    const file = req.file;

    if (!file || !chatId) {
        return res.json({ success: false, message: 'Файл или чат не выбраны' });
    }

    db.get('SELECT * FROM chats WHERE id = ? AND user_id = ?', [chatId, req.session.userId], (err, chat) => {
        if (err || !chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const time = getCurrentTime();
        const roomId = chat.room_id || null;
        const fileUrl = `/uploads/${file.filename}`;
        const fileType = file.mimetype;
        const fileName = file.originalname;
        const messageType = fileType.startsWith('image/') ? 'image'
            : fileType.startsWith('video/') ? 'video'
            : fileType.startsWith('audio/') ? 'audio'
            : 'file';
        const messageText = text ? String(text).trim() : (messageType === 'audio' ? 'Голосовое сообщение' : fileName);

        db.run(
            'INSERT INTO messages (chat_id, room_id, user_id, text, file_url, file_name, file_type, message_type, sent, time, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [chatId, roomId, req.session.userId, messageText, fileUrl, fileName, fileType, messageType, 1, time, 'sent'],
            function(err) {
                if (err) {
                    return res.json({ success: false, message: 'Ошибка отправки файла' });
                }

                const messageId = this.lastID;

                // Simulate status updates
                setTimeout(() => {
                    db.run('UPDATE messages SET status = ? WHERE id = ?', ['delivered', messageId]);
                }, 1000);

                setTimeout(() => {
                    db.run('UPDATE messages SET status = ? WHERE id = ?', ['read', messageId]);
                }, 2000);

                res.json({
                    success: true,
                    message: {
                        id: messageId,
                        text: messageText,
                        file_url: fileUrl,
                        file_name: fileName,
                        file_type: fileType,
                        message_type: messageType,
                        sent: true,
                        time,
                        status: 'sent'
                    }
                });
            }
        );
    });
});

// Create new chat with invite room code
app.post('/api/chats', async (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const { name } = req.body;

    if (!name) {
        return res.json({ success: false, message: 'Введите имя чата' });
    }

    const avatar = name.charAt(0).toUpperCase();

    try {
        const roomCode = await generateInviteCodeAsync();

        db.run(
            'INSERT INTO rooms (name, code) VALUES (?, ?)',
            [name, roomCode],
            function(err) {
                if (err) {
                    return res.json({ success: false, message: 'Ошибка создания комнаты' });
                }

                const roomId = this.lastID;

                db.run(
                    'INSERT INTO room_participants (room_id, user_id) VALUES (?, ?)',
                    [roomId, req.session.userId],
                    function(err) {
                        if (err) {
                            return res.json({ success: false, message: 'Ошибка добавления участника комнаты' });
                        }

                        db.run(
                            'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES (?, ?, ?, ?, ?, ?)',
                            [req.session.userId, roomId, name, avatar, 0, 0],
                            function(err) {
                                if (err) {
                                    return res.json({ success: false, message: 'Ошибка создания чата' });
                                }
                                res.json({ 
                                    success: true, 
                                    chat: { id: this.lastID, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode }
                                });
                            }
                        );
                    }
                );
            }
        );
    } catch (error) {
        res.json({ success: false, message: 'Ошибка создания кода приглашения' });
    }
});

// Get invite code for current room chat
app.get('/api/chats/invite/:chatId', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const chatId = req.params.chatId;

    db.get('SELECT room_id FROM chats WHERE id = ? AND user_id = ?', [chatId, req.session.userId], (err, chat) => {
        if (err || !chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        if (!chat.room_id) {
            return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
        }

        db.get('SELECT code FROM rooms WHERE id = ?', [chat.room_id], (err, room) => {
            if (err || !room) {
                return res.json({ success: false, message: 'Код не найден' });
            }
            res.json({ success: true, code: room.code });
        });
    });
});

// Join shared chat by invite code
app.post('/api/chats/join', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const { code } = req.body;

    if (!code) {
        return res.json({ success: false, message: 'Введите код приглашения' });
    }

    db.get('SELECT * FROM rooms WHERE code = ?', [code], (err, room) => {
        if (err || !room) {
            return res.json({ success: false, message: 'Чат по этому коду не найден' });
        }

        db.get('SELECT id FROM room_participants WHERE room_id = ? AND user_id = ?', [room.id, req.session.userId], (err, participant) => {
            if (err) {
                return res.json({ success: false, message: 'Ошибка проверки доступа к чату' });
            }

            if (participant) {
                db.get('SELECT id FROM chats WHERE room_id = ? AND user_id = ?', [room.id, req.session.userId], (err, chat) => {
                    if (err || !chat) {
                        return res.json({ success: false, message: 'Чат уже добавлен' });
                    }
                    return res.json({ success: true, chat: { id: chat.id } });
                });
                return;
            }

            // Determine chat name and avatar using room name or first other participant
            db.get(
                'SELECT u.username FROM users u JOIN room_participants rp ON u.id = rp.user_id WHERE rp.room_id = ? AND u.id != ? LIMIT 1',
                [room.id, req.session.userId],
                (err, otherUser) => {
                    const chatName = otherUser ? `Чат с ${otherUser.username}` : room.name;
                    const avatar = chatName.charAt(0).toUpperCase();

                    db.run('INSERT INTO room_participants (room_id, user_id) VALUES (?, ?)', [room.id, req.session.userId], function(err) {
                        if (err) {
                            return res.json({ success: false, message: 'Ошибка добавления в чат' });
                        }

                        db.run(
                            'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot) VALUES (?, ?, ?, ?, ?, ?)',
                            [req.session.userId, room.id, chatName, avatar, 0, 0],
                            function(err) {
                                if (err) {
                                    return res.json({ success: false, message: 'Ошибка создания чата' });
                                }
                                res.json({ success: true, chat: { id: this.lastID, name: chatName, avatar, online: 0, is_bot: 0, room_id: room.id, invite_code: room.code } });
                            }
                        );
                    });
                }
            );
        });
    });
});

// Helper function
function getCurrentTime() {
    const now = new Date();
    return `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
}

// Start server
app.listen(PORT, HOST, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    const addresses = getLocalAddresses();
    if (addresses.length > 0) {
        console.log(`Accessible on local network at: ${addresses.map(ip => `http://${ip}:${PORT}`).join(', ')}`);
    }
});