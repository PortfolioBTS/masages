const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Chats table
    db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        avatar TEXT NOT NULL,
        online INTEGER DEFAULT 0,
        is_bot INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        sent INTEGER DEFAULT 1,
        time TEXT NOT NULL,
        status TEXT DEFAULT 'sent',
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Unread messages table
    db.run(`CREATE TABLE IF NOT EXISTS unread (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        count INTEGER DEFAULT 0,
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
});

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));
app.use(session({
    secret: 'messenger-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

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
                'INSERT INTO users (unique_code, username, email, password) VALUES (?, ?, ?, ?)',
                [uniqueCode, username, email, hashedPassword],
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

                    res.json({ 
                        success: true, 
                        message: 'Регистрация успешна!',
                        user: { id: userId, username, uniqueCode }
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

        res.json({ 
            success: true, 
            message: 'Вход выполнен!',
            user: { id: user.id, username: user.username, uniqueCode: user.unique_code }
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
                uniqueCode: req.session.uniqueCode
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

    db.get('SELECT id, unique_code, username, email, created_at FROM users WHERE id = ?', 
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
                    email: user.email,
                    createdAt: user.created_at
                }
            });
        }
    );
});

// Get chats
app.get('/api/chats', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    db.all(`
        SELECT c.id, c.name, c.avatar, c.online, c.is_bot,
               (SELECT text FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_message,
               (SELECT time FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_time,
               (SELECT COUNT(*) FROM messages m 
                JOIN chats ch ON m.chat_id = ch.id 
                WHERE ch.id = c.id AND m.sent = 0 AND m.status != 'read') as unread
        FROM chats c
        WHERE c.user_id = ?
        ORDER BY (SELECT MAX(id) FROM messages WHERE chat_id = c.id) DESC
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

        db.all('SELECT * FROM messages WHERE chat_id = ? ORDER BY id ASC', [chatId], (err, messages) => {
            if (err) {
                return res.json({ success: false, message: 'Ошибка загрузки сообщений' });
            }

            // Mark messages as read
            db.run('UPDATE messages SET status = ? WHERE chat_id = ? AND sent = 0', ['read', chatId]);

            res.json({ success: true, messages, chat });
        });
    });
});

// Send message
app.post('/api/messages', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const { chatId, text } = req.body;

    if (!text || !chatId) {
        return res.json({ success: false, message: 'Введите текст сообщения' });
    }

    // Verify chat belongs to user
    db.get('SELECT * FROM chats WHERE id = ? AND user_id = ?', [chatId, req.session.userId], (err, chat) => {
        if (err || !chat) {
            return res.json({ success: false, message: 'Чат не найден' });
        }

        const time = getCurrentTime();

        db.run(
            'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES (?, ?, ?, ?, ?, ?)',
            [chatId, req.session.userId, text, 1, time, 'sent'],
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
                            'INSERT INTO messages (chat_id, user_id, text, sent, time, status) VALUES (?, ?, ?, ?, ?, ?)',
                            [chatId, req.session.userId, randomResponse, 0, botTime, 'read']
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
                    message: { id: messageId, text, sent: true, time, status: 'sent' }
                });
            }
        );
    });
});

// Create new chat
app.post('/api/chats', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, message: 'Не авторизован' });
    }

    const { name } = req.body;

    if (!name) {
        return res.json({ success: false, message: 'Введите имя чата' });
    }

    const avatar = name.charAt(0).toUpperCase();

    db.run(
        'INSERT INTO chats (user_id, name, avatar, online, is_bot) VALUES (?, ?, ?, ?, ?)',
        [req.session.userId, name, avatar, 0, 0],
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'Ошибка создания чата' });
            }
            res.json({ 
                success: true, 
                chat: { id: this.lastID, name, avatar, online: 0, is_bot: 0 }
            });
        }
    );
});

// Helper function
function getCurrentTime() {
    const now = new Date();
    return `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
}

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});