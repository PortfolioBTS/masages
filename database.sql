-- =====================================================
-- МЕССЕНДЖЕР - SQL СХЕМА БАЗЫ ДАННЫХ
-- =====================================================

-- Таблица пользователей
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_code TEXT UNIQUE NOT NULL,    -- Уникальный код (8 символов: A-Z, a-z, 0-9)
    username TEXT UNIQUE NOT NULL,       -- Имя пользователя
    email TEXT UNIQUE NOT NULL,          -- Email
    password TEXT NOT NULL,              -- Хэшированный пароль
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Таблица чатов
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,            -- Ссылка на пользователя
    name TEXT NOT NULL,                  -- Название чата
    avatar TEXT NOT NULL,                -- Аватар (первая буква имени)
    online INTEGER DEFAULT 0,            -- Онлайн статус (0/1)
    is_bot INTEGER DEFAULT 0,            -- Является ли ботом (0/1)
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Таблица сообщений
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,            -- Ссылка на чат
    user_id INTEGER NOT NULL,            -- Ссылка на пользователя
    text TEXT NOT NULL,                  -- Текст сообщения
    sent INTEGER DEFAULT 1,              -- Отправлено пользователем (1) или получено (0)
    time TEXT NOT NULL,                  -- Время отправки (ЧЧ:ММ)
    status TEXT DEFAULT 'sent',          -- Статус: sent, delivered, read
    FOREIGN KEY (chat_id) REFERENCES chats(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Таблица непрочитанных сообщений
CREATE TABLE IF NOT EXISTS unread (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    count INTEGER DEFAULT 0,
    FOREIGN KEY (chat_id) REFERENCES chats(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- =====================================================
-- ПРИМЕРЫ ЗАПРОСОВ
-- =====================================================

-- Получить всех пользователей:
-- SELECT * FROM users;

-- Получить все чаты пользователя:
-- SELECT * FROM chats WHERE user_id = 1;

-- Получить все сообщения чата:
-- SELECT * FROM messages WHERE chat_id = 1 ORDER BY id ASC;

-- Получить последнее сообщение каждого чата:
-- SELECT c.id, c.name, c.avatar, c.online, c.is_bot,
--        (SELECT text FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_message,
--        (SELECT time FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_time
-- FROM chats c WHERE c.user_id = 1;

-- Удалить пользователя и все его данные:
-- DELETE FROM messages WHERE chat_id IN (SELECT id FROM chats WHERE user_id = 1);
-- DELETE FROM chats WHERE user_id = 1;
-- DELETE FROM users WHERE id = 1;