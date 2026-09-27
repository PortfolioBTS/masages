-- PostgreSQL schema for Nyxo messenger
-- Run this manually if you prefer external migration over initDatabase()
--
-- ВАЖНО (п.9 аудита от 2026-09-01): initDatabase() в server.js — это
-- ЕДИНСТВЕННЫЙ источник истины, который реально применяется при каждом
-- старте сервера (CREATE TABLE IF NOT EXISTS + серия ALTER TABLE, которые
-- переопределяют ограничения на уже существующей БД). Этот файл — best-effort
-- слепок того, что делает initDatabase() на момент последней сверки, для тех,
-- кто предпочитает накатить схему вручную один раз перед первым запуском.
-- Если он когда-либо разойдётся с initDatabase() (например, кто-то поправит
-- миграцию в server.js и забудет обновить этот файл) — доверяйте server.js,
-- а не этому файлу.
--
-- Ключевые ограничения ниже намеренно отличаются от "наивной" схемы:
--   * messages.chat_id — NULLABLE, ON DELETE SET NULL (не NOT NULL/CASCADE).
--     Когда участник выходит из групповой комнаты, его личная запись в chats
--     удаляется, но сами сообщения не пропадают — им обнуляется chat_id, а
--     история остаётся видна остальным участникам по messages.room_id.
--   * chats.room_id — ON DELETE CASCADE (когда комната удаляется целиком,
--     все личные записи chats участников удаляются вместе с ней).
--   * messages.room_id — ON DELETE CASCADE (см. комментарий в initDatabase:
--     подстраховка на случай будущих изменений порядка удаления в
--     DELETE /api/chats/:chatId; в норме сообщения комнаты удаляет само
--     приложение до удаления room).
--   * messages.reply_to_id — ON DELETE SET NULL (ответ на удалённое
--     сообщение не блокирует и не каскадирует удаление).
--   * reactions.message_id, unread.chat_id, room_participants.room_id —
--     ON DELETE CASCADE.
--   * Все FK на users(id) (chats.user_id, messages.user_id, unread.user_id,
--     room_participants.user_id, reactions.user_id, e2ee_key_shares.*) НЕ
--     каскадные (обычный ON DELETE NO ACTION): удаление пользователя
--     (deleteUserAccount в server.js) само удаляет его строки в нужном
--     порядке одной транзакцией.
--   * Удаление сообщений физическое (DELETE), колонка messages.deleted
--     осталась от старой soft-delete схемы: новые строки всегда 0, старые
--     deleted = 1 сервер удаляет после старта.
--   * users.id, rooms.id, chats.id у новых строк — случайные (функция
--     nyxo_random_id ниже, PG 13+ из-за gen_random_uuid()); messages.id
--     остаётся последовательным: на его порядке держатся история,
--     непрочитанное и room_participants.visible_from_id.

-- Случайный id из [1 000 000, 2^31 - 1]: 48 бит gen_random_uuid() (внутри —
-- pg_strong_random) по модулю размера диапазона, с перепроверкой занятости.
-- Тело должно совпадать с RANDOM_ID_FUNCTION_BODY в server.js.
CREATE OR REPLACE FUNCTION nyxo_random_id(target regclass) RETURNS integer
LANGUAGE plpgsql VOLATILE AS $fn$
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
$fn$;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    unique_code TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password TEXT,
    avatar TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- отметки прочтения (POST /api/user/privacy)
    read_receipts BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS rooms (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- срок жизни инвайт-кода (INVITE_TTL_HOURS); NULL считается истёкшим
    code_expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS chats (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    avatar TEXT NOT NULL,
    online INTEGER DEFAULT 0,
    is_bot INTEGER DEFAULT 0,
    -- id последнего прочитанного сообщения (счётчик непрочитанного)
    last_read_message_id INTEGER NOT NULL DEFAULT 0,
    -- порядок чатов без сообщений (id случайные); у старых строк NULL
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users ALTER COLUMN id SET DEFAULT nyxo_random_id('users'::regclass);
ALTER TABLE rooms ALTER COLUMN id SET DEFAULT nyxo_random_id('rooms'::regclass);
ALTER TABLE chats ALTER COLUMN id SET DEFAULT nyxo_random_id('chats'::regclass);

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
    -- text содержит клиентский E2EE-конверт (см. public/e2ee.js)
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    -- точное время отправки; у сообщений до миграции — NULL (клиент показывает time)
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- размер вложения в байтах (квота UPLOAD_QUOTA_MB); у старых вложений NULL
    file_size BIGINT
);

CREATE TABLE IF NOT EXISTS unread (
    id SERIAL PRIMARY KEY,
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS room_participants (
    id SERIAL PRIMARY KEY,
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    -- участник видит только сообщения с id > visible_from_id (MAX(id)
    -- сообщений комнаты на момент вступления; у старых участников 0)
    visible_from_id INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reactions (
    id SERIAL PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    emoji TEXT NOT NULL,
    UNIQUE(message_id, user_id, emoji)
);

-- Миграция для БД, созданных до появления комнат (room_id)
ALTER TABLE chats ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE;

-- Миграция для БД, созданных до того, как chat_id стал nullable (см.
-- комментарий вверху файла и initDatabase() в server.js).
ALTER TABLE messages ALTER COLUMN chat_id DROP NOT NULL;
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_chat_id_fkey;
ALTER TABLE messages ADD CONSTRAINT messages_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE SET NULL;

-- Колонки hardening-версии для БД, созданных раньше. Перевыпуск старых
-- инвайт-кодов и обезличивание имён старых вложений делает только
-- server.js (regenerateLegacyInviteCodes, anonymizeLegacyFileNames) — им
-- нужен код генерации/шифрования.
ALTER TABLE users ADD COLUMN IF NOT EXISTS read_receipts BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS code_expires_at TIMESTAMPTZ;
ALTER TABLE room_participants ADD COLUMN IF NOT EXISTS visible_from_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size BIGINT;
ALTER TABLE chats ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
ALTER TABLE chats ALTER COLUMN created_at SET DEFAULT NOW();

-- Таблицы lib/disappearing-messages.js и lib/e2ee-groups.js
CREATE TABLE IF NOT EXISTS message_expiry (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    auto_delete_on_read BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_message_expiry_expires_at ON message_expiry(expires_at);

CREATE TABLE IF NOT EXISTS chat_settings (
    chat_id INTEGER PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE,
    default_message_expiry INTEGER
);

CREATE TABLE IF NOT EXISTS e2ee_key_shares (
    id SERIAL PRIMARY KEY,
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_e2ee_key_shares_recipient ON e2ee_key_shares(recipient_id, room_id);

-- Индексы (см. комментарии в initDatabase() в server.js). Выборки
-- "сообщения чата по id" (последнее сообщение, непрочитанные, страница
-- истории, поиск) идут index-only scan'ом по idx_messages_*_live.
CREATE INDEX IF NOT EXISTS idx_messages_room_live ON messages(room_id, deleted, id) INCLUDE (user_id, sent, encrypted);
CREATE INDEX IF NOT EXISTS idx_messages_chat_live ON messages(chat_id, deleted, id) INCLUDE (user_id, sent, encrypted);
CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);
CREATE INDEX IF NOT EXISTS idx_messages_file_url ON messages(file_url) WHERE file_url IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_reply_to_id ON messages(reply_to_id) WHERE reply_to_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_user_files ON messages(user_id) INCLUDE (file_size) WHERE file_size IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id);
CREATE INDEX IF NOT EXISTS idx_chats_room_id ON chats(room_id);
-- Один участник — одна строка на комнату (на существующей БД server.js
-- перед созданием индекса удаляет дубли, см. ensureUniqueRoomParticipants).
CREATE UNIQUE INDEX IF NOT EXISTS idx_room_participants_unique ON room_participants(room_id, user_id);
DROP INDEX IF EXISTS idx_room_participants_room_user;
CREATE INDEX IF NOT EXISTS idx_room_participants_user ON room_participants(user_id);
CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id);
