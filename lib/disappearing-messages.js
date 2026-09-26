// Disappearing messages: удаление сообщения по таймеру и по факту прочтения.
//
// Технически это soft-delete (строка остаётся, text заменяется на
// плейсхолдер, deleted = 1) — см. README. Вложение такого сообщения
// отвязывается (file_url = NULL), а сам файл удаляет server.js в
// onMessagesDeleted, вместе с socket-уведомлением участникам.

// setTimeout с задержкой больше 2^31-1 мс (~24.8 суток) Node не "ждёт
// долго", а срабатывает почти сразу (TimeoutOverflowWarning) — сообщение
// с таймером на месяц удалялось бы через миллисекунду. Такие сроки
// планируем только в БД: их подберёт фоновый воркер.
const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;
const MAX_EXPIRY_SECONDS = 365 * 24 * 60 * 60;
const DELETE_AFTER_READ_SECONDS = 3;
const DELETED_PLACEHOLDER = '[Сообщение удалено]';
const CLEANUP_BATCH = 500;

function normalizeExpirySeconds(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds <= 0 || seconds > MAX_EXPIRY_SECONDS) {
        throw new RangeError(`Время жизни сообщения должно быть от 1 до ${MAX_EXPIRY_SECONDS} секунд`);
    }
    return Math.ceil(seconds);
}

class DisappearingMessagesManager {
    // onMessagesDeleted(rows) — вызывается после каждого удаления с
    // [{ id, chat_id, room_id, file_url }] уже удалённых сообщений.
    constructor(pool, { onMessagesDeleted, cleanupIntervalMs } = {}) {
        this.pool = pool;
        this.onMessagesDeleted = onMessagesDeleted || null;
        this.cleanupIntervalMs = Number(cleanupIntervalMs) > 0 ? Number(cleanupIntervalMs) : 60000;
        this.scheduledDeletions = new Map();
        this.cleanupRunning = false;
    }

    // Должен вызываться ПОСЛЕ создания таблиц messages/chats: обе таблицы
    // ниже ссылаются на них внешним ключом.
    async initialize() {
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS message_expiry (
                message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                expires_at TIMESTAMP NOT NULL,
                auto_delete_on_read BOOLEAN DEFAULT FALSE
            )
        `);
        await this.pool.query(`
            CREATE INDEX IF NOT EXISTS idx_message_expiry_expires_at
            ON message_expiry(expires_at)
        `);
        // Раньше таблица создавалась лениво в setChatDefaultExpiry(), и до
        // первого вызова каждый POST /api/messages получал от Postgres
        // ошибку "relation chat_settings does not exist".
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id INTEGER PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE,
                default_message_expiry INTEGER
            )
        `);

        console.log('[DisappearingMessages] Initialized');
        this.startCleanupWorker();
    }

    // expires_at считается в самом Postgres (NOW() + interval), а не
    // передаётся как JS Date: колонка TIMESTAMP без часового пояса, и Date
    // из Node с другим TZ, чем у сессии БД, сдвигал срок на разницу поясов.
    async setMessageExpiry(messageId, expirySeconds, autoDeleteOnRead = false) {
        const seconds = normalizeExpirySeconds(expirySeconds);
        await this.pool.query(
            `INSERT INTO message_expiry (message_id, expires_at, auto_delete_on_read)
             VALUES ($1, NOW() + $2::integer * INTERVAL '1 second', $3)
             ON CONFLICT (message_id) DO UPDATE
             SET expires_at = EXCLUDED.expires_at, auto_delete_on_read = EXCLUDED.auto_delete_on_read`,
            [messageId, seconds, Boolean(autoDeleteOnRead)]
        );
        this.scheduleMessageDeletion(messageId, seconds * 1000);
    }

    scheduleMessageDeletion(messageId, delayMs) {
        if (this.scheduledDeletions.has(messageId)) {
            clearTimeout(this.scheduledDeletions.get(messageId));
            this.scheduledDeletions.delete(messageId);
        }
        if (delayMs > MAX_TIMER_DELAY_MS) return; // дождётся фонового воркера

        const timeoutId = setTimeout(() => {
            this.scheduledDeletions.delete(messageId);
            this.deleteMessages([messageId]);
        }, Math.max(0, delayMs));
        this.scheduledDeletions.set(messageId, timeoutId);
    }

    async deleteMessage(messageId) {
        return this.deleteMessages([messageId]);
    }

    async deleteMessages(messageIds) {
        const ids = messageIds.map(Number).filter(Number.isInteger);
        if (ids.length === 0) return [];
        try {
            const result = await this.pool.query(
                `WITH target AS (
                     SELECT id, file_url FROM messages
                     WHERE id = ANY($1::int[]) AND deleted = 0
                     FOR UPDATE
                 )
                 UPDATE messages m
                 SET deleted = 1, text = $2, file_url = NULL, file_name = NULL
                 FROM target
                 WHERE m.id = target.id
                 RETURNING m.id, m.chat_id, m.room_id, target.file_url`,
                [ids, DELETED_PLACEHOLDER]
            );
            await this.pool.query('DELETE FROM message_expiry WHERE message_id = ANY($1::int[])', [ids]);

            if (result.rows.length > 0) {
                console.log(`[DisappearingMessages] Deleted ${result.rows.length} message(s)`);
                if (this.onMessagesDeleted) {
                    try { this.onMessagesDeleted(result.rows); } catch (err) {
                        console.error('[DisappearingMessages] onMessagesDeleted failed:', err.message);
                    }
                }
            }
            return result.rows;
        } catch (error) {
            console.error('[DisappearingMessages] Error deleting messages:', error.message);
            return [];
        }
    }

    // Вызывается, когда получатель открыл/увидел сообщения. Те из них, что
    // помечены auto_delete_on_read, удаляются через несколько секунд.
    // Срок пишется и в БД — удаление не потеряется при рестарте процесса.
    async handleMessagesRead(messageIds) {
        const ids = messageIds.map(Number).filter(Number.isInteger);
        if (ids.length === 0) return;
        try {
            const result = await this.pool.query(
                `UPDATE message_expiry
                 SET expires_at = LEAST(expires_at, NOW() + $2::integer * INTERVAL '1 second')
                 WHERE message_id = ANY($1::int[]) AND auto_delete_on_read = TRUE
                 RETURNING message_id`,
                [ids, DELETE_AFTER_READ_SECONDS]
            );
            for (const row of result.rows) {
                this.scheduleMessageDeletion(row.message_id, DELETE_AFTER_READ_SECONDS * 1000);
            }
        } catch (error) {
            console.error('[DisappearingMessages] Error handling message read:', error.message);
        }
    }

    startCleanupWorker() {
        if (this.cleanupTimer) return;
        this.cleanupTimer = setInterval(() => this.cleanupExpired(), this.cleanupIntervalMs);
    }

    async cleanupExpired() {
        if (this.cleanupRunning) return; // предыдущий проход ещё не закончился
        this.cleanupRunning = true;
        try {
            for (;;) {
                const result = await this.pool.query(
                    'SELECT message_id FROM message_expiry WHERE expires_at < NOW() ORDER BY expires_at LIMIT $1',
                    [CLEANUP_BATCH]
                );
                if (result.rows.length === 0) break;
                await this.deleteMessages(result.rows.map(r => r.message_id));
                if (result.rows.length < CLEANUP_BATCH) break;
            }
        } catch (error) {
            console.error('[DisappearingMessages] Cleanup worker error:', error.message);
        } finally {
            this.cleanupRunning = false;
        }
    }

    // expirySeconds <= 0 выключает автоудаление для чата.
    async setChatDefaultExpiry(chatId, expirySeconds) {
        const raw = Number(expirySeconds);
        if (Number.isFinite(raw) && raw <= 0) {
            await this.pool.query('DELETE FROM chat_settings WHERE chat_id = $1', [chatId]);
            return;
        }
        const seconds = normalizeExpirySeconds(raw);
        await this.pool.query(
            `INSERT INTO chat_settings (chat_id, default_message_expiry)
             VALUES ($1, $2)
             ON CONFLICT (chat_id) DO UPDATE SET default_message_expiry = EXCLUDED.default_message_expiry`,
            [chatId, seconds]
        );
    }

    async getChatSettings(chatId) {
        const result = await this.pool.query(
            'SELECT default_message_expiry FROM chat_settings WHERE chat_id = $1',
            [chatId]
        );
        return result.rows.length > 0 ? result.rows[0] : null;
    }
}

DisappearingMessagesManager.normalizeExpirySeconds = normalizeExpirySeconds;
DisappearingMessagesManager.MAX_EXPIRY_SECONDS = MAX_EXPIRY_SECONDS;

module.exports = DisappearingMessagesManager;
