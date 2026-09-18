const { Pool } = require('pg');

class DisappearingMessagesManager {
    constructor(pool) {
        this.pool = pool;
        this.scheduledDeletions = new Map();
    }

    // Инициализация таблицы для disappearing messages
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

        console.log('[DisappearingMessages] Initialized');

        // Запускаем фоновый процесс очистки
        this.startCleanupWorker();
    }

    // Установка времени жизни сообщения
    async setMessageExpiry(messageId, expirySeconds, autoDeleteOnRead = false) {
        const expiresAt = new Date(Date.now() + expirySeconds * 1000);

        await this.pool.query(
            `INSERT INTO message_expiry (message_id, expires_at, auto_delete_on_read)
             VALUES ($1, $2, $3)
             ON CONFLICT (message_id) DO UPDATE
             SET expires_at = $2, auto_delete_on_read = $3`,
            [messageId, expiresAt, autoDeleteOnRead]
        );

        // Планируем удаление
        this.scheduleMessageDeletion(messageId, expirySeconds * 1000);
    }

    // Планирование удаления сообщения
    scheduleMessageDeletion(messageId, delayMs) {
        // Отменяем предыдущее запланированное удаление если есть
        if (this.scheduledDeletions.has(messageId)) {
            clearTimeout(this.scheduledDeletions.get(messageId));
        }

        const timeoutId = setTimeout(async () => {
            await this.deleteMessage(messageId);
            this.scheduledDeletions.delete(messageId);
        }, delayMs);

        this.scheduledDeletions.set(messageId, timeoutId);
    }

    // Удаление сообщения
    async deleteMessage(messageId) {
        try {
            await this.pool.query(
                'UPDATE messages SET deleted = 1, text = \'[Сообщение удалено]\' WHERE id = $1',
                [messageId]
            );

            await this.pool.query(
                'DELETE FROM message_expiry WHERE message_id = $1',
                [messageId]
            );

            console.log(`[DisappearingMessages] Deleted message ${messageId}`);
        } catch (error) {
            console.error('[DisappearingMessages] Error deleting message:', error.message);
        }
    }

    // Обработка прочтения сообщения (для auto-delete-on-read)
    async handleMessageRead(messageId) {
        try {
            const result = await this.pool.query(
                'SELECT auto_delete_on_read FROM message_expiry WHERE message_id = $1',
                [messageId]
            );

            if (result.rows.length > 0 && result.rows[0].auto_delete_on_read) {
                // Удаляем через 3 секунды после прочтения
                setTimeout(() => this.deleteMessage(messageId), 3000);
            }
        } catch (error) {
            console.error('[DisappearingMessages] Error handling message read:', error.message);
        }
    }

    // Фоновый процесс очистки просроченных сообщений
    startCleanupWorker() {
        setInterval(async () => {
            try {
                const result = await this.pool.query(
                    'SELECT message_id FROM message_expiry WHERE expires_at < NOW()'
                );

                for (const row of result.rows) {
                    await this.deleteMessage(row.message_id);
                }

                if (result.rows.length > 0) {
                    console.log(`[DisappearingMessages] Cleaned up ${result.rows.length} expired messages`);
                }
            } catch (error) {
                console.error('[DisappearingMessages] Cleanup worker error:', error.message);
            }
        }, 60000); // Проверка каждую минуту
    }

    // Установка глобального времени жизни для чата
    async setChatDefaultExpiry(chatId, expirySeconds) {
        await this.pool.query(
            `CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id INTEGER PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE,
                default_message_expiry INTEGER
            )`
        );

        await this.pool.query(
            `INSERT INTO chat_settings (chat_id, default_message_expiry)
             VALUES ($1, $2)
             ON CONFLICT (chat_id) DO UPDATE SET default_message_expiry = $2`,
            [chatId, expirySeconds]
        );
    }

    // Получение настроек чата
    async getChatSettings(chatId) {
        try {
            const result = await this.pool.query(
                'SELECT default_message_expiry FROM chat_settings WHERE chat_id = $1',
                [chatId]
            );

            return result.rows.length > 0 ? result.rows[0] : null;
        } catch (error) {
            return null;
        }
    }
}

module.exports = DisappearingMessagesManager;
