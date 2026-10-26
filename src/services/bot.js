'use strict';
// Бот-помощник: ответ в чат с ботом с небольшой задержкой (тексты — lib/bot-guide.js).
// Вынесено из server.js.

// Бот-помощник: ответ по теме запроса, приветствие нового аккаунта и подписи
// кнопок-подсказок — чистые функции без БД (lib/bot-guide.js).
const botGuide = require('../../lib/bot-guide');
const { logError } = require('../../lib/log-error');
const { getSocketRoomKey } = require('../realtime/io');
const { withMessageIdRetry } = require('../db/transactions');
const { writeMessageText, apiMessage } = require('./messages');

// Небольшая пауза перед ответом: он должен выглядеть ответом на сообщение, а
// не выскакивать одновременно с ним.
const BOT_REPLY_DELAY_MS = 600;

function createBot(ctx) {
    const { io, dbAll, withTransactionRetry, applyNewMessageExpiry, unarchiveForRecipients } = ctx;

    // userText — открытый текст сообщения пользователя (чат с ботом не
    // шифруется). Что ответить, решает lib/bot-guide.js по теме запроса.
    function scheduleBotReply(chat, userText) {
        const socketRoomKey = getSocketRoomKey(chat.id, null);
        setTimeout(async () => {
            // Весь колбэк в try: раньше ошибка БД в первом же запросе здесь
            // была необработанным reject'ом и роняла процесс.
            try {
                const replyText = botGuide.botReply(userText).text;
                // Порядок блокировок users → chats → messages
                // (docs/security/message-ordering.md, §8): строку владельца
                // берём явно и первой. Иначе INSERT сам проверял бы внешние
                // ключи — сначала chats, потом users — и сходился во взаимной
                // блокировке с удалением аккаунта (users FOR UPDATE, затем
                // DELETE FROM chats), если пользователь удаляет аккаунт, пока
                // бот готовит ответ. Аккаунта или чата уже нет — отвечать некому.
                const botMessage = await withMessageIdRetry(() => withTransactionRetry(async (client) => {
                    const owner = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [chat.user_id]);
                    if (owner.rows.length === 0) return null;
                    // Строку чата блокируем сразу так, как её всё равно обновит
                    // триггер seq (счётчик msg_seq), без повышения блокировки.
                    const alive = await client.query('SELECT id FROM chats WHERE id = $1 AND is_bot = 1 FOR NO KEY UPDATE', [chat.id]);
                    if (alive.rows.length === 0) return null;
                    // Сообщения бота хранятся от имени владельца чата (sent = 0).
                    // INSERT — последний оператор транзакции: окно блокировки
                    // строки области — один INSERT и COMMIT.
                    const inserted = await client.query(
                        `INSERT INTO messages (chat_id, room_id, user_id, text, sent, status)
                     VALUES ($1, NULL, $2, $3, 0, 'read')
                     RETURNING id, seq, chat_id, room_id, user_id, sent, status, created_at, message_type, encrypted`,
                        [chat.id, chat.user_id, writeMessageText(replyText, { room_id: null, chat_id: chat.id, user_id: chat.user_id })]
                    );
                    return inserted.rows[0];
                }));
                if (!botMessage) return;
                // Личный таймер чата с ботом действует и на ответы бота.
                await applyNewMessageExpiry(chat, botMessage.id);
                // Бот "прочитал" сообщения пользователя.
                const read = await dbAll(
                    `UPDATE messages SET status = 'read' WHERE chat_id = $1 AND room_id IS NULL AND sent = 1 AND status <> 'read' RETURNING id`,
                    [chat.id]
                );
                io.to(socketRoomKey).emit('newMessage', apiMessage({
                    ...botMessage, text: replyText, reactions: [], reply_to: null,
                    sender_username: 'Бот Помощник', sender_avatar: '',
                }));
                if (read.length > 0) {
                    io.to(socketRoomKey).emit('messagesRead', { chat_id: chat.id, room_id: null, up_to_seq: Number(botMessage.seq) });
                }
                unarchiveForRecipients(chat, null);
            } catch (e) {
                logError('Bot error', e);
            }
        }, BOT_REPLY_DELAY_MS);
    }

    return { scheduleBotReply };
}

module.exports = { createBot };
