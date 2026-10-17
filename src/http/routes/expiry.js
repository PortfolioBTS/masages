'use strict';
// Исчезающие сообщения и настройки чата: срок сообщения, срок чата и умолчание, настройки и
// персональные предпочтения (закрепление, звук, архив). Вынесено из server.js.

const DisappearingMessagesManager = require('../../../lib/disappearing-messages');
const {
    effectiveMessageExpiry, parseChatExpirySeconds, parseChatPrefs,
} = require('../../../lib/chat-settings');
const { logError } = require('../../../lib/log-error');
const { toPositiveInt } = require('../params');

function register(app, ctx) {
    const {
        notifyChatListChanged, dbGet, disappearingMessagesManager, getDefaultExpirySeconds, setChatExpiry,
        getOwnChat, findOwnMessage,
    } = ctx;

    // API для disappearing messages
    app.post('/api/messages/:messageId/set-expiry', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        const messageId = toPositiveInt(req.params.messageId);
        const { autoDeleteOnRead } = req.body || {};
        let expirySeconds;
        try {
            expirySeconds = DisappearingMessagesManager.normalizeExpirySeconds(req.body?.expirySeconds);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }
        if (!messageId) return res.json({ success: false, message: 'Неверные параметры' });

        try {
            // Проверка доступа к сообщению: свои, видимые, по тегу автора (8.2)
            const message = await findOwnMessage(messageId, req.session.userId);
            if (!message) {
                return res.json({ success: false, message: 'Сообщение не найдено или нет доступа' });
            }

            // Общий таймер чата — верхняя граница: автор может ускорить
            // исчезновение своего сообщения, но не продлить его сверх того, о чём
            // договорилась комната (уже назначенный срок только приближается).
            const chatDefault = await getDefaultExpirySeconds({ id: message.chat_id, room_id: message.room_id });
            await disappearingMessagesManager.setMessageExpiry(
                messageId, effectiveMessageExpiry(expirySeconds, chatDefault), autoDeleteOnRead === true,
                { shortenOnly: Boolean(chatDefault) }
            );

            res.json({ success: true, message: 'Таймер самоуничтожения установлен' });
        } catch (error) {
            logError('Set expiry error', error);
            res.json({ success: false, message: 'Ошибка установки таймера' });
        }
    });

    app.post('/api/chats/:chatId/expiry', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        let seconds;
        try {
            seconds = parseChatExpirySeconds(req.body?.seconds);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }
        try {
            const chat = await getOwnChat(req.params.chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });
            res.json({ success: true, seconds: await setChatExpiry(chat, seconds) });
        } catch (error) {
            logError('Set chat expiry error', error);
            res.json({ success: false, message: 'Ошибка настройки автоудаления' });
        }
    });

    // Старый маршрут ({ expirySeconds }) — тот же общий таймер и тот же набор
    // допустимых сроков, что и POST /api/chats/:chatId/expiry.
    app.post('/api/chats/:chatId/set-default-expiry', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        let seconds;
        try {
            seconds = parseChatExpirySeconds(req.body?.expirySeconds);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }

        try {
            // Проверка доступа к чату
            const chat = await getOwnChat(req.params.chatId, req.session.userId);
            if (!chat) {
                return res.json({ success: false, message: 'Чат не найден' });
            }

            const effective = await setChatExpiry(chat, seconds);
            res.json({
                success: true,
                seconds: effective,
                message: seconds > 0 ? 'Автоудаление сообщений настроено для чата' : 'Автоудаление сообщений выключено',
            });
        } catch (error) {
            logError('Set chat default expiry error', error);
            res.json({ success: false, message: 'Ошибка настройки автоудаления' });
        }
    });

    app.get('/api/chats/:chatId/settings', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });

        try {
            const chat = await getOwnChat(req.params.chatId, req.session.userId);
            if (!chat) {
                return res.json({ success: false, message: 'Чат не найден' });
            }

            const expiry = await getDefaultExpirySeconds(chat);
            res.json({ success: true, settings: expiry ? { default_message_expiry: expiry } : {} });
        } catch (error) {
            logError('Get chat settings error', error);
            res.json({ success: false, message: 'Ошибка получения настроек' });
        }
    });

    // Личные флаги чата: закреплён, без звука, в архиве. Хранятся в строке
    // chats самого пользователя — собеседники их не видят. Остальным вкладкам
    // и устройствам пользователя — chatListChanged.
    app.post('/api/chats/:chatId/prefs', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        let prefs;
        try {
            prefs = parseChatPrefs(req.body);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }
        const chatId = toPositiveInt(req.params.chatId);
        if (!chatId) return res.json({ success: false, message: 'Чат не найден' });
        try {
            const row = await dbGet(
                `UPDATE chats SET pinned = COALESCE($3, pinned), muted = COALESCE($4, muted), archived = COALESCE($5, archived)
             WHERE id = $1 AND user_id = $2
             RETURNING pinned, muted, archived`,
                [chatId, userId, prefs.pinned, prefs.muted, prefs.archived]
            );
            if (!row) return res.json({ success: false, message: 'Чат не найден' });
            notifyChatListChanged(userId);
            res.json({ success: true, pinned: row.pinned, muted: row.muted, archived: row.archived });
        } catch (error) {
            logError('Set chat prefs error', error);
            res.json({ success: false, message: 'Ошибка сохранения настроек чата' });
        }
    });
}

module.exports = { register };
