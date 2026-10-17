'use strict';
// Исчезающие сообщения: менеджер сроков (DisappearingMessagesManager) и расчёт срока нового
// сообщения и умолчания чата. Удалённые менеджером сообщения сразу пропадают у открытых
// клиентов, а их вложения удаляются с диска. Вынесено из server.js.

const DisappearingMessagesManager = require('../../lib/disappearing-messages');
const { effectiveMessageExpiry } = require('../../lib/chat-settings');
const { getSocketRoomKey } = require('../realtime/io');

// expirySeconds из тела запроса: null — не задан, число — валидный срок;
// некорректное значение бросает RangeError с текстом для пользователя.
function parseRequestedExpiry(value) {
    if (value === undefined || value === null || value === '' || Number(value) === 0) return null;
    return DisappearingMessagesManager.normalizeExpirySeconds(value);
}

function createExpiry(ctx) {
    const { GLOBAL_DEFAULT_EXPIRY_SECONDS, removeUploadedFiles, io, pool } = ctx;

    // Менеджер исчезающих сообщений. Удалённые им сообщения сразу пропадают
    // и у открытых клиентов (раньше — только после перезагрузки страницы), а
    // их вложения удаляются с диска.
    const disappearingMessagesManager = new DisappearingMessagesManager(pool, {
        cleanupIntervalMs: process.env.CLEANUP_INTERVAL_MS,
        onMessagesDeleted: (rows) => {
            removeUploadedFiles(rows.map(r => r.file_url));
            for (const row of rows) {
                // У строки комнаты chat_id нет (sealed-sender.md, 8.1): событие несёт только room_id.
                io.to(getSocketRoomKey(row.chat_id, row.room_id)).emit('messageDeleted', row.room_id
                    ? { id: String(row.id), room_id: row.room_id }
                    : { id: String(row.id), chat_id: row.chat_id, room_id: null });
            }
        },
    });

    // Действующий срок новых сообщений чата: общий таймер комнаты (для чата с
    // ботом — личный), иначе DEFAULT_MESSAGE_EXPIRY_SECONDS; null — не исчезают.
    async function getDefaultExpirySeconds(chat) {
        const settings = chat.room_id
            ? await disappearingMessagesManager.getRoomSettings(chat.room_id)
            : await disappearingMessagesManager.getChatSettings(chat.id);
        return (settings && settings.default_message_expiry) || GLOBAL_DEFAULT_EXPIRY_SECONDS || null;
    }

    // Срок жизни только что созданного сообщения (текст или файл, E2EE или
    // нет, от любого участника): общий таймер чата; личный срок из запроса
    // отправителя — только если он не длиннее общего (effectiveMessageExpiry).
    async function applyNewMessageExpiry(chat, messageId, requestedSeconds = null) {
        const expiry = effectiveMessageExpiry(requestedSeconds, await getDefaultExpirySeconds(chat));
        if (expiry) await disappearingMessagesManager.setMessageExpiry(messageId, expiry, false);
    }

    // Срок жизни нового сообщения в секундах (общий таймер чата; личный срок из
    // запроса — только если он не длиннее общего) или null — не исчезает.
    async function newMessageExpirySeconds(chat, requestedSeconds = null) {
        return effectiveMessageExpiry(requestedSeconds, await getDefaultExpirySeconds(chat)) || null;
    }

    // Таймер исчезающих сообщений чата. В комнате — общий для всех участников
    // (room_settings), и менять его может любой участник, как и код
    // приглашения; в чате с ботом — личный (chat_settings). Действует на
    // сообщения, отправленные после изменения. Возвращается действующий срок
    // (выключенный таймер — DEFAULT_MESSAGE_EXPIRY_SECONDS, если он задан).
    async function setChatExpiry(chat, seconds) {
        if (chat.room_id) await disappearingMessagesManager.setRoomDefaultExpiry(chat.room_id, seconds);
        else await disappearingMessagesManager.setChatDefaultExpiry(chat.id, seconds);
        const effective = seconds || GLOBAL_DEFAULT_EXPIRY_SECONDS || 0;
        // В комнате chatId не отправляется: у каждого участника он свой.
        io.to(getSocketRoomKey(chat.id, chat.room_id)).emit('chatExpiryChanged', {
            roomId: chat.room_id || null,
            chatId: chat.room_id ? null : chat.id,
            seconds: effective,
        });
        return effective;
    }

    return {
        disappearingMessagesManager, getDefaultExpirySeconds, applyNewMessageExpiry, newMessageExpirySeconds,
        setChatExpiry,
    };
}

module.exports = { createExpiry, parseRequestedExpiry };
