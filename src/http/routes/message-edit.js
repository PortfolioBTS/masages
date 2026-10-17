'use strict';
// Правка и удаление своего сообщения. Вынесено из server.js.

const { sanitizeText } = require('../../../lib/privacy');
const { isClientOutdated: isOutdatedProto } = require('../../../lib/proto');
const { logError } = require('../../../lib/log-error');
// Огрубление времени сообщений и файлов (раздел 11 контракта).
const { floorToMinute } = require('../../../lib/coarse-time');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const { CLIENT_OUTDATED } = require('../../../lib/message-ids');
// Форма E2EE-конверта и тела отказов 400 для комнат и бота (R7).
const { MAX_ENVELOPE_LENGTH } = require('../../../lib/e2ee-envelope');
const { toPositiveInt, isNonEmptyString } = require('../params');
const { e2eePolicyViolation, writeMessageText } = require('../../services/messages');
const { getSocketRoomKey } = require('../../realtime/io');

function register(app, ctx) {
    const { io, emitRoomMessageEvent, dbAll, dbRun, disappearingMessagesManager, findOwnMessage } = ctx;

    app.put('/api/messages/:messageId', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        // Общий признак версии клиента (message-ordering.md, 14.1) - первая проверка.
        if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
        const messageId = toPositiveInt(req.params.messageId);
        const { text } = req.body || {};
        if (!messageId || !isNonEmptyString(text)) return res.json({ success: false, message: 'Текст не может быть пустым' });

        try {
            // Правятся только текстовые сообщения: у вложения подпись внутри
            // E2EE-конверта (или имя файла), и менять её задним числом нельзя.
            const message = await findOwnMessage(messageId, userId, { sentOnly: true });
            if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
            if (message.file_url) return res.json({ success: false, message: 'Сообщение с вложением нельзя изменить' });
            // Правка E2EE-сообщения — это новый конверт: клиент сам шифрует новый
            // текст перед PUT, флаг encrypted при редактировании не меняется.
            // Сообщение комнаты без шифрования (в базе его быть не должно) править
            // нельзя, а новый конверт обязан иметь правильную форму — иначе правкой
            // можно было бы подменить шифротекст открытым текстом.
            if (message.room_id) {
                const violation = e2eePolicyViolation({ room_id: message.room_id }, Boolean(message.encrypted), text.trim());
                if (violation) return res.status(400).json(violation);
            }
            const maxLen = message.encrypted ? MAX_ENVELOPE_LENGTH : 4000;
            if (text.length > maxLen) return res.json({ success: false, message: `Сообщение не может быть длиннее ${maxLen} символов` });

            // Та же очистка, что и при отправке (раньше правкой её можно было обойти).
            const newText = message.encrypted ? text.trim() : sanitizeText(text.trim());
            if (!newText) return res.json({ success: false, message: 'Текст не может быть пустым' });
            // Время правки хранится с точностью до минуты (вниз), в API — ISO-8601 UTC.
            const editedAt = floorToMinute(new Date()).toISOString();
            // AAD — от исходной строки: комната, id и тег (у бота - чат и владелец) при
            // правке не меняются, тег берётся ИЗ строки, а не пересчитывается по
            // текущей неделе (правка на границе недели - тот же тег).
            //
            // Запись условна по тегу строки: пока шла правка, scripts/retag-messages.js мог
            // перетегировать строку (смена MESSAGE_ENCRYPTION_KEY, 14.1), и текст с AAD старого
            // тега под новым тегом не читался бы. Тогда правку нужно повторить.
            const written = message.room_id
                ? await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3 AND author_tag = $4', [writeMessageText(newText, message), editedAt, messageId, message.author_tag])
                : await dbRun('UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3', [writeMessageText(newText, message), editedAt, messageId]);
            if (written.rowCount === 0) return res.json({ success: false, message: 'Сообщение изменилось, попробуйте ещё раз' });

            if (message.room_id) {
                // Тем, кто вступил в комнату после этого сообщения, новый текст не
                // уходит: для них этого сообщения нет (visible_from_seq >= seq).
                const hidden = await dbAll(
                    'SELECT user_id FROM room_participants WHERE room_id = $1 AND visible_from_seq >= $2',
                    [message.room_id, message.seq]
                );
                emitRoomMessageEvent('messageEdited', message.room_id, userId, {
                    id: String(messageId), seq: Number(message.seq), text: newText, edited_at: editedAt,
                    room_id: message.room_id, encrypted: message.encrypted,
                }, { hiddenUserIds: hidden.map(row => row.user_id) });
            } else {
                io.to(getSocketRoomKey(message.chat_id, null)).emit('messageEdited', {
                    id: String(messageId), seq: Number(message.seq), text: newText, edited_at: editedAt,
                    chat_id: message.chat_id, room_id: null, encrypted: message.encrypted, user_id: message.user_id
                });
            }

            res.json({ success: true, edited_at: editedAt, text: newText });
        } catch (error) {
            logError('Edit message error', error);
            res.json({ success: false, message: 'Ошибка редактирования' });
        }
    });

    app.delete('/api/messages/:messageId', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const messageId = toPositiveInt(req.params.messageId);
        if (!messageId) return res.json({ success: false, message: 'Сообщение не найдено' });
        try {
            const message = await findOwnMessage(messageId, userId);
            if (!message) return res.json({ success: false, message: 'Сообщение не найдено' });
            // Тот же путь, что и у disappearing messages: строка удаляется из БД
            // физически (триггер оставляет надгробие id), вложение — с диска (раньше
            // файл удалённого сообщения оставался доступен по прямой ссылке),
            // участникам уходит 'messageDeleted' (в комнате - одно событие всем сокетам
            // комнаты, включая вкладки автора, и без chat_id). Пустой результат — ошибка
            // БД (она уже в логе).
            const deleted = await disappearingMessagesManager.deleteMessages([messageId]);
            if (deleted.length === 0) return res.json({ success: false, message: 'Ошибка удаления' });
            res.json({ success: true });
        } catch (error) {
            logError('Delete message error', error);
            res.json({ success: false, message: 'Ошибка удаления' });
        }
    });
}

module.exports = { register };
