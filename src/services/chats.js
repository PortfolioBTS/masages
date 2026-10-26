'use strict';
// Чаты пользователя: свой чат по id, область событий чата, отметка «прочитано» и возврат чата
// из архива при новом сообщении. Вынесено из server.js.

const { logError } = require('../../lib/log-error');
const { toPositiveInt } = require('../http/params');
const { getSocketRoomKey } = require('../realtime/io');

// Сообщения чата лежат либо по room_id (групповая комната), либо по
// chat_id (личный чат с ботом). where(alias, param) — условие WHERE для таблицы
// messages под этим псевдонимом, param (по умолчанию $1) — номер параметра со value. У чата с ботом условие
// содержит и room_id IS NULL: так запрос ложится на частичный уникальный
// индекс idx_messages_chat_seq (у сообщений комнаты chat_id — личная строка
// их автора, а не область). Сравнивать seq можно только внутри одной области.
function chatScope(chat) {
    const room = Boolean(chat.room_id);
    return {
        column: room ? 'room_id' : 'chat_id',
        value: room ? chat.room_id : chat.id,
        where: (alias = 'm', param = '$1') => (room ? `${alias}.room_id = ${param}` : `${alias}.chat_id = ${param} AND ${alias}.room_id IS NULL`),
    };
}

function createChats(ctx) {
    const { authorTags, io, notifyChatListChanged, dbGet, dbAll, disappearingMessagesManager } = ctx;

    // Личная строка chats вызывающего (chats.id — у каждого участника своя) и
    // граница видимости истории: visible_from_seq — seq последнего сообщения
    // комнаты на момент вступления, видно только то, что новее, то есть с
    // seq > visible_from_seq (для чата с ботом и создателя комнаты — 0, то есть
    // всё: seq всегда не меньше 1).
    async function getOwnChat(chatId, userId) {
        const id = toPositiveInt(chatId);
        if (!id) return null;
        return dbGet(
            `SELECT c.*, COALESCE(rp.visible_from_seq, 0) AS visible_from_seq
         FROM chats c
         LEFT JOIN room_participants rp ON rp.room_id = c.room_id AND rp.user_id = c.user_id
         WHERE c.id = $1 AND c.user_id = $2`,
            [id, userId]
        );
    }

    // Отмечает сообщения чата прочитанными вплоть до upToSeq: двигает личный
    // маркер непрочитанного (last_read_seq только растёт), ставит статус 'read'
    // чужим сообщениям (у отправителя появляются ✓✓) и запускает
    // auto-delete-on-read.
    //
    // «Чужие» в комнате — строки, чей author_tag не входит в теги читателя
    // (sealed-sender.md, 8.4): сервер вычисляет их из сессии (комната, пользователь,
    // все недели с создания аккаунта, все ключи сообщений). В чате с ботом — по
    // user_id, как раньше.
    //
    // Если читатель выключил отметки прочтения (users.read_receipts), двигается
    // только его личный маркер: статус сообщений не меняется и messagesRead не
    // рассылается. Auto-delete-on-read срабатывает всё равно — это обещание
    // отправителя, а не отметка для него.
    //
    // Два оператора, не одна транзакция (раздел 8.2 контракта): сначала UPDATE
    // chats, затем UPDATE messages SET status — порядок блокировок chats → messages.
    async function markChatRead(chat, userId, upToSeq) {
        const previous = Number(chat.last_read_seq) || 0;
        if (!upToSeq || upToSeq <= previous) return;
        const moved = await dbGet(
            `UPDATE chats c SET last_read_seq = $1
         FROM users u
         WHERE c.id = $2 AND c.last_read_seq < $1 AND u.id = c.user_id
         RETURNING u.read_receipts, u.created_at AS user_created_at`,
            [upToSeq, chat.id]
        );
        if (!moved) return; // уже отмечено (например, из другой вкладки)
        chat.last_read_seq = upToSeq;

        // Только сообщения после предыдущего маркера — раньше при КАЖДОМ
        // открытии чата UPDATE переписывал статус всех сообщений чата заново.
        const scope = chatScope(chat);
        const notMine = chat.room_id
            ? { sql: 'NOT (m.author_tag = ANY($4::bytea[]))', value: authorTags.tagsForAccount(chat.room_id, userId, moved.user_created_at, Date.now()) }
            : { sql: 'm.user_id <> $4', value: userId };
        if (!moved.read_receipts) {
            const autoDelete = await dbAll(
                `SELECT m.id FROM messages m
             JOIN message_expiry e ON e.message_id = m.id AND e.auto_delete_on_read = TRUE
             WHERE ${scope.where('m')} AND m.seq > $2 AND m.seq <= $3
               AND ${notMine.sql}`,
                [scope.value, previous, upToSeq, notMine.value]
            );
            disappearingMessagesManager.handleMessagesRead(autoDelete.map(r => r.id));
            return;
        }
        const readRows = await dbAll(
            `UPDATE messages m SET status = 'read'
         WHERE ${scope.where('m')} AND m.seq > $2 AND m.seq <= $3
           AND ${notMine.sql} AND m.status <> 'read'
         RETURNING m.id`,
            [scope.value, previous, upToSeq, notMine.value]
        );
        if (readRows.length > 0) {
            // Без reader_id: кто именно прочитал, остальным участникам знать не
            // нужно. Сокетам самого читателя событие не шлётся — иначе его
            // клиент принял бы его за прочтение своих же сообщений.
            io.to(getSocketRoomKey(chat.id, chat.room_id)).except('user:' + userId).emit('messagesRead', {
                chat_id: chat.room_id ? null : chat.id, room_id: chat.room_id, up_to_seq: upToSeq,
            });
            disappearingMessagesManager.handleMessagesRead(readRows.map(r => r.id));
        }
    }

    // Новое сообщение возвращает архивный чат из архива — у получателей и
    // только если чат не "без звука" (заглушённый архивный чат так и лежит в
    // архиве). senderId = null — ответ бота владельцу чата. Не на пути ответа
    // отправителю: сбой здесь только логируется. По частичному индексу
    // idx_chats_archived запрос обычно не находит ни одной строки.
    function unarchiveForRecipients(chat, senderId) {
        const query = chat.room_id
            ? dbAll(
                'UPDATE chats SET archived = FALSE WHERE room_id = $1 AND archived AND NOT muted AND user_id <> $2 RETURNING user_id',
                [chat.room_id, senderId]
            )
            : dbAll('UPDATE chats SET archived = FALSE WHERE id = $1 AND archived AND NOT muted RETURNING user_id', [chat.id]);
        query.then(
            (rows) => { for (const row of rows) notifyChatListChanged(row.user_id); },
            (err) => logError('[Chats] Не удалось вернуть чат из архива', err)
        );
    }

    return { getOwnChat, markChatRead, unarchiveForRecipients };
}

module.exports = { createChats, chatScope };
