'use strict';
// Сообщения: шифрование текста в БД (enc:v2/enc:v3 с AAD), вставка сообщений чата и комнаты,
// проверки конверта E2EE и повтора по id, ответы API, доступ к сообщению и вложению.
// Вынесено из server.js.

const DisappearingMessagesManager = require('../../lib/disappearing-messages');
const {
    encryptRoomText, messageAadV3, encryptText, messageAad, decryptRoomText, decryptText,
} = require('../../lib/message-crypto');
const { sanitizeText } = require('../../lib/privacy');
const { anonymizedFileName } = require('../../lib/security-utils');
const { reserveUploadQuota, remainingUploadQuota } = require('../../lib/upload-quota');
const { logError } = require('../../lib/log-error');
// Огрубление времени сообщений и файлов (раздел 11 контракта).
const { floorToMinute } = require('../../lib/coarse-time');
// Форма E2EE-конверта и тела отказов 400 для комнат и бота (R7).
const {
    E2EE_NOT_ALLOWED, E2EE_REQUIRED, isE2eeEnvelopeShape, BAD_ENVELOPE,
} = require('../../lib/e2ee-envelope');

// ---- Текст сообщения в БД: шифрование at rest с AAD ----
//
// Строка КОМНАТЫ шифруется enc:v3 (lib/message-crypto.js): AAD привязывает
// шифротекст к комнате, к id сообщения и к author_tag строки (пользователя в AAD
// нет: в строке комнаты нет user_id, sealed-sender.md, раздел 7). Шифротекст,
// перенесённый в другую комнату, под другой id или под другой тег, не
// расшифруется. Строка чата с БОТОМ — enc:v2 с AAD из чата и владельца.
// Поэтому везде, где читается или пишется messages.text, выбираются поля этой же
// строки: room_id, id, author_tag (комната) или chat_id, user_id (бот).
const UNREADABLE_TEXT = '[Не удалось расшифровать]';

function writeMessageText(text, row) {
    if (row.room_id) return encryptRoomText(text, messageAadV3(row));
    return encryptText(text, messageAad(row));
}

function readMessageText(stored, row) {
    if (stored === null || stored === undefined) return stored;
    try {
        return row.room_id ? decryptRoomText(stored, messageAadV3(row)) : decryptText(stored, messageAad(row));
    } catch (err) {
        // AAD не собирается только у строки без обязательных полей (комната без
        // id или тега, чат без владельца, осиротевшее сообщение) — показать её
        // всё равно некому и нечем.
        logError('[MessageCrypto] Нет AAD для сообщения', err);
        return UNREADABLE_TEXT;
    }
}

// Сообщение в ответах и событиях API: id — всегда строка, seq — число
// (message-ordering.md, 6.1). Остальные поля как были.
function apiMessage(message) {
    const out = { ...message };
    if (out.id !== undefined && out.id !== null) out.id = String(out.id);
    if (out.seq !== undefined && out.seq !== null) out.seq = Number(out.seq);
    if (out.reply_to_id !== undefined && out.reply_to_id !== null) out.reply_to_id = String(out.reply_to_id);
    if (out.reply_to && out.reply_to.id !== undefined && out.reply_to.id !== null) {
        out.reply_to = { ...out.reply_to, id: String(out.reply_to.id) };
    }
    return out;
}

// ---- Вставка сообщения: id клиента, блокировки, повторы ----
//
// id сообщения комнаты выбирает клиент (clientMessageId) ДО шифрования и кладёт
// его внутрь E2EE-содержимого (mid): сервер не может выдать правку одного
// сообщения за другое. Чат с ботом id не присылает: его выдаёт DEFAULT.
// Конфликт id (первичный ключ или надгробие) и повтор запроса после обрыва связи
// разбирает describeMessageIdUse (раздел 6.4 контракта порядка сообщений).

// Колонки, которые разрешено вставлять через insertMessageRow: имена идут в
// текст SQL, поэтому только из этого списка.
const MESSAGE_INSERT_COLUMNS = new Set([
    'id', 'chat_id', 'room_id', 'user_id', 'author_tag', 'text', 'file_url', 'file_name', 'file_type',
    'message_type', 'sent', 'status', 'reply_to_id', 'encrypted', 'file_size', 'created_at',
]);

// INSERT сообщения; если задан срок жизни — тем же оператором и запись
// message_expiry (раздел 8.4): сообщение не остаётся без срока при сбое между
// операторами. Время удаления в базе округлено вверх до минуты. Возвращает
// { id, seq, created_at }.
async function insertMessageRow(client, fields, expirySeconds) {
    const names = Object.keys(fields);
    for (const name of names) {
        if (!MESSAGE_INSERT_COLUMNS.has(name)) throw new Error(`insertMessageRow: неизвестная колонка ${name}`);
    }
    const values = names.map(name => fields[name]);
    const insert = `INSERT INTO messages (${names.join(', ')}) VALUES (${names.map((_, i) => `$${i + 1}`).join(', ')})`;
    if (!expirySeconds) {
        const result = await client.query(`${insert} RETURNING id, seq, created_at`, values);
        return result.rows[0];
    }
    values.push(expirySeconds);
    const result = await client.query(
        `WITH m AS (${insert} RETURNING id, seq, created_at),
              e AS (INSERT INTO message_expiry (message_id, expires_at, auto_delete_on_read)
                    SELECT m.id, ${DisappearingMessagesManager.expiresAtSql(`$${values.length}`)}, FALSE FROM m)
         SELECT id, seq, created_at FROM m`,
        values
    );
    return result.rows[0];
}

// Ответ на отказ транзакции отправки в комнату.
function respondRoomSendError(res, error) {
    if (error === 'no-user') return res.status(401).json({ success: false, message: 'Не авторизован' });
    if (error === 'no-room') return res.status(404).json({ success: false, message: 'Комната не найдена' });
    if (error === 'not-member') return res.status(403).json({ success: false, message: 'Вы не участник этой комнаты' });
    return res.status(413).json({ success: false, message: 'Превышена квота хранилища вложений' });
}

// Правило R7: в комнате принимается только E2EE-конверт правильной формы, в чате с
// ботом — только открытый текст (расшифровать конверт там некому). null — запрос
// допустим, иначе тело ответа 400 { success:false, code, message }. Проверка
// формы не заменяет проверки подписи на стороне получателей, но не даёт
// «шифрованным» назвать открытый текст или произвольные данные.
function e2eePolicyViolation(chat, encrypted, envelope) {
    if (!chat.room_id) return encrypted ? E2EE_NOT_ALLOWED : null;
    if (!encrypted) return E2EE_REQUIRED;
    return isE2eeEnvelopeShape(envelope) ? null : BAD_ENVELOPE;
}

// Текст сообщения-вложения, как он хранится в messages.text: для E2EE — конверт,
// иначе подпись или обезличенное имя по типу. null — конверта нет (так сравнить
// с сохранённой строкой нечем).
function expectedFileMessageText(body, mimetype) {
    if (body.encrypted === 'true') return typeof body.envelope === 'string' ? body.envelope.trim() : null;
    const caption = typeof body.text === 'string' ? sanitizeText(body.text.trim()) : '';
    return caption || anonymizedFileName(mimetype);
}

// ---- Сообщение комнаты в ответах и событиях (sealed-sender.md, 8.1) ----
//
// Без user_id, chat_id (личная строка отправителя), sender_username,
// sender_avatar и author_tag: автора знает только клиент (по E2EE-конверту).
// Сторона пузыря не расшифрованного сообщения — подсказка mine: она есть только в
// ответе отправителю и в копии события на user:<id> отправителя; остальным
// участникам и в истории её нет. Клиент никогда не передаёт её в расшифровку.
function roomMessagePayload(row, text, { replyTo = null, mine = false } = {}) {
    const message = {
        id: row.id, seq: row.seq, room_id: row.room_id,
        text, file_url: row.file_url, file_name: row.file_name, file_type: row.file_type,
        message_type: row.message_type, sent: row.sent, status: row.status, edited_at: row.edited_at,
        encrypted: row.encrypted, created_at: row.created_at,
        reply_to_id: replyTo ? replyTo.id : null, reply_to: replyTo, reactions: [],
    };
    if (mine) message.mine = true;
    return apiMessage(message);
}

// Сообщение для ответа клиенту по уже сохранённой строке (повтор запроса): то же,
// что вернула бы первая отправка. Повторяет её только автор, поэтому mine: true.
function messageFromRow(row, text, replyTo = null) {
    return roomMessagePayload(row, text, { replyTo, mine: true });
}

function createMessages(ctx) {
    const {
        UPLOAD_QUOTA_BYTES, authorTags, dbGet, dbRun, withTransactionRetry, disappearingMessagesManager,
    } = ctx;

    // Вставка сообщения ЧАТА С БОТОМ от пользователя userId. Порядок блокировок
    // users → rooms → room_participants → chats → … → upload_quota → messages
    // (message-ordering.md, раздел 8.1): строка отправителя берётся явно ПЕРВОЙ
    // (FOR KEY SHARE), и только потом INSERT, у которого триггер seq блокирует строку
    // чата, а внешние ключи — chats и снова users. Без явного шага INSERT проверял бы
    // внешние ключи в порядке их создания, и отправка сходилась бы во взаимной
    // блокировке с удалением аккаунта. Нет строки users — аккаунт удалён: null.
    // upload = { bytes } — вложение: квота резервируется в той же транзакции, строка
    // чата берётся раньше строки квоты. { error: 'quota' } — квота исчерпана.
    // INSERT — последний оператор транзакции. При 40P01 транзакция повторяется один
    // раз.
    async function insertChatMessage(userId, fields, expirySeconds, upload = null) {
        const row = await withTransactionRetry(async (client) => {
            const sender = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
            if (sender.rows.length === 0) return null;
            if (upload) {
                await client.query('SELECT id FROM chats WHERE id = $1 FOR NO KEY UPDATE', [fields.chat_id]);
                if (!(await reserveUploadQuota(client, authorTags.qkey(userId), upload.bytes, UPLOAD_QUOTA_BYTES))) {
                    return { error: 'quota' };
                }
            }
            return insertMessageRow(client, fields, expirySeconds);
        });
        // Таймер в памяти — точный; в базе срок округлён вверх до минуты.
        if (row && !row.error && expirySeconds) disappearingMessagesManager.scheduleNewMessage(row.id, expirySeconds);
        return row;
    }

    // Транзакция отправки в КОМНАТУ (sealed-sender.md, 8.5): членство отправителя
    // проверяется внутри неё, под блокировкой строки комнаты. Выход из комнаты берёт
    // rooms FOR UPDATE и решает, писать ли user_left_rooms, по тому, есть ли у
    // пользователя сообщения; без блокировки «выход без сообщений + отправка» оставили
    // бы строку с тегом пользователя, которой удаление аккаунта не найдёт.
    //
    //   BEGIN
    //     users(я) FOR KEY SHARE                 → { error: 'no-user' }   (401)
    //     rooms    FOR NO KEY UPDATE             → { error: 'no-room' }   (404)
    //     room_participants                      → { error: 'not-member' } (403)
    //     [вложение] резервирование квоты        → { error: 'quota' }     (413)
    //     INSERT messages (последний оператор)   — триггер seq: UPDATE rooms SET msg_seq
    //   COMMIT
    //
    // created_at — минута, которую приложение передаёт в INSERT и от которой считает
    // тег (неделя): строка и тег согласованы. id выбирает клиент (clientMessageId) и
    // известен до вставки, поэтому AAD enc:v3 собирается заранее. Откат (409, ошибка)
    // откатывает и резервирование квоты. Возвращает { row: { id, seq, created_at } }
    // или { error }.
    async function insertRoomMessage({ userId, roomId, id, plainText, fields, expirySeconds, upload = null }) {
        const outcome = await withTransactionRetry(async (client) => {
            const sender = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
            if (sender.rows.length === 0) return { error: 'no-user' };
            const room = await client.query('SELECT id FROM rooms WHERE id = $1 FOR NO KEY UPDATE', [roomId]);
            if (room.rows.length === 0) return { error: 'no-room' };
            const member = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
            if (member.rows.length === 0) return { error: 'not-member' };
            if (upload && !(await reserveUploadQuota(client, authorTags.qkey(userId), upload.bytes, UPLOAD_QUOTA_BYTES))) {
                return { error: 'quota' };
            }
            const createdAt = floorToMinute(new Date());
            const authorTag = authorTags.tagFor(roomId, userId, createdAt);
            const text = writeMessageText(plainText, { room_id: roomId, id, author_tag: authorTag });
            const row = await insertMessageRow(client, {
                id, room_id: roomId, author_tag: authorTag, created_at: createdAt, text, ...fields,
            }, expirySeconds);
            return { row };
        });
        if (outcome.row && expirySeconds) disappearingMessagesManager.scheduleNewMessage(outcome.row.id, expirySeconds);
        return outcome;
    }

    // Что сейчас с id сообщения КОМНАТЫ (раздел 6.4 контракта порядка сообщений):
    //   free      — свободен;
    //   duplicate — строка уже есть, и это тот же запрос: та же комната, тот же автор
    //               (тег строки входит в теги пользователя за неделю её created_at),
    //               расшифрованный на сервере текст равен присланному, а у вложения
    //               file_url задан. Повтор после обрыва связи идемпотентен: клиент
    //               получает уже сохранённое сообщение (row);
    //   conflict  — id занят другим сообщением либо стоит в надгробии: 409, клиент
    //               выберет новый id и зашифрует содержимое заново.
    async function describeMessageIdUse({ id, roomId, userId, expectedText, file }) {
        const row = await dbGet(
            `SELECT id, seq, room_id, author_tag, text, file_url, file_name, file_type, message_type,
                sent, status, edited_at, encrypted, created_at, reply_to_id
         FROM messages WHERE id = $1`,
            [id]
        );
        if (row) {
            const same = row.room_id === roomId
                && authorTags.ownsTag(row.author_tag, authorTags.tagsForRow(row.room_id, userId, row.created_at))
                && Boolean(row.file_url) === Boolean(file)
                && expectedText !== null && expectedText !== undefined
                && readMessageText(row.text, row) === expectedText;
            return same ? { status: 'duplicate', row } : { status: 'conflict' };
        }
        const retired = await dbGet('SELECT 1 AS retired FROM message_tombstones WHERE id = $1 AND expires_at > now()', [id]);
        return retired ? { status: 'conflict' } : { status: 'free' };
    }

    // Отправитель сам не считает свои сообщения непрочитанными: после COMMIT вставки
    // его личный маркер двигается к seq сообщения (sealed-sender.md, 8.3). Маркер
    // только растёт, поэтому по порядку блокировок отдельным оператором безопасно.
    // Упрощение документа: чужие сообщения со seq меньше нового тоже перестают быть
    // непрочитанными. Сбой только логируется - сообщение уже сохранено.
    async function advanceSenderMarker(chat, seq) {
        try {
            await dbRun('UPDATE chats SET last_read_seq = $1 WHERE id = $2 AND last_read_seq < $1', [seq, chat.id]);
            chat.last_read_seq = Math.max(Number(chat.last_read_seq) || 0, Number(seq));
        } catch (err) {
            logError('[Chats] Не удалось сдвинуть маркер отправителя', err);
        }
    }

    // Сообщение, которое пользователь вправе менять или удалять (sealed-sender.md,
    // 8.2). В комнате автора в строке нет, поэтому: пользователь - ТЕКУЩИЙ участник
    // комнаты, сообщение для него ВИДНО (seq > visible_from_seq) и тег строки входит
    // в его теги за неделю created_at строки. Вышедший и вернувшийся участник со
    // своими старыми сообщениями под границей видимости их не меняет и не удаляет
    // (он удалит их вместе с аккаунтом). Нет строки, граница, чужой тег - один и тот же
    // ответ null: чужое, невидимое и несуществующее неразличимы. В чате с ботом -
    // по user_id, как раньше. Выбираются поля для AAD (writeMessageText).
    async function findOwnMessage(messageId, userId, { sentOnly = false } = {}) {
        const inRoom = await dbGet(
            `SELECT m.id, m.seq, m.room_id, m.author_tag, m.created_at, m.encrypted, m.file_url, m.sent
         FROM messages m
         JOIN room_participants rp ON rp.room_id = m.room_id AND rp.user_id = $2
         WHERE m.id = $1 AND m.room_id IS NOT NULL AND m.seq > rp.visible_from_seq`,
            [messageId, userId]
        );
        if (inRoom) {
            const mine = authorTags.ownsTag(inRoom.author_tag, authorTags.tagsForRow(inRoom.room_id, userId, inRoom.created_at));
            return mine && (!sentOnly || Number(inRoom.sent) === 1) ? inRoom : null;
        }
        const inBotChat = await dbGet(
            `SELECT id, seq, chat_id, room_id, user_id, encrypted, file_url, sent
         FROM messages WHERE id = $1 AND room_id IS NULL AND user_id = $2`,
            [messageId, userId]
        );
        return inBotChat && (!sentOnly || Number(inBotChat.sent) === 1) ? inBotChat : null;
    }

    async function userCanAccessMessage(userId, messageId) {
        // LEFT JOIN, не INNER JOIN (см. п.3 аудита): если автор сообщения вышел
        // из групповой комнаты, его персональная строка в chats удаляется и
        // m.chat_id уходит в NULL (ON DELETE SET NULL). INNER JOIN на chats
        // тогда терял строку сообщения целиком, и функция возвращала false для
        // абсолютно любого пользователя — файл переставал открываться вообще
        // всем, включая оставшихся участников комнаты. m.room_id при этом всегда
        // записан прямо на сообщении в момент отправки (см. /api/messages,
        // /api/messages/file) и не зависит от того, жива ли ещё запись chats
        // автора, поэтому для групповых чатов JOIN для доступа не обязателен.
        const row = await dbGet(
            `SELECT m.seq, m.room_id, c.room_id AS chat_room_id, c.user_id AS chat_owner_id
         FROM messages m
         LEFT JOIN chats c ON m.chat_id = c.id
         WHERE m.id = $1`,
            [messageId]
        );
        if (!row) return false;
        const roomId = row.room_id || row.chat_room_id;
        if (!roomId) {
            // Не групповой (1:1) чат — доступ только у владельца самой записи
            // chats. Если chat_id уже NULL, значит запись chats удалена вместе
            // со всем DM-чатом (см. DELETE /api/chats/:chatId, ветка без
            // room_id — там messages удаляются явно перед чатом), и доступа ни
            // у кого больше нет.
            return row.chat_owner_id != null && row.chat_owner_id === userId;
        }
        // Участник, вступивший после этого сообщения, его не видит — ни файл,
        // ни реакции (граница visible_from_seq, см. addRoomMember).
        const participant = await dbGet(
            'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2 AND visible_from_seq < $3',
            [roomId, userId, row.seq]
        );
        return Boolean(participant);
    }

    // Файлы отдаются только тому, кто реально является участником чата/комнаты,
    // к которому относится сообщение с этим файлом — а не просто "залогинен ли
    // кто-то вообще" (см. п.1 аудита). Имя файла уникально (случайное),
    // поэтому джойн messages.file_url -> chats/room_participants однозначно
    // определяет владельца. Поиск идёт по индексу idx_messages_file_url.
    async function userCanAccessFile(userId, filename) {
        const fileUrl = `/uploads/${filename}`;
        const message = await dbGet('SELECT id FROM messages WHERE file_url = $1 LIMIT 1', [fileUrl]);
        if (!message) return false;
        return userCanAccessMessage(userId, message.id);
    }

    // Остаток квоты вложений пользователя (подсказка до обработки файла, R1 п.1).
    function uploadQuotaLeft(userId) {
        return remainingUploadQuota({ dbGet }, authorTags.qkey(userId), UPLOAD_QUOTA_BYTES);
    }

    return {
        insertChatMessage, insertRoomMessage, describeMessageIdUse, advanceSenderMarker, findOwnMessage,
        userCanAccessMessage, userCanAccessFile, uploadQuotaLeft,
    };
}

module.exports = {
    createMessages, writeMessageText, apiMessage, e2eePolicyViolation, expectedFileMessageText,
    messageFromRow, readMessageText, roomMessagePayload, respondRoomSendError,
};
