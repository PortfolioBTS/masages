'use strict';
// POST /api/messages/file — отправка вложения (multipart). Вынесено из server.js.

const path = require('path');
const fs = require('fs');
const { stripMetadataFromFile } = require('../../../lib/metadata-stripper');
const { sanitizeText } = require('../../../lib/privacy');
const { ENCRYPTED_FILE_MIME, anonymizedFileName, checkMagicBytes } = require('../../../lib/security-utils');
const { isClientOutdated: isOutdatedProto } = require('../../../lib/proto');
const { logError } = require('../../../lib/log-error');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const {
    CLIENT_OUTDATED, parseClientMessageId, BAD_MESSAGE_ID, ID_CONFLICT, isMessageIdConflict,
} = require('../../../lib/message-ids');
const { toPositiveInt } = require('../params');
const {
    e2eePolicyViolation, messageFromRow, respondRoomSendError, roomMessagePayload, writeMessageText,
    apiMessage,
} = require('../../services/messages');
const { readFileHead, coarsenFileTimes } = require('../../services/uploads');
const { withMessageIdRetry, respondIfDeadlock } = require('../../db/transactions');
const { getSocketRoomKey } = require('../../realtime/io');

// checkMagicBytes (сигнатура файла против заявленного типа) — в
// lib/security-utils.js: чистая функция, её проверяют юнит-тесты.

function register(app, ctx) {
    const {
        UPLOAD_QUOTA_BYTES, UPLOADS_DIR, cleanupUploadedFile, rejectUpload, rejectUploadWith, io,
        emitRoomMessageEvent, newMessageExpirySeconds, getOwnChat, unarchiveForRecipients, insertChatMessage,
        insertRoomMessage, describeMessageIdUse, advanceSenderMarker, uploadFile, uploadQuotaLeft,
    } = ctx;

    // Квота вложений (sealed-sender.md, раздел 13): объём ЗАГРУЗОК ЗА ОКНО В 30 ДНЕЙ,
    // а не сумма размеров сообщений (у строки комнаты нет user_id). Строка квоты лежит
    // в upload_quota под псевдонимом qkey и резервируется в транзакции вставки
    // сообщения (lib/upload-quota.js); удаление сообщения квоту не возвращает. До
    // транзакции отсеивается только файл, который не поместился бы в квоту вовсе.

    // Два вида вложений:
    //   * обычное — только в чате с ботом: проверка сигнатуры, снятие метаданных
    //     (все типы, fail closed), имя по типу вместо исходного (anonymizedFileName);
    //   * E2EE (encrypted=true) — единственный вид в комнатах (R7): сервер получает
    //     лишь шифротекст (.bin) и E2EE-конверт с типом, именем и ключом файла;
    //     сигнатуры и метаданные тут проверять не у чего — это случайные байты.
    //     Открытое вложение в комнате и конверт неверной формы — 400
    //     (e2ee-required, bad-envelope), шифротекст в чате с ботом — 400 e2ee-not-allowed.
    // Сообщение комнаты несёт clientMessageId (раздел 6 контракта порядка сообщений):
    // его формат и занятость проверяет fileFilter ещё до приёма файла
    // (acceptUpload), здесь — повторно и для случая, когда chatId пришёл позже
    // файла. При 409 и при повторе той же отправки файл удаляется с диска.
    app.post('/api/messages/file', uploadFile, async (req, res) => {
        const file = req.file;
        const userId = req.session.userId;
        if (!userId) return rejectUpload(res, file, 401, 'Не авторизован');
        const body = req.body || {};
        // Общий признак версии клиента — первая проверка запроса (14.1); обычно её
        // делает fileFilter ещё до приёма файла, здесь — на случай, когда поле пришло
        // после файла или файла нет.
        if (isOutdatedProto(body.proto)) return rejectUploadWith(res, file, 400, CLIENT_OUTDATED);
        if (!file) return res.status(400).json({ success: false, message: 'Файл не выбран' });

        // Перепроверка fileFilter в обе стороны: шифротекст — только с флагом
        // encrypted, флаг — только с шифротекстом (поле encrypted могло прийти
        // после файла, когда fileFilter его ещё не видел).
        const encrypted = body.encrypted === 'true';
        if (encrypted !== (file.mimetype === ENCRYPTED_FILE_MIME)) {
            return rejectUpload(res, file, 400, 'Неподдерживаемый тип файла');
        }
        if (!toPositiveInt(body.chatId)) return rejectUpload(res, file, 400, 'Не указан чат');

        let caption = '';
        let envelope = null;
        if (encrypted) {
            // Форму конверта проверяет e2eePolicyViolation, когда известен чат.
            envelope = typeof body.envelope === 'string' ? body.envelope.trim() : '';
        } else {
            caption = typeof body.text === 'string' ? sanitizeText(body.text.trim()) : '';
            if (caption.length > 4000) return rejectUpload(res, file, 400, 'Подпись слишком длинная');
        }

        // Сначала проверка чата, id и квоты (дёшево), потом обработка файла (дорого).
        let chat;
        let clientId = null;
        const fileType = file.mimetype;
        // Исходное имя файла (file.originalname) не хранится и не логируется.
        const fileName = encrypted ? null : anonymizedFileName(fileType);
        const messageText = encrypted ? envelope : (caption || fileName);
        try {
            chat = await getOwnChat(body.chatId, userId);
            if (!chat) return rejectUpload(res, file, 404, 'Чат не найден');
            if (chat.room_id) {
                const raw = body.clientMessageId;
                if (raw === undefined || raw === null || raw === '') return rejectUploadWith(res, file, 400, CLIENT_OUTDATED);
                clientId = parseClientMessageId(raw);
                if (clientId === null) return rejectUploadWith(res, file, 400, BAD_MESSAGE_ID);
            }
            // Открытое вложение в комнате, неверный конверт и шифротекст в чате с
            // ботом (то же правило, что в fileFilter: поля могли прийти после файла).
            const violation = e2eePolicyViolation(chat, encrypted, envelope);
            if (violation) return rejectUploadWith(res, file, 400, violation);
            if (chat.room_id) {
                const use = await describeMessageIdUse({ id: clientId, roomId: chat.room_id, userId, expectedText: messageText, file: true });
                if (use.status === 'duplicate') {
                    cleanupUploadedFile(file);
                    return res.json({ success: true, message: messageFromRow(use.row, messageText) });
                }
                if (use.status === 'conflict') return rejectUploadWith(res, file, 409, ID_CONFLICT);
            }
            if (file.size > UPLOAD_QUOTA_BYTES) {
                return rejectUpload(res, file, 413, 'Превышена квота хранилища вложений');
            }
            // Остаток квоты — ДО санитайзера (R1 п.1): резерв делается только в
            // транзакции вставки, а обработка файла дорогая; аккаунт с исчерпанной
            // квотой иначе гонял бы её впустую. Окончательно решает резерв в транзакции.
            if (file.size > await uploadQuotaLeft(userId)) {
                return rejectUpload(res, file, 413, 'Превышена квота хранилища вложений');
            }
        } catch (err) {
            cleanupUploadedFile(file);
            throw err;
        }

        const uploadedFilePath = path.join(UPLOADS_DIR, file.filename);
        let fileSize = file.size;
        if (!encrypted) {
            try {
                const head = await readFileHead(uploadedFilePath, 12);
                if (!checkMagicBytes(head, file.mimetype)) {
                    return rejectUpload(res, file, 400, 'Содержимое файла не соответствует его типу');
                }
                // Метаданные (EXIF/GPS, автор PDF, теги видео...) снимаются
                // у ВСЕХ типов — раньше только у картинок и PDF.
                await stripMetadataFromFile(uploadedFilePath, file.mimetype);
                fileSize = (await fs.promises.stat(uploadedFilePath)).size;
            } catch (magicErr) {
                // Очередь обработки переполнена (lib/work-limiter.js): не ошибка файла,
                // повтор через несколько секунд пройдёт. В лог не пишем — это штатный отказ.
                if (magicErr && magicErr.busy) {
                    res.set('Retry-After', '5');
                    return rejectUpload(res, file, 503, magicErr.message);
                }
                // Раньше при исключении здесь проверка молча пропускалась и файл
                // проходил дальше — теоретическая лазейка мимо проверки типа файла.
                // Теперь любая ошибка проверки = отказ (fail closed), а не fail open.
                logError('Upload processing error', magicErr);
                // Отказ санитайзера с понятной причиной (userFacing) отдаётся как есть:
                // в нём нет данных файла, только что сделать пользователю.
                return rejectUpload(res, file, 400, magicErr && magicErr.userFacing ? magicErr.message : 'Не удалось проверить содержимое файла');
            }
        }
        await coarsenFileTimes(uploadedFilePath);

        try {
            const roomId = chat.room_id || null;
            const fileUrl = `/uploads/${file.filename}`;
            const messageType = encrypted ? 'file'
                : fileType.startsWith('image/') ? 'image' : fileType.startsWith('video/') ? 'video' : 'file';

            const fileFields = {
                file_url: fileUrl, file_name: fileName, file_type: fileType, message_type: messageType,
                sent: 1, status: 'sent', encrypted, file_size: fileSize,
            };
            const expirySeconds = await newMessageExpirySeconds(chat);
            // Квота резервируется в той же транзакции, что и вставка: откат (409,
            // ошибка) возвращает и её, а неудачная вставка квоту не расходует.
            const quotaUpload = { bytes: fileSize };

            if (roomId) {
                let outcome;
                try {
                    outcome = await insertRoomMessage({
                        userId, roomId, id: clientId, plainText: messageText, fields: fileFields, expirySeconds, upload: quotaUpload,
                    });
                } catch (err) {
                    if (isMessageIdConflict(err)) {
                        // Параллельная такая же отправка успела раньше: файл этой
                        // не нужен ни при повторе (200), ни при конфликте (409).
                        cleanupUploadedFile(file);
                        const use = await describeMessageIdUse({ id: clientId, roomId, userId, expectedText: messageText, file: true });
                        if (use.status === 'duplicate') {
                            return res.json({ success: true, message: messageFromRow(use.row, messageText) });
                        }
                        return res.status(409).json(ID_CONFLICT);
                    }
                    throw err;
                }
                if (outcome.error) {
                    cleanupUploadedFile(file);
                    return respondRoomSendError(res, outcome.error);
                }
                // Раньше здесь по setTimeout статус "доставлено"/"прочитано"
                // выставлялся через 1 и 2 секунды независимо от реальности (и без
                // обработки ошибок — сбой БД ронял процесс). Теперь 'read' ставит
                // только markChatRead, когда получатель действительно открыл чат.
                const row = {
                    id: outcome.row.id, seq: outcome.row.seq, room_id: roomId, file_url: fileUrl, file_name: fileName,
                    file_type: fileType, message_type: messageType, sent: 1, status: 'sent', edited_at: null, encrypted,
                    created_at: outcome.row.created_at,
                };
                await advanceSenderMarker(chat, row.seq);
                emitRoomMessageEvent('newMessage', roomId, userId, roomMessagePayload(row, messageText));
                res.json({ success: true, message: roomMessagePayload(row, messageText, { mine: true }) });
                unarchiveForRecipients(chat, userId);
                return;
            }

            // Чат с ботом: id по DEFAULT, при гонке или попадании в надгробие — один повтор.
            const fields = {
                chat_id: chat.id, room_id: null, user_id: userId,
                text: writeMessageText(messageText, { room_id: null, chat_id: chat.id, user_id: userId }),
                ...fileFields,
            };
            const inserted = await withMessageIdRetry(() => insertChatMessage(userId, fields, expirySeconds, quotaUpload));
            if (!inserted) return rejectUpload(res, file, 401, 'Не авторизован');
            if (inserted.error) return rejectUpload(res, file, 413, 'Превышена квота хранилища вложений');

            const fileMessage = apiMessage({
                id: inserted.id, seq: inserted.seq, chat_id: chat.id, room_id: null, user_id: userId,
                sender_username: req.session.username, sender_avatar: req.session.avatar || '',
                text: messageText, file_url: fileUrl, file_name: fileName,
                file_type: fileType, message_type: messageType, sent: 1, status: 'sent',
                edited_at: null, encrypted, created_at: inserted.created_at,
                reply_to: null, reactions: [],
            });
            io.to(getSocketRoomKey(chat.id, null)).emit('newMessage', fileMessage);
            res.json({ success: true, message: fileMessage });
        } catch (error) {
            cleanupUploadedFile(file);
            if (respondIfDeadlock(res, error)) return;
            logError('Upload file error', error);
            res.status(500).json({ success: false, message: 'Ошибка отправки файла' });
        }
    });
}

module.exports = { register };
