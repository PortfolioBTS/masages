'use strict';
// Приём вложений (multer): папка, имя файла на диске, тип и расширение, проверки запроса ДО
// записи файла на диск. Вынесено из server.js.

const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const {
    ENCRYPTED_FILE_MIME, ENCRYPTED_FILE_EXTENSION, MIME_EXTENSIONS, ALLOWED_MIME_TYPES,
} = require('../../../lib/security-utils');
const { isClientOutdated: isOutdatedProto } = require('../../../lib/proto');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const {
    CLIENT_OUTDATED, parseClientMessageId, BAD_MESSAGE_ID, ID_CONFLICT,
} = require('../../../lib/message-ids');
const { SAFE_FILENAME_RE } = require('../../services/uploads');
const { EarlyResponse } = require('../early-response');
const { toPositiveInt } = require('../params');
const { e2eePolicyViolation, expectedFileMessageText, messageFromRow } = require('../../services/messages');
const { STORAGE_FULL_MESSAGE } = require('../../../lib/account-limits');

// ALLOWED_MIME_TYPES и MIME_EXTENSIONS (жёсткий маппинг mimetype ->
// расширение на диске, расширение никогда не берётся из имени файла) —
// в lib/security-utils.js, рядом с обезличенными именами вложений.

// '.svg' явно в блок-листе как доп. защита (defense-in-depth, п.7 аудита):
// image/svg+xml и так не входит в ALLOWED_MIME_TYPES, но SVG может нести
// <script>, поэтому расширение блокируется отдельно на случай, если формат
// когда-либо попадёт в разрешённый список по ошибке.
const BLOCKED_EXTENSIONS = new Set(['.html', '.htm', '.php', '.exe', '.js', '.sh', '.py', '.rb', '.pl', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.msi', '.svg']);

function createUploadMiddleware(ctx) {
    const { UPLOADS_DIR, getOwnChat, describeMessageIdUse, diskGuard, openUploadGate } = ctx;

    const upload = multer({
        storage: multer.diskStorage({
            destination: (req, file, cb) => cb(null, UPLOADS_DIR),
            filename: (req, file, cb) => {
                // Расширение — только из MIME_EXTENSIONS (жёсткий маппинг по
                // уже проверенному в fileFilter mimetype), никогда из
                // file.originalname — см. комментарий у MIME_EXTENSIONS.
                // Шифротекст E2EE-вложения — всегда .bin.
                const ext = file.mimetype === ENCRYPTED_FILE_MIME ? ENCRYPTED_FILE_EXTENSION : (MIME_EXTENSIONS[file.mimetype] || '');
                // Имя — только случайное, без Date.now(): время загрузки в имени файла
                // (message-ordering.md, раздел 11) вернуло бы секунды, которые мы
                // огрубили в базе. 16 случайных байт: перебрать нельзя.
                const safeName = `${crypto.randomBytes(16).toString('hex')}${ext}`;
                if (!SAFE_FILENAME_RE.test(safeName)) {
                    return cb(new Error('Не удалось сформировать безопасное имя файла'));
                }
                cb(null, safeName);
            }
        }),
        // fieldSize: самое длинное текстовое поле - конверт E2EE (~11 КБ) или подпись (4000 символов);
        // по умолчанию multer пускает по 1 МБ на поле, то есть до 10 МБ полей ещё до проверки сессии (R1 п.8).
        limits: { fileSize: 50 * 1024 * 1024, files: 1, fields: 10, fieldSize: 64 * 1024 },
        // Имя файла в multipart — UTF-8 (по умолчанию busboy декодировал его как
        // latin1). Само имя больше нигде не хранится, но BLOCKED_EXTENSIONS
        // ниже смотрит на его расширение.
        defParamCharset: 'utf8',
        fileFilter: (req, file, cb) => {
            const ext = path.extname(file.originalname).toLowerCase();
            if (BLOCKED_EXTENSIONS.has(ext)) {
                return cb(new Error('Неподдерживаемый тип файла'), false);
            }
            // Поля формы (chatId, encrypted, envelope) клиент шлёт ДО файла,
            // поэтому к этому моменту они уже в req.body. application/octet-stream
            // — это шифротекст E2EE-вложения, и принимается он только с явным
            // encrypted=true: иначе под видом "шифротекста" можно было бы залить
            // любой файл без проверки сигнатуры и очистки метаданных. И наоборот,
            // encrypted=true с обычным типом — тоже отказ.
            const wantsEncrypted = Boolean(req.body) && req.body.encrypted === 'true';
            if (file.mimetype === ENCRYPTED_FILE_MIME) {
                return wantsEncrypted ? acceptUpload(req, file, cb) : cb(new Error('Неподдерживаемый тип файла'), false);
            }
            if (wantsEncrypted || !ALLOWED_MIME_TYPES.includes(file.mimetype)) {
                return cb(new Error('Неподдерживаемый тип файла'), false);
            }
            acceptUpload(req, file, cb);
        }
    });

    // Проверки запроса ДО приёма файла (message-ordering.md, раздел 6.3). multer
    // уже разобрал поля формы, пришедшие раньше файла (proto, chatId, encrypted,
    // clientMessageId, envelope), а тело файла ещё не читал: заведомо ненужный файл
    // на диск не пишется. Клиент обязан класть эти поля в FormData ДО поля file;
    // если proto или clientMessageId пришли позже, здесь их ещё нет и ответ — 400
    // client-outdated.
    //
    //   * нет сессии — 401;
    //   * нет proto или proto < 4 — 400 client-outdated (14.1);
    //   * чат с ботом — clientMessageId игнорируется (id выдаёт DEFAULT);
    //   * комната: нет id — 400 client-outdated, неверный формат — 400 bad-message-id;
    //   * id занят чужим сообщением или стоит в надгробии — 409 id-conflict;
    //   * тот же автор, комната и конверт (повтор после обрыва связи) — 200 с уже
    //     сохранённым сообщением, второй файл не принимается.
    // Если чата нет среди разобранных полей (chatId пришёл позже файла или чат
    // неизвестен), остальное проверит обработчик после приёма файла.
    function acceptUpload(req, file, cb) {
        // Поля снимаются СЕЙЧАС, синхронно: fileFilter вызывается в тот момент,
        // когда разобрано всё, что стоит до файла. Пока идёт запрос в базу, парсер
        // может успеть разобрать и поля после небольшого файла, но «после файла»
        // для проверки по-прежнему значит «нет».
        const body = { ...req.body };
        checkUploadBeforeStore(req.session, body, file).then(() => cb(null, true), (err) => cb(err, false));
    }

    async function checkUploadBeforeStore(session, body, file) {
        const userId = session && session.userId;
        if (!userId) throw new EarlyResponse(401, { success: false, message: 'Не авторизован' });
        // Места на томе вложений почти нет (UPLOAD_MIN_FREE_MB): файл не принимается совсем (R1 п.3).
        if (!(await diskGuard.hasRoom())) {
            throw new EarlyResponse(507, { success: false, code: 'storage-full', message: STORAGE_FULL_MESSAGE });
        }
        // Общий признак версии клиента (message-ordering.md, 14.1) — первая проверка
        // запроса после сессии. Поле proto лежит в FormData ДО файла; пришло позже —
        // здесь его ещё нет, и ответ — client-outdated.
        if (isOutdatedProto(body.proto)) throw new EarlyResponse(400, CLIENT_OUTDATED);
        const chat = toPositiveInt(body.chatId) ? await getOwnChat(body.chatId, userId) : null;
        if (chat && !chat.room_id) {
            // Чат с ботом: шифротекст читать некому — отказ до записи файла на диск.
            const violation = e2eePolicyViolation(chat, body.encrypted === 'true', null);
            if (violation) throw new EarlyResponse(400, violation);
            // Открытое вложение сервер разбирает сам: частота на аккаунт ограничена до записи файла (Н0).
            const limited = await openUploadGate(userId);
            if (limited) throw new EarlyResponse(limited.status, limited.body, limited.headers);
            return;
        }
        const raw = body.clientMessageId;
        if (raw === undefined || raw === null || raw === '') {
            // Чат назван, но такого нет: ответит обработчик («Чат не найден»).
            if (!chat && toPositiveInt(body.chatId)) return;
            throw new EarlyResponse(400, CLIENT_OUTDATED);
        }
        const id = parseClientMessageId(raw);
        if (id === null) throw new EarlyResponse(400, BAD_MESSAGE_ID);
        if (!chat) return;
        // Открытое вложение в комнате и неверный конверт — тоже до записи файла.
        const violation = e2eePolicyViolation(chat, body.encrypted === 'true', typeof body.envelope === 'string' ? body.envelope.trim() : '');
        if (violation) throw new EarlyResponse(400, violation);
        const expectedText = expectedFileMessageText(body, file.mimetype);
        const use = await describeMessageIdUse({ id, roomId: chat.room_id, userId, expectedText, file: true });
        if (use.status === 'duplicate') {
            throw new EarlyResponse(200, { success: true, message: messageFromRow(use.row, expectedText) });
        }
        if (use.status === 'conflict') throw new EarlyResponse(409, ID_CONFLICT);
    }

    // Приём вложения целиком: сессия проверяется ДО разбора multipart. Раньше multer разбирал тело (поля до
    // 10 МБ и файл на диск) и только потом обработчик отвечал 401: неавторизованный запрос стоил как
    // настоящая загрузка (R1 п.8). Теперь тело не разбирается и на диск не пишется: ответ уходит сразу, а
    // остаток тела дочитывается и отбрасывается (req.resume) - так клиент получает ответ, а не обрыв
    // соединения. Заведомо огромное или неизвестной длины тело (больше предела файла с запасом на поля) не
    // дочитывается: соединение закрывается после ответа.
    const MAX_DRAINED_BODY_BYTES = 51 * 1024 * 1024;
    const uploadSingleFile = upload.single('file');
    function uploadFile(req, res, next) {
        if (!(req.session && req.session.userId)) {
            if (!(Number(req.headers['content-length']) <= MAX_DRAINED_BODY_BYTES)) res.set('Connection', 'close');
            req.resume();
            return res.status(401).json({ success: false, message: 'Не авторизован' });
        }
        uploadSingleFile(req, res, next);
    }

    return { upload, uploadFile };
}

module.exports = { createUploadMiddleware };
