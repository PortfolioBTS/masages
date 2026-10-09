'use strict';
// Идентификаторы сообщений и курсоры порядка (docs/security/message-ordering.md,
// разделы 6 и 7): чистые функции без БД, их проверяют юнит-тесты.
//
// * parseClientMessageId — id сообщения комнаты выбирает клиент (до шифрования,
//   чтобы положить его внутрь E2EE-содержимого как mid). Формат строго
//   ^[1-9]\d{6,9}$ и не больше 2^31-1; в запросе только строка (число принимается
//   лишь там, где оно было и раньше: replyToId, messageId в реакциях).
// * parseSeq — курсоры beforeSeq и upToSeq: положительное целое не больше 2^31-1,
//   строкой или числом.
// * isMessageIdConflict — конфликт именно id сообщения (первичный ключ или
//   надгробие), а не любой 23505: нарушение уникального индекса (room_id, seq)
//   означало бы сбой выдачи seq, и повторять такую вставку нельзя.
// * тела ответов с кодами: все новые ошибки контракта имеют вид
//   { success:false, code, message } и HTTP-статус (раздел 14).

const MAX_MESSAGE_ID = 2147483647;
const CLIENT_MESSAGE_ID_RE = /^[1-9]\d{6,9}$/;

// Целое id или null: строка неверного формата, число, пустое значение и всё
// остальное — null. Проверка длины строки идёт регуляркой, а не Number(): строка
// вроде "1e7" или "0x10" в Number() валидна, а клиентом так выбрать id нельзя.
function parseClientMessageId(value) {
    if (typeof value !== 'string' || !CLIENT_MESSAGE_ID_RE.test(value)) return null;
    const id = Number(value);
    return id <= MAX_MESSAGE_ID ? id : null;
}

// Курсор порядка: строка из цифр или целое число, 1..2^31-1; иначе null.
function parseSeq(value) {
    let n;
    if (typeof value === 'number') n = value;
    else if (typeof value === 'string' && /^[1-9]\d{0,9}$/.test(value)) n = Number(value);
    else return null;
    return Number.isInteger(n) && n >= 1 && n <= MAX_MESSAGE_ID ? n : null;
}

const MESSAGE_ID_CONSTRAINTS = new Set(['messages_pkey', 'message_tombstones_pkey']);

function isMessageIdConflict(err) {
    return Boolean(err) && err.code === '23505' && MESSAGE_ID_CONSTRAINTS.has(err.constraint);
}

// Взаимная блокировка Postgres (deadlock_detected).
function isDeadlock(err) {
    return Boolean(err) && err.code === '40P01';
}

const CLIENT_OUTDATED = Object.freeze({
    success: false,
    code: 'client-outdated',
    message: 'Обновите страницу: эта версия приложения устарела и больше не поддерживается',
});
const BAD_MESSAGE_ID = Object.freeze({
    success: false,
    code: 'bad-message-id',
    message: 'Некорректный идентификатор сообщения',
});
const ID_CONFLICT = Object.freeze({
    success: false,
    code: 'id-conflict',
    message: 'Идентификатор сообщения занят, повторите отправку',
});
const BAD_SEQ = Object.freeze({
    success: false,
    code: 'bad-seq',
    message: 'Некорректный номер сообщения',
});

module.exports = {
    MAX_MESSAGE_ID,
    CLIENT_MESSAGE_ID_RE,
    parseClientMessageId,
    parseSeq,
    isMessageIdConflict,
    isDeadlock,
    CLIENT_OUTDATED,
    BAD_MESSAGE_ID,
    ID_CONFLICT,
    BAD_SEQ,
};
