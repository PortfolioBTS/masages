'use strict';
// Запись ошибки в лог без персональных данных.
//
// У ошибок Postgres в detail, where и parameters лежат значения строк:
// «Key (user_id)=(1955890954) is not present in table "users"». id
// пользователей, комнат и заявок в логах хостинга связывают время запроса с
// конкретным аккаунтом, поэтому в лог идут только code (SQLSTATE или код
// системной ошибки), message и constraint — по ним причину видно и так.
// Стек тоже не пишется: console.error(err) печатает объект целиком, вместе
// с detail.
//
// Само message тоже бывает с данными запроса, поэтому его чистят (safeMessage):
//  - ошибки данных Postgres (класс 22): «invalid input syntax for type
//    integer: "1955890954"» повторяет значение, присланное клиентом;
//  - разбор JSON (SyntaxError, в том числе тела запроса): V8 вставляет в
//    сообщение начало разбираемого текста;
//  - ошибки body-parser и http-errors со статусом 4xx: «unsupported charset
//    "…"» повторяет заголовок клиента — остаются type и status;
//  - ошибки файловой системы: в «ENOENT: …, unlink '/uploads/<имя>'» лежит
//    путь, а в нём имя вложения, — путь заменяется на «<путь>».

const SQLSTATE_DATA_EXCEPTION = /^22[0-9A-Z]{3}$/;
const PATH_MASK = '<путь>';

// Node пишет путь в кавычках: «open '/uploads/x.bin'». Голое вхождение пути
// (его пишут не все библиотеки) заменяется только у путей подлиннее двух
// символов, иначе замена '.' или 'a' испортила бы весь текст.
function maskPath(text, path) {
    if (typeof path !== 'string' || path === '') return text;
    const quoted = text.split(`'${path}'`).join(`'${PATH_MASK}'`);
    return path.length > 2 ? quoted.split(path).join(PATH_MASK) : quoted;
}

function safeMessage(err) {
    if (typeof err.type === 'string' && err.type !== '' && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
        return `${err.type} (${err.status})`;
    }
    if (typeof err.code === 'string' && SQLSTATE_DATA_EXCEPTION.test(err.code)) {
        return 'значение запроса не подошло к типу или размеру столбца';
    }
    if (err.name === 'SyntaxError' || err instanceof SyntaxError) {
        return 'SyntaxError: разбираемый текст не показан';
    }
    const raw = typeof err.message === 'string' ? err.message : '';
    if (raw === '') return raw;
    // dest — второй путь у rename, link и copyFile.
    return maskPath(maskPath(raw, err.path), err.dest);
}

function describeError(err) {
    if (err === null || err === undefined) return 'неизвестная ошибка';
    if (typeof err !== 'object' && typeof err !== 'function') return String(err);
    const cleaned = safeMessage(err);
    const message = cleaned !== ''
        ? cleaned
        : (typeof err.name === 'string' && err.name !== '' ? err.name : 'ошибка без описания');
    const extra = [];
    if (err.code !== undefined && err.code !== null && err.code !== '') extra.push(`code=${err.code}`);
    if (typeof err.constraint === 'string' && err.constraint !== '') extra.push(`constraint=${err.constraint}`);
    return extra.length > 0 ? `${message} (${extra.join(', ')})` : message;
}

// context — где случилось («[Anon] Purge error»); log — для тестов.
function logError(context, err, { log = console.error } = {}) {
    log(`${context}: ${describeError(err)}`);
}

module.exports = { logError, describeError };
