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

function describeError(err) {
    if (err === null || err === undefined) return 'неизвестная ошибка';
    if (typeof err !== 'object' && typeof err !== 'function') return String(err);
    const message = typeof err.message === 'string' && err.message !== ''
        ? err.message
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
