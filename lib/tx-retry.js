'use strict';
// Транзакция с одним повтором при взаимной блокировке Postgres (40P01).
// Порядок блокировок users → rooms → room_participants → chats → messages
// (docs/security/message-ordering.md, раздел 8) закрывает почти все циклы, но
// не все: внешние ключи проверяются в порядке их создания, а реакции, заявки и
// key-share пишут строки, ссылающиеся на users и rooms без явного порядка.
// Postgres разрывает цикл, откатывая одну из транзакций, — безопасно повторить
// её целиком один раз (раздел 8.3).
//
// Вынесено из server.js, чтобы поведение проверялось юнит-тестом
// (test/tx-retry.test.js) без базы.

const { isDeadlock } = require('./message-ids');

// withTransaction(work) — выполняет work(client) в BEGIN/COMMIT и откатывает
// при ошибке; warn(message) — куда сообщить о повторе (в лог пишется только
// код ошибки, без id и текста запроса).
function createTransactionRetry({ withTransaction, warn }) {
    return async function withTransactionRetry(work) {
        try {
            return await withTransaction(work);
        } catch (err) {
            if (!isDeadlock(err)) throw err;
            // Первая попытка откатилась целиком: work() должна не иметь побочных
            // эффектов вне БД и читать всё заново. Вторая попытка тоже упала с
            // 40P01 — ошибка уходит вызывающему, он отвечает 503 busy.
            if (typeof warn === 'function') warn('[DB] Взаимная блокировка (40P01), транзакция повторяется');
            return withTransaction(work);
        }
    };
}

module.exports = { createTransactionRetry };
