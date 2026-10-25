'use strict';
// Транзакции: withTransaction, повтор при взаимной блокировке (withTransactionRetry), запрос с
// повтором и повтор вставки с занятым id сообщения. Ответ 503 при deadlock и других сбоях
// доступности базы — lib/db-errors.js (respondIfDbBusy). Вынесено из server.js.

const { createTransactionRetry } = require('../../lib/tx-retry');
const { guardClient } = require('../../lib/pg-client-guard');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const { isMessageIdConflict } = require('../../lib/message-ids');

// Вставки, где id выдаёт DEFAULT (чат с ботом, приветствие): два одинаковых
// случайных id в одну минуту или попадание в надгробие — один повтор на 23505
// по id сообщения (message-ids.js: isMessageIdConflict).
async function withMessageIdRetry(work) {
    try {
        return await work();
    } catch (err) {
        if (!isMessageIdConflict(err)) throw err;
        return work();
    }
}

function createTransactions(ctx) {
    const { pool } = ctx;

    async function withTransaction(work) {
        const client = await pool.connect();
        // Обрыв соединения посреди транзакции — ошибка запроса, а не падение
        // процесса (lib/pg-client-guard.js).
        const release = guardClient(client, '[DB] Обрыв соединения во время транзакции');
        let broken;
        try {
            await client.query('BEGIN');
            const result = await work(client);
            await client.query('COMMIT');
            return result;
        } catch (txErr) {
            // Исходная ошибка важнее: сбой самого ROLLBACK её не затирает. Не
            // откатившееся соединение в пул не возвращается — оно закрывается.
            await client.query('ROLLBACK').catch((rollbackErr) => { broken = rollbackErr; });
            throw txErr;
        } finally {
            release(broken);
        }
    }

    // Транзакция с одним повтором при взаимной блокировке (40P01, раздел 8.3
    // контракта порядка сообщений; lib/tx-retry.js). Первая попытка откатилась
    // целиком, поэтому повтор безопасен: work() обязана не иметь побочных эффектов
    // вне БД и читать всё заново (вставка сообщения идемпотентна по clientMessageId).
    // Если вторая попытка тоже упала с 40P01, ошибка уходит вызывающему, а он
    // отвечает 503 busy (respondIfDbBusy, lib/db-errors.js). В лог — только код ошибки, без id.
    // Строка предупреждения нужна сквозным тестам блокировок: они считают повторы.
    const withTransactionRetry = createTransactionRetry({ withTransaction, warn: (message) => console.warn(message) });

    // Один оператор с повтором при 40P01: для записей, которые не вошли в порядок
    // блокировок целиком (реакции, заявки, key-share — раздел 8.2), но ссылаются на
    // users и rooms внешними ключами и потому могут сойтись с удалением аккаунта.
    function queryWithRetry(sql, params) {
        return withTransactionRetry((client) => client.query(sql, params));
    }

    return { withTransaction, withTransactionRetry, queryWithRetry };
}

module.exports = { createTransactions, withMessageIdRetry };
