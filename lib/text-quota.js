'use strict';
// Суточный объём текста сообщений на аккаунт (W7 R1 п.3). Без него аккаунт мог слать
// конверты по ~11 КБ, пока не упрётся в общий лимит запросов (~1 ГБ в сутки с аккаунта).
//
// Счётчик лежит в UNLOGGED-таблице rl_counters (lib/pg-limits.js) под ключом
// text-quota:HMAC(user_id): ни id, ни имени в таблице нет, а строка сама исчезает
// через сутки после первой записи окна (уборка purgeExpiredLimits) и вместе с
// удалением аккаунта ничего не оставляет. Окно фиксированное, 24 часа с первой
// отправки; потеря таблицы при аварии БД безвредна (лимит начнётся заново).
//
// Резерв делается ОДНИМ оператором вне транзакции вставки сообщения: так он не
// входит в порядок блокировок users -> rooms -> ... -> messages (message-ordering.md,
// раздел 8.1), и взаимной блокировки с удалением аккаунта быть не может. Цена -
// отправка, не дошедшая до вставки (409, сбой), расход всё равно учтёт.

const { createLimitKeys, LimitStoreError } = require('./pg-limits');

const SCOPE = 'text-quota';
const WINDOW_SQL = "interval '24 hours'";

const RESERVE_SQL = `
    INSERT INTO rl_counters AS c (k, hits, reset_at)
    VALUES ($1, $2::int, now() + ${WINDOW_SQL})
    ON CONFLICT (k) DO UPDATE SET
        hits     = CASE WHEN c.reset_at <= now() THEN $2::int ELSE c.hits + $2::int END,
        reset_at = CASE WHEN c.reset_at <= now() THEN now() + ${WINDOW_SQL} ELSE c.reset_at END
    WHERE (CASE WHEN c.reset_at <= now() THEN $2::int ELSE c.hits + $2::int END) <= $3::int
    RETURNING hits
`;

// pool - { query(sql, params) }. reserve: true - объём учтён, false - суточный объём
// исчерпан. Сбой хранилища - LimitStoreError (вызывающий отвечает 503 busy).
function createTextQuota({ pool, secret, limitBytes }) {
    const keys = createLimitKeys(secret);
    return {
        async reserve(userId, bytes) {
            // Одно сообщение не больше суточного объёма: иначе первая вставка (она не
            // проверяется условием ON CONFLICT) оставила бы строку с превышением.
            if (!(bytes > 0) || bytes > limitBytes) return false;
            try {
                const result = await pool.query(RESERVE_SQL, [keys.text(SCOPE, String(userId)), bytes, limitBytes]);
                return result.rows.length > 0;
            } catch (err) {
                throw new LimitStoreError('Счётчик текста недоступен', err);
            }
        },
    };
}

module.exports = { createTextQuota, RESERVE_SQL, SCOPE };
