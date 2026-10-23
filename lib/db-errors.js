'use strict';
// Ошибки базы, при которых клиенту отвечают «занято» (503 busy с Retry-After), а
// не «внутренняя ошибка» (ревью W7 R2.4, R2.10).
//
// Это сбои не запроса, а доступности базы: соединения нет или оно оборвалось,
// пул исчерпан, кончились слоты, запрос не дождался блокировки или времени
// (таймауты сессии — src/db/pool.js), взаимная блокировка повторилась и после
// повтора. Повтор через несколько секунд обычно проходит, и клиенту нужно
// именно это: «повторите», а не «ошибка отправки». Ошибки самого запроса
// (ограничения, типы, синтаксис) сюда не входят — они остаются 4xx/500.

const { respondBusy } = require('./pg-limits');
const { logError } = require('./log-error');
const { isDeadlock } = require('./message-ids');

// SQLSTATE (https://www.postgresql.org/docs/16/errcodes-appendix.html):
//   класс 08 — обрыв и отказ соединения; класс 53 — нехватка ресурсов сервера
//   (53300 too_many_connections); 57P01–57P03 — сервер останавливается или ещё
//   запускается; 57014 — запрос отменён (statement_timeout); 55P03 — не дождался
//   блокировки (lock_timeout); 25P03 — простой в транзакции дольше
//   idle_in_transaction_session_timeout; 40P01 — взаимная блокировка;
//   40001 — конфликт сериализации.
const BUSY_SQLSTATES = new Set(['57P01', '57P02', '57P03', '57014', '55P03', '25P03', '40P01', '40001']);
const BUSY_SQLSTATE_CLASSES = new Set(['08', '53']);
const SQLSTATE_RE = /^[0-9A-Z]{5}$/;
// Сетевые коды Node: база недоступна по сети.
const BUSY_NET_CODES = new Set(['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH']);
// Тексты node-postgres без кода: пул не выдал соединение за connectionTimeoutMillis,
// соединение оборвалось или уже непригодно, пул закрыт; база закрыта для подключений.
const BUSY_MESSAGE_RE = /timeout exceeded when trying to connect|Connection terminated|connection error and is not queryable|Cannot use a pool after calling end|is not currently accepting connections/i;
// Хранилище точных лимитов (lib/pg-limits.js) недоступно.
const LIMIT_STORE_UNAVAILABLE = 'LIMIT_STORE_UNAVAILABLE';
const REPORT_INTERVAL_MS = 10 * 1000;

function isDbUnavailable(err) {
    if (!err || typeof err !== 'object') return false;
    const code = typeof err.code === 'string' ? err.code : '';
    if (code === LIMIT_STORE_UNAVAILABLE) return true;
    if (BUSY_SQLSTATES.has(code) || BUSY_NET_CODES.has(code)) return true;
    if (SQLSTATE_RE.test(code) && BUSY_SQLSTATE_CLASSES.has(code.slice(0, 2))) return true;
    return BUSY_MESSAGE_RE.test(typeof err.message === 'string' ? err.message : '');
}

// Не больше одной записи в REPORT_INTERVAL_MS: при упавшей базе каждый запрос
// приносит ту же ошибку, и лог не должен в ней тонуть.
function createBusyReporter({ log = logError, intervalMs = REPORT_INTERVAL_MS, now = Date.now } = {}) {
    let lastAt = -Infinity;
    let skipped = 0;
    return (err) => {
        if (now() - lastAt < intervalMs) {
            skipped++;
            return;
        }
        const extra = skipped > 0 ? ` (и ещё ${skipped} таких ответов за последние секунды)` : '';
        lastAt = now();
        skipped = 0;
        log(`[DB] База недоступна или занята, клиенту 503 busy${extra}`, err && err.cause ? err.cause : err);
    };
}

const defaultReporter = createBusyReporter();

// true — ошибка из этого класса, ответ 503 busy с Retry-After отправлен (если
// ответа ещё не было). Взаимная блокировка, повторившаяся после повтора
// (withTransactionRetry), пишется каждый раз своей строкой: её ищут сквозные
// тесты блокировок, и она редка.
function respondIfDbBusy(res, err, { report = defaultReporter } = {}) {
    if (!isDbUnavailable(err)) return false;
    if (isDeadlock(err)) logError('[DB] Взаимная блокировка повторилась, клиенту 503', err);
    else report(err);
    respondBusy(res);
    return true;
}

module.exports = { isDbUnavailable, respondIfDbBusy, createBusyReporter };
