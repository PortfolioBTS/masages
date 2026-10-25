'use strict';
// Сессии express-session в Postgres (connect-pg-simple) с огрублением времени
// и продление сессий анонимов (контракт этапа 1, §4).
//
// NyxoPgStore пишет в таблицу session не сам объект сессии, а копию, где
// время огрублено: cookie.expires и originalMaxAge — вверх до 5 минут,
// createdAt не хранится. Срок строки (session.expire) — тоже вверх до 5
// минут: для куки со сроком — её expires, для куки без срока (tab) —
// сейчас + 24 часа. Точные моменты запросов в таблице не оседают; кука в
// браузере остаётся точной — её выставляет express-session из объекта в
// памяти.
//
// Строки сессий без срока (tab) продлевает сервер: HTTP-запросом раз в
// интервал продления (renewSession) и touch открытых сокетов
// (extendTabSessions), иначе вкладка, открытая дольше суток, теряла бы
// аккаунт.

const connectPgSimple = require('connect-pg-simple');
const {
    SESSION_RENEW_INTERVAL_MS,
    anonCookieMaxAgeMs,
    renewBucket,
    storedAnonLifetime,
} = require('./anon-lifetime');

// TTL строки session у куки без срока.
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
// Шаг огрубления времени в таблице session.
const SESSION_TIME_STEP_MS = 5 * 60 * 1000;

function ceilToStep(ms, stepMs = SESSION_TIME_STEP_MS) {
    return Math.ceil(ms / stepMs) * stepMs;
}

// Копия сессии для записи в БД. JSON-круг снимает класс Cookie (его toJSON
// даёт expires строкой ISO) и методы Session.
function coarseSessionForStore(sess, { stepMs = SESSION_TIME_STEP_MS } = {}) {
    const stored = JSON.parse(JSON.stringify(sess));
    delete stored.createdAt;
    const cookie = stored.cookie;
    if (cookie && typeof cookie === 'object') {
        if (cookie.expires) {
            const expires = Date.parse(cookie.expires);
            if (Number.isFinite(expires)) cookie.expires = new Date(ceilToStep(expires, stepMs)).toISOString();
        }
        // originalMaxAge задаёт срок куки при каждом продлении (express-session
        // делает expires = сейчас + originalMaxAge), поэтому он округляется
        // вверх, а не отбрасывается. Для срока + 15 минут он кратен шагу и не
        // меняется: в базе нет «дрожащих» миллисекунд времени записи.
        if (typeof cookie.originalMaxAge === 'number' && Number.isFinite(cookie.originalMaxAge)) {
            cookie.originalMaxAge = ceilToStep(cookie.originalMaxAge, stepMs);
        }
    }
    return stored;
}

// session.expire (мс) для копии из coarseSessionForStore.
function sessionRowExpireMs(stored, { now = Date.now(), ttlMs = SESSION_TTL_MS, stepMs = SESSION_TIME_STEP_MS } = {}) {
    const expires = stored && stored.cookie && stored.cookie.expires ? Date.parse(stored.cookie.expires) : NaN;
    return Number.isFinite(expires) ? ceilToStep(expires, stepMs) : ceilToStep(now + ttlMs, stepMs);
}

// Подкласс стора connect-pg-simple для данного express-session. set()
// переопределён целиком: у connect-pg-simple срок строки без куки со сроком
// — сейчас + ttl с точностью до секунды, а здесь он огрубляется. Остальное
// (get, destroy, чистка просроченных строк) — как в библиотеке; touch
// выключен (disableTouch в src/http/middleware/session.js), продление — явное.
function createNyxoPgStore(session, { now = Date.now } = {}) {
    const PgStore = connectPgSimple(session);
    class NyxoPgStore extends PgStore {
        constructor(options = {}) {
            super({ ...options, ttl: SESSION_TTL_MS / 1000 });
        }

        set(sid, sess, fn) {
            const stored = coarseSessionForStore(sess);
            const expireSeconds = sessionRowExpireMs(stored, { now: now() }) / 1000;
            this.query(
                `INSERT INTO ${this.quotedTable()} (sess, expire, sid) SELECT $1, to_timestamp($2), $3
                 ON CONFLICT (sid) DO UPDATE SET sess = $1, expire = to_timestamp($2) RETURNING sid`,
                [stored, expireSeconds, sid],
                (err) => { if (fn) fn(err); }
            );
        }
    }
    return NyxoPgStore;
}

// Срок куки сессии по сроку аккаунта: tab — без срока, day/week — срок +
// 15 минут. originalMaxAge выставляется ровно: по нему express-session
// продлевает куку на каждом ответе, где она отправляется.
function setSessionCookieLifetime(cookie, lifetime) {
    const maxAge = anonCookieMaxAgeMs(lifetime);
    cookie.maxAge = maxAge;
    cookie.originalMaxAge = maxAge;
}

// Продление сессии на HTTP-запросе: раз в интервал меняется маркер
// sess.renewBucket — сессия «изменена», и express-session сам сохранит строку
// (новый expire) и для куки со сроком пошлёт Set-Cookie с новым Expires.
// Заодно срок сессии и куки сверяется с актуальным сроком аккаунта (его могли
// сменить в другой сессии). true — сессия продлена в этом запросе.
function renewSession(sess, { lifetime, now = Date.now(), intervalMs = SESSION_RENEW_INTERVAL_MS }) {
    const bucket = renewBucket(now, intervalMs);
    if (sess.renewBucket === bucket) return false;
    sess.renewBucket = bucket;
    const value = storedAnonLifetime(lifetime);
    if (sess.anonLifetime !== value) sess.anonLifetime = value;
    if (sess.cookie) setSessionCookieLifetime(sess.cookie, value);
    return true;
}

// Touch открытых сокетов: строки tab-сессий (кука без срока) этих
// пользователей живут ещё 24 часа от текущего момента. GREATEST — срок
// только растёт. Время — через to_timestamp, как у connect-pg-simple:
// колонка expire без часового пояса, и JS Date с поправкой пояса процесса
// разошёлся бы с поясом сессии Postgres.
async function extendTabSessions(dbRun, userIds, { now = Date.now(), ttlMs = SESSION_TTL_MS, stepMs = SESSION_TIME_STEP_MS } = {}) {
    const ids = [...new Set(userIds)].filter(id => Number.isSafeInteger(id) && id > 0).map(String);
    if (ids.length === 0) return 0;
    const result = await dbRun(
        `UPDATE session SET expire = GREATEST(expire, to_timestamp($2))
         WHERE sess->>'userId' = ANY($1::text[]) AND sess->'cookie'->>'expires' IS NULL`,
        [ids, ceilToStep(now + ttlMs, stepMs) / 1000]
    );
    return result && typeof result.rowCount === 'number' ? result.rowCount : 0;
}

module.exports = {
    SESSION_TTL_MS,
    SESSION_TIME_STEP_MS,
    ceilToStep,
    coarseSessionForStore,
    sessionRowExpireMs,
    createNyxoPgStore,
    setSessionCookieLifetime,
    renewSession,
    extendTabSessions,
};
