'use strict';
// Общее для наборов волны 1 (срок жизни анонима, сессии, куки): числа
// контракта docs/dev/contracts/stage-1.md §4 и разбор того, что сервер
// отдаёт в Set-Cookie и пишет в базу.
//
// Числа здесь — копия контракта, а не импорт из lib/anon-lifetime.js: тест
// сверяет сервер с контрактом, а не код с самим собой. Поменяется контракт —
// поменяется и этот файл.

const crypto = require('crypto');
const { parseSetCookie } = require('./cookies');
const { sessionIdFromCookie } = require('./time');

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

// §4: срок без активности. Потолка от создания нет.
const LIFETIME_MS = Object.freeze({ tab: 30 * MINUTE_MS, day: DAY_MS, week: 7 * DAY_MS });
const LIFETIME_SECONDS = Object.freeze({ tab: 1800, day: 86400, week: 604800 });
// §4: корзина активности — last_active_at пишется с округлением ВВЕРХ до 5 минут.
const BUCKET_MS = 5 * MINUTE_MS;
// §4: кука day/week живёт срок + 15 минут (переживает аккаунт с учётом корзины и интервала продления).
const COOKIE_EXTRA_MS = 15 * MINUTE_MS;
// §4: строка session живёт 24 часа (у tab-сессий её продлевает touch сокетов).
const SESSION_TTL_MS = DAY_MS;
const SESSION_COOKIE = 'connect.sid';

const bucketCeil = (ms) => Math.ceil(ms / BUCKET_MS) * BUCKET_MS;

// Куки сессии из заголовков ответа: массив { name, value, expiresAt, … }
// (разбор — как у браузера, helpers/cookies.js). expiresAt === null — кука
// сессионная: ни Expires, ни Max-Age.
function setCookies(response, name = SESSION_COOKIE, now = Date.now()) {
    const list = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
    return list.map(header => parseSetCookie(header, '/', now)).filter(cookie => cookie && cookie.name === name);
}

// Живая кука сессии клиента: { value, sid, expiresAt } или null.
function sessionCookie(client) {
    const cookie = client.jar.list('/').find(c => c.name === SESSION_COOKIE);
    if (!cookie) return null;
    return { value: cookie.value, sid: sessionIdFromCookie(cookie.value), expiresAt: cookie.expiresAt };
}

// Подпись куки так, как её ставит express-session (cookie-signature):
// s:<sid>.<HMAC-SHA256(sid, SESSION_SECRET) в base64 без «=»>, urlencoded.
// Нужна, чтобы подложить серверу куку чужой (например, легаси-) сессии.
function signSessionCookie(sid, secret) {
    const signature = crypto.createHmac('sha256', secret).update(sid).digest('base64').replace(/=+$/, '');
    return encodeURIComponent(`s:${sid}.${signature}`);
}

// Строка users: lastActiveMs — числом (null, если колонки нет в строке).
async function userRow(suite, id) {
    const { rows } = await suite.query(
        `SELECT id, anon_lifetime, last_active_at, created_at, read_receipts FROM users WHERE id = $1`, [id]
    );
    if (!rows[0]) return null;
    return { ...rows[0], lastActiveMs: rows[0].last_active_at ? new Date(rows[0].last_active_at).getTime() : null };
}

// Строка session: { sid, expireMs, sess } (sess — разобранный JSON) или null.
async function sessionRow(suite, sid) {
    const { rows } = await suite.query(`SELECT sid, sess, expire FROM session WHERE sid = $1`, [sid]);
    if (!rows[0]) return null;
    const sess = typeof rows[0].sess === 'string' ? JSON.parse(rows[0].sess) : rows[0].sess;
    return { sid: rows[0].sid, expireMs: new Date(rows[0].expire).getTime(), sess };
}

async function count(suite, sql, params = []) {
    const { rows } = await suite.query(`SELECT count(*)::int AS n FROM (${sql}) q`, params);
    return rows[0].n;
}

// Сдвинуть «срок жизни» сессии назад, как это делает тест времени: expire и
// cookie.expires на ms раньше (helpers/time.js#rewindSession), плюс сбросить
// маркер продления sess.renewBucket (контракт §4), чтобы СЛЕДУЮЩИЙ запрос
// считался первым в новом интервале и продлил сессию. Ждать смены интервала
// 5 минут нельзя, а подменять часы сервера — тоже.
async function forceRenewal(suite, sid, { rewindExpireMs = 0 } = {}) {
    if (rewindExpireMs > 0) await suite.time.rewindSession(sid, rewindExpireMs);
    const { rowCount } = await suite.query(
        `UPDATE session SET sess = (sess::jsonb || '{"renewBucket": -1}'::jsonb)::json WHERE sid = $1`, [sid]
    );
    if (rowCount === 0) throw new Error(`forceRenewal: нет сессии ${sid}`);
}

module.exports = {
    MINUTE_MS,
    HOUR_MS,
    DAY_MS,
    LIFETIME_MS,
    LIFETIME_SECONDS,
    BUCKET_MS,
    COOKIE_EXTRA_MS,
    SESSION_TTL_MS,
    SESSION_COOKIE,
    bucketCeil,
    setCookies,
    sessionCookie,
    signSessionCookie,
    userRow,
    sessionRow,
    count,
    forceRenewal,
};
