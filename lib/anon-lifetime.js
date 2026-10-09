// Срок жизни анонимного аккаунта. Аноним сам выбирает, сколько его данные
// живут БЕЗ АКТИВНОСТИ: 30 минут ("пока открыта вкладка"), сутки или
// неделю. Потолка от создания нет: аккаунт, которым пользуются, живёт
// сколько нужно, а брошенный удаляется через выбранный срок. Активность —
// открытый сокет и запросы к API (server.js, lib/anon-activity.js).
//
// Время активности хранится огрублённым: корзинами по 5 минут с округлением
// ВВЕРХ (users.last_active_at). В базе нет точного времени последнего
// действия, а аккаунт никогда не удаляется раньше срока — позже максимум на
// корзину и период чистки.
//
// Чистые функции — проверяются тестами без БД (test/lib.test.js).

const ANON_LIFETIMES = Object.freeze({
    tab: 30 * 60,
    day: 24 * 60 * 60,
    week: 7 * 24 * 60 * 60,
});
const DEFAULT_ANON_LIFETIME = 'tab';
// Шаг корзины активности.
const ACTIVITY_STEP_MS = 5 * 60 * 1000;
// Кука day/week живёт на 15 минут дольше срока: аккаунт удаляется по
// корзине (до 5 минут позже точного срока) и чисткой (раз в 5 минут), и
// кука не должна пропасть раньше аккаунта.
const ANON_COOKIE_GRACE_MS = 15 * 60 * 1000;
// Продление сессии (маркер sess.renewBucket) — не чаще раза в 5 минут на
// сессию: каждое продление — запись строки session и Set-Cookie.
const SESSION_RENEW_INTERVAL_MS = 5 * 60 * 1000;
// Продление активности открытых сокетов — вдвое чаще шага корзины: пока
// сокет открыт, last_active_at отстаёт от настоящего момента меньше чем на
// корзину.
const ANON_SOCKET_ACTIVITY_INTERVAL_MS = 150 * 1000;

function isAnonLifetime(value) {
    return typeof value === 'string' && Object.prototype.hasOwnProperty.call(ANON_LIFETIMES, value);
}

// Смена срока (POST /api/user/lifetime): значение обязательно и без
// значения по умолчанию — пустой или кривой запрос не должен молча
// превращать неделю в 30 минут. Неизвестное значение — RangeError с текстом
// для пользователя.
function parseAnonLifetimeStrict(value) {
    if (!isAnonLifetime(value)) throw new RangeError('Некорректный срок жизни анонимного аккаунта');
    return value;
}

// lifetime из тела запроса регистрации: не задан — 'tab'.
function parseAnonLifetime(value) {
    if (value === undefined || value === null || value === '') return DEFAULT_ANON_LIFETIME;
    return parseAnonLifetimeStrict(value);
}

// Значение из БД или сессии: неизвестное — самый короткий срок (fail closed).
function storedAnonLifetime(value) {
    return isAnonLifetime(value) ? value : DEFAULT_ANON_LIFETIME;
}

function anonLifetimeSeconds(lifetime) {
    return ANON_LIFETIMES[storedAnonLifetime(lifetime)];
}

// Момент времени в мс; null, пустое и нечисловое — NaN (Number(null) был бы 0).
function toMs(value) {
    if (value === null || value === undefined || value === '' || typeof value === 'boolean') return NaN;
    return Number(value);
}

// Корзина активности: момент, округлённый ВВЕРХ до шага 5 минут. Ровно на
// границе — сама граница, поэтому повторное округление ничего не меняет.
function activityBucketMs(now) {
    return Math.ceil(toMs(now) / ACTIVITY_STEP_MS) * ACTIVITY_STEP_MS;
}

// Момент удаления (мс), если после lastActiveMs активности больше не будет:
// корзина последней активности + срок. Та же граница у чистки по БД
// (users.last_active_at уже хранит корзину), поэтому сессия действительна
// ровно столько, сколько живёт строка users. Без времени активности — NaN.
function anonExpiresAtMs({ lifetime, lastActiveMs }) {
    const bucket = activityBucketMs(lastActiveMs);
    return Number.isFinite(bucket) ? bucket + anonLifetimeSeconds(lifetime) * 1000 : NaN;
}

// Без времени активности решить нельзя — считаем истёкшим (fail closed).
function isAnonExpired({ lifetime, lastActiveMs, now = Date.now() }) {
    const expiresAt = anonExpiresAtMs({ lifetime, lastActiveMs });
    return !Number.isFinite(expiresAt) || now >= expiresAt;
}

// maxAge сессионной куки (мс). 'tab' — null, кука без срока: живёт до
// закрытия браузера и не остаётся на диске общего устройства. 'day'/'week'
// — срок + 15 минут; кука продлевается при каждом продлении сессии, то есть
// не реже раза в 5 минут активности.
function anonCookieMaxAgeMs(lifetime) {
    const value = storedAnonLifetime(lifetime);
    if (value === 'tab') return null;
    return ANON_LIFETIMES[value] * 1000 + ANON_COOKIE_GRACE_MS;
}

// Интервал продления сессии. Тестовая ручка NYXO_TEST_RENEW_INTERVAL_MS
// (целое число мс > 0) действует только при NODE_ENV=test: сквозные тесты
// не ждут по 5 минут. В production env-check считает её ошибкой.
function sessionRenewIntervalMs(env = process.env) {
    if (!env || env.NODE_ENV !== 'test') return SESSION_RENEW_INTERVAL_MS;
    const value = Number(env.NYXO_TEST_RENEW_INTERVAL_MS);
    return Number.isInteger(value) && value > 0 ? value : SESSION_RENEW_INTERVAL_MS;
}

// Номер интервала продления, в который попадает момент now: сессия
// продлевается, когда он отличается от sess.renewBucket.
function renewBucket(now, intervalMs = SESSION_RENEW_INTERVAL_MS) {
    return Math.floor(toMs(now) / intervalMs);
}

// Поля срока для ответов API (/api/auth, /api/user, регистрация, смена
// срока). anonExpiresAt — только у day/week: у 'tab' отсчёт идёт от
// закрытия последней вкладки, и «удалится в 12:05» было бы неправдой, пока
// вкладка открыта.
function describeAnonLifetime({ lifetime, lastActiveMs }) {
    const value = storedAnonLifetime(lifetime);
    const expiresAt = value === 'tab' ? NaN : anonExpiresAtMs({ lifetime: value, lastActiveMs });
    return {
        anonLifetime: value,
        anonInactivitySeconds: ANON_LIFETIMES[value],
        anonExpiresAt: Number.isFinite(expiresAt) ? new Date(expiresAt).toISOString() : null,
    };
}

const LIFETIME_PHRASES = Object.freeze({
    tab: 'через 30 минут без активности',
    day: 'через сутки без активности',
    week: 'через 7 дней без активности',
});

module.exports = {
    ANON_LIFETIMES,
    DEFAULT_ANON_LIFETIME,
    ACTIVITY_STEP_MS,
    ANON_COOKIE_GRACE_MS,
    SESSION_RENEW_INTERVAL_MS,
    ANON_SOCKET_ACTIVITY_INTERVAL_MS,
    LIFETIME_PHRASES,
    isAnonLifetime,
    parseAnonLifetime,
    parseAnonLifetimeStrict,
    storedAnonLifetime,
    anonLifetimeSeconds,
    activityBucketMs,
    anonExpiresAtMs,
    isAnonExpired,
    anonCookieMaxAgeMs,
    sessionRenewIntervalMs,
    renewBucket,
    describeAnonLifetime,
};
