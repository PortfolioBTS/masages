// Срок жизни анонимного аккаунта. Аноним сам выбирает, сколько его данные
// живут БЕЗ АКТИВНОСТИ: 30 минут ("до закрытия вкладки"), сутки или
// неделю; в любом случае — не дольше 7 дней с создания. Активность —
// открытый сокет и запросы к API (см. server.js). Раньше срок был
// фиксированный: сессия 4 часа с момента создания, даже если человек всё
// это время переписывался, и удаление ещё через час.
//
// Чистые функции — проверяются тестами без БД (test/lib.test.js).

const ANON_LIFETIMES = Object.freeze({
    tab: 30 * 60,
    day: 24 * 60 * 60,
    week: 7 * 24 * 60 * 60,
});
const DEFAULT_ANON_LIFETIME = 'tab';
// Жёсткий потолок от создания: анонимный аккаунт не должен жить вечно,
// даже если вкладка открыта месяцами.
const ANON_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
// Как часто активность по API пишется в users.last_active_at (не чаще раза
// в минуту на пользователя) и как часто продлевается активность открытых
// сокетов. Оба интервала много меньше самого короткого срока (30 минут).
const ANON_ACTIVITY_PERSIST_INTERVAL_MS = 60 * 1000;
const ANON_SOCKET_ACTIVITY_INTERVAL_MS = 5 * 60 * 1000;

function isAnonLifetime(value) {
    return typeof value === 'string' && Object.prototype.hasOwnProperty.call(ANON_LIFETIMES, value);
}

// lifetime из тела запроса: не задан — 'tab'; неизвестное значение —
// RangeError с текстом для пользователя.
function parseAnonLifetime(value) {
    if (value === undefined || value === null || value === '') return DEFAULT_ANON_LIFETIME;
    if (!isAnonLifetime(value)) throw new RangeError('Некорректный срок жизни анонимного аккаунта');
    return value;
}

// Значение из БД/сессии: анонимы, созданные до появления выбора (NULL),
// живут по самому короткому сроку — как и было обещано им при входе
// ("данные удалятся после выхода").
function storedAnonLifetime(value) {
    return isAnonLifetime(value) ? value : DEFAULT_ANON_LIFETIME;
}

function anonLifetimeSeconds(lifetime) {
    return ANON_LIFETIMES[storedAnonLifetime(lifetime)];
}

// Момент удаления (мс), если с lastActiveMs больше не будет активности.
// lastActiveMs не задан — считаем от создания.
function anonExpiresAtMs({ lifetime, createdAtMs, lastActiveMs }) {
    const created = Number(createdAtMs);
    const lastActive = Number.isFinite(Number(lastActiveMs)) && lastActiveMs !== null ? Number(lastActiveMs) : created;
    const byInactivity = lastActive + anonLifetimeSeconds(lifetime) * 1000;
    const byAge = created + ANON_MAX_AGE_SECONDS * 1000;
    const result = Math.min(byInactivity, byAge);
    return Number.isFinite(result) ? result : 0;
}

function isAnonExpired({ lifetime, createdAtMs, lastActiveMs, now = Date.now() }) {
    // Без времени создания решить нельзя — такая сессия недействительна
    // (fail closed): её выдал не этот сервер.
    if (!Number.isFinite(Number(createdAtMs)) || createdAtMs === null) return true;
    return now >= anonExpiresAtMs({ lifetime, createdAtMs, lastActiveMs });
}

// maxAge сессионной куки анонима. 'tab' — кука без срока (живёт до
// закрытия браузера и не пишется на диск общего устройства надолго);
// 'day'/'week' — до жёсткого потолка: сервер сам проверяет неактивность
// при каждом запросе, а кука с коротким сроком выкинула бы из аккаунта,
// который из-за активности ещё жив.
function anonCookieMaxAgeMs({ lifetime, createdAtMs, now = Date.now() }) {
    if (storedAnonLifetime(lifetime) === 'tab') return null;
    return Math.max(0, Number(createdAtMs) + ANON_MAX_AGE_SECONDS * 1000 - now);
}

// Пора ли записать активность в БД (не чаще interval на пользователя).
function shouldPersistActivity(lastPersistedMs, now = Date.now(), intervalMs = ANON_ACTIVITY_PERSIST_INTERVAL_MS) {
    const last = Number(lastPersistedMs);
    return !Number.isFinite(last) || now - last >= intervalMs;
}

const LIFETIME_PHRASES = {
    tab: 'через 30 минут без активности',
    day: 'через сутки без активности',
    week: 'через 7 дней без активности',
};

// Первое сообщение бота анонимному пользователю. Без эмодзи и маркеров:
// только факты о том, что и когда будет удалено.
function anonWelcomeText(lifetime) {
    const phrase = LIFETIME_PHRASES[storedAnonLifetime(lifetime)];
    return [
        'Приватный режим.',
        `Аккаунт не связан с почтой или телефоном. Все его данные удаляются при выходе, а также ${phrase} — но не позже чем через 7 дней после создания.`,
        'Для большей анонимности используйте Tor Browser, не сообщайте о себе лишнего и включайте исчезающие сообщения.',
    ].join('\n\n');
}

module.exports = {
    ANON_LIFETIMES,
    DEFAULT_ANON_LIFETIME,
    ANON_MAX_AGE_SECONDS,
    ANON_ACTIVITY_PERSIST_INTERVAL_MS,
    ANON_SOCKET_ACTIVITY_INTERVAL_MS,
    isAnonLifetime,
    parseAnonLifetime,
    storedAnonLifetime,
    anonLifetimeSeconds,
    anonExpiresAtMs,
    isAnonExpired,
    anonCookieMaxAgeMs,
    shouldPersistActivity,
    anonWelcomeText,
};
