// Настройки чата: общий таймер исчезающих сообщений комнаты и личные
// флаги строки chats (закреплён / без звука / в архиве). Чистые функции —
// проверяются тестами без БД (test/lib.test.js).

// Сроки, которые можно выбрать для чата: выкл, 5 минут, час, сутки,
// неделя. Произвольные значения не принимаются: таймер общий для всех
// участников, и у всех клиентов должен быть понятный набор вариантов.
const CHAT_EXPIRY_OPTIONS = Object.freeze([0, 300, 3600, 86400, 604800]);

// seconds из тела запроса -> одно из CHAT_EXPIRY_OPTIONS; иначе RangeError
// с текстом для пользователя.
function parseChatExpirySeconds(value) {
    let seconds = NaN;
    if (typeof value === 'number') seconds = value;
    else if (typeof value === 'string' && /^\s*\d{1,10}\s*$/.test(value)) seconds = Number(value);
    if (!CHAT_EXPIRY_OPTIONS.includes(seconds)) {
        throw new RangeError('Недопустимый срок: выключено, 5 минут, 1 час, 1 день или 1 неделя');
    }
    return seconds;
}

// Срок жизни нового сообщения: личный срок отправителя (expirySeconds в
// запросе) не может быть длиннее общего таймера чата — иначе один
// участник обходил бы договорённость всей комнаты.
function effectiveMessageExpiry(requestedSeconds, chatDefaultSeconds) {
    const requested = Number(requestedSeconds) > 0 ? Number(requestedSeconds) : null;
    const chatDefault = Number(chatDefaultSeconds) > 0 ? Number(chatDefaultSeconds) : null;
    if (requested && chatDefault) return Math.min(requested, chatDefault);
    return requested || chatDefault || null;
}

const CHAT_PREF_FIELDS = Object.freeze(['pinned', 'muted', 'archived']);

// Тело POST /api/chats/:chatId/prefs -> { pinned, muted, archived }, где
// null — поле не меняется. Хотя бы одно поле обязательно, все — boolean.
function parseChatPrefs(body) {
    const source = body && typeof body === 'object' ? body : {};
    const result = {};
    let any = false;
    for (const field of CHAT_PREF_FIELDS) {
        const value = source[field];
        if (value === undefined || value === null) {
            result[field] = null;
            continue;
        }
        if (typeof value !== 'boolean') throw new RangeError('Некорректные параметры');
        result[field] = value;
        any = true;
    }
    if (!any) throw new RangeError('Некорректные параметры');
    return result;
}

module.exports = {
    CHAT_EXPIRY_OPTIONS,
    CHAT_PREF_FIELDS,
    parseChatExpirySeconds,
    effectiveMessageExpiry,
    parseChatPrefs,
};
