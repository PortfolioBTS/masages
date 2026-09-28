// Приглашения в комнату: параметры кода (срок, лимит участников, одобрение),
// состояние кода для участников и заявки на вступление. Только чистые
// функции — проверяются тестами без БД (test/lib.test.js), а server.js
// держит у себя SQL и блокировки.

const { isInviteExpired } = require('./security-utils');

// Сроки жизни кода, которые можно выбрать при перевыпуске: час, сутки,
// неделя, 30 дней. Без параметра — INVITE_TTL_HOURS из окружения (он может
// и не входить в этот список: это решение администратора, а не клиента).
const INVITE_TTL_OPTIONS = Object.freeze([3600, 86400, 604800, 2592000]);

// Лимит участников по коду: меньше двух — комната сама с собой, больше
// тысячи — уже не "группа друзей", а рассылка, для которой E2EE на Sender
// Keys (попарная доставка ключа каждому) и не рассчитано.
const MIN_INVITE_MAX_MEMBERS = 2;
const MAX_INVITE_MAX_MEMBERS = 1000;

// Заявка живёт неделю: дольше её никто не рассматривает, а висящая заявка —
// это ещё и метаданные "кто хотел в какую комнату".
const JOIN_REQUEST_TTL_SECONDS = 7 * 24 * 60 * 60;
// Сколько живых заявок может ждать в одной комнате. С кодом на руках
// ботоферма анонимов иначе завалила бы участников заявками.
const MAX_PENDING_JOIN_REQUESTS_PER_ROOM = 100;

// Одинаковый ответ на несуществующий, истёкший и выключенный код: иначе по
// тексту ошибки можно было бы узнать, что код когда-то существовал.
const INVALID_INVITE_MESSAGE = 'Код недействителен';
const ROOM_FULL_MESSAGE = 'В группе нет свободных мест';

// Целое из JSON-числа или строки из цифр; всё остальное — NaN (в том числе
// true/false, которые Number() превратил бы в 1/0).
function toStrictInteger(value) {
    if (typeof value === 'number') return Number.isInteger(value) ? value : NaN;
    if (typeof value === 'string' && /^\s*\d{1,10}\s*$/.test(value)) return Number(value);
    return NaN;
}

const isAbsent = (value) => value === undefined || value === null || value === '';

// Тело POST /api/chats/:chatId/invite/rotate -> нормализованные параметры.
// Некорректное значение бросает RangeError с текстом для пользователя
// (как normalizeExpirySeconds в lib/disappearing-messages.js).
function parseInviteSettings(body, { defaultTtlSeconds } = {}) {
    const source = body && typeof body === 'object' ? body : {};

    let ttlSeconds;
    if (isAbsent(source.ttlSeconds)) {
        ttlSeconds = Number(defaultTtlSeconds);
        if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) throw new RangeError('Не задан срок действия кода');
    } else {
        ttlSeconds = toStrictInteger(source.ttlSeconds);
        if (!INVITE_TTL_OPTIONS.includes(ttlSeconds)) throw new RangeError('Недопустимый срок действия кода');
    }

    let maxMembers = null;
    if (!isAbsent(source.maxMembers)) {
        maxMembers = toStrictInteger(source.maxMembers);
        if (!Number.isInteger(maxMembers) || maxMembers < MIN_INVITE_MAX_MEMBERS || maxMembers > MAX_INVITE_MAX_MEMBERS) {
            throw new RangeError(`Лимит участников — от ${MIN_INVITE_MAX_MEMBERS} до ${MAX_INVITE_MAX_MEMBERS}`);
        }
    }

    // По умолчанию — с одобрением: код, случайно выложенный в открытый
    // чат, не должен сразу впускать в переписку.
    let requireApproval = true;
    if (source.requireApproval !== undefined && source.requireApproval !== null) {
        if (typeof source.requireApproval !== 'boolean') throw new RangeError('Некорректный параметр одобрения');
        requireApproval = source.requireApproval;
    }

    return { ttlSeconds, maxMembers, requireApproval };
}

// Код можно использовать: не выключен и не истёк (NULL-срок — истёк,
// см. isInviteExpired).
function isInviteUsable(room, now = Date.now()) {
    return Boolean(room) && !room.invite_disabled && !isInviteExpired(room.code_expires_at, now);
}

function isRoomFull(memberCount, maxMembers) {
    if (maxMembers === null || maxMembers === undefined) return false;
    return Number(memberCount) >= Number(maxMembers);
}

function toIso(value) {
    if (value === null || value === undefined) return null;
    const time = new Date(value).getTime();
    return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

// Ответ GET /api/chats/invite/:chatId. Выключенный код не показывается
// (в БД на его месте уже случайный, нигде не выданный код).
function describeInvite(room, memberCount, now = Date.now()) {
    const disabled = Boolean(room.invite_disabled);
    return {
        code: disabled ? null : room.code,
        expiresAt: disabled ? null : toIso(room.code_expires_at),
        expired: disabled ? false : isInviteExpired(room.code_expires_at, now),
        disabled,
        maxMembers: room.invite_max_members === null || room.invite_max_members === undefined ? null : Number(room.invite_max_members),
        requireApproval: room.invite_require_approval !== false,
        memberCount: Number(memberCount) || 0,
    };
}

function isJoinRequestExpired(createdAt, now = Date.now()) {
    const time = new Date(createdAt).getTime();
    return !Number.isFinite(time) || time + JOIN_REQUEST_TTL_SECONDS * 1000 <= now;
}

module.exports = {
    INVITE_TTL_OPTIONS,
    MIN_INVITE_MAX_MEMBERS,
    MAX_INVITE_MAX_MEMBERS,
    JOIN_REQUEST_TTL_SECONDS,
    MAX_PENDING_JOIN_REQUESTS_PER_ROOM,
    INVALID_INVITE_MESSAGE,
    ROOM_FULL_MESSAGE,
    parseInviteSettings,
    isInviteUsable,
    isRoomFull,
    describeInvite,
    isJoinRequestExpired,
};
