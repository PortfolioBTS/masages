'use strict';
// Тег автора сообщения комнаты и псевдоним квоты (docs/security/sealed-sender.md,
// разделы 6 и 13).
//
// В строке сообщения комнаты нет user_id: вместо него лежит author_tag — первые
// 16 байт HMAC-SHA256 от (комната, пользователь, неделя) на ключе, выведенном из
// MESSAGE_ENCRYPTION_KEY. Сервер при каждой операции «по автору» (правка,
// удаление, таймер, прочитано, выход, удаление аккаунта) вычисляет теги
// пользователя из сессии и сравнивает их с тегами строк; читатель дампа без
// ключа связать тег с пользователем не может.
//
//   ikm        = 32 байта ПОСЛЕ parseKey (а не текст переменной окружения)
//   K_tag      = HKDF-SHA256(ikm, соль пустая, "nyxo-author-tag-key-v1", 32)
//   week(t)    = floor(t_мс / 604 800 000)   — t это created_at строки (уже до минуты)
//   author_tag = HMAC-SHA256(K_tag, "nyxo-author-tag-v1\0" ‖ u32be(room) ‖ u32be(user) ‖ u32be(week))[0..16]
//
//   K_quota    = HKDF-SHA256(ikm, "nyxo-upload-quota-v1")
//   qkey       = HMAC-SHA256(K_quota, u32be(user_id))[0..16]
//
// Ключей может быть несколько (MESSAGE_ENCRYPTION_KEY и …_PREVIOUS): теги
// ПРОВЕРЯЮТСЯ по всем ключам, ПИШУТСЯ текущим. Один автор в одну неделю может
// иметь два тега, если ключ меняли в течение недели; строки старого ключа
// перетегирует scripts/retag-messages.js (docs/ops/message-key-rotation.md).
//
// Модуль чистый: ключи ему передают (createAuthorTags), env он не читает —
// поэтому контрольные векторы документа проверяются юнит-тестом без окружения.
// Для сервера — createAuthorTagsFromEnvironment().

const crypto = require('crypto');
const { deriveKey } = require('./derive-key');

// Метки доменов (sealed-sender.md, 6.4): каждая — ровно для одной цели.
const LABEL_TAG_KEY = 'nyxo-author-tag-key-v1';
const LABEL_TAG_INPUT = Buffer.from('nyxo-author-tag-v1\0', 'utf8');
const LABEL_QUOTA_KEY = 'nyxo-upload-quota-v1';

const WEEK_MS = 604800000;
const TAG_BYTES = 16;
// Предел недель аккаунта (около 11 лет): защита от ошибочных данных, для
// временных аккаунтов недостижим.
const MAX_ACCOUNT_WEEKS = 600;

function u32be(n) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(n);
    return buf;
}

// Идентификаторы входят в HMAC четырьмя байтами: только целые 1..2^32-1.
function requireU32(value, field) {
    if (!Number.isInteger(value) || value < 0 || value > 0xFFFFFFFF) {
        throw new TypeError(`author-tag: некорректный ${field}`);
    }
    return value;
}

// Date, ISO-строка или миллисекунды → миллисекунды.
function toMs(value, field) {
    const ms = value instanceof Date ? value.getTime() : (typeof value === 'number' ? value : new Date(value).getTime());
    if (!Number.isFinite(ms) || ms < 0) throw new TypeError(`author-tag: некорректное время ${field}`);
    return ms;
}

// Неделя от эпохи Unix (границы — четверг 00:00 UTC).
function weekOf(time) {
    return Math.floor(toMs(time, 'weekOf') / WEEK_MS);
}

function deriveTagKey(ikm) {
    return deriveKey(ikm, LABEL_TAG_KEY);
}

function deriveQuotaKey(ikm) {
    return deriveKey(ikm, LABEL_QUOTA_KEY);
}

// Вход HMAC всегда 31 байт: метка (18 символов и нулевой байт) и три поля по
// 4 байта. Поля фиксированной длины, разделителей не нужно.
function computeTag(tagKey, roomId, userId, week) {
    const input = Buffer.concat([LABEL_TAG_INPUT, u32be(requireU32(roomId, 'room_id')), u32be(requireU32(userId, 'user_id')), u32be(requireU32(week, 'week'))]);
    return crypto.createHmac('sha256', tagKey).update(input).digest().subarray(0, TAG_BYTES);
}

function computeQkey(quotaKey, userId) {
    return crypto.createHmac('sha256', quotaKey).update(u32be(requireU32(userId, 'user_id'))).digest().subarray(0, TAG_BYTES);
}

// ikms — 32-байтные ключи после parseKey, текущий первым (messageKeyRing()).
function createAuthorTags(ikms) {
    if (!Array.isArray(ikms) || ikms.length === 0 || !ikms.every(k => Buffer.isBuffer(k) && k.length === 32)) {
        throw new TypeError('author-tag: нужен непустой список 32-байтных ключей');
    }
    const tagKeys = ikms.map(deriveTagKey);
    const quotaKeys = ikms.map(deriveQuotaKey);

    // Тег для записи: текущий ключ, неделя created_at строки.
    function tagFor(roomId, userId, createdAt) {
        return computeTag(tagKeys[0], roomId, userId, weekOf(createdAt));
    }

    // Все теги пользователя в комнате за одну неделю (по всем ключам): правка,
    // удаление, таймер, повтор отправки.
    function tagsForRow(roomId, userId, createdAt) {
        const week = weekOf(createdAt);
        return tagKeys.map(key => computeTag(key, roomId, userId, week));
    }

    // Все теги пользователя в комнате от недели создания аккаунта до недели now
    // (по всем ключам): выход с удалением сообщений, удаление аккаунта, отметки
    // прочтения. Не больше MAX_ACCOUNT_WEEKS последних недель.
    function tagsForAccount(roomId, userId, usersCreatedAt, now = Date.now()) {
        const last = weekOf(now);
        const first = Math.max(weekOf(usersCreatedAt), last - (MAX_ACCOUNT_WEEKS - 1));
        const tags = [];
        for (let week = first; week <= last; week++) {
            for (const key of tagKeys) tags.push(computeTag(key, roomId, userId, week));
        }
        return tags;
    }

    // Принадлежит ли тег строки одному из тегов пользователя. Сравнение за
    // постоянное время и без раннего выхода: сравниваемое значение вычисляет
    // сервер из сессии, но лишняя разница во времени ничего не стоит.
    function ownsTag(rowTag, candidateTags) {
        if (!Buffer.isBuffer(rowTag) || rowTag.length !== TAG_BYTES) return false;
        let hit = false;
        for (const tag of candidateTags) {
            if (crypto.timingSafeEqual(rowTag, tag)) hit = true;
        }
        return hit;
    }

    // Псевдоним квоты по текущему ключу (запись) и по всем ключам (удаление
    // аккаунта: окна, начатые под прежним ключом, тоже удаляются).
    function qkey(userId) {
        return computeQkey(quotaKeys[0], userId);
    }
    function qkeysFor(userId) {
        return quotaKeys.map(key => computeQkey(key, userId));
    }

    return { tagFor, tagsForRow, tagsForAccount, ownsTag, qkey, qkeysFor, keyCount: ikms.length };
}

// Ключи — из MESSAGE_ENCRYPTION_KEY и …_PREVIOUS (lib/message-crypto.js читает и
// проверяет их при загрузке модуля: без ключа сервер не стартует).
function createAuthorTagsFromEnvironment() {
    const { messageKeyRing } = require('./message-crypto');
    return createAuthorTags(messageKeyRing().map(entry => entry.ikm));
}

module.exports = {
    WEEK_MS,
    TAG_BYTES,
    MAX_ACCOUNT_WEEKS,
    weekOf,
    deriveTagKey,
    deriveQuotaKey,
    computeTag,
    computeQkey,
    createAuthorTags,
    createAuthorTagsFromEnvironment,
};
