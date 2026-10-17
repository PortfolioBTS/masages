// Записи состояния ядра E2EE без обращения к хранилищу (roadmap R14, T6.4): чистые нормализаторы и
// проверки над данными, прочитанными из хранилища или присланными сервером. Вынесено дословно из
// public/e2ee.js (раздел «Записи ключей»):
//   - индекс архива ключей: archiveEntryId, archiveHas;
//   - missingKeyReason: почему нет ключа сообщения ниже позиции цепочки;
//   - normalizePolicy, normalizeIds, normalizeParticipants: любой мусор сводится к безопасному виду;
//   - logExcluded, identityStatus: статус закреплённой identity собеседника.
// Файл исполняется и в браузере (window.NyxoE2eeState, подключается до e2ee.js), и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoE2eeState = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ---- Записи ключей: индекс архива ----

    const archiveEntryId = (entry) => (typeof entry === 'string' ? entry : entry && entry.id);
    const archiveHas = (state, keyId) => (state.archive || []).some(entry => archiveEntryId(entry) === keyId);

    // Почему нет ключа сообщения, которое ниже позиции цепочки (раздел 5 и 6
    // плана криптографии): удалено режимом «не хранить историю», удалено по
    // сроку или бюджету, либо ключа не было вовсе (цепочка началась позже).
    function missingKeyReason(rec, iteration) {
        if (iteration < (rec.forgottenBelow || 0)) return 'history-not-kept';
        if (iteration < (rec.expiredBelow || 0)) return 'key-expired';
        return 'no-message-key';
    }

    // Политика комнаты на устройстве (roomPolicy:<комната>): режим истории и
    // срок исчезающих сообщений. Любой мусор в записи сводится к значениям по умолчанию.
    function normalizePolicy(raw) {
        const p = raw && typeof raw === 'object' ? raw : {};
        return {
            historyMode: p.historyMode === 'none' ? 'none' : 'keep',
            expirySeconds: Number.isSafeInteger(p.expirySeconds) && p.expirySeconds > 0 ? p.expirySeconds : null,
            updatedAt: Number.isFinite(p.updatedAt) ? p.updatedAt : 0,
        };
    }

    function normalizeIds(list) {
        const out = [];
        for (const v of Array.isArray(list) ? list : []) {
            const id = Number(v);
            if (Number.isSafeInteger(id) && id > 0 && !out.includes(id)) out.push(id);
        }
        return out;
    }

    function normalizeParticipants(list) {
        const out = [];
        const seen = new Set();
        for (const p of Array.isArray(list) ? list : []) {
            const id = Number(p && p.id);
            if (!Number.isSafeInteger(id) || id <= 0 || seen.has(id)) continue;
            seen.add(id);
            out.push({ id, username: p && typeof p.username === 'string' ? p.username : '' });
        }
        return out;
    }

    // Ключа собеседника нет в журнале (mismatch) — отдельный статус, пока код безопасности не сверен
    // (markPeerVerified) и пользователь не продолжил явно (overrideLogMismatch). pending журнала статус
    // не меняет: это «ключ ждёт подтверждения», а не нарушение.
    function logExcluded(pin) {
        return Boolean(pin && pin.kt && pin.kt.status === 'mismatch' && !pin.verified && !pin.kt.override);
    }

    function identityStatus(pin) {
        if (!pin) return 'unknown';
        if (pin.pending) return 'changed';
        if (logExcluded(pin)) return 'log-mismatch';
        return pin.verified ? 'verified' : 'unverified';
    }

    return Object.freeze({
        archiveEntryId, archiveHas, missingKeyReason, normalizePolicy, normalizeIds, normalizeParticipants,
        logExcluded, identityStatus,
    });
});
