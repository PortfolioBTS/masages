// Записи состояния ядра E2EE без обращения к хранилищу (roadmap R14, T6.4): чистые нормализаторы и
// проверки над данными, прочитанными из хранилища или присланными сервером. Вынесено дословно из
// public/e2ee.js (раздел «Записи ключей»):
//   - индекс архива ключей: archiveEntryId, archiveHas;
//   - missingKeyReason: почему нет ключа сообщения ниже позиции цепочки;
//   - normalizePolicy, normalizeIds, normalizeParticipants: любой мусор сводится к безопасному виду;
//   - logExcluded, identityStatus: статус закреплённой identity собеседника;
//   - имена записей хранилища (stateName, archiveName, seenName, skIndexName, keyRequestName, editName и др.),
//     sharedMarkName, tombstoneArchive, sessionMatchesPin, envelopeKeyId - мелкие помощники, которые лежали внутри
//     createClient, но не пользовались его замыканием.
// Файл исполняется и в браузере (window.NyxoE2eeState, подключается до e2ee.js), и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./e2ee-codec.js'));
    } else {
        root.NyxoE2eeState = factory(root.NyxoE2eeCodec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    const { isCanonicalKeyId } = Codec;

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

    // ---- Имена записей хранилища и мелкие помощники (прежде внутри createClient) ----

    const stateName = (roomId, senderId) => 'senderKey:' + roomId + ':' + senderId;
    const archiveName = (roomId, senderId, keyId) => 'skArchive:' + roomId + ':' + senderId + ':' + keyId;
    const seenName = (roomId, senderId, keyId) => 'seen:' + roomId + ':' + senderId + ':' + keyId;
    const archivePrefix = (roomId) => 'skArchive:' + roomId + ':';

    const skIndexName = (roomId, keyId) => 'skIndex:' + roomId + ':' + keyId;
    const skIndexPrefix = (roomId) => 'skIndex:' + roomId + ':';

    const keyRequestName = (roomId, keyId) => 'keyReq:' + roomId + ':' + keyId;
    const keyServedName = (roomId, keyId, requesterId) => 'keyServed:' + roomId + ':' + keyId + ':' + requesterId;

    const editPrefix = (roomId) => 'edit:' + roomId + ':';
    const editName = (roomId, mid) => editPrefix(roomId) + mid;

    function sharedMarkName(roomId, senderKeyId, peerId) {
        return 'sharedWith2:' + roomId + ':' + senderKeyId + ':' + peerId;
    }

    // В индексе архива запись превращается в надгробие (просто id): ключ
    // удалён, но заменённый ротацией ключ обратно уже не поставить.
    function tombstoneArchive(state, keyId) {
        const list = state.archive || [];
        const i = list.findIndex(entry => archiveEntryId(entry) === keyId);
        if (i >= 0 && typeof list[i] !== 'string') list[i] = keyId;
    }

    function sessionMatchesPin(session, pin) {
        return Boolean(session && pin && !pin.pending
            && session.peerSignPub === pin.signPub && session.peerDhPub === pin.dhPub);
    }

    function envelopeKeyId(text) {
        let envelope;
        try { envelope = JSON.parse(text); } catch { return null; }
        return envelope && typeof envelope === 'object' && isCanonicalKeyId(envelope.senderKeyId) ? envelope.senderKeyId : null;
    }

    return Object.freeze({
        archiveEntryId, archiveHas, missingKeyReason, normalizePolicy, normalizeIds, normalizeParticipants,
        logExcluded, identityStatus, stateName, archiveName, seenName, archivePrefix,
        skIndexName, skIndexPrefix, keyRequestName, keyServedName, editPrefix, editName,
        sharedMarkName, tombstoneArchive, sessionMatchesPin, envelopeKeyId,
    });
});
