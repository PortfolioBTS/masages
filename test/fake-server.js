'use strict';
// Имитация серверного контракта (Node proxy + Rust e2ee-key-server +
// новые маршруты participants/key-shares) в памяти — ровно то же
// поведение (порядок проверок, консюминг one-time prekey, 404 без
// ключей), без реального Postgres/HTTP. Используется только тестами.

function makeFakeServer() {
    const identityKeys = new Map(); // userId -> {identity_signing_key, identity_dh_key}
    const signedPrekeys = new Map(); // userId -> {key_id, public_key, signature}
    const oneTimePrekeys = new Map(); // userId -> Map<key_id, public_key> (insertion order = FIFO)
    const rooms = new Map(); // roomId -> Set<userId>
    const userChats = new Map(); // userId -> Map<chatId, roomId>
    const keyShares = []; // {id, roomId, senderId, recipientId, ciphertext}
    let nextShareId = 1;

    function room(userId, chatId) {
        const m = userChats.get(userId);
        if (!m || !m.has(chatId)) return null;
        return m.get(chatId);
    }

    function addParticipant(roomId, userId, chatId) {
        if (!rooms.has(roomId)) rooms.set(roomId, new Set());
        rooms.get(roomId).add(userId);
        if (!userChats.has(userId)) userChats.set(userId, new Map());
        userChats.get(userId).set(chatId, roomId);
    }

    function transportFor(userId) {
        return {
            async putIdentity(body) {
                identityKeys.set(userId, { identity_signing_key: body.identity_signing_key, identity_dh_key: body.identity_dh_key });
                return { status: 200, data: { success: true } };
            },
            async putSignedPrekey(body) {
                if (!identityKeys.has(userId)) return { status: 409, data: { success: false, message: 'identity keys must be registered first' } };
                signedPrekeys.set(userId, { key_id: body.key_id, public_key: body.public_key, signature: body.signature });
                return { status: 200, data: { success: true } };
            },
            async postOneTimePrekeys(body) {
                if (!oneTimePrekeys.has(userId)) oneTimePrekeys.set(userId, new Map());
                const map = oneTimePrekeys.get(userId);
                let inserted = 0;
                for (const item of body.keys) {
                    if (!map.has(item.key_id)) { map.set(item.key_id, item.public_key); inserted++; }
                }
                return { status: 200, data: { success: true, inserted } };
            },
            async getOneTimePrekeyCount() {
                const map = oneTimePrekeys.get(userId);
                return { status: 200, data: { count: map ? map.size : 0 } };
            },
            async getBundle(targetUserId) {
                const identity = identityKeys.get(targetUserId);
                const spk = signedPrekeys.get(targetUserId);
                if (!identity || !spk) return { status: 404, data: { success: false } };
                const map = oneTimePrekeys.get(targetUserId);
                let otpk = null;
                if (map && map.size > 0) {
                    const firstKey = map.keys().next().value;
                    otpk = { key_id: firstKey, public_key: map.get(firstKey) };
                    map.delete(firstKey); // атомарный consume, как в db.rs::fetch_bundle
                }
                return {
                    status: 200,
                    data: {
                        identity_signing_key: identity.identity_signing_key,
                        identity_dh_key: identity.identity_dh_key,
                        signed_prekey: spk,
                        one_time_prekey: otpk,
                    },
                };
            },
            async getParticipants(chatId) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 200, data: { success: true, roomId: null, participants: [{ id: userId, username: 'me' }] } };
                const ids = Array.from(rooms.get(roomId));
                return { status: 200, data: { success: true, roomId, participants: ids.map(id => ({ id, username: 'user' + id })) } };
            },
            async postKeyShares(chatId, shares) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 400, data: { success: false, message: 'no room' } };
                const members = rooms.get(roomId);
                for (const s of shares) {
                    if (!members.has(s.recipientUserId)) return { status: 400, data: { success: false, message: 'recipient not a participant' } };
                    keyShares.push({ id: nextShareId++, roomId, senderId: userId, recipientId: s.recipientUserId, ciphertext: s.ciphertext });
                }
                return { status: 200, data: { success: true } };
            },
            async getKeyShares(chatId) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 200, data: { success: true, roomId: null, shares: [] } };
                const mine = [];
                for (let i = keyShares.length - 1; i >= 0; i--) {
                    if (keyShares[i].roomId === roomId && keyShares[i].recipientId === userId) {
                        mine.push(keyShares[i]);
                        keyShares.splice(i, 1); // fetch-and-delete, одноразовая доставка
                    }
                }
                mine.reverse();
                return { status: 200, data: { success: true, roomId, shares: mine.map(s => ({ senderId: s.senderId, ciphertext: s.ciphertext })) } };
            },
        };
    }

    return { transportFor, addParticipant, _rooms: rooms, _keyShares: keyShares };
}

module.exports = { makeFakeServer };
