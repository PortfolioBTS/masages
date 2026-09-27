'use strict';
// Имитация серверного контракта (Node-прокси + Rust e2ee-key-server +
// маршруты participants/key-shares, см. К1 в контрактах) в памяти — то же
// поведение (порядок проверок, консюминг one-time prekey, 404 без ключей,
// 403 без общей комнаты, проверка подписей prekey), без реального
// Postgres/HTTP. Используется только тестами.
//
// server.evil — хелперы "злонамеренного сервера": сервер в модели угроз
// E2EE недоверенный, и протокол обязан выдерживать именно такие подмены.

const subtle = globalThis.crypto.subtle;

function b64ToBytes(str) {
    return new Uint8Array(Buffer.from(String(str || ''), 'base64'));
}

async function verifyEd25519(signPubB64, sigB64, data) {
    try {
        const key = await subtle.importKey('raw', b64ToBytes(signPubB64), { name: 'Ed25519' }, false, ['verify']);
        return await subtle.verify('Ed25519', key, b64ToBytes(sigB64), data);
    } catch {
        return false;
    }
}

function makeFakeServer() {
    const identityKeys = new Map(); // userId -> {identity_signing_key, identity_dh_key}
    const signedPrekeys = new Map(); // userId -> {key_id, public_key, signature}
    const pqPrekeys = new Map(); // userId -> {key_id, public_key, signature}
    const oneTimePrekeys = new Map(); // userId -> Map<key_id, public_key> (insertion order = FIFO)
    const rooms = new Map(); // roomId -> Set<userId>
    const userChats = new Map(); // userId -> Map<chatId, roomId>
    const keyShares = []; // {id, roomId, senderId, recipientId, ciphertext}
    const deliveredKeyShares = []; // всё, что уже забрали получатели (для повторов)
    const messages = new Map(); // id -> {id, roomId, senderId, text}
    let nextShareId = 1;
    let nextMessageId = 1;

    // Подмены злонамеренного сервера.
    const impersonations = new Map(); // victimId -> attackerId (чьи ключи отдаются вместо victim)
    const hiddenPq = new Set(); // userId, у кого pq_prekey "пропал" из bundle

    function room(userId, chatId) {
        const m = userChats.get(userId);
        if (!m || !m.has(chatId)) return null;
        return m.get(chatId);
    }

    function sharesRoom(a, b) {
        for (const members of rooms.values()) {
            if (members.has(a) && members.has(b)) return true;
        }
        return false;
    }

    function addParticipant(roomId, userId, chatId) {
        if (!rooms.has(roomId)) rooms.set(roomId, new Set());
        rooms.get(roomId).add(userId);
        if (!userChats.has(userId)) userChats.set(userId, new Map());
        userChats.get(userId).set(chatId, roomId);
    }

    function removeParticipant(roomId, userId) {
        if (rooms.has(roomId)) rooms.get(roomId).delete(userId);
        const m = userChats.get(userId);
        if (m) {
            for (const [chatId, rid] of m) if (rid === roomId) m.delete(chatId);
        }
    }

    function participantsOf(roomId) {
        return Array.from(rooms.get(roomId) || []).map(id => ({ id, username: 'user' + id }));
    }

    function effectiveKeysOwner(userId) {
        return impersonations.has(userId) ? impersonations.get(userId) : userId;
    }

    function transportFor(userId, opts) {
        const shadow = Boolean(opts && opts.shadow);
        const t = {
            async putIdentity(body) {
                if (shadow) return { status: 200, data: { success: true } };
                identityKeys.set(userId, { identity_signing_key: body.identity_signing_key, identity_dh_key: body.identity_dh_key });
                return { status: 200, data: { success: true } };
            },
            async putSignedPrekey(body) {
                if (shadow) return { status: 200, data: { success: true } };
                const identity = identityKeys.get(userId);
                if (!identity) return { status: 409, data: { success: false, message: 'identity keys must be registered first' } };
                if (!(await verifyEd25519(identity.identity_signing_key, body.signature, b64ToBytes(body.public_key)))) {
                    return { status: 400, data: { success: false, message: 'bad signature' } };
                }
                signedPrekeys.set(userId, { key_id: body.key_id, public_key: body.public_key, signature: body.signature });
                return { status: 200, data: { success: true } };
            },
            async putPqPrekey(body) {
                if (shadow) return { status: 200, data: { success: true } };
                const identity = identityKeys.get(userId);
                if (!identity) return { status: 409, data: { success: false, message: 'identity keys must be registered first' } };
                const pub = b64ToBytes(body.public_key);
                if (pub.length !== 1184 || b64ToBytes(body.signature).length !== 64) {
                    return { status: 400, data: { success: false, message: 'bad length' } };
                }
                if (!(await verifyEd25519(identity.identity_signing_key, body.signature, pub))) {
                    return { status: 400, data: { success: false, message: 'bad signature' } };
                }
                pqPrekeys.set(userId, { key_id: body.key_id, public_key: body.public_key, signature: body.signature });
                return { status: 200, data: { success: true } };
            },
            async postOneTimePrekeys(body) {
                if (shadow) return { status: 200, data: { success: true, inserted: body.keys.length } };
                if (!oneTimePrekeys.has(userId)) oneTimePrekeys.set(userId, new Map());
                const map = oneTimePrekeys.get(userId);
                let inserted = 0;
                for (const item of body.keys) {
                    if (!map.has(item.key_id)) { map.set(item.key_id, item.public_key); inserted++; }
                }
                return { status: 200, data: { success: true, inserted } };
            },
            async getOneTimePrekeyCount() {
                if (shadow) return { status: 200, data: { count: 100 } };
                const map = oneTimePrekeys.get(userId);
                return { status: 200, data: { count: map ? map.size : 0 } };
            },
            async deleteKeys() {
                if (shadow) return { status: 200, data: { success: true } };
                identityKeys.delete(userId);
                signedPrekeys.delete(userId);
                pqPrekeys.delete(userId);
                oneTimePrekeys.delete(userId);
                return { status: 200, data: { success: true } };
            },
            async getBundle(targetUserId) {
                // Node-прокси (К1): bundle только собеседнику с общей комнатой.
                if (targetUserId !== userId && !sharesRoom(userId, targetUserId)) {
                    return { status: 403, data: { success: false, message: 'Нет общего чата с пользователем' } };
                }
                const owner = effectiveKeysOwner(targetUserId);
                const identity = identityKeys.get(owner);
                const spk = signedPrekeys.get(owner);
                if (!identity || !spk) return { status: 404, data: { success: false } };
                const map = oneTimePrekeys.get(owner);
                let otpk = null;
                if (map && map.size > 0) {
                    const firstKey = map.keys().next().value;
                    otpk = { key_id: firstKey, public_key: map.get(firstKey) };
                    map.delete(firstKey); // атомарный consume, как в db.rs::fetch_bundle
                }
                const pq = hiddenPq.has(targetUserId) ? null : (pqPrekeys.get(owner) || null);
                return {
                    status: 200,
                    data: {
                        identity_signing_key: identity.identity_signing_key,
                        identity_dh_key: identity.identity_dh_key,
                        signed_prekey: spk,
                        one_time_prekey: otpk,
                        pq_prekey: pq,
                    },
                };
            },
            async getIdentities(ids) {
                if (!Array.isArray(ids) || ids.length === 0 || ids.length > 200) {
                    return { status: 400, data: { success: false, message: 'bad ids' } };
                }
                const out = [];
                for (const raw of ids) {
                    const id = Number(raw);
                    // Node-прокси молча выкидывает тех, с кем нет общей комнаты.
                    if (id !== userId && !sharesRoom(userId, id)) continue;
                    const identity = identityKeys.get(effectiveKeysOwner(id));
                    if (!identity) continue;
                    out.push({ user_id: id, identity_signing_key: identity.identity_signing_key, identity_dh_key: identity.identity_dh_key });
                }
                return { status: 200, data: { success: true, identities: out } };
            },
            async getParticipants(chatId) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 200, data: { success: true, roomId: null, participants: [] } };
                return { status: 200, data: { success: true, roomId, participants: participantsOf(roomId) } };
            },
            async postKeyShares(chatId, shares) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 400, data: { success: false, message: 'no room' } };
                if (shares.length > 200) return { status: 400, data: { success: false, message: 'too many recipients' } };
                const members = rooms.get(roomId);
                for (const s of shares) {
                    if (!members.has(s.recipientUserId)) return { status: 400, data: { success: false, message: 'recipient not a participant' } };
                    if (typeof s.ciphertext !== 'string' || s.ciphertext.length > 8192) return { status: 400, data: { success: false, message: 'key-share too large' } };
                }
                for (const s of shares) {
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
                deliveredKeyShares.push(...mine);
                return { status: 200, data: { success: true, roomId, shares: mine.map(s => ({ senderId: s.senderId, ciphertext: s.ciphertext })) } };
            },
        };
        return t;
    }

    // Простейшее хранилище сообщений комнаты — ради сценариев повтора.
    function postMessage(roomId, senderId, text) {
        const id = nextMessageId++;
        messages.set(id, { id, roomId, senderId, text });
        return id;
    }

    function editMessage(id, text) {
        const m = messages.get(id);
        if (!m) throw new Error('no message ' + id);
        m.text = text;
    }

    function getMessage(id) {
        const m = messages.get(id);
        return m ? Object.assign({}, m) : null;
    }

    const evil = {
        // Сервер выдаёт identity/bundle атакующего (зарегистрированного под
        // attackerId) за ключи victimId — классическая попытка MITM.
        impersonate(victimId, attackerId) { impersonations.set(victimId, attackerId); },
        stopImpersonating(victimId) { impersonations.delete(victimId); },
        // Сервер "теряет" PQ-prekey в bundle — попытка понизить PQXDH до X3DH.
        hidePqPrekey(userId) { hiddenPq.add(userId); },
        // Произвольная правка bundle (подмена подписи и т.п.).
        async tamperedBundle(requesterId, targetUserId, mutate) {
            const res = await transportFor(requesterId).getBundle(targetUserId);
            if (res.status === 200) mutate(res.data);
            return res;
        },
        // Внедрение key-share от имени senderId (например, собранного
        // клиентом атакующего с чужим identity).
        injectKeyShare({ roomId, senderId, recipientId, ciphertext }) {
            keyShares.push({ id: nextShareId++, roomId, senderId, recipientId, ciphertext });
        },
        // Повторная доставка уже забранного получателем key-share.
        replayDeliveredKeyShare(index) {
            const s = deliveredKeyShares[index];
            if (!s) throw new Error('no delivered key-share ' + index);
            keyShares.push(Object.assign({}, s, { id: nextShareId++ }));
        },
        // Повтор конверта: тот же текст под новым id сообщения.
        replayMessage(id) {
            const m = messages.get(id);
            if (!m) throw new Error('no message ' + id);
            return postMessage(m.roomId, m.senderId, m.text);
        },
        // "Призрачный участник": сервер молча добавляет своего пользователя
        // в комнату — клиенты видят его только через список участников.
        addGhost(roomId, ghostUserId, chatId) { addParticipant(roomId, ghostUserId, chatId); },
    };

    return {
        transportFor,
        // Транспорт "от имени" userId для клиента атакующего: читает и шлёт
        // как userId, но не перезаписывает зарегистрированные ключи жертвы.
        shadowTransportFor(userId) { return transportFor(userId, { shadow: true }); },
        addParticipant, removeParticipant, participantsOf,
        postMessage, editMessage, getMessage,
        evil,
        _rooms: rooms,
        _keyShares: keyShares,
        _deliveredKeyShares: deliveredKeyShares,
        _signedPrekeys: signedPrekeys,
        _pqPrekeys: pqPrekeys,
        _oneTimePrekeys: oneTimePrekeys,
    };
}

module.exports = { makeFakeServer };
