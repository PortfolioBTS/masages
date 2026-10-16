'use strict';
// Имитация серверного контракта (маршруты /api/keys/* с встроенным
// хранилищем ключей lib/key-store.js + маршруты participants/key-shares,
// см. К1 в контрактах) в памяти — то же поведение (порядок проверок,
// консюминг one-time prekey, 404 без ключей, 403 без общей комнаты, проверка
// подписей prekey), без реального Postgres/HTTP. Используется только тестами.
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

// Подписываемые байты одноразового PQ-prekey собраны здесь независимо от
// клиента и сервера: 'nyxo-pqopk-v1' + NUL, u64be(key_id), ключ.
function pqOneTimeMessage(keyId, publicKey) {
    const label = Buffer.from([...'nyxo-pqopk-v1'].map(c => c.charCodeAt(0)).concat([0]));
    const id = Buffer.alloc(8);
    id.writeBigUInt64BE(BigInt(keyId));
    return new Uint8Array(Buffer.concat([label, id, Buffer.from(publicKey)]));
}

// Оставляет в списке не больше max подходящих под условие записей, самые новые
// (по id): вытеснение очереди key-share, как на сервере.
function evictOldest(list, match, max) {
    const scope = list.filter(match).sort((a, b) => b.id - a.id);
    const victims = new Set(scope.slice(max));
    for (let i = list.length - 1; i >= 0; i--) if (victims.has(list[i])) list.splice(i, 1);
}

// opts.kt — журнал ключей (test/fake-kt.js): модель либо функция userId -> модель (у каждого пользователя
// свой «мир», для проверок двуличия); регистрации идут во все модели из opts.ktAll. Без opts.kt сервер
// ведёт себя, как до журнала: ни kt в ответах, ни маршрутов /api/kt/*.
function makeFakeServer(opts = {}) {
    const ktOpt = opts.kt || null;
    const ktModels = !ktOpt ? [] : (typeof ktOpt === 'function' ? (opts.ktAll || []) : [ktOpt]);
    const ktOf = (userId) => (!ktOpt ? null : (typeof ktOpt === 'function' ? ktOpt(userId) : ktOpt));
    const identityKeys = new Map(); // userId -> {identity_signing_key, identity_dh_key}
    const signedPrekeys = new Map(); // userId -> {key_id, public_key, signature}
    const pqPrekeys = new Map(); // userId -> {key_id, public_key, signature}
    const oneTimePrekeys = new Map(); // userId -> Map<key_id, public_key> (insertion order = FIFO)
    const pqOneTimePrekeys = new Map(); // userId -> Map<key_id, {key_id, public_key, signature}> (FIFO)
    const rooms = new Map(); // roomId -> Set<userId>
    const userChats = new Map(); // userId -> Map<chatId, roomId>
    const keyShares = []; // {id, roomId, senderId, recipientId, ciphertext}
    const deliveredKeyShares = []; // всё, что уже забрали получатели (для повторов)
    const keyRequests = []; // {roomId, requesterId, keyId (base64)}: запросы ключа Sender Key, ожидающие владельцев
    const messages = new Map(); // id (строка) -> {id, roomId, senderId, text}
    const keyRequestPosts = []; // журнал POST /key-requests: что и кто просил
    let nextShareId = 1;
    // Id сообщений как у настоящего сервера (message-ordering.md, 6.1): строка из
    // 7-10 цифр. Клиент выбирает id ДО шифрования (mid внутри содержимого), сервер
    // кладёт сообщение под присланным id.
    let nextMessageId = 1000001;

    // Подмены злонамеренного сервера.
    const impersonations = new Map(); // victimId -> attackerId (чьи ключи отдаются вместо victim)
    const hiddenPq = new Set(); // userId, у кого pq_prekey и одноразовые PQ-ключи "пропали" из bundle
    const strippedPqOneTime = new Set(); // userId, у кого пропал только одноразовый PQ-ключ (и он не расходуется)
    const reusedPqOneTime = new Set(); // userId, чей одноразовый PQ-ключ сервер выдаёт повторно
    const relabelOneTimeAsLastResort = new Set(); // одноразовый PQ-ключ выдан в поле pq_prekey
    const relabelLastResortAsOneTime = new Set(); // запасной ключ выдан в поле pq_one_time_prekey
    const lastServedPq = new Map(); // userId -> последний выданный одноразовый PQ-ключ (для reuse)
    let pqUploadFailure = null; // { mode: 'refuse' | 'network', skip }: сбой загрузки пула после skip успешных пачек

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
                const old = identityKeys.get(userId);
                if (old && (old.identity_signing_key !== body.identity_signing_key || old.identity_dh_key !== body.identity_dh_key)) {
                    // lib/key-store.js: prekey подписаны старой identity — стираются.
                    signedPrekeys.delete(userId);
                    pqPrekeys.delete(userId);
                    oneTimePrekeys.delete(userId);
                    pqOneTimePrekeys.delete(userId);
                }
                identityKeys.set(userId, { identity_signing_key: body.identity_signing_key, identity_dh_key: body.identity_dh_key });
                if (!ktOpt) return { status: 200, data: { success: true } };
                for (const model of ktModels) model.register(userId, body);
                return { status: 200, data: { success: true, kt: ktOf(userId).hintFor(userId) } };
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
            // Одноразовые PQ-prekey: как lib/key-store.js — identity обязана быть
            // (409), не больше 50 в запросе и 100 на пользователя, подпись с
            // меткой над key_id, 1184 байта и подпись 64 байта.
            async postPqOneTimePrekeys(body) {
                if (shadow) return { status: 200, data: { success: true, inserted: body.keys.length } };
                if (pqUploadFailure && pqUploadFailure.skip > 0) {
                    pqUploadFailure.skip--;
                } else if (pqUploadFailure) {
                    const { mode } = pqUploadFailure;
                    pqUploadFailure = null;
                    if (mode === 'network') throw new TypeError('fetch failed');
                    return { status: 400, data: { success: false, message: 'refused' } };
                }
                const identity = identityKeys.get(userId);
                if (!identity) return { status: 409, data: { success: false, message: 'identity keys must be registered first' } };
                if (!Array.isArray(body.keys) || body.keys.length === 0 || body.keys.length > 50) {
                    return { status: 400, data: { success: false, message: 'bad batch' } };
                }
                if (!pqOneTimePrekeys.has(userId)) pqOneTimePrekeys.set(userId, new Map());
                const map = pqOneTimePrekeys.get(userId);
                if (map.size + body.keys.length > 100) return { status: 400, data: { success: false, message: 'too many stored keys' } };
                for (const item of body.keys) {
                    const pub = b64ToBytes(item.public_key);
                    if (!Number.isSafeInteger(item.key_id) || item.key_id < 0 || pub.length !== 1184 || b64ToBytes(item.signature).length !== 64) {
                        return { status: 400, data: { success: false, message: 'bad key' } };
                    }
                    if (!(await verifyEd25519(identity.identity_signing_key, item.signature, pqOneTimeMessage(item.key_id, pub)))) {
                        return { status: 400, data: { success: false, message: 'bad signature' } };
                    }
                }
                let inserted = 0;
                for (const item of body.keys) {
                    if (!map.has(item.key_id)) {
                        map.set(item.key_id, { key_id: item.key_id, public_key: item.public_key, signature: item.signature });
                        inserted++;
                    }
                }
                return { status: 200, data: { success: true, inserted } };
            },
            async deletePqOneTimePrekeys() {
                if (shadow) return { status: 200, data: { success: true } };
                pqOneTimePrekeys.delete(userId);
                return { status: 200, data: { success: true } };
            },
            async getOneTimePrekeyCount() {
                if (shadow) return { status: 200, data: { count: 100, pq_count: 100 } };
                const map = oneTimePrekeys.get(userId);
                const pqMap = pqOneTimePrekeys.get(userId);
                return { status: 200, data: { count: map ? map.size : 0, pq_count: pqMap ? pqMap.size : 0 } };
            },
            async deleteKeys() {
                if (shadow) return { status: 200, data: { success: true } };
                identityKeys.delete(userId);
                signedPrekeys.delete(userId);
                pqPrekeys.delete(userId);
                oneTimePrekeys.delete(userId);
                pqOneTimePrekeys.delete(userId);
                return { status: 200, data: { success: true } };
            },
            async getBundle(targetUserId) {
                // Маршрут /api/keys/bundle (К1): только собеседнику с общей комнатой.
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
                let pq = hiddenPq.has(targetUserId) ? null : (pqPrekeys.get(owner) || null);
                // Одноразовый PQ-ключ: первый в очереди, расходуется при выдаче.
                let pqOne = null;
                const pqMap = pqOneTimePrekeys.get(owner);
                if (!hiddenPq.has(targetUserId) && !strippedPqOneTime.has(targetUserId)) {
                    if (reusedPqOneTime.has(targetUserId) && lastServedPq.has(owner)) {
                        pqOne = lastServedPq.get(owner); // злонамеренный сервер: тот же ключ второй раз
                    } else if (pqMap && pqMap.size > 0) {
                        const firstKey = pqMap.keys().next().value;
                        pqOne = pqMap.get(firstKey);
                        pqMap.delete(firstKey);
                        lastServedPq.set(owner, pqOne);
                    }
                }
                if (pqOne && relabelOneTimeAsLastResort.has(targetUserId)) { pq = pqOne; pqOne = null; }
                else if (relabelLastResortAsOneTime.has(targetUserId) && pq) { pqOne = pq; }
                return {
                    status: 200,
                    data: {
                        identity_signing_key: identity.identity_signing_key,
                        identity_dh_key: identity.identity_dh_key,
                        ...(ktOpt ? { kt: ktOf(userId).hintFor(targetUserId) } : {}),
                        signed_prekey: spk,
                        one_time_prekey: otpk,
                        pq_one_time_prekey: pqOne,
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
                    // Маршрут /api/keys/identities молча выкидывает тех, с кем нет общей комнаты.
                    if (id !== userId && !sharesRoom(userId, id)) continue;
                    const identity = identityKeys.get(effectiveKeysOwner(id));
                    if (!identity) continue;
                    out.push({
                        user_id: id, identity_signing_key: identity.identity_signing_key, identity_dh_key: identity.identity_dh_key,
                        ...(ktOpt ? { kt: ktOf(userId).hintFor(id) } : {}),
                    });
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
                // Как lib/e2ee-groups.js: сверх потолков вытесняются самые старые строки
                // (200 от одного отправителя получателю, 1000 получателю в комнате).
                for (const recipientId of new Set(shares.map(s => s.recipientUserId))) {
                    evictOldest(keyShares, sh => sh.roomId === roomId && sh.senderId === userId && sh.recipientId === recipientId, 200);
                    evictOldest(keyShares, sh => sh.roomId === roomId && sh.recipientId === recipientId, 1000);
                }
                return { status: 200, data: { success: true } };
            },
            // Запросы ключа (lib/e2ee-groups.js): до 20 id в запросе, запрос видят все
            // участники комнаты, строки читает владелец ключа, свои стирает запросивший.
            async postKeyRequests(chatId, senderKeyIds) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 200, data: { success: false, message: 'no room' } };
                if (!Array.isArray(senderKeyIds) || senderKeyIds.length === 0 || senderKeyIds.length > 20) {
                    return { status: 400, data: { success: false, message: 'bad ids' } };
                }
                for (const keyId of new Set(senderKeyIds)) {
                    if (!keyRequests.some(r => r.roomId === roomId && r.requesterId === userId && r.keyId === keyId)) {
                        keyRequests.push({ roomId, requesterId: userId, keyId });
                    }
                }
                keyRequestPosts.push({ roomId, requesterId: userId, senderKeyIds: senderKeyIds.slice() });
                return { status: 200, data: { success: true, requested: senderKeyIds.length } };
            },
            async getKeyRequests(chatId) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 200, data: { success: true, roomId: null, requests: [] } };
                const byRequester = new Map();
                for (const r of keyRequests) {
                    if (r.roomId !== roomId || r.requesterId === userId) continue;
                    if (!byRequester.has(r.requesterId)) byRequester.set(r.requesterId, []);
                    byRequester.get(r.requesterId).push(r.keyId);
                }
                return { status: 200, data: { success: true, roomId, requests: [...byRequester].map(([fromUserId, senderKeyIds]) => ({ fromUserId, senderKeyIds })) } };
            },
            async postKeyRequestsDone(chatId, senderKeyIds) {
                const roomId = room(userId, chatId);
                if (!roomId) return { status: 200, data: { success: false } };
                for (let i = keyRequests.length - 1; i >= 0; i--) {
                    const r = keyRequests[i];
                    if (r.roomId === roomId && r.requesterId === userId && senderKeyIds.includes(r.keyId)) keyRequests.splice(i, 1);
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
        // Журнал ключей (opts.kt): маршруты /api/kt/* от имени userId; «теневой» транспорт их не видит.
        // Мир пользователя выбирается при каждом вызове: тест может переключить его на другой журнал.
        if (ktOpt && !shadow) {
            for (const name of ['ktHead', 'ktRoots', 'ktProof', 'ktSelf']) t[name] = (...args) => ktOf(userId).transportFor(userId)[name](...args);
        }
        return t;
    }

    // Простейшее хранилище сообщений комнаты — ради сценариев повтора.
    function newMessageId() {
        return String(nextMessageId++);
    }

    function postMessage(roomId, senderId, text, id = newMessageId()) {
        id = String(id);
        if (messages.has(id)) throw new Error('id занят: ' + id);
        messages.set(id, { id, roomId, senderId, text });
        return id;
    }

    function editMessage(id, text) {
        const m = messages.get(String(id));
        if (!m) throw new Error('no message ' + id);
        m.text = text;
    }

    function getMessage(id) {
        const m = messages.get(String(id));
        return m ? Object.assign({}, m) : null;
    }

    const evil = {
        // Сервер выдаёт identity/bundle атакующего (зарегистрированного под
        // attackerId) за ключи victimId — классическая попытка MITM.
        impersonate(victimId, attackerId) { impersonations.set(victimId, attackerId); },
        stopImpersonating(victimId) { impersonations.delete(victimId); },
        // Сервер "теряет" все PQ-ключи в bundle (запасной и одноразовые) —
        // попытка понизить PQXDH до X3DH.
        hidePqPrekey(userId) { hiddenPq.add(userId); },
        // Сервер срезает только одноразовый PQ-ключ: инициатор переходит на запасной.
        stripPqOneTime(userId) { strippedPqOneTime.add(userId); },
        // Сервер выдаёт один и тот же одноразовый PQ-ключ всем инициаторам.
        reusePqOneTime(userId) { reusedPqOneTime.add(userId); },
        // Подмена роли ключа: одноразовый ключ (подпись с меткой) в поле pq_prekey...
        relabelPqOneTimeAsLastResort(userId) { relabelOneTimeAsLastResort.add(userId); },
        // ... и запасной ключ («сырая» подпись) в поле pq_one_time_prekey.
        relabelLastResortAsPqOneTime(userId) { relabelLastResortAsOneTime.add(userId); },
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
            const m = messages.get(String(id));
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
        // Загрузка пула одноразовых PQ-ключей после skip принятых пачек:
        // 'refuse' — явный отказ сервера (success: false), 'network' — исключение fetch.
        failNextPqUpload(mode, skip = 0) { pqUploadFailure = { mode, skip }; },
        addParticipant, removeParticipant, participantsOf,
        newMessageId, postMessage, editMessage, getMessage,
        evil,
        _rooms: rooms,
        _keyRequests: keyRequests,
        _keyRequestPosts: keyRequestPosts,
        _keyShares: keyShares,
        _deliveredKeyShares: deliveredKeyShares,
        _signedPrekeys: signedPrekeys,
        _pqPrekeys: pqPrekeys,
        _oneTimePrekeys: oneTimePrekeys,
        _pqOneTimePrekeys: pqOneTimePrekeys,
    };
}

module.exports = { makeFakeServer };
