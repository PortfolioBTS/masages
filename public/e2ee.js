// E2EE-клиент: X3DH (попарное согласование ключей) + Sender Keys
// (Signal-style групповое шифрование) поверх стандартного Web Crypto API.
//
// Почему именно так:
//   - X3DH используется НЕ для самих сообщений, а только для того, чтобы
//     каждому участнику чата один раз попарно передать его "Sender Key" —
//     общий для всех получателей симметричный ключ конкретного отправителя.
//     Дальше все сообщения от этого отправителя шифруются продвижением
//     этого ключа вперёд (KDF chain), без повторного X3DH на каждое
//     сообщение — так делает Signal в группах.
//   - Identity-ключей два отдельных (Ed25519 для подписи + X25519 для DH),
//     а не один конвертируемый — см. e2ee-key-server/src/crypto.rs, сервер
//     ключей уже спроектирован под эту схему.
//   - Никаких внешних крипто-библиотек: только crypto.subtle и
//     crypto.getRandomValues. Это одновременно и требование CSP
//     (script-src 'self', внешние CDN недоступны), и то, что делает этот
//     файл исполнимым один-в-один в браузере и в чистом Node (Node 19+
//     отдаёт тот же Web Crypto API в globalThis.crypto) — на этом строятся
//     протокольные тесты в test/e2ee.protocol.test.js.
//
// Честные ограничения (см. также README → "Известные ограничения"):
//   - Попарный X3DH-секрет между двумя пользователями закэширован и
//     переиспользуется статически для последующих key-share без Double
//     Ratchet поверх — то есть pairwise-канал (который передаёт только
//     сам Sender Key, не сообщения) не обновляется на каждую передачу.
//     Сами Sender Key чаты используют forward-secret KDF-цепочку.
//   - Ключ отправителя, который receiver подтвердил, не удаляется после
//     использования (в отличие от "чистого" Double Ratchet) — иначе при
//     каждой перезагрузке страницы вся история чата стала бы
//     нерасшифровываемой, т.к. сервер отдаёт полную историю по chat_id, а
//     не только новые сообщения. Это защищает от пассивного наблюдателя
//     (сервера/сети — они никогда не видят ни ключей, ни открытого
//     текста), но не от компрометации самого устройства.
//   - Идентификационный ключ отправителя, вложенный в X3DH-конверт,
//     принимается по модели TOFU (как в самом X3DH/Signal) — сверка через
//     отдельный "код безопасности" не реализована.
//   - Вложения (файлы) НЕ шифруются E2EE — см. /api/messages/file,
//     это отдельная, более крупная задача.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.E2EE = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const subtle = crypto.subtle;

    // ===================== Кодирование =====================

    const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    function b64encode(bytes) {
        const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
        let out = '';
        let i = 0;
        for (; i + 3 <= arr.length; i += 3) {
            const n = (arr[i] << 16) | (arr[i + 1] << 8) | arr[i + 2];
            out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + B64_CHARS[(n >> 6) & 63] + B64_CHARS[n & 63];
        }
        const rem = arr.length - i;
        if (rem === 1) {
            const n = arr[i] << 16;
            out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + '==';
        } else if (rem === 2) {
            const n = (arr[i] << 16) | (arr[i + 1] << 8);
            out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + B64_CHARS[(n >> 6) & 63] + '=';
        }
        return out;
    }

    function b64decode(str) {
        const clean = String(str || '').replace(/[^A-Za-z0-9+/]/g, '');
        const lookup = new Int16Array(256).fill(-1);
        for (let i = 0; i < B64_CHARS.length; i++) lookup[B64_CHARS.charCodeAt(i)] = i;
        const len = clean.length;
        const outLen = Math.floor((len * 6) / 8);
        const out = new Uint8Array(outLen);
        let bits = 0, value = 0, pos = 0;
        for (let i = 0; i < len; i++) {
            const c = lookup[clean.charCodeAt(i)];
            if (c === -1) continue;
            value = (value << 6) | c;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[pos++] = (value >> bits) & 0xff;
            }
        }
        return out.slice(0, pos);
    }

    function utf8encode(str) {
        return new TextEncoder().encode(str);
    }

    function utf8decode(bytes) {
        return new TextDecoder().decode(bytes);
    }

    function concatBytes(...parts) {
        let len = 0;
        for (const p of parts) len += p.length;
        const out = new Uint8Array(len);
        let off = 0;
        for (const p of parts) { out.set(p, off); off += p.length; }
        return out;
    }

    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    // ===================== Примитивы =====================

    function randomBytes(n) {
        return crypto.getRandomValues(new Uint8Array(n));
    }

    async function generateX25519() {
        const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        const privJwk = await subtle.exportKey('jwk', kp.privateKey);
        return { pub, privJwk };
    }

    async function generateEd25519() {
        const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        const privJwk = await subtle.exportKey('jwk', kp.privateKey);
        return { pub, privJwk };
    }

    async function importX25519Pub(rawBytes) {
        return subtle.importKey('raw', rawBytes, { name: 'X25519' }, true, []);
    }

    async function importX25519Priv(jwk) {
        return subtle.importKey('jwk', jwk, { name: 'X25519' }, true, ['deriveBits']);
    }

    async function importEd25519Pub(rawBytes) {
        return subtle.importKey('raw', rawBytes, { name: 'Ed25519' }, true, ['verify']);
    }

    async function importEd25519Priv(jwk) {
        return subtle.importKey('jwk', jwk, { name: 'Ed25519' }, true, ['sign']);
    }

    // low-order/identity точка на Curve25519 — та же defense-in-depth
    // проверка, что уже есть на сервере ключей (crypto.rs::decode_pubkey).
    function isAllZero(bytes) {
        for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
        return true;
    }

    async function dh(privJwk, pubRawBytes) {
        if (isAllZero(pubRawBytes)) throw new Error('E2EE: получен вырожденный (all-zero) публичный ключ');
        const priv = await importX25519Priv(privJwk);
        const pub = await importX25519Pub(pubRawBytes);
        const bits = await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
        return new Uint8Array(bits);
    }

    async function sign(privJwk, data) {
        const priv = await importEd25519Priv(privJwk);
        return new Uint8Array(await subtle.sign('Ed25519', priv, data));
    }

    async function verify(pubRawBytes, sig, data) {
        const pub = await importEd25519Pub(pubRawBytes);
        return subtle.verify('Ed25519', pub, sig, data);
    }

    async function hkdf(ikm, salt, infoStr, lengthBytes) {
        const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt, info: utf8encode(infoStr) },
            key,
            lengthBytes * 8
        );
        return new Uint8Array(bits);
    }

    async function hmacSha256(keyBytes, dataBytes) {
        const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return new Uint8Array(await subtle.sign('HMAC', key, dataBytes));
    }

    async function aesGcmEncrypt(rawKey32, plaintext, aad) {
        const key = await subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['encrypt']);
        const iv = randomBytes(12);
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext));
        return { iv, ct };
    }

    async function aesGcmDecrypt(rawKey32, iv, ct, aad) {
        const key = await subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct);
        return new Uint8Array(pt);
    }

    // ===================== KDF-цепочка Sender Key =====================
    // Стандартная схема Signal: messageKey = HMAC(chainKey, 0x01),
    // nextChainKey = HMAC(chainKey, 0x02). Продвижение необратимо —
    // предыдущий chainKey нельзя восстановить из следующего.

    async function chainStep(chainKey) {
        const messageKey = await hmacSha256(chainKey, new Uint8Array([0x01]));
        const nextChainKey = await hmacSha256(chainKey, new Uint8Array([0x02]));
        return { messageKey, nextChainKey };
    }

    const MAX_CACHED_KEYS = 2000;

    // Возвращает messageKey для нужной iteration, продвигая цепочку и
    // кэшируя "пропущенные" (и уже использованные — см. комментарий в
    // шапке файла про историю чата) ключи по пути.
    async function getOrDeriveMessageKey(state, targetIteration) {
        if (targetIteration < state.nextIteration) {
            const cached = state.cachedKeys[targetIteration];
            if (!cached) return null; // ключ не сохранён (обрезан по MAX_CACHED_KEYS) или никогда не существовал
            return b64decode(cached);
        }
        let chainKey = b64decode(state.chainKey);
        for (let it = state.nextIteration; it <= targetIteration; it++) {
            const { messageKey, nextChainKey } = await chainStep(chainKey);
            state.cachedKeys[it] = b64encode(messageKey);
            chainKey = nextChainKey;
        }
        state.chainKey = b64encode(chainKey);
        state.nextIteration = targetIteration + 1;
        trimCache(state);
        return b64decode(state.cachedKeys[targetIteration]);
    }

    function trimCache(state) {
        const keys = Object.keys(state.cachedKeys);
        if (keys.length <= MAX_CACHED_KEYS) return;
        keys.map(Number).sort((a, b) => a - b)
            .slice(0, keys.length - MAX_CACHED_KEYS)
            .forEach(it => { delete state.cachedKeys[it]; });
    }

    // ===================== Хранилище (внедряется) =====================
    // storage — { get(key)->Promise<any|null>, set(key,value)->Promise,
    //             delete(key)->Promise, keys(prefix)->Promise<string[]> }

    class MemoryStorage {
        constructor() { this.map = new Map(); }
        async get(key) { return this.map.has(key) ? this.map.get(key) : null; }
        async set(key, value) { this.map.set(key, value); }
        async delete(key) { this.map.delete(key); }
        async keys(prefix) { return Array.from(this.map.keys()).filter(k => k.startsWith(prefix)); }
    }

    // IndexedDB-хранилище для браузера. Ключи устройства никогда не
    // покидают этот origin и не отправляются на сервер.
    function makeIndexedDbStorage(dbName) {
        let dbPromise = null;
        function openDb() {
            if (dbPromise) return dbPromise;
            dbPromise = new Promise((resolve, reject) => {
                const req = indexedDB.open(dbName || 'nyxo-e2ee', 1);
                req.onupgradeneeded = () => {
                    if (!req.result.objectStoreNames.contains('kv')) req.result.createObjectStore('kv');
                };
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
            return dbPromise;
        }
        return {
            async get(key) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction('kv', 'readonly').objectStore('kv').get(key);
                    tx.onsuccess = () => resolve(tx.result === undefined ? null : tx.result);
                    tx.onerror = () => reject(tx.error);
                });
            },
            async set(key, value) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction('kv', 'readwrite').objectStore('kv').put(value, key);
                    tx.onsuccess = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            },
            async delete(key) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction('kv', 'readwrite').objectStore('kv').delete(key);
                    tx.onsuccess = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            },
            async keys(prefix) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const out = [];
                    const req = db.transaction('kv', 'readonly').objectStore('kv').openCursor();
                    req.onsuccess = () => {
                        const cursor = req.result;
                        if (!cursor) return resolve(out);
                        if (String(cursor.key).startsWith(prefix)) out.push(String(cursor.key));
                        cursor.continue();
                    };
                    req.onerror = () => reject(req.error);
                });
            },
        };
    }

    // ===================== Транспорт (внедряется) =====================
    // transport — обёртка над /api/keys/* и /api/keys/key-shares*.
    // Реализация по умолчанию для браузера — fetch с CSRF-заголовком.

    function getCsrfTokenFromCookies() {
        if (typeof document === 'undefined') return '';
        const match = document.cookie.match(/csrf_token=([^;]+)/);
        return match ? match[1] : '';
    }

    function makeFetchTransport() {
        async function call(url, method, body) {
            const res = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCsrfTokenFromCookies(),
                },
                body: body !== undefined ? JSON.stringify(body) : undefined,
            });
            const data = await res.json().catch(() => ({ success: false }));
            return { status: res.status, data };
        }
        return {
            async putIdentity(body) { return call('/api/keys/identity', 'PUT', body); },
            async putSignedPrekey(body) { return call('/api/keys/signed-prekey', 'PUT', body); },
            async postOneTimePrekeys(body) { return call('/api/keys/one-time-prekeys', 'POST', body); },
            async getOneTimePrekeyCount() { return call('/api/keys/one-time-prekeys/count', 'GET'); },
            async getBundle(targetUserId) { return call('/api/keys/bundle/' + encodeURIComponent(targetUserId), 'GET'); },
            async getParticipants(chatId) { return call('/api/chats/' + encodeURIComponent(chatId) + '/participants', 'GET'); },
            async postKeyShares(chatId, shares) { return call('/api/keys/key-shares', 'POST', { chatId, shares }); },
            async getKeyShares(chatId) { return call('/api/keys/key-shares/' + encodeURIComponent(chatId), 'GET'); },
        };
    }

    // ===================== Клиент =====================

    const LOW_WATER_OPK = 10;
    const TOPUP_OPK = 30;

    function createClient(options) {
        const storage = options.storage;
        const transport = options.transport || makeFetchTransport();
        let userId = options.userId || null;

        async function nextKeyId() {
            const cur = (await storage.get('nextKeyId')) || Math.floor(Date.now() / 1000);
            await storage.set('nextKeyId', cur + 1);
            return cur;
        }

        async function loadOrCreateIdentity() {
            let identity = await storage.get('identity');
            if (identity) return identity;
            const dhKp = await generateX25519();
            const signKp = await generateEd25519();
            identity = {
                dhPub: b64encode(dhKp.pub), dhPriv: dhKp.privJwk,
                signPub: b64encode(signKp.pub), signPriv: signKp.privJwk,
            };
            await storage.set('identity', identity);
            return identity;
        }

        async function loadOrCreateSpk(identity) {
            let spk = await storage.get('spk');
            if (spk) return spk;
            const kp = await generateX25519();
            const keyId = await nextKeyId();
            const sig = await sign(identity.signPriv, kp.pub);
            spk = { keyId, pub: b64encode(kp.pub), priv: kp.privJwk, sig: b64encode(sig) };
            await storage.set('spk', spk);
            return spk;
        }

        async function uploadIdentityAndSpkIfNeeded(identity, spk) {
            if (await storage.get('uploaded')) return;
            const idRes = await transport.putIdentity({
                identity_signing_key: identity.signPub,
                identity_dh_key: identity.dhPub,
            });
            if (!idRes.data || idRes.data.success !== true) {
                throw new Error('E2EE: не удалось зарегистрировать identity-ключи');
            }
            const spkRes = await transport.putSignedPrekey({
                key_id: spk.keyId, public_key: spk.pub, signature: spk.sig,
            });
            if (!spkRes.data || spkRes.data.success !== true) {
                throw new Error('E2EE: не удалось зарегистрировать signed prekey');
            }
            await storage.set('uploaded', true);
        }

        async function topUpOneTimePreKeysIfNeeded() {
            const countRes = await transport.getOneTimePrekeyCount();
            const count = countRes.data && typeof countRes.data.count === 'number' ? countRes.data.count : 0;
            if (count >= LOW_WATER_OPK) return;
            const toGenerate = TOPUP_OPK - count;
            const keys = [];
            for (let i = 0; i < toGenerate; i++) {
                const kp = await generateX25519();
                const keyId = await nextKeyId();
                await storage.set('opk:' + keyId, { pub: b64encode(kp.pub), priv: kp.privJwk });
                keys.push({ key_id: keyId, public_key: b64encode(kp.pub) });
            }
            if (keys.length > 0) await transport.postOneTimePrekeys({ keys });
        }

        // Инициализация: сгенерировать (или загрузить) ключи устройства,
        // зарегистрировать публичную часть на сервере, пополнить пул OPK.
        async function init() {
            const identity = await loadOrCreateIdentity();
            const spk = await loadOrCreateSpk(identity);
            await uploadIdentityAndSpkIfNeeded(identity, spk);
            await topUpOneTimePreKeysIfNeeded();
            return { identityPub: identity.dhPub, signPub: identity.signPub };
        }

        function setUserId(id) { userId = id; }

        // ---- X3DH: я — инициатор (нужно отправить key-share пиру) ----

        async function ensurePairwiseSendSecret(peerUserId) {
            const cached = await storage.get('pairwiseSend:' + peerUserId);
            if (cached) return { sk: b64decode(cached.sk), header: null };

            const bundleRes = await transport.getBundle(peerUserId);
            if (bundleRes.status === 404 || !bundleRes.data || !bundleRes.data.identity_dh_key) {
                return null; // у пира ещё нет ключей — E2EE с ним пока недоступен
            }
            const bundle = bundleRes.data;
            const identitySignPub = b64decode(bundle.identity_signing_key);
            const identityDhPub = b64decode(bundle.identity_dh_key);
            const spkPub = b64decode(bundle.signed_prekey.public_key);
            const spkSig = b64decode(bundle.signed_prekey.signature);

            // Критическая проверка: подпись Signed PreKey СВОИМ identity-
            // ключом пира. Без этого сервер (или кто-то на пути к нему)
            // мог бы подменить SPK и провести MITM — сервер ключей эту
            // подпись при загрузке тоже проверяет, но полагаться только на
            // это нельзя (см. комментарий в e2ee-key-server/src/crypto.rs).
            const sigOk = await verify(identitySignPub, spkSig, spkPub);
            if (!sigOk) throw new Error('E2EE: неверная подпись Signed PreKey у пользователя ' + peerUserId + ' — возможная подмена ключа');

            const myIdentity = await storage.get('identity');
            const eph = await generateX25519();
            const otpk = bundle.one_time_prekey;

            const dh1 = await dh(myIdentity.dhPriv, spkPub);
            const dh2 = await dh(eph.privJwk, identityDhPub);
            const dh3 = await dh(eph.privJwk, spkPub);
            const dh4 = otpk ? await dh(eph.privJwk, b64decode(otpk.public_key)) : new Uint8Array(0);

            const ikm = concatBytes(new Uint8Array(32).fill(0xff), dh1, dh2, dh3, dh4);
            const sk = await hkdf(ikm, new Uint8Array(32), 'nyxo-e2ee-x3dh-v1', 32);

            await storage.set('pairwiseSend:' + peerUserId, { sk: b64encode(sk) });

            return {
                sk,
                header: {
                    type: 'x3dh-init',
                    senderIdentityDhPub: myIdentity.dhPub,
                    senderEphemeralPub: b64encode(eph.pub),
                    usedSignedPrekeyId: bundle.signed_prekey.key_id,
                    usedOneTimePrekeyId: otpk ? otpk.key_id : null,
                },
            };
        }

        // ---- X3DH: я — получатель (кто-то прислал мне key-share) ----

        async function resolvePairwiseRecvSecret(senderUserId, header) {
            if (!header) {
                const cached = await storage.get('pairwiseRecv:' + senderUserId);
                if (!cached) return null;
                return b64decode(cached.sk);
            }
            const identity = await storage.get('identity');
            const spk = await storage.get('spk');
            if (!spk || spk.keyId !== header.usedSignedPrekeyId) {
                return null; // прислано на SPK, который у нас уже ротирован — не можем расшифровать
            }
            let otpkPriv = null;
            if (header.usedOneTimePrekeyId !== null && header.usedOneTimePrekeyId !== undefined) {
                const otpk = await storage.get('opk:' + header.usedOneTimePrekeyId);
                if (otpk) otpkPriv = otpk.priv;
            }

            const senderIdentityDhPub = b64decode(header.senderIdentityDhPub);
            const senderEphemeralPub = b64decode(header.senderEphemeralPub);

            const dh1 = await dh(spk.priv, senderIdentityDhPub);
            const dh2 = await dh(identity.dhPriv, senderEphemeralPub);
            const dh3 = await dh(spk.priv, senderEphemeralPub);
            const dh4 = otpkPriv ? await dh(otpkPriv, senderEphemeralPub) : new Uint8Array(0);

            const ikm = concatBytes(new Uint8Array(32).fill(0xff), dh1, dh2, dh3, dh4);
            const sk = await hkdf(ikm, new Uint8Array(32), 'nyxo-e2ee-x3dh-v1', 32);

            await storage.set('pairwiseRecv:' + senderUserId, { sk: b64encode(sk) });
            if (header.usedOneTimePrekeyId !== null && header.usedOneTimePrekeyId !== undefined) {
                await storage.delete('opk:' + header.usedOneTimePrekeyId); // одноразовый — использован
            }
            return sk;
        }

        // ---- Sender Key: моё состояние в комнате ----

        async function loadOrCreateOwnSenderKey(roomId) {
            const key = 'senderKey:' + roomId + ':' + userId;
            let state = await storage.get(key);
            if (state) return state;
            const chainKey = randomBytes(32);
            const signKp = await generateEd25519();
            state = {
                senderKeyId: b64encode(randomBytes(16)),
                signingPublicKey: b64encode(signKp.pub),
                signingPrivateKey: signKp.privJwk,
                chainKey: b64encode(chainKey),
                nextIteration: 0,
                cachedKeys: {},
                archived: [],
            };
            await storage.set(key, state);
            return state;
        }

        const MAX_ARCHIVED_KEYS = 3;

        // При ротации Sender Key (новый senderKeyId для того же
        // room+sender) старое состояние не выбрасывается, а переносится в
        // archived — иначе после ротации переставали бы открываться уже
        // показанные ранее сообщения этого отправителя (см. комментарий в
        // шапке файла про то, почему кэш вообще не чистится).
        function archiveIfRotated(state, incomingSenderKeyId) {
            if (!state.senderKeyId || state.senderKeyId === incomingSenderKeyId) return;
            if (!state.archived) state.archived = [];
            state.archived.unshift({
                senderKeyId: state.senderKeyId,
                signingPublicKey: state.signingPublicKey,
                cachedKeys: state.cachedKeys,
            });
            if (state.archived.length > MAX_ARCHIVED_KEYS) state.archived.length = MAX_ARCHIVED_KEYS;
        }

        // Принудительная ротация собственного Sender Key в комнате (новый
        // случайный chainKey + новая подписывающая пара, старое состояние
        // архивируется, чтобы уже отправленные сообщения не потеряли
        // читаемость лично для нас). После вызова ensureRoomSession нужно
        // вызвать заново, чтобы разослать новый ключ участникам —
        // "sharedWith" отметки для старого senderKeyId к новому не относятся.
        async function rotateRoomKey(roomId) {
            const key = 'senderKey:' + roomId + ':' + userId;
            const existing = await storage.get(key);
            const chainKey = randomBytes(32);
            const signKp = await generateEd25519();
            const next = {
                senderKeyId: b64encode(randomBytes(16)),
                signingPublicKey: b64encode(signKp.pub),
                signingPrivateKey: signKp.privJwk,
                chainKey: b64encode(chainKey),
                nextIteration: 0,
                cachedKeys: {},
                archived: existing ? existing.archived || [] : [],
            };
            if (existing) {
                archiveIfRotated(existing, next.senderKeyId);
                next.archived = existing.archived;
            }
            await storage.set(key, next);
            return next;
        }

        function skdmAad(roomId) { return utf8encode('x3dh-skdm:' + roomId); }
        function msgAad(roomId, senderId, senderKeyId) { return utf8encode('senderkey:' + roomId + ':' + senderId + ':' + senderKeyId); }

        // Устанавливает/подтверждает мой Sender Key для комнаты и
        // рассылает его всем участникам, кому ещё не отправляли текущую
        // версию ключа (попарно завёрнутым в X3DH-секрет).
        async function ensureRoomSession(chatId, roomId, participants) {
            const mySenderKey = await loadOrCreateOwnSenderKey(roomId);
            const others = participants.filter(p => Number(p.id) !== Number(userId));
            const shares = [];
            const warnings = [];

            for (const peer of others) {
                const markKey = 'sharedWith:' + roomId + ':' + mySenderKey.senderKeyId + ':' + peer.id;
                if (await storage.get(markKey)) continue;

                let pairwise;
                try {
                    pairwise = await ensurePairwiseSendSecret(peer.id);
                } catch (err) {
                    warnings.push({ userId: peer.id, reason: err.message });
                    continue;
                }
                if (!pairwise) {
                    warnings.push({ userId: peer.id, reason: 'у собеседника ещё не настроен E2EE' });
                    continue;
                }

                const skdm = {
                    v: 1, type: 'skdm', roomId,
                    senderKeyId: mySenderKey.senderKeyId,
                    chainKey: mySenderKey.chainKey,
                    iteration: mySenderKey.nextIteration,
                    signingPublicKey: mySenderKey.signingPublicKey,
                };
                const { iv, ct } = await aesGcmEncrypt(pairwise.sk, utf8encode(JSON.stringify(skdm)), skdmAad(roomId));
                const envelope = Object.assign({ v: 1, iv: b64encode(iv), ct: b64encode(ct) }, pairwise.header || { type: 'reuse' });

                shares.push({ recipientUserId: peer.id, ciphertext: JSON.stringify(envelope) });
                await storage.set(markKey, true);
            }

            if (shares.length > 0) {
                const res = await transport.postKeyShares(chatId, shares);
                if (!res.data || res.data.success !== true) {
                    warnings.push({ reason: 'сервер отклонил отправку key-share' });
                }
            }

            return { ok: true, warnings };
        }

        // Забирает и применяет ожидающие key-share для этого чата.
        async function syncKeyShares(chatId, roomId) {
            const res = await transport.getKeyShares(chatId);
            const list = (res.data && res.data.shares) || [];
            let applied = 0, failed = 0;

            for (const item of list) {
                try {
                    let envelope;
                    try { envelope = JSON.parse(item.ciphertext); } catch { failed++; continue; }
                    const header = envelope.type === 'x3dh-init' ? envelope : null;
                    const sk = await resolvePairwiseRecvSecret(item.senderId, header);
                    if (!sk) { failed++; continue; }

                    const pt = await aesGcmDecrypt(sk, b64decode(envelope.iv), b64decode(envelope.ct), skdmAad(roomId));
                    const skdm = JSON.parse(utf8decode(pt));
                    if (skdm.type !== 'skdm' || Number(skdm.roomId) !== Number(roomId)) { failed++; continue; }

                    const key = 'senderKey:' + roomId + ':' + item.senderId;
                    const existing = await storage.get(key);
                    if (existing && existing.senderKeyId === skdm.senderKeyId) { applied++; continue; } // уже есть, не откатываем состояние

                    // Если это ротация (senderKeyId сменился), архивируем
                    // старое состояние прямо в объекте existing, затем
                    // переносим полученный archived-список в новое.
                    if (existing) archiveIfRotated(existing, skdm.senderKeyId);

                    await storage.set(key, {
                        senderKeyId: skdm.senderKeyId,
                        signingPublicKey: skdm.signingPublicKey,
                        chainKey: skdm.chainKey,
                        nextIteration: skdm.iteration,
                        cachedKeys: {},
                        archived: existing ? existing.archived : [],
                    });
                    applied++;
                } catch (err) {
                    failed++;
                }
            }
            return { applied, failed };
        }

        async function hasRoomKey(roomId) {
            return Boolean(await storage.get('senderKey:' + roomId + ':' + userId));
        }

        // ---- Шифрование/расшифровка сообщений чата ----

        async function encryptOutgoing(roomId, plaintext) {
            const key = 'senderKey:' + roomId + ':' + userId;
            const state = await storage.get(key);
            if (!state) throw new Error('E2EE: для этой комнаты ещё не создан Sender Key — вызовите ensureRoomSession()');

            const iteration = state.nextIteration;
            const { messageKey, nextChainKey } = await chainStep(b64decode(state.chainKey));
            state.cachedKeys[iteration] = b64encode(messageKey); // сохраняем и для собственного отображения истории
            state.chainKey = b64encode(nextChainKey);
            state.nextIteration = iteration + 1;
            trimCache(state);
            await storage.set(key, state);

            const aesKey = await hkdf(messageKey, new Uint8Array(32), 'nyxo-e2ee-msgkey-v1', 32);
            const { iv, ct } = await aesGcmEncrypt(aesKey, utf8encode(plaintext), msgAad(roomId, userId, state.senderKeyId));

            const signingPriv = state.signingPrivateKey;
            const sigInput = concatBytes(iv, ct, new Uint8Array(new Uint32Array([iteration]).buffer));
            const sig = signingPriv ? await sign(signingPriv, sigInput) : new Uint8Array(64);

            const envelope = {
                v: 1, alg: 'senderkey-v1',
                senderKeyId: state.senderKeyId,
                iteration,
                iv: b64encode(iv), ct: b64encode(ct),
                sig: b64encode(sig),
            };
            return JSON.stringify(envelope);
        }

        async function decryptIncoming(roomId, senderId, text) {
            let envelope;
            try { envelope = JSON.parse(text); } catch { return { ok: false, reason: 'bad-envelope' }; }
            if (!envelope || envelope.alg !== 'senderkey-v1') return { ok: false, reason: 'bad-envelope' };

            const key = 'senderKey:' + roomId + ':' + senderId;
            const state = await storage.get(key);
            if (!state) return { ok: false, reason: 'no-sender-key' };

            const iv = b64decode(envelope.iv);
            const ct = b64decode(envelope.ct);
            const sig = b64decode(envelope.sig);
            const sigInput = concatBytes(iv, ct, new Uint8Array(new Uint32Array([envelope.iteration]).buffer));

            let messageKey;
            if (state.senderKeyId === envelope.senderKeyId) {
                const sigOk = await verify(b64decode(state.signingPublicKey), sig, sigInput);
                if (!sigOk) return { ok: false, reason: 'bad-signature' };
                messageKey = await getOrDeriveMessageKey(state, envelope.iteration);
                await storage.set(key, state);
            } else {
                // Не текущий ключ отправителя — возможно, это сообщение,
                // отправленное ДО его ротации (см. archiveIfRotated): ищем
                // среди архивных состояний, чтобы старая история осталась
                // читаемой. Новые (ещё не выведенные) итерации архивного
                // ключа не выводятся — только то, что уже было закэшировано
                // до ротации.
                const archived = (state.archived || []).find(a => a.senderKeyId === envelope.senderKeyId);
                if (!archived) return { ok: false, reason: 'stale-sender-key' };
                const sigOk = await verify(b64decode(archived.signingPublicKey), sig, sigInput);
                if (!sigOk) return { ok: false, reason: 'bad-signature' };
                const cached = archived.cachedKeys[envelope.iteration];
                messageKey = cached ? b64decode(cached) : null;
            }
            if (!messageKey) return { ok: false, reason: 'no-message-key' };

            try {
                const aesKey = await hkdf(messageKey, new Uint8Array(32), 'nyxo-e2ee-msgkey-v1', 32);
                const pt = await aesGcmDecrypt(aesKey, iv, ct, msgAad(roomId, senderId, envelope.senderKeyId));
                return { ok: true, text: utf8decode(pt) };
            } catch (err) {
                return { ok: false, reason: 'decrypt-failed' };
            }
        }

        return {
            init, setUserId,
            ensureRoomSession, syncKeyShares, hasRoomKey, rotateRoomKey,
            encryptOutgoing, decryptIncoming,
        };
    }

    return {
        createClient,
        MemoryStorage,
        makeIndexedDbStorage,
        makeFetchTransport,
        _internal: { b64encode, b64decode, bytesEqual }, // для тестов
    };
});
