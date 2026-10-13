// E2EE-клиент Nyxo: PQXDH (X3DH + ML-KEM-768) для попарных каналов +
// Sender Keys (Signal-style групповое шифрование) поверх Web Crypto API.
//
// Как устроено и почему:
//   - Попарный канал используется НЕ для самих сообщений, а только чтобы
//     передать каждому участнику комнаты "Sender Key" отправителя — общий
//     для всех получателей симметричный ключ. Дальше сообщения шифруются
//     продвижением этого ключа вперёд (KDF-цепочка), без попарной работы на
//     каждое сообщение — так делает Signal в группах.
//   - Identity-ключей два отдельных (Ed25519 для подписи + X25519 для DH),
//     а не один конвертируемый — под эту схему спроектирован
//     e2ee-key-server (src/crypto.rs).
//   - Из внешнего кода — только ML-KEM (public/mlkem.js, чистый JS: в
//     браузерах WebCrypto его пока не умеет). Остальное — crypto.subtle и
//     crypto.getRandomValues. Это и требование CSP (script-src 'self'), и то,
//     что делает файл исполнимым один-в-один в браузере и в Node — на этом
//     построены протокольные тесты test/e2ee.protocol.test.js.
//
// Что закрыто в протоколе v2:
//   - Приватные ключи (identity, SPK, OPK, подпись Sender Key) — неизвлекаемые
//     CryptoKey (extractable:false): XSS не может выгрузить их и унести.
//     Старые JWK из хранилища мигрируются в init() и при чтении.
//   - Identity собеседника закрепляется при первом контакте (TOFU), смена
//     identity блокирует обмен ключами с ним до явного
//     acceptPeerIdentityChange(); для сверки есть 60-значный код
//     безопасности, как в Signal. Получатель больше не верит identity из
//     конверта на слово.
//   - PQXDH: к X3DH добавлен ML-KEM-768 по PQ-prekey, подписанному identity —
//     защита от "перехватить сейчас, расшифровать потом". Отката на
//     классический X3DH нет, поэтому сервер не может понизить версию.
//   - AD ключевого обмена включает identity-ключи обеих сторон.
//   - SPK и PQ-prekey ротируются раз в 7 дней (старые приватные живут ещё
//     14). Канал key-share — симметричная KDF-цепочка с удалением
//     использованных ключей (прямая секретность); раз в 7 дней сессия
//     перезапускается новым PQXDH.
//   - Повтор конверта под другим messageId распознаётся ('replay').
//   - Текст дополняется по схеме Padmé (минимум 256 байт); файлы шифруются
//     AES-256-GCM на клиенте, ключ едет внутри E2EE-сообщения.
//   - Клиент помнит состав комнаты: новые участники видны (атака
//     "призрачного участника" перестаёт быть тихой), при уходе участника
//     свой Sender Key ротируется.
//
// Честные ограничения (см. также README → "Известные ограничения"):
//   - Код клиента отдаёт тот же сервер: злонамеренный сервер может выдать
//     изменённый e2ee.js, и веб-клиент от этого защититься не может.
//   - Метаданные видны серверу: кто, когда, в какой комнате, кому раздаёт
//     ключи, класс размера сообщения/файла (после Padmé), состав комнат.
//   - Состав комнаты задаёт сервер; клиент лишь делает изменения видимыми
//     (newMembers/removedMembers), решение остаётся за пользователем.
//   - Нет post-compromise security для Sender Keys: утёкший ключ цепочки
//     читает всё будущее до ротации (ротация — при уходе участника или
//     вручную через rotateRoomKey()).
//   - Ключи уже показанных сообщений не удаляются (иначе история не
//     открывалась бы после перезагрузки — сервер отдаёт её целиком), поэтому
//     от компрометации самого устройства история не защищена.
//   - Неизвлекаемость не мешает активной XSS ПОЛЬЗОВАТЬСЯ ключами, пока она
//     на странице. Seed ML-KEM хранится байтами (чистый JS), но без
//     X25519-ключей он бесполезен.
//   - Первый контакт — TOFU: пока коды безопасности не сверены, MITM со
//     стороны сервера на первом контакте не исключён.
//   - Одно устройство на аккаунт (identity на сервере — одна запись).
//   - Подмену текста сообщения его же старой правкой (тот же messageId) не
//     распознать; таблица повторов ограничена 5000 итерациями на ключ.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.E2EE = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const subtle = crypto.subtle;

    // ===================== Константы =====================

    const DAY_MS = 24 * 60 * 60 * 1000;
    const PREKEY_ROTATE_MS = 7 * DAY_MS;   // SPK и PQ-prekey
    const PREKEY_RETAIN_MS = 14 * DAY_MS;  // сколько держим приватную часть после ротации
    const PAIRWISE_SESSION_MAX_AGE_MS = 7 * DAY_MS;

    const MAX_CACHED_KEYS = 2000;
    // Насколько далеко вперёд по цепочке Sender Key можно "перескочить" за
    // одно сообщение. Без предела конверт с iteration = 10^9 (его может
    // подписать любой участник комнаты) заставлял клиента получателя
    // посчитать миллиард HMAC подряд — вкладка намертво зависала.
    const MAX_SKIP = 5000;
    // То же для попарной цепочки key-share: передач ключей на порядки
    // меньше, чем сообщений.
    const MAX_PW_SKIP = 1000;
    const MAX_ARCHIVED_KEYS = 3;
    const MAX_SEEN_PER_KEY = 5000;
    const MAX_SEEN_EPHEMERAL = 64;
    const MAX_PENDING_SHARES = 50;

    const MSG_PAD_MIN = 256;
    const FILE_PAD_MIN = 4096;
    // Сервер принимает зашифрованный текст до 12000 символов.
    const MAX_ENVELOPE_CHARS = 12000;
    const MAX_FILE_FIELD = 1024;
    // Сервер принимает до 200 получателей и 8192 символа на один share;
    // пачки по 50 держат тело запроса небольшим.
    const SHARE_BATCH = 50;
    const MAX_SHARE_CHARS = 8192;

    const FINGERPRINT_ITERATIONS = 5200;
    const PQ_PUBLIC_KEY_BYTES = 1184;
    const PQ_CIPHERTEXT_BYTES = 1088;
    const PQ_SEED_BYTES = 64;

    const LOW_WATER_OPK = 10;
    const TOPUP_OPK = 30;
    const SCHEMA_VERSION = 2;

    const REASON_NOT_READY = 'у собеседника ещё не настроен E2EE';
    const REASON_OUTDATED = 'у собеседника устаревшая версия E2EE';
    const REASON_IDENTITY_CHANGED = 'ключ безопасности собеседника изменился — нужно подтверждение';

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

    // Таблица строится один раз, а не на каждый вызов b64decode.
    const B64_LOOKUP = new Int16Array(256).fill(-1);
    for (let i = 0; i < B64_CHARS.length; i++) B64_LOOKUP[B64_CHARS.charCodeAt(i)] = i;

    function b64decode(str) {
        const clean = String(str || '').replace(/[^A-Za-z0-9+/]/g, '');
        const lookup = B64_LOOKUP;
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

    // Строгое декодирование поля фиксированной длины из недоверенного JSON.
    function decodeFixed(str, len) {
        if (typeof str !== 'string') return null;
        const bytes = b64decode(str);
        return bytes.length === len ? bytes : null;
    }

    // Публичный ключ X25519/Ed25519 в каноническом base64. Сравниваем ключи
    // строками, поэтому разные написания одних и тех же байт недопустимы.
    function canonicalPubKey(str) {
        const bytes = decodeFixed(str, 32);
        if (!bytes || isAllZero(bytes)) return null;
        return b64encode(bytes);
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

    function u32be(n) {
        return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
    }

    function u32le(n) {
        return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
    }

    function toBytes(data) {
        if (data instanceof Uint8Array) return data;
        if (data instanceof ArrayBuffer) return new Uint8Array(data);
        if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        throw new TypeError('E2EE: ожидались байты (Uint8Array/ArrayBuffer)');
    }

    function isKeyId(v) {
        return Number.isSafeInteger(v) && v >= 0;
    }

    // ===================== Примитивы =====================

    const ZERO32 = new Uint8Array(32);
    const FF32 = new Uint8Array(32).fill(0xff);

    function randomBytes(n) {
        return crypto.getRandomValues(new Uint8Array(n));
    }

    // Приватные ключи создаются неизвлекаемыми: их можно использовать, но не
    // выгрузить наружу (exportKey кидает). Публичная половина пары по
    // спецификации WebCrypto извлекаема всегда.
    async function generateX25519() {
        const kp = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        return { pub, priv: kp.privateKey };
    }

    async function generateEd25519() {
        const kp = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        return { pub, priv: kp.privateKey };
    }

    function isCryptoKey(v) {
        return Boolean(v) && typeof v === 'object' && typeof v.type === 'string' && Boolean(v.algorithm) && typeof v.extractable === 'boolean';
    }

    function isJwk(v) {
        return Boolean(v) && typeof v === 'object' && typeof v.kty === 'string';
    }

    // Миграция: JWK, записанный прежней версией, импортируется как
    // неизвлекаемый CryptoKey (после перезаписи в хранилище JWK исчезает).
    async function toPrivateKey(value, algName, usages) {
        if (isCryptoKey(value)) return value;
        if (isJwk(value)) return subtle.importKey('jwk', value, { name: algName }, false, usages);
        throw new Error('E2EE: повреждён приватный ключ в хранилище');
    }

    // low-order/identity точка на Curve25519 — та же defense-in-depth
    // проверка, что уже есть на сервере ключей (crypto.rs::decode_pubkey).
    function isAllZero(bytes) {
        for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
        return true;
    }

    async function dh(privKey, pubRawBytes) {
        if (pubRawBytes.length !== 32 || isAllZero(pubRawBytes)) {
            throw new Error('E2EE: получен вырожденный (all-zero) публичный ключ');
        }
        const pub = await subtle.importKey('raw', pubRawBytes, { name: 'X25519' }, false, []);
        const bits = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, privKey, 256));
        if (isAllZero(bits)) throw new Error('E2EE: вырожденный результат DH (точка малого порядка)');
        return bits;
    }

    async function sign(privKey, data) {
        return new Uint8Array(await subtle.sign('Ed25519', privKey, data));
    }

    // Импорт публичного ключа стоит заметно дороже самой проверки, а ключи
    // подписи Sender Key одни и те же для тысяч сообщений истории.
    const verifyKeyCache = new Map();
    async function verify(pubRawBytes, sig, data) {
        try {
            if (pubRawBytes.length !== 32 || sig.length !== 64) return false;
            const cacheKey = b64encode(pubRawBytes);
            let pub = verifyKeyCache.get(cacheKey);
            if (!pub) {
                pub = await subtle.importKey('raw', pubRawBytes, { name: 'Ed25519' }, false, ['verify']);
                if (verifyKeyCache.size >= 256) verifyKeyCache.delete(verifyKeyCache.keys().next().value);
                verifyKeyCache.set(cacheKey, pub);
            }
            return await subtle.verify('Ed25519', pub, sig, data);
        } catch {
            return false;
        }
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

    // ===================== KDF-цепочка =====================
    // Стандартная схема Signal: messageKey = HMAC(chainKey, 0x01),
    // nextChainKey = HMAC(chainKey, 0x02). Продвижение необратимо —
    // предыдущий chainKey нельзя восстановить из следующего. Одна и та же
    // схема у Sender Key и у попарного канала key-share.

    async function chainStep(chainKey) {
        const messageKey = await hmacSha256(chainKey, new Uint8Array([0x01]));
        const nextChainKey = await hmacSha256(chainKey, new Uint8Array([0x02]));
        return { messageKey, nextChainKey };
    }

    // Возвращает messageKey для нужной iteration, продвигая цепочку и
    // кэшируя "пропущенные" (и уже использованные — см. шапку файла про
    // историю чата) ключи по пути.
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

    function trimNumericMap(map, max) {
        const keys = Object.keys(map);
        if (keys.length <= max) return;
        keys.map(Number).sort((a, b) => a - b)
            .slice(0, keys.length - max)
            .forEach(k => { delete map[k]; });
    }

    function trimCache(state) {
        trimNumericMap(state.cachedKeys, MAX_CACHED_KEYS);
    }

    // Ключ сообщения n попарной цепочки. В отличие от Sender Key здесь
    // использованный ключ сразу удаляется, а в сессии остаются только
    // следующий chainKey и ключи ещё не пришедших (пропущенных) передач —
    // это и есть прямая секретность канала key-share.
    async function takePairwiseKey(session, n) {
        if (n < session.n) {
            const stored = session.skipped[n];
            if (!stored) return null; // уже использован (повтор) или слишком старый
            delete session.skipped[n];
            return b64decode(stored);
        }
        if (n - session.n > MAX_PW_SKIP) return null;
        let chainKey = b64decode(session.ck);
        let target = null;
        for (let i = session.n; i <= n; i++) {
            const { messageKey, nextChainKey } = await chainStep(chainKey);
            if (i === n) target = messageKey;
            else session.skipped[i] = b64encode(messageKey);
            chainKey = nextChainKey;
        }
        session.ck = b64encode(chainKey);
        session.n = n + 1;
        trimNumericMap(session.skipped, MAX_PW_SKIP);
        return target;
    }

    // ===================== Паддинг (Padmé) =====================
    // Padmé (Nikitin et al., PETS 2019): округляет длину так, что утечка
    // ограничена O(log log L) бит, а накладные расходы — не более ~12%.

    function bitLength(n) {
        let bits = 0;
        while (n >= 1) { n = Math.floor(n / 2); bits++; }
        return bits;
    }

    function padmeLength(len) {
        if (len < 2) return len;
        const e = bitLength(len) - 1;   // floor(log2 L)
        const s = bitLength(e);         // floor(log2 E) + 1
        const step = 2 ** (e - s);
        return Math.ceil(len / step) * step;
    }

    // Текст: 4 байта длины (big-endian) ‖ данные ‖ нули до длины Padmé,
    // но не меньше 256 байт — короткие сообщения неотличимы по размеру.
    function padMessage(bytes) {
        const out = new Uint8Array(Math.max(MSG_PAD_MIN, padmeLength(4 + bytes.length)));
        out.set(u32be(bytes.length), 0);
        out.set(bytes, 4);
        return out;
    }

    function unpadMessage(buf) {
        if (buf.length < 4) return null;
        const len = ((buf[0] << 24) >>> 0) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
        if (len > buf.length - 4) return null;
        return buf.subarray(4, 4 + len);
    }

    function filePaddedLength(size) {
        return Math.max(FILE_PAD_MIN, padmeLength(size));
    }

    // ===================== Содержимое сообщения v2 =====================

    function normalizeFileDescriptor(o) {
        if (!o || typeof o !== 'object') return null;
        const { mime, name, size, key, iv } = o;
        if (typeof mime !== 'string' || mime.length > MAX_FILE_FIELD) return null;
        if (typeof name !== 'string' || name.length > MAX_FILE_FIELD) return null;
        if (!Number.isSafeInteger(size) || size < 0) return null;
        if (!decodeFixed(key, 32) || !decodeFixed(iv, 12)) return null;
        return { mime, name, size, key, iv };
    }

    function encodeContent(content) {
        if (typeof content === 'string') return { t: 'text', b: content };
        if (content && typeof content === 'object' && content.type === 'file') {
            const file = normalizeFileDescriptor(content);
            if (!file) throw new Error('E2EE: некорректное описание файла');
            const caption = content.caption === undefined || content.caption === null ? '' : content.caption;
            if (typeof caption !== 'string') throw new Error('E2EE: подпись к файлу должна быть строкой');
            return { t: 'file', mime: file.mime, name: file.name, size: file.size, key: file.key, iv: file.iv, caption };
        }
        throw new Error('E2EE: неподдерживаемое содержимое сообщения');
    }

    function decodeContent(obj) {
        if (!obj || typeof obj !== 'object') return null;
        if (obj.t === 'text' && typeof obj.b === 'string') return { text: obj.b };
        if (obj.t === 'file') {
            const file = normalizeFileDescriptor(obj);
            if (!file || typeof obj.caption !== 'string') return null;
            return { text: obj.caption, file };
        }
        return null;
    }

    // ===================== Файлы =====================
    // Каждый файл — свой случайный ключ AES-256-GCM и iv; ключ, iv и
    // исходный размер передаются внутри E2EE-сообщения (encryptOutgoing с
    // объектом { type:'file', ... }), серверу достаётся только шифротекст
    // Padmé-длины.

    const FILE_AAD = utf8encode('nyxo-file-v1');

    async function encryptFile(bytes) {
        const data = toBytes(bytes);
        const padded = new Uint8Array(filePaddedLength(data.length));
        padded.set(data, 0);
        const key = randomBytes(32);
        const { iv, ct } = await aesGcmEncrypt(key, padded, FILE_AAD);
        return { ciphertext: ct, key: b64encode(key), iv: b64encode(iv), size: data.length };
    }

    async function decryptFile(ciphertext, key, iv, size) {
        const keyBytes = decodeFixed(key, 32);
        const ivBytes = decodeFixed(iv, 12);
        if (!keyBytes || !ivBytes) throw new Error('E2EE: некорректный ключ файла');
        if (!Number.isSafeInteger(size) || size < 0) throw new Error('E2EE: некорректный размер файла');
        let pt;
        try {
            pt = await aesGcmDecrypt(keyBytes, ivBytes, toBytes(ciphertext), FILE_AAD);
        } catch {
            throw new Error('E2EE: файл повреждён или подменён');
        }
        // Размер пришёл в подписанном сообщении; несовпадение с длиной
        // расшифрованного — признак чужого файла или испорченного описания.
        if (pt.length !== filePaddedLength(size)) throw new Error('E2EE: размер файла не совпадает');
        for (let i = size; i < pt.length; i++) {
            if (pt[i] !== 0) throw new Error('E2EE: некорректный паддинг файла');
        }
        return pt.slice(0, size);
    }

    // ===================== Код безопасности =====================
    // Как NumericFingerprintGenerator в Signal: для каждой стороны
    // hash0 = 0x0000 ‖ signPub ‖ dhPub ‖ utf8(userId), затем 5200 раз
    // hash = SHA-512(hash ‖ signPub ‖ dhPub); первые 30 байт → 6 блоков по
    // 5 байт → uint40 mod 100000 → по 5 цифр. Половины упорядочены по
    // числовому userId, поэтому обе стороны видят одну и ту же строку.

    async function fingerprintHalf(userId, signPubB64, dhPubB64) {
        const keys = concatBytes(b64decode(signPubB64), b64decode(dhPubB64));
        let hash = concatBytes(new Uint8Array([0, 0]), keys, utf8encode(String(userId)));
        for (let i = 0; i < FINGERPRINT_ITERATIONS; i++) {
            hash = new Uint8Array(await subtle.digest('SHA-512', concatBytes(hash, keys)));
        }
        let out = '';
        for (let i = 0; i < 30; i += 5) {
            let v = 0;
            for (let j = 0; j < 5; j++) v = v * 256 + hash[i + j];
            out += String(v % 100000).padStart(5, '0');
        }
        return out;
    }

    async function computeSafetyNumber(idA, signA, dhA, idB, signB, dhB) {
        const halfA = await fingerprintHalf(idA, signA, dhA);
        const halfB = await fingerprintHalf(idB, signB, dhB);
        const digits = Number(idA) <= Number(idB) ? halfA + halfB : halfB + halfA;
        return digits.match(/.{5}/g).join(' ');
    }

    // ===================== Хранилище (внедряется) =====================
    // storage — { get(key)->Promise<any|null>, set(key,value)->Promise,
    //             delete(key)->Promise, keys(prefix)->Promise<string[]> }

    // Значения клонируются так же, как их клонирует IndexedDB (structured
    // clone): тесты на MemoryStorage ловят забытый set() после изменения
    // объекта и заодно проверяют, что CryptoKey переживает клонирование.
    class MemoryStorage {
        constructor() { this.map = new Map(); }
        async get(key) { return this.map.has(key) ? structuredClone(this.map.get(key)) : null; }
        async set(key, value) { this.map.set(key, structuredClone(value)); }
        async delete(key) { this.map.delete(key); }
        async keys(prefix) { return Array.from(this.map.keys()).filter(k => k.startsWith(prefix)); }
    }

    // IndexedDB-хранилище для браузера. Ключи устройства никогда не
    // покидают этот origin и не отправляются на сервер; приватные ключи
    // лежат в нём как неизвлекаемые CryptoKey (structured clone это умеет).
    function makeIndexedDbStorage(dbName) {
        let dbPromise = null;
        function openDb() {
            if (dbPromise) return dbPromise;
            dbPromise = new Promise((resolve, reject) => {
                const req = indexedDB.open(dbName || 'nyxo-e2ee', 1);
                req.onupgradeneeded = () => {
                    if (!req.result.objectStoreNames.contains('kv')) req.result.createObjectStore('kv');
                };
                req.onsuccess = () => {
                    const db = req.result;
                    // deleteLocalData() (или другая вкладка) удаляет базу —
                    // отпускаем соединение, иначе удаление заблокируется.
                    db.onversionchange = () => { db.close(); dbPromise = null; };
                    resolve(db);
                };
                req.onerror = () => { dbPromise = null; reject(req.error); };
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

    // Удаляет локальную базу ключей пользователя (выход с удалением данных,
    // удаление аккаунта). Резолвится true после удаления, false — если
    // IndexedDB нет вовсе.
    function deleteLocalData(userId) {
        return new Promise((resolve, reject) => {
            const id = Number(userId);
            if (!Number.isSafeInteger(id) || id <= 0) {
                reject(new Error('E2EE: некорректный userId'));
                return;
            }
            if (typeof indexedDB === 'undefined' || !indexedDB) {
                resolve(false);
                return;
            }
            let settled = false;
            let timer = null;
            const finish = (fn, value) => {
                if (settled) return;
                settled = true;
                if (timer) clearTimeout(timer);
                fn(value);
            };
            const req = indexedDB.deleteDatabase('nyxo-e2ee-' + id);
            req.onsuccess = () => finish(resolve, true);
            req.onerror = () => finish(reject, req.error || new Error('E2EE: не удалось удалить локальные ключи'));
            // База открыта в другой вкладке. Наши соединения закрываются сами
            // по versionchange (makeIndexedDbStorage), но зависшая вкладка
            // может держать её долго — не ждём вечно. Запрос на удаление при
            // этом остаётся в очереди и выполнится, когда вкладку закроют.
            req.onblocked = () => {
                if (settled || timer) return;
                timer = setTimeout(() => finish(reject, new Error(
                    'E2EE: локальные ключи открыты в другой вкладке — закройте её, удаление завершится автоматически'
                )), 10000);
            };
        });
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
            async putPqPrekey(body) { return call('/api/keys/pq-prekey', 'PUT', body); },
            async postOneTimePrekeys(body) { return call('/api/keys/one-time-prekeys', 'POST', body); },
            async getOneTimePrekeyCount() { return call('/api/keys/one-time-prekeys/count', 'GET'); },
            async getBundle(targetUserId) { return call('/api/keys/bundle/' + encodeURIComponent(targetUserId), 'GET'); },
            async getIdentities(ids) {
                const list = ids.map(Number).filter(id => Number.isSafeInteger(id) && id > 0);
                return call('/api/keys/identities?ids=' + list.join(','), 'GET');
            },
            async deleteKeys() { return call('/api/keys', 'DELETE'); },
            async getParticipants(chatId) { return call('/api/chats/' + encodeURIComponent(chatId) + '/participants', 'GET'); },
            async postKeyShares(chatId, shares) { return call('/api/keys/key-shares', 'POST', { chatId, shares }); },
            async getKeyShares(chatId) { return call('/api/keys/key-shares/' + encodeURIComponent(chatId), 'GET'); },
        };
    }

    // ML-KEM по умолчанию: в браузере — глобальный MLKEM (public/mlkem.js
    // подключается до e2ee.js), в Node — соседний модуль.
    function resolveDefaultKem() {
        if (typeof MLKEM !== 'undefined' && MLKEM) return MLKEM;
        if (typeof require === 'function') {
            try {
                return require('./mlkem.js');
            } catch {
                throw new Error('E2EE: модуль ML-KEM (mlkem.js) недоступен');
            }
        }
        throw new Error('E2EE: модуль ML-KEM (mlkem.js) не загружен');
    }

    // ===================== Форматы конвертов =====================

    function sigInputV1(iv, ct, iteration) {
        // v1 подписывал iteration в порядке байт платформы (Uint32Array) —
        // на всех реальных платформах это little-endian; воспроизводим явно.
        return concatBytes(iv, ct, u32le(iteration));
    }

    function sigInputV2(iv, ct, iteration, senderKeyId) {
        return concatBytes(iv, ct, u32be(iteration), utf8encode(senderKeyId));
    }

    function msgAadV1(roomId, senderId, senderKeyId) {
        return utf8encode('senderkey:' + roomId + ':' + senderId + ':' + senderKeyId);
    }

    function msgAadV2(roomId, senderId, senderKeyId) {
        return utf8encode('senderkey-v2:' + roomId + ':' + senderId + ':' + senderKeyId);
    }

    // AD key-share v2: помимо комнаты и направления — identity-ключи обеих
    // сторон (требование X3DH: AD = IK_A ‖ IK_B). Подмена identity любой из
    // сторон ломает AEAD, даже если сессионный ключ каким-то образом совпал.
    function skdmAadV2(roomId, senderUserId, recipientUserId, senderSignPub, senderDhPub, recipientSignPub, recipientDhPub) {
        return concatBytes(
            utf8encode('nyxo-skdm-v2:' + roomId + ':' + senderUserId + ':' + recipientUserId),
            b64decode(senderSignPub), b64decode(senderDhPub),
            b64decode(recipientSignPub), b64decode(recipientDhPub)
        );
    }

    // Конверт key-share v2: { v:2, type:'skdm', n, iv, ct, init:{...} }.
    // Заголовок PQXDH (init) повторяется в каждой передаче сессии: получатель
    // узнаёт сессию по эфемерному ключу, а если первая передача потерялась
    // (или была отложена до подтверждения смены identity) — выводит её из
    // заголовка любой следующей.
    function parseShareEnvelope(ciphertext) {
        let env;
        try { env = JSON.parse(ciphertext); } catch { return null; }
        if (!env || typeof env !== 'object' || env.v !== 2 || env.type !== 'skdm') return null;
        if (!Number.isSafeInteger(env.n) || env.n < 0) return null;
        const iv = decodeFixed(env.iv, 12);
        const ct = typeof env.ct === 'string' ? b64decode(env.ct) : null;
        if (!iv || !ct || ct.length < 16) return null;
        const h = env.init;
        if (!h || typeof h !== 'object') return null;
        const signPub = canonicalPubKey(h.senderIdentitySignPub);
        const dhPub = canonicalPubKey(h.senderIdentityDhPub);
        const eph = canonicalPubKey(h.senderEphemeralPub);
        const opkId = h.usedOneTimePrekeyId === null || h.usedOneTimePrekeyId === undefined ? null : h.usedOneTimePrekeyId;
        // Без PQ-части заголовок не принимается вовсе: иначе сервер мог бы
        // "понизить" обмен до классического X3DH.
        const pqCt = decodeFixed(h.pqCiphertext, PQ_CIPHERTEXT_BYTES);
        if (!signPub || !dhPub || !eph || !pqCt) return null;
        if (!isKeyId(h.usedSignedPrekeyId) || !isKeyId(h.usedPqPrekeyId) || (opkId !== null && !isKeyId(opkId))) return null;
        return {
            n: env.n, iv, ct,
            init: { signPub, dhPub, eph, spkId: h.usedSignedPrekeyId, opkId, pqId: h.usedPqPrekeyId, pqCt },
        };
    }

    function parseSkdm(pt, roomId) {
        let skdm;
        try { skdm = JSON.parse(utf8decode(pt)); } catch { return null; }
        if (!skdm || skdm.v !== 2 || skdm.type !== 'skdm' || Number(skdm.roomId) !== Number(roomId)) return null;
        if (typeof skdm.senderKeyId !== 'string' || !decodeFixed(skdm.senderKeyId, 16)) return null;
        if (!decodeFixed(skdm.chainKey, 32)) return null;
        if (!Number.isInteger(skdm.iteration) || skdm.iteration < 0 || skdm.iteration > 0xFFFFFFFF) return null;
        const signingPublicKey = canonicalPubKey(skdm.signingPublicKey);
        if (!signingPublicKey) return null;
        return {
            senderKeyId: skdm.senderKeyId,
            chainKey: skdm.chainKey,
            iteration: skdm.iteration,
            signingPublicKey,
        };
    }

    // При ротации Sender Key (новый senderKeyId для того же room+sender)
    // старое состояние не выбрасывается, а переносится в archived — иначе
    // после ротации переставали бы открываться уже показанные сообщения.
    // Подписывающий приватный ключ в архив не попадает. У ЧУЖОГО ключа
    // сохраняется и позиция цепочки (keepChain): ротация теперь происходит
    // автоматически при уходе участника, и сообщения, отправленные до неё,
    // но ещё не открытые получателем, иначе стали бы нечитаемыми. Новых
    // сообщений старым ключом отправитель уже не шлёт, а подписать их за
    // него никто другой не может. Свои сообщения кэшируются при отправке,
    // поэтому свою цепочку в архиве не держим. Возвращает id вытесненных из
    // архива ключей (их таблицы повторов больше не нужны).
    function archiveIfRotated(state, incomingSenderKeyId, keepChain) {
        if (!state.senderKeyId || state.senderKeyId === incomingSenderKeyId) return [];
        if (!state.archived) state.archived = [];
        const entry = {
            senderKeyId: state.senderKeyId,
            signingPublicKey: state.signingPublicKey,
            cachedKeys: state.cachedKeys,
        };
        if (keepChain) {
            entry.chainKey = state.chainKey;
            entry.nextIteration = state.nextIteration;
        }
        state.archived.unshift(entry);
        const dropped = state.archived.length > MAX_ARCHIVED_KEYS ? state.archived.splice(MAX_ARCHIVED_KEYS) : [];
        return dropped.map(a => a.senderKeyId);
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

    function identityStatus(pin) {
        if (!pin) return 'unknown';
        if (pin.pending) return 'changed';
        return pin.verified ? 'verified' : 'unverified';
    }

    // ===================== Клиент =====================

    function createClient(options) {
        const storage = options.storage;
        const transport = options.transport || makeFetchTransport();
        // Часы внедряются ради тестов ротации prekey (7/14 дней).
        const now = typeof options.now === 'function' ? options.now : () => Date.now();
        let kem = options.kem || null;
        let userId = options.userId || null;

        function getKem() {
            if (!kem) kem = resolveDefaultKem();
            return kem;
        }

        // Все изменения состояния в хранилище идут строго по очереди: иначе
        // два параллельных вызова (открытие чата + отправка, синхронизация
        // ключей + расшифровка истории) читали одно состояние и затирали
        // изменения друг друга — например, ротацию Sender Key собеседника
        // перезаписывало продвижение его старой цепочки. Сетевые запросы по
        // возможности делаются вне очереди, чтобы не тормозить расшифровку.
        // Функции *Locked вызываются только изнутри withLock.
        let lockTail = Promise.resolve();
        function withLock(fn) {
            const run = lockTail.then(() => fn());
            lockTail = run.then(() => undefined, () => undefined);
            return run;
        }

        async function nextKeyId() {
            const cur = (await storage.get('nextKeyId')) || Math.floor(now() / 1000);
            await storage.set('nextKeyId', cur + 1);
            return cur;
        }

        // ---- Ключи устройства (с ленивой миграцией JWK → CryptoKey) ----

        async function loadIdentityLocked() {
            const identity = await storage.get('identity');
            if (!identity) return null;
            if (!isCryptoKey(identity.dhPriv) || !isCryptoKey(identity.signPriv)) {
                identity.dhPriv = await toPrivateKey(identity.dhPriv, 'X25519', ['deriveBits']);
                identity.signPriv = await toPrivateKey(identity.signPriv, 'Ed25519', ['sign']);
                await storage.set('identity', identity);
            }
            return identity;
        }

        async function loadOrCreateIdentityLocked() {
            let identity = await loadIdentityLocked();
            if (identity) return identity;
            const dhKp = await generateX25519();
            const signKp = await generateEd25519();
            identity = {
                dhPub: b64encode(dhKp.pub), dhPriv: dhKp.priv,
                signPub: b64encode(signKp.pub), signPriv: signKp.priv,
            };
            await storage.set('identity', identity);
            return identity;
        }

        async function loadSpkLocked() {
            const spk = await storage.get('spk');
            if (!spk) return null;
            if (!isCryptoKey(spk.priv)) {
                spk.priv = await toPrivateKey(spk.priv, 'X25519', ['deriveBits']);
                // У ключа прежней версии нет даты создания: считаем его
                // давно просроченным, init() сразу его ротирует.
                if (typeof spk.createdAt !== 'number') spk.createdAt = 0;
                await storage.set('spk', spk);
            }
            return spk;
        }

        async function loadOpkLocked(keyId) {
            const name = 'opk:' + keyId;
            const opk = await storage.get(name);
            if (!opk) return null;
            if (!isCryptoKey(opk.priv)) {
                opk.priv = await toPrivateKey(opk.priv, 'X25519', ['deriveBits']);
                await storage.set(name, opk);
            }
            return opk;
        }

        function ownKeyName(roomId) {
            return 'senderKey:' + roomId + ':' + userId;
        }

        async function loadOwnSenderKeyLocked(roomId) {
            const name = ownKeyName(roomId);
            const state = await storage.get(name);
            if (!state) return null;
            if (state.signingPrivateKey && !isCryptoKey(state.signingPrivateKey)) {
                state.signingPrivateKey = await toPrivateKey(state.signingPrivateKey, 'Ed25519', ['sign']);
                await storage.set(name, state);
            }
            return state;
        }

        // Разовая миграция хранилища прежней версии: JWK → неизвлекаемые
        // CryptoKey, флаг загрузки → отдельные флаги по ключам, статичные
        // попарные секреты v1 удаляются (их заменяет цепочка v2, а лишний
        // ключевой материал на диске — лишний риск).
        async function migrateLegacyLocked() {
            if ((await storage.get('schema')) === SCHEMA_VERSION) return;
            const identity = await loadIdentityLocked();
            const spk = await loadSpkLocked();
            for (const name of await storage.keys('opk:')) {
                await loadOpkLocked(name.slice('opk:'.length));
            }
            for (const name of await storage.keys('senderKey:')) {
                const parts = name.split(':');
                if (parts.length === 3 && parts[2] === String(userId)) await loadOwnSenderKeyLocked(parts[1]);
            }
            if (await storage.get('uploaded')) {
                if (identity) await storage.set('up:identity', identity.signPub + ':' + identity.dhPub);
                if (spk) await storage.set('up:spk', spk.keyId);
                await storage.delete('uploaded');
            }
            for (const prefix of ['pairwiseSend:', 'pairwiseRecv:', 'sharedWith:']) {
                for (const name of await storage.keys(prefix)) await storage.delete(name);
            }
            await storage.set('schema', SCHEMA_VERSION);
        }

        let localReady = null;
        function ensureLocal() {
            if (!localReady) {
                localReady = withLock(async () => {
                    await migrateLegacyLocked();
                    await loadOrCreateIdentityLocked();
                });
                localReady.catch(() => { localReady = null; });
            }
            return localReady;
        }

        // Секретный ключ ML-KEM восстанавливается из 64-байтового seed
        // детерминированно; держим пару последних в памяти.
        const pqSecretCache = new Map();
        async function pqSecretKey(seedB64) {
            let sk = pqSecretCache.get(seedB64);
            if (!sk) {
                sk = (await getKem().keygen(b64decode(seedB64))).secretKey;
                if (pqSecretCache.size >= 4) pqSecretCache.delete(pqSecretCache.keys().next().value);
                pqSecretCache.set(seedB64, sk);
            }
            return sk;
        }

        // Создание и ротация SPK и PQ-prekey. Старый приватный ключ уходит в
        // spkOld:/pqpkOld: и живёт ещё 14 дней — x3dh-init, собранные по
        // bundle до ротации, должны расшифроваться.
        async function maintainPrekeysLocked(identity) {
            const t = now();
            let spk = await loadSpkLocked();
            if (spk && t - spk.createdAt >= PREKEY_ROTATE_MS) {
                await storage.set('spkOld:' + spk.keyId, { keyId: spk.keyId, priv: spk.priv, retiredAt: t });
                spk = null;
            }
            if (!spk) {
                const kp = await generateX25519();
                const keyId = await nextKeyId();
                const sig = await sign(identity.signPriv, kp.pub);
                spk = { keyId, pub: b64encode(kp.pub), priv: kp.priv, sig: b64encode(sig), createdAt: t };
                await storage.set('spk', spk);
            }

            let pq = await storage.get('pqpk');
            if (pq && t - pq.createdAt >= PREKEY_ROTATE_MS) {
                await storage.set('pqpkOld:' + pq.keyId, { keyId: pq.keyId, seed: pq.seed, retiredAt: t });
                pq = null;
            }
            if (!pq) {
                const seed = randomBytes(PQ_SEED_BYTES);
                const { publicKey } = await getKem().keygen(seed);
                if (!publicKey || publicKey.length !== PQ_PUBLIC_KEY_BYTES) throw new Error('E2EE: ML-KEM вернул ключ неверной длины');
                const keyId = await nextKeyId();
                const sig = await sign(identity.signPriv, publicKey);
                pq = { keyId, pub: b64encode(publicKey), seed: b64encode(seed), sig: b64encode(sig), createdAt: t };
                await storage.set('pqpk', pq);
            }

            for (const prefix of ['spkOld:', 'pqpkOld:']) {
                for (const name of await storage.keys(prefix)) {
                    const old = await storage.get(name);
                    if (!old || t - old.retiredAt > PREKEY_RETAIN_MS) await storage.delete(name);
                }
            }
        }

        async function putIdentity(identity) {
            const res = await transport.putIdentity({
                identity_signing_key: identity.signPub,
                identity_dh_key: identity.dhPub,
            });
            if (!res || !res.data || res.data.success !== true) {
                throw new Error('E2EE: не удалось зарегистрировать identity-ключи');
            }
        }

        // 409 от key-server значит "identity не зарегистрирован" (например,
        // его база была очищена) — регистрируем заново и повторяем.
        async function putWithIdentityRetry(doPut, identity, what) {
            let res = await doPut();
            if (res && res.status === 409) {
                await putIdentity(identity);
                res = await doPut();
            }
            if (!res || !res.data || res.data.success !== true) {
                throw new Error('E2EE: не удалось зарегистрировать ' + what);
            }
        }

        async function uploadKeysIfNeeded() {
            const { identity, spk, pq } = await withLock(async () => ({
                identity: await loadIdentityLocked(),
                spk: await storage.get('spk'),
                pq: await storage.get('pqpk'),
            }));
            const idTag = identity.signPub + ':' + identity.dhPub;
            if ((await storage.get('up:identity')) !== idTag) {
                // Новый identity (новая установка): ключи прошлой установки на
                // сервере бесполезны — их приватных частей больше нет. Особенно
                // OPK: сервер продолжал бы раздавать их инициаторам, и каждый
                // такой key-share был бы нерасшифровываем.
                if (typeof transport.deleteKeys === 'function') {
                    try { await transport.deleteKeys(); } catch { /* best effort */ }
                }
                await putIdentity(identity);
                await storage.set('up:identity', idTag);
                await storage.delete('up:spk');
                await storage.delete('up:pq');
            }
            if ((await storage.get('up:spk')) !== spk.keyId) {
                await putWithIdentityRetry(() => transport.putSignedPrekey({
                    key_id: spk.keyId, public_key: spk.pub, signature: spk.sig,
                }), identity, 'signed prekey');
                await storage.set('up:spk', spk.keyId);
            }
            if ((await storage.get('up:pq')) !== pq.keyId) {
                await putWithIdentityRetry(() => transport.putPqPrekey({
                    key_id: pq.keyId, public_key: pq.pub, signature: pq.sig,
                }), identity, 'PQ prekey');
                await storage.set('up:pq', pq.keyId);
            }
        }

        async function topUpOneTimePreKeysIfNeeded() {
            const countRes = await transport.getOneTimePrekeyCount();
            const count = countRes && countRes.data && typeof countRes.data.count === 'number' ? countRes.data.count : 0;
            if (count >= LOW_WATER_OPK) return;
            const keys = await withLock(async () => {
                const out = [];
                for (let i = 0; i < TOPUP_OPK - count; i++) {
                    const kp = await generateX25519();
                    const keyId = await nextKeyId();
                    await storage.set('opk:' + keyId, { pub: b64encode(kp.pub), priv: kp.priv });
                    out.push({ key_id: keyId, public_key: b64encode(kp.pub) });
                }
                return out;
            });
            if (keys.length > 0) await transport.postOneTimePrekeys({ keys });
        }

        // Инициализация: сгенерировать (или загрузить и мигрировать) ключи
        // устройства, ротировать просроченные SPK/PQ-prekey, загрузить
        // публичные части на сервер, пополнить пул OPK. Идемпотентна —
        // можно вызывать повторно (например, раз в сутки), чтобы ротация
        // срабатывала и без перезагрузки страницы.
        async function init() {
            await ensureLocal();
            const identity = await withLock(async () => {
                const id = await loadIdentityLocked();
                await maintainPrekeysLocked(id);
                return id;
            });
            await uploadKeysIfNeeded();
            await topUpOneTimePreKeysIfNeeded();
            return { identityPub: identity.dhPub, signPub: identity.signPub };
        }

        function setUserId(id) { userId = id; }

        // ---- Закрепление identity собеседников ----

        // Сверка identity, который сообщил сервер, с закреплённым.
        // Первый контакт — TOFU; несовпадение — status 'changed', новый
        // ключ ждёт в pending до acceptPeerIdentityChange().
        async function reconcilePinLocked(peerId, signPub, dhPub) {
            const name = 'peer:' + peerId;
            const pin = await storage.get(name);
            if (!pin) {
                await storage.set(name, { signPub, dhPub, verified: false, firstSeenAt: now() });
                return 'unverified';
            }
            if (pin.signPub === signPub && pin.dhPub === dhPub) {
                if (pin.pending) {
                    // Сервер снова отдаёт закреплённый ключ — "смена"
                    // отменена; закреплённому ключу мы и так доверяли.
                    delete pin.pending;
                    await storage.set(name, pin);
                }
                return identityStatus(pin);
            }
            if (!pin.pending || pin.pending.signPub !== signPub || pin.pending.dhPub !== dhPub) {
                pin.pending = { signPub, dhPub, seenAt: now() };
                await storage.set(name, pin);
            }
            return 'changed';
        }

        // Map userId → { signPub, dhPub } по данным сервера или null, если
        // узнать не удалось (сеть, старый сервер без /api/keys/identities).
        async function fetchServerIdentities(ids) {
            if (typeof transport.getIdentities !== 'function' || ids.length === 0) return null;
            const out = new Map();
            for (let i = 0; i < ids.length; i += 200) {
                const chunk = ids.slice(i, i + 200);
                let res;
                try { res = await transport.getIdentities(chunk); } catch { return null; }
                if (!res || !res.data || res.data.success !== true || !Array.isArray(res.data.identities)) return null;
                for (const item of res.data.identities) {
                    const id = Number(item && item.user_id);
                    if (!chunk.includes(id)) continue;
                    const signPub = canonicalPubKey(item.identity_signing_key);
                    const dhPub = canonicalPubKey(item.identity_dh_key);
                    if (signPub && dhPub) out.set(id, { signPub, dhPub });
                }
            }
            return out;
        }

        // Сверка закреплённых ключей с сервером. serverKnown — множество id, у
        // которых identity на сервере есть, или null, если сервер не ответил
        // (тогда "ключей нет" и "не удалось узнать" неразличимы).
        async function checkPeersWithServer(userIds) {
            await ensureLocal();
            const me = Number(userId);
            const ids = normalizeIds(userIds).filter(id => id !== me);
            const server = await fetchServerIdentities(ids);
            const statuses = await withLock(async () => {
                const out = [];
                for (const id of ids) {
                    const s = server && server.get(id);
                    const status = s
                        ? await reconcilePinLocked(id, s.signPub, s.dhPub)
                        : identityStatus(await storage.get('peer:' + id));
                    out.push({ userId: id, status });
                }
                return out;
            });
            return { statuses, serverKnown: server ? new Set(server.keys()) : null };
        }

        async function checkPeerIdentities(userIds) {
            return (await checkPeersWithServer(userIds)).statuses;
        }

        async function getPeerIdentityStatus(peerId) {
            return identityStatus(await storage.get('peer:' + Number(peerId)));
        }

        // Пользователь сверил код безопасности. Для собеседника со
        // сменившимся (не подтверждённым) ключом отметка не ставится.
        async function markPeerVerified(peerId) {
            await ensureLocal();
            return withLock(async () => {
                const name = 'peer:' + Number(peerId);
                const pin = await storage.get(name);
                if (!pin || pin.pending) return false;
                pin.verified = true;
                await storage.set(name, pin);
                return true;
            });
        }

        // Код безопасности для закреплённого (не pending) ключа собеседника.
        async function getSafetyNumber(peerId) {
            await ensureLocal();
            const id = Number(peerId);
            if (!Number.isSafeInteger(id) || id <= 0 || id === Number(userId)) return null;
            const identity = await storage.get('identity');
            const pin = await storage.get('peer:' + id);
            if (!identity || !pin) return null;
            return computeSafetyNumber(Number(userId), identity.signPub, identity.dhPub, id, pin.signPub, pin.dhPub);
        }

        // Пользователь принял новый ключ собеседника: он становится
        // закреплённым (не проверенным), старые попарные сессии и отметки
        // "ключ комнаты уже отправлен" для него сбрасываются — при следующем
        // ensureRoomSession ключи уйдут к нему заново. Отложенные key-share
        // от него обрабатываются сразу.
        async function acceptPeerIdentityChange(peerId) {
            await ensureLocal();
            const id = Number(peerId);
            const queued = await withLock(async () => {
                const name = 'peer:' + id;
                const pin = await storage.get(name);
                if (!pin || !pin.pending) return null;
                await storage.set(name, {
                    signPub: pin.pending.signPub,
                    dhPub: pin.pending.dhPub,
                    verified: false,
                    firstSeenAt: pin.pending.seenAt || now(),
                });
                await storage.delete('pw2Send:' + id);
                await storage.delete('pw2Recv:' + id);
                for (const name of await storage.keys('sharedWith2:')) {
                    if (name.split(':')[3] === String(id)) await storage.delete(name);
                }
                const list = (await storage.get('pendingShares:' + id)) || [];
                await storage.delete('pendingShares:' + id);
                return list;
            });
            if (!queued) return false;
            for (const item of queued) {
                try { await applyShare(item.roomId, id, item.ciphertext); } catch { /* битый отложенный share просто пропускаем */ }
            }
            return true;
        }

        // ---- Попарный канал: я — отправитель key-share ----

        function sessionMatchesPin(session, pin) {
            return Boolean(session && pin && !pin.pending
                && session.peerSignPub === pin.signPub && session.peerDhPub === pin.dhPub);
        }

        async function fetchBundle(peerId) {
            let res;
            try { res = await transport.getBundle(peerId); } catch { return { error: 'не удалось получить ключи собеседника' }; }
            if (!res) return { error: 'не удалось получить ключи собеседника' };
            if (res.status === 404) return { error: REASON_NOT_READY };
            if (res.status === 403) return { error: (res.data && res.data.message) || 'нет общего чата с пользователем' };
            if (res.status === 429) return { error: (res.data && res.data.message) || 'слишком много запросов ключей — попробуйте позже' };
            if (res.status >= 500) return { error: 'сервер ключей недоступен' };
            if (!res.data || !res.data.identity_dh_key) return { error: REASON_NOT_READY };
            return { bundle: res.data };
        }

        // PQXDH со стороны инициатора. Возвращает { session } | { changed } | { error }.
        async function startSendSessionLocked(identity, peerId, bundle) {
            const signPub = canonicalPubKey(bundle.identity_signing_key);
            const dhPub = canonicalPubKey(bundle.identity_dh_key);
            if (!signPub || !dhPub) return { error: 'некорректные identity-ключи собеседника' };

            // Bundle обязан совпасть с закреплённым identity: иначе сервер мог
            // бы подсунуть свой bundle (MITM) — раньше это проходило молча.
            const pinName = 'peer:' + peerId;
            const pin = await storage.get(pinName);
            if (pin && pin.pending) return { changed: true };
            if (pin && (pin.signPub !== signPub || pin.dhPub !== dhPub)) {
                await reconcilePinLocked(peerId, signPub, dhPub);
                return { changed: true };
            }

            // Критическая проверка: подпись Signed PreKey СВОИМ identity-
            // ключом пира. Сервер ключей эту подпись при загрузке тоже
            // проверяет, но полагаться только на это нельзя.
            const spkInfo = bundle.signed_prekey || {};
            const spkPub = decodeFixed(spkInfo.public_key, 32);
            const spkSig = decodeFixed(spkInfo.signature, 64);
            if (!spkPub || !spkSig || !isKeyId(spkInfo.key_id)) return { error: 'некорректный Signed PreKey собеседника' };
            if (!(await verify(b64decode(signPub), spkSig, spkPub))) {
                return { error: 'неверная подпись Signed PreKey у пользователя ' + peerId + ' — возможная подмена ключа' };
            }

            // Без PQ-prekey не откатываемся на классический X3DH: иначе
            // сервер, просто убрав его из bundle, понижал бы защиту.
            const pqInfo = bundle.pq_prekey;
            if (!pqInfo) return { error: REASON_OUTDATED };
            const pqPub = decodeFixed(pqInfo.public_key, PQ_PUBLIC_KEY_BYTES);
            const pqSig = decodeFixed(pqInfo.signature, 64);
            if (!pqPub || !pqSig || !isKeyId(pqInfo.key_id)) return { error: 'некорректный PQ-prekey собеседника' };
            if (!(await verify(b64decode(signPub), pqSig, pqPub))) {
                return { error: 'неверная подпись PQ-prekey у пользователя ' + peerId + ' — возможная подмена ключа' };
            }

            const otpk = bundle.one_time_prekey || null;
            let otpkPub = null;
            if (otpk) {
                otpkPub = decodeFixed(otpk.public_key, 32);
                if (!otpkPub || !isKeyId(otpk.key_id)) return { error: 'некорректный one-time prekey собеседника' };
            }

            let pqResult;
            try {
                pqResult = await getKem().encapsulate(pqPub);
            } catch {
                return { error: 'некорректный PQ-prekey собеседника' };
            }
            const pqCiphertext = pqResult && pqResult.ciphertext;
            const pqShared = pqResult && pqResult.sharedSecret;
            if (!pqCiphertext || pqCiphertext.length !== PQ_CIPHERTEXT_BYTES || !pqShared || pqShared.length !== 32) {
                return { error: 'ошибка ML-KEM' };
            }

            let sk;
            const eph = await generateX25519();
            try {
                const dh1 = await dh(identity.dhPriv, spkPub);
                const dh2 = await dh(eph.priv, b64decode(dhPub));
                const dh3 = await dh(eph.priv, spkPub);
                const dh4 = otpkPub ? await dh(eph.priv, otpkPub) : new Uint8Array(0);
                sk = await hkdf(concatBytes(FF32, dh1, dh2, dh3, dh4, pqShared), ZERO32, 'nyxo-e2ee-pqxdh-v1', 32);
            } catch (err) {
                return { error: err.message };
            }

            if (!pin) await storage.set(pinName, { signPub, dhPub, verified: false, firstSeenAt: now() });
            const session = {
                ck: b64encode(await hkdf(sk, ZERO32, 'nyxo-e2ee-pw-chain-v2', 32)),
                n: 0,
                header: {
                    type: 'x3dh-init',
                    senderIdentityDhPub: identity.dhPub,
                    senderIdentitySignPub: identity.signPub,
                    senderEphemeralPub: b64encode(eph.pub),
                    usedSignedPrekeyId: spkInfo.key_id,
                    usedOneTimePrekeyId: otpk ? otpk.key_id : null,
                    pqCiphertext: b64encode(pqCiphertext),
                    usedPqPrekeyId: pqInfo.key_id,
                },
                peerSignPub: signPub,
                peerDhPub: dhPub,
                createdAt: now(),
            };
            await storage.set('pw2Send:' + peerId, session);
            return { session };
        }

        // Готовит key-share моего текущего Sender Key для одного участника.
        // Возвращает { share, senderKeyId } | { changed:true } | { warning }.
        async function prepareShareForPeer(roomId, peerId) {
            const pre = await withLock(async () => {
                const pin = await storage.get('peer:' + peerId);
                if (pin && pin.pending) return { changed: true };
                const session = await storage.get('pw2Send:' + peerId);
                return { fresh: sessionMatchesPin(session, pin) && now() - session.createdAt < PAIRWISE_SESSION_MAX_AGE_MS };
            });
            if (pre.changed) return { changed: true };

            // Сессия старше 7 дней перезапускается новым PQXDH (свежий
            // эфемерный ключ и свежий prekey собеседника).
            let fetched = null;
            if (!pre.fresh) fetched = await fetchBundle(peerId);

            return withLock(async () => {
                const identity = await loadIdentityLocked();
                let session = null;
                let bundleError = null;
                if (fetched && fetched.bundle) {
                    const started = await startSendSessionLocked(identity, peerId, fetched.bundle);
                    if (started.changed) return { changed: true };
                    if (started.error) bundleError = started.error;
                    else session = started.session;
                } else if (fetched) {
                    bundleError = fetched.error;
                }

                const pin = await storage.get('peer:' + peerId);
                if (pin && pin.pending) return { changed: true };
                if (!session) {
                    // Новую сессию начать не удалось (лимит запросов, нет
                    // PQ-prekey, битый bundle) — старая, заведённая по PQXDH с
                    // закреплённым identity, по-прежнему безопасна.
                    const old = await storage.get('pw2Send:' + peerId);
                    if (!sessionMatchesPin(old, pin)) return { warning: bundleError || REASON_NOT_READY };
                    session = old;
                }

                const own = await loadOwnSenderKeyLocked(roomId);
                if (!own) return { warning: 'нет ключа комнаты' };

                const { messageKey, nextChainKey } = await chainStep(b64decode(session.ck));
                const n = session.n;
                session.ck = b64encode(nextChainKey);
                session.n = n + 1;
                await storage.set('pw2Send:' + peerId, session);

                const skdm = {
                    v: 2, type: 'skdm', roomId,
                    senderKeyId: own.senderKeyId,
                    chainKey: own.chainKey,
                    iteration: own.nextIteration,
                    signingPublicKey: own.signingPublicKey,
                };
                const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-skdm-v2', 32);
                const aad = skdmAadV2(roomId, userId, peerId, identity.signPub, identity.dhPub, session.peerSignPub, session.peerDhPub);
                const { iv, ct } = await aesGcmEncrypt(aesKey, utf8encode(JSON.stringify(skdm)), aad);
                const ciphertext = JSON.stringify({ v: 2, type: 'skdm', n, iv: b64encode(iv), ct: b64encode(ct), init: session.header });
                // Размер фиксирован структурой (~2,3 тыс. символов, основная
                // часть — pqCiphertext); проверка — страховка от регрессий.
                if (ciphertext.length > MAX_SHARE_CHARS) return { warning: 'key-share превышает допустимый размер' };
                return {
                    share: { recipientUserId: peerId, ciphertext },
                    senderKeyId: own.senderKeyId,
                };
            });
        }

        // ---- Попарный канал: я — получатель key-share ----

        // PQXDH со стороны получателя; null, если нужный prekey уже удалён
        // или вычисление не удалось.
        async function deriveRecvSecretLocked(identity, h) {
            const t = now();
            try {
                let spkPriv = null;
                const spk = await loadSpkLocked();
                if (spk && spk.keyId === h.spkId) {
                    spkPriv = spk.priv;
                } else {
                    const old = await storage.get('spkOld:' + h.spkId);
                    if (old && t - old.retiredAt <= PREKEY_RETAIN_MS) spkPriv = await toPrivateKey(old.priv, 'X25519', ['deriveBits']);
                }
                if (!spkPriv) return null; // SPK давно ротирован — расшифровать нечем

                let pqSeed = null;
                const pq = await storage.get('pqpk');
                if (pq && pq.keyId === h.pqId) {
                    pqSeed = pq.seed;
                } else {
                    const old = await storage.get('pqpkOld:' + h.pqId);
                    if (old && t - old.retiredAt <= PREKEY_RETAIN_MS) pqSeed = old.seed;
                }
                if (!pqSeed) return null;

                let opkPriv = null;
                if (h.opkId !== null) {
                    // Раньше отсутствующий OPK молча пропускался, и ключ
                    // расходился с отправителем; теперь это явная ошибка.
                    const opk = await loadOpkLocked(h.opkId);
                    if (!opk) return null;
                    opkPriv = opk.priv;
                }

                const senderDh = b64decode(h.dhPub);
                const eph = b64decode(h.eph);
                const dh1 = await dh(spkPriv, senderDh);
                const dh2 = await dh(identity.dhPriv, eph);
                const dh3 = await dh(spkPriv, eph);
                const dh4 = opkPriv ? await dh(opkPriv, eph) : new Uint8Array(0);
                // Неверный шифротекст ML-KEM правильной длины не бросает
                // (implicit rejection) — ошибка проявится на AEAD.
                const ss = toBytes(await getKem().decapsulate(await pqSecretKey(pqSeed), h.pqCt));
                if (ss.length !== 32) return null;
                return await hkdf(concatBytes(FF32, dh1, dh2, dh3, dh4, ss), ZERO32, 'nyxo-e2ee-pqxdh-v1', 32);
            } catch {
                return null;
            }
        }

        // Расшифровывает key-share, ничего не сохраняя: состояние
        // коммитится только после успешной проверки AEAD, иначе поддельный
        // share мог бы сжечь OPK или сбить сессию.
        async function openShareLocked(roomId, senderId, env, identity) {
            const h = env.init;
            const current = await storage.get('pw2Recv:' + senderId);
            let session;
            let isNew = false;
            if (current && current.eph === h.eph && current.peerSignPub === h.signPub && current.peerDhPub === h.dhPub) {
                session = current;
            } else {
                // Эфемерный ключ уже встречался, но это не текущая сессия —
                // повтор старой сессии (например, чтобы откатить ключ).
                const seen = (await storage.get('pw2Seen:' + senderId)) || [];
                if (seen.includes(h.eph)) return null;
                const sk = await deriveRecvSecretLocked(identity, h);
                if (!sk) return null;
                session = {
                    eph: h.eph,
                    ck: b64encode(await hkdf(sk, ZERO32, 'nyxo-e2ee-pw-chain-v2', 32)),
                    n: 0,
                    skipped: {},
                    peerSignPub: h.signPub,
                    peerDhPub: h.dhPub,
                    createdAt: now(),
                };
                isNew = true;
            }

            const messageKey = await takePairwiseKey(session, env.n);
            if (!messageKey) return null;
            const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-skdm-v2', 32);
            const aad = skdmAadV2(roomId, senderId, userId, h.signPub, h.dhPub, identity.signPub, identity.dhPub);
            let pt;
            try { pt = await aesGcmDecrypt(aesKey, env.iv, env.ct, aad); } catch { return null; }
            const skdm = parseSkdm(pt, roomId);
            if (!skdm) return null;

            return {
                skdm,
                async commit() {
                    await storage.set('pw2Recv:' + senderId, session);
                    if (isNew) {
                        const seen = (await storage.get('pw2Seen:' + senderId)) || [];
                        seen.push(h.eph);
                        if (seen.length > MAX_SEEN_EPHEMERAL) seen.splice(0, seen.length - MAX_SEEN_EPHEMERAL);
                        await storage.set('pw2Seen:' + senderId, seen);
                        if (h.opkId !== null) await storage.delete('opk:' + h.opkId); // одноразовый — использован
                    }
                },
            };
        }

        async function dropSeenTablesLocked(roomId, senderId, senderKeyIds) {
            for (const id of senderKeyIds) await storage.delete('seen:' + roomId + ':' + senderId + ':' + id);
        }

        // order = { eph, n } — позиция key-share в попарной сессии.
        async function installSenderKeyLocked(roomId, senderId, skdm, order) {
            const name = 'senderKey:' + roomId + ':' + senderId;
            const existing = await storage.get(name);
            if (existing && existing.senderKeyId === skdm.senderKeyId) return; // уже есть, не откатываем состояние
            // Ключ, который уже был заменён ротацией, обратно не ставим: иначе
            // повтор старого key-share возвращал бы в оборот старый ключ.
            if (existing && (existing.archived || []).some(a => a.senderKeyId === skdm.senderKeyId)) return;
            // Более ранняя передача той же сессии, пришедшая позже более
            // поздней, несёт более старый ключ — текущий ею не заменяем.
            if (existing && existing.installedBy && existing.installedBy.eph === order.eph && order.n < existing.installedBy.n) return;
            let dropped = [];
            if (existing) dropped = archiveIfRotated(existing, skdm.senderKeyId, true);
            await storage.set(name, {
                senderKeyId: skdm.senderKeyId,
                signingPublicKey: skdm.signingPublicKey,
                chainKey: skdm.chainKey,
                nextIteration: skdm.iteration,
                cachedKeys: {},
                archived: existing ? existing.archived : [],
                installedBy: { eph: order.eph, n: order.n },
            });
            await dropSeenTablesLocked(roomId, senderId, dropped);
        }

        async function queuePendingShareLocked(senderId, roomId, ciphertext) {
            const name = 'pendingShares:' + senderId;
            const list = (await storage.get(name)) || [];
            if (list.some(item => item.ciphertext === ciphertext)) return;
            list.push({ roomId, ciphertext, receivedAt: now() });
            if (list.length > MAX_PENDING_SHARES) list.splice(0, list.length - MAX_PENDING_SHARES);
            await storage.set(name, list);
        }

        // Обрабатывает один key-share → 'applied' | 'failed' | 'changed'.
        async function applyShare(roomId, senderId, ciphertext) {
            const me = Number(userId);
            if (!Number.isSafeInteger(senderId) || senderId <= 0 || senderId === me) return 'failed';
            if (typeof ciphertext !== 'string') return 'failed';
            const env = parseShareEnvelope(ciphertext);
            if (!env) return 'failed';
            const h = env.init;

            // identity из заголовка на слово не принимается: он должен
            // совпасть с закреплённым, а если закрепления нет — с тем, что
            // сервер отдаёт как identity отправителя (запрос — вне очереди).
            const pinBefore = await storage.get('peer:' + senderId);
            let serverIdentity = null;
            const matchesPin = pinBefore && !pinBefore.pending && pinBefore.signPub === h.signPub && pinBefore.dhPub === h.dhPub;
            if (!matchesPin && !(pinBefore && pinBefore.pending)) {
                const map = await fetchServerIdentities([senderId]);
                serverIdentity = map ? map.get(senderId) || null : null;
            }
            const serverMatches = Boolean(serverIdentity && serverIdentity.signPub === h.signPub && serverIdentity.dhPub === h.dhPub);

            return withLock(async () => {
                const identity = await loadIdentityLocked();
                const pin = await storage.get('peer:' + senderId);
                if (pin && pin.pending) {
                    // Смена identity ещё не подтверждена: x3dh-init от нового
                    // ключа откладываем до acceptPeerIdentityChange, прочие
                    // отбрасываем.
                    if (pin.pending.signPub === h.signPub && pin.pending.dhPub === h.dhPub) {
                        await queuePendingShareLocked(senderId, roomId, ciphertext);
                        return 'changed';
                    }
                    return 'failed';
                }
                if (pin && (pin.signPub !== h.signPub || pin.dhPub !== h.dhPub)) {
                    if (serverMatches) {
                        await reconcilePinLocked(senderId, h.signPub, h.dhPub);
                        await queuePendingShareLocked(senderId, roomId, ciphertext);
                        return 'changed';
                    }
                    return 'failed'; // чужой identity, сервер его не подтверждает — подделка
                }
                if (!pin && !serverMatches) return 'failed';

                const opened = await openShareLocked(roomId, senderId, env, identity);
                if (!opened) return 'failed';
                if (!pin) await storage.set('peer:' + senderId, { signPub: h.signPub, dhPub: h.dhPub, verified: false, firstSeenAt: now() });
                await opened.commit();
                await installSenderKeyLocked(roomId, senderId, opened.skdm, { eph: h.eph, n: env.n });
                return 'applied';
            });
        }

        // ---- Sender Key: моё состояние в комнате ----

        async function newOwnSenderKeyState(archived) {
            const signKp = await generateEd25519();
            return {
                senderKeyId: b64encode(randomBytes(16)),
                signingPublicKey: b64encode(signKp.pub),
                signingPrivateKey: signKp.priv,
                chainKey: b64encode(randomBytes(32)),
                nextIteration: 0,
                cachedKeys: {},
                archived: archived || [],
            };
        }

        // Ротация собственного Sender Key: новый chainKey и новая
        // подписывающая пара, старое состояние архивируется, чтобы уже
        // отправленные сообщения остались читаемыми для нас самих.
        async function rotateRoomKeyLocked(roomId) {
            const existing = await loadOwnSenderKeyLocked(roomId);
            const next = await newOwnSenderKeyState(existing ? existing.archived || [] : []);
            if (existing) {
                const dropped = archiveIfRotated(existing, next.senderKeyId, false);
                next.archived = existing.archived;
                await dropSeenTablesLocked(roomId, userId, dropped);
                // Отметки рассылки старого ключа больше ни к чему.
                for (const name of await storage.keys('sharedWith2:' + roomId + ':' + existing.senderKeyId + ':')) {
                    await storage.delete(name);
                }
            }
            await storage.set(ownKeyName(roomId), next);
            return next;
        }

        // После ротации нужно вызвать ensureRoomSession, чтобы разослать
        // новый ключ, — и сделать это ДО отправки сообщений новым ключом:
        // key-share несёт текущую позицию цепочки, более ранние итерации
        // получатели вывести не смогут.
        async function rotateRoomKey(roomId) {
            await ensureLocal();
            const next = await withLock(() => rotateRoomKeyLocked(roomId));
            return { senderKeyId: next.senderKeyId };
        }

        async function hasRoomKey(roomId) {
            return Boolean(await storage.get(ownKeyName(roomId)));
        }

        function sharedMarkName(roomId, senderKeyId, peerId) {
            return 'sharedWith2:' + roomId + ':' + senderKeyId + ':' + peerId;
        }

        // Устанавливает/подтверждает мой Sender Key для комнаты, сверяет
        // состав комнаты с запомненным и рассылает ключ тем, кому текущая
        // версия ещё не отправлена.
        async function ensureRoomSession(chatId, roomId, participants) {
            await ensureLocal();
            const me = Number(userId);
            const current = normalizeParticipants(participants);
            const empty = { newMembers: [], removedMembers: [], rotated: false, identityChanges: [] };
            if (!current.some(p => p.id === me)) {
                return Object.assign({ ok: false, warnings: [{ reason: 'вы не участник этой комнаты' }] }, empty);
            }

            const membership = await withLock(async () => {
                let own = await loadOwnSenderKeyLocked(roomId);
                let rotated = false;
                if (!own) {
                    own = await newOwnSenderKeyState([]);
                    await storage.set(ownKeyName(roomId), own);
                } else if (!own.signingPrivateKey) {
                    // Состояние из очень старой версии без ключа подписи.
                    await rotateRoomKeyLocked(roomId);
                    rotated = true;
                }
                const known = await storage.get('members:' + roomId);
                let newMembers = [];
                let removedMembers = [];
                // Первый вызов для комнаты только запоминает состав: сравнивать
                // не с чем, и "новыми" оказались бы все.
                if (Array.isArray(known)) {
                    const knownIds = new Set(known.map(p => Number(p.id)));
                    const currentIds = new Set(current.map(p => p.id));
                    newMembers = current.filter(p => p.id !== me && !knownIds.has(p.id));
                    removedMembers = known
                        .filter(p => Number(p.id) !== me && !currentIds.has(Number(p.id)))
                        .map(p => ({ id: Number(p.id), username: typeof p.username === 'string' ? p.username : '' }));
                    // Ушедший участник знает текущий ключ цепочки и мог бы
                    // читать всё будущее — ротируем до рассылки, так что
                    // новый ключ он не получит.
                    if (removedMembers.length > 0 && !rotated) {
                        await rotateRoomKeyLocked(roomId);
                        rotated = true;
                    }
                }
                await storage.set('members:' + roomId, current);
                return { newMembers, removedMembers, rotated };
            });

            const others = current.filter(p => p.id !== me);
            const { statuses, serverKnown } = await checkPeersWithServer(others.map(p => p.id));
            const changedIds = new Set(statuses.filter(s => s.status === 'changed').map(s => s.userId));

            const warnings = [];
            const identityChanges = [];
            const shares = [];
            const marks = [];
            const noteChanged = (peer) => {
                identityChanges.push({ userId: peer.id, username: peer.username });
                warnings.push({ userId: peer.id, reason: REASON_IDENTITY_CHANGED });
            };

            for (const peer of others) {
                if (changedIds.has(peer.id)) { noteChanged(peer); continue; }
                // У собеседника нет identity на сервере — bundle заведомо 404.
                // Не запрашиваем его: каждый запрос bundle расходует лимит на
                // пару (5 в час), и после нескольких открытий комнаты ключ не
                // ушёл бы даже тогда, когда собеседник E2EE настроит.
                if (serverKnown && !serverKnown.has(peer.id)) {
                    warnings.push({ userId: peer.id, reason: REASON_NOT_READY });
                    continue;
                }
                const own = await storage.get(ownKeyName(roomId));
                if (own && await storage.get(sharedMarkName(roomId, own.senderKeyId, peer.id))) continue;
                let prepared;
                try {
                    prepared = await prepareShareForPeer(roomId, peer.id);
                } catch (err) {
                    warnings.push({ userId: peer.id, reason: err.message });
                    continue;
                }
                if (prepared.changed) { noteChanged(peer); continue; }
                if (prepared.warning) { warnings.push({ userId: peer.id, reason: prepared.warning }); continue; }
                shares.push(prepared.share);
                marks.push(sharedMarkName(roomId, prepared.senderKeyId, peer.id));
            }

            let ok = true;
            for (let i = 0; i < shares.length; i += SHARE_BATCH) {
                let res = null;
                try { res = await transport.postKeyShares(chatId, shares.slice(i, i + SHARE_BATCH)); } catch { res = null; }
                if (!res || !res.data || res.data.success !== true) {
                    ok = false;
                    warnings.push({ reason: 'сервер отклонил отправку key-share' });
                    continue;
                }
                // Отметка ставится только после того, как сервер принял
                // share, — иначе при сбое ключ так и не ушёл бы повторно.
                const done = marks.slice(i, i + SHARE_BATCH);
                await withLock(async () => { for (const name of done) await storage.set(name, true); });
            }

            return {
                ok, warnings,
                newMembers: membership.newMembers,
                removedMembers: membership.removedMembers,
                rotated: membership.rotated,
                identityChanges,
            };
        }

        // Забирает и применяет ожидающие key-share для этого чата.
        async function syncKeyShares(chatId, roomId) {
            await ensureLocal();
            const res = await transport.getKeyShares(chatId);
            const list = res && res.data && Array.isArray(res.data.shares) ? res.data.shares : [];
            let applied = 0, failed = 0;
            const changes = [];
            for (const item of list) {
                const senderId = Number(item && item.senderId);
                let result;
                try { result = await applyShare(roomId, senderId, item && item.ciphertext); } catch { result = 'failed'; }
                if (result === 'applied') applied++;
                else if (result === 'changed') { if (!changes.includes(senderId)) changes.push(senderId); }
                else failed++;
            }
            return { applied, failed, identityChanges: changes };
        }

        // ---- Шифрование/расшифровка сообщений чата ----

        async function encryptOutgoing(roomId, content) {
            await ensureLocal();
            const padded = padMessage(utf8encode(JSON.stringify(encodeContent(content))));
            const { state, iteration, messageKey } = await withLock(async () => {
                const st = await loadOwnSenderKeyLocked(roomId);
                if (!st) throw new Error('E2EE: для этой комнаты ещё не создан Sender Key — вызовите ensureRoomSession()');
                if (!st.signingPrivateKey) throw new Error('E2EE: ключ комнаты устарел — вызовите ensureRoomSession()');
                const it = st.nextIteration;
                const step = await chainStep(b64decode(st.chainKey));
                st.cachedKeys[it] = b64encode(step.messageKey); // сохраняем и для собственного отображения истории
                st.chainKey = b64encode(step.nextChainKey);
                st.nextIteration = it + 1;
                trimCache(st);
                await storage.set(ownKeyName(roomId), st);
                return { state: st, iteration: it, messageKey: step.messageKey };
            });

            const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-msgkey-v2', 32);
            const { iv, ct } = await aesGcmEncrypt(aesKey, padded, msgAadV2(roomId, userId, state.senderKeyId));
            const sig = await sign(state.signingPrivateKey, sigInputV2(iv, ct, iteration, state.senderKeyId));
            const envelope = JSON.stringify({
                v: 2, alg: 'senderkey-v2',
                senderKeyId: state.senderKeyId,
                iteration,
                iv: b64encode(iv), ct: b64encode(ct),
                sig: b64encode(sig),
            });
            if (envelope.length > MAX_ENVELOPE_CHARS) throw new Error('E2EE: сообщение слишком длинное для шифрования');
            return envelope;
        }

        // messageId (id сообщения на сервере) нужен для защиты от повтора:
        // пара (senderKeyId, iteration) привязывается к первому messageId, с
        // которым её расшифровали, и под другим id конверт не принимается.
        // Правка — новая итерация для того же messageId, это легально.
        async function decryptIncoming(roomId, senderId, text, messageId) {
            const bad = { ok: false, reason: 'bad-envelope' };
            let envelope;
            try { envelope = JSON.parse(text); } catch { return bad; }
            if (!envelope || typeof envelope !== 'object') return bad;
            let version;
            if (envelope.v === 2 && envelope.alg === 'senderkey-v2') version = 2;
            else if (envelope.alg === 'senderkey-v1') version = 1;
            else return bad;
            if (!Number.isInteger(envelope.iteration) || envelope.iteration < 0 || envelope.iteration > 0xFFFFFFFF) return bad;
            if (typeof envelope.senderKeyId !== 'string' || !envelope.senderKeyId) return bad;
            const boundId = messageId === undefined || messageId === null ? null : String(messageId);

            await ensureLocal();
            return withLock(async () => {
                const stateName = 'senderKey:' + roomId + ':' + senderId;
                const state = await storage.get(stateName);
                if (!state) return { ok: false, reason: 'no-sender-key' };

                const iv = decodeFixed(envelope.iv, 12);
                const sig = decodeFixed(envelope.sig, 64);
                const ct = typeof envelope.ct === 'string' ? b64decode(envelope.ct) : null;
                if (!iv || !sig || !ct || ct.length < 16) return bad;
                const iteration = envelope.iteration;
                const sigInput = version === 2
                    ? sigInputV2(iv, ct, iteration, envelope.senderKeyId)
                    : sigInputV1(iv, ct, iteration);

                const seenName = 'seen:' + roomId + ':' + senderId + ':' + envelope.senderKeyId;
                const seen = (await storage.get(seenName)) || {};
                const bound = Object.prototype.hasOwnProperty.call(seen, iteration) ? seen[iteration] : undefined;

                let messageKey;
                if (state.senderKeyId === envelope.senderKeyId) {
                    if (!(await verify(b64decode(state.signingPublicKey), sig, sigInput))) return { ok: false, reason: 'bad-signature' };
                    if (iteration - state.nextIteration > MAX_SKIP) return { ok: false, reason: 'too-far-ahead' };
                    if (boundId !== null && bound !== undefined && bound !== boundId) return { ok: false, reason: 'replay' };
                    // Цепочка продвигается (и состояние сохраняется) только для
                    // новых итераций — при простом повторном показе истории
                    // хранилище не переписывается.
                    const advances = iteration >= state.nextIteration;
                    messageKey = await getOrDeriveMessageKey(state, iteration);
                    if (advances) await storage.set(stateName, state);
                } else {
                    // Не текущий ключ отправителя — возможно, сообщение
                    // отправлено ДО его ротации: ищем среди архивных состояний
                    // (см. archiveIfRotated). Если позиция цепочки архивного
                    // ключа сохранена, ещё не открытые итерации выводятся с тем
                    // же пределом MAX_SKIP; иначе — только закэшированные.
                    const archived = (state.archived || []).find(a => a.senderKeyId === envelope.senderKeyId);
                    if (!archived) return { ok: false, reason: 'stale-sender-key' };
                    if (!(await verify(b64decode(archived.signingPublicKey), sig, sigInput))) return { ok: false, reason: 'bad-signature' };
                    if (boundId !== null && bound !== undefined && bound !== boundId) return { ok: false, reason: 'replay' };
                    if (archived.chainKey && Number.isInteger(archived.nextIteration)) {
                        if (iteration - archived.nextIteration > MAX_SKIP) return { ok: false, reason: 'too-far-ahead' };
                        const advances = iteration >= archived.nextIteration;
                        messageKey = await getOrDeriveMessageKey(archived, iteration);
                        if (advances) await storage.set(stateName, state);
                    } else {
                        const cached = archived.cachedKeys[iteration];
                        messageKey = cached ? b64decode(cached) : null;
                    }
                }
                if (!messageKey) return { ok: false, reason: 'no-message-key' };

                let result;
                try {
                    if (version === 2) {
                        const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-msgkey-v2', 32);
                        const pt = await aesGcmDecrypt(aesKey, iv, ct, msgAadV2(roomId, senderId, envelope.senderKeyId));
                        const body = unpadMessage(pt);
                        let decoded = null;
                        if (body) {
                            try { decoded = decodeContent(JSON.parse(utf8decode(body))); } catch { decoded = null; }
                        }
                        if (!decoded) return { ok: false, reason: 'bad-plaintext' };
                        result = decoded.file
                            ? { ok: true, text: decoded.text, file: decoded.file }
                            : { ok: true, text: decoded.text };
                    } else {
                        const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-msgkey-v1', 32);
                        const pt = await aesGcmDecrypt(aesKey, iv, ct, msgAadV1(roomId, senderId, envelope.senderKeyId));
                        result = { ok: true, text: utf8decode(pt) };
                    }
                } catch {
                    return { ok: false, reason: 'decrypt-failed' };
                }

                if (boundId !== null && bound === undefined) {
                    seen[iteration] = boundId;
                    trimNumericMap(seen, MAX_SEEN_PER_KEY);
                    await storage.set(seenName, seen);
                }
                return result;
            });
        }

        return {
            init, setUserId,
            ensureRoomSession, syncKeyShares, hasRoomKey, rotateRoomKey,
            encryptOutgoing, decryptIncoming,
            encryptFile, decryptFile,
            checkPeerIdentities, getPeerIdentityStatus, getSafetyNumber,
            markPeerVerified, acceptPeerIdentityChange,
        };
    }

    return {
        createClient,
        MemoryStorage,
        makeIndexedDbStorage,
        makeFetchTransport,
        deleteLocalData,
        // для тестов
        _internal: {
            b64encode, b64decode, bytesEqual,
            padmeLength, padMessage, unpadMessage, filePaddedLength,
            computeSafetyNumber,
            MAX_SKIP, MAX_PW_SKIP, PREKEY_ROTATE_MS, PREKEY_RETAIN_MS,
            MSG_PAD_MIN, FILE_PAD_MIN, MAX_ENVELOPE_CHARS, MAX_SHARE_CHARS, SHARE_BATCH,
        },
    };
});
