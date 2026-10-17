// Кодирование и дополнение для ядра E2EE (roadmap R14, T6.4): чистые функции без состояния и без
// криптографии. Вынесено дословно из public/e2ee.js (разделы «Кодирование», «Паддинг (Padmé)» и
// мелкие проверки форм из разделов «Примитивы» и «Форматы конвертов»):
//   - base64 (b64encode/b64decode), строгое поле фиксированной длины (decodeFixed), ключ X25519/Ed25519
//     в каноническом base64 (canonicalPubKey), каноническое имя ключа отправителя (isCanonicalKeyId);
//   - байты: utf8encode/utf8decode, concatBytes, bytesEqual, u32be, u64be, toBytes, проверки isKeyId,
//     isU32, isAllZero;
//   - дополнение Padmé: padmeLength, padMessage, unpadMessage, filePaddedLength и пределы MSG_PAD_MIN,
//     FILE_PAD_MIN.
// Файл исполняется и в браузере (window.NyxoE2eeCodec, подключается до e2ee.js), и в Node (require);
// сам public/e2ee.js берёт эти функции отсюда. Проверяют их протокольные тесты (test/e2ee*.test.js).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoE2eeCodec = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ---- Размеры: минимум дополнения Padmé ----

    const MSG_PAD_MIN = 256;
    const FILE_PAD_MIN = 4096;

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

    // Целое до 2^53 в восемь байт, старшие первыми: u32be(n div 2^32) ‖ u32be(n mod 2^32).
    function u64be(n) {
        return concatBytes(u32be(Math.floor(n / 0x100000000)), u32be(n >>> 0));
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

    function isU32(n) {
        return Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF;
    }

    // low-order/identity точка на Curve25519 — та же defense-in-depth
    // проверка, что уже есть на сервере ключей (crypto.rs::decode_pubkey).
    function isAllZero(bytes) {
        for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
        return true;
    }

    // senderKeyId попадает в имена записей хранилища (skArchive:…, seen:…):
    // только каноническое base64 ровно 16 байт, без посторонних символов.
    function isCanonicalKeyId(value) {
        if (typeof value !== 'string') return false;
        const bytes = decodeFixed(value, 16);
        return Boolean(bytes) && b64encode(bytes) === value;
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

    return Object.freeze({
        MSG_PAD_MIN, FILE_PAD_MIN, b64encode, b64decode, decodeFixed, canonicalPubKey,
        utf8encode, utf8decode, concatBytes, bytesEqual, u32be, u64be,
        toBytes, isKeyId, isU32, isAllZero, isCanonicalKeyId, padmeLength,
        padMessage, unpadMessage, filePaddedLength,
    });
});
