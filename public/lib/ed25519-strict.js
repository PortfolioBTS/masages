// Строгая проверка ключей и подписей Ed25519 (docs/security/signed-membership.md, 6.1;
// docs/security/key-transparency.md, 11).
//
// Платформенный verify (Web Crypto и node:crypto) принимает ключи малого порядка и
// некорректную кодировку единичной точки с битом знака: пара R = 01 00…00, S = 0
// «подходит» к ЛЮБОМУ сообщению, если ключ — 01 00…00 или 01 00…00 80 (OpenSSL при
// x = 0 бит знака не проверяет). Поэтому проверка явная и выполняется ДО verify:
//   1. декодирование по RFC 8032, 5.1.3: длина 32 байта; y < p; корень x существует;
//      если x = 0 при бите знака 1 — отказ (п. 4 RFC: так выглядят 01 00…00 80 и
//      ec ff…ff ff);
//   2. точка не малого порядка: [8]P ≠ O на декодированной точке (закрывает все
//      восемь точек порядка 1, 2, 4, 8 без таблицы кодировок);
//   3. для подписи S < L.
// Пункты 1 и 2 — отдельные функции (decodePoint, hasSmallOrder): отказ одного не должен
// маскировать отсутствие другого, и тесты проверяют их по отдельности.
//
// Один и тот же файл исполняется в браузере (window.NyxoEd25519Strict) и на сервере
// (require): клиент и сервер не могут разойтись в том, что считать допустимым.
// Арифметика — BigInt: нужна только проверка точки (один раз на ключ и на подпись),
// а не подписывание.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoEd25519Strict = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // p = 2^255 − 19; L — порядок базовой подгруппы; d = −121665/121666 (кривая a = −1).
    const P = (1n << 255n) - 19n;
    const L = (1n << 252n) + 27742317777372353535851937790883648493n;

    const mod = (a) => {
        const r = a % P;
        return r >= 0n ? r : r + P;
    };

    function pow(base, exponent) {
        let result = 1n;
        let b = mod(base);
        let e = exponent;
        while (e > 0n) {
            if (e & 1n) result = (result * b) % P;
            b = (b * b) % P;
            e >>= 1n;
        }
        return result;
    }

    const inv = (a) => pow(a, P - 2n);
    const D = mod(-121665n * inv(121666n));
    const SQRT_M1 = pow(2n, (P - 1n) / 4n);

    // Little-endian → BigInt.
    function toInt(bytes) {
        let n = 0n;
        for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
        return n;
    }

    // ---- Пункт 1: декодирование точки ----

    // Возвращает { x, y } либо { error } с причиной:
    //   'length' — не 32 байта; 'non-canonical-y' — y ≥ p; 'no-square-root' — точки нет на кривой;
    //   'zero-x-sign' — x = 0 при бите знака 1 (RFC 8032, 5.1.3, п. 4).
    // rejectZeroXSign: false нужен только тестам — проверить [8]P ≠ O отдельно от декодера,
    // который бит знака при x = 0 не проверяет (как OpenSSL).
    function decodePoint(bytes, { rejectZeroXSign = true } = {}) {
        if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return { error: 'length' };
        const sign = bytes[31] >> 7;
        const y = toInt(bytes) & ((1n << 255n) - 1n);
        if (y >= P) return { error: 'non-canonical-y' };
        const y2 = (y * y) % P;
        const u = mod(y2 - 1n);
        const v = mod(D * y2 + 1n);
        // x = u v³ (u v⁷)^((p−5)/8)
        const v3 = (v * v % P) * v % P;
        const v7 = (v3 * v3 % P) * v % P;
        let x = (u * v3 % P) * pow(u * v7, (P - 5n) / 8n) % P;
        const check = (v * x % P) * x % P;
        if (check === u) {
            // корень найден
        } else if (check === mod(-u)) {
            x = x * SQRT_M1 % P;
        } else {
            return { error: 'no-square-root' };
        }
        if (x === 0n && sign === 1 && rejectZeroXSign) return { error: 'zero-x-sign' };
        if (Number(x & 1n) !== sign) x = mod(-x);
        return { x, y };
    }

    // ---- Пункт 2: [8]P = O ----

    // Сложение в расширенных координатах (RFC 8032, 5.1.4): полная формула, годится и для
    // единичной точки, и для точек малого порядка.
    function add(p, q) {
        const a = mod((p.y - p.x) * (q.y - q.x));
        const b = mod((p.y + p.x) * (q.y + q.x));
        const c = mod(p.t * 2n * D % P * q.t);
        const d = mod(p.z * 2n * q.z);
        const e = b - a;
        const f = d - c;
        const g = d + c;
        const h = b + a;
        return { x: mod(e * f), y: mod(g * h), t: mod(e * h), z: mod(f * g) };
    }

    // true, если [8]P = O: точка порядка 1, 2, 4 или 8 (подгруппа кручения).
    function hasSmallOrder(point) {
        let q = { x: point.x, y: point.y, z: 1n, t: (point.x * point.y) % P };
        for (let i = 0; i < 3; i++) q = add(q, q);
        return q.x === 0n && q.y === q.z;
    }

    // Ключ целиком: пункты 1 и 2. { ok: true } либо { ok: false, reason }.
    function checkPublicKey(bytes) {
        const point = decodePoint(bytes);
        if (point.error) return { ok: false, reason: point.error };
        if (hasSmallOrder(point)) return { ok: false, reason: 'small-order' };
        return { ok: true };
    }

    const keyCache = new Map();
    const KEY_CACHE_SIZE = 256;

    // Булево с памятью: ключ журнала и ключи участников проверяются на каждом сообщении.
    function isStrictKey(bytes) {
        if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return false;
        const id = String.fromCharCode.apply(null, bytes);
        if (keyCache.has(id)) return keyCache.get(id);
        const ok = checkPublicKey(bytes).ok;
        if (keyCache.size >= KEY_CACHE_SIZE) keyCache.delete(keyCache.keys().next().value);
        keyCache.set(id, ok);
        return ok;
    }

    // ---- Пункт 3 и подпись целиком ----

    // Подпись: 64 байта; R (первые 32) проходит пункты 1 и 2; S < L (little-endian).
    function checkSignature(sig) {
        if (!(sig instanceof Uint8Array) || sig.length !== 64) return { ok: false, reason: 'length' };
        const r = checkPublicKey(sig.subarray(0, 32));
        if (!r.ok) return { ok: false, reason: 'R-' + r.reason };
        if (toInt(sig.subarray(32)) >= L) return { ok: false, reason: 'S-not-less-than-L' };
        return { ok: true };
    }

    // Проверка подписи: строгая проверка ключа и подписи, и только потом платформенный verify.
    async function verify(pub, message, sig) {
        if (!isStrictKey(pub) || !checkSignature(sig).ok) return false;
        const subtle = typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle;
        if (!subtle) return false;
        try {
            const key = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
            return await subtle.verify({ name: 'Ed25519' }, key, sig, message);
        } catch {
            return false;
        }
    }

    // Канонические кодировки восьми точек малого порядка — только для тестов (проверка их не перечисляет).
    const SMALL_ORDER_ENCODINGS = Object.freeze([
        '0100000000000000000000000000000000000000000000000000000000000000',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    ]);

    return { P, L, decodePoint, hasSmallOrder, checkPublicKey, isStrictKey, checkSignature, verify, SMALL_ORDER_ENCODINGS };
});
