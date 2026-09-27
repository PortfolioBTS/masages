'use strict';
// Решатель proof-of-work для регистрации (пара к lib/pow.js).
//
// Сервер выдаёт токен и сложность d; нужно найти nonce из десятичных цифр,
// при котором SHA-256(utf8(token + ':' + nonce)) начинается с d нулевых бит.
// Это заменяет жёсткий лимит регистраций по IP: у пользователей Tor общий
// exit-IP (а через onion-сервис — вообще один адрес на всех), и лимит по IP
// запирал их всех разом. Цена регистрации теперь — секунда-другая работы CPU
// клиента, а не "повезло ли с IP".
//
// Почему своя SHA-256, а не crypto.subtle.digest:
//   - subtle.digest асинхронный: на каждый из ~2^18 хэшей уходил бы промис и
//     выделение буферов — на порядки медленнее синхронного цикла;
//   - Tor Browser на уровне "Safer" отключает WebAssembly, так что остаётся
//     только чистый JS.
// Горячий цикл не выделяет память: байты token + ':' (и все полные 64-байтные
// блоки перед nonce) сжимаются один раз в midstate, а на каждой попытке
// пересчитывается только хвостовой блок, где меняется одна-две цифры nonce.
//
// Файл — классический worker-скрипт: без eval, без importScripts, поэтому
// работает под CSP script-src 'self'. В Node (тесты) экспортирует
// { solve, sha256 } и обработчик сообщений не регистрирует.
(function (root) {
    var K = new Int32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    var IV = new Int32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    // Nonce — не длиннее 20 цифр (столько принимает сервер).
    var MAX_NONCE_DIGITS = 20;

    // Одно сжатие SHA-256: состояние из inState, 16 слов блока из
    // block[off..off+15], результат — в outState (может совпадать с inState).
    // w — рабочий буфер расписания на 64 слова, передаётся снаружи, чтобы
    // не выделять его на каждый вызов.
    //
    // Раунд SHA-256: t1 = h + Σ1(e) + Ch(e,f,g) + K[i] + w[i]; d += t1;
    // h = t1 + Σ0(a) + Maj(a,b,c) — после чего a..h "сдвигаются" на одну
    // позицию. Вместо восьми присваиваний на каждом раунде цикл развёрнут на
    // 8 раундов, а роли переменных поворачиваются в тексте. Ch и Maj записаны
    // эквивалентными формулами с меньшим числом операций:
    // Ch = g ^ (e & (f ^ g)), Maj = (a & b) | (c & (a | b)).
    // Вместе это ~25% скорости в V8 (≈3.5 млн сжатий/с против ≈2.8).
    function compress(inState, outState, block, off, w) {
        var i, x, s0, s1, t1;
        for (i = 0; i < 16; i++) w[i] = block[off + i];
        for (i = 16; i < 64; i++) {
            x = w[i - 15];
            s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
            x = w[i - 2];
            s1 = ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        var a = inState[0], b = inState[1], c = inState[2], d = inState[3];
        var e = inState[4], f = inState[5], g = inState[6], h = inState[7];
        for (i = 0; i < 64; i += 8) {
            t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + (g ^ (e & (f ^ g))) + K[i] + w[i]) | 0;
            d = (d + t1) | 0;
            h = (t1 + (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) | (c & (a | b)))) | 0;

            t1 = (g + (((d >>> 6) | (d << 26)) ^ ((d >>> 11) | (d << 21)) ^ ((d >>> 25) | (d << 7))) + (f ^ (d & (e ^ f))) + K[i + 1] + w[i + 1]) | 0;
            c = (c + t1) | 0;
            g = (t1 + (((h >>> 2) | (h << 30)) ^ ((h >>> 13) | (h << 19)) ^ ((h >>> 22) | (h << 10))) + ((h & a) | (b & (h | a)))) | 0;

            t1 = (f + (((c >>> 6) | (c << 26)) ^ ((c >>> 11) | (c << 21)) ^ ((c >>> 25) | (c << 7))) + (e ^ (c & (d ^ e))) + K[i + 2] + w[i + 2]) | 0;
            b = (b + t1) | 0;
            f = (t1 + (((g >>> 2) | (g << 30)) ^ ((g >>> 13) | (g << 19)) ^ ((g >>> 22) | (g << 10))) + ((g & h) | (a & (g | h)))) | 0;

            t1 = (e + (((b >>> 6) | (b << 26)) ^ ((b >>> 11) | (b << 21)) ^ ((b >>> 25) | (b << 7))) + (d ^ (b & (c ^ d))) + K[i + 3] + w[i + 3]) | 0;
            a = (a + t1) | 0;
            e = (t1 + (((f >>> 2) | (f << 30)) ^ ((f >>> 13) | (f << 19)) ^ ((f >>> 22) | (f << 10))) + ((f & g) | (h & (f | g)))) | 0;

            t1 = (d + (((a >>> 6) | (a << 26)) ^ ((a >>> 11) | (a << 21)) ^ ((a >>> 25) | (a << 7))) + (c ^ (a & (b ^ c))) + K[i + 4] + w[i + 4]) | 0;
            h = (h + t1) | 0;
            d = (t1 + (((e >>> 2) | (e << 30)) ^ ((e >>> 13) | (e << 19)) ^ ((e >>> 22) | (e << 10))) + ((e & f) | (g & (e | f)))) | 0;

            t1 = (c + (((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7))) + (b ^ (h & (a ^ b))) + K[i + 5] + w[i + 5]) | 0;
            g = (g + t1) | 0;
            c = (t1 + (((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10))) + ((d & e) | (f & (d | e)))) | 0;

            t1 = (b + (((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7))) + (a ^ (g & (h ^ a))) + K[i + 6] + w[i + 6]) | 0;
            f = (f + t1) | 0;
            b = (t1 + (((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10))) + ((c & d) | (e & (c | d)))) | 0;

            t1 = (a + (((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7))) + (h ^ (f & (g ^ h))) + K[i + 7] + w[i + 7]) | 0;
            e = (e + t1) | 0;
            a = (t1 + (((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10))) + ((b & c) | (d & (b | c)))) | 0;
        }
        outState[0] = (inState[0] + a) | 0; outState[1] = (inState[1] + b) | 0;
        outState[2] = (inState[2] + c) | 0; outState[3] = (inState[3] + d) | 0;
        outState[4] = (inState[4] + e) | 0; outState[5] = (inState[5] + f) | 0;
        outState[6] = (inState[6] + g) | 0; outState[7] = (inState[7] + h) | 0;
    }

    // Байты -> big-endian слова. Длина bytes кратна 4.
    function bytesToWords(bytes, words) {
        for (var i = 0, j = 0; j < bytes.length; i++, j += 4) {
            words[i] = (bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3];
        }
    }

    // Добивка SHA-256: 0x80, нули, 64-битная длина в битах. tail — байты
    // после последнего полного блока, totalBytes — длина всего сообщения.
    // Возвращает 16 или 32 слова (один или два блока).
    function padTail(tail, totalBytes) {
        var blocks = tail.length + 9 <= 64 ? 1 : 2;
        var buf = new Uint8Array(blocks * 64);
        buf.set(tail);
        buf[tail.length] = 0x80;
        // Длина в битах: старшая часть — через деление, чтобы не упереться
        // в 32-битные побитовые операции JS.
        var hi = Math.floor(totalBytes / 0x20000000);
        var lo = (totalBytes * 8) >>> 0;
        var end = buf.length;
        buf[end - 8] = hi >>> 24; buf[end - 7] = hi >>> 16; buf[end - 6] = hi >>> 8; buf[end - 5] = hi;
        buf[end - 4] = lo >>> 24; buf[end - 3] = lo >>> 16; buf[end - 2] = lo >>> 8; buf[end - 1] = lo;
        var words = new Int32Array(blocks * 16);
        bytesToWords(buf, words);
        return words;
    }

    // Сжимает все полные 64-байтные блоки из bytes в state, возвращает
    // число сжатых байт.
    function absorbFullBlocks(state, bytes, w) {
        var full = bytes.length - (bytes.length % 64);
        var block = new Int32Array(16);
        for (var off = 0; off < full; off += 64) {
            bytesToWords(bytes.subarray(off, off + 64), block);
            compress(state, state, block, 0, w);
        }
        return full;
    }

    function sha256(bytes) {
        if (!(bytes instanceof Uint8Array)) throw new TypeError('sha256 ожидает Uint8Array');
        var state = new Int32Array(IV);
        var w = new Int32Array(64);
        var done = absorbFullBlocks(state, bytes, w);
        var tail = padTail(bytes.subarray(done), bytes.length);
        for (var off = 0; off < tail.length; off += 16) compress(state, state, tail, off, w);
        var out = new Uint8Array(32);
        for (var i = 0; i < 8; i++) {
            out[i * 4] = state[i] >>> 24; out[i * 4 + 1] = state[i] >>> 16;
            out[i * 4 + 2] = state[i] >>> 8; out[i * 4 + 3] = state[i];
        }
        return out;
    }

    function hasLeadingZeroBits(state, bits) {
        var i = 0;
        for (; bits >= 32; bits -= 32, i++) if (state[i] !== 0) return false;
        return bits === 0 || (state[i] >>> (32 - bits)) === 0;
    }

    function encodeUtf8(str) {
        return new TextEncoder().encode(str);
    }

    function solve(token, difficulty) {
        if (typeof token !== 'string' || token === '') throw new TypeError('Пустой токен proof-of-work');
        if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > 256) {
            throw new RangeError('Недопустимая сложность proof-of-work');
        }
        var prefix = encodeUtf8(token + ':');
        var w = new Int32Array(64);
        var mid = new Int32Array(IV);
        var absorbed = absorbFullBlocks(mid, prefix, w);
        var rest = prefix.subarray(absorbed);
        var st = new Int32Array(8);
        // Быстрая предпроверка по первому слову; точная — hasLeadingZeroBits.
        var mask0 = difficulty >= 32 ? -1 : (difficulty === 0 ? 0 : (-1 << (32 - difficulty)));

        // Nonce хранится ASCII-цифрами; стартуем с "0", длина растёт по мере
        // перебора. При смене длины меняются добивка и длина сообщения —
        // хвостовые блоки пересобираются (это случается раз на порядок).
        var digits = new Uint8Array([0x30]);
        var n, tail, tailWords, k, pos, shift, wi;
        for (;;) {
            n = digits.length;
            var tailBytes = new Uint8Array(rest.length + n);
            tailBytes.set(rest);
            tailBytes.set(digits, rest.length);
            tail = padTail(tailBytes, absorbed + tailBytes.length);
            tailWords = tail.length;

            for (;;) {
                compress(mid, st, tail, 0, w);
                if (tailWords === 32) compress(st, st, tail, 16, w);
                if ((st[0] & mask0) === 0 && hasLeadingZeroBits(st, difficulty)) {
                    return String.fromCharCode.apply(null, digits);
                }
                // Инкремент десятичного числа прямо в словах блока: обычно
                // меняется только последняя цифра — одна операция над словом.
                for (k = n - 1; k >= 0 && digits[k] === 0x39; k--) {
                    digits[k] = 0x30;
                    pos = rest.length + k; wi = pos >> 2; shift = (3 - (pos & 3)) << 3;
                    tail[wi] = (tail[wi] & ~(0xff << shift)) | (0x30 << shift);
                }
                if (k < 0) break;
                digits[k]++;
                pos = rest.length + k; wi = pos >> 2; shift = (3 - (pos & 3)) << 3;
                tail[wi] = (tail[wi] & ~(0xff << shift)) | (digits[k] << shift);
            }
            // Все цифры были девятками: следующее число — 1 и n нулей.
            if (n + 1 > MAX_NONCE_DIGITS) throw new Error('Пространство nonce исчерпано');
            digits = new Uint8Array(n + 1);
            digits.fill(0x30);
            digits[0] = 0x31;
        }
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { solve: solve, sha256: sha256 };
    } else {
        root.onmessage = function (event) {
            var data = event.data || {};
            root.postMessage({ nonce: solve(data.token, data.difficulty) });
        };
    }
})(typeof self !== 'undefined' ? self : this);
