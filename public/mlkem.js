// ML-KEM-768 (FIPS 203, финальная версия, август 2024) + SHA-3/SHAKE (FIPS 202)
// на чистом JS — постквантовая половина гибридного X3DH (PQXDH, как у Signal)
// в public/e2ee.js.
//
// Почему своя реализация, а не WebCrypto:
//   - ML-KEM в crypto.subtle есть далеко не во всех браузерах (в Node 24 —
//     только экспериментально), а внешние библиотеки/CDN запрещены CSP
//     (script-src 'self'). Файл исполняется один-в-один в браузере, в
//     Web Worker и в чистом Node — на этом построены тесты
//     test/mlkem.test.js, которые сверяют его побайтно с ML-KEM-768 из
//     Node/OpenSSL и SHA-3 из node:crypto.
//   - Все функции синхронные: операция ML-KEM занимает доли миллисекунды,
//     промисы здесь только мешали бы.
//
// Всё строго по FIPS 203 (номера алгоритмов указаны в комментариях), без
// «упрощений»: KeyGen_internal/Encaps_internal/Decaps_internal, implicit
// rejection K̄ = J(z‖c), проверки ввода из §7.2/§7.3 (длины, modulus check
// ключа инкапсуляции, hash check ключа декапсуляции).
//
// Постоянное время — «в меру возможностей JS»: JIT и сборщик мусора не дают
// гарантий, но в коде нет ветвлений и обращений к памяти по индексам,
// зависящих от секретов; деление на q по секретным данным не используется
// вовсе (атака KyberSlash была именно на деление в Compress), редукции по
// модулю q — через Монтгомери на Math.imul и маскированные вычитания;
// сравнение c′ == c и выбор K′/K̄ — накоплением XOR и маской. Секретные
// промежуточные буферы затираются после использования, но копии, которые
// мог сделать движок, JS затереть не позволяет.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MLKEM = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ===================== Проверка аргументов и случайность =====================

    function checkBytes(value, length, name) {
        if (!(value instanceof Uint8Array)) throw new TypeError('MLKEM: ' + name + ' должен быть Uint8Array');
        if (length !== undefined && value.length !== length) {
            throw new RangeError('MLKEM: ' + name + ' должен быть длиной ' + length + ' байт, получено ' + value.length);
        }
    }

    function checkOutLen(outLen) {
        if (!Number.isSafeInteger(outLen) || outLen < 0) throw new RangeError('MLKEM: длина выхода должна быть целым числом ≥ 0');
    }

    function randomBytes(n) {
        const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
        if (!c || typeof c.getRandomValues !== 'function') throw new Error('MLKEM: нет crypto.getRandomValues');
        return c.getRandomValues(new Uint8Array(n));
    }

    function concatBytes(parts) {
        let len = 0;
        for (const p of parts) len += p.length;
        const out = new Uint8Array(len);
        let off = 0;
        for (const p of parts) { out.set(p, off); off += p.length; }
        return out;
    }

    // Сравнение без раннего выхода: 0xff, если массивы равны, иначе 0.
    // Длины — публичные (фиксированы параметрами), по ним ветвиться можно.
    function ctEqualMask(a, b) {
        let diff = a.length ^ b.length;
        const n = Math.min(a.length, b.length);
        for (let i = 0; i < n; i++) diff |= a[i] ^ b[i];
        // diff ∈ [0, 2^31): (diff − 1) >> 31 даёт −1 только при diff = 0
        return ((diff - 1) >> 31) & 0xff;
    }

    function wipe(...items) {
        for (const item of items) {
            if (Array.isArray(item)) wipe(...item);
            else if (item) item.fill(0);
        }
    }

    // ===================== Keccak-f[1600] (FIPS 202, §3) =====================
    //
    // Состояние — 25 дорожек по 64 бита, каждая хранится парой 32-битных слов
    // (младшее, старшее) в Uint32Array(50): BigInt в JS на порядки медленнее.
    // Дорожка (x, y) — индекс x + 5y (FIPS 202 §3.1.2), слова 2(x+5y) и
    // 2(x+5y)+1. Байты сообщения ложатся в дорожки little-endian, поэтому
    // байт номер b состояния — это байт (b & 3) слова (b >> 2).
    //
    // Таблицы ρ, π и констант ι не переписаны вручную, а вычисляются при
    // загрузке прямо по определениям из FIPS 202 (алг. 2, 3, 5, 6) — так их
    // нельзя «опечатать», а правильность подтверждают тесты против node:crypto.

    const RHO_PI_SRC = new Uint8Array(25); // для дорожки-приёмника: номер дорожки-источника (π)
    const RHO_OFFSET = new Uint8Array(25); // сдвиг ρ этой дорожки-источника
    const RC_LO = new Uint32Array(24);
    const RC_HI = new Uint32Array(24);

    (function initKeccakTables() {
        // Алг. 2 (ρ): (x, y) = (1, 0); для t = 0..23 сдвиг дорожки (x, y) равен
        // (t+1)(t+2)/2 mod 64, затем (x, y) = (y, (2x + 3y) mod 5). Дорожка (0,0) не сдвигается.
        const rho = new Uint8Array(25);
        let x = 1, y = 0;
        for (let t = 0; t < 24; t++) {
            rho[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
            const nx = y;
            y = (2 * x + 3 * y) % 5;
            x = nx;
        }
        // Алг. 3 (π): A′[x, y] = A[(x + 3y) mod 5, x]
        for (let dx = 0; dx < 5; dx++) {
            for (let dy = 0; dy < 5; dy++) {
                const src = ((dx + 3 * dy) % 5) + 5 * dx;
                RHO_PI_SRC[dx + 5 * dy] = src;
                RHO_OFFSET[dx + 5 * dy] = rho[src];
            }
        }
        // Алг. 5: rc(t) — выход LFSR с многочленом x^8 + x^6 + x^5 + x^4 + 1
        // (бит i целого R — это R[i] из стандарта).
        function rc(t) {
            if (t % 255 === 0) return 1;
            let R = 1;
            for (let i = 1; i <= t % 255; i++) {
                R <<= 1;                                   // R = 0 ‖ R
                const r8 = (R >>> 8) & 1;
                R ^= r8 | (r8 << 4) | (r8 << 5) | (r8 << 6); // R[0], R[4], R[5], R[6] ⊕= R[8]
                R &= 0xff;                                 // Trunc8
            }
            return R & 1;
        }
        // Алг. 6 (ι): RC[2^j − 1] = rc(j + 7·i_r) для j = 0..6
        for (let ir = 0; ir < 24; ir++) {
            let lo = 0, hi = 0;
            for (let j = 0; j <= 6; j++) {
                if (rc(j + 7 * ir)) {
                    const bit = (1 << j) - 1;
                    if (bit < 32) lo |= 1 << bit;
                    else hi |= 1 << (bit - 32);
                }
            }
            RC_LO[ir] = lo;
            RC_HI[ir] = hi;
        }
    })();

    // Рабочие буферы перестановки. Код синхронный и нереентерабельный, так что
    // общие буферы безопасны; после каждой перестановки они затираются.
    const KECCAK_B = new Uint32Array(50);
    const KECCAK_C = new Uint32Array(10);

    function keccakF1600(s) {
        const B = KECCAK_B, C = KECCAK_C;
        for (let round = 0; round < 24; round++) {
            // θ (алг. 1): C[x] = ⊕_y A[x, y]; D[x] = C[x−1] ⊕ ROT(C[x+1], 1)
            for (let x = 0; x < 10; x += 2) {
                C[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
                C[x + 1] = s[x + 1] ^ s[x + 11] ^ s[x + 21] ^ s[x + 31] ^ s[x + 41];
            }
            for (let x = 0; x < 10; x += 2) {
                const prev = (x + 8) % 10, next = (x + 2) % 10;
                const dl = C[prev] ^ ((C[next] << 1) | (C[next + 1] >>> 31));
                const dh = C[prev + 1] ^ ((C[next + 1] << 1) | (C[next] >>> 31));
                for (let y = 0; y < 50; y += 10) {
                    s[y + x] ^= dl;
                    s[y + x + 1] ^= dh;
                }
            }
            // ρ и π (алг. 2, 3): B[x, y] = ROT(A[(x + 3y) mod 5, x], сдвиг)
            for (let i = 0; i < 25; i++) {
                const w = RHO_PI_SRC[i] << 1, r = RHO_OFFSET[i];
                const lo = s[w], hi = s[w + 1];
                let nl, nh;
                if (r === 0) {
                    nl = lo; nh = hi;
                } else if (r < 32) {
                    nl = (lo << r) | (hi >>> (32 - r));
                    nh = (hi << r) | (lo >>> (32 - r));
                } else if (r === 32) {
                    nl = hi; nh = lo;
                } else {
                    const m = r - 32;
                    nl = (hi << m) | (lo >>> (32 - m));
                    nh = (lo << m) | (hi >>> (32 - m));
                }
                B[i << 1] = nl;
                B[(i << 1) + 1] = nh;
            }
            // χ (алг. 4): A[x, y] = B[x, y] ⊕ (¬B[x+1, y] ∧ B[x+2, y])
            for (let y = 0; y < 50; y += 10) {
                for (let x = 0; x < 10; x += 2) {
                    const x1 = y + (x + 2) % 10, x2 = y + (x + 4) % 10;
                    s[y + x] = B[y + x] ^ (~B[x1] & B[x2]);
                    s[y + x + 1] = B[y + x + 1] ^ (~B[x1 + 1] & B[x2 + 1]);
                }
            }
            // ι (алг. 6)
            s[0] ^= RC_LO[round];
            s[1] ^= RC_HI[round];
        }
        B.fill(0);
        C.fill(0);
    }

    // ===================== Губка SHA-3 / SHAKE (FIPS 202, §4, §6) =====================
    //
    // rate — скорость губки в байтах; suffix — доменный суффикс вместе с первым
    // битом pad10*1: SHA3 — «01» → 0x06, SHAKE — «1111» → 0x1f. Squeeze
    // инкрементальный: последовательные вызовы продолжают один и тот же поток
    // (это и есть XOF.Squeeze из FIPS 203 §4.1).

    class KeccakSponge {
        constructor(rate, suffix) {
            this.state = new Uint32Array(50);
            this.rate = rate;
            this.suffix = suffix;
            this.pos = 0;
            this.squeezing = false;
        }

        absorb(data) {
            if (this.squeezing) throw new Error('MLKEM: absorb после squeeze не поддерживается');
            const s = this.state, rate = this.rate;
            let pos = this.pos;
            for (let i = 0; i < data.length; i++) {
                s[pos >> 2] ^= data[i] << ((pos & 3) << 3);
                if (++pos === rate) {
                    keccakF1600(s);
                    pos = 0;
                }
            }
            this.pos = pos;
            return this;
        }

        // pad10*1 (FIPS 202 §5.1) с доменным суффиксом; если оба маркера
        // попадают в последний байт блока, они просто складываются по XOR.
        pad() {
            const s = this.state, last = this.rate - 1;
            s[this.pos >> 2] ^= this.suffix << ((this.pos & 3) << 3);
            s[last >> 2] ^= 0x80 << ((last & 3) << 3);
            keccakF1600(s);
            this.pos = 0;
            this.squeezing = true;
        }

        squeezeInto(out) {
            if (!this.squeezing) this.pad();
            const s = this.state, rate = this.rate;
            let pos = this.pos;
            for (let i = 0; i < out.length; i++) {
                if (pos === rate) {
                    keccakF1600(s);
                    pos = 0;
                }
                out[i] = s[pos >> 2] >>> ((pos & 3) << 3);
                pos++;
            }
            this.pos = pos;
            return out;
        }

        squeeze(n) {
            return this.squeezeInto(new Uint8Array(n));
        }

        destroy() {
            this.state.fill(0);
        }
    }

    const SHA3_256_RATE = 136, SHA3_512_RATE = 72, SHAKE128_RATE = 168, SHAKE256_RATE = 136;
    const SHA3_SUFFIX = 0x06, SHAKE_SUFFIX = 0x1f;

    function keccakHash(rate, suffix, parts, outLen) {
        const sponge = new KeccakSponge(rate, suffix);
        for (const p of parts) sponge.absorb(p);
        const out = sponge.squeeze(outLen);
        sponge.destroy();
        return out;
    }

    function sha3_256(data) {
        checkBytes(data, undefined, 'data');
        return keccakHash(SHA3_256_RATE, SHA3_SUFFIX, [data], 32);
    }

    function sha3_512(data) {
        checkBytes(data, undefined, 'data');
        return keccakHash(SHA3_512_RATE, SHA3_SUFFIX, [data], 64);
    }

    function shake128(data, outLen) {
        checkBytes(data, undefined, 'data');
        checkOutLen(outLen);
        return keccakHash(SHAKE128_RATE, SHAKE_SUFFIX, [data], outLen);
    }

    function shake256(data, outLen) {
        checkBytes(data, undefined, 'data');
        checkOutLen(outLen);
        return keccakHash(SHAKE256_RATE, SHAKE_SUFFIX, [data], outLen);
    }

    // Инкрементальный XOF (для тестов потокового squeeze).
    function xof(bits, data) {
        checkBytes(data, undefined, 'data');
        if (bits !== 128 && bits !== 256) throw new RangeError('MLKEM: XOF только SHAKE128 или SHAKE256');
        return new KeccakSponge(bits === 128 ? SHAKE128_RATE : SHAKE256_RATE, SHAKE_SUFFIX).absorb(data);
    }

    // Функции из FIPS 203 §4.1 (аргументы — части конкатенации).
    const H = (...parts) => keccakHash(SHA3_256_RATE, SHA3_SUFFIX, parts, 32);     // H(s) = SHA3-256(s)
    const G = (...parts) => keccakHash(SHA3_512_RATE, SHA3_SUFFIX, parts, 64);     // G(c) = SHA3-512(c) → (a, b)
    const J = (...parts) => keccakHash(SHAKE256_RATE, SHAKE_SUFFIX, parts, 32);    // J(s) = SHAKE256(s, 8·32)
    // PRF_η(s, b) = SHAKE256(s ‖ b, 8·64·η) — (4.3)
    const PRF = (eta, s, b) => keccakHash(SHAKE256_RATE, SHAKE_SUFFIX, [s, Uint8Array.of(b)], 64 * eta);

    // ===================== Параметры ML-KEM-768 (FIPS 203, §8, табл. 2) =====================

    const N = 256;
    const Q = 3329;
    const K = 3;
    const ETA1 = 2;
    const ETA2 = 2;
    const DU = 10;
    const DV = 4;

    const POLY_BYTES = 32 * 12;                              // ByteEncode_12 одного многочлена
    const PUBLIC_KEY_BYTES = 384 * K + 32;                   // 1184
    const SECRET_KEY_BYTES = 768 * K + 96;                   // 2400
    const CIPHERTEXT_BYTES = 32 * (DU * K + DV);             // 1088
    const SEED_BYTES = 64;                                   // d ‖ z
    const SHARED_SECRET_BYTES = 32;

    // ===================== Арифметика в Z_q =====================
    //
    // На границах всех функций из FIPS 203 коэффициенты канонические, в [0, q).
    // Внутри умножения — редукция Монтгомери (R = 2^16) на Math.imul: только
    // 32-битные целые операции, без деления и без ветвлений по данным.
    // Константы, на которые умножаем, хранятся заранее умноженными на R.

    const MONT = (1 << 16) % Q;                // R mod q = 2285
    const MONT_SQ = (MONT * MONT) % Q;         // R² mod q = 1353: fqmul(x, R²) = x·R
    const QINV = 62209;                        // q⁻¹ mod 2^16 (3329 · 62209 ≡ 1)
    const INV128_MONT = (3303 * MONT) % Q;     // 3303 = 128⁻¹ mod q (последний шаг алг. 10), в форме Монтгомери

    // |a| < q·2^15 → a·R⁻¹ mod q, результат в (−q, q)
    function montReduce(a) {
        const t = (Math.imul(a, QINV) << 16) >> 16;     // a·q⁻¹ mod 2^16 как знаковое 16-битное
        return (a - Math.imul(t, Q)) >> 16;             // a − t·q делится на 2^16 нацело
    }

    // a·b·R⁻¹ mod q; при |a|, |b| < q произведение заведомо < q·2^15
    function fqmul(a, b) {
        return montReduce(a * b);
    }

    // a ∈ (−q, 2q) → a mod q ∈ [0, q) двумя маскированными коррекциями
    function freeze(a) {
        a += (a >> 31) & Q;
        a -= Q;
        a += (a >> 31) & Q;
        return a;
    }

    function polyAdd(a, b) {
        const r = new Int32Array(N);
        for (let i = 0; i < N; i++) r[i] = freeze(a[i] + b[i]);
        return r;
    }

    function polySub(a, b) {
        const r = new Int32Array(N);
        for (let i = 0; i < N; i++) r[i] = freeze(a[i] - b[i]);
        return r;
    }

    // ===================== NTT (FIPS 203, §4.3, алг. 9–12) =====================

    function bitRev7(i) {
        let r = 0;
        for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b);
        return r;
    }

    function powModQ(base, exp) {
        let r = 1;
        base %= Q;
        while (exp > 0) {
            if (exp & 1) r = (r * base) % Q;
            base = (base * base) % Q;
            exp >>= 1;
        }
        return r;
    }

    // ζ = 17 — первообразный корень 256-й степени из единицы по модулю q.
    // ZETAS[i] = ζ^BitRev7(i) (алг. 9, 10), GAMMAS[i] = ζ^(2·BitRev7(i)+1) (алг. 11);
    // обе таблицы — в форме Монтгомери (·R mod q).
    const ZETAS_MONT = new Int32Array(128);
    const GAMMAS_MONT = new Int32Array(128);
    for (let i = 0; i < 128; i++) {
        ZETAS_MONT[i] = (powModQ(17, bitRev7(i)) * MONT) % Q;
        GAMMAS_MONT[i] = (powModQ(17, 2 * bitRev7(i) + 1) * MONT) % Q;
    }

    // Алг. 9: NTT(f)
    function ntt(f) {
        const a = Int32Array.from(f);
        let i = 1;
        for (let len = 128; len >= 2; len >>= 1) {
            for (let start = 0; start < N; start += 2 * len) {
                const zeta = ZETAS_MONT[i++];
                for (let j = start; j < start + len; j++) {
                    const t = fqmul(zeta, a[j + len]);      // ζ·f̂[j+len] ∈ (−q, q)
                    a[j + len] = freeze(a[j] - t);
                    a[j] = freeze(a[j] + t);
                }
            }
        }
        return a;
    }

    // Алг. 10: NTT⁻¹(f̂)
    function nttInverse(fHat) {
        const a = Int32Array.from(fHat);
        let i = 127;
        for (let len = 2; len <= 128; len <<= 1) {
            for (let start = 0; start < N; start += 2 * len) {
                const zeta = ZETAS_MONT[i--];
                for (let j = start; j < start + len; j++) {
                    const t = a[j];
                    a[j] = freeze(t + a[j + len]);
                    a[j + len] = freeze(fqmul(zeta, a[j + len] - t));
                }
            }
        }
        for (let j = 0; j < N; j++) a[j] = freeze(fqmul(a[j], INV128_MONT));
        return a;
    }

    // Алг. 11 (MultiplyNTTs) с встроенным алг. 12 (BaseCaseMultiply):
    //   c0 = a0·b0 + a1·b1·γ,  c1 = a0·b1 + a1·b0.
    // Оба сомножителя — обычные (не Монтгомери) значения, поэтому после
    // montReduce результат несёт лишний множитель R⁻¹, который снимается
    // умножением на R² в форме Монтгомери.
    function multiplyNTTs(f, g) {
        const h = new Int32Array(N);
        for (let i = 0; i < 128; i++) {
            const a0 = f[2 * i], a1 = f[2 * i + 1];
            const b0 = g[2 * i], b1 = g[2 * i + 1];
            const a1b1 = fqmul(a1, b1);                                  // a1·b1·R⁻¹
            const c0 = montReduce(a0 * b0 + a1b1 * GAMMAS_MONT[i]);      // (a0·b0 + a1·b1·γ)·R⁻¹, |аргумент| < 2q²
            const c1 = montReduce(a0 * b1 + a1 * b0);                    // (a0·b1 + a1·b0)·R⁻¹
            h[2 * i] = freeze(fqmul(c0, MONT_SQ));
            h[2 * i + 1] = freeze(fqmul(c1, MONT_SQ));
        }
        return h;
    }

    // Σ_j MultiplyNTTs(a[j], b[j]) — скалярное произведение векторов в NTT-области
    function dotNTT(a, b) {
        let acc = multiplyNTTs(a[0], b[0]);
        for (let j = 1; j < a.length; j++) {
            const prod = multiplyNTTs(a[j], b[j]);
            const next = polyAdd(acc, prod);
            wipe(acc, prod);
            acc = next;
        }
        return acc;
    }

    // ===================== Сжатие и кодирование (FIPS 203, §4.2.1, алг. 5, 6) =====================

    // Compress_d(x) = ⌈(2^d/q)·x⌋ mod 2^d  (4.7), x ∈ [0, q).
    // Округление «половина вверх» (x·2^d/q никогда не равно ровно k + 1/2, т.к.
    // q нечётно и x < q), поэтому ⌈x·2^d/q⌋ = ⌊(x·2^d + (q−1)/2)/q⌋. Деление на q
    // заменено умножением на ⌈2^35/q⌉ с последующим сдвигом: для числителя
    // < 2^22 (d ≤ 10) результат точный — ошибка < 2^−13 < 1/q, а произведение
    // < 2^46 точно представимо в double. Это без деления по секретным данным
    // (KyberSlash); тест проверяет все x ∈ [0, q) для d = 1, 4, 10.
    const COMPRESS_MUL = Math.ceil(2 ** 35 / Q);
    const COMPRESS_SCALE = 2 ** -35;

    function compressPoly(f, d) {
        const r = new Int32Array(N);
        const mask = (1 << d) - 1;
        for (let i = 0; i < N; i++) {
            const num = f[i] * (1 << d) + (Q - 1) / 2;
            r[i] = Math.floor(num * COMPRESS_MUL * COMPRESS_SCALE) & mask;
        }
        return r;
    }

    // Decompress_d(y) = ⌈(q/2^d)·y⌋  (4.8) = ⌊(q·y + 2^(d−1)) / 2^d⌋, y ∈ [0, 2^d)
    function decompressPoly(f, d) {
        const r = new Int32Array(N);
        const half = 1 << (d - 1);
        for (let i = 0; i < N; i++) r[i] = (Q * f[i] + half) >> d;
        return r;
    }

    // Алг. 5: ByteEncode_d(F) — 256 чисел по d бит, младшие биты первыми
    // (эквивалентно BitsToBytes из алг. 3). Цикл зависит только от d.
    function byteEncode(F, d) {
        const out = new Uint8Array(32 * d);
        let acc = 0, bits = 0, o = 0;
        for (let i = 0; i < N; i++) {
            acc |= F[i] << bits;
            bits += d;
            while (bits >= 8) {
                out[o++] = acc & 0xff;
                acc >>>= 8;
                bits -= 8;
            }
        }
        return out;
    }

    // Алг. 6: ByteDecode_d(B); при d = 12 результат берётся mod q (m = q),
    // при d < 12 — mod 2^d, что для d-битного поля ничего не меняет.
    function byteDecode(B, d) {
        const F = new Int32Array(N);
        const mask = (1 << d) - 1;
        let acc = 0, bits = 0, p = 0;
        for (let i = 0; i < N; i++) {
            while (bits < d) {
                acc |= B[p++] << bits;
                bits += 8;
            }
            let v = acc & mask;
            acc >>>= d;
            bits -= d;
            if (d === 12) {
                v -= Q;                 // v ∈ [0, 4096) → маскированное mod q
                v += (v >> 31) & Q;
            }
            F[i] = v;
        }
        return F;
    }

    function encodeVector(polys, d) {
        return concatBytes(polys.map(p => byteEncode(p, d)));
    }

    function decodeVector(bytes, d) {
        const len = 32 * d, out = [];
        for (let i = 0; i < K; i++) out.push(byteDecode(bytes.subarray(i * len, (i + 1) * len), d));
        return out;
    }

    // ===================== Сэмплирование (FIPS 203, §4.2.2, алг. 7, 8) =====================

    // Алг. 7: SampleNTT(B), B = ρ ‖ j ‖ i (34 байта) — отбор с отклонением из
    // потока SHAKE128. Поток читается блоками по 168 байт: 168 = 56·3, так
    // что тройки байт не пересекают границу блока и результат совпадает с
    // побайтовым XOF.Squeeze(ctx, 3) из стандарта. Данные публичные (ρ),
    // ветвления здесь допустимы.
    function sampleNTT(B) {
        const x = new KeccakSponge(SHAKE128_RATE, SHAKE_SUFFIX).absorb(B);
        const a = new Int32Array(N);
        const C = new Uint8Array(SHAKE128_RATE);
        let j = 0;
        while (j < N) {
            x.squeezeInto(C);
            for (let p = 0; p < C.length && j < N; p += 3) {
                const d1 = C[p] + 256 * (C[p + 1] & 15);
                const d2 = (C[p + 1] >> 4) + 16 * C[p + 2];
                if (d1 < Q) a[j++] = d1;
                if (d2 < Q && j < N) a[j++] = d2;
            }
        }
        x.destroy();
        return a;
    }

    // Â[i][j] = SampleNTT(ρ ‖ j ‖ i) — обратите внимание: в конкатенации
    // сначала индекс столбца j, потом строки i (алг. 13 и 14).
    function sampleMatrix(rho) {
        const seed = new Uint8Array(34);
        seed.set(rho, 0);
        const A = [];
        for (let i = 0; i < K; i++) {
            const row = [];
            for (let j = 0; j < K; j++) {
                seed[32] = j;
                seed[33] = i;
                row.push(sampleNTT(seed));
            }
            A.push(row);
        }
        return A;
    }

    // Алг. 8: SamplePolyCBD_η(B), |B| = 64η. Биты берутся младшими первыми
    // (BytesToBits, алг. 4); x − y ∈ [−η, η] переводится в [0, q) маской.
    function samplePolyCBD(B, eta) {
        const f = new Int32Array(N);
        for (let i = 0; i < N; i++) {
            let x = 0, y = 0;
            for (let j = 0; j < eta; j++) {
                const bx = 2 * i * eta + j, by = 2 * i * eta + eta + j;
                x += (B[bx >> 3] >> (bx & 7)) & 1;
                y += (B[by >> 3] >> (by & 7)) & 1;
            }
            f[i] = freeze(x - y);
        }
        return f;
    }

    // ===================== K-PKE (FIPS 203, §5, алг. 13–15) =====================

    // Алг. 13: K-PKE.KeyGen(d)
    function kpkeKeyGen(d) {
        const g = G(d, Uint8Array.of(K));             // (ρ, σ) ← G(d ‖ k) — байт k есть только в финальном FIPS 203
        const rho = g.slice(0, 32), sigma = g.subarray(32, 64);
        const A = sampleMatrix(rho);
        let n = 0;
        const s = [], e = [];
        for (let i = 0; i < K; i++) {
            const prf = PRF(ETA1, sigma, n++);
            s.push(samplePolyCBD(prf, ETA1));
            wipe(prf);
        }
        for (let i = 0; i < K; i++) {
            const prf = PRF(ETA1, sigma, n++);
            e.push(samplePolyCBD(prf, ETA1));
            wipe(prf);
        }
        const sHat = s.map(ntt), eHat = e.map(ntt);
        const tHat = [];
        for (let i = 0; i < K; i++) {                  // t̂ ← Â ∘ ŝ + ê
            const as = dotNTT(A[i], sHat);
            tHat.push(polyAdd(as, eHat[i]));
            wipe(as);
        }
        const ekPKE = concatBytes([encodeVector(tHat, 12), rho]);
        const dkPKE = encodeVector(sHat, 12);
        wipe(g, s, e, sHat, eHat);
        return { ekPKE, dkPKE };
    }

    // Алг. 14: K-PKE.Encrypt(ek_PKE, m, r)
    function kpkeEncrypt(ekPKE, m, r) {
        const tHat = decodeVector(ekPKE.subarray(0, 384 * K), 12);
        const rho = ekPKE.subarray(384 * K, 384 * K + 32);
        const A = sampleMatrix(rho);
        let n = 0;
        const y = [], e1 = [];
        for (let i = 0; i < K; i++) {
            const prf = PRF(ETA1, r, n++);
            y.push(samplePolyCBD(prf, ETA1));
            wipe(prf);
        }
        for (let i = 0; i < K; i++) {
            const prf = PRF(ETA2, r, n++);
            e1.push(samplePolyCBD(prf, ETA2));
            wipe(prf);
        }
        const prfE2 = PRF(ETA2, r, n++);
        const e2 = samplePolyCBD(prfE2, ETA2);
        const yHat = y.map(ntt);

        // u ← NTT⁻¹(Âᵀ ∘ ŷ) + e1: (Âᵀ ∘ ŷ)[i] = Σ_j Â[j][i] ∘ ŷ[j]
        const u = [];
        for (let i = 0; i < K; i++) {
            const column = [];
            for (let j = 0; j < K; j++) column.push(A[j][i]);
            const prod = dotNTT(column, yHat);
            const inv = nttInverse(prod);
            u.push(polyAdd(inv, e1[i]));
            wipe(prod, inv);
        }
        // μ ← Decompress_1(ByteDecode_1(m)); v ← NTT⁻¹(t̂ᵀ ∘ ŷ) + e2 + μ
        const mBits = byteDecode(m, 1);
        const mu = decompressPoly(mBits, 1);
        const tProd = dotNTT(tHat, yHat);
        const tInv = nttInverse(tProd);
        const ve2 = polyAdd(tInv, e2);
        const v = polyAdd(ve2, mu);

        const uCompressed = u.map(p => compressPoly(p, DU));
        const vCompressed = compressPoly(v, DV);
        const c1 = encodeVector(uCompressed, DU);
        const c2 = byteEncode(vCompressed, DV);
        wipe(prfE2, y, e1, e2, yHat, u, mBits, mu, tProd, tInv, ve2, v, uCompressed, vCompressed);
        return concatBytes([c1, c2]);
    }

    // Алг. 15: K-PKE.Decrypt(dk_PKE, c)
    function kpkeDecrypt(dkPKE, c) {
        const c1 = c.subarray(0, 32 * DU * K);
        const c2 = c.subarray(32 * DU * K, 32 * (DU * K + DV));
        const uPrime = decodeVector(c1, DU).map(p => decompressPoly(p, DU));
        const vPrime = decompressPoly(byteDecode(c2, DV), DV);
        const sHat = decodeVector(dkPKE, 12);
        const uHat = uPrime.map(ntt);
        const prod = dotNTT(sHat, uHat);                // ŝᵀ ∘ NTT(u′)
        const inv = nttInverse(prod);
        const w = polySub(vPrime, inv);                 // w ← v′ − NTT⁻¹(ŝᵀ ∘ NTT(u′))
        const wCompressed = compressPoly(w, 1);
        const m = byteEncode(wCompressed, 1);           // m ← ByteEncode_1(Compress_1(w))
        wipe(sHat, prod, inv, w, wCompressed);
        return m;
    }

    // ===================== ML-KEM (FIPS 203, §6, алг. 16–18) =====================

    // Алг. 16: ML-KEM.KeyGen_internal(d, z)
    function keygenInternal(d, z) {
        const { ekPKE, dkPKE } = kpkeKeyGen(d);
        const dk = new Uint8Array(SECRET_KEY_BYTES);  // dk ← dk_PKE ‖ ek ‖ H(ek) ‖ z
        dk.set(dkPKE, 0);
        dk.set(ekPKE, 384 * K);
        dk.set(H(ekPKE), 768 * K + 32);
        dk.set(z, 768 * K + 64);
        wipe(dkPKE);
        return { ek: ekPKE, dk };
    }

    // Алг. 17: ML-KEM.Encaps_internal(ek, m)
    function encapsInternal(ek, m) {
        const g = G(m, H(ek));                          // (K, r) ← G(m ‖ H(ek))
        const sharedKey = g.slice(0, 32);
        const c = kpkeEncrypt(ek, m, g.subarray(32, 64));
        wipe(g);
        return { K: sharedKey, c };
    }

    // Алг. 18: ML-KEM.Decaps_internal(dk, c)
    function decapsInternal(dk, c) {
        const dkPKE = dk.subarray(0, 384 * K);
        const ekPKE = dk.subarray(384 * K, 768 * K + 32);
        const h = dk.subarray(768 * K + 32, 768 * K + 64);
        const z = dk.subarray(768 * K + 64, 768 * K + 96);
        const mPrime = kpkeDecrypt(dkPKE, c);
        const g = G(mPrime, h);                         // (K′, r′) ← G(m′ ‖ h)
        const kBar = J(z, c);                           // K̄ ← J(z ‖ c)
        const cPrime = kpkeEncrypt(ekPKE, mPrime, g.subarray(32, 64));
        // if c ≠ c′ then K′ ← K̄ — без ветвления: маска 0xff при c = c′
        const eq = ctEqualMask(c, cPrime);
        const out = new Uint8Array(SHARED_SECRET_BYTES);
        for (let i = 0; i < SHARED_SECRET_BYTES; i++) out[i] = (g[i] & eq) | (kBar[i] & ~eq);
        wipe(mPrime, g, kBar, cPrime);
        return out;
    }

    // ===================== Публичный API (FIPS 203, §7, алг. 19–21) =====================

    // §7.2, modulus check: ByteEncode_12(ByteDecode_12(ek[0:384k])) = ek[0:384k]
    function ekPassesModulusCheck(ek) {
        const encoded = ek.subarray(0, 384 * K);
        const test = encodeVector(decodeVector(encoded, 12), 12);
        return ctEqualMask(test, encoded) === 0xff;
    }

    // Алг. 19 (ML-KEM.KeyGen): seed = d ‖ z — тот же формат, что `raw-seed`
    // в WebCrypto. Без seed берутся случайные 64 байта (как в самом алг. 19).
    function keygen(seed) {
        if (seed === undefined) seed = randomBytes(SEED_BYTES);
        checkBytes(seed, SEED_BYTES, 'seed');
        const { ek, dk } = keygenInternal(seed.subarray(0, 32), seed.subarray(32, 64));
        return { publicKey: ek, secretKey: dk };
    }

    // Алг. 20 (ML-KEM.Encaps) с проверкой ключа из §7.2. m — только для
    // детерминированных тестов; в протоколе он всегда случайный.
    function encapsulate(publicKey, m) {
        checkBytes(publicKey, PUBLIC_KEY_BYTES, 'publicKey');
        if (!ekPassesModulusCheck(publicKey)) throw new Error('MLKEM: публичный ключ не прошёл modulus check (коэффициент ≥ q)');
        if (m === undefined) m = randomBytes(32);
        checkBytes(m, 32, 'm');
        const { K: sharedSecret, c } = encapsInternal(publicKey, m);
        return { ciphertext: c, sharedSecret };
    }

    // Алг. 21 (ML-KEM.Decaps) с проверками из §7.3. Неверный, но правильно
    // оформленный шифртекст НЕ приводит к ошибке: возвращается псевдослучайный
    // K̄ (implicit rejection), и расхождение ключей проявится уже в протоколе.
    function decapsulate(secretKey, ciphertext) {
        checkBytes(ciphertext, CIPHERTEXT_BYTES, 'ciphertext');
        checkBytes(secretKey, SECRET_KEY_BYTES, 'secretKey');
        const test = H(secretKey.subarray(384 * K, 768 * K + 32));
        if (ctEqualMask(test, secretKey.subarray(768 * K + 32, 768 * K + 64)) !== 0xff) {
            throw new Error('MLKEM: секретный ключ повреждён (не прошёл hash check)');
        }
        return decapsInternal(secretKey, ciphertext);
    }

    return {
        keygen,
        encapsulate,
        decapsulate,
        sha3_256,
        sha3_512,
        shake128,
        shake256,
        PUBLIC_KEY_BYTES,
        SECRET_KEY_BYTES,
        CIPHERTEXT_BYTES,
        SEED_BYTES,
        SHARED_SECRET_BYTES,
        // для тестов: полный перебор Compress/Decompress и потоковый squeeze
        _internal: {
            compress: (f, d) => compressPoly(f, d),
            decompress: (f, d) => decompressPoly(f, d),
            xof,
        },
    };
});
