// Прозрачность ключей: формулы и проверки без сети и без хранилища
// (docs/security/key-transparency.md, разделы 5, 7.2, 11).
//
// Файл исполняется в трёх местах и обязан давать одни и те же байты везде:
//   * в браузере (window.NyxoKt) — проверки клиента (public/lib/kt-client.js);
//   * на сервере (lib/kt-log.js) — построение дерева, цепочка, подписи;
//   * в Node-тестах (test/kt-verify.test.js) — контрольные векторы раздела 5.
// Поэтому формулы лежат ровно в одном месте: расхождение клиента и сервера в
// одном байте превратило бы каждое доказательство в «несоответствие».
//
// Хэш — SHA-256. В браузере WebCrypto отдаёт его только асинхронно, а одна
// проверка доказательства — 128 хэшей, самомониторинг за поколение — десятки
// тысяч, поэтому здесь свой синхронный SHA-256 (проверяется против
// node:crypto на случайных входах, test/kt-verify.test.js). Серверу этот
// модуль отдаёт хэш из node:crypto через create({ sha256 }).
//
// Подпись Ed25519 проверяет WebCrypto, но ключи малого порядка и неканоничные
// кодировки платформа принимает, поэтому проверка ключа и подписи явная
// (раздел 11): isValidLogKey и isCanonicalSignature.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoKt = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ===================== Константы протокола =====================

    // Глубина дерева в битах метки: метка — 16 байт.
    const DEPTH = 128;
    const LABEL_BYTES = 16;
    const HASH_BYTES = 32;
    const NONCE_BYTES = 16;
    const KEY_BYTES = 32;
    const SIG_BYTES = 64;
    // Эпоха — час UTC; поколение — 720 эпох (30 суток); льготный срок
    // предыдущего поколения — 336 эпох (14 суток). Это константы протокола, не
    // настройки (раздел 6.4): клиент проверяет, что сервер их соблюдает.
    const EPOCH_SECONDS = 3600;
    const GEN_EPOCHS = 720;
    const GRACE_EPOCHS = 336;
    // k обязательств одной метки в эпохе входит в value как u16be(k).
    const MAX_ENTRIES_PER_LEAF = 65535;

    // ===================== SHA-256 =====================

    const K256 = new Uint32Array(64);
    const H256 = new Uint32Array(8);
    (function initSha256Constants() {
        // Дробные части корней первых простых чисел (FIPS 180-4, 4.2.2 и 5.3.3).
        let n = 0;
        for (let c = 2; n < 64; c++) {
            let prime = true;
            for (let d = 2; d * d <= c; d++) {
                if (c % d === 0) { prime = false; break; }
            }
            if (!prime) continue;
            if (n < 8) H256[n] = Math.floor((Math.sqrt(c) % 1) * 4294967296);
            K256[n] = Math.floor((Math.cbrt(c) % 1) * 4294967296);
            n++;
        }
    })();

    const W256 = new Int32Array(64);

    function pureSha256(data) {
        const len = data.length;
        const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
        padded.set(data);
        padded[len] = 0x80;
        const view = new DataView(padded.buffer);
        const bits = len * 8;
        view.setUint32(padded.length - 8, Math.floor(bits / 4294967296));
        view.setUint32(padded.length - 4, bits >>> 0);
        let h0 = H256[0] | 0, h1 = H256[1] | 0, h2 = H256[2] | 0, h3 = H256[3] | 0;
        let h4 = H256[4] | 0, h5 = H256[5] | 0, h6 = H256[6] | 0, h7 = H256[7] | 0;
        const w = W256;
        for (let off = 0; off < padded.length; off += 64) {
            for (let i = 0; i < 16; i++) w[i] = view.getInt32(off + i * 4);
            for (let i = 16; i < 64; i++) {
                const x = w[i - 15];
                const y = w[i - 2];
                const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
                const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
            }
            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (let i = 0; i < 64; i++) {
                const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                const ch = (e & f) ^ (~e & g);
                const t1 = (h + S1 + ch + K256[i] + w[i]) | 0;
                const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const t2 = (S0 + maj) | 0;
                h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
            h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
        }
        const out = new Uint8Array(32);
        const ov = new DataView(out.buffer);
        [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => ov.setInt32(i * 4, v));
        return out;
    }

    // ===================== Байты =====================

    function concat(...parts) {
        let len = 0;
        for (const p of parts) len += p.length;
        const out = new Uint8Array(len);
        let off = 0;
        for (const p of parts) { out.set(p, off); off += p.length; }
        return out;
    }

    function u32be(n) {
        const out = new Uint8Array(4);
        new DataView(out.buffer).setUint32(0, n >>> 0);
        return out;
    }

    function u16be(n) {
        const out = new Uint8Array(2);
        new DataView(out.buffer).setUint16(0, n);
        return out;
    }

    // Метки домена — ASCII (в том числе с нулевым байтом).
    function ascii(str) {
        const out = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
        return out;
    }

    function bytesEqual(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    // Лексикографическое сравнение (как сравнение BYTEA в Postgres).
    function compareBytes(a, b) {
        const n = Math.min(a.length, b.length);
        for (let i = 0; i < n; i++) {
            if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
        }
        return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
    }

    const HEX = '0123456789abcdef';
    function toHex(bytes) {
        let out = '';
        for (let i = 0; i < bytes.length; i++) out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
        return out;
    }

    function fromHex(hex) {
        if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new TypeError('kt: неверный hex');
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }

    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const B64_INDEX = (() => {
        const map = new Int16Array(128).fill(-1);
        for (let i = 0; i < B64.length; i++) map[B64.charCodeAt(i)] = i;
        return map;
    })();

    function b64encode(bytes) {
        let out = '';
        let i = 0;
        for (; i + 2 < bytes.length; i += 3) {
            const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
        }
        const rem = bytes.length - i;
        if (rem === 1) {
            const n = bytes[i] << 16;
            out += B64[n >> 18] + B64[(n >> 12) & 63] + '==';
        } else if (rem === 2) {
            const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
            out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '=';
        }
        return out;
    }

    // Строгий разбор: стандартный алфавит, обязательное «=», канонические биты.
    // Возвращает Uint8Array или null; len — ожидаемая длина (необязательно).
    function b64decode(str, len) {
        if (typeof str !== 'string' || str.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(str)) return null;
        const pad = str.endsWith('==') ? 2 : (str.endsWith('=') ? 1 : 0);
        const out = new Uint8Array((str.length / 4) * 3 - pad);
        let o = 0;
        for (let i = 0; i < str.length; i += 4) {
            const c = [0, 1, 2, 3].map(k => (str[i + k] === '=' ? 0 : B64_INDEX[str.charCodeAt(i + k)]));
            const n = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3];
            if (o < out.length) out[o++] = n >> 16;
            if (o < out.length) out[o++] = (n >> 8) & 255;
            if (o < out.length) out[o++] = n & 255;
        }
        if (b64encode(out) !== str) return null;
        if (len !== undefined && out.length !== len) return null;
        return out;
    }

    // ===================== Проверка ключа и подписи Ed25519 (раздел 11) =====================

    // Ключ журнала и подпись проверяются явно: платформенный verify принимает
    // точки малого порядка и неканоничные кодировки.
    //
    // Запрещённые кодировки публичного ключа (RFC 8032, 5.1.3): y ≥ p (p = 2^255 − 19)
    // и десять кодировок, чей x либо нулевой, либо лежит в подгруппе порядка 8:
    //   y = 1 (порядок 1) и y = p − 1 (порядок 2) — каждая и со знаковым битом, и без
    //   (со знаковым битом при x = 0 кодировка ещё и неканоническая);
    //   y = 0 (порядок 4) — со знаковым битом и без;
    //   четыре точки порядка 8 — по две на два значения y.
    const SMALL_ORDER_KEYS = [
        '0100000000000000000000000000000000000000000000000000000000000000',
        '0100000000000000000000000000000000000000000000000000000000000080',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    ].map(fromHex);

    // y (255 бит, little-endian, без знакового бита) < p?
    function isCanonicalY(bytes) {
        if ((bytes[31] & 0x7f) !== 0x7f) return true;
        for (let i = 30; i >= 1; i--) if (bytes[i] !== 0xff) return true;
        return bytes[0] < 0xed;
    }

    function isValidLogKey(pub) {
        if (!(pub instanceof Uint8Array) || pub.length !== KEY_BYTES) return false;
        if (!isCanonicalY(pub)) return false;
        return !SMALL_ORDER_KEYS.some(bad => bytesEqual(bad, pub));
    }

    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const ED25519_L = fromHex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');

    // S < L и точка R подписи каноническая (y < p).
    function isCanonicalSignature(sig) {
        if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) return false;
        if (!isCanonicalY(sig.subarray(0, 32))) return false;
        for (let i = 31; i >= 0; i--) {
            const s = sig[32 + i];
            if (s !== ED25519_L[i]) return s < ED25519_L[i];
        }
        return false; // S == L
    }

    async function verifyEd25519(pub, message, sig) {
        if (!isValidLogKey(pub) || !isCanonicalSignature(sig)) return false;
        const subtle = typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle;
        if (!subtle) return false;
        try {
            const key = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
            return await subtle.verify({ name: 'Ed25519' }, key, sig, message);
        } catch {
            return false;
        }
    }

    // ===================== Формулы раздела 5 =====================

    const LABEL_LABEL = ascii('nyxo-kt-label-v1');
    const LABEL_COMMIT = ascii('nyxo-kt-commit-v1');
    const LABEL_VALUE = ascii('nyxo-kt-value-v1');
    const LABEL_GENESIS = ascii('nyxo-kt-genesis-v1');
    const LABEL_HEAD = ascii('nyxo-kt-head-v1');
    // Подписи: метка ‖ NUL ‖ поля фиксированной длины.
    const LABEL_STH = ascii('nyxo-kt-sth-v1\0');
    const LABEL_SKT = ascii('nyxo-kt-skt-v1\0');
    const LABEL_KEYCHANGE = ascii('nyxo-kt-keychange-v1\0');

    // Фабрика: hash — функция (Uint8Array) → Uint8Array(32). По умолчанию
    // собственный SHA-256; серверу передаётся хэш из node:crypto.
    function create(options) {
        const hash = options && typeof options.sha256 === 'function' ? options.sha256 : pureSha256;
        const H = (data) => {
            const out = hash(data);
            return out instanceof Uint8Array ? out : new Uint8Array(out);
        };

        // E_0 = 32 нулевых байта; E_{h+1} = node(E_h, E_h) — пустое поддерево высоты h.
        const empties = [new Uint8Array(HASH_BYTES)];
        function emptyHash(height) {
            if (!Number.isInteger(height) || height < 0 || height > DEPTH) throw new RangeError('kt: высота вне 0..128');
            while (empties.length <= height) {
                const prev = empties[empties.length - 1];
                empties.push(nodeHash(prev, prev));
            }
            return empties[height];
        }

        // label(u) = SHA-256("nyxo-kt-label-v1" ‖ u32be(u))[0..16]
        function label(userId) {
            return H(concat(LABEL_LABEL, u32be(userId))).slice(0, LABEL_BYTES);
        }

        // commit = SHA-256("nyxo-kt-commit-v1" ‖ u32be(u) ‖ signPub ‖ dhPub ‖ nonce)
        function commit(userId, signPub, dhPub, nonce) {
            if (signPub.length !== KEY_BYTES || dhPub.length !== KEY_BYTES || nonce.length !== NONCE_BYTES) {
                throw new RangeError('kt: длины ключей или nonce неверны');
            }
            return H(concat(LABEL_COMMIT, u32be(userId), signPub, dhPub, nonce));
        }

        // value = SHA-256("nyxo-kt-value-v1" ‖ u16be(k) ‖ c₁ ‖ … ‖ cₖ); c — по возрастанию.
        function valueHash(commits) {
            const k = commits.length;
            if (k < 1 || k > MAX_ENTRIES_PER_LEAF) throw new RangeError('kt: число обязательств метки вне 1..65535');
            return H(concat(LABEL_VALUE, u16be(k), ...commits));
        }

        // leaf(L, v) = SHA-256(0x00 ‖ L ‖ v);  node(l, r) = SHA-256(0x01 ‖ l ‖ r)
        function leafHash(lbl, value) {
            return H(concat(new Uint8Array([0]), lbl, value));
        }
        function nodeHash(left, right) {
            return H(concat(new Uint8Array([1]), left, right));
        }

        // genesis(g) = SHA-256("nyxo-kt-genesis-v1" ‖ u32be(g) ‖ finalHead_{g−1}); для g = 1 — 32 нулевых байта.
        function genesisHash(gen, prevFinalHead) {
            return H(concat(LABEL_GENESIS, u32be(gen), prevFinalHead));
        }

        // head(g, e) = SHA-256("nyxo-kt-head-v1" ‖ u32be(g) ‖ u32be(e) ‖ head(g, e−1) ‖ smtRoot(g, e));
        // для первой эпохи поколения head(g, e−1) := genesis(g).
        function headHash(gen, epoch, prevHead, smtRoot) {
            return H(concat(LABEL_HEAD, u32be(gen), u32be(epoch), prevHead, smtRoot));
        }

        // Головы эпох from…from+roots.length−1 по корням; prev — голова перед from
        // (для первой эпохи поколения — genesis).
        function extendChain(prev, gen, fromEpoch, roots) {
            const heads = [];
            let cur = prev;
            for (let i = 0; i < roots.length; i++) {
                cur = headHash(gen, fromEpoch + i, cur, roots[i]);
                heads.push(cur);
            }
            return heads;
        }

        // ---- Дерево: доказательство для метки ----

        // Бит i метки: i = 0 — старший бит первого байта.
        function bitOf(bytes, i) {
            return (bytes[i >> 3] >> (7 - (i & 7))) & 1;
        }

        function popcount(bytes) {
            let n = 0;
            for (let i = 0; i < bytes.length; i++) {
                let v = bytes[i];
                while (v) { n += v & 1; v >>= 1; }
            }
            return n;
        }

        // Корень, к которому сворачивается доказательство, либо null, если оно
        // построено неверно (раздел 5, «Доказательство для метки L»):
        //   entries  — обязательства метки в эпохе (пусто — доказательство отсутствия);
        //             строго по возрастанию байт, не больше 65535;
        //   bitmap   — ceil(depth/8) байт; бит i установлен, если брат на глубине i+1 не пуст;
        //   siblings — хэши непустых братьев по возрастанию i.
        // depth — только для тестов малых деревьев (по умолчанию 128).
        function proofRoot(lbl, entries, bitmap, siblings, depth) {
            const d = depth === undefined ? DEPTH : depth;
            if (!Number.isInteger(d) || d < 1 || d > DEPTH) return null;
            if (!(lbl instanceof Uint8Array) || lbl.length !== LABEL_BYTES) return null;
            if (!Array.isArray(entries) || !Array.isArray(siblings)) return null;
            if (!(bitmap instanceof Uint8Array) || bitmap.length !== Math.ceil(d / 8)) return null;
            if (entries.length > MAX_ENTRIES_PER_LEAF) return null;
            for (let i = 0; i < entries.length; i++) {
                const c = entries[i];
                if (!(c instanceof Uint8Array) || c.length !== HASH_BYTES) return null;
                if (i > 0 && compareBytes(entries[i - 1], c) >= 0) return null;
            }
            // Биты за пределами глубины (последний байт, если d не кратно 8) нулевые.
            if (d % 8 !== 0 && (bitmap[bitmap.length - 1] & (0xff >> (d % 8))) !== 0) return null;
            if (siblings.length !== popcount(bitmap)) return null;
            for (const s of siblings) {
                if (!(s instanceof Uint8Array) || s.length !== HASH_BYTES) return null;
            }
            let cur = entries.length === 0 ? emptyHash(0) : leafHash(lbl, valueHash(entries));
            let next = siblings.length;
            for (let i = d - 1; i >= 0; i--) {
                const sibling = bitOf(bitmap, i) ? siblings[--next] : emptyHash(d - 1 - i);
                cur = bitOf(lbl, i) === 0 ? nodeHash(cur, sibling) : nodeHash(sibling, cur);
            }
            return cur;
        }

        // ---- Сообщения для подписей ----

        function sthMessage(gen, epoch, head) {
            return concat(LABEL_STH, u32be(gen), u32be(epoch), head);
        }
        function sktMessage(gen, epoch, lbl, commitment) {
            return concat(LABEL_SKT, u32be(gen), u32be(epoch), lbl, commitment);
        }
        function keychangeMessage(newPub, gen, epoch) {
            return concat(LABEL_KEYCHANGE, newPub, u32be(gen), u32be(epoch));
        }

        return {
            hash: H, emptyHash, label, commit, valueHash, leafHash, nodeHash,
            genesisHash, headHash, extendChain, bitOf, popcount, proofRoot,
            sthMessage, sktMessage, keychangeMessage,
        };
    }

    // Сравнение позиций журнала (поколение, эпоха).
    function comparePos(a, b) {
        return a.gen !== b.gen ? (a.gen < b.gen ? -1 : 1) : (a.epoch === b.epoch ? 0 : (a.epoch < b.epoch ? -1 : 1));
    }

    const api = create();
    api.create = create;
    Object.assign(api, {
        DEPTH, LABEL_BYTES, HASH_BYTES, NONCE_BYTES, KEY_BYTES, SIG_BYTES,
        EPOCH_SECONDS, GEN_EPOCHS, GRACE_EPOCHS, MAX_ENTRIES_PER_LEAF,
        pureSha256, concat, u32be, u16be, ascii, bytesEqual, compareBytes, toHex, fromHex, b64encode, b64decode,
        isCanonicalY, isValidLogKey, isCanonicalSignature, verifyEd25519, comparePos,
        SMALL_ORDER_KEYS,
    });
    return api;
});
