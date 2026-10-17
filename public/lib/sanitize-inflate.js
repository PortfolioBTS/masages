// Собственный inflate, RFC 1950 + RFC 1951 (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js, раздел
// «Inflate»: inflateSync, деревья Хаффмана, Adler-32 и три потолка распаковки (INFLATE_MAX_STREAM, INFLATE_MAX_TOTAL,
// INFLATE_MAX_BLOCKS). Нужен разбору PDF, чтобы заглянуть в сжатые потоки (sanitize-pdf.js). Это парсер недоверенных данных:
// потолки и отказы - часть его контракта. Таблица пробелов PDF_WS берётся из sanitize-common.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizeInflate, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'));
    } else {
        root.NyxoSanitizeInflate = factory(root.NyxoSanitizeCommon);
    }
})(typeof self !== 'undefined' ? self : this, function (Common) {
    'use strict';

    const { MediaSanitizeError, fail, need, u32be, toUint8Array, PDF_WS } = Common;

    // ===================== Inflate (RFC 1950 + RFC 1951) =====================
    //
    // Нужен, чтобы заглянуть внутрь сжатых потоков PDF (object streams и XMP).
    // Синхронный и одинаковый в браузере и в Node, поэтому свой, а не
    // DecompressionStream (асинхронный, только браузер) и не zlib (только Node).
    // Это парсер недоверенных данных, поэтому:
    //   - любой некорректный вход даёт MediaSanitizeError, а не "best effort";
    //   - три потолка: на распакованный поток (INFLATE_MAX_STREAM), на всю
    //     распаковку одного файла (INFLATE_MAX_TOTAL, общий бюджет budget.out)
    //     и на число блоков deflate (budget.blocks: пустые блоки стоят
    //     времени, но почти не дают вывода);
    //   - каждая итерация любого цикла съедает хотя бы один бит входа, поэтому
    //     вход конечной длины не может зациклить разбор;
    //   - деревья Хаффмана принимаются только корректные: переподписанное
    //     отвергается всегда, неполное — только как у zlib (единственный код
    //     длины 1), а для алфавита длин кодов — только полное.

    const INFLATE_MAX_STREAM = 20 * 1024 * 1024;
    const INFLATE_MAX_TOTAL = 100 * 1024 * 1024;
    const INFLATE_MAX_BLOCKS = 500000;
    // Коды короче этой длины декодируются одним обращением к таблице, более
    // длинные — по битам (канонический разбор). Таблица маленькая, поэтому её
    // построение на каждый динамический блок дёшево даже для тысяч блоков.
    const INFLATE_FAST_BITS = 9;

    const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    // Строит таблицы декодирования по длинам кодов lens[start .. start+n).
    // allowSingle: допустим неполный код из одного символа длины 1 (так делает
    // zlib для литералов/длин и расстояний). Для кодов длин — всегда полный.
    function buildHuffman(lens, start, n, allowSingle) {
        const count = new Uint16Array(16);
        let used = 0;
        let maxLen = 0;
        for (let i = 0; i < n; i++) {
            const l = lens[start + i];
            count[l]++;
            if (l) { used++; if (l > maxLen) maxLen = l; }
        }
        if (used === 0) return { empty: true };

        let left = 1;
        for (let l = 1; l <= 15; l++) {
            left = (left << 1) - count[l];
            if (left < 0) fail('deflate: переподписанное дерево Хаффмана');
        }
        if (left > 0 && !(allowSingle && used === 1 && maxLen === 1)) fail('deflate: неполное дерево Хаффмана');

        // Символы в каноническом порядке (по длине, затем по номеру).
        const offs = new Uint16Array(17);
        for (let l = 1; l <= 15; l++) offs[l + 1] = offs[l] + count[l];
        const symbols = new Uint16Array(used);
        const next = new Uint16Array(16);
        let code = 0;
        count[0] = 0;
        for (let l = 1; l <= 15; l++) {
            code = (code + count[l - 1]) << 1;
            next[l] = code;
        }
        const fastBits = Math.min(maxLen, INFLATE_FAST_BITS);
        const fast = new Uint16Array(1 << fastBits);
        for (let sym = 0; sym < n; sym++) {
            const l = lens[start + sym];
            if (!l) continue;
            symbols[offs[l]++] = sym;
            let c = next[l]++;
            if (l <= fastBits) {
                let rev = 0; // биты кода идут в потоке старшим вперёд, а читаются младшим
                for (let k = 0; k < l; k++) { rev = (rev << 1) | (c & 1); c >>= 1; }
                const entry = (sym << 4) | l;
                for (let k = rev; k < fast.length; k += 1 << l) fast[k] = entry;
            }
        }
        return { empty: false, fast, fastMask: fast.length - 1, count, symbols };
    }

    let fixedHuffman = null;
    function getFixedHuffman() {
        if (!fixedHuffman) {
            const lit = new Uint8Array(288);
            lit.fill(8, 0, 144); lit.fill(9, 144, 256); lit.fill(7, 256, 280); lit.fill(8, 280, 288);
            const dist = new Uint8Array(32).fill(5);
            fixedHuffman = { lit: buildHuffman(lit, 0, 288, false), dist: buildHuffman(dist, 0, 32, false) };
        }
        return fixedHuffman;
    }

    function adler32(b, len) {
        let a = 1;
        let s = 0;
        for (let i = 0; i < len;) {
            const stop = Math.min(len, i + 5552); // после стольких байт сумма ещё не переполняет 32 бита
            for (; i < stop; i++) { a += b[i]; s += a; }
            a %= 65521;
            s %= 65521;
        }
        return ((s << 16) | a) >>> 0;
    }

    // Распаковывает поток zlib (RFC 1950) целиком, как zlib.inflateSync.
    //   opts.maxOut — потолок распакованного размера (по умолчанию 20 МБ);
    //   opts.budget — общий счётчик { out, blocks } на файл: уменьшается на
    //     фактический вывод и число блоков, исчерпание — отказ;
    //   opts.allowTrailingWhitespace — после Adler-32 допустимы пробельные
    //     байты PDF (перевод строки перед endstream).
    function inflateSync(bytes, opts) {
        const src = toUint8Array(bytes);
        const o = opts || {};
        const budget = o.budget || { out: INFLATE_MAX_TOTAL, blocks: INFLATE_MAX_BLOCKS };
        let maxOut = o.maxOut === undefined ? INFLATE_MAX_STREAM : o.maxOut;
        if (!(Number.isInteger(maxOut) && maxOut >= 0)) throw new MediaSanitizeError('inflate: неверный потолок распаковки');
        maxOut = Math.min(maxOut, budget.out);
        const n = src.length;

        need(src, 0, 2);
        const cmf = src[0];
        const flg = src[1];
        if ((cmf & 0x0F) !== 8) fail('zlib: неизвестный метод сжатия');
        if ((cmf >> 4) > 7) fail('zlib: недопустимый размер окна');
        if (((cmf << 8) | flg) % 31 !== 0) fail('zlib: неверная контрольная сумма заголовка');
        if (flg & 0x20) fail('zlib: предустановленный словарь (FDICT) не поддерживается');

        let pos = 2;
        let bitBuf = 0;
        let bitCnt = 0;
        let cap = Math.min(maxOut, Math.max(4096, Math.min(n * 4, 1 << 20)));
        let out = new Uint8Array(cap);
        let outLen = 0;

        function grow(total) {
            if (total > maxOut) fail('deflate: превышен потолок размера распакованных данных');
            let c = cap;
            while (c < total) c = Math.min(maxOut, c * 2 + 1024);
            const bigger = new Uint8Array(c);
            bigger.set(out.subarray(0, outLen));
            out = bigger;
            cap = c;
        }

        function getBits(k) {
            while (bitCnt < k) {
                if (pos >= n) fail('deflate: неожиданный конец данных');
                bitBuf |= src[pos++] << bitCnt;
                bitCnt += 8;
            }
            const v = bitBuf & ((1 << k) - 1);
            bitBuf >>>= k;
            bitCnt -= k;
            return v;
        }

        // Отбрасывает неполный байт и возвращает во вход целые байты, которые
        // декодер успел прочитать наперёд (stored-блок и Adler-32 идут с границы байта).
        function alignToByte() {
            bitCnt -= bitCnt & 7;
            pos -= bitCnt >> 3;
            bitBuf = 0;
            bitCnt = 0;
        }

        function decodeSym(h) {
            if (h.empty) fail('deflate: обращение к пустому дереву Хаффмана');
            while (bitCnt < 15 && pos < n) {
                bitBuf |= src[pos++] << bitCnt;
                bitCnt += 8;
            }
            const e = h.fast[bitBuf & h.fastMask];
            if (e !== 0) {
                const l = e & 15;
                if (l > bitCnt) fail('deflate: неожиданный конец данных');
                bitBuf >>>= l;
                bitCnt -= l;
                return e >> 4;
            }
            // Длинный код (или недопустимая комбинация битов): канонический разбор по одному биту.
            let code = 0;
            let first = 0;
            let index = 0;
            for (let len = 1; len <= 15; len++) {
                if (len > bitCnt) fail('deflate: неожиданный конец данных');
                code |= (bitBuf >> (len - 1)) & 1;
                const c = h.count[len];
                if (code - c < first) {
                    bitBuf >>>= len;
                    bitCnt -= len;
                    return h.symbols[index + (code - first)];
                }
                index += c;
                first += c;
                first <<= 1;
                code <<= 1;
            }
            return fail('deflate: недопустимый код Хаффмана');
        }

        function inflateBlock(lit, dist) {
            for (;;) {
                const sym = decodeSym(lit);
                if (sym < 256) {
                    if (outLen >= cap) grow(outLen + 1);
                    out[outLen++] = sym;
                    continue;
                }
                if (sym === 256) return;
                const li = sym - 257;
                if (li >= 29) fail('deflate: недопустимый код длины');
                let len = LEN_BASE[li];
                if (LEN_EXTRA[li]) len += getBits(LEN_EXTRA[li]);
                const ds = decodeSym(dist);
                if (ds >= 30) fail('deflate: недопустимый код расстояния');
                let d = DIST_BASE[ds];
                if (DIST_EXTRA[ds]) d += getBits(DIST_EXTRA[ds]);
                if (d > outLen) fail('deflate: расстояние указывает за начало данных');
                if (outLen + len > cap) grow(outLen + len);
                // Копирование побайтно: при d < len области перекрываются намеренно.
                for (let from = outLen - d, k = 0; k < len; k++) out[outLen++] = out[from++];
            }
        }

        for (let last = 0; !last;) {
            if (--budget.blocks < 0) fail('deflate: слишком много блоков');
            last = getBits(1);
            const type = getBits(2);
            if (type === 0) {
                alignToByte();
                need(src, pos, 4);
                const len = src[pos] | (src[pos + 1] << 8);
                const nlen = src[pos + 2] | (src[pos + 3] << 8);
                if ((len ^ 0xFFFF) !== nlen) fail('deflate: неверная длина несжатого блока');
                pos += 4;
                need(src, pos, len);
                if (outLen + len > cap) grow(outLen + len);
                out.set(src.subarray(pos, pos + len), outLen);
                outLen += len;
                pos += len;
            } else if (type === 1) {
                const f = getFixedHuffman();
                inflateBlock(f.lit, f.dist);
            } else if (type === 2) {
                const hlit = getBits(5) + 257;
                const hdist = getBits(5) + 1;
                const hclen = getBits(4) + 4;
                if (hlit > 286 || hdist > 30) fail('deflate: слишком много кодов длины или расстояния');
                const clLens = new Uint8Array(19);
                for (let i = 0; i < hclen; i++) clLens[CODE_LENGTH_ORDER[i]] = getBits(3);
                const clCode = buildHuffman(clLens, 0, 19, false);
                const total = hlit + hdist;
                const lens = new Uint8Array(total);
                for (let i = 0; i < total;) {
                    const sym = decodeSym(clCode);
                    if (sym < 16) { lens[i++] = sym; continue; }
                    let rep;
                    let val = 0;
                    if (sym === 16) {
                        if (i === 0) fail('deflate: повтор длины кода без предыдущей');
                        val = lens[i - 1];
                        rep = 3 + getBits(2);
                    } else if (sym === 17) rep = 3 + getBits(3);
                    else rep = 11 + getBits(7);
                    if (i + rep > total) fail('deflate: длины кодов выходят за заявленное число');
                    lens.fill(val, i, i + rep);
                    i += rep;
                }
                if (lens[256] === 0) fail('deflate: в блоке нет кода конца блока');
                inflateBlock(buildHuffman(lens, 0, hlit, true), buildHuffman(lens, hlit, hdist, true));
            } else {
                fail('deflate: недопустимый тип блока');
            }
        }

        alignToByte();
        need(src, pos, 4);
        const expected = u32be(src, pos);
        pos += 4;
        if (pos < n) {
            let ok = !!o.allowTrailingWhitespace;
            for (let i = pos; ok && i < n; i++) if (!PDF_WS[src[i]]) ok = false;
            if (!ok) fail('zlib: лишние данные после конца потока');
        }
        if (adler32(out, outLen) !== expected) fail('zlib: неверная контрольная сумма Adler-32');
        budget.out -= outLen;
        return outLen === cap ? out : out.slice(0, outLen);
    }

    return Object.freeze({ INFLATE_MAX_STREAM, INFLATE_MAX_TOTAL, INFLATE_MAX_BLOCKS, inflateSync });
});
