'use strict';
// Тесты inflateSync из public/media-sanitizer.js (RFC 1950/1951, свой разбор
// без внешних библиотек). Node zlib здесь — только ОРАКУЛ: им сжимаются
// данные и сверяется результат. Битые потоки собираются вручную мини-кодером
// (BitWriter), чтобы получить именно нужную ошибку: тип блока 3, дистанцию
// за пределами вывода, переподписанное и неполное дерево и т.д.
// Запуск: node test/pdf-inflate.test.js

const assert = require('assert');
const zlib = require('zlib');
const MediaSanitizer = require('../public/media-sanitizer.js');

const { MediaSanitizeError, inflateSync, INFLATE_LIMITS } = MediaSanitizer._internal;

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// ===================== Помощники =====================

let seed = 0x9E3779B9;
function rnd(n) {
    seed ^= seed << 13; seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5; seed >>>= 0;
    return seed % n;
}
function randomBytes(len) { return Buffer.from(Array.from({ length: len }, () => rnd(256))); }
function textBytes(len) {
    const words = ['метаданные', 'object', 'stream', 'Producer', 'xref', 'obj', 'endobj', '/Type', '/Length', 'PDF', '0123456789'];
    let s = '';
    while (s.length < len) s += words[rnd(words.length)] + (rnd(5) === 0 ? '\n' : ' ');
    return Buffer.from(s.slice(0, len), 'utf8');
}

function adler(buf) {
    let a = 1, b = 0;
    for (const x of buf) { a = (a + x) % 65521; b = (b + a) % 65521; }
    return ((b << 16) | a) >>> 0;
}

function assertInflateError(data, opts, re) {
    assert.throws(() => inflateSync(data, opts), (err) => {
        assert.ok(err instanceof MediaSanitizeError, `unexpected ${err && err.name}: ${err && err.stack}`);
        if (re) assert.ok(re.test(err.message), `message "${err.message}" must match ${re}`);
        return true;
    });
}

// Побитовая запись deflate-потока: поля — младшим битом вперёд, коды Хаффмана — старшим.
class BitWriter {
    constructor() { this.bytes = []; this.cur = 0; this.n = 0; }
    bits(value, count) {
        for (let i = 0; i < count; i++) {
            this.cur |= ((value >>> i) & 1) << this.n;
            if (++this.n === 8) { this.bytes.push(this.cur); this.cur = 0; this.n = 0; }
        }
        return this;
    }
    code(value, len) {
        for (let i = len - 1; i >= 0; i--) this.bits((value >>> i) & 1, 1);
        return this;
    }
    align() { if (this.n) { this.bytes.push(this.cur); this.cur = 0; this.n = 0; } return this; }
    raw(buf) { this.align(); for (const b of buf) this.bytes.push(b); return this; }
    toBuffer() { this.align(); return Buffer.from(this.bytes); }
}

// Канонические коды по длинам (RFC 1951, 3.2.2) — независимая от тестируемого кода реализация.
function canonicalCodes(lens) {
    const count = new Array(16).fill(0);
    for (const l of lens) count[l]++;
    count[0] = 0;
    const next = new Array(16).fill(0);
    let code = 0;
    for (let l = 1; l <= 15; l++) { code = (code + count[l - 1]) << 1; next[l] = code; }
    return lens.map((l) => (l ? next[l]++ : -1));
}

const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];

// Заголовок динамического блока. cl — длины алфавита длин кодов (19 штук),
// tokens — последовательность { sym, extra: [значение, битов] } для длин литералов/длин и расстояний.
function dynamicHeader(w, { last = 1, hlit, hdist, cl, tokens }) {
    w.bits(last, 1).bits(2, 2).bits(hlit - 257, 5).bits(hdist - 1, 5).bits(19 - 4, 4);
    for (let i = 0; i < 19; i++) w.bits(cl[CL_ORDER[i]], 3);
    const codes = canonicalCodes(cl);
    for (const t of tokens) {
        w.code(codes[t.sym], cl[t.sym]);
        if (t.extra) w.bits(t.extra[0], t.extra[1]);
    }
}

// Алфавит длин кодов: символы 0..15 по 4 бита (полный код), 16..18 не используются.
const CL_PLAIN = [...new Array(16).fill(4), 0, 0, 0];
const plainTokens = (lens) => lens.map((sym) => ({ sym }));

// Динамический блок целиком. items: { lit } | { len, dist } (len — 3..258, dist — 1..32768).
function dynamicBlock(w, { litLens, distLens, items, last = 1, cl = CL_PLAIN }) {
    dynamicHeader(w, { last, hlit: litLens.length, hdist: distLens.length, cl, tokens: plainTokens([...litLens, ...distLens]) });
    const litCodes = canonicalCodes(litLens);
    const distCodes = canonicalCodes(distLens);
    for (const it of items) {
        if (it.lit !== undefined) { w.code(litCodes[it.lit], litLens[it.lit]); continue; }
        const li = LEN_BASE.findIndex((b, i) => it.len >= b && (i === 28 ? it.len === 258 : it.len < LEN_BASE[i + 1]));
        w.code(litCodes[257 + li], litLens[257 + li]);
        const lenExtraBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0][li];
        if (lenExtraBits) w.bits(it.len - LEN_BASE[li], lenExtraBits);
        const di = DIST_BASE.findIndex((b, i) => it.dist >= b && (i === 29 ? true : it.dist < DIST_BASE[i + 1]));
        w.code(distCodes[di], distLens[di]);
        const distExtraBits = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13][di];
        if (distExtraBits) w.bits(it.dist - DIST_BASE[di], distExtraBits);
    }
    w.code(litCodes[256], litLens[256]);
}

// Оборачивает deflate-поток в zlib: CMF/FLG 78 9C и Adler-32 контрольной суммы expected.
function zlibWrap(deflate, expected) {
    const tail = Buffer.alloc(4);
    tail.writeUInt32BE(adler(expected));
    return Buffer.concat([Buffer.from([0x78, 0x9C]), deflate, tail]);
}

// Длины кодов, дающие в сумме полный код на 256 литералов + конец блока + 2 длины:
// литералы 'a'(97) и 'b'(98) по 2 бита, конец блока 256 — 3 бита, символ 257 (длина 3) — 3 бита.
function smallLitLens(extra = {}) {
    const lens = new Array(258).fill(0);
    lens[97] = 2; lens[98] = 2; lens[256] = 3; lens[257] = 3;
    for (const [k, v] of Object.entries(extra)) lens[k] = v;
    return lens;
}

// ===================== Тесты =====================

async function main() {
    console.log('PDF inflate tests\n');

    // ---- Векторы ----

    await test('vectors: empty stream, fixed Huffman, stored block (hex fixtures)', async () => {
        assert.strictEqual(inflateSync(Buffer.from('789c030000000001', 'hex')).length, 0);
        assert.strictEqual(Buffer.from(inflateSync(Buffer.from('789c4b04000062 0062'.replace(' ', ''), 'hex'))).toString(), 'a');
        // zlib level 0: stored-блок "hello"
        const stored = Buffer.from('7801010500faff68656c6c6f062c0215', 'hex');
        assert.strictEqual(Buffer.from(inflateSync(stored)).toString(), 'hello');
        // Z_FIXED: "abcabcabc" — фиксированные коды плюс обратная ссылка
        const fixed = zlib.deflateSync('abcabcabc', { strategy: zlib.constants.Z_FIXED });
        assert.strictEqual((fixed[2] >> 1) & 3, 1, 'zlib really produced a fixed block');
        assert.strictEqual(Buffer.from(inflateSync(fixed)).toString(), 'abcabcabc');
    });

    await test('vectors: dynamic Huffman block (zlib default on text) and hand-built dynamic block', async () => {
        const text = textBytes(5000);
        const dyn = zlib.deflateSync(text, { level: 9 });
        assert.strictEqual((dyn[2] >> 1) & 3, 2, 'zlib produced a dynamic block');
        assert.ok(Buffer.from(inflateSync(dyn)).equals(text));

        // Блок собран вручную: "ab" + совпадение длины 4 на расстоянии 2 (перекрывающееся копирование) = "ababab".
        // Длины: a=2, b=2, длина 4 (символ 258)=2, конец блока=3, символ 257=3 — сумма ровно 1 (полный код).
        // Дерево расстояний: единственный код длины 1 у символа 1 (расстояние 2) — допустим, как у zlib.
        const w = new BitWriter();
        dynamicBlock(w, {
            litLens: smallLitLens({ 258: 2 }),
            distLens: [0, 1],
            items: [{ lit: 97 }, { lit: 98 }, { len: 4, dist: 2 }],
        });
        assert.strictEqual(Buffer.from(inflateSync(zlibWrap(w.toBuffer(), Buffer.from('ababab')))).toString(), 'ababab');
    });

    await test('single distance code of length 1 is accepted (zlib compatible), empty distance tree is accepted when unused', async () => {
        const w = new BitWriter();
        // литералы без совпадений: дерево расстояний пустое (одна нулевая длина) — допустимо
        dynamicBlock(w, {
            litLens: smallLitLens({ 257: 0 }).map((l, i) => (i === 256 ? 2 : l)),
            distLens: [0],
            items: [{ lit: 97 }, { lit: 98 }, { lit: 97 }],
        });
        // a=2 b=2 eob=2: неполный код (3/4) — запрещён, потому что в нём больше одного символа
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.from('aba')), undefined, /неполное/);

        const lens = new Array(257).fill(0);
        lens[97] = 1; lens[256] = 1; // полный код из двух символов
        const w2 = new BitWriter();
        dynamicBlock(w2, { litLens: lens, distLens: [0], items: [{ lit: 97 }, { lit: 97 }] });
        assert.strictEqual(Buffer.from(inflateSync(zlibWrap(w2.toBuffer(), Buffer.from('aa')))).toString(), 'aa');

        // единственный код расстояния длины 1 (неполный, но допустимый), длина 3 на расстоянии 1
        const lens2 = new Array(258).fill(0);
        lens2[97] = 2; lens2[256] = 2; lens2[257] = 1; // 1/4+1/4+1/2 = 1
        const w3 = new BitWriter();
        dynamicBlock(w3, { litLens: lens2, distLens: [1], items: [{ lit: 97 }, { len: 3, dist: 1 }] });
        assert.strictEqual(Buffer.from(inflateSync(zlibWrap(w3.toBuffer(), Buffer.from('aaaa')))).toString(), 'aaaa');

        // обращение к пустому дереву расстояний — отказ
        const w4 = new BitWriter();
        dynamicHeader(w4, { hlit: 258, hdist: 1, cl: CL_PLAIN, tokens: plainTokens([...lens2, 0]) });
        const litCodes = canonicalCodes(lens2);
        w4.code(litCodes[97], 2).code(litCodes[257], 1); // длина 3, затем символ расстояния из пустого дерева
        w4.bits(0, 3);
        assertInflateError(zlibWrap(w4.toBuffer(), Buffer.from('aaaa')), undefined, /пустому дереву/);
    });

    // ---- Сравнение с zlib ----

    await test('oracle: all zlib levels 0-9 on random, text, repetitive and tiny inputs', async () => {
        const inputs = [
            Buffer.alloc(0), Buffer.from('a'), Buffer.from('ab'), randomBytes(1), randomBytes(100), randomBytes(70000),
            textBytes(3000), textBytes(200000), Buffer.alloc(100000, 0x41), Buffer.alloc(300000, 0),
            Buffer.concat([randomBytes(1000), textBytes(40000), randomBytes(1000), Buffer.alloc(50000, 7)]),
        ];
        for (const input of inputs) {
            for (let level = 0; level <= 9; level++) {
                const packed = zlib.deflateSync(input, { level });
                const got = inflateSync(packed);
                assert.ok(got instanceof Uint8Array);
                assert.ok(Buffer.from(got).equals(input), `level ${level}, ${input.length} bytes`);
            }
        }
    });

    await test('oracle: strategies (filtered, huffman-only, rle, fixed), window bits 9-15, memLevel 1-9', async () => {
        const C = zlib.constants;
        const input = Buffer.concat([textBytes(30000), randomBytes(3000), textBytes(30000)]);
        for (const strategy of [C.Z_DEFAULT_STRATEGY, C.Z_FILTERED, C.Z_HUFFMAN_ONLY, C.Z_RLE, C.Z_FIXED]) {
            for (const windowBits of [9, 10, 12, 15]) {
                for (const memLevel of [1, 5, 9]) {
                    const packed = zlib.deflateSync(input, { strategy, windowBits, memLevel });
                    assert.ok(Buffer.from(inflateSync(packed)).equals(input), `strategy ${strategy}, wbits ${windowBits}, mem ${memLevel}`);
                }
            }
        }
    });

    await test('oracle: random inputs of random sizes (deterministic seed)', async () => {
        for (let i = 0; i < 120; i++) {
            const len = rnd(4) === 0 ? rnd(40) : rnd(60000);
            const kind = rnd(3);
            const input = kind === 0 ? randomBytes(len) : kind === 1 ? textBytes(len) : Buffer.alloc(len, rnd(256));
            const packed = zlib.deflateSync(input, { level: rnd(10) });
            assert.ok(Buffer.from(inflateSync(packed)).equals(input), `iteration ${i}`);
        }
    });

    await test('oracle: result is a copy independent of the input, input is not modified', async () => {
        const packed = Buffer.from(zlib.deflateSync(textBytes(1000)));
        const snapshot = Buffer.from(packed);
        const out = inflateSync(packed);
        assert.ok(packed.equals(snapshot));
        out.fill(0);
        assert.ok(packed.equals(snapshot));
        // Uint8Array и ArrayBuffer на входе тоже принимаются
        assert.ok(Buffer.from(inflateSync(new Uint8Array(packed))).equals(Buffer.from(inflateSync(packed.buffer.slice(packed.byteOffset, packed.byteOffset + packed.length)))));
    });

    await test('trailing whitespace after Adler-32 is accepted only with allowTrailingWhitespace', async () => {
        const input = textBytes(500);
        const packed = Buffer.concat([zlib.deflateSync(input), Buffer.from('\r\n ')]);
        assertInflateError(packed, undefined, /лишние данные/);
        assert.ok(Buffer.from(inflateSync(packed, { allowTrailingWhitespace: true })).equals(input));
        assertInflateError(Buffer.concat([packed, Buffer.from('x')]), { allowTrailingWhitespace: true }, /лишние данные/);
    });

    // ---- Заголовок zlib ----

    await test('zlib header: wrong method, wrong window, bad FCHECK, FDICT, too short', async () => {
        const good = zlib.deflateSync(Buffer.from('hello'));
        const withHeader = (cmf, flg) => Buffer.concat([Buffer.from([cmf, flg]), good.subarray(2)]);
        assertInflateError(withHeader(0x79, 0x9C), undefined, /метод/); // CM = 9
        assertInflateError(withHeader(0x88, 0x1C), undefined, /окна/); // CINFO = 8 (0x8815 % 31 == 0 нужно подобрать)
        assertInflateError(withHeader(0x78, 0x9D), undefined, /контрольная сумма заголовка/);
        // FDICT = 1 с правильным FCHECK: 0x78 0xBB (0x78BB % 31 == 0)
        assert.strictEqual(0x78BB % 31, 0);
        assertInflateError(withHeader(0x78, 0xBB), undefined, /словар/);
        assertInflateError(Buffer.alloc(0), undefined, /конец данных/);
        assertInflateError(Buffer.from([0x78]), undefined, /конец данных/);
        assertInflateError(Buffer.from([0x78, 0x9C]), undefined, /конец данных/);
    });

    await test('invalid arguments: maxOut must be a non-negative integer, input must be bytes', async () => {
        const packed = zlib.deflateSync(Buffer.from('x'));
        for (const bad of [-1, 1.5, NaN, '10', Infinity, null]) assertInflateError(packed, { maxOut: bad }, /потолок/);
        assert.throws(() => inflateSync('not bytes'), (e) => e instanceof MediaSanitizeError);
        assert.throws(() => inflateSync(null), (e) => e instanceof MediaSanitizeError);
    });

    // ---- Битые потоки ----

    await test('corrupt: Adler-32 mismatch, every single-bit flip in the trailer', async () => {
        const packed = Buffer.from(zlib.deflateSync(textBytes(2000)));
        for (let bit = 0; bit < 32; bit++) {
            const bad = Buffer.from(packed);
            bad[packed.length - 4 + (bit >> 3)] ^= 1 << (bit & 7);
            assertInflateError(bad, undefined, /Adler/);
        }
    });

    await test('corrupt: reserved block type 3', async () => {
        const w = new BitWriter().bits(1, 1).bits(3, 2);
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.alloc(0)), undefined, /тип блока/);
    });

    await test('corrupt: stored block with wrong NLEN and truncated stored block', async () => {
        const w = new BitWriter().bits(1, 1).bits(0, 2).align();
        const bad = Buffer.concat([Buffer.from([0x78, 0x9C]), w.toBuffer(), Buffer.from([5, 0, 0xFA, 0xFE]), Buffer.from('hello'), Buffer.alloc(4)]);
        assertInflateError(bad, undefined, /длина несжатого/);
        const short = Buffer.concat([Buffer.from([0x78, 0x9C]), w.toBuffer(), Buffer.from([9, 0, 0xF6, 0xFF]), Buffer.from('hello')]);
        assertInflateError(short, undefined, /конец данных/);
    });

    await test('corrupt: distance reaches before the start of the output (fixed block)', async () => {
        // фиксированный блок: литерал 'a' (код 0x30+0x61 = 8 бит), длина 3 (символ 257, код 7 бит = 1), расстояние 2 (символ 1, 5 бит)
        const w = new BitWriter().bits(1, 1).bits(1, 2);
        w.code(0x30 + 0x61, 8); // 'a'
        w.code(1, 7);           // символ 257: длина 3
        w.code(1, 5);           // символ расстояния 1: расстояние 2, а вывод — один байт
        w.code(0, 7);           // конец блока
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.from('aaaa')), undefined, /расстояние/);
        // то же расстояние 1 — корректно
        const ok = new BitWriter().bits(1, 1).bits(1, 2);
        ok.code(0x30 + 0x61, 8).code(1, 7).code(0, 5).code(0, 7);
        assert.strictEqual(Buffer.from(inflateSync(zlibWrap(ok.toBuffer(), Buffer.from('aaaa')))).toString(), 'aaaa');
    });

    await test('corrupt: distance as the very first symbol and distance larger than the preceding output (dynamic)', async () => {
        const lens = new Array(258).fill(0);
        lens[97] = 2; lens[256] = 2; lens[257] = 1;
        const w = new BitWriter();
        dynamicBlock(w, { litLens: lens, distLens: [1], items: [{ len: 3, dist: 1 }] });
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.from('aaa')), undefined, /расстояние/);
        const w2 = new BitWriter();
        dynamicBlock(w2, { litLens: lens, distLens: new Array(13).fill(0).concat([1]), items: [{ lit: 97 }, { len: 3, dist: 100 }] });
        assertInflateError(zlibWrap(w2.toBuffer(), Buffer.from('aaaa')), undefined, /расстояние/);
    });

    await test('corrupt: invalid length symbols 286/287 and distance symbols 30/31 in a fixed block', async () => {
        // символ 286: 8-битный код 0xC0 + (286-280) = 0xC6
        const a = new BitWriter().bits(1, 1).bits(1, 2).code(0xC0 + 6, 8).code(0, 5).code(0, 7);
        assertInflateError(zlibWrap(a.toBuffer(), Buffer.alloc(0)), undefined, /длины/);
        const b = new BitWriter().bits(1, 1).bits(1, 2).code(0x30 + 0x61, 8).code(1, 7).code(30, 5).code(0, 7);
        assertInflateError(zlibWrap(b.toBuffer(), Buffer.alloc(0)), undefined, /расстояния/);
    });

    await test('corrupt: oversubscribed literal/length tree', async () => {
        const lens = new Array(258).fill(0);
        lens[97] = 1; lens[98] = 1; lens[256] = 1; // три кода длины 1: сумма 3/2 > 1
        const w = new BitWriter();
        dynamicBlock(w, { litLens: lens, distLens: [0], items: [{ lit: 97 }] });
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.from('a')), undefined, /переподписанное/);
    });

    await test('corrupt: oversubscribed code-length tree', async () => {
        const w = new BitWriter();
        const cl = new Array(19).fill(0);
        cl[0] = 1; cl[1] = 1; cl[2] = 1;
        dynamicHeader(w, { hlit: 257, hdist: 1, cl, tokens: [] });
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.alloc(0)), undefined, /переподписанное/);
    });

    await test('corrupt: incomplete code-length tree (even a single code) and incomplete literal tree', async () => {
        const w = new BitWriter();
        const cl = new Array(19).fill(0);
        cl[0] = 1; // единственный код длины 1 — для алфавита длин кодов недопустим
        dynamicHeader(w, { hlit: 257, hdist: 1, cl, tokens: [] });
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.alloc(0)), undefined, /неполное/);

        const lens = new Array(257).fill(0);
        lens[97] = 2; lens[256] = 2; // 1/2 — два кода, но дерево неполное
        const w2 = new BitWriter();
        dynamicBlock(w2, { litLens: lens, distLens: [0], items: [{ lit: 97 }] });
        assertInflateError(zlibWrap(w2.toBuffer(), Buffer.from('a')), undefined, /неполное/);
    });

    await test('corrupt: no end-of-block code, repeat-previous at the start, run past the declared count, too many symbols', async () => {
        const noEob = new Array(257).fill(0);
        noEob[97] = 1; noEob[98] = 1;
        const w = new BitWriter();
        dynamicHeader(w, { hlit: 257, hdist: 1, cl: CL_PLAIN, tokens: plainTokens([...noEob, 0]) });
        assertInflateError(zlibWrap(w.toBuffer(), Buffer.alloc(0)), undefined, /конца блока/);

        // символ 16 (повтор предыдущей) как первая длина: алфавит длин {0: 1 бит, 16: 1 бит}
        const clRep = new Array(19).fill(0);
        clRep[0] = 1; clRep[16] = 1;
        const w2 = new BitWriter();
        dynamicHeader(w2, { hlit: 257, hdist: 1, cl: clRep, tokens: [{ sym: 16, extra: [0, 2] }] });
        assertInflateError(zlibWrap(w2.toBuffer(), Buffer.alloc(0)), undefined, /повтор длины/);

        // повтор нулей (символ 18) выходит за 258 длин
        const clRun = new Array(19).fill(0);
        clRun[18] = 1; clRun[0] = 1;
        const w3 = new BitWriter();
        dynamicHeader(w3, { hlit: 257, hdist: 1, cl: clRun, tokens: [{ sym: 18, extra: [127, 7] }, { sym: 18, extra: [127, 7] }, { sym: 18, extra: [127, 7] }] });
        assertInflateError(zlibWrap(w3.toBuffer(), Buffer.alloc(0)), undefined, /выходят за заявленное число/);

        // HLIT = 287 (31 + 257) и HDIST = 31 + 1 больше допустимого (286 и 30)
        const w4 = new BitWriter().bits(1, 1).bits(2, 2).bits(30, 5).bits(0, 5).bits(0, 4);
        assertInflateError(zlibWrap(w4.toBuffer(), Buffer.alloc(0)), undefined, /слишком много кодов/);
        const w5 = new BitWriter().bits(1, 1).bits(2, 2).bits(0, 5).bits(30, 5).bits(0, 4);
        assertInflateError(zlibWrap(w5.toBuffer(), Buffer.alloc(0)), undefined, /слишком много кодов/);
    });

    await test('corrupt: every proper prefix of valid streams (stored, fixed, dynamic) is rejected', async () => {
        const inputs = [textBytes(300), Buffer.from('hello'), Buffer.alloc(0), randomBytes(200)];
        const variants = [{ level: 0 }, { level: 9 }, { level: 6, strategy: zlib.constants.Z_FIXED }];
        for (const input of inputs) {
            for (const v of variants) {
                const packed = zlib.deflateSync(input, v);
                for (let cut = 0; cut < packed.length; cut++) assertInflateError(packed.subarray(0, cut));
            }
        }
    });

    await test('fuzz: mutated streams — never anything but MediaSanitizeError, and agree with zlib whenever zlib accepts the stream', async () => {
        const bases = [textBytes(2000), randomBytes(500), Buffer.alloc(3000, 5), Buffer.concat([textBytes(500), randomBytes(100)])]
            .flatMap((b) => [zlib.deflateSync(b, { level: 9 }), zlib.deflateSync(b, { level: 0 }), zlib.deflateSync(b, { strategy: zlib.constants.Z_FIXED })]);
        let rejected = 0, accepted = 0;
        for (const base of bases) {
            for (let iter = 0; iter < 400; iter++) {
                const buf = Buffer.from(base);
                const mode = rnd(3);
                if (mode === 0) buf[rnd(buf.length)] ^= 1 << rnd(8);
                else if (mode === 1) for (let k = 0, m = 1 + rnd(4); k < m; k++) buf[rnd(buf.length)] = rnd(256);
                else buf.fill(rnd(256), rnd(buf.length), Math.min(buf.length, rnd(buf.length) + rnd(8)));
                let mine, theirs;
                try { mine = Buffer.from(inflateSync(buf, { maxOut: 1 << 20 })); } catch (err) {
                    assert.ok(err instanceof MediaSanitizeError, `unexpected ${err && err.name}: ${err && err.stack}`);
                    rejected++;
                }
                try { theirs = zlib.inflateSync(buf); } catch (_) { /* zlib тоже отказал */ }
                if (mine) {
                    accepted++;
                    assert.ok(theirs && theirs.equals(mine), 'accepted stream must inflate identically in zlib');
                } else if (theirs) {
                    assert.fail('zlib accepts a stream that was rejected here');
                }
            }
        }
        assert.ok(rejected > 100, `rejected ${rejected}`);
    });

    await test('fuzz: random garbage never crashes and never hangs', async () => {
        const started = Date.now();
        for (let i = 0; i < 3000; i++) {
            const junk = randomBytes(rnd(300));
            // половину прогонов начинаем с корректного заголовка zlib, чтобы дойти до разбора блоков
            const buf = rnd(2) ? Buffer.concat([Buffer.from([0x78, 0x9C]), junk]) : junk;
            try { inflateSync(buf, { maxOut: 1 << 20 }); } catch (err) {
                assert.ok(err instanceof MediaSanitizeError, `unexpected ${err && err.name}: ${err && err.stack}`);
            }
        }
        assert.ok(Date.now() - started < 30000, 'finishes quickly');
    });

    // ---- Потолки ----

    await test('limits: documented defaults', async () => {
        assert.strictEqual(INFLATE_LIMITS.stream, 20 * 1024 * 1024);
        assert.strictEqual(INFLATE_LIMITS.total, 100 * 1024 * 1024);
        assert.ok(INFLATE_LIMITS.blocks > 0);
    });

    await test('limits: maxOut — exact size passes, one byte less is a refusal', async () => {
        const input = textBytes(5000);
        const packed = zlib.deflateSync(input);
        assert.ok(Buffer.from(inflateSync(packed, { maxOut: input.length })).equals(input));
        assertInflateError(packed, { maxOut: input.length - 1 }, /потолок/);
        assertInflateError(packed, { maxOut: 0 }, /потолок/);
        assert.strictEqual(inflateSync(zlib.deflateSync(Buffer.alloc(0)), { maxOut: 0 }).length, 0);
        // stored-блок тоже под потолком
        assertInflateError(zlib.deflateSync(input, { level: 0 }), { maxOut: 100 }, /потолок/);
    });

    await test('limits: compression bomb (1 GB of zeros, ~1 MB of input) stops at the default 20 MB ceiling without allocating more', async () => {
        const bomb = zlib.deflateSync(Buffer.alloc(1 << 30), { level: 9 });
        assert.ok(bomb.length < 2 * 1024 * 1024, `bomb is small (${bomb.length})`);
        const before = process.memoryUsage().arrayBuffers;
        const started = Date.now();
        assertInflateError(bomb, undefined, /потолок/);
        assert.ok(Date.now() - started < 5000, 'refusal is fast');
        assert.ok(process.memoryUsage().arrayBuffers - before < 64 * 1024 * 1024, 'no allocation above the ceiling');
    });

    await test('limits: a stream of exactly 20 MB passes by default, quickly', async () => {
        const input = Buffer.alloc(INFLATE_LIMITS.stream, 0);
        for (let i = 0; i < input.length; i += 4096) input[i] = i & 255;
        const packed = zlib.deflateSync(input, { level: 6 });
        const started = Date.now();
        const out = inflateSync(packed);
        assert.strictEqual(out.length, input.length);
        assert.ok(Buffer.from(out).equals(input));
        assert.ok(Date.now() - started < 5000, `20 MB inflates in ${Date.now() - started} ms`);
        const over = zlib.deflateSync(Buffer.alloc(INFLATE_LIMITS.stream + 1, 1));
        assertInflateError(over, undefined, /потолок/);
    });

    await test('limits: shared budget — total output across streams and total number of blocks', async () => {
        const part = zlib.deflateSync(Buffer.alloc(600000, 3));
        const budget = { out: 1000000, blocks: 1000 };
        assert.strictEqual(inflateSync(part, { budget }).length, 600000);
        assert.strictEqual(budget.out, 400000, 'budget is decreased by the real output');
        assertInflateError(part, { budget }, /потолок/);

        // пустые stored-блоки: каждый почти ничего не выдаёт, но стоит времени
        const w = new BitWriter();
        for (let i = 0; i < 50; i++) { w.bits(0, 1).bits(0, 2).align(); w.raw([0, 0, 0xFF, 0xFF]); }
        w.bits(1, 1).bits(1, 2).code(0, 7);
        const many = zlibWrap(w.toBuffer(), Buffer.alloc(0));
        assert.strictEqual(inflateSync(many, { budget: { out: 10, blocks: 51 } }).length, 0);
        assertInflateError(many, { budget: { out: 10, blocks: 50 } }, /слишком много блоков/);
    });

    await test('limits: a million empty blocks are refused by the default block budget, not processed', async () => {
        const w = new BitWriter();
        const emptyStored = [0x00, 0x00, 0x00, 0xFF, 0xFF]; // заголовок BFINAL=0, BTYPE=00, затем LEN=0, NLEN=0xFFFF
        const bytes = [0x78, 0x9C];
        for (let i = 0; i < 1000000; i++) bytes.push(...emptyStored);
        void w;
        const started = Date.now();
        assertInflateError(Buffer.from(bytes), undefined, /слишком много блоков/);
        assert.ok(Date.now() - started < 5000);
    });

    await test('performance: tiny dynamic blocks (the expensive case) are bounded by the block budget', async () => {
        // каждый динамический блок строит таблицы; 500 000 таких блоков не должны занять заметное время
        const lens = new Array(257).fill(0);
        lens[256] = 1; lens[97] = 1;
        const one = new BitWriter();
        dynamicBlock(one, { litLens: lens, distLens: [0], items: [], last: 0 });
        const block = one.toBuffer();
        const bytes = [0x78, 0x9C];
        for (let i = 0; i < 1000; i++) for (const b of block) bytes.push(b);
        const started = Date.now();
        try { inflateSync(Buffer.from(bytes), { budget: { out: 1000, blocks: 600 } }); } catch (err) {
            assert.ok(err instanceof MediaSanitizeError);
        }
        assert.ok(Date.now() - started < 2000);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
