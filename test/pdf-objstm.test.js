'use strict';
// Тесты PDF со сжатыми object streams, сжатым XMP, /Encrypt и /ID
// (public/media-sanitizer.js, пункт 8.2 плана). PDF собираются здесь же через
// zlib: настоящий xref-поток, ObjStm с Info внутри и без, XMP в трёх видах.
// Результат проверяется независимым разбором xref-потока: каждое смещение
// по-прежнему указывает на "N 0 obj".
// Запуск: node test/pdf-objstm.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const MediaSanitizer = require('../public/media-sanitizer.js');
const { stripMetadataFromFile } = require('../lib/metadata-stripper');

const { MediaSanitizeError } = MediaSanitizer._internal;
const PDF = 'application/pdf';

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

// ===================== Сборка PDF =====================

const bytes = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p, 'latin1'))));

const XMP = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
    + '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description>'
    + '<dc:creator>Ivan Petrov</dc:creator><xmp:CreatorTool>Secret Writer 9</xmp:CreatorTool>'
    + '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>';

class PdfBuilder {
    constructor(header = '%PDF-1.5\n%\xE2\xE3\xCF\xD3\n') {
        this.chunks = [];
        this.len = 0;
        this.offsets = new Map(); // номер объекта → смещение
        this.inStm = new Map();   // номер объекта → [ObjStm, индекс]
        this.maxNum = 0;
        this.push(header);
    }
    push(...parts) {
        for (const p of parts) {
            const b = Buffer.isBuffer(p) ? p : Buffer.from(p, 'latin1');
            this.chunks.push(b);
            this.len += b.length;
        }
        return this;
    }
    obj(num, body) {
        this.offsets.set(num, this.len);
        this.maxNum = Math.max(this.maxNum, num);
        return this.push(`${num} 0 obj\n`, body, '\nendobj\n');
    }
    stream(num, dict, data, { length } = {}) {
        this.lastStreamLength = data.length;
        return this.obj(num, bytes(`<< ${dict} /Length ${length === undefined ? data.length : length} >>\nstream\n`, data, '\nendstream'));
    }
    // items: [{ num, body }] — объекты, которые уходят внутрь потока.
    objStm(num, items, { filter = '/Filter /FlateDecode', compress = true, length, extra = '' } = {}) {
        let header = '';
        let bodies = '';
        for (const it of items) { header += `${it.num} ${bodies.length} `; bodies += it.body + '\n'; }
        const payload = Buffer.from(header + bodies, 'latin1');
        const data = compress ? zlib.deflateSync(payload) : payload;
        this.stream(num, `/Type /ObjStm /N ${items.length} /First ${header.length} ${filter} ${extra}`, data, { length });
        items.forEach((it, idx) => { this.inStm.set(it.num, [num, idx]); this.maxNum = Math.max(this.maxNum, it.num); });
        return this;
    }
    // Завершает файл xref-потоком (без сжатия, чтобы тесты читали его без распаковки).
    finish({ root = 1, info, id, extra = '', xnum } = {}) {
        const xrefNum = xnum || this.maxNum + 1;
        const size = Math.max(this.maxNum, xrefNum) + 1;
        const xoff = this.len;
        this.offsets.set(xrefNum, xoff);
        const rows = [];
        for (let n = 0; n < size; n++) {
            const row = Buffer.alloc(7);
            if (n === 0) { row[0] = 0; row.writeUInt16BE(65535, 5); }
            else if (this.offsets.has(n)) { row[0] = 1; row.writeUInt32BE(this.offsets.get(n), 1); }
            else if (this.inStm.has(n)) { row[0] = 2; row.writeUInt32BE(this.inStm.get(n)[0], 1); row.writeUInt16BE(this.inStm.get(n)[1], 5); }
            rows.push(row);
        }
        const data = Buffer.concat(rows);
        const dict = `/Type /XRef /Size ${size} /W [1 4 2] /Root ${root} 0 R${info ? ` /Info ${info} 0 R` : ''}${id ? ` /ID ${id}` : ''} ${extra}`;
        this.push(`${xrefNum} 0 obj\n<< ${dict} /Length ${data.length} >>\nstream\n`, data, `\nendstream\nendobj\nstartxref\n${xoff}\n%%EOF\n`);
        return Buffer.concat(this.chunks);
    }
}

// Независимый разбор xref-потока готового файла: [{ num, type, f2, f3 }].
function readXref(pdf) {
    const text = pdf.toString('latin1');
    const sx = Number(text.match(/startxref\n(\d+)/)[1]);
    const head = text.slice(sx, sx + 400);
    assert.ok(/^\d+ 0 obj/.test(head), 'startxref points to the xref stream object');
    const size = Number(head.match(/\/Size (\d+)/)[1]);
    const length = Number(head.match(/\/Length (\d+)/)[1]);
    const dataStart = sx + head.indexOf('stream\n') + 7;
    const rows = [];
    for (let n = 0; n < size; n++) {
        const o = dataStart + n * 7;
        rows.push({ num: n, type: pdf[o], f2: pdf.readUInt32BE(o + 1), f3: pdf.readUInt16BE(o + 5) });
    }
    assert.strictEqual(size * 7, length);
    return rows;
}

function assertOffsetsValid(pdf) {
    for (const r of readXref(pdf)) {
        if (r.type !== 1) continue;
        assert.ok(pdf.toString('latin1', r.f2, r.f2 + 12).startsWith(`${r.num} 0 obj`), `object ${r.num} offset ${r.f2} still valid`);
    }
}

// Данные потока объекта num по xref и его словарю (поток без ссылочной /Length).
function streamData(pdf, num) {
    const row = readXref(pdf).find((r) => r.num === num && r.type === 1);
    const text = pdf.toString('latin1');
    const dictText = text.slice(row.f2, row.f2 + 600);
    const length = Number(dictText.match(/\/Length (\d+)/)[1]);
    const start = row.f2 + dictText.indexOf('stream\n') + 7;
    return { start, length, data: pdf.subarray(start, start + length) };
}

// Классический PDF с таблицей xref и trailer (для проверок /ID в trailer).
function classicPdf(objects, trailer) {
    let body = '%PDF-1.4\n';
    const offsets = [];
    for (const o of objects) { offsets.push(body.length); body += o; }
    const x = body.length;
    body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const off of offsets) body += `${String(off).padStart(10, '0')} 00000 n \n`;
    body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R ${trailer} >>\nstartxref\n${x}\n%%EOF\n`;
    return Buffer.from(body, 'latin1');
}

const CATALOG = '<< /Type /Catalog /Pages 2 0 R >>';
const PAGES = '<< /Type /Pages /Kids [] /Count 0 >>';

// Образцовый файл: каталог и Pages в ObjStm, Info — по параметру.
function sample({ info = 'compressed', infoBody = '<< /Producer (Secret Producer) /Author (Ivan Petrov) /CreationDate (D:20240501123456+03\'00\') >>', xmp = null, id = '[<00112233445566778899AABBCCDDEEFF><FFEEDDCCBBAA99887766554433221100>]', stmExtra = [], objstm = {}, extra = '' } = {}) {
    const b = new PdfBuilder();
    const items = [{ num: 1, body: xmp ? `<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>` : CATALOG }, { num: 2, body: PAGES }];
    if (info === 'compressed') items.push({ num: 3, body: infoBody });
    items.push(...stmExtra);
    b.objStm(4, items, objstm);
    if (info === 'plain') b.obj(3, infoBody);
    if (xmp) {
        const data = xmp.filter === 'flate' ? zlib.deflateSync(Buffer.from(xmp.text, 'latin1')) : Buffer.from(xmp.text, 'latin1');
        const filter = xmp.filter === 'flate' ? '/Filter /FlateDecode' : (xmp.filterDict || '');
        b.stream(5, `/Type /Metadata /Subtype /XML ${filter}`, data, { length: xmp.length });
    }
    return b.finish({ info: info === 'none' ? undefined : 3, id, extra });
}

function sanitize(buf) {
    const input = Buffer.from(buf);
    const out = MediaSanitizer.sanitize(input, PDF);
    assert.ok(input.equals(buf), 'input must not be modified');
    return Buffer.from(out.buffer, out.byteOffset, out.byteLength);
}

function assertRefused(buf, re, { userFacing = true } = {}) {
    assert.throws(() => MediaSanitizer.sanitize(buf, PDF), (err) => {
        assert.ok(err instanceof MediaSanitizeError, `unexpected ${err && err.name}: ${err && err.stack}`);
        if (userFacing) assert.strictEqual(err.userFacing, true, 'userFacing flag');
        if (re) assert.ok(re.test(err.message), `message "${err.message}" must match ${re}`);
        return true;
    });
}

const RESAVE = /Печать → Сохранить как PDF/;

// ===================== Тесты =====================

async function main() {
    console.log('PDF object streams / XMP / Encrypt / ID tests\n');

    // ---- ObjStm ----

    await test('objstm: Info with /Producer and /Author inside a compressed ObjStm → refusal with a user-facing text', async () => {
        const pdf = sample({ info: 'compressed' });
        assert.ok(!pdf.toString('latin1').includes('Secret Producer'), 'fixture really hides the metadata from text search');
        assertRefused(pdf, /сжатые метаданные/);
        assertRefused(pdf, RESAVE);
    });

    await test('objstm: metadata keys in a non-Info object of a compressed ObjStm (bookmark /Title, /Subject) → refusal', async () => {
        for (const body of ['<< /Title (Chapter 1) /Parent 9 0 R >>', '<< /Subject (secret) >>', '<< /Keywords (a b) >>', '<< /ModDate (D:2024) >>', '<< /Creator (X) >>']) {
            assertRefused(sample({ info: 'none', stmExtra: [{ num: 7, body }] }), /сжатые метаданные/);
        }
    });

    await test('objstm: hex-escaped key names (/Au#74hor, /Pro#64ucer) are recognised in compressed and plain dictionaries', async () => {
        assertRefused(sample({ info: 'none', stmExtra: [{ num: 7, body: '<< /Au#74hor (Ivan) >>' }] }), /сжатые метаданные/);
        assertRefused(sample({ info: 'none', stmExtra: [{ num: 7, body: '<< /#50roducer (X) >>' }] }), /сжатые метаданные/);
        const plain = classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, `2 0 obj\n${PAGES}\nendobj\n`, '3 0 obj\n<< /Au#74hor (Ivan Petrov) /#50roducer <49 76 61 6E> >>\nendobj\n'], '/Info 3 0 R');
        const out = sanitize(plain).toString('latin1');
        assert.ok(!out.includes('Ivan Petrov') && !out.includes('49 76 61 6E'), 'escaped keys are blanked in plain dictionaries too');
    });

    await test('objstm: Info reference to an object that exists only inside an ObjStm → refusal even without listed keys', async () => {
        assertRefused(sample({ info: 'compressed', infoBody: '<< /Company (ACME) >>' }), /сжатые метаданные/);
    });

    await test('objstm: dangling /Info reference → refusal', async () => {
        const pdf = new PdfBuilder().obj(1, CATALOG).obj(2, PAGES).finish({ info: 9 });
        assertRefused(pdf, /сжатые метаданные/);
    });

    await test('objstm: compressed ObjStm without metadata is accepted; ObjStm bytes untouched, only /ID changes', async () => {
        const pdf = sample({ info: 'none' });
        const out = sanitize(pdf);
        assert.strictEqual(out.length, pdf.length);
        assertOffsetsValid(out);
        const a = pdf.toString('latin1');
        const bText = out.toString('latin1');
        const idRe = /\/ID \[<([0-9A-Fa-f]+)><([0-9A-Fa-f]+)>\]/;
        const before = a.match(idRe);
        const after = bText.match(idRe);
        assert.ok(after, 'ID keeps its shape');
        assert.notStrictEqual(after[1], before[1]);
        assert.notStrictEqual(after[2], before[2]);
        assert.strictEqual(after[1].length, before[1].length);
        assert.strictEqual(after[2].length, before[2].length);
        // всё остальное — те же байты
        assert.strictEqual(bText.replace(idRe, 'ID'), a.replace(idRe, 'ID'));
    });

    await test('objstm: plain (uncompressed) Info is blanked as before while a clean ObjStm passes; offsets unchanged', async () => {
        const pdf = sample({ info: 'plain' });
        const out = sanitize(pdf);
        const t = out.toString('latin1');
        assert.strictEqual(out.length, pdf.length);
        assert.ok(!t.includes('Secret Producer') && !t.includes('Ivan Petrov') && !t.includes('D:2024'));
        assert.ok(t.includes('/Producer (') && t.includes('/Author ('), 'structure kept');
        assertOffsetsValid(out);
    });

    await test('objstm: /Length as an indirect reference to an uncompressed integer object', async () => {
        const build = (extraItems, lengthValue) => {
            const b = new PdfBuilder();
            b.objStm(4, [{ num: 1, body: CATALOG }, { num: 2, body: PAGES }, ...extraItems], { length: '7 0 R' });
            b.obj(7, String(lengthValue === undefined ? b.lastStreamLength : lengthValue));
            return b.finish({});
        };
        sanitize(build([])); // ссылка разрешена, границы подтверждены словом endstream
        assertRefused(build([{ num: 8, body: '<< /Author (Ivan) >>' }]), /сжатые метаданные/);
        // неверное значение длины и ссылка на несуществующий объект
        assertRefused(build([], 5), /границы потока объектов/);
        const missing = new PdfBuilder();
        missing.objStm(4, [{ num: 1, body: CATALOG }], { length: '99 0 R' });
        assertRefused(missing.finish({}), /границы потока объектов/);
        // ссылка на объект, который сам не целое число
        const notInt = new PdfBuilder();
        notInt.objStm(4, [{ num: 1, body: CATALOG }], { length: '7 0 R' });
        notInt.obj(7, '(12)');
        assertRefused(notInt.finish({}), /границы потока объектов/);
    });

    await test('objstm: unsupported filters, predictors and broken /Length → refusal with the re-save hint', async () => {
        const mk = (opts, items) => new PdfBuilder().objStm(4, items || [{ num: 1, body: CATALOG }], opts).finish({});
        assertRefused(mk({ filter: '/Filter [/ASCII85Decode /FlateDecode]', compress: false }), RESAVE);
        assertRefused(mk({ filter: '/Filter /LZWDecode', compress: false }), RESAVE);
        assertRefused(mk({ filter: '/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 5 >>' }), RESAVE);
        assertRefused(mk({ filter: '/Filter /FlateDecode /DecodeParms 9 0 R' }), RESAVE);
        assertRefused(mk({ filter: '/Filter 5' }), RESAVE);
        assertRefused(mk({ length: 3 }), RESAVE);               // /Length короче данных: слова endstream за ним нет
        assertRefused(mk({ length: 100000 }), RESAVE);          // /Length за концом файла
        assertRefused(mk({ length: 'abc' }), RESAVE);
        // предиктор 1 (нет) и массив с null допустимы
        sanitize(mk({ filter: '/Filter /FlateDecode /DecodeParms << /Predictor 1 >>' }));
        sanitize(mk({ filter: '/Filter [/FlateDecode] /DecodeParms [null]' }));
        // сжатие /FlateDecode, записанное через #-escape, — то же самое имя
        sanitize(mk({ filter: '/Filter /Flate#44ecode' }));
    });

    await test('objstm: corrupt compressed data (bad Adler, truncated, not zlib) → refusal', async () => {
        const clean = zlib.deflateSync(Buffer.from('1 0 1 0 << /Type /Catalog >>'));
        const mk = (data) => {
            const b = new PdfBuilder();
            b.stream(4, '/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode', data);
            return b.finish({});
        };
        sanitize(mk(clean));
        const badAdler = Buffer.from(clean);
        badAdler[badAdler.length - 1] ^= 1;
        assertRefused(mk(badAdler), /Adler/);
        assertRefused(mk(clean.subarray(0, clean.length - 6)), RESAVE);
        assertRefused(mk(Buffer.from('this is not zlib at all')), RESAVE);
    });

    await test('objstm: uncompressed ObjStm (no /Filter) is handled by the text passes: its strings are blanked, a clean one passes', async () => {
        sanitize(new PdfBuilder().objStm(4, [{ num: 1, body: CATALOG }], { filter: '', compress: false }).finish({}));
        const withKey = new PdfBuilder().objStm(4, [{ num: 1, body: CATALOG }, { num: 3, body: '<< /Author (Ivan Petrov) >>' }], { filter: '', compress: false }).finish({});
        // объект 3 не имеет несжатого определения "3 0 obj", но на него нет и ссылки → ключ стёрт текстовым проходом
        const out = sanitize(withKey).toString('latin1');
        assert.ok(!out.includes('Ivan Petrov'));
    });

    await test('objstm: duplicate /Type or /Filter keys make the dictionary ambiguous → refusal', async () => {
        const b = new PdfBuilder();
        b.obj(4, bytes('<< /Type /ObjStm /Type /Font /N 0 /First 0 /Filter /FlateDecode /Length 0 >>\nstream\n\nendstream'));
        assertRefused(b.finish({}), RESAVE);
    });

    await test('objstm: decoy text inside strings ("7 0 obj << /Type /ObjStm") is not treated as an object', async () => {
        const b = new PdfBuilder();
        b.obj(1, '<< /Type /Catalog /Pages 2 0 R /Foo (see 7 0 obj << /Type /ObjStm /Filter /Unknown >> stream) >>');
        b.obj(2, PAGES);
        sanitize(b.finish({}));
    });

    // ---- XMP ----

    await test('xmp: FlateDecode stream is replaced by an empty zlib stream; length, /Length and every xref offset unchanged', async () => {
        const pdf = sample({ info: 'none', xmp: { filter: 'flate', text: XMP } });
        const before = streamData(pdf, 5);
        assert.ok(!pdf.toString('latin1').includes('Ivan Petrov'), 'fixture: compressed');
        assert.ok(zlib.inflateSync(before.data).toString('latin1').includes('Ivan Petrov'));
        const out = sanitize(pdf);
        assert.strictEqual(out.length, pdf.length);
        assertOffsetsValid(out);
        const after = streamData(out, 5);
        assert.strictEqual(after.length, before.length, '/Length unchanged');
        assert.strictEqual(after.start, before.start);
        assert.ok(after.data.subarray(0, 8).equals(Buffer.from('789c030000000001', 'hex')), 'empty zlib stream');
        assert.strictEqual(zlib.inflateSync(after.data.subarray(0, 8)).length, 0, 'inflates to an empty string');
        assert.ok(after.data.subarray(8).every((x) => x === 0), 'the rest of the stream area is zeroed');
        assert.strictEqual(zlib.inflateSync(after.data).length, 0, 'whole area still inflates to an empty string');
        // сама сжатая XMP физически стёрта
        assert.ok(!out.includes(before.data.subarray(10, 40)), 'compressed XMP bytes are gone');
        const t = out.toString('latin1');
        assert.ok(t.slice(after.start + after.length).startsWith('\nendstream'), 'endstream follows the area');
    });

    await test('xmp: uncompressed XMP stream (any /Length, even a wrong one) is blanked up to endstream', async () => {
        for (const length of [undefined, 3, 100000]) {
            const pdf = sample({ info: 'none', xmp: { filter: 'none', text: XMP, length } });
            assert.ok(pdf.toString('latin1').includes('Ivan Petrov'));
            const out = sanitize(pdf);
            const t = out.toString('latin1');
            assert.strictEqual(out.length, pdf.length);
            assert.ok(!t.includes('Ivan Petrov') && !t.includes('Secret Writer') && !t.includes('xmpmeta'), `length ${length}`);
            assertOffsetsValid(out);
        }
    });

    await test('xmp: /Subtype /XML without /Type is recognised; stream with /Length as a reference', async () => {
        const b = new PdfBuilder();
        b.obj(1, CATALOG).obj(2, PAGES);
        const data = zlib.deflateSync(Buffer.from(XMP, 'latin1'));
        b.stream(5, '/Subtype /XML /Filter /FlateDecode', data, { length: '6 0 R' });
        b.obj(6, String(data.length));
        const out = sanitize(b.finish({}));
        const t = out.toString('latin1');
        assert.ok(!out.includes(data.subarray(10, 40)));
        assert.ok(t.includes('/Length 6 0 R'));
        assertOffsetsValid(out);
    });

    await test('xmp: unsupported filter, short or unmeasurable compressed XMP → refusal', async () => {
        const text = XMP;
        assertRefused(sample({ info: 'none', xmp: { filter: 'other', filterDict: '/Filter /LZWDecode', text } }), /метаданные в неподдерживаемом сжатии/);
        assertRefused(sample({ info: 'none', xmp: { filter: 'other', filterDict: '/Filter [/ASCII85Decode /FlateDecode]', text } }), RESAVE);
        // Flate, но поток короче 8 байт (длина пустого zlib)
        const b = new PdfBuilder();
        b.obj(1, CATALOG).obj(2, PAGES).stream(5, '/Type /Metadata /Subtype /XML /Filter /FlateDecode', Buffer.from('abcde'));
        assertRefused(b.finish({}), /слишком короткий/);
        // Flate с неверной /Length: границы неизвестны
        assertRefused(sample({ info: 'none', xmp: { filter: 'flate', text, length: 4 } }), /границы сжатого потока метаданных/);
    });

    // ---- /Encrypt ----

    await test('encrypt: /Encrypt in a classic trailer and in an xref stream → refusal (also with #-escapes)', async () => {
        const classic = classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, `2 0 obj\n${PAGES}\nendobj\n`, '3 0 obj\n<< /Filter /Standard /V 1 /R 2 >>\nendobj\n'], '/Encrypt 3 0 R');
        assertRefused(classic, /зашифрован/);
        assertRefused(sample({ info: 'none', extra: '/Encrypt 9 0 R' }), /зашифрован/);
        assertRefused(sample({ info: 'none', extra: '/Encr#79pt 9 0 R' }), /зашифрован/);
        assertRefused(sample({ info: 'none', extra: '/E#6ecrypt<</V 1>>' }), /зашифрован/);
        // имя, лишь начинающееся с /Encrypt, — не ключ шифрования
        sanitize(sample({ info: 'none', extra: '/EncryptMetadataNote true' }));
    });

    // ---- /ID ----

    await test('id: classic trailer — both hex strings replaced by random hex of the same length; formatting kept', async () => {
        const trailer = '/ID [<AABBCCDDEEFF00112233445566778899> <0123456789abcdef0123456789abcdef>]';
        const pdf = classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, `2 0 obj\n${PAGES}\nendobj\n`], trailer);
        const a = sanitize(pdf).toString('latin1');
        const b = sanitize(pdf).toString('latin1');
        const re = /\/ID \[<([0-9a-f]{32})> <([0-9a-f]{32})>\]/;
        assert.ok(re.test(a), 'shape kept: ' + a.slice(a.indexOf('/ID')));
        assert.ok(!a.includes('AABBCCDD') && !a.includes('0123456789abcdef0123456789abcdef'));
        assert.notStrictEqual(a.match(re)[1], b.match(re)[1], 'every run gives a fresh value');
        assert.strictEqual(sanitize(pdf).length, pdf.length);
    });

    await test('id: equal first elements of several trailers (incremental update) stay equal after replacement', async () => {
        const one = classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, `2 0 obj\n${PAGES}\nendobj\n`], '/ID [<00112233445566778899aabbccddeeff><11111111111111111111111111111111>]');
        const two = classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, `2 0 obj\n${PAGES}\nendobj\n`], '/ID [<00112233445566778899aabbccddeeff><22222222222222222222222222222222>] /Prev 10');
        const out = sanitize(Buffer.concat([one, two])).toString('latin1');
        const ids = [...out.matchAll(/\/ID \[<([0-9a-f]+)><([0-9a-f]+)>\]/g)];
        assert.strictEqual(ids.length, 2);
        assert.strictEqual(ids[0][1], ids[1][1], 'same original → same replacement');
        assert.notStrictEqual(ids[0][2], ids[1][2]);
    });

    await test('id: /ID that cannot be randomised (literal strings, not an array, enormous) → refusal; struct-element /ID strings elsewhere are left alone', async () => {
        const mk = (idValue) => classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, `2 0 obj\n${PAGES}\nendobj\n`], `/ID ${idValue}`);
        assertRefused(mk('[(abc)(def)]'), /\/ID/);
        assertRefused(mk('(abc)'), /\/ID/);
        assertRefused(mk('[<00ZZ><11>]'), /\/ID/);
        assertRefused(mk(`[<${'ab'.repeat(3000)}><00>]`), /слишком длинный/);
        assertRefused(mk('[<0011>'), RESAVE);
        // тегированный PDF: /ID структурного элемента — строка в обычном объекте, не идентификатор файла
        const tagged = classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, '2 0 obj\n<< /Type /StructElem /S /P /ID (node00012) >>\nendobj\n'], '');
        assert.ok(sanitize(tagged).toString('latin1').includes('/ID (node00012)'));
    });

    // ---- Потолки и устойчивость ----

    await test('limits: compression-bomb ObjStm is refused quickly instead of being inflated', async () => {
        const bomb = zlib.deflateSync(Buffer.alloc(1 << 28), { level: 9 });
        const b = new PdfBuilder();
        b.stream(4, '/Type /ObjStm /N 0 /First 0 /Filter /FlateDecode', bomb);
        const pdf = b.finish({});
        const started = Date.now();
        assertRefused(pdf, /потолок/);
        assert.ok(Date.now() - started < 5000, 'refusal is fast');
    });

    await test('limits: 100 MB total inflate budget per file (five 19 MB streams pass, the sixth does not)', async () => {
        const chunk = zlib.deflateSync(Buffer.alloc(19 * 1024 * 1024, 0x20), { level: 9 });
        const mk = (count) => {
            const b = new PdfBuilder();
            for (let i = 0; i < count; i++) b.stream(10 + i, '/Type /ObjStm /N 0 /First 0 /Filter /FlateDecode', chunk);
            return b.finish({});
        };
        sanitize(mk(5));
        assertRefused(mk(6), /потолок/);
    });

    await test('limits: PDF with 200 000 objects is processed in linear time', async () => {
        const parts = ['%PDF-1.4\n'];
        for (let i = 1; i <= 200000; i++) parts.push(`${i} 0 obj\n<< /Type /Annot /Rect [0 0 10 10] /Contents (note ${i}) >>\nendobj\n`);
        parts.push('trailer\n<< /Size 200001 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n');
        const pdf = Buffer.from(parts.join(''), 'latin1');
        const started = Date.now();
        sanitize(pdf);
        assert.ok(Date.now() - started < 10000, `took ${Date.now() - started} ms`);
    });

    await test('limits: nested-decoy and unterminated-dictionary inputs are refused fast (no quadratic behaviour)', async () => {
        let started = Date.now();
        assertRefused(Buffer.from('%PDF-1.5\n' + 'trailer<</A('.repeat(200000), 'latin1'), RESAVE);
        assert.ok(Date.now() - started < 5000, 'unterminated decoys');
        started = Date.now();
        assertRefused(Buffer.from('%PDF-1.5\n' + '1 0 obj <</A ['.repeat(100000), 'latin1'), RESAVE);
        assert.ok(Date.now() - started < 5000, 'unterminated arrays');
        // вложенность глубже допустимой
        assertRefused(Buffer.from('%PDF-1.5\n1 0 obj ' + '<</A '.repeat(200) + '1' + '>>'.repeat(200) + ' endobj', 'latin1'), RESAVE);
        // миллион вложенных строк: дерево не строится, время линейное
        started = Date.now();
        const nested = '%PDF-1.5\n1 0 obj <</A ' + '('.repeat(300000) + ')'.repeat(300000) + '>> endobj\n';
        sanitize(Buffer.from(nested, 'latin1'));
        assert.ok(Date.now() - started < 5000, 'nested strings');
    });

    await test('fuzz: truncated / corrupted PDFs with ObjStm and XMP never fail with anything but MediaSanitizeError', async () => {
        let seed = 0x2468ACE1;
        const rnd = (n) => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed % n; };
        const fixtures = [
            sample({ info: 'none', xmp: { filter: 'flate', text: XMP } }),
            sample({ info: 'plain', xmp: { filter: 'none', text: XMP } }),
            sample({ info: 'compressed' }),
            classicPdf([`1 0 obj\n${CATALOG}\nendobj\n`, '2 0 obj\n<< /Author (x) /Title (y) >>\nendobj\n'], '/Info 2 0 R /ID [<00112233><44556677>]'),
        ];
        let rejected = 0, accepted = 0;
        for (const original of fixtures) {
            for (let iter = 0; iter < 400; iter++) {
                let buf = Buffer.from(original);
                const mode = rnd(4);
                if (mode === 0) buf = buf.subarray(0, rnd(buf.length + 1));
                else if (mode === 1) for (let k = 0, m = 1 + rnd(8); k < m; k++) buf[rnd(buf.length)] = rnd(256);
                else if (mode === 2) { const at = rnd(buf.length); buf.fill(rnd(2) ? 0xFF : 0x00, at, Math.min(buf.length, at + 1 + rnd(16))); }
                else buf = bytes(buf.subarray(0, 40), Buffer.from(Array.from({ length: rnd(300) }, () => rnd(256))), buf.subarray(40 + rnd(60)));
                let out;
                try { out = MediaSanitizer.sanitize(buf, PDF); } catch (err) {
                    assert.ok(err instanceof MediaSanitizeError, `unexpected ${err && err.name}: ${err && err.stack}`);
                    rejected++;
                    continue;
                }
                accepted++;
                assert.strictEqual(out.length, buf.length, 'length never changes');
                MediaSanitizer.sanitize(out, PDF); // результат снова очищается
            }
        }
        assert.ok(rejected > 0 && accepted > 0, `both outcomes occur (rejected ${rejected}, accepted ${accepted})`);
    });

    // ---- Серверный путь (тот же код) ----

    await test('server path: stripMetadataFromFile applies the same rules to PDFs on disk (refusal leaves no temp file; clean PDF is rewritten in place)', async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-pdf-'));
        try {
            const bad = path.join(dir, 'bad.pdf');
            fs.writeFileSync(bad, sample({ info: 'compressed' }));
            const original = fs.readFileSync(bad);
            await assert.rejects(() => stripMetadataFromFile(bad, PDF), /сжатые метаданные/);
            assert.ok(fs.readFileSync(bad).equals(original), 'rejected file is untouched (the caller deletes it)');
            assert.deepStrictEqual(fs.readdirSync(dir), ['bad.pdf'], 'no temporary files left behind');

            const good = path.join(dir, 'good.pdf');
            const pdf = sample({ info: 'none', xmp: { filter: 'flate', text: XMP } });
            fs.writeFileSync(good, pdf);
            await stripMetadataFromFile(good, PDF);
            const out = fs.readFileSync(good);
            assert.strictEqual(out.length, pdf.length);
            assertOffsetsValid(out);
            assert.strictEqual(zlib.inflateSync(streamData(out, 5).data).length, 0);
            assert.deepStrictEqual(fs.readdirSync(dir).sort(), ['bad.pdf', 'good.pdf']);

            const enc = path.join(dir, 'enc.pdf');
            fs.writeFileSync(enc, sample({ info: 'none', extra: '/Encrypt 9 0 R' }));
            await assert.rejects(() => stripMetadataFromFile(enc, PDF), /зашифрован/);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
