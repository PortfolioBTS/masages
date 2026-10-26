'use strict';
// Общие образцы PDF для тестов санитайзера (юнит test/pdf-objstm.test.js и
// сквозной test/e2e/pdf-upload.e2e.test.js). Собираются через zlib: настоящий
// xref-поток, ObjStm с Info внутри и без, XMP в разных видах. Файл не тест:
// раннер берёт только *.test.js.

const assert = require('assert');
const zlib = require('zlib');

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

// PDF-«бомба» для очистки на сервере (повторное ревью W7, Н0): несколько ObjStm, каждый распаковывается в мегабайты
// пробелов. Файл ~20 КБ на поток, распаковка — streamBytes на поток; по умолчанию 5 × (20 МБ − 64 байта), то есть в
// пределах клиентских бюджетов (20 МБ на поток, 100 МБ на файл) — клиентский санитайзер такой файл принимает.
function objStmBomb({ streams = 5, streamBytes = 20 * 1024 * 1024 - 64 } = {}) {
    const b = new PdfBuilder();
    b.obj(1, CATALOG);
    b.obj(2, PAGES);
    for (let i = 0; i < streams; i++) {
        const num = 3 + i;
        const header = `${100 + i} 0 `;
        const payload = Buffer.alloc(streamBytes, 0x20);
        payload.write(header + '<< >>', 0, 'latin1');
        const data = zlib.deflateSync(payload, { level: 9 });
        b.stream(num, `/Type /ObjStm /N 1 /First ${header.length} /Filter /FlateDecode`, data);
    }
    return b.finish({});
}

module.exports = { bytes, XMP, PdfBuilder, readXref, assertOffsetsValid, streamData, classicPdf, CATALOG, PAGES, sample, objStmBomb };
