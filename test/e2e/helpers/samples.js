'use strict';
// Образцы файлов для сквозных тестов вложений: минимальные, но настоящие
// контейнеры (сервер не просто смотрит на тип, а снимает метаданные —
// заглушка из нулей до этого бы не дошла).
//
// Звуковые образцы — только «голова» файла с верной сигнатурой: сервер обязан
// отказать по ТИПУ, ещё не глядя в содержимое, и тест должен показать, что
// отказ не зависит от того, насколько файл похож на настоящий.

const zeros = (n) => Buffer.alloc(n);
const latin = (text) => Buffer.from(text, 'latin1');

// ---- Звук (отказ по типу) ----

const MP3_ID3 = Buffer.concat([latin('ID3\x03\x00\x00\x00\x00\x00\x00'), zeros(64)]);
const MP3_FRAME = Buffer.concat([Buffer.from([0xFF, 0xFB, 0x90, 0x00]), zeros(64)]);
const OGG = Buffer.concat([latin('OggS\x00\x02'), zeros(64)]);
const WAV = Buffer.concat([latin('RIFF'), Buffer.from([0x24, 0, 0, 0]), latin('WAVEfmt '), zeros(40)]);
const EBML_STUB = Buffer.concat([Buffer.from([0x1A, 0x45, 0xDF, 0xA3]), zeros(64)]);
const M4A = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), latin('ftypM4A '), zeros(32)]);

// ---- Обычные вложения (проходят) ----

// Минимальный PDF с автором, создателем и XMP — то, что сервер должен вычистить.
function makePdf() {
    const objects = [
        '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>\nendobj\n',
        '2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n',
        '3 0 obj\n<< /Author (Ivan \\(secret\\) Petrov) /Title (Report) >>\nendobj\n',
        '4 0 obj\n<< /Type /Metadata /Subtype /XML /Length 80 >>\nstream\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><dc:creator>Ivan Petrov</dc:creator></x:xmpmeta>\nendstream\nendobj\n',
    ];
    let body = '%PDF-1.4\n';
    const offsets = [];
    for (const obj of objects) { offsets.push(body.length); body += obj; }
    const xrefOffset = body.length;
    body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const off of offsets) body += `${String(off).padStart(10, '0')} 00000 n \n`;
    body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 3 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
    return Buffer.from(body, 'latin1');
}

const GPS = '+55.7558+037.6173/';

// Минимальный MP4 «с телефона»: координаты ©xyz в moov/udta и время съёмки в mvhd.
function makeMp4() {
    const box = (type, ...parts) => {
        const body = Buffer.concat(parts.map(p => (typeof p === 'string' ? latin(p) : p)));
        const head = Buffer.alloc(8);
        head.writeUInt32BE(8 + body.length);
        head.write(type, 4, 'latin1');
        return Buffer.concat([head, body]);
    };
    const mvhd = Buffer.alloc(100);
    mvhd.writeUInt32BE(0xDEADBEEF, 4);
    mvhd.writeUInt32BE(0xCAFEBABE, 8);
    mvhd.writeUInt32BE(1000, 12);
    const xyz = Buffer.concat([Buffer.from([0, GPS.length, 0x15, 0xC7]), latin(GPS)]);
    return Buffer.concat([
        box('ftyp', 'isom', zeros(4), 'isommp42'),
        box('moov', box('mvhd', mvhd), box('udta', box('\xa9xyz', xyz), box('\xa9mod', 'SM-G991B'))),
        box('mdat', Buffer.alloc(64, 0x11)),
    ]);
}

// Минимальный WebM: EBML-заголовок и Segment (Info с названием и программой
// записи, Tracks, Cluster с двумя блоками).
function makeWebm() {
    const idBytes = (id) => {
        const len = id > 0xFFFFFF ? 4 : id > 0xFFFF ? 3 : id > 0xFF ? 2 : 1;
        const b = Buffer.alloc(len);
        b.writeUIntBE(id, 0, len);
        return b;
    };
    const sizeBytes = (n) => {
        let len = 1;
        while (n >= 2 ** (7 * len) - 1) len++;
        const b = Buffer.alloc(len);
        let v = n;
        for (let i = len - 1; i >= 0; i--) { b[i] = v % 256; v = Math.floor(v / 256); }
        b[0] |= 0x80 >> (len - 1);
        return b;
    };
    const el = (id, ...parts) => {
        const body = Buffer.concat(parts.map(p => (typeof p === 'string' ? Buffer.from(p, 'utf8') : p)));
        return Buffer.concat([idBytes(id), sizeBytes(body.length), body]);
    };
    const uint = (id, v, len = 1) => { const b = Buffer.alloc(len); b.writeUIntBE(v, 0, len); return el(id, b); };
    const block = (fill) => el(0xA3, Buffer.from([0x81, 0x00, 0x00, 0x80]), Buffer.alloc(24, fill));
    return Buffer.concat([
        el(0x1A45DFA3, uint(0x4286, 1), el(0x4282, 'webm'), uint(0x4287, 4), uint(0x4285, 2)),
        el(0x18538067,
            el(0x1549A966, uint(0x2AD7B1, 1000000, 3), el(0x4D80, 'Lavf60.3.100'), el(0x5741, 'SecretWriter 1.0'), el(0x7BA9, 'Secret Title')),
            el(0x1654AE6B, el(0xAE, uint(0xD7, 1), uint(0x73C5, 12345, 2), uint(0x83, 1), el(0x86, 'V_VP8'))),
            el(0x1F43B675, uint(0xE7, 0), block(0x5A), block(0x5B))),
    ]);
}

module.exports = { MP3_ID3, MP3_FRAME, OGG, WAV, EBML_STUB, M4A, makePdf, makeMp4, makeWebm, GPS };
