'use strict';
// Тесты public/media-sanitizer.js: синтетические файлы каждого формата с
// метаданными собираются прямо здесь, результат проверяется НЕЗАВИСИМЫМИ
// разборщиками (свои парсеры боксов/EBML/страниц OGG/RIFF, побитовый CRC)
// и, для изображений, декодированием через sharp.
// Запуск: node test/media-sanitizer.test.js

const assert = require('assert');
const zlib = require('zlib');
const sharp = require('sharp');
const MediaSanitizer = require('../public/media-sanitizer.js');

const { MediaSanitizeError } = MediaSanitizer._internal;

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

// ===================== Общие помощники =====================

function bytes(...parts) {
    return Buffer.concat(parts.map((p) => {
        if (typeof p === 'string') return Buffer.from(p, 'latin1');
        if (Buffer.isBuffer(p)) return p;
        return Buffer.from(p);
    }));
}
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u16le = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const zeros = (n) => Buffer.alloc(n);

function run(buf, mime) {
    const input = Buffer.from(buf);
    const out = MediaSanitizer.sanitize(input, mime);
    assert.ok(out instanceof Uint8Array, 'result must be a Uint8Array');
    assert.ok(input.equals(buf), 'input must not be modified');
    return Buffer.from(out.buffer, out.byteOffset, out.byteLength);
}

function assertAbsent(buf, needles) {
    const text = buf.toString('latin1');
    for (const s of needles) assert.ok(!text.includes(s), `"${s}" must be gone`);
}

function assertRejects(buf, mime) {
    assert.throws(() => MediaSanitizer.sanitize(buf, mime), (err) => err instanceof MediaSanitizeError, mime);
}

// ===================== ISO BMFF (MP4 / MOV) =====================

function box(type, ...parts) {
    const body = bytes(...parts);
    return bytes(u32(8 + body.length), type, body);
}
function fullBox(type, version, flags, ...parts) {
    return box(type, Buffer.from([version, (flags >> 16) & 255, (flags >> 8) & 255, flags & 255]), ...parts);
}
const MATRIX = bytes(u32(0x10000), u32(0), u32(0), u32(0), u32(0x10000), u32(0), u32(0), u32(0), u32(0x40000000));

function mvhd(version, ctime, mtime) {
    const times = version === 1 ? bytes(u64(ctime), u64(mtime), u32(1000), u64(1000)) : bytes(u32(ctime), u32(mtime), u32(1000), u32(1000));
    return fullBox('mvhd', version, 0, times, u32(0x10000), u16(0x100), zeros(10), MATRIX, zeros(24), u32(3));
}
function tkhd(version, id, ctime, mtime) {
    const head = version === 1
        ? bytes(u64(ctime), u64(mtime), u32(id), u32(0), u64(1000))
        : bytes(u32(ctime), u32(mtime), u32(id), u32(0), u32(1000));
    return fullBox('tkhd', version, 3, head, zeros(8), u16(0), u16(0), u16(0), u16(0), MATRIX, u32(64 << 16), u32(48 << 16));
}
function mdhd(version, ctime, mtime) {
    const times = version === 1 ? bytes(u64(ctime), u64(mtime), u32(1000), u64(1000)) : bytes(u32(ctime), u32(mtime), u32(1000), u32(1000));
    return fullBox('mdhd', version, 0, times, u16(0x55c4), u16(0));
}
const hdlr = (type) => fullBox('hdlr', 0, 0, u32(0), type, zeros(12), 'Handler\0');
const qtText = (type, s) => box(type, u16(s.length), u16(0x15c7), s);

function stbl({ entry, sizes = [], constSize = 0, count = sizes.length, chunks = [], spc = 1 }) {
    return box('stbl',
        fullBox('stsd', 0, 0, u32(1), box(entry, zeros(8))),
        fullBox('stts', 0, 0, u32(0)),
        chunks.length ? fullBox('stsc', 0, 0, u32(1), u32(1), u32(spc), u32(1)) : fullBox('stsc', 0, 0, u32(0)),
        fullBox('stsz', 0, 0, u32(constSize), u32(count), ...(constSize ? [] : sizes.map(u32))),
        fullBox('stco', 0, 0, u32(chunks.length), ...chunks.map(u32)));
}
function trak({ id, handler, version = 0, times = [0x11111111, 0x22222222], table, extra = [] }) {
    return box('trak', tkhd(version, id, times[0], times[1]),
        box('mdia', mdhd(1, 0x3333333333, 0x4444444444), hdlr(handler), box('minf', stbl(table))), ...extra);
}

const XMP_UUID = Buffer.from('BE7ACFCB97A942E89C71999491E3AFAC', 'hex');
const GPS_SAMPLE = Buffer.from('GPS5 +55.7558+037.6173 alt 150m ........'.slice(0, 40), 'latin1');

// MP4 с телефона: ©xyz и модель устройства в udta, XMP в uuid, старая копия
// метаданных в free, дорожка GoPro-телеметрии (GPS покадрово) и ненулевые
// времена mvhd/tkhd/mdhd. mdatMode: normal | large (size==1) | zero (size==0).
function makeMp4(mdatMode = 'normal') {
    const video = [Buffer.alloc(100, 0x11), Buffer.alloc(100, 0x22)];
    const mdatPayload = bytes(video[0], GPS_SAMPLE, video[1], GPS_SAMPLE);
    const build = (base) => {
        const moov = box('moov',
            mvhd(0, 0xDEADBEEF, 0xCAFEBABE),
            trak({ id: 1, handler: 'vide', table: { entry: 'avc1', sizes: [100, 100], chunks: [base, base + 140] },
                extra: [box('udta', qtText('\xa9nam', 'Secret clip'))] }),
            trak({ id: 2, handler: 'meta', table: { entry: 'gpmd', constSize: 40, count: 2, chunks: [base + 100, base + 240] } }),
            box('udta', qtText('\xa9xyz', '+55.7558+037.6173/'), qtText('\xa9mak', 'samsung'), qtText('\xa9mod', 'SM-G991B')));
        const head = bytes(
            box('ftyp', 'isom', u32(0x200), 'isommp42'),
            moov,
            box('uuid', XMP_UUID, '<x:xmpmeta><exif:GPSLatitude>55,45.3N</exif:GPSLatitude></x:xmpmeta>'),
            box('free', 'old copy: \xa9xyz +55.7558+037.6173/'));
        let mdat;
        if (mdatMode === 'large') mdat = bytes(u32(1), 'mdat', u64(16 + mdatPayload.length), mdatPayload);
        else if (mdatMode === 'zero') mdat = bytes(u32(0), 'mdat', mdatPayload);
        else mdat = box('mdat', mdatPayload);
        return { file: bytes(head, mdat), payloadStart: head.length + (mdatMode === 'large' ? 16 : 8) };
    };
    const first = build(0);
    return { ...build(first.payloadStart), video };
}

const BMFF_CONTAINERS = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl', 'edts', 'moof', 'traf', 'mvex']);

// Независимый разбор дерева боксов: размеры детей должны точно покрывать родителя.
function parseBmff(buf, start = 0, end = buf.length) {
    const out = [];
    let pos = start;
    while (pos < end) {
        assert.ok(end - pos >= 8, 'box header fits');
        let size = buf.readUInt32BE(pos);
        const type = buf.toString('latin1', pos + 4, pos + 8);
        let hdr = 8;
        if (size === 1) { size = Number(buf.readBigUInt64BE(pos + 8)); hdr = 16; } else if (size === 0) size = end - pos;
        assert.ok(size >= hdr && pos + size <= end, `box ${type} fits its parent`);
        const node = { type, start: pos, payload: pos + hdr, end: pos + size };
        if (BMFF_CONTAINERS.has(type)) node.children = parseBmff(buf, pos + hdr, pos + size);
        out.push(node);
        pos += size;
    }
    assert.strictEqual(pos, end, 'children cover the parent exactly');
    return out;
}
function findAll(tree, type, acc = []) {
    for (const n of tree) {
        if (n.type === type) acc.push(n);
        if (n.children) findAll(n.children, type, acc);
    }
    return acc;
}
function assertTimesZero(buf, node) {
    const version = buf[node.payload];
    const len = version === 1 ? 16 : 8;
    assert.ok(buf.subarray(node.payload + 4, node.payload + 4 + len).every((x) => x === 0), `${node.type} times must be zero`);
}
function assertFreeZeroed(buf, node) {
    assert.strictEqual(node.type, 'free');
    assert.ok(buf.subarray(node.payload, node.end).every((x) => x === 0), 'free payload must be zeroed');
}

// ===================== EBML (WebM) =====================

const MKV = {
    EBML: 0x1A45DFA3, SEGMENT: 0x18538067, SEEK_HEAD: 0x114D9B74, SEEK: 0x4DBB, SEEK_ID: 0x53AB, SEEK_POS: 0x53AC,
    INFO: 0x1549A966, TRACKS: 0x1654AE6B, TRACK_ENTRY: 0xAE, CLUSTER: 0x1F43B675, CUES: 0x1C53BB6B,
    ATTACHMENTS: 0x1941A469, CHAPTERS: 0x1043A770, TAGS: 0x1254C367, VOID: 0xEC, CRC32: 0xBF,
    TITLE: 0x7BA9, MUXING_APP: 0x4D80, WRITING_APP: 0x5741, DATE_UTC: 0x4461, TRACK_NAME: 0x536E,
};
const SEGMENT_LEVEL = new Set([MKV.SEEK_HEAD, MKV.INFO, MKV.TRACKS, MKV.CLUSTER, MKV.CUES, MKV.ATTACHMENTS, MKV.CHAPTERS, MKV.TAGS, MKV.VOID]);

function ebmlIdBytes(id) {
    const len = id > 0xFFFFFF ? 4 : id > 0xFFFF ? 3 : id > 0xFF ? 2 : 1;
    const b = Buffer.alloc(len);
    b.writeUIntBE(id, 0, len);
    return b;
}
function ebmlSizeBytes(n) {
    let len = 1;
    while (n >= 2 ** (7 * len) - 1) len++;
    const b = Buffer.alloc(len);
    let v = n;
    for (let i = len - 1; i >= 0; i--) { b[i] = v % 256; v = Math.floor(v / 256); }
    b[0] |= 0x80 >> (len - 1);
    return b;
}
const el = (id, ...parts) => { const body = bytes(...parts); return bytes(ebmlIdBytes(id), ebmlSizeBytes(body.length), body); };
const elUnknown = (id, ...parts) => bytes(ebmlIdBytes(id), Buffer.from([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), ...parts);
const elUnknown1 = (id, ...parts) => bytes(ebmlIdBytes(id), Buffer.from([0xFF]), ...parts); // однобайтовый "неизвестный"
const euint = (id, v, len = 1) => { const b = Buffer.alloc(len); b.writeUIntBE(v, 0, len); return el(id, b); };
function withCrc(id, ...children) {
    const body = bytes(...children);
    return el(id, el(MKV.CRC32, u32le(zlib.crc32(body))), body);
}

const mkvHeader = () => el(MKV.EBML, euint(0x4286, 1), el(0x4282, 'webm'), euint(0x4287, 4), euint(0x4285, 2));
const mkvInfo = () => withCrc(MKV.INFO,
    euint(0x2AD7B1, 1000000, 3),
    el(MKV.MUXING_APP, 'Lavf60.3.100'),
    el(MKV.WRITING_APP, 'SecretWriter 1.0'),
    el(MKV.TITLE, 'Secret Title'),
    el(MKV.DATE_UTC, Buffer.from('0102030405060708', 'hex')));
const mkvTracks = () => el(MKV.TRACKS, el(MKV.TRACK_ENTRY,
    euint(0xD7, 1), euint(0x73C5, 12345, 2), euint(0x83, 2), el(0x86, 'A_OPUS'), el(MKV.TRACK_NAME, 'Ivan mic')));
const mkvBlock = (fill) => el(0xA3, Buffer.from([0x81, 0x00, 0x00, 0x80]), Buffer.alloc(24, fill));
const mkvTags = () => el(MKV.TAGS, el(0x7373, el(0x67C8, el(0x45A3, 'LOCATION'), el(0x4487, '+55.7558+037.6173/'))));
const mkvAttachments = () => el(MKV.ATTACHMENTS, el(0x61A7, el(0x466E, 'cover.jpg'), el(0x465C, 'IVANPHOTO')));
const mkvChapters = () => el(MKV.CHAPTERS, el(0x45B9, el(0xB6, el(0x80, el(0x85, 'Moscow trip')))));
const mkvSeek = (id, pos) => el(MKV.SEEK, el(MKV.SEEK_ID, ebmlIdBytes(id)), euint(MKV.SEEK_POS, pos, 2));

// Вариант A: всё известного размера, CRC-32 в Info.
function makeWebmKnown() {
    return bytes(mkvHeader(), el(MKV.SEGMENT,
        el(MKV.SEEK_HEAD, mkvSeek(MKV.INFO, 100), mkvSeek(MKV.TAGS, 300), mkvSeek(MKV.CUES, 400)),
        mkvInfo(), mkvTracks(),
        el(MKV.CLUSTER, euint(0xE7, 0), mkvBlock(0x5A), mkvBlock(0x5B)),
        mkvTags(), mkvAttachments(), mkvChapters()));
}
// Вариант B (как пишет MediaRecorder): Segment и Cluster неизвестного размера,
// Tags после кластеров.
function makeWebmUnknown() {
    return bytes(mkvHeader(), elUnknown(MKV.SEGMENT,
        mkvInfo(), mkvTracks(),
        elUnknown(MKV.CLUSTER, euint(0xE7, 0), mkvBlock(0x5A), mkvBlock(0x5B)),
        elUnknown1(MKV.CLUSTER, euint(0xE7, 20), mkvBlock(0x5C)),
        el(MKV.VOID, zeros(4)),
        elUnknown(MKV.CLUSTER, euint(0xE7, 40), mkvBlock(0x5D)),
        el(MKV.CUES, el(0xBB, euint(0xB3, 0))),
        mkvTags(), mkvChapters()));
}

function readVintT(buf, pos, isId) {
    const first = buf[pos];
    let len = 1;
    while (len <= 8 && !(first & (0x80 >> (len - 1)))) len++;
    assert.ok(len <= (isId ? 4 : 8), 'valid vint');
    const mask = 0xFF >> len;
    let v = isId ? first : first & mask;
    let ones = (first & mask) === mask;
    for (let i = 1; i < len; i++) { v = v * 256 + buf[pos + i]; ones = ones && buf[pos + i] === 0xFF; }
    return { v, len, unknown: !isId && ones };
}
function readElT(buf, pos, end) {
    const id = readVintT(buf, pos, true);
    const sz = readVintT(buf, pos + id.len, false);
    const dataStart = pos + id.len + sz.len;
    if (sz.unknown) return { id: id.v, start: pos, dataStart, end: -1 };
    assert.ok(dataStart + sz.v <= end, 'element fits its parent');
    return { id: id.v, start: pos, dataStart, end: dataStart + sz.v };
}
function childrenT(buf, parent) {
    const out = [];
    let pos = parent.dataStart;
    while (pos < parent.end) { const c = readElT(buf, pos, parent.end); assert.ok(c.end >= 0); out.push(c); pos = c.end; }
    assert.strictEqual(pos, parent.end);
    return out;
}
// Независимый разбор файла: список детей Segment (кластер неизвестного
// размера кончается на ID уровня Segment).
function parseWebm(buf) {
    const header = readElT(buf, 0, buf.length);
    assert.strictEqual(header.id, MKV.EBML);
    const seg = readElT(buf, header.end, buf.length);
    assert.strictEqual(seg.id, MKV.SEGMENT);
    const end = seg.end < 0 ? buf.length : seg.end;
    const kids = [];
    let pos = seg.dataStart;
    while (pos < end) {
        const c = readElT(buf, pos, end);
        if (c.end < 0) {
            assert.strictEqual(c.id, MKV.CLUSTER);
            let p = c.dataStart;
            while (p < end && !SEGMENT_LEVEL.has(readVintT(buf, p, true).v)) p = readElT(buf, p, end).end;
            c.end = p;
        }
        kids.push(c);
        pos = c.end;
    }
    assert.strictEqual(pos, buf.length, 'segment covers the file');
    return kids;
}

// ===================== MP3 =====================

function synchsafe(n) { return Buffer.from([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F]); }
function id3v23(...frames) {
    const body = bytes(...frames, zeros(20)); // + паддинг внутри тега
    return bytes('ID3', Buffer.from([3, 0, 0]), synchsafe(body.length), body);
}
const id3Frame = (id, payload) => { const p = bytes(payload); return bytes(id, u32(p.length), u16(0), p); };
function id3v24WithFooter(...frames) {
    const body = bytes(...frames);
    return bytes('ID3', Buffer.from([4, 0, 0x10]), synchsafe(body.length), body, '3DI', Buffer.from([4, 0, 0x10]), synchsafe(body.length));
}
function mpegFrames(count) {
    const frames = [];
    for (let i = 0; i < count; i++) frames.push(bytes(Buffer.from([0xFF, 0xFB, 0x90, 0x64]), Buffer.alloc(413, 0x55 + i)));
    return bytes(...frames);
}
function apeTag() {
    const items = bytes(u32le(4), u32le(0), 'Artist\0', 'Ivan');
    const size = items.length + 32;
    const hdr = (flags) => bytes('APETAGEX', u32le(2000), u32le(size), u32le(1), u32le(flags), zeros(8));
    return bytes(hdr(0xA0000000), items, hdr(0x80000000));
}
function lyrics3v2() {
    const content = bytes('LYRICSBEGIN', 'IND00002', '10', 'LYR00012', 'Secret lyric');
    return bytes(content, String(content.length).padStart(6, '0'), 'LYRICS200');
}
function id3v1() {
    const pad = (s, n) => Buffer.from(s.padEnd(n, '\0'), 'latin1');
    return bytes('TAG', pad('Secret Moscow', 30), pad('Ivan Petrov', 30), pad('Album', 30), '2024', pad('comment', 30), Buffer.from([12]));
}
const id3v1Plus = () => bytes('TAG+', Buffer.from('Secret extended title'.padEnd(223, '\0'), 'latin1'));

// ===================== OGG =====================

// Побитовый CRC — нарочно не табличный, чтобы не повторять реализацию модуля.
function oggCrcBitwise(buf) {
    let crc = 0;
    for (const byte of buf) {
        crc = (crc ^ (byte << 24)) >>> 0;
        for (let k = 0; k < 8; k++) crc = crc & 0x80000000 ? ((crc << 1) ^ 0x04C11DB7) >>> 0 : (crc << 1) >>> 0;
    }
    return crc >>> 0;
}

// Раскладывает группы пакетов по страницам (каждая группа — с новой
// страницы), не больше 255 сегментов на страницу, продолжение пакета — флаг 0x01.
function oggStream(serial, groups) {
    const pages = [];
    let continued = false;
    for (const group of groups) {
        let segs = [];
        let data = [];
        const flush = () => {
            pages.push({ segs, data: bytes(...data), continued });
            continued = segs[segs.length - 1] === 255;
            segs = [];
            data = [];
        };
        for (const packet of group) {
            let off = 0;
            for (;;) {
                const lace = Math.min(255, packet.length - off);
                segs.push(lace);
                data.push(packet.subarray(off, off + lace));
                off += lace;
                if (segs.length === 255) flush();
                if (lace < 255) break;
            }
        }
        if (segs.length) flush();
    }
    return bytes(...pages.map((p, i) => {
        const flags = (p.continued ? 1 : 0) | (i === 0 ? 2 : 0) | (i === pages.length - 1 ? 4 : 0);
        const header = Buffer.alloc(27);
        header.write('OggS', 0, 'latin1');
        header[5] = flags;
        header.writeBigUInt64LE(BigInt(i < 2 ? 0 : i * 960), 6);
        header.writeUInt32LE(serial, 14);
        header.writeUInt32LE(i, 18);
        header[26] = p.segs.length;
        const page = bytes(header, Buffer.from(p.segs), p.data);
        page.writeUInt32LE(oggCrcBitwise(page), 22);
        return page;
    }));
}

function vorbisComments(vendor, comments) {
    return bytes(u32le(vendor.length), vendor, u32le(comments.length), ...comments.map((c) => bytes(u32le(c.length), c)));
}
const OGG_PICTURE = 'METADATA_BLOCK_PICTURE=' + 'SXZhbiBQZXRyb3YgcGhvdG8g'.repeat(3400); // ~80 КБ, 2+ страницы
function makeOpus(serial = 0x1234) {
    const head = bytes('OpusHead', Buffer.from([1, 1]), u16le(312), u32le(48000), u16le(0), Buffer.from([0]));
    const tags = bytes('OpusTags', vorbisComments('libopus 1.4 SecretVendor',
        ['TITLE=Secret Title', 'LOCATION=+55.7558+037.6173', OGG_PICTURE]), Buffer.from([0x01]), 'IVAN-BINARY');
    const audio = [0, 1, 2].map((i) => Buffer.alloc(60, 0xA0 + i));
    return { file: oggStream(serial, [[head], [tags], audio]), head, audio };
}
function makeVorbis(serial = 0x5678) {
    const ident = bytes('\x01vorbis', u32le(0), Buffer.from([1]), u32le(44100), u32le(0), u32le(128000), u32le(0), Buffer.from([0xB8, 1]));
    const comment = bytes('\x03vorbis', vorbisComments('Xiph.Org libVorbis SecretVendor',
        ['ARTIST=Ivan Petrov', 'GPS=+55.7558+037.6173', 'LYRICS=' + 'Secret words '.repeat(6000)]), Buffer.from([1]));
    const setup = bytes('\x05vorbis', Buffer.alloc(300, 0x42));
    const audio = [0, 1].map((i) => Buffer.alloc(80, 0xB0 + i));
    return { file: oggStream(serial, [[ident], [comment, setup], audio]), ident, setup, audio };
}

// Независимый разбор: страницы (CRC побитово) и пакеты по serial.
function parseOgg(buf) {
    const pages = [];
    const packets = new Map();
    const partial = new Map();
    let pos = 0;
    while (pos < buf.length) {
        assert.strictEqual(buf.toString('latin1', pos, pos + 4), 'OggS');
        const nseg = buf[pos + 26];
        const lacing = [...buf.subarray(pos + 27, pos + 27 + nseg)];
        const end = pos + 27 + nseg + lacing.reduce((a, b) => a + b, 0);
        assert.ok(end <= buf.length, 'page fits the file');
        const page = Buffer.from(buf.subarray(pos, end));
        const stored = page.readUInt32LE(22);
        page.writeUInt32LE(0, 22);
        assert.strictEqual(oggCrcBitwise(page), stored, `page ${pages.length} CRC must be valid`);
        const serial = buf.readUInt32LE(pos + 14);
        pages.push({ start: pos, end, header: Buffer.from(buf.subarray(pos, pos + 27 + nseg)) });
        if (!packets.has(serial)) { packets.set(serial, []); partial.set(serial, []); }
        let off = pos + 27 + nseg;
        for (const lace of lacing) {
            partial.get(serial).push(buf.subarray(off, off + lace));
            off += lace;
            if (lace < 255) { packets.get(serial).push(Buffer.concat(partial.get(serial))); partial.set(serial, []); }
        }
        pos = end;
    }
    return { pages, packets };
}
function checkBlankedComments(p, off, original) {
    const vendorLen = p.readUInt32LE(off);
    assert.strictEqual(vendorLen, original.readUInt32LE(off), 'vendor length kept');
    assert.ok(p.subarray(off + 4, off + 4 + vendorLen).every((x) => x === 0x20), 'vendor blanked with spaces');
    off += 4 + vendorLen;
    const count = p.readUInt32LE(off);
    assert.strictEqual(count, original.readUInt32LE(off), 'comment count kept');
    off += 4;
    for (let i = 0; i < count; i++) {
        const len = p.readUInt32LE(off);
        assert.strictEqual(len, original.readUInt32LE(off), 'comment length kept');
        const c = p.toString('latin1', off + 4, off + 4 + len);
        assert.strictEqual(c, 'X=' + ' '.repeat(len - 2));
        off += 4 + len;
    }
    return off;
}

// ===================== RIFF / WAV =====================

const riffChunk = (id, data) => { const d = bytes(data); return bytes(id, u32le(d.length), d, d.length & 1 ? zeros(1) : zeros(0)); };
function makeWav() {
    const fmt = riffChunk('fmt ', bytes(u16le(1), u16le(1), u32le(8000), u32le(16000), u16le(2), u16le(16)));
    const list = riffChunk('LIST', bytes('INFO', riffChunk('INAM', 'Secret Title\0'), riffChunk('IART', 'Ivan Petrov\0')));
    const bextBody = Buffer.alloc(602);
    bextBody.write('Recorded near Moscow', 0, 'latin1');
    bextBody.write('Ivan Petrov', 256, 'latin1');
    bextBody.write('2024-05-01', 320, 'latin1');
    bextBody.write('12:34:56', 330, 'latin1');
    const bext = riffChunk('bext', bextBody);
    const data = riffChunk('data', Buffer.from([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16])); // нечётный размер + pad
    const ixml = riffChunk('iXML', '<BWFXML><PROJECT>Ivan</PROJECT></BWFXML>');
    const body = bytes('WAVE', fmt, list, bext, data, ixml);
    return { file: bytes('RIFF', u32le(body.length), body), fmt, data };
}
function parseRiff(buf) {
    assert.strictEqual(buf.readUInt32LE(4) + 8, buf.length, 'RIFF size matches the file');
    const chunks = [];
    let pos = 12;
    while (pos < buf.length) {
        const id = buf.toString('latin1', pos, pos + 4);
        const size = buf.readUInt32LE(pos + 4);
        assert.ok(pos + 8 + size <= buf.length, `chunk ${id} fits`);
        chunks.push({ id, start: pos, data: buf.subarray(pos + 8, pos + 8 + size), end: Math.min(pos + 8 + size + (size & 1), buf.length) });
        pos = chunks[chunks.length - 1].end;
    }
    assert.strictEqual(pos, buf.length);
    return chunks;
}

// ===================== Изображения =====================

const jpegSeg = (marker, payload) => { const p = bytes(payload); return bytes(Buffer.from([0xFF, marker]), u16(p.length + 2), p); };
const insertAfterSoi = (jpeg, ...segs) => bytes(jpeg.subarray(0, 2), ...segs, jpeg.subarray(2));

// Сегменты до SOS (для проверок результата).
function jpegHeaderSegments(buf) {
    const out = [];
    let pos = 2;
    for (;;) {
        assert.strictEqual(buf[pos], 0xFF);
        const marker = buf[pos + 1];
        const len = buf.readUInt16BE(pos + 2);
        out.push({ marker, data: buf.subarray(pos + 4, pos + 2 + len) });
        if (marker === 0xDA) return out;
        pos += 2 + len;
    }
}

// EXIF little-endian (II): Make, Orientation и указатель на GPS IFD.
function exifII(orientation) {
    const t = Buffer.alloc(78);
    t.write('II', 0, 'latin1');
    t.writeUInt16LE(42, 2);
    t.writeUInt32LE(8, 4);
    t.writeUInt16LE(3, 8);
    const entry = (i, tag, type, count, value) => {
        const e = 10 + i * 12;
        t.writeUInt16LE(tag, e); t.writeUInt16LE(type, e + 2); t.writeUInt32LE(count, e + 4); t.writeUInt32LE(value, e + 8);
    };
    entry(0, 0x010F, 2, 10, 50); // Make -> "SecretCam\0" по смещению 50
    entry(1, 0x0112, 3, 1, orientation);
    entry(2, 0x8825, 4, 1, 60); // GPS IFD по смещению 60
    t.writeUInt32LE(0, 46);
    t.write('SecretCam\0', 50, 'latin1');
    t.writeUInt16LE(1, 60);
    t.writeUInt16LE(0x0001, 62); t.writeUInt16LE(2, 64); t.writeUInt32LE(2, 66); t.write('N\0', 70, 'latin1');
    return bytes('Exif\0\0', t);
}

// Разбор IFD0 из APP1-EXIF результата: [{tag, value}].
function exifIfd0(exif) {
    const t = exif.subarray(6);
    const le = t.toString('latin1', 0, 2) === 'II';
    const r16 = (o) => (le ? t.readUInt16LE(o) : t.readUInt16BE(o));
    const r32 = (o) => (le ? t.readUInt32LE(o) : t.readUInt32BE(o));
    const ifd = r32(4);
    const out = [];
    for (let i = 0; i < r16(ifd); i++) out.push({ tag: r16(ifd + 2 + i * 12), value: r16(ifd + 2 + i * 12 + 8) });
    return out;
}

const pngChunk = (type, data) => { const td = bytes(type, data); return bytes(u32(td.length - 4), td, u32(zlib.crc32(td))); };
function pngChunkTypes(buf) {
    const types = [];
    let pos = 8;
    while (pos < buf.length) {
        const len = buf.readUInt32BE(pos);
        types.push(buf.toString('latin1', pos + 4, pos + 8));
        pos += 12 + len;
    }
    assert.strictEqual(pos, buf.length);
    return types;
}

function gifBlocks(buf) {
    let pos = 13;
    if (buf[10] & 0x80) pos += 3 * (1 << ((buf[10] & 7) + 1));
    const blocks = [];
    const skipSub = (q) => { while (buf[q] !== 0) q += 1 + buf[q]; return q + 1; };
    while (buf[pos] !== 0x3B) {
        if (buf[pos] === 0x2C) {
            let q = pos + 10;
            if (buf[pos + 9] & 0x80) q += 3 * (1 << ((buf[pos + 9] & 7) + 1));
            blocks.push('image');
            pos = skipSub(q + 1);
        } else {
            assert.strictEqual(buf[pos], 0x21);
            const label = buf[pos + 1];
            blocks.push(label === 0xFF ? 'app:' + buf.toString('latin1', pos + 3, pos + 14) : 'ext:' + label.toString(16));
            pos = skipSub(pos + 2);
        }
    }
    assert.strictEqual(pos, buf.length - 1, 'trailer is the last byte');
    return blocks;
}

function webpChunks(buf) {
    const chunks = [];
    let pos = 12;
    while (pos < buf.length) {
        const size = buf.readUInt32LE(pos + 4);
        chunks.push({ id: buf.toString('latin1', pos, pos + 4), data: buf.subarray(pos + 8, pos + 8 + size) });
        pos += 8 + size + (size & 1);
    }
    assert.strictEqual(pos, buf.length);
    return chunks;
}
function riffWebp(...chunks) {
    const body = bytes('WEBP', ...chunks.map((c) => riffChunk(c.id, c.data)));
    return bytes('RIFF', u32le(body.length), body);
}

async function assertDecodes(buf, width, height, pages) {
    const meta = await sharp(buf, { animated: Boolean(pages) }).metadata();
    assert.strictEqual(meta.width, width, 'width preserved');
    assert.strictEqual(pages ? meta.pageHeight : meta.height, height, 'height preserved');
    if (pages) assert.strictEqual(meta.pages, pages, 'all frames preserved');
    const raw = await sharp(buf, { animated: Boolean(pages) }).raw().toBuffer({ resolveWithObject: true });
    assert.strictEqual(raw.info.width, width);
    return meta;
}

// ===================== PDF =====================

function makePdf() {
    const objects = [
        '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R /Outlines 6 0 R >>\nendobj\n',
        '2 0 obj\n<< /Type /Pages /Kids [] /Count 0 /Producer (Secret Producer) /Titles (keep me) >>\nendobj\n',
        '3 0 obj\n<< /Author (Ivan \\(secret\\) Petrov) /Creator <4D7943616D> /Title (Report (draft)) /CreationDate (D:20240501123456+03\'00\') >>\nendobj\n',
        '4 0 obj\n<< /Type /Metadata /Subtype /XML /Length 150 >>\nstream\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><dc:creator>Ivan Petrov</dc:creator></x:xmpmeta>\n<rdf:RDF><rdf:li>Moscow office</rdf:li></rdf:RDF>\nendstream\nendobj\n',
        '5 0 obj\n(Ivan Indirect)\nendobj\n',
        '6 0 obj\n<< /Type /Outlines /Author 5 0 R /Keywords <49 76 61 6E> >>\nendobj\n',
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

// ===================== Тесты =====================

async function main() {
    console.log('Media sanitizer tests\n');

    // ---- API ----

    await test('api: SUPPORTED_TYPES / isSupported / MIME parameters and aliases', async () => {
        assert.deepStrictEqual([...MediaSanitizer.SUPPORTED_TYPES].sort(), [
            'application/pdf', 'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'image/gif', 'image/jpeg',
            'image/png', 'image/webp', 'text/plain', 'video/mp4', 'video/quicktime', 'video/webm',
        ]);
        for (const t of MediaSanitizer.SUPPORTED_TYPES) assert.ok(MediaSanitizer.isSupported(t), t);
        assert.ok(MediaSanitizer.isSupported('audio/webm;codecs=opus'));
        assert.ok(MediaSanitizer.isSupported('Audio/X-WAV'));
        for (const t of ['image/svg+xml', 'text/html', 'application/octet-stream', '', null, undefined, 42]) {
            assert.strictEqual(MediaSanitizer.isSupported(t), false, String(t));
        }
        assert.throws(() => MediaSanitizer.sanitize(new Uint8Array(4), 'image/svg+xml'), /Неподдерживаемый тип/);
        assert.throws(() => MediaSanitizer.sanitize('not bytes', 'text/plain'), (e) => e instanceof MediaSanitizeError);
    });

    await test('text/plain: bytes unchanged, result is a new array', async () => {
        const input = Buffer.from('Привет, Ivan!\n', 'utf8');
        const out = MediaSanitizer.sanitize(input, 'text/plain; charset=utf-8');
        assert.ok(Buffer.from(out).equals(input));
        out[0] = 0;
        assert.notStrictEqual(input[0], 0, 'output must not share memory with input');
    });

    // ---- MP4 / MOV ----

    for (const mode of ['normal', 'large', 'zero']) {
        await test(`mp4 (${mode} mdat): ©xyz/model/XMP/free leftovers/GPS track removed, times zeroed, layout intact`, async () => {
            const { file, video, payloadStart } = makeMp4(mode);
            assert.ok(file.toString('latin1').includes('+55.7558+037.6173/'), 'fixture carries GPS');
            const out = run(file, 'video/mp4');
            assert.strictEqual(out.length, file.length, 'length must not change');
            const tree = parseBmff(out);
            assert.deepStrictEqual(tree.map((n) => n.type), ['ftyp', 'moov', 'free', 'free', 'mdat']);
            assertFreeZeroed(out, tree[2]);
            assertFreeZeroed(out, tree[3]);
            const moov = tree[1].children;
            assert.deepStrictEqual(moov.map((n) => n.type), ['mvhd', 'trak', 'free', 'free'], 'GPS track and udta are free');
            for (const n of moov.slice(2)) assertFreeZeroed(out, n);
            for (const type of ['mvhd', 'tkhd', 'mdhd']) for (const n of findAll(tree, type)) assertTimesZero(out, n);
            assert.strictEqual(findAll(tree, 'tkhd')[0].type, 'tkhd');
            const videoTrak = moov[1];
            assert.deepStrictEqual(videoTrak.children.map((n) => n.type), ['tkhd', 'mdia', 'free']);
            const stco = findAll(videoTrak.children, 'stco')[0];
            assert.strictEqual(out.readUInt32BE(stco.payload + 8), payloadStart, 'chunk offsets unchanged');
            assert.ok(out.subarray(payloadStart, payloadStart + 100).equals(video[0]), 'video samples intact');
            assert.ok(out.subarray(payloadStart + 140, payloadStart + 240).equals(video[1]), 'video samples intact');
            assert.ok(out.subarray(payloadStart + 100, payloadStart + 140).every((x) => x === 0), 'telemetry samples zeroed');
            assertAbsent(out, ['55.7558', 'SM-G991B', 'samsung', 'xmpmeta', 'GPS5', 'Secret clip', 'gpmd']);
            assert.ok(MediaSanitizer.sanitize(out, 'video/mp4').length === out.length, 'idempotent');
        });
    }

    await test('mov: Apple meta/keys ISO6709 + model removed, 64-bit times zeroed', async () => {
        const build = (base) => bytes(
            box('ftyp', 'qt  ', u32(0), 'qt  '),
            box('moov',
                mvhd(1, 0xE0000000AA, 0xE0000000BB),
                trak({ id: 1, handler: 'vide', version: 1, times: [0xE0000000CC, 0xE0000000DD], table: { entry: 'avc1', sizes: [64], chunks: [base] } }),
                box('meta',
                    fullBox('hdlr', 0, 0, u32(0), 'mdta', zeros(12), '\0'),
                    fullBox('keys', 0, 0, u32(2), box('mdta', 'com.apple.quicktime.location.ISO6709'), box('mdta', 'com.apple.quicktime.model')),
                    box('ilst',
                        box('\0\0\0\x01', box('data', u32(1), u32(0), '+55.7558+037.6173+150.000/')),
                        box('\0\0\0\x02', box('data', u32(1), u32(0), 'iPhone 15 Pro'))))),
            box('mdat', Buffer.alloc(64, 0x44)));
        const probe = build(0);
        const file = build(probe.length - 64);
        const out = run(file, 'video/quicktime');
        assert.strictEqual(out.length, file.length);
        const tree = parseBmff(out);
        const moov = tree[1].children;
        assert.deepStrictEqual(moov.map((n) => n.type), ['mvhd', 'trak', 'free']);
        assertFreeZeroed(out, moov[2]);
        for (const type of ['mvhd', 'tkhd', 'mdhd']) for (const n of findAll(tree, type)) assertTimesZero(out, n);
        assert.ok(out.subarray(out.length - 64).every((x) => x === 0x44), 'media data intact');
        assertAbsent(out, ['com.apple.quicktime', '55.7558', 'iPhone']);
    });

    await test('mp4 fragmented: prft and telemetry track removed, fragment samples zeroed via trun/trex', async () => {
        const emptyTable = (entry) => ({ entry, chunks: [] });
        const moov = box('moov',
            mvhd(0, 5, 6),
            trak({ id: 1, handler: 'vide', table: emptyTable('avc1') }),
            trak({ id: 2, handler: 'meta', table: emptyTable('gpmd') }),
            box('mvex',
                fullBox('trex', 0, 0, u32(1), u32(1), u32(0), u32(0), u32(0)),
                fullBox('trex', 0, 0, u32(2), u32(1), u32(0), u32(20), u32(0))));
        const prft = fullBox('prft', 0, 0, u32(1), u64(0xE8F1A2B3C4D5E6F7n), u32(0));
        const moofFor = (x, y) => box('moof',
            fullBox('mfhd', 0, 0, u32(1)),
            box('traf', fullBox('tfhd', 0, 0x20000, u32(1)), fullBox('trun', 0, 0x201, u32(2), u32(x), u32(50), u32(50))),
            box('traf', fullBox('tfhd', 0, 0x20000, u32(2)), fullBox('trun', 0, 0x001, u32(2), u32(y))));
        const moofLen = moofFor(0, 0).length;
        const video = Buffer.alloc(100, 0x33);
        const gps = bytes(GPS_SAMPLE.subarray(0, 20), GPS_SAMPLE.subarray(0, 20));
        const file = bytes(box('ftyp', 'iso6', u32(0), 'iso6'), moov, prft, moofFor(moofLen + 8, moofLen + 108), box('mdat', video, gps));
        const out = run(file, 'video/mp4');
        assert.strictEqual(out.length, file.length);
        const tree = parseBmff(out);
        assert.deepStrictEqual(tree.map((n) => n.type), ['ftyp', 'moov', 'free', 'moof', 'mdat']);
        assert.deepStrictEqual(tree[1].children.map((n) => n.type), ['mvhd', 'trak', 'free', 'mvex']);
        const mdat = tree[4];
        assert.ok(out.subarray(mdat.payload, mdat.payload + 100).equals(video), 'video fragment intact');
        assert.ok(out.subarray(mdat.payload + 100, mdat.end).every((x) => x === 0), 'telemetry fragment zeroed');
        assertAbsent(out, ['GPS5']);
    });

    await test('mp4: broken inputs are rejected', async () => {
        const { file } = makeMp4();
        assertRejects(file.subarray(0, file.length - 10), 'video/mp4'); // обрезан mdat
        assertRejects(box('ftyp', 'isom', u32(0), 'isom'), 'video/mp4'); // нет moov
        assertRejects(Buffer.from('not a video at all, just text'), 'video/mp4');
        const badSize = Buffer.from(file);
        badSize.writeUInt32BE(4, 0); // размер меньше заголовка
        assertRejects(badSize, 'video/mp4');
        // Смещение чанка дорожки метаданных указывает в moov, а не в mdat.
        const evil = Buffer.from(file);
        const stco = findAll(parseBmff(file), 'stco')[1];
        evil.writeUInt32BE(40, stco.payload + 8);
        assertRejects(evil, 'video/mp4');
        const cmov = bytes(box('ftyp', 'qt  ', u32(0), 'qt  '), box('moov', box('cmov', zeros(16))));
        assertRejects(cmov, 'video/quicktime');
    });

    // ---- WebM ----

    await test('webm (known sizes): Tags/Attachments/Chapters -> Void, Info/Track name blanked, CRC-32 recomputed', async () => {
        const file = makeWebmKnown();
        const out = run(file, 'video/webm');
        assert.strictEqual(out.length, file.length);
        const kids = parseWebm(out);
        assert.deepStrictEqual(kids.map((k) => k.id), [MKV.SEEK_HEAD, MKV.INFO, MKV.TRACKS, MKV.CLUSTER, MKV.VOID, MKV.VOID, MKV.VOID]);
        for (const v of kids.slice(4)) assert.ok(out.subarray(v.dataStart, v.end).every((x) => x === 0), 'Void is zeroed');
        const seeks = childrenT(out, kids[0]);
        assert.deepStrictEqual(seeks.map((s) => s.id), [MKV.SEEK, MKV.VOID, MKV.SEEK], 'SeekHead entry for Tags removed');
        const info = childrenT(out, kids[1]);
        assert.strictEqual(info[0].id, MKV.CRC32);
        assert.strictEqual(out.readUInt32LE(info[0].dataStart), zlib.crc32(out.subarray(info[0].end, kids[1].end)), 'Info CRC-32 valid');
        for (const c of info) {
            if ([MKV.TITLE, MKV.MUXING_APP, MKV.WRITING_APP, MKV.DATE_UTC].includes(c.id)) {
                assert.ok(out.subarray(c.dataStart, c.end).every((x) => x === 0), `Info child ${c.id.toString(16)} zeroed`);
            }
        }
        const entry = childrenT(out, childrenT(out, kids[2])[0]);
        const name = entry.find((c) => c.id === MKV.TRACK_NAME);
        assert.ok(out.subarray(name.dataStart, name.end).every((x) => x === 0), 'track name zeroed');
        assert.ok(out.toString('latin1').includes('A_OPUS'), 'codec id kept');
        assert.ok(out.subarray(kids[3].start, kids[3].end).equals(file.subarray(kids[3].start, kids[3].end)), 'cluster untouched');
        assertAbsent(out, ['55.7558', 'LOCATION', 'Secret', 'Lavf', 'Ivan', 'IVANPHOTO', 'cover.jpg', 'Moscow']);
    });

    await test('webm (MediaRecorder style): unknown-size Segment/Clusters, Tags after clusters', async () => {
        const file = makeWebmUnknown();
        const out = run(file, 'audio/webm;codecs=opus');
        assert.strictEqual(out.length, file.length);
        const kids = parseWebm(out);
        assert.deepStrictEqual(kids.map((k) => k.id), [
            MKV.INFO, MKV.TRACKS, MKV.CLUSTER, MKV.CLUSTER, MKV.VOID, MKV.CLUSTER, MKV.CUES, MKV.VOID, MKV.VOID,
        ]);
        for (const k of kids.filter((x) => x.id === MKV.CLUSTER)) {
            assert.ok(out.subarray(k.start, k.end).equals(file.subarray(k.start, k.end)), 'clusters untouched');
        }
        assertAbsent(out, ['55.7558', 'LOCATION', 'Secret', 'Lavf', 'Ivan', 'Moscow']);
    });

    await test('webm: broken inputs are rejected', async () => {
        const file = makeWebmKnown();
        assertRejects(file.subarray(0, file.length - 5), 'video/webm');
        assertRejects(Buffer.from('OggS but not really'), 'video/webm');
        assertRejects(mkvHeader(), 'video/webm'); // нет Segment
        // Tags неизвестного размера — не бывает в корректном файле.
        assertRejects(bytes(mkvHeader(), elUnknown(MKV.SEGMENT, elUnknown(MKV.TAGS, zeros(10)))), 'video/webm');
    });

    // ---- MP3 ----

    await test('mp3: ID3v2 (x2, footer), APEv2, Lyrics3v2, ID3v1 and TAG+ removed, audio frames intact', async () => {
        const frames = mpegFrames(3);
        const file = bytes(
            id3v23(id3Frame('TXXX', bytes(Buffer.from([0]), 'GPS\0+55.7558,37.6173')), id3Frame('TPE1', bytes(Buffer.from([0]), 'Ivan Petrov'))),
            id3v24WithFooter(id3Frame('TIT2', bytes(Buffer.from([0]), 'Secret Title'))),
            frames, lyrics3v2(), apeTag(), id3v1Plus(), id3v1());
        const out = run(file, 'audio/mpeg');
        assert.ok(out.equals(frames), 'only MPEG frames remain');
        assert.ok(run(bytes(frames, id3v24WithFooter(id3Frame('TPE1', 'Ivan'))), 'audio/mpeg').equals(frames), 'appended ID3v2.4 removed');
        assertAbsent(out, ['ID3', 'TAG', 'APETAGEX', 'LYRICS', 'Ivan']);
    });

    await test('mp3: broken inputs are rejected', async () => {
        const frames = mpegFrames(2);
        assertRejects(bytes(id3v23(id3Frame('TPE1', 'Ivan')), 'garbage garbage garbage'), 'audio/mpeg');
        const hugeTag = bytes('ID3', Buffer.from([3, 0, 0]), synchsafe(100000), zeros(10), frames);
        assertRejects(hugeTag, 'audio/mpeg');
        assertRejects(bytes(frames.subarray(0, 100), 'LYRICS200'), 'audio/mpeg'); // Lyrics3 без размера
        assertRejects(Buffer.alloc(3), 'audio/mpeg');
    });

    // ---- OGG ----

    await test('ogg/opus: vendor + comments (spanning 2+ pages) blanked, binary tail zeroed, all CRC valid', async () => {
        const { file, head, audio } = makeOpus();
        const before = parseOgg(file);
        assert.ok(before.pages.filter((p) => p.header[5] & 1).length >= 1, 'comment packet continues onto another page');
        const out = run(file, 'audio/ogg');
        assert.strictEqual(out.length, file.length);
        const after = parseOgg(out); // проверяет CRC каждой страницы побитово
        assert.strictEqual(after.pages.length, before.pages.length);
        for (let i = 0; i < after.pages.length; i++) {
            const a = after.pages[i].header;
            const b = before.pages[i].header;
            assert.ok(a.subarray(0, 22).equals(b.subarray(0, 22)) && a.subarray(26).equals(b.subarray(26)), 'page headers unchanged');
        }
        const packets = [...after.packets.values()][0];
        const original = [...before.packets.values()][0];
        assert.ok(packets[0].equals(head), 'OpusHead intact');
        const end = checkBlankedComments(packets[1], 8, original[1]);
        assert.ok(packets[1].subarray(end).every((x) => x === 0), 'binary tail zeroed');
        audio.forEach((a, i) => assert.ok(packets[2 + i].equals(a), 'audio packets intact'));
        assertAbsent(out, ['Secret', '55.7558', 'SXZhbiBQZXRyb3Y', 'IVAN', 'libopus', 'METADATA_BLOCK']);
    });

    await test('ogg/vorbis: comment packet sharing pages with setup header, chained with an Opus stream', async () => {
        const vorbis = makeVorbis();
        const opus = makeOpus(0x9999);
        const file = bytes(vorbis.file, opus.file);
        const out = run(file, 'audio/ogg');
        assert.strictEqual(out.length, file.length);
        const before = parseOgg(file);
        const after = parseOgg(out);
        const v = after.packets.get(0x5678);
        const vOrig = before.packets.get(0x5678);
        assert.ok(v[0].equals(vorbis.ident), 'identification header intact');
        const end = checkBlankedComments(v[1], 7, vOrig[1]);
        assert.strictEqual(v[1][end], 1, 'framing bit kept');
        assert.ok(v[2].equals(vorbis.setup), 'setup header intact');
        vorbis.audio.forEach((a, i) => assert.ok(v[3 + i].equals(a)));
        checkBlankedComments(after.packets.get(0x9999)[1], 8, before.packets.get(0x9999)[1]);
        assertAbsent(out, ['Secret', '55.7558', 'Ivan', 'IVAN', 'Xiph', 'libopus']);
    });

    await test('ogg: broken inputs are rejected', async () => {
        const { file } = makeOpus();
        const badCrc = Buffer.from(file);
        badCrc[30] ^= 0xFF;
        assertRejects(badCrc, 'audio/ogg');
        assertRejects(file.subarray(0, file.length - 7), 'audio/ogg');
        const flac = oggStream(1, [[bytes('\x7FFLAC', zeros(20))], [bytes('comment')]]);
        assertRejects(flac, 'audio/ogg');
        const noComments = oggStream(1, [[bytes('OpusHead', zeros(11))]]);
        assertRejects(noComments, 'audio/ogg');
        const liar = oggStream(1, [[bytes('OpusHead', zeros(11))], [bytes('OpusTags', u32le(1000), 'x')]]);
        assertRejects(liar, 'audio/ogg');
    });

    // ---- WAV ----

    await test('wav: LIST/INFO, bext, iXML become zeroed JUNK, sizes and audio unchanged', async () => {
        const { file, fmt, data } = makeWav();
        const out = run(file, 'audio/wav');
        assert.strictEqual(out.length, file.length);
        const chunks = parseRiff(out);
        assert.deepStrictEqual(chunks.map((c) => c.id), ['fmt ', 'JUNK', 'JUNK', 'data', 'JUNK']);
        for (const c of chunks.filter((x) => x.id === 'JUNK')) {
            assert.ok(out.subarray(c.start + 8, c.end).every((x) => x === 0), 'JUNK zeroed (with pad byte)');
        }
        assert.ok(out.subarray(chunks[0].start, chunks[0].end).equals(fmt));
        assert.ok(out.subarray(chunks[3].start, chunks[3].end).equals(data));
        assertAbsent(out, ['INFO', 'Secret', 'Ivan', 'Moscow', '2024-05-01', 'BWFXML']);
        // Хвост за пределами RIFF (например, ID3, дописанный тегером) отбрасывается.
        const tailed = run(bytes(file, 'ID3 Ivan tail'), 'audio/wav');
        assert.ok(tailed.equals(out));
    });

    await test('wav: broken inputs are rejected', async () => {
        const { file } = makeWav();
        assertRejects(file.subarray(0, file.length - 3), 'audio/wav');
        assertRejects(bytes('RF64', u32le(0xFFFFFFFF), 'WAVE'), 'audio/wav');
        const noData = bytes('RIFF', u32le(4 + 24), 'WAVE', riffChunk('fmt ', zeros(16)));
        assertRejects(noData, 'audio/wav');
    });

    // ---- JPEG ----

    await test('jpeg: EXIF with GPS + Orientation=6 -> only Orientation=6 remains; XMP/IPTC/COM/MPF/trailer removed', async () => {
        const base = await sharp({ create: { width: 40, height: 20, channels: 3, background: '#336699' } })
            .jpeg()
            .withMetadata({ orientation: 6 })
            .withExifMerge({ IFD0: { Artist: 'Ivan Petrov', Make: 'SecretCam' }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '55/1 45/1 20/1' } })
            .toBuffer();
        const before = await sharp(base).metadata();
        assert.ok(before.exif.toString('latin1').includes('Ivan Petrov'), 'fixture carries EXIF');
        const file = bytes(insertAfterSoi(base,
            jpegSeg(0xE1, 'http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>Ivan</x:xmpmeta>'),
            jpegSeg(0xED, 'Photoshop 3.0\x008BIM\x04\x04 Ivan IPTC'),
            jpegSeg(0xE2, 'MPF\0 secondary image index'),
            jpegSeg(0xEF, 'APP15 Ivan'),
            jpegSeg(0xFE, 'Comment: Ivan was here')),
        'MotionPhoto_Data ftyp mp42 +55.7558+037.6173');
        const out = run(file, 'image/jpeg');
        const meta = await assertDecodes(out, 40, 20);
        assert.strictEqual(meta.orientation, 6, 'orientation preserved');
        assert.strictEqual(meta.xmp, undefined);
        const ifd = exifIfd0(meta.exif);
        assert.deepStrictEqual(ifd, [{ tag: 0x0112, value: 6 }], 'EXIF contains only Orientation');
        const rotated = await sharp(out).rotate().metadata();
        assert.ok(rotated.width === 40 || rotated.autoOrient, 'decoder sees orientation');
        assert.deepStrictEqual((await sharp(out).rotate().toBuffer({ resolveWithObject: true })).info.width, 20, 'auto-rotation works');
        assert.deepStrictEqual(out.subarray(out.length - 2), Buffer.from([0xFF, 0xD9]), 'ends with EOI');
        assertAbsent(out, ['Ivan', 'SecretCam', 'Photoshop', 'MPF', 'MotionPhoto', 'xmpmeta', '55.7558', 'APP15']);
    });

    await test('jpeg: little-endian EXIF orientation, JFIF thumbnail dropped, orientation 1 -> no EXIF at all', async () => {
        const plain = await sharp({ create: { width: 24, height: 16, channels: 3, background: '#aa3300' } }).jpeg().toBuffer();
        const segs = jpegHeaderSegments(plain);
        const jfifThumb = jpegSeg(0xE0, bytes('JFIF\0', Buffer.from([1, 1, 0, 0, 1, 0, 1, 2, 2]), Buffer.alloc(12, 0x77)));
        const withoutApp0 = segs[0].marker === 0xE0 ? bytes(plain.subarray(0, 2), plain.subarray(4 + segs[0].data.length)) : plain;
        const file = insertAfterSoi(withoutApp0, jfifThumb, jpegSeg(0xE1, exifII(8)));
        const out = run(file, 'image/jpeg');
        const outSegs = jpegHeaderSegments(out);
        assert.strictEqual(outSegs[0].marker, 0xE0);
        assert.strictEqual(outSegs[0].data.length, 14, 'JFIF without thumbnail');
        assert.strictEqual(outSegs[1].marker, 0xE1, 'orientation EXIF right after JFIF');
        const meta = await assertDecodes(out, 24, 16);
        assert.strictEqual(meta.orientation, 8);
        assertAbsent(out, ['SecretCam']);

        const upright = run(insertAfterSoi(withoutApp0, jpegSeg(0xE1, exifII(1))), 'image/jpeg');
        assertAbsent(upright, ['Exif', 'SecretCam']);
        await assertDecodes(upright, 24, 16);
    });

    await test('jpeg: progressive — COM between scans removed, all scans kept', async () => {
        const prog = await sharp({ create: { width: 32, height: 32, channels: 3, background: '#123456' } }).jpeg({ progressive: true }).toBuffer();
        // Второй SOS: вставляем перед ним COM.
        let sos = -1, count = 0;
        for (let i = 2; i < prog.length - 1; i++) {
            if (prog[i] === 0xFF && prog[i + 1] === 0xDA && ++count === 2) { sos = i; break; }
        }
        assert.ok(sos > 0, 'fixture has several scans');
        const file = bytes(prog.subarray(0, sos), jpegSeg(0xFE, 'Ivan between scans'), prog.subarray(sos));
        const out = run(file, 'image/jpeg');
        assert.ok(out.equals(prog), 'result equals the original progressive JPEG');
        await assertDecodes(out, 32, 32);
    });

    await test('jpeg: broken inputs are rejected', async () => {
        assertRejects(Buffer.from([0xFF, 0xD8, 0x00, 0x11, 0x22]), 'image/jpeg');
        assertRejects(Buffer.from('GIF89a'), 'image/jpeg');
        assertRejects(Buffer.from([0xFF, 0xD8, 0xFF, 0xE1, 0x10, 0x00, 0x01]), 'image/jpeg'); // сегмент длиннее файла
        assertRejects(Buffer.from([0xFF, 0xD8, 0xFF, 0xD9]), 'image/jpeg'); // нет скана
    });

    // ---- PNG ----

    await test('png: tEXt/zTXt/iTXt/eXIf/tIME/caBX/private chunks and trailing data removed', async () => {
        const base = await sharp({ create: { width: 16, height: 8, channels: 4, background: '#00ff0080' } }).png().toBuffer();
        const extra = bytes(
            pngChunk('tEXt', 'Author\0Ivan Petrov'),
            pngChunk('zTXt', bytes('Comment\0\0', zlib.deflateSync('Ivan secret'))),
            pngChunk('iTXt', 'XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta>Ivan</x:xmpmeta>'),
            pngChunk('eXIf', bytes('MM', u16(42), u32(8), u16(0), u32(0), 'SecretCam')),
            pngChunk('tIME', Buffer.from([7, 232, 5, 1, 12, 34, 56])),
            pngChunk('caBX', 'c2pa manifest Ivan'),
            pngChunk('prVt', 'Ivan private'));
        const file = bytes(base.subarray(0, 33), extra, base.subarray(33), 'trailing Ivan');
        const out = run(file, 'image/png');
        assert.ok(out.equals(base), 'result equals the clean PNG');
        assert.ok(pngChunkTypes(out).every((t) => ['IHDR', 'IDAT', 'IEND', 'PLTE', 'tRNS', 'pHYs', 'sRGB', 'gAMA', 'cHRM', 'iCCP'].includes(t)));
        const meta = await assertDecodes(out, 16, 8);
        assert.strictEqual(meta.exif, undefined);
        assertAbsent(out, ['Ivan', 'SecretCam', 'xmpmeta']);
    });

    await test('png: broken CRC / missing IEND / bad signature are rejected', async () => {
        const base = await sharp({ create: { width: 4, height: 4, channels: 3, background: '#000' } }).png().toBuffer();
        const badCrc = Buffer.from(base);
        badCrc[29] ^= 1; // CRC IHDR
        assertRejects(badCrc, 'image/png');
        assertRejects(base.subarray(0, base.length - 12), 'image/png');
        assertRejects(Buffer.from('89504E470D0A1A0A0000garbage', 'hex'), 'image/png');
        assertRejects(Buffer.from('GIF89a garbage'), 'image/png');
    });

    // ---- GIF ----

    await test('gif: comment and XMP application extensions removed, NETSCAPE2.0 and all frames kept', async () => {
        const frame = (color) => sharp({ create: { width: 8, height: 8, channels: 3, background: color } }).png().toBuffer();
        const frames = await Promise.all(['#ff0000', '#00ff00', '#0000ff'].map(frame));
        const base = await sharp(frames, { join: { animated: true } }).gif({ loop: 0 }).toBuffer();
        let head = 13;
        if (base[10] & 0x80) head += 3 * (1 << ((base[10] & 7) + 1));
        const xmp = Buffer.from('<x:xmpmeta>Ivan Petrov</x:xmpmeta>', 'latin1');
        const file = bytes(base.subarray(0, head),
            Buffer.from([0x21, 0xFE, 18]), 'Ivan Petrov Moscow', Buffer.from([0]),
            Buffer.from([0x21, 0xFF, 11]), 'XMP DataXMP', Buffer.from([xmp.length]), xmp, Buffer.from([0]),
            Buffer.from([0x21, 0x01, 12]), zeros(12), Buffer.from([4]), 'Ivan', Buffer.from([0]),
            base.subarray(head));
        const out = run(file, 'image/gif');
        const blocks = gifBlocks(out);
        assert.ok(!blocks.includes('ext:fe') && !blocks.includes('ext:1'), 'no comment / plain text');
        assert.ok(blocks.includes('app:NETSCAPE2.0'), 'loop extension kept');
        assert.ok(!blocks.some((b) => b.startsWith('app:XMP')), 'no XMP');
        assert.strictEqual(blocks.filter((b) => b === 'image').length, 3);
        await assertDecodes(out, 8, 8, 3);
        assertAbsent(out, ['Ivan', 'XMP DataXMP']);
    });

    await test('gif: broken inputs are rejected', async () => {
        assertRejects(Buffer.from('GIF89a'), 'image/gif');
        assertRejects(bytes('GIF89a', Buffer.from([1, 0, 1, 0, 0, 0, 0]), Buffer.from([0x3B])), 'image/gif'); // нет кадров
        assertRejects(bytes('GIF89a', Buffer.from([1, 0, 1, 0, 0, 0, 0]), Buffer.from([0x2C, 0, 0])), 'image/gif');
        assertRejects(bytes('GIF89a', Buffer.from([1, 0, 1, 0, 0, 0, 0]), Buffer.from([0x99])), 'image/gif');
    });

    // ---- WebP ----

    await test('webp: EXIF/XMP/unknown chunks removed, VP8X flags cleared, RIFF size recomputed', async () => {
        const simple = await sharp({ create: { width: 16, height: 8, channels: 3, background: '#445566' } }).webp().toBuffer();
        const vp8 = webpChunks(simple).find((c) => c.id === 'VP8 ' || c.id === 'VP8L');
        const vp8x = Buffer.alloc(10);
        vp8x[0] = 0x08 | 0x04; // EXIF + XMP
        vp8x.writeUIntLE(15, 4, 3);
        vp8x.writeUIntLE(7, 7, 3);
        const file = riffWebp(
            { id: 'VP8X', data: vp8x }, { id: vp8.id, data: vp8.data },
            { id: 'EXIF', data: bytes('MM', u16(42), u32(8), u16(0), u32(0), 'SecretCam Ivan') },
            { id: 'XMP ', data: '<x:xmpmeta>Ivan</x:xmpmeta>' },
            { id: 'ZZZZ', data: 'Ivan unknown' });
        const out = run(file, 'image/webp');
        const chunks = webpChunks(out);
        assert.deepStrictEqual(chunks.map((c) => c.id), ['VP8X', vp8.id]);
        assert.strictEqual(chunks[0].data[0] & 0x0C, 0, 'EXIF/XMP flags cleared');
        assert.strictEqual(out.readUInt32LE(4), out.length - 8, 'RIFF size recomputed');
        const meta = await assertDecodes(out, 16, 8);
        assert.strictEqual(meta.exif, undefined);
        assertAbsent(out, ['Ivan', 'SecretCam', 'xmpmeta']);
    });

    await test('webp: animated file keeps ANIM/ANMF frames', async () => {
        const frame = (color) => sharp({ create: { width: 8, height: 8, channels: 3, background: color } }).png().toBuffer();
        const frames = await Promise.all(['#ff0000', '#00ff00', '#0000ff'].map(frame));
        const anim = await sharp(frames, { join: { animated: true } }).webp().toBuffer();
        const chunks = webpChunks(anim).map((c) => ({ id: c.id, data: Buffer.from(c.data) }));
        chunks[0].data[0] |= 0x08;
        chunks.push({ id: 'EXIF', data: 'Ivan GPS 55.7558' });
        const out = run(riffWebp(...chunks), 'image/webp');
        assert.ok(webpChunks(out).some((c) => c.id === 'ANIM'));
        assert.strictEqual(webpChunks(out).filter((c) => c.id === 'ANMF').length, 3);
        await assertDecodes(out, 8, 8, 3);
        assertAbsent(out, ['Ivan', '55.7558']);
    });

    await test('webp: broken inputs are rejected', async () => {
        const simple = await sharp({ create: { width: 4, height: 4, channels: 3, background: '#000' } }).webp().toBuffer();
        assertRejects(simple.subarray(0, simple.length - 4), 'image/webp');
        assertRejects(riffWebp({ id: 'EXIF', data: 'only exif' }), 'image/webp');
        assertRejects(Buffer.from('RIFF\x04\0\0\0WAVE'), 'image/webp');
    });

    // ---- PDF ----

    await test('pdf: Info (direct and indirect), metadata keys in any dictionary and XMP blanked; offsets unchanged', async () => {
        const pdf = makePdf();
        const out = run(pdf, 'application/pdf');
        const text = out.toString('latin1');
        assert.strictEqual(out.length, pdf.length);
        assertAbsent(out, ['Ivan', '4D7943616D', 'draft', 'Secret Producer', 'D:2024', 'Moscow', '49 76 61 6E']);
        assert.ok(text.includes('/Author ('), 'dictionary structure stays intact');
        assert.ok(text.includes('/Titles (keep me)'), 'other names are not touched');
        const xrefOffset = Number(text.match(/startxref\n(\d+)/)[1]);
        assert.strictEqual(text.slice(xrefOffset, xrefOffset + 4), 'xref');
        const offsets = text.match(/(\d{10}) 00000 n /g).map((m) => Number(m.slice(0, 10)));
        offsets.forEach((off, i) => assert.ok(text.slice(off).startsWith(`${i + 1} 0 obj`), `object ${i + 1} offset valid`));
        assertRejects(Buffer.from('not a pdf'), 'application/pdf');
    });

    // ---- Устойчивость ----

    await test('fuzz: truncated / corrupted inputs either throw MediaSanitizeError or give a re-sanitizable result', async () => {
        let seed = 0x12345678;
        const rnd = (n) => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed % n; };
        const jpeg = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#808080' } })
            .jpeg().withMetadata({ orientation: 3 }).toBuffer();
        const png = await sharp({ create: { width: 8, height: 8, channels: 3, background: '#808080' } }).png().toBuffer();
        const gif = await sharp({ create: { width: 8, height: 8, channels: 3, background: '#808080' } }).gif().toBuffer();
        const webp = await sharp({ create: { width: 8, height: 8, channels: 3, background: '#808080' } }).webp().toBuffer();
        const fixtures = [
            ['image/jpeg', jpeg], ['image/png', png], ['image/gif', gif], ['image/webp', webp],
            ['video/mp4', makeMp4().file], ['video/mp4', makeMp4('large').file],
            ['video/webm', makeWebmKnown()], ['video/webm', makeWebmUnknown()],
            ['audio/mpeg', bytes(id3v23(id3Frame('TPE1', 'Ivan')), mpegFrames(2), apeTag(), id3v1())],
            ['audio/ogg', makeVorbis().file], ['audio/wav', makeWav().file], ['application/pdf', makePdf()],
        ];
        let rejected = 0, accepted = 0;
        const started = Date.now();
        for (const [mime, original] of fixtures) {
            for (let iter = 0; iter < 250; iter++) {
                let buf = Buffer.from(original);
                const mode = rnd(4);
                if (mode === 0) buf = buf.subarray(0, rnd(buf.length + 1));
                else if (mode === 1) for (let k = 0, m = 1 + rnd(8); k < m; k++) buf[rnd(buf.length)] = rnd(256);
                else if (mode === 2) { const at = rnd(buf.length); buf.fill(rnd(2) ? 0xFF : 0x00, at, Math.min(buf.length, at + 1 + rnd(16))); }
                else buf = bytes(buf.subarray(0, 64), Buffer.from(Array.from({ length: rnd(512) }, () => rnd(256))), buf.subarray(64 + rnd(64)));
                let out;
                try {
                    out = MediaSanitizer.sanitize(buf, mime);
                } catch (err) {
                    assert.ok(err instanceof MediaSanitizeError, `${mime}: unexpected ${err && err.name}: ${err && err.stack}`);
                    rejected++;
                    continue;
                }
                accepted++;
                assert.ok(out instanceof Uint8Array);
                MediaSanitizer.sanitize(out, mime); // результат должен снова разбираться
            }
            for (let iter = 0; iter < 50; iter++) {
                const junk = Buffer.from(Array.from({ length: rnd(2048) }, () => rnd(256)));
                try { MediaSanitizer.sanitize(junk, mime); } catch (err) {
                    assert.ok(err instanceof MediaSanitizeError, `${mime} random: ${err && err.stack}`);
                }
            }
        }
        assert.ok(rejected > 0 && accepted > 0, `both outcomes occur (rejected ${rejected}, accepted ${accepted})`);
        assert.ok(Date.now() - started < 60000, 'fuzzing finishes quickly');
    });

    await test('performance: 20 MB MP4 and WebM are processed in well under a second each', async () => {
        const big = Buffer.alloc(20 * 1024 * 1024, 0x5A);
        const mp4 = bytes(box('ftyp', 'isom', u32(0), 'isom'), box('moov', mvhd(0, 1, 2)), box('mdat', big));
        let t = Date.now();
        run(mp4, 'video/mp4');
        assert.ok(Date.now() - t < 2000, 'mp4 fast');
        const webm = bytes(mkvHeader(), elUnknown(MKV.SEGMENT, mkvInfo(),
            ...Array.from({ length: 200 }, (_, i) => elUnknown(MKV.CLUSTER, euint(0xE7, i, 2),
                ...Array.from({ length: 50 }, () => el(0xA3, Buffer.from([0x81, 0, 0, 0x80]), big.subarray(0, 2000)))))));
        t = Date.now();
        run(webm, 'video/webm');
        assert.ok(Date.now() - t < 2000, 'webm fast');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
