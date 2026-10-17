// Очистка метаданных MP4 и MOV, контейнер ISO BMFF (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js,
// раздел «MP4 / MOV»: разбор боксов и sanitizeBmff (правка на месте: длины и смещения не меняются).
// Зависит только от sanitize-common.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizeMp4, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'));
    } else {
        root.NyxoSanitizeMp4 = factory(root.NyxoSanitizeCommon);
    }
})(typeof self !== 'undefined' ? self : this, function (Common) {
    'use strict';

    const { fail, makeGuard, u8, u16be, u24be, u32be, u64be, s32be, fourcc, writeAscii } = Common;

    // ===================== MP4 / MOV (ISO BMFF) =====================
    //
    // Всё на месте: метаданные превращаются в бокс 'free' того же размера
    // с обнулённым содержимым, поэтому смещения чанков (stco/co64) и
    // фрагментов не меняются.

    const BMFF_CONTAINERS = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl', 'edts', 'moof', 'traf', 'mvex']);
    // udta — ©xyz, модель устройства, ©day; meta — Apple keys/ilst с
    // com.apple.quicktime.location.ISO6709; uuid — XMP и вендорские данные;
    // prft — абсолютное время записи (NTP) во фрагментированных файлах.
    const BMFF_METADATA_BOXES = new Set(['udta', 'meta', 'uuid', 'XMP_', 'prft']);
    const BMFF_TIME_BOXES = new Set(['mvhd', 'tkhd', 'mdhd']);
    const BMFF_SAMPLE_TABLES = new Set(['stsz', 'stz2', 'stsc', 'stco', 'co64']);
    // Дорожки таймированных метаданных: GoPro (GPMF, покадровый GPS), Google
    // CAMM, DJI, Sony rtmd, Apple mebx, а также субтитры (DJI пишет в них
    // координаты) и таймкод (время суток съёмки). Дорожка удаляется целиком,
    // её сэмплы в mdat обнуляются.
    const BMFF_METADATA_HANDLERS = new Set(['meta', 'camm', 'text', 'sbtl', 'subt', 'clcp', 'tmcd']);
    const BMFF_METADATA_SAMPLE_ENTRIES = new Set(['gpmd', 'camm', 'mebx', 'djmd', 'dbgi', 'rtmd']);
    const BMFF_MAX_DEPTH = 16;

    function isPrintableFourcc(b, o) {
        for (let i = 0; i < 4; i++) if (b[o + i] < 0x20 || b[o + i] > 0x7E) return false;
        return true;
    }

    function readBmffBox(b, pos, end) {
        if (end - pos < 8) fail('обрезан заголовок бокса');
        let size = u32be(b, pos);
        const type = fourcc(b, pos + 4);
        let header = 8;
        if (size === 1) { // largesize: 64-битный размер после типа
            if (end - pos < 16) fail('обрезан заголовок бокса');
            size = u64be(b, pos + 8);
            header = 16;
        } else if (size === 0) { // "до конца родителя"
            size = end - pos;
        }
        if (size < header || size > end - pos) fail('бокс выходит за границы родителя');
        return { type, start: pos, payload: pos + header, end: pos + size };
    }

    function neutralizeBmffBox(b, box) {
        writeAscii(b, box.start + 4, 'free');
        b.fill(0, box.payload, box.end); // у uuid сюда попадает и 16-байтный usertype
    }

    function zeroBmffTimes(b, box) {
        const version = u8(b, box.payload);
        if (version > 1) fail('неизвестная версия бокса ' + box.type);
        // version 0: creation_time и modification_time по 32 бита, version 1 — по 64.
        const len = version === 1 ? 16 : 8;
        if (box.payload + 4 + len > box.end) fail('обрезан бокс ' + box.type);
        b.fill(0, box.payload + 4, box.payload + 4 + len);
    }

    function walkBmff(b, start, end, depth, ctx, parentType, track) {
        if (depth > BMFF_MAX_DEPTH) fail('слишком глубокая вложенность боксов');
        let pos = start;
        while (pos < end) {
            ctx.guard();
            if (end - pos < 8) {
                // Хвост короче заголовка допустим только как нулевое выравнивание.
                for (let i = pos; i < end; i++) if (b[i] !== 0) fail('мусор в конце контейнера');
                return;
            }
            const box = readBmffBox(b, pos, end);
            const t = box.type;
            if (depth === 0) {
                if (!isPrintableFourcc(b, box.start + 4)) fail('не похоже на ISO BMFF');
                if (t === 'moov') ctx.sawMoov = true;
                else if (t === 'mdat') ctx.mdats.push(box);
                else if (t === 'moof') ctx.moofs.push(box);
            }
            if (BMFF_METADATA_BOXES.has(t)) {
                neutralizeBmffBox(b, box);
            } else if (t === 'free' || t === 'skip') {
                // В "свободном месте" редакторы оставляют старые копии метаданных.
                b.fill(0, box.payload, box.end);
            } else if (t === 'cmov') {
                fail('сжатый заголовок moov не поддерживается');
            } else if (BMFF_TIME_BOXES.has(t)) {
                if (t === 'tkhd' && track) {
                    const v = u8(b, box.payload);
                    const idPos = box.payload + (v === 1 ? 20 : 12);
                    if (idPos + 4 > box.end) fail('обрезан бокс tkhd');
                    track.id = u32be(b, idPos);
                }
                zeroBmffTimes(b, box);
            } else if (t === 'trak') {
                const tr = { box, id: null, handler: null, entry: null, tables: {} };
                walkBmff(b, box.payload, box.end, depth + 1, ctx, t, tr);
                ctx.tracks.push(tr);
            } else if (BMFF_CONTAINERS.has(t)) {
                walkBmff(b, box.payload, box.end, depth + 1, ctx, t, track);
            } else if (t === 'trex' && parentType === 'mvex') {
                if (box.payload + 20 > box.end) fail('обрезан бокс trex');
                ctx.trex.set(u32be(b, box.payload + 4), u32be(b, box.payload + 16));
            } else if (track) {
                // hdlr бывает и в minf (QuickTime data handler 'alis') — нужен именно из mdia.
                if (t === 'hdlr' && parentType === 'mdia' && box.payload + 12 <= box.end) {
                    track.handler = fourcc(b, box.payload + 8);
                } else if (t === 'stsd' && box.payload + 16 <= box.end) {
                    track.entry = fourcc(b, box.payload + 12);
                } else if (BMFF_SAMPLE_TABLES.has(t) && parentType === 'stbl') {
                    track.tables[t] = box;
                }
            }
            pos = box.end;
        }
    }

    // Обнуляет диапазон, только если он целиком внутри какого-то mdat:
    // испорченная таблица смещений не должна затирать структуру файла.
    function zeroInMdat(b, off, len, ctx) {
        if (len === 0) return;
        for (const m of ctx.mdats) {
            if (off >= m.payload && off + len <= m.end) {
                b.fill(0, off, off + len);
                return;
            }
        }
        fail('данные дорожки метаданных лежат вне mdat');
    }

    function zeroTrackSamples(b, tr, ctx) {
        const t = tr.tables;
        const co = t.stco || t.co64;
        if (!co) return; // нет таблицы чанков — нет и данных в mdat
        const wide = !t.stco;
        const chunkCount = u32be(b, co.payload + 4);
        if (chunkCount === 0) return;
        const chunkBase = co.payload + 8;
        if (chunkCount > (co.end - chunkBase) / (wide ? 8 : 4)) fail('таблица чанков повреждена');
        const stsc = t.stsc;
        if (!stsc) fail('нет таблицы stsc');
        const scCount = u32be(b, stsc.payload + 4);
        if (scCount === 0 || scCount > (stsc.end - stsc.payload - 8) / 12) fail('таблица stsc повреждена');

        let constSize = 0;
        let sampleCount = 0;
        let sizeAt = null;
        if (t.stsz) {
            constSize = u32be(b, t.stsz.payload + 4);
            sampleCount = u32be(b, t.stsz.payload + 8);
            const base = t.stsz.payload + 12;
            if (constSize === 0) {
                if (sampleCount > (t.stsz.end - base) / 4) fail('таблица stsz повреждена');
                sizeAt = (i) => u32be(b, base + 4 * i);
            }
        } else if (t.stz2) {
            const field = u8(b, t.stz2.payload + 7);
            sampleCount = u32be(b, t.stz2.payload + 8);
            const base = t.stz2.payload + 12;
            if (field !== 4 && field !== 8 && field !== 16) fail('таблица stz2 повреждена');
            if (Math.ceil(sampleCount * field / 8) > t.stz2.end - base) fail('таблица stz2 повреждена');
            if (field === 16) sizeAt = (i) => u16be(b, base + 2 * i);
            else if (field === 8) sizeAt = (i) => b[base + i];
            else sizeAt = (i) => (i & 1 ? b[base + (i >> 1)] & 0x0F : b[base + (i >> 1)] >> 4);
        } else {
            fail('нет таблицы размеров сэмплов');
        }

        let sc = 0;
        let sample = 0;
        for (let c = 1; c <= chunkCount; c++) {
            while (sc + 1 < scCount && u32be(b, stsc.payload + 8 + (sc + 1) * 12) <= c) sc++;
            if (u32be(b, stsc.payload + 8 + sc * 12) > c) fail('таблица stsc повреждена');
            const perChunk = u32be(b, stsc.payload + 12 + sc * 12);
            if (perChunk > sampleCount - sample) fail('таблицы сэмплов не согласованы');
            let bytes = 0;
            if (sizeAt) {
                for (let k = 0; k < perChunk; k++) bytes += sizeAt(sample + k);
            } else {
                bytes = perChunk * constSize;
            }
            sample += perChunk;
            const off = wide ? u64be(b, chunkBase + 8 * (c - 1)) : u32be(b, chunkBase + 4 * (c - 1));
            zeroInMdat(b, off, bytes, ctx);
        }
    }

    // Во фрагментированном файле сэмплы удалённых дорожек описаны в moof/traf/trun.
    // Правила базового смещения — ISO/IEC 14496-12, 8.8.7 и 8.8.8.
    function zeroFragmentSamples(b, moof, removed, ctx) {
        let prevDataEnd = moof.start;
        let firstTraf = true;
        let pos = moof.payload;
        while (pos + 8 <= moof.end) {
            ctx.guard();
            const traf = readBmffBox(b, pos, moof.end);
            pos = traf.end;
            if (traf.type !== 'traf') continue;
            let tfhd = null;
            const truns = [];
            let q = traf.payload;
            while (q + 8 <= traf.end) {
                ctx.guard();
                const child = readBmffBox(b, q, traf.end);
                if (child.type === 'tfhd') tfhd = child;
                else if (child.type === 'trun') truns.push(child);
                q = child.end;
            }
            if (!tfhd) fail('traf без tfhd');
            const flags = u24be(b, tfhd.payload + 1);
            const trackId = u32be(b, tfhd.payload + 4);
            let p = tfhd.payload + 8;
            let base = null;
            if (flags & 0x1) { base = u64be(b, p); p += 8; }
            if (flags & 0x2) p += 4;
            if (flags & 0x8) p += 4;
            let defaultSize = ctx.trex.has(trackId) ? ctx.trex.get(trackId) : null;
            if (flags & 0x10) { defaultSize = u32be(b, p); p += 4; }
            if (flags & 0x20) p += 4;
            if (p > tfhd.end) fail('обрезан бокс tfhd');
            if (base === null) base = (flags & 0x20000) || firstTraf ? moof.start : prevDataEnd;
            const isRemoved = removed.has(trackId);

            let cursor = base;
            for (const trun of truns) {
                const tf = u24be(b, trun.payload + 1);
                const count = u32be(b, trun.payload + 4);
                let r = trun.payload + 8;
                if (tf & 0x1) { cursor = base === null ? null : base + s32be(b, r); r += 4; }
                if (tf & 0x4) r += 4;
                let rec = 0;
                for (const f of [0x100, 0x200, 0x400, 0x800]) if (tf & f) rec += 4;
                if (r > trun.end || count * rec > trun.end - r) fail('обрезан бокс trun');
                let bytes = null;
                if (tf & 0x200) {
                    const sizeOffset = tf & 0x100 ? 4 : 0;
                    bytes = 0;
                    for (let k = 0; k < count; k++) bytes += u32be(b, r + k * rec + sizeOffset);
                } else if (defaultSize !== null) {
                    bytes = count * defaultSize;
                }
                if (isRemoved) {
                    if (cursor === null || bytes === null) fail('не удалось найти данные фрагмента');
                    zeroInMdat(b, cursor, bytes, ctx);
                }
                cursor = cursor === null || bytes === null ? null : cursor + bytes;
            }
            if (truns.length) prevDataEnd = cursor;
            firstTraf = false;
        }
    }

    function sanitizeBmff(src) {
        const b = new Uint8Array(src);
        const ctx = {
            guard: makeGuard(),
            sawMoov: false,
            mdats: [],
            moofs: [],
            tracks: [],
            trex: new Map(),
        };
        if (b.length < 8) fail('файл слишком короткий');
        walkBmff(b, 0, b.length, 0, ctx, null, null);
        if (!ctx.sawMoov) fail('нет бокса moov');

        const removed = new Set();
        for (const tr of ctx.tracks) {
            if (!BMFF_METADATA_HANDLERS.has(tr.handler) && !BMFF_METADATA_SAMPLE_ENTRIES.has(tr.entry)) continue;
            zeroTrackSamples(b, tr, ctx); // до обнуления trak: там же лежат таблицы
            if (tr.id !== null) removed.add(tr.id);
            neutralizeBmffBox(b, tr.box);
        }
        if (removed.size) {
            for (const moof of ctx.moofs) zeroFragmentSamples(b, moof, removed, ctx);
        }
        return b;
    }

    return Object.freeze({ sanitizeBmff });
});
