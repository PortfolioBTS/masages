// Очистка метаданных медиафайлов: чистые функции над Uint8Array, одинаково
// работающие в браузере и в Node.
//
// Зачем изоморфно: при E2EE-вложениях файл шифруется в браузере ДО отправки,
// и сервер видит только шифротекст — снять с него GPS, модель телефона и
// время съёмки сервер уже не может. Поэтому та же логика нужна клиенту
// (вызов перед шифрованием) и серверу (lib/metadata-stripper.js — для
// незашифрованных вложений). Отсюда жёсткие ограничения: ни Buffer, ни
// Node-API, ни асинхронности, ни внешних библиотек (CSP: script-src 'self').
//
// Принципы:
//   - Fail closed. Файл, который не удалось разобрать целиком, не
//     "пропускается как есть", а отклоняется с исключением: частично
//     понятый файл — это файл, в котором метаданные могли остаться.
//   - Где формат позволяет — правка "на месте": метаданные затираются, а
//     длины и смещения остаются прежними (MP4/MOV, WebM, PDF).
//     Так не нужно пересчитывать таблицы смещений (stco, SeekHead, xref),
//     в которых легко ошибиться и сломать воспроизведение.
//   - Белые списки вместо чёрных там, где это возможно (PNG, WebP):
//     неизвестный чанк — потенциальный носитель метаданных.
//   - Любое чтение проверяет границы буфера, все циклы ограничены по числу
//     итераций, рекурсия — по глубине. Испорченный или специально
//     сконструированный файл даёт исключение, а не зависание.
//
// Известные ограничения (честно):
//   - PDF: объекты внутри сжатых object streams (/ObjStm, PDF 1.5+) и
//     сжатые (FlateDecode) XMP-потоки не разбираются — такие метаданные
//     остаются. Ключ /Title затирается в любом несжатом словаре, поэтому
//     названия закладок (outline) тоже становятся пустыми.
//   - MP4/MOV: не трогаются описания сэмплов (stsd) и имена обработчиков
//     (hdlr) — там только названия кодеков/софта, а не данные о съёмке.
//   - Звуковые форматы не поддерживаются вовсе: мессенджер не принимает
//     звук, поэтому такой файл — неподдерживаемый тип (isSupported → false,
//     sanitize бросает исключение). Контейнер WebM разбирается только как
//     video/webm.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MediaSanitizer = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const SUPPORTED_TYPES = Object.freeze([
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'video/mp4', 'video/quicktime', 'video/webm',
        'application/pdf', 'text/plain',
    ]);

    // Браузеры и ОС называют одни и те же форматы по-разному (File.type у
    // JPEG бывает image/jpeg, image/jpg и image/pjpeg).
    const MIME_ALIASES = {
        'image/jpg': 'image/jpeg',
        'image/pjpeg': 'image/jpeg',
    };

    // Потолок числа структурных элементов (сегментов, боксов, страниц...)
    // на один файл: с запасом для 50-мегабайтного вложения и одновременно
    // гарантия, что никакой вход не крутит цикл бесконечно.
    const MAX_ITERATIONS = 5000000;

    class MediaSanitizeError extends Error {
        constructor(message) {
            super(message);
            this.name = 'MediaSanitizeError';
        }
    }

    function fail(reason) {
        throw new MediaSanitizeError(reason);
    }

    function makeGuard() {
        let count = 0;
        return function guard() {
            if (++count > MAX_ITERATIONS) fail('слишком много структурных элементов');
        };
    }

    // ===================== Байтовые утилиты =====================

    // Все чтения идут через эти функции: выход за границу — это не
    // undefined/NaN, которые тихо ломают арифметику, а понятная ошибка.
    function need(b, o, len) {
        if (!(o >= 0 && o + len <= b.length)) fail('неожиданный конец данных');
    }
    function u8(b, o) { need(b, o, 1); return b[o]; }
    function u16be(b, o) { need(b, o, 2); return (b[o] << 8) | b[o + 1]; }
    function u16le(b, o) { need(b, o, 2); return b[o] | (b[o + 1] << 8); }
    function u24be(b, o) { need(b, o, 3); return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]; }
    function u32be(b, o) { need(b, o, 4); return b[o] * 0x1000000 + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]); }
    function u32le(b, o) { need(b, o, 4); return b[o + 3] * 0x1000000 + ((b[o + 2] << 16) | (b[o + 1] << 8) | b[o]); }
    function u64be(b, o) { return u32be(b, o) * 0x100000000 + u32be(b, o + 4); }
    function s32be(b, o) { return u32be(b, o) | 0; }

    function fourcc(b, o) {
        need(b, o, 4);
        return String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);
    }

    function asciiAt(b, o, s) {
        if (o < 0 || o + s.length > b.length) return false;
        for (let i = 0; i < s.length; i++) if (b[o + i] !== s.charCodeAt(i)) return false;
        return true;
    }

    function writeAscii(b, o, s) {
        for (let i = 0; i < s.length; i++) b[o + i] = s.charCodeAt(i);
    }

    function concatBytes(parts) {
        let total = 0;
        for (const p of parts) total += p.length;
        const out = new Uint8Array(total);
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    }

    // latin1 вручную: 1 байт == 1 символ, поэтому индексы в строке равны
    // смещениям в файле. TextDecoder('latin1') в браузерах на самом деле
    // windows-1252, полагаться на него не хочется.
    function latin1(b) {
        let s = '';
        for (let i = 0; i < b.length; i += 0x8000) {
            s += String.fromCharCode.apply(null, b.subarray(i, Math.min(i + 0x8000, b.length)));
        }
        return s;
    }

    // Buffer из Node — тоже Uint8Array, но его .slice() возвращает view на
    // ту же память, а не копию. Переводим вход в "чистый" Uint8Array.
    function toUint8Array(bytes) {
        if (bytes instanceof Uint8Array) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
        if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        throw new MediaSanitizeError('ожидаются байты файла (Uint8Array или ArrayBuffer)');
    }

    // CRC-32 (IEEE 802.3, отражённый полином 0xEDB88320) — PNG и Matroska.
    let crc32Table = null;
    function crc32(b, start, end) {
        if (!crc32Table) {
            crc32Table = new Uint32Array(256);
            for (let i = 0; i < 256; i++) {
                let c = i;
                for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
                crc32Table[i] = c >>> 0;
            }
        }
        let crc = 0xFFFFFFFF;
        for (let i = start; i < end; i++) crc = crc32Table[(crc ^ b[i]) & 0xFF] ^ (crc >>> 8);
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    // ===================== JPEG =====================
    //
    // Сегменты до первого SOS разбираются по одному; энтропийно-кодированные
    // данные сканов копируются как есть, но маркеры МЕЖДУ сканами
    // (прогрессивный JPEG) проходят через тот же фильтр. Всё после EOI
    // отбрасывается: туда телефоны дописывают видео Motion Photo (со своим
    // GPS), дополнительные кадры MPF (со своим EXIF) и трейлеры Samsung.

    const JPEG_EOI = Uint8Array.of(0xFF, 0xD9);

    function isJpegSof(m) {
        return m >= 0xC0 && m <= 0xCF && m !== 0xC4 && m !== 0xC8 && m !== 0xCC;
    }

    // Ориентация из EXIF (тег 0x0112 в IFD0), с учётом порядка байт II/MM.
    // 0 — тега нет или он некорректен.
    function readExifOrientation(b, tiff, end) {
        if (end - tiff < 8) return 0;
        const le = b[tiff] === 0x49 && b[tiff + 1] === 0x49;
        const be = b[tiff] === 0x4D && b[tiff + 1] === 0x4D;
        if (!le && !be) return 0;
        const r16 = (o) => (le ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1]);
        const r32 = (o) => (le
            ? b[o + 3] * 0x1000000 + ((b[o + 2] << 16) | (b[o + 1] << 8) | b[o])
            : b[o] * 0x1000000 + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]));
        if (r16(tiff + 2) !== 42) return 0;
        const ifd = tiff + r32(tiff + 4);
        if (ifd < tiff + 8 || ifd + 2 > end) return 0;
        const count = r16(ifd);
        for (let i = 0; i < count; i++) {
            const e = ifd + 2 + i * 12;
            if (e + 12 > end) return 0;
            if (r16(e) !== 0x0112) continue;
            if (r16(e + 2) !== 3) return 0; // тип SHORT
            const v = r16(e + 8);
            return v >= 1 && v <= 8 ? v : 0;
        }
        return 0;
    }

    // Минимальный EXIF: только IFD0 с одним тегом Orientation. Без него
    // вертикальные фото с телефона легли бы на бок — пиксели здесь не
    // поворачиваются, в отличие от серверного пути через sharp.
    function jpegOrientationSegment(v) {
        return Uint8Array.of(
            0xFF, 0xE1, 0x00, 0x22,
            0x45, 0x78, 0x69, 0x66, 0x00, 0x00, // "Exif\0\0"
            0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, // TIFF MM, IFD0 по смещению 8
            0x00, 0x01, // одна запись
            0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, v, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00 // следующего IFD нет
        );
    }

    // APP0 JFIF может содержать несжатую миниатюру — а миниатюра хранит
    // исходный (необрезанный) кадр. Оставляем только сам заголовок JFIF.
    function jpegCleanJfif(seg) {
        if (seg.length < 18 || !asciiAt(seg, 4, 'JFIF\0')) return null;
        const out = new Uint8Array(18);
        out.set(seg.subarray(0, 16));
        out[2] = 0;
        out[3] = 16;
        return out;
    }

    function sanitizeJpeg(src) {
        const n = src.length;
        if (n < 4 || src[0] !== 0xFF || src[1] !== 0xD8) fail('нет маркера начала изображения (SOI)');
        const guard = makeGuard();
        const leading = []; // APP0 JFIF, идущие сразу за SOI
        const rest = [];
        let orientation = 0;
        let sawFrame = false;
        let sawScan = false;
        let pos = 2;
        while (pos < n) {
            guard();
            if (src[pos] !== 0xFF) fail('ожидался маркер сегмента');
            while (pos + 1 < n && src[pos + 1] === 0xFF) pos++; // байты-заполнители
            if (pos + 1 >= n) fail('обрезан маркер сегмента');
            const marker = src[pos + 1];
            if (marker === 0xD9) break; // EOI
            if (marker === 0xD8 || marker === 0x00) fail('неожиданный маркер');
            if ((marker >= 0xD0 && marker <= 0xD7) || marker === 0x01) {
                rest.push(src.subarray(pos, pos + 2));
                pos += 2;
                continue;
            }
            const len = u16be(src, pos + 2);
            if (len < 2) fail('некорректная длина сегмента');
            const segEnd = pos + 2 + len;
            if (segEnd > n) fail('сегмент выходит за конец файла');
            const seg = src.subarray(pos, segEnd);

            if (marker === 0xDA) { // SOS: заголовок скана + энтропийные данные
                if (!sawFrame) fail('скан без заголовка кадра');
                sawScan = true;
                let p = segEnd;
                for (;;) {
                    guard();
                    const ff = src.indexOf(0xFF, p);
                    if (ff === -1 || ff + 1 >= n) { p = n; break; }
                    const next = src[ff + 1];
                    // 0xFF00 — байт-стаффинг, RSTn — маркеры рестарта, 0xFFFF —
                    // заполнитель: всё это часть энтропийных данных.
                    if (next === 0x00 || (next >= 0xD0 && next <= 0xD7) || next === 0xFF) {
                        p = next === 0xFF ? ff + 1 : ff + 2;
                        continue;
                    }
                    p = ff;
                    break;
                }
                rest.push(src.subarray(pos, p));
                pos = p;
                continue;
            }

            if (marker === 0xE0) {
                const jfif = jpegCleanJfif(seg);
                if (jfif) (rest.length === 0 ? leading : rest).push(jfif);
            } else if (marker === 0xE1) {
                // EXIF и XMP удаляются всегда; ориентацию запоминаем до удаления.
                if (!orientation && asciiAt(seg, 4, 'Exif\0\0')) orientation = readExifOrientation(seg, 10, seg.length);
            } else if (marker === 0xE2) {
                // Из APP2 нужен только ICC-профиль (цвет); MPF и FlashPix — нет.
                if (asciiAt(seg, 4, 'ICC_PROFILE\0')) rest.push(seg);
            } else if (marker === 0xEE) {
                // APP14 Adobe задаёт цветовую трансформацию (YCCK/CMYK) — без
                // него цвета части JPEG съедут.
                if (asciiAt(seg, 4, 'Adobe')) rest.push(seg);
            } else if ((marker >= 0xE3 && marker <= 0xEF) || marker === 0xFE) {
                // APP3–APP13 (в т.ч. IPTC/Photoshop), APP15 и COM — удаляются.
            } else {
                if (isJpegSof(marker)) sawFrame = true;
                rest.push(seg);
            }
            pos = segEnd;
        }
        if (!sawScan) fail('нет данных изображения');
        // EOI пишется заново всегда: и после обычного конца, и у файла,
        // обрезанного посреди скана (декодеры показывают такой частично).
        const parts = [src.subarray(0, 2)].concat(leading);
        if (orientation > 1) parts.push(jpegOrientationSegment(orientation));
        for (const seg of rest) parts.push(seg);
        parts.push(JPEG_EOI);
        return concatBytes(parts);
    }

    // ===================== PNG =====================

    const PNG_SIGNATURE = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    // Всё, что влияет на отображение, плюс APNG. tEXt/zTXt/iTXt/eXIf/tIME,
    // C2PA (caBX) и приватные чанки в список не входят.
    const PNG_KEEP = new Set([
        'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB',
        'bKGD', 'hIST', 'pHYs', 'sPLT', 'cICP', 'mDCv', 'cLLi', 'acTL', 'fcTL', 'fdAT',
    ]);

    function isAsciiLetter(c) {
        return (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A);
    }

    function sanitizePng(src) {
        const n = src.length;
        for (let i = 0; i < 8; i++) if (src[i] !== PNG_SIGNATURE[i]) fail('неверная сигнатура');
        const guard = makeGuard();
        const parts = [src.subarray(0, 8)];
        let pos = 8;
        let first = true;
        let sawData = false;
        let ended = false;
        while (pos < n) {
            guard();
            if (n - pos < 12) fail('обрезан чанк');
            const len = u32be(src, pos);
            if (len > 0x7FFFFFFF) fail('некорректная длина чанка');
            const end = pos + 12 + len;
            if (end > n) fail('чанк выходит за конец файла');
            for (let i = 4; i < 8; i++) if (!isAsciiLetter(src[pos + i])) fail('некорректный тип чанка');
            const type = fourcc(src, pos + 4);
            if (crc32(src, pos + 4, pos + 8 + len) !== u32be(src, pos + 8 + len)) {
                fail('неверная контрольная сумма чанка ' + type);
            }
            if (first && type !== 'IHDR') fail('первый чанк не IHDR');
            first = false;
            if (type === 'IDAT') sawData = true;
            if (PNG_KEEP.has(type)) parts.push(src.subarray(pos, end));
            pos = end;
            if (type === 'IEND') { ended = true; break; } // всё после IEND отбрасывается
        }
        if (!sawData) fail('нет данных изображения (IDAT)');
        if (!ended) fail('нет завершающего чанка IEND');
        return concatBytes(parts);
    }

    // ===================== GIF =====================

    function skipGifSubBlocks(b, q) {
        const n = b.length;
        for (;;) {
            if (q >= n) fail('обрезаны подблоки данных');
            const size = b[q];
            q += 1 + size;
            if (size === 0) return q;
        }
    }

    function sanitizeGif(src) {
        const n = src.length;
        if (n < 13 || !(asciiAt(src, 0, 'GIF87a') || asciiAt(src, 0, 'GIF89a'))) fail('неверная сигнатура');
        const guard = makeGuard();
        let pos = 13;
        const lsd = src[10];
        if (lsd & 0x80) pos += 3 * (1 << ((lsd & 7) + 1)); // глобальная палитра
        if (pos > n) fail('обрезана глобальная палитра');
        const parts = [src.subarray(0, pos)];
        let images = 0;
        while (pos < n) {
            guard();
            const intro = src[pos];
            if (intro === 0x3B) break; // трейлер; всё после него отбрасывается
            if (intro === 0x2C) { // кадр
                if (n - pos < 11) fail('обрезан дескриптор кадра');
                const packed = src[pos + 9];
                let q = pos + 10;
                if (packed & 0x80) q += 3 * (1 << ((packed & 7) + 1)); // локальная палитра
                q += 1; // минимальный размер LZW-кода
                if (q > n) fail('обрезан кадр');
                q = skipGifSubBlocks(src, q);
                parts.push(src.subarray(pos, q));
                images++;
                pos = q;
                continue;
            }
            if (intro === 0x21) { // расширение
                if (n - pos < 3) fail('обрезано расширение');
                const label = src[pos + 1];
                const end = skipGifSubBlocks(src, pos + 2);
                let keep = label === 0xF9; // Graphic Control: задержки и прозрачность кадров
                if (label === 0xFF) {
                    // Из Application Extension нужны только расширения
                    // зацикливания анимации; XMP (XMP DataXMP), ICC и прочие — нет.
                    keep = src[pos + 2] === 11
                        && (asciiAt(src, pos + 3, 'NETSCAPE2.0') || asciiAt(src, pos + 3, 'ANIMEXTS1.0'));
                }
                // Comment (0xFE) и Plain Text (0x01) удаляются: второй браузеры
                // не рисуют, то есть это такой же скрытый текст, как комментарий.
                if (keep) parts.push(src.subarray(pos, end));
                pos = end;
                continue;
            }
            fail('неизвестный блок');
        }
        if (!images) fail('нет ни одного кадра');
        parts.push(Uint8Array.of(0x3B));
        return concatBytes(parts);
    }

    // ===================== WebP =====================

    const WEBP_KEEP = new Set(['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANIM', 'ANMF', 'ICCP']);

    function sanitizeWebp(src) {
        const n = src.length;
        if (n < 20 || !asciiAt(src, 0, 'RIFF') || !asciiAt(src, 8, 'WEBP')) fail('неверная сигнатура');
        const riffEnd = 8 + u32le(src, 4);
        if (riffEnd > n) fail('размер RIFF больше файла');
        const guard = makeGuard();
        const chunks = [];
        let pos = 12;
        let first = true;
        let hasImage = false;
        while (pos < riffEnd) {
            guard();
            if (riffEnd - pos < 8) fail('обрезан чанк');
            const id = fourcc(src, pos);
            const size = u32le(src, pos + 4);
            const dataEnd = pos + 8 + size;
            if (dataEnd > riffEnd) fail('чанк выходит за конец файла');
            if (first) {
                if (id !== 'VP8 ' && id !== 'VP8L' && id !== 'VP8X') fail('первый чанк не VP8/VP8L/VP8X');
                if (id === 'VP8X' && size < 10) fail('некорректный чанк VP8X');
                first = false;
            }
            if (id === 'VP8 ' || id === 'VP8L' || id === 'ANMF') hasImage = true;
            // Всё, кроме белого списка (EXIF, "XMP " и неизвестные чанки), удаляется.
            if (WEBP_KEEP.has(id)) chunks.push({ id, data: src.subarray(pos + 8, dataEnd) });
            // Байт выравнивания у последнего чанка иногда не записан — терпимо.
            pos = Math.min(dataEnd + (size & 1), riffEnd);
        }
        if (!hasImage) fail('нет данных изображения');
        let total = 12;
        for (const c of chunks) total += 8 + c.data.length + (c.data.length & 1);
        const out = new Uint8Array(total);
        writeAscii(out, 0, 'RIFF');
        const riffSize = total - 8;
        out[4] = riffSize & 0xFF; out[5] = (riffSize >>> 8) & 0xFF;
        out[6] = (riffSize >>> 16) & 0xFF; out[7] = (riffSize >>> 24) & 0xFF;
        writeAscii(out, 8, 'WEBP');
        let o = 12;
        for (const c of chunks) {
            const len = c.data.length;
            writeAscii(out, o, c.id);
            out[o + 4] = len & 0xFF; out[o + 5] = (len >>> 8) & 0xFF;
            out[o + 6] = (len >>> 16) & 0xFF; out[o + 7] = (len >>> 24) & 0xFF;
            out.set(c.data, o + 8);
            // Флаги VP8X "есть EXIF" (0x08) и "есть XMP" (0x04) — самих чанков больше нет.
            if (c.id === 'VP8X') out[o + 8] &= ~0x0C;
            o += 8 + len + (len & 1); // байт выравнивания уже нулевой
        }
        return out;
    }

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

    // ===================== WebM / Matroska (EBML) =====================

    const EBML_HEADER = 0x1A45DFA3;
    const MKV_SEGMENT = 0x18538067;
    const MKV_SEEK_HEAD = 0x114D9B74;
    const MKV_INFO = 0x1549A966;
    const MKV_TRACKS = 0x1654AE6B;
    const MKV_CLUSTER = 0x1F43B675;
    const MKV_CUES = 0x1C53BB6B;
    const MKV_ATTACHMENTS = 0x1941A469;
    const MKV_CHAPTERS = 0x1043A770;
    const MKV_TAGS = 0x1254C367;
    const MKV_VOID = 0xEC;
    const MKV_CRC32 = 0xBF;
    const MKV_SEEK = 0x4DBB;
    const MKV_SEEK_ID = 0x53AB;
    const MKV_TRACK_ENTRY = 0xAE;
    const MKV_TRACK_NAME = 0x536E;

    // Элементы, которые целиком превращаются в Void: теги (в т.ч. GPS,
    // автор, дата), вложения (обложки, шрифты), главы (названия).
    const MKV_REMOVED = new Set([MKV_TAGS, MKV_ATTACHMENTS, MKV_CHAPTERS]);
    // ID уровня Segment: кластер неизвестного размера заканчивается там, где
    // встретился один из них.
    const MKV_SEGMENT_LEVEL = new Set([
        MKV_SEEK_HEAD, MKV_INFO, MKV_TRACKS, MKV_CLUSTER, MKV_CUES,
        MKV_ATTACHMENTS, MKV_CHAPTERS, MKV_TAGS, MKV_VOID,
    ]);
    // В Info обнуляются: Title, MuxingApp, WritingApp, DateUTC (время
    // записи), а также имена исходных файлов SegmentFilename/Prev/NextFilename.
    const MKV_INFO_BLANK = new Set([0x7BA9, 0x4D80, 0x5741, 0x4461, 0x7384, 0x3C83BB, 0x3E83BB]);

    // vint: длина кодируется числом ведущих нулей первого байта. Для ID
    // маркер длины остаётся частью значения, для размера — нет; размер из
    // одних единиц означает "неизвестен".
    function readVint(b, pos, end, maxLen, isId) {
        if (pos >= end) fail('обрезан элемент EBML');
        const first = b[pos];
        const len = Math.clz32(first) - 23;
        if (len > maxLen) fail('некорректное число переменной длины');
        if (pos + len > end) fail('обрезан элемент EBML');
        const mask = 0xFF >> len;
        let value = isId ? first : first & mask;
        let allOnes = (first & mask) === mask;
        for (let i = 1; i < len; i++) {
            const x = b[pos + i];
            value = value * 256 + x;
            if (x !== 0xFF) allOnes = false;
        }
        return { value, len, unknown: !isId && allOnes };
    }

    function readEbmlElement(b, pos, end) {
        const id = readVint(b, pos, end, 4, true);
        const size = readVint(b, pos + id.len, end, 8, false);
        const dataStart = pos + id.len + size.len;
        if (size.unknown) return { id: id.value, start: pos, dataStart, size: -1, end: -1 };
        if (size.value > end - dataStart) fail('элемент выходит за границы родителя');
        return { id: id.value, start: pos, dataStart, size: size.value, end: dataStart + size.value };
    }

    function writeVint(b, pos, len, value) {
        for (let i = len - 1; i >= 0; i--) {
            b[pos + i] = value % 256;
            value = Math.floor(value / 256);
        }
        b[pos] |= 0x80 >> (len - 1);
    }

    // Превращает [start, end) в Void той же длины. ID у Void однобайтовый,
    // а у заменяемых элементов — четырёхбайтовый, поэтому payload Void
    // больше исходного на разницу; размер кодируем 8-байтовым vint (или
    // короче, если элемент совсем маленький).
    function voidifyEbml(b, start, end) {
        const total = end - start;
        if (total < 2) fail('элемент слишком короткий');
        const sizeLen = Math.min(8, total - 1);
        const payload = total - 1 - sizeLen;
        b[start] = MKV_VOID;
        writeVint(b, start + 1, sizeLen, payload);
        b.fill(0, start + 1 + sizeLen, end);
    }

    function forEachEbmlChild(b, el, guard, fn) {
        let pos = el.dataStart;
        while (pos < el.end) {
            guard();
            const child = readEbmlElement(b, pos, el.end);
            if (child.size < 0) fail('элемент неизвестного размера внутри ' + el.id.toString(16));
            fn(child);
            pos = child.end;
        }
    }

    // mkvmerge кладёт первым ребёнком элемента CRC-32 от всех остальных
    // детей; после правки содержимого его нужно пересчитать, иначе
    // строгие демультиплексоры сочтут элемент повреждённым.
    function fixEbmlCrc(b, el) {
        if (el.size <= 0) return;
        const first = readEbmlElement(b, el.dataStart, el.end);
        if (first.id !== MKV_CRC32 || first.size !== 4) return;
        const crc = crc32(b, first.end, el.end);
        b[first.dataStart] = crc & 0xFF;
        b[first.dataStart + 1] = (crc >>> 8) & 0xFF;
        b[first.dataStart + 2] = (crc >>> 16) & 0xFF;
        b[first.dataStart + 3] = (crc >>> 24) & 0xFF;
    }

    function readEbmlUint(b, el) {
        let v = 0;
        for (let i = el.dataStart; i < el.end && i < el.dataStart + 8; i++) v = v * 256 + b[i];
        return el.size > 8 ? -1 : v;
    }

    function sanitizeMkvInfo(b, el, guard) {
        forEachEbmlChild(b, el, guard, (child) => {
            if (MKV_INFO_BLANK.has(child.id)) b.fill(0, child.dataStart, child.end);
        });
        fixEbmlCrc(b, el);
    }

    function sanitizeMkvTracks(b, el, guard) {
        forEachEbmlChild(b, el, guard, (entry) => {
            if (entry.id !== MKV_TRACK_ENTRY) return;
            forEachEbmlChild(b, entry, guard, (child) => {
                if (child.id === MKV_TRACK_NAME) b.fill(0, child.dataStart, child.end);
            });
            fixEbmlCrc(b, entry);
        });
        fixEbmlCrc(b, el);
    }

    // Ссылки SeekHead на удалённые элементы тоже убираем: иначе в индексе
    // остался бы след "здесь были теги".
    function sanitizeMkvSeekHead(b, el, guard) {
        forEachEbmlChild(b, el, guard, (seek) => {
            if (seek.id !== MKV_SEEK) return;
            let target = -1;
            forEachEbmlChild(b, seek, guard, (child) => {
                if (child.id === MKV_SEEK_ID) target = readEbmlUint(b, child);
            });
            if (MKV_REMOVED.has(target)) voidifyEbml(b, seek.start, seek.end);
        });
        fixEbmlCrc(b, el);
    }

    // Кластер неизвестного размера (так пишут потоковые энкодеры, которым
    // длина заранее неизвестна) кончается там, где начинается элемент уровня
    // Segment или новый EBML/Segment.
    function skipUnknownCluster(b, pos, end, guard) {
        while (pos < end) {
            guard();
            const id = readVint(b, pos, end, 4, true).value;
            if (MKV_SEGMENT_LEVEL.has(id) || id === EBML_HEADER || id === MKV_SEGMENT) return pos;
            const child = readEbmlElement(b, pos, end);
            if (child.size < 0) fail('элемент неизвестного размера внутри Cluster');
            pos = child.end;
        }
        return end;
    }

    function sanitizeMkvSegment(b, seg, fileEnd, guard) {
        const unknown = seg.size < 0;
        const end = unknown ? fileEnd : seg.end;
        let pos = seg.dataStart;
        while (pos < end) {
            guard();
            const el = readEbmlElement(b, pos, end);
            // Сегмент неизвестного размера кончается там, где начинается следующий.
            if (unknown && (el.id === EBML_HEADER || el.id === MKV_SEGMENT)) return pos;
            if (el.size < 0) {
                if (el.id !== MKV_CLUSTER) fail('элемент неизвестного размера на уровне Segment');
                pos = skipUnknownCluster(b, el.dataStart, end, guard);
                continue;
            }
            if (MKV_REMOVED.has(el.id)) voidifyEbml(b, el.start, el.end);
            else if (el.id === MKV_INFO) sanitizeMkvInfo(b, el, guard);
            else if (el.id === MKV_TRACKS) sanitizeMkvTracks(b, el, guard);
            else if (el.id === MKV_SEEK_HEAD) sanitizeMkvSeekHead(b, el, guard);
            pos = el.end;
        }
        return end;
    }

    function sanitizeMatroska(src) {
        const b = new Uint8Array(src);
        const n = b.length;
        const guard = makeGuard();
        if (n < 4 || u32be(b, 0) !== EBML_HEADER) fail('нет заголовка EBML');
        let pos = 0;
        let segments = 0;
        while (pos < n) {
            guard();
            const el = readEbmlElement(b, pos, n);
            if (el.id === MKV_SEGMENT) {
                pos = sanitizeMkvSegment(b, el, n, guard);
                segments++;
                continue;
            }
            if (el.size < 0) fail('элемент неизвестного размера на верхнем уровне');
            if (el.id !== EBML_HEADER && el.id !== MKV_VOID) fail('неожиданный элемент верхнего уровня');
            pos = el.end;
        }
        if (!segments) fail('нет элемента Segment');
        return b;
    }

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

    // Пробельные байты PDF (ISO 32000, 7.2.3): NUL, TAB, LF, FF, CR, пробел.
    const PDF_WS = new Uint8Array(256);
    for (const c of [0, 9, 10, 12, 13, 32]) PDF_WS[c] = 1;

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

    // ===================== PDF =====================
    //
    // Метаданные затираются пробелами той же длины — ни одно смещение в
    // таблице xref не меняется. Прежняя серверная версия вырезала байты и
    // ломала xref, а сам словарь Info оставляла нетронутым.
    //
    // Ограничение: объекты внутри сжатых object streams (/ObjStm, PDF 1.5+)
    // и сжатые XMP-потоки без полного разбора PDF не видны — такие
    // метаданные остаются.

    const PDF_META_KEYS = /\/(?:Author|Creator|Producer|Title|Subject|Keywords|CreationDate|ModDate)(?=[\s()<>[\]{}/%])\s*/g;

    // Затирает одну строку ((...) или <hex>), начинающуюся в i, не дальше end.
    // Возвращает позицию сразу за ней.
    function blankPdfStringAt(buf, i, end) {
        if (buf[i] === 0x28) { // литеральная строка, скобки внутри могут быть вложенными
            let depth = 1;
            i++;
            while (i < end && depth > 0) {
                const ch = buf[i];
                if (ch === 0x5C) { // '\' — экранирование, следующий байт не может закрыть строку
                    buf[i] = 0x20;
                    if (i + 1 < end) buf[i + 1] = 0x20;
                    i += 2;
                    continue;
                }
                if (ch === 0x28) depth++;
                else if (ch === 0x29 && --depth === 0) break;
                buf[i] = 0x20;
                i++;
            }
            return i + 1;
        }
        i++; // hex-строка
        while (i < end && buf[i] !== 0x3E) { buf[i] = 0x20; i++; }
        return i + 1;
    }

    // Затирает содержимое всех строк PDF в диапазоне [start, end).
    function blankPdfStrings(buf, start, end) {
        let i = start;
        while (i < end) {
            const c = buf[i];
            if (c === 0x28 || (c === 0x3C && buf[i + 1] !== 0x3C)) i = blankPdfStringAt(buf, i, end);
            else if (c === 0x3C) i += 2; // '<<' — начало словаря, не строка
            else i++;
        }
    }

    // Все вхождения open…close заменяются пробелами. Поиск идёт только
    // вперёд, поэтому время линейно даже на тысячах незакрытых open.
    function blankPdfBetween(buf, text, open, close) {
        let from = 0;
        for (;;) {
            const s = text.indexOf(open, from);
            if (s === -1) return;
            const e = text.indexOf(close, s + open.length);
            if (e === -1) return;
            buf.fill(0x20, s, e + close.length);
            from = e + close.length;
        }
    }

    function blankPdfMetadata(buf) {
        const text = latin1(buf); // 1 символ == 1 байт, смещения совпадают
        const n = buf.length;

        const endobjs = [];
        for (let i = text.indexOf('endobj'); i !== -1; i = text.indexOf('endobj', i + 6)) endobjs.push(i);
        const nextEndobj = (p) => {
            let lo = 0;
            let hi = endobjs.length;
            while (lo < hi) {
                const mid = (lo + hi) >> 1;
                if (endobjs[mid] < p) lo = mid + 1; else hi = mid;
            }
            return lo < endobjs.length ? endobjs[lo] : n;
        };

        // Словари Info — по ссылкам из trailer'ов (их несколько при
        // инкрементальных обновлениях) и из xref-потоков.
        const refs = new Set();
        for (const m of text.matchAll(/\/Info\s+(\d+)\s+(\d+)\s+R/g)) refs.add(m[1] + ' ' + m[2]);

        // Ключи метаданных в любом несжатом словаре: строковое значение
        // затирается сразу, косвенная ссылка — через объект, на который указывает.
        const refRe = /(\d+)\s+(\d+)\s+R/y;
        let blankedUpTo = 0; // ключи внутри уже затёртой строки пропускаем
        for (const m of text.matchAll(PDF_META_KEYS)) {
            if (m.index < blankedUpTo) continue;
            const p = m.index + m[0].length;
            const c = text.charCodeAt(p);
            if (c === 0x28 || (c === 0x3C && text.charCodeAt(p + 1) !== 0x3C)) {
                blankedUpTo = blankPdfStringAt(buf, p, nextEndobj(p));
            } else {
                refRe.lastIndex = p;
                const r = refRe.exec(text);
                if (r) refs.add(r[1] + ' ' + r[2]);
            }
        }

        if (refs.size) {
            const ranges = [];
            // Без lookbehind: в Safari < 16.4 он — синтаксическая ошибка всего скрипта.
            for (const m of text.matchAll(/(?:^|[^0-9])(\d+)\s+(\d+)\s+obj\b/g)) {
                if (!refs.has(m[1] + ' ' + m[2])) continue;
                const start = m.index + m[0].length;
                ranges.push([start, nextEndobj(start)]);
            }
            // Диапазоны сливаются, чтобы перекрывающиеся объекты не
            // обрабатывались повторно (линейное время на любом входе).
            ranges.sort((a, b) => a[0] - b[0]);
            let cur = null;
            for (const r of ranges) {
                if (cur && r[0] <= cur[1]) { cur[1] = Math.max(cur[1], r[1]); continue; }
                if (cur) blankPdfStrings(buf, cur[0], cur[1]);
                cur = [r[0], r[1]];
            }
            if (cur) blankPdfStrings(buf, cur[0], cur[1]);
        }

        // XMP-пакеты: содержимое заменяется пробелами, длина потока (и
        // /Length) не меняется. RDF без обёртки x:xmpmeta тоже встречается.
        blankPdfBetween(buf, text, '<x:xmpmeta', '</x:xmpmeta>');
        blankPdfBetween(buf, text, '<rdf:RDF', '</rdf:RDF>');
        return buf;
    }

    function sanitizePdf(src) {
        // Заголовок %PDF- по спецификации может стоять не в самом начале, а в пределах первого килобайта.
        if (latin1(src.subarray(0, Math.min(1024, src.length))).indexOf('%PDF-') === -1) fail('нет заголовка %PDF-');
        return blankPdfMetadata(new Uint8Array(src));
    }

    // ===================== API =====================

    const HANDLERS = {
        'image/jpeg': { label: 'JPEG', fn: sanitizeJpeg },
        'image/png': { label: 'PNG', fn: sanitizePng },
        'image/gif': { label: 'GIF', fn: sanitizeGif },
        'image/webp': { label: 'WebP', fn: sanitizeWebp },
        'video/mp4': { label: 'MP4', fn: sanitizeBmff },
        'video/quicktime': { label: 'MOV', fn: sanitizeBmff },
        'video/webm': { label: 'WebM', fn: sanitizeMatroska },
        'application/pdf': { label: 'PDF', fn: sanitizePdf },
        'text/plain': { label: 'TXT', fn: (src) => src.slice() },
    };

    // Параметры типа отбрасываются, регистр и синонимы приводятся к
    // каноническому виду: 'Video/WebM;codecs=vp9' → 'video/webm'.
    function normalizeMimeType(mimeType) {
        if (typeof mimeType !== 'string') return '';
        const base = mimeType.split(';')[0].trim().toLowerCase();
        return Object.prototype.hasOwnProperty.call(MIME_ALIASES, base) ? MIME_ALIASES[base] : base;
    }

    function isSupported(mimeType) {
        return Object.prototype.hasOwnProperty.call(HANDLERS, normalizeMimeType(mimeType));
    }

    function sanitize(bytes, mimeType) {
        const mime = normalizeMimeType(mimeType);
        if (!Object.prototype.hasOwnProperty.call(HANDLERS, mime)) {
            throw new MediaSanitizeError('Неподдерживаемый тип файла: ' + String(mimeType).slice(0, 100));
        }
        const handler = HANDLERS[mime];
        try {
            return handler.fn(toUint8Array(bytes));
        } catch (err) {
            if (err instanceof MediaSanitizeError) {
                throw new MediaSanitizeError('Файл ' + handler.label + ' повреждён или не поддерживается: ' + err.message);
            }
            throw err;
        }
    }

    return {
        sanitize,
        isSupported,
        SUPPORTED_TYPES,
        // для тестов и сервера
        _internal: {
            MediaSanitizeError, normalizeMimeType, blankPdfMetadata, crc32, inflateSync,
            INFLATE_LIMITS: Object.freeze({ stream: INFLATE_MAX_STREAM, total: INFLATE_MAX_TOTAL, blocks: INFLATE_MAX_BLOCKS }),
        },
    };
});
