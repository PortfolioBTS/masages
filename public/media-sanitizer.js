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
//     длины и смещения остаются прежними (MP4/MOV, WebM, OGG, WAV, PDF).
//     Так не нужно пересчитывать таблицы смещений (stco, SeekHead, xref),
//     в которых легко ошибиться и сломать воспроизведение.
//   - Белые списки вместо чёрных там, где это возможно (PNG, WebP, WAV):
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
//   - OGG: поддерживаются только потоки Opus и Vorbis; FLAC/Speex/Theora
//     в OGG отклоняются.
//   - MP3: теги снимаются только в начале и в конце файла; заголовок
//     Xing/LAME (название энкодера) остаётся — это не данные пользователя.
//   - WAV: RF64 (файлы > 4 ГБ) не поддерживается.
//   - MP4/MOV: не трогаются описания сэмплов (stsd) и имена обработчиков
//     (hdlr) — там только названия кодеков/софта, а не данные о съёмке.

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
        'audio/webm', 'audio/ogg', 'audio/mpeg', 'audio/wav',
        'application/pdf', 'text/plain',
    ]);

    // Браузеры и ОС называют одни и те же форматы по-разному (File.type у
    // WAV в разных браузерах — audio/wav или audio/x-wav).
    const MIME_ALIASES = {
        'image/jpg': 'image/jpeg',
        'image/pjpeg': 'image/jpeg',
        'audio/mp3': 'audio/mpeg',
        'audio/x-wav': 'audio/wav',
        'audio/wave': 'audio/wav',
        'audio/vnd.wave': 'audio/wav',
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

    // CRC страниц OGG: полином 0x04C11DB7 без отражения, начальное значение 0,
    // без финального XOR. Поле CRC самой страницы (4 байта с crcPos) при
    // расчёте считается нулевым — поэтому считаем тремя кусками.
    let oggCrcTable = null;
    function oggCrc(b, start, end, crcPos) {
        if (!oggCrcTable) {
            oggCrcTable = new Uint32Array(256);
            for (let i = 0; i < 256; i++) {
                let c = i << 24;
                for (let k = 0; k < 8; k++) c = c & 0x80000000 ? (c << 1) ^ 0x04C11DB7 : c << 1;
                oggCrcTable[i] = c >>> 0;
            }
        }
        let crc = 0;
        for (let i = start; i < crcPos; i++) crc = (crc << 8) ^ oggCrcTable[((crc >>> 24) ^ b[i]) & 0xFF];
        for (let i = 0; i < 4; i++) crc = (crc << 8) ^ oggCrcTable[(crc >>> 24) & 0xFF];
        for (let i = crcPos + 4; i < end; i++) crc = (crc << 8) ^ oggCrcTable[((crc >>> 24) ^ b[i]) & 0xFF];
        return crc >>> 0;
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

    // Кластер неизвестного размера (так пишет MediaRecorder) кончается там,
    // где начинается элемент уровня Segment или новый EBML/Segment.
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

    // ===================== MP3 =====================

    function synchsafe32(b, o) {
        need(b, o, 4);
        if ((b[o] | b[o + 1] | b[o + 2] | b[o + 3]) & 0x80) fail('некорректный размер тега ID3v2');
        return (b[o] << 21) | (b[o + 1] << 14) | (b[o + 2] << 7) | b[o + 3];
    }

    function isMpegFrameHeader(b, o, end) {
        if (end - o < 4) return false;
        if (b[o] !== 0xFF || (b[o + 1] & 0xE0) !== 0xE0) return false;
        if (((b[o + 1] >> 3) & 3) === 1) return false; // зарезервированная версия
        if (((b[o + 1] >> 1) & 3) === 0) return false; // зарезервированный layer
        if ((b[o + 2] >> 4) === 15) return false; // запрещённый битрейт
        if (((b[o + 2] >> 2) & 3) === 3) return false; // зарезервированная частота
        return true;
    }

    function lastIndexOfAscii(b, s, from, to) {
        for (let i = to - s.length; i >= from; i--) if (asciiAt(b, i, s)) return i;
        return -1;
    }

    function sanitizeMp3(src) {
        const guard = makeGuard();
        let start = 0;
        let end = src.length;
        // Ведущие ID3v2 (их бывает несколько подряд) и нулевой паддинг между ними.
        for (;;) {
            guard();
            const padLimit = Math.min(end, start + 65536);
            while (start < padLimit && src[start] === 0) start++;
            if (end - start < 10 || !asciiAt(src, start, 'ID3')) break;
            const flags = src[start + 5];
            const total = 10 + synchsafe32(src, start + 6) + (flags & 0x10 ? 10 : 0); // +футер
            if (total > end - start) fail('тег ID3v2 выходит за конец файла');
            start += total;
        }
        // Хвостовые теги: порядок бывает разный, поэтому снимаем, пока снимается.
        for (;;) {
            guard();
            const avail = end - start;
            if (avail >= 128 && asciiAt(src, end - 128, 'TAG')) { // ID3v1
                end -= 128;
                if (end - start >= 227 && asciiAt(src, end - 227, 'TAG+')) end -= 227; // расширенный ID3v1
                continue;
            }
            if (avail >= 32 && asciiAt(src, end - 32, 'APETAGEX')) { // футер APEv1/v2
                const size = u32le(src, end - 32 + 12);
                const flags = u32le(src, end - 32 + 20);
                const total = size + (flags & 0x80000000 ? 32 : 0); // + заголовок
                if (size < 32 || total > avail) fail('некорректный тег APE');
                end -= total;
                continue;
            }
            if (avail >= 15 && asciiAt(src, end - 9, 'LYRICS200')) { // Lyrics3v2
                let size = 0;
                for (let i = end - 15; i < end - 9; i++) {
                    if (src[i] < 0x30 || src[i] > 0x39) fail('некорректный тег Lyrics3');
                    size = size * 10 + (src[i] - 0x30);
                }
                const total = size + 15;
                if (total > avail || !asciiAt(src, end - total, 'LYRICSBEGIN')) fail('некорректный тег Lyrics3');
                end -= total;
                continue;
            }
            if (avail >= 20 && asciiAt(src, end - 9, 'LYRICSEND')) { // Lyrics3v1: не длиннее 5100 байт
                const at = lastIndexOfAscii(src, 'LYRICSBEGIN', Math.max(start, end - 9 - 5100 - 11), end - 9);
                if (at === -1) fail('некорректный тег Lyrics3');
                end = at;
                continue;
            }
            if (avail >= 20 && asciiAt(src, end - 10, '3DI')) { // ID3v2.4 в конце файла (с футером)
                const total = synchsafe32(src, end - 4) + 20;
                if (total > avail || !asciiAt(src, end - total, 'ID3')) fail('некорректный тег ID3v2');
                end -= total;
                continue;
            }
            break;
        }
        if (!isMpegFrameHeader(src, start, end)) fail('после тегов нет заголовка MPEG-кадра');
        return src.slice(start, end);
    }

    // ===================== OGG (Opus, Vorbis) =====================
    //
    // Второй пакет каждого логического потока — заголовок комментариев. Он
    // может тянуться через несколько страниц (обложка в
    // METADATA_BLOCK_PICTURE занимает сотни килобайт), поэтому пакеты
    // собираются по lacing-таблицам как список кусков в файле. Правка на
    // месте: длины полей сохраняются, у изменённых страниц пересчитывается CRC.

    // Затирает vendor и все комментарии. Возвращает смещение сразу за списком.
    function blankVorbisComments(p, off) {
        const vendorLen = u32le(p, off);
        off += 4;
        if (vendorLen > p.length - off) fail('некорректная длина vendor-строки');
        p.fill(0x20, off, off + vendorLen);
        off += vendorLen;
        const count = u32le(p, off);
        off += 4;
        if (count > (p.length - off) / 4) fail('некорректное число комментариев');
        for (let i = 0; i < count; i++) {
            const len = u32le(p, off);
            off += 4;
            if (len > p.length - off) fail('некорректная длина комментария');
            // "X=" + пробелы: поле остаётся синтаксически корректным, а имя и
            // значение (GPS, обложка, автор) исчезают.
            if (len >= 2) {
                p[off] = 0x58;
                p[off + 1] = 0x3D;
                p.fill(0x20, off + 2, off + len);
            } else if (len === 1) {
                p[off] = 0x3D;
            }
            off += len;
        }
        return off;
    }

    function sanitizeOggCommentPacket(p, codec) {
        if (codec === 'opus') {
            if (!asciiAt(p, 0, 'OpusTags')) fail('второй пакет Opus не OpusTags');
            const off = blankVorbisComments(p, 8);
            p.fill(0, off); // бинарный хвост OpusTags
        } else {
            if (!(p[0] === 3 && asciiAt(p, 1, 'vorbis'))) fail('второй пакет Vorbis не заголовок комментариев');
            const off = blankVorbisComments(p, 7);
            if (off >= p.length || !(p[off] & 1)) fail('нет framing-бита в заголовке комментариев');
            p.fill(0, off + 1);
        }
    }

    function finishOggPacket(b, st, pages) {
        const index = st.packets++;
        const spans = st.spans;
        st.spans = [];
        if (index > 1) return;
        let len = 0;
        for (const s of spans) len += s.len;
        const p = new Uint8Array(len);
        let o = 0;
        for (const s of spans) { p.set(b.subarray(s.off, s.off + s.len), o); o += s.len; }
        if (index === 0) {
            if (asciiAt(p, 0, 'OpusHead')) st.codec = 'opus';
            else if (p[0] === 1 && asciiAt(p, 1, 'vorbis')) st.codec = 'vorbis';
            else fail('неподдерживаемый кодек в OGG (поддерживаются Opus и Vorbis)');
            return;
        }
        sanitizeOggCommentPacket(p, st.codec);
        o = 0;
        for (const s of spans) {
            b.set(p.subarray(o, o + s.len), s.off);
            o += s.len;
            pages[s.page].dirty = true;
        }
        st.done = true;
    }

    function sanitizeOgg(src) {
        const b = new Uint8Array(src);
        const n = b.length;
        const guard = makeGuard();
        const pages = [];
        const streams = new Map();
        let pos = 0;
        while (pos < n) {
            guard();
            if (n - pos < 27 || !asciiAt(b, pos, 'OggS')) fail('ожидалась страница OggS');
            if (b[pos + 4] !== 0) fail('неизвестная версия формата страницы');
            const flags = b[pos + 5];
            const serial = u32le(b, pos + 14);
            const nseg = b[pos + 26];
            const table = pos + 27;
            const dataStart = table + nseg;
            if (dataStart > n) fail('обрезана таблица сегментов');
            let dataLen = 0;
            for (let i = 0; i < nseg; i++) dataLen += b[table + i];
            const end = dataStart + dataLen;
            if (end > n) fail('страница выходит за конец файла');
            if (oggCrc(b, pos, end, pos + 22) !== u32le(b, pos + 22)) fail('неверная контрольная сумма страницы');
            const pageIndex = pages.length;
            pages.push({ start: pos, end, dirty: false });

            let st = streams.get(serial);
            if (!st) {
                if (!(flags & 0x02)) fail('страница потока без начала потока');
                st = { packets: 0, spans: [], codec: null, done: false };
                streams.set(serial, st);
            }
            let off = dataStart;
            for (let i = 0; i < nseg && !st.done; i++) {
                const lace = b[table + i];
                if (lace) st.spans.push({ off, len: lace, page: pageIndex });
                off += lace;
                if (lace < 255) finishOggPacket(b, st, pages); // lacing < 255 завершает пакет
            }
            pos = end;
        }
        if (!streams.size) fail('нет ни одной страницы');
        for (const st of streams.values()) if (!st.done) fail('нет заголовка комментариев');
        for (const page of pages) {
            if (!page.dirty) continue;
            const crc = oggCrc(b, page.start, page.end, page.start + 22);
            b[page.start + 22] = crc & 0xFF;
            b[page.start + 23] = (crc >>> 8) & 0xFF;
            b[page.start + 24] = (crc >>> 16) & 0xFF;
            b[page.start + 25] = (crc >>> 24) & 0xFF;
        }
        return b;
    }

    // ===================== WAV =====================

    // Белый список: формат, звук и то, что нужно семплерам. LIST/INFO,
    // LIST/adtl, bext (BWF: автор, дата, место), iXML, id3, _PMX (XMP),
    // cart, DISP, axml и всё незнакомое становятся JUNK с нулями.
    const WAV_KEEP = new Set(['fmt ', 'data', 'fact', 'cue ', 'smpl', 'inst']);

    function sanitizeWav(src) {
        const n = src.length;
        if (n >= 12 && (asciiAt(src, 0, 'RF64') || asciiAt(src, 0, 'BW64'))) fail('формат RF64 не поддерживается');
        if (n < 12 || !asciiAt(src, 0, 'RIFF') || !asciiAt(src, 8, 'WAVE')) fail('неверная сигнатура');
        const riffEnd = 8 + u32le(src, 4);
        if (riffEnd > n) fail('размер RIFF больше файла');
        if (riffEnd < 12) fail('некорректный размер RIFF');
        // Байты за пределами RIFF — не часть WAV (туда, например, дописывают ID3).
        const b = src.slice(0, riffEnd);
        const guard = makeGuard();
        let sawFmt = false;
        let sawData = false;
        let pos = 12;
        while (pos < riffEnd) {
            guard();
            if (riffEnd - pos < 8) fail('обрезан чанк');
            const id = fourcc(b, pos);
            const size = u32le(b, pos + 4);
            const dataEnd = pos + 8 + size;
            if (dataEnd > riffEnd) fail('чанк выходит за конец файла');
            // Байт выравнивания у последнего чанка иногда не записан — терпимо.
            const next = Math.min(dataEnd + (size & 1), riffEnd);
            if (id === 'fmt ') sawFmt = true;
            else if (id === 'data') sawData = true;
            if (!WAV_KEEP.has(id)) {
                writeAscii(b, pos, 'JUNK');
                b.fill(0, pos + 8, next);
            }
            pos = next;
        }
        if (!sawFmt || !sawData) fail('нет чанков fmt/data');
        return b;
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
        'audio/webm': { label: 'WebM', fn: sanitizeMatroska },
        'audio/ogg': { label: 'OGG', fn: sanitizeOgg },
        'audio/mpeg': { label: 'MP3', fn: sanitizeMp3 },
        'audio/wav': { label: 'WAV', fn: sanitizeWav },
        'application/pdf': { label: 'PDF', fn: sanitizePdf },
        'text/plain': { label: 'TXT', fn: (src) => src.slice() },
    };

    // 'audio/webm;codecs=opus' (так MediaRecorder подписывает записи) → 'audio/webm'.
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
        _internal: { MediaSanitizeError, normalizeMimeType, blankPdfMetadata, crc32, oggCrc }, // для тестов и сервера
    };
});
