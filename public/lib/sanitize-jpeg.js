// Очистка метаданных JPEG (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js, раздел «JPEG»:
// sanitizeJpeg и его помощники (EXIF-ориентация, JFIF). Зависит только от sanitize-common.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizeJpeg, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'));
    } else {
        root.NyxoSanitizeJpeg = factory(root.NyxoSanitizeCommon);
    }
})(typeof self !== 'undefined' ? self : this, function (Common) {
    'use strict';

    const { fail, makeGuard, u16be, asciiAt, concatBytes } = Common;

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

    return Object.freeze({ sanitizeJpeg });
});
