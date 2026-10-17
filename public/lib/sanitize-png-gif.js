// Очистка метаданных PNG и GIF (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js, разделы «PNG» и
// «GIF»: sanitizePng (белый список чанков) и sanitizeGif. Зависит только от sanitize-common.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizePngGif, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'));
    } else {
        root.NyxoSanitizePngGif = factory(root.NyxoSanitizeCommon);
    }
})(typeof self !== 'undefined' ? self : this, function (Common) {
    'use strict';

    const { fail, makeGuard, u32be, fourcc, asciiAt, concatBytes, crc32 } = Common;

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

    return Object.freeze({ sanitizePng, sanitizeGif });
});
