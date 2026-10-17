// Очистка метаданных WebP (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js, раздел «WebP»:
// sanitizeWebp (белый список чанков). Зависит только от sanitize-common.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizeWebp, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'));
    } else {
        root.NyxoSanitizeWebp = factory(root.NyxoSanitizeCommon);
    }
})(typeof self !== 'undefined' ? self : this, function (Common) {
    'use strict';

    const { fail, makeGuard, u32le, fourcc, asciiAt, writeAscii } = Common;

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

    return Object.freeze({ sanitizeWebp });
});
