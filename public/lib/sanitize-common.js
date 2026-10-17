// Общая часть санитайзера медиафайлов (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js
// (потолок итераций, ошибки, раздел «Байтовые утилиты» и таблица пробелов PDF). На этом стоят все разборщики форматов:
//   - MediaSanitizeError, fail (отказ с внутренним текстом) и refuse (отказ с текстом для пользователя, признак userFacing);
//   - makeGuard и потолок MAX_ITERATIONS: ограничение числа шагов любого цикла разбора;
//   - чтение и запись байтов с проверкой границ: need, u8, u16be/le, u24be, u32be/le, u64be, s32be, fourcc, asciiAt,
//     writeAscii, concatBytes, latin1, toUint8Array;
//   - crc32 (PNG и Matroska);
//   - PDF_WS: таблица пробельных байтов PDF. Лежит здесь, а не в sanitize-pdf.js, потому что её читают и разбор PDF, и
//     inflate (допустимый хвост после zlib-потока), а inflate от PDF не зависит.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizeCommon, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoSanitizeCommon = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

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

    // Отказ, текст которого написан для пользователя и показывается как есть
    // (с подсказкой, что делать), а не оборачивается в "файл повреждён".
    // Признак userFacing читают sanitize() и интерфейс.
    function refuse(userMessage) {
        const err = new MediaSanitizeError(userMessage);
        err.userFacing = true;
        throw err;
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

    // Пробельные байты PDF (ISO 32000, 7.2.3): NUL, TAB, LF, FF, CR, пробел.
    const PDF_WS = new Uint8Array(256);
    for (const c of [0, 9, 10, 12, 13, 32]) PDF_WS[c] = 1;

    return Object.freeze({
        MediaSanitizeError, fail, refuse, makeGuard, need, u8, u16be, u16le, u24be, u32be, u32le, u64be, s32be,
        fourcc, asciiAt, writeAscii, concatBytes, latin1, toUint8Array, crc32, PDF_WS,
    });
});
