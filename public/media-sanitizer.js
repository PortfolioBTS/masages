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
//   - PDF: сжатые object streams (/ObjStm, PDF 1.5+) изменить на месте
//     нельзя, поэтому PDF с метаданными (Info, /Title закладок и т.п) внутри
//     такого потока отклоняется с просьбой сохранить файл заново («Печать →
//     Сохранить как PDF»). Так же отклоняются зашифрованные PDF и PDF, у
//     которых не удалось достоверно определить границы нужных потоков.
//     Сжатые XMP-потоки затираются на месте. EXIF/XMP внутри встроенных JPEG
//     (DCTDecode) и нестандартные ключи Info (например /Company) остаются.
//     Ключ /Title затирается в любом несжатом словаре, поэтому названия
//     закладок (outline) тоже становятся пустыми.
//   - MP4/MOV: не трогаются описания сэмплов (stsd) и имена обработчиков
//     (hdlr) — там только названия кодеков/софта, а не данные о съёмке.
//   - Звуковые форматы не поддерживаются вовсе: мессенджер не принимает
//     звук, поэтому такой файл — неподдерживаемый тип (isSupported → false,
//     sanitize бросает исключение). Контейнер WebM разбирается только как
//     video/webm.
//
// Устройство (roadmap R14, T6.5). Файл вырос почти до 1900 строк, поэтому разборщики форматов вынесены дословно в
// public/lib/sanitize-*.js; поведение и публичный API прежние. Здесь остаются список SUPPORTED_TYPES, синонимы типов,
// диспетчер HANDLERS, normalizeMimeType, isSupported, sanitize и экспорт (в том числе _internal для тестов и сервера).
// Вынесено:
//   sanitize-common.js - MediaSanitizeError, fail/refuse, потолок итераций, чтение и запись байтов с проверкой границ, CRC-32;
//   sanitize-jpeg.js - JPEG;
//   sanitize-png-gif.js - PNG и GIF;
//   sanitize-webp.js - WebP;
//   sanitize-mp4.js - MP4/MOV (ISO BMFF);
//   sanitize-webm.js - WebM (Matroska/EBML);
//   sanitize-inflate.js - собственный inflate (RFC 1950/1951) для сжатых потоков PDF;
//   sanitize-pdf.js - PDF.
// В браузере части - глобальные Nyxo* (index.html подключает их ДО этого файла), в Node - соседние файлы через
// require. Без любой из частей санитайзер не загружается: молча пропустить формат нельзя (fail closed).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./lib/sanitize-common.js'),
            require('./lib/sanitize-jpeg.js'),
            require('./lib/sanitize-png-gif.js'),
            require('./lib/sanitize-webp.js'),
            require('./lib/sanitize-mp4.js'),
            require('./lib/sanitize-webm.js'),
            require('./lib/sanitize-inflate.js'),
            require('./lib/sanitize-pdf.js'),
        );
    } else {
        root.MediaSanitizer = factory(
            root.NyxoSanitizeCommon,
            root.NyxoSanitizeJpeg,
            root.NyxoSanitizePngGif,
            root.NyxoSanitizeWebp,
            root.NyxoSanitizeMp4,
            root.NyxoSanitizeWebm,
            root.NyxoSanitizeInflate,
            root.NyxoSanitizePdf,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Common, Jpeg, PngGif, Webp, Mp4, Webm, Inflate, Pdf) {
    'use strict';

    // Части санитайзера обязательны: формат, чей разборщик не загрузился, нельзя "пропускать как есть".
    const PARTS = [
        [Common, 'lib/sanitize-common.js'],
        [Jpeg, 'lib/sanitize-jpeg.js'],
        [PngGif, 'lib/sanitize-png-gif.js'],
        [Webp, 'lib/sanitize-webp.js'],
        [Mp4, 'lib/sanitize-mp4.js'],
        [Webm, 'lib/sanitize-webm.js'],
        [Inflate, 'lib/sanitize-inflate.js'],
        [Pdf, 'lib/sanitize-pdf.js'],
    ];
    for (const [part, label] of PARTS) {
        if (!part) throw new Error('MediaSanitizer: модуль ' + label + ' не загружен');
    }

    const { MediaSanitizeError, toUint8Array, crc32 } = Common;
    const { sanitizeJpeg } = Jpeg;
    const { sanitizePng, sanitizeGif } = PngGif;
    const { sanitizeWebp } = Webp;
    const { sanitizeBmff } = Mp4;
    const { sanitizeMatroska } = Webm;
    const { INFLATE_MAX_STREAM, INFLATE_MAX_TOTAL, INFLATE_MAX_BLOCKS, inflateSync } = Inflate;
    const { blankPdfMetadata, sanitizePdf } = Pdf;

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

    // options — только для сервера: { maxInflateTotal } — бюджет распаковки PDF на файл, меньше клиентского
    // (lib/metadata-stripper.js). Клиент вызывает без options.
    function sanitize(bytes, mimeType, options) {
        const mime = normalizeMimeType(mimeType);
        if (!Object.prototype.hasOwnProperty.call(HANDLERS, mime)) {
            throw new MediaSanitizeError('Неподдерживаемый тип файла: ' + String(mimeType).slice(0, 100));
        }
        const handler = HANDLERS[mime];
        try {
            return handler.fn(toUint8Array(bytes), options);
        } catch (err) {
            if (err instanceof MediaSanitizeError) {
                if (err.userFacing) throw err;
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
