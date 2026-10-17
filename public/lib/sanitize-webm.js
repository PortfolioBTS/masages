// Очистка метаданных WebM, контейнер Matroska/EBML (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js,
// раздел «WebM / Matroska»: разбор EBML и sanitizeMatroska (правка на месте). Зависит только от sanitize-common.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizeWebm, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'));
    } else {
        root.NyxoSanitizeWebm = factory(root.NyxoSanitizeCommon);
    }
})(typeof self !== 'undefined' ? self : this, function (Common) {
    'use strict';

    const { fail, makeGuard, u32be, crc32 } = Common;

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

    return Object.freeze({ sanitizeMatroska });
});
