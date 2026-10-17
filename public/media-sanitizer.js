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
        );
    } else {
        root.MediaSanitizer = factory(
            root.NyxoSanitizeCommon,
            root.NyxoSanitizeJpeg,
            root.NyxoSanitizePngGif,
            root.NyxoSanitizeWebp,
            root.NyxoSanitizeMp4,
            root.NyxoSanitizeWebm,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Common, Jpeg, PngGif, Webp, Mp4, Webm) {
    'use strict';

    // Части санитайзера обязательны: формат, чей разборщик не загрузился, нельзя "пропускать как есть".
    const PARTS = [
        [Common, 'lib/sanitize-common.js'],
        [Jpeg, 'lib/sanitize-jpeg.js'],
        [PngGif, 'lib/sanitize-png-gif.js'],
        [Webp, 'lib/sanitize-webp.js'],
        [Mp4, 'lib/sanitize-mp4.js'],
        [Webm, 'lib/sanitize-webm.js'],
    ];
    for (const [part, label] of PARTS) {
        if (!part) throw new Error('MediaSanitizer: модуль ' + label + ' не загружен');
    }

    const {
        MediaSanitizeError, fail, refuse, makeGuard, need, u32be, asciiAt, latin1, toUint8Array, crc32, PDF_WS,
    } = Common;
    const { sanitizeJpeg } = Jpeg;
    const { sanitizePng, sanitizeGif } = PngGif;
    const { sanitizeWebp } = Webp;
    const { sanitizeBmff } = Mp4;
    const { sanitizeMatroska } = Webm;

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
    // Сжатые данные (PDF 1.5+) без полной пересборки файла:
    //   - объекты внутри сжатого object stream (/ObjStm) изменить на месте
    //     нельзя (пришлось бы пересжимать и править xref), поэтому поток
    //     распаковывается только для проверки: нашлись ключи метаданных или
    //     /Info живёт внутри потока — файл отклоняется с просьбой сохранить
    //     его заново (sanitizePdfStructure, blankPdfMetadata);
    //   - сжатый XMP-поток (/Type /Metadata) заменяется пустым zlib-потоком
    //     тех же размеров, остаток области потока обнуляется;
    //   - идентификатор документа /ID в trailer и в xref-потоках заменяется
    //     случайными hex-цифрами той же длины.
    //
    // Ограничение: EXIF/XMP внутри встроенных JPEG (DCTDecode) не затираются —
    // это содержимое изображения, а не метаданные PDF. Нестандартные ключи
    // словаря Info (например /Company) тоже остаются, затираются только
    // перечисленные в PDF_META_KEYS.

    const PDF_RESAVE_HINT = 'Сохраните его заново, например через «Печать → Сохранить как PDF», и отправьте снова.';
    const PDF_MSG_COMPRESSED_META = 'PDF содержит сжатые метаданные, которые нельзя безопасно удалить. ' + PDF_RESAVE_HINT;
    const PDF_MSG_ENCRYPTED = 'PDF зашифрован: метаданные в нём удалить нельзя. '
        + 'Откройте его, снимите защиту и сохраните копию без шифрования (например, через «Печать → Сохранить как PDF»), затем отправьте снова.';
    function pdfUnsafe(reason) {
        return refuse('Не удалось безопасно очистить PDF (' + reason + '). ' + PDF_RESAVE_HINT);
    }

    // Имена PDF допускают #xx вместо любого символа (/Au#74hor — то же, что
    // /Author): без этого ключ метаданных прятался бы от поиска по тексту.
    function pdfNamePattern(name) {
        let src = '';
        for (const ch of name) {
            const hex = ch.charCodeAt(0).toString(16).padStart(2, '0').replace(/[a-f]/g, (d) => '[' + d + d.toUpperCase() + ']');
            src += '(?:' + ch + '|#' + hex + ')';
        }
        return src;
    }
    const PDF_META_NAMES = ['Author', 'Creator', 'Producer', 'Title', 'Subject', 'Keywords', 'CreationDate', 'ModDate'];
    const PDF_META_SRC = '/(?:' + PDF_META_NAMES.map(pdfNamePattern).join('|') + ')(?=[\\s()<>[\\]{}/%])\\s*';
    const PDF_META_KEYS = new RegExp(PDF_META_SRC, 'g');
    const PDF_META_KEYS_TEST = new RegExp(PDF_META_SRC); // без флага g: .test() не хранит состояние
    const PDF_INFO_REF = new RegExp('/' + pdfNamePattern('Info') + '\\s+(\\d+)\\s+(\\d+)\\s+R', 'g');
    const PDF_ENCRYPT_KEY = new RegExp('/' + pdfNamePattern('Encrypt') + '(?![^\\s()<>[\\]{}/%])');

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
        for (const m of text.matchAll(PDF_INFO_REF)) refs.add(m[1] + ' ' + m[2]);

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
            const found = new Set();
            // Без lookbehind: в Safari < 16.4 он — синтаксическая ошибка всего скрипта.
            for (const m of text.matchAll(/(?:^|[^0-9])(\d+)\s+(\d+)\s+obj\b/g)) {
                const key = m[1] + ' ' + m[2];
                if (!refs.has(key)) continue;
                found.add(key);
                const start = m.index + m[0].length;
                ranges.push([start, nextEndobj(start)]);
            }
            // Ссылка на объект, которого нет среди несжатых (обычно он лежит в
            // сжатом object stream, но может и не существовать): затереть его
            // на месте нельзя, а значит, нельзя и ручаться, что метаданных там нет.
            for (const key of refs) if (!found.has(key)) refuse(PDF_MSG_COMPRESSED_META);
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

    // ---- Разбор словарей PDF (минимальный, только то, что нужно для потоков) ----
    //
    // Разбираются лишь словари, стоящие сразу после "N G obj" и "trailer";
    // вложенные значения пропускаются без построения дерева. Любая неясность
    // (незакрытая строка, лишний разделитель, слишком глубокая вложенность)
    // — исключение, то есть отказ: файл, структуру которого не удалось
    // прочитать, нельзя объявлять очищенным.

    const PDF_MAX_DEPTH = 64;
    const PDF_MAX_ID_DIGITS = 4096;
    const PDF_DELIM = new Uint8Array(256);
    for (const ch of '()<>[]{}/%') PDF_DELIM[ch.charCodeAt(0)] = 1;
    // Ключи, повтор которых делает толкование словаря неоднозначным (разные
    // программы берут первое или последнее значение) — на них отказ.
    const PDF_UNIQUE_KEYS = new Set(['Type', 'Subtype', 'Filter', 'DecodeParms', 'Length', 'ID', 'Info', 'Encrypt']);
    // Пустой, но корректный поток zlib: заголовок, конечный пустой fixed-блок, Adler-32 пустых данных.
    const PDF_EMPTY_ZLIB = [0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];

    // Пропускает пробелы и комментарии.
    function pdfSkipWs(b, i, end) {
        while (i < end) {
            const c = b[i];
            if (PDF_WS[c]) i++;
            else if (c === 0x25) { while (i < end && b[i] !== 0x0A && b[i] !== 0x0D) i++; }
            else break;
        }
        return i;
    }

    // Строка ((...) или <hex>) с позиции i; возвращает позицию за ней или -1, если она не закрыта.
    function pdfSkipString(b, i, end) {
        if (b[i] === 0x28) {
            let depth = 1;
            i++;
            while (i < end) {
                const c = b[i++];
                if (c === 0x5C) i++;
                else if (c === 0x28) depth++;
                else if (c === 0x29 && --depth === 0) return i;
            }
            return -1;
        }
        i++;
        while (i < end) if (b[i++] === 0x3E) return i;
        return -1;
    }

    function pdfNameEnd(b, i, end) {
        let j = i + 1;
        while (j < end && !PDF_WS[b[j]] && !PDF_DELIM[b[j]]) j++;
        return j;
    }

    function hexDigitValue(c) {
        if (c >= 0x30 && c <= 0x39) return c - 0x30;
        if (c >= 0x41 && c <= 0x46) return c - 0x37;
        if (c >= 0x61 && c <= 0x66) return c - 0x57;
        return -1;
    }

    // Имя /Abc#20d → "Abc d" (без ведущего слэша); s — позиция слэша.
    function pdfDecodeName(b, s, e) {
        let out = '';
        for (let i = s + 1; i < e; i++) {
            const c = b[i];
            if (c === 0x23 && i + 2 < e) {
                const hi = hexDigitValue(b[i + 1]);
                const lo = hexDigitValue(b[i + 2]);
                if (hi >= 0 && lo >= 0) { out += String.fromCharCode(hi * 16 + lo); i += 2; continue; }
            }
            out += String.fromCharCode(c);
        }
        return out;
    }

    // Целое без знака из span [s, e) или -1. Не больше 15 цифр: безопасно для Number.
    function pdfInt(b, s, e) {
        if (e <= s || e - s > 15) return -1;
        let v = 0;
        for (let i = s; i < e; i++) {
            const d = b[i] - 0x30;
            if (d < 0 || d > 9) return -1;
            v = v * 10 + d;
        }
        return v;
    }

    // Косвенная ссылка "N G R" ровно в span [s, e): число N * 65536 + G или -1.
    function pdfRef(b, s, e) {
        let i = s;
        let j = i;
        while (j < e && b[j] >= 0x30 && b[j] <= 0x39) j++;
        const num = pdfInt(b, i, j);
        if (num < 0 || j - i > 10) return -1; // номер объекта: не больше 10 цифр, чтобы N * 65536 + G был точным
        i = j;
        while (i < e && PDF_WS[b[i]]) i++;
        j = i;
        while (j < e && b[j] >= 0x30 && b[j] <= 0x39) j++;
        const gen = pdfInt(b, i, j);
        if (gen < 0 || gen > 65535) return -1;
        i = j;
        while (i < e && PDF_WS[b[i]]) i++;
        if (b[i] !== 0x52) return -1;
        for (i++; i < e; i++) if (!PDF_WS[b[i]]) return -1;
        return num * 65536 + gen;
    }

    // Пропускает одно значение (число, имя, строку, массив, словарь, ссылку) с позиции i; возвращает позицию за ним.
    function pdfSkipValue(b, i, end, depth, guard) {
        if (depth > PDF_MAX_DEPTH) fail('слишком глубокая вложенность в PDF');
        guard();
        i = pdfSkipWs(b, i, end);
        if (i >= end) fail('неожиданный конец объекта PDF');
        const c = b[i];
        if (c === 0x3C) {
            if (b[i + 1] !== 0x3C) {
                const e = pdfSkipString(b, i, end);
                if (e < 0) fail('не закрыта шестнадцатеричная строка PDF');
                return e;
            }
            let j = i + 2;
            for (;;) {
                j = pdfSkipWs(b, j, end);
                if (j + 2 > end) fail('не закрыт словарь PDF');
                if (b[j] === 0x3E) {
                    if (b[j + 1] !== 0x3E) fail('неожиданный символ ">" в PDF');
                    return j + 2;
                }
                if (b[j] !== 0x2F) fail('ключ словаря PDF не является именем');
                j = pdfSkipValue(b, pdfNameEnd(b, j, end), end, depth + 1, guard);
            }
        }
        if (c === 0x5B) {
            let j = i + 1;
            for (;;) {
                j = pdfSkipWs(b, j, end);
                if (j >= end) fail('не закрыт массив PDF');
                if (b[j] === 0x5D) return j + 1;
                j = pdfSkipValue(b, j, end, depth + 1, guard);
            }
        }
        if (c === 0x28) {
            const e = pdfSkipString(b, i, end);
            if (e < 0) fail('не закрыта строка PDF');
            return e;
        }
        if (c === 0x2F) return pdfNameEnd(b, i, end);
        if (PDF_DELIM[c]) fail('неожиданный разделитель в PDF');
        let j = i + 1;
        while (j < end && !PDF_WS[b[j]] && !PDF_DELIM[b[j]]) j++;
        if (pdfInt(b, i, j) >= 0) { // число может оказаться началом ссылки "N G R"
            let k = pdfSkipWs(b, j, end);
            let k2 = k;
            while (k2 < end && b[k2] >= 0x30 && b[k2] <= 0x39) k2++;
            if (k2 > k) {
                k = pdfSkipWs(b, k2, end);
                if (k < end && b[k] === 0x52 && (k + 1 >= end || PDF_WS[b[k + 1]] || PDF_DELIM[b[k + 1]])) return k + 1;
            }
        }
        return j;
    }

    // Словарь с позиции i (там "<<"): ключи верхнего уровня → span значения.
    function pdfParseDict(b, i, end, guard) {
        const entries = new Map();
        let j = i + 2;
        for (;;) {
            j = pdfSkipWs(b, j, end);
            if (j + 2 > end) fail('не закрыт словарь PDF');
            if (b[j] === 0x3E) {
                if (b[j + 1] !== 0x3E) fail('неожиданный символ ">" в PDF');
                return { entries, end: j + 2 };
            }
            if (b[j] !== 0x2F) fail('ключ словаря PDF не является именем');
            const keyEnd = pdfNameEnd(b, j, end);
            const key = pdfDecodeName(b, j, keyEnd);
            const vs = pdfSkipWs(b, keyEnd, end);
            const ve = pdfSkipValue(b, vs, end, 1, guard);
            if (entries.has(key)) {
                if (PDF_UNIQUE_KEYS.has(key)) fail('ключ /' + key + ' повторяется в словаре PDF');
            } else {
                entries.set(key, { s: vs, e: ve });
            }
            j = ve;
        }
    }

    function pdfNameValue(b, v) {
        return v && b[v.s] === 0x2F ? pdfDecodeName(b, v.s, v.e) : '';
    }

    // /Filter: одно имя или массив имён → список имён; null — если там что-то другое.
    function pdfFilterNames(b, v) {
        if (!v) return [];
        if (b[v.s] === 0x2F) return [pdfDecodeName(b, v.s, v.e)];
        if (asciiAt(b, v.s, 'null')) return [];
        if (b[v.s] !== 0x5B) return null;
        const names = [];
        let i = v.s + 1;
        for (;;) {
            i = pdfSkipWs(b, i, v.e);
            if (i >= v.e) return null;
            if (b[i] === 0x5D) return names;
            if (b[i] !== 0x2F) return null;
            const e = pdfNameEnd(b, i, v.e);
            names.push(pdfDecodeName(b, i, e));
            i = e;
        }
    }

    // Есть ли предиктор в /DecodeParms. true и при "не удалось понять": лучше отказ, чем пропуск.
    function pdfHasPredictor(b, v, guard) {
        const i = pdfSkipWs(b, v.s, v.e);
        if (asciiAt(b, i, 'null')) return false;
        if (b[i] === 0x3C && b[i + 1] === 0x3C) {
            const p = pdfParseDict(b, i, v.e, guard).entries.get('Predictor');
            if (!p) return false;
            const val = pdfInt(b, p.s, p.e);
            return !(val >= 0 && val <= 1);
        }
        if (b[i] !== 0x5B) return true;
        let j = i + 1;
        for (;;) {
            j = pdfSkipWs(b, j, v.e);
            if (j >= v.e) return true;
            if (b[j] === 0x5D) return false;
            const e = pdfSkipValue(b, j, v.e, 1, guard);
            if (pdfHasPredictor(b, { s: j, e }, guard)) return true;
            j = e;
        }
    }

    // Начало данных потока после словаря (ключевое слово stream и перевод
    // строки CRLF или LF). -1 — это не поток; -2 — после stream стоит
    // что-то иное (например одиночный CR), и границы данных неоднозначны.
    function pdfStreamStart(ctx, dictEnd) {
        const i = pdfSkipWs(ctx.b, dictEnd, ctx.n);
        if (!asciiAt(ctx.b, i, 'stream')) return -1;
        const c = ctx.b[i + 6];
        if (c === 0x0D && ctx.b[i + 7] === 0x0A) return i + 8;
        if (c === 0x0A) return i + 7;
        return -2;
    }

    // Целое значение объекта "N G obj <int> endobj" (последнее определение в файле) или -1.
    function pdfResolveInt(ctx, key) {
        const at = ctx.objs.get(key);
        if (at === undefined) return -1;
        let i = pdfSkipWs(ctx.b, at, ctx.n);
        let j = i;
        while (j < ctx.n && ctx.b[j] >= 0x30 && ctx.b[j] <= 0x39) j++;
        const v = pdfInt(ctx.b, i, j);
        if (v < 0) return -1;
        i = pdfSkipWs(ctx.b, j, ctx.n);
        return asciiAt(ctx.b, i, 'endobj') ? v : -1;
    }

    // Конец данных потока по /Length (число или ссылка на целое), проверенный
    // по слову endstream сразу за данными. -1 — достоверно определить нельзя.
    function pdfStreamEnd(ctx, entries, start) {
        const v = entries.get('Length');
        if (!v) return -1;
        let len = pdfInt(ctx.b, v.s, v.e);
        if (len < 0) {
            const ref = pdfRef(ctx.b, v.s, v.e);
            if (ref < 0) return -1;
            len = pdfResolveInt(ctx, ref);
            if (len < 0) return -1;
        }
        const end = start + len;
        if (end > ctx.n) return -1;
        let k = end;
        while (k < ctx.n && PDF_WS[ctx.b[k]]) k++;
        return asciiAt(ctx.b, k, 'endstream') ? end : -1;
    }

    // ---- Случайные числа и /ID ----

    function secureRandomBytes(len) {
        const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
        if (!c || typeof c.getRandomValues !== 'function') fail('нет криптографического генератора случайных чисел');
        const out = new Uint8Array(len);
        c.getRandomValues(out); // len не больше 2048 байт (PDF_MAX_ID_DIGITS / 2): в пределах лимита 65536
        return out;
    }

    // Заменяет цифры в hex-строках массива /ID случайными той же длины.
    // Одинаковые исходные строки (первый элемент у всех ревизий и у
    // линеаризованной копии) получают одинаковую замену, чтобы не
    // нарушить сравнение идентификаторов между trailer'ами.
    function randomizePdfId(ctx, v) {
        const b = ctx.b;
        if (b[v.s] !== 0x5B) pdfUnsafe('идентификатор документа /ID не является массивом');
        const strings = [];
        let digits = 0;
        let i = v.s + 1;
        for (;;) {
            i = pdfSkipWs(b, i, v.e);
            if (i >= v.e) pdfUnsafe('не закрыт массив /ID');
            if (b[i] === 0x5D) break;
            if (b[i] !== 0x3C || b[i + 1] === 0x3C) pdfUnsafe('/ID не из шестнадцатеричных строк');
            let close = i + 1;
            while (close < v.e && b[close] !== 0x3E) {
                if (hexDigitValue(b[close]) >= 0) digits++;
                else if (!PDF_WS[b[close]]) pdfUnsafe('недопустимый символ в /ID');
                close++;
            }
            if (close >= v.e) pdfUnsafe('не закрыта строка /ID');
            if (digits > PDF_MAX_ID_DIGITS) pdfUnsafe('слишком длинный /ID');
            strings.push([i + 1, close]);
            i = close + 1;
        }
        for (const [s, e] of strings) {
            let original = '';
            for (let k = s; k < e; k++) if (!PDF_WS[b[k]]) original += String.fromCharCode(b[k] | 0x20);
            let fresh = ctx.idMap.get(original);
            if (fresh === undefined) {
                const rnd = secureRandomBytes(Math.ceil(original.length / 2));
                fresh = '';
                for (let k = 0; k < original.length; k++) fresh += ((rnd[k >> 1] >> ((k & 1) * 4)) & 15).toString(16);
                ctx.idMap.set(original, fresh);
            }
            for (let k = s, d = 0; k < e; k++) if (!PDF_WS[b[k]]) b[k] = fresh.charCodeAt(d++);
        }
    }

    // ---- Потоки ----

    // Сжатый object stream: изменить его на месте нельзя, поэтому он
    // только проверяется. Метаданные внутри — отказ.
    function checkPdfObjStm(ctx, d) {
        const b = ctx.b;
        const names = pdfFilterNames(b, d.entries.get('Filter'));
        if (names === null) pdfUnsafe('непонятный /Filter у потока объектов');
        if (names.length === 0) return; // несжатый: его текст — часть файла, его чистят общие проходы
        if (names.length !== 1 || names[0] !== 'FlateDecode') pdfUnsafe('неподдерживаемое сжатие потока объектов');
        const parms = d.entries.get('DecodeParms');
        if (parms && pdfHasPredictor(b, parms, ctx.guard)) pdfUnsafe('поток объектов с предиктором');
        const start = pdfStreamStart(ctx, d.end);
        if (start < 0) pdfUnsafe('у потока объектов нет данных');
        const end = pdfStreamEnd(ctx, d.entries, start);
        if (end < 0) pdfUnsafe('не удалось определить границы потока объектов');
        const data = inflateSync(b.subarray(start, end), { maxOut: INFLATE_MAX_STREAM, budget: ctx.budget, allowTrailingWhitespace: true });
        if (PDF_META_KEYS_TEST.test(latin1(data))) refuse(PDF_MSG_COMPRESSED_META);
    }

    // Поток XMP (/Type /Metadata или /Subtype /XML): данные затираются на
    // месте, длина потока и все смещения остаются прежними.
    function blankPdfMetadataStream(ctx, d) {
        const b = ctx.b;
        const start = pdfStreamStart(ctx, d.end);
        if (start === -1) return; // словарь без потока: затирать нечего
        if (start < 0) pdfUnsafe('не удалось определить начало потока метаданных');
        const names = pdfFilterNames(b, d.entries.get('Filter'));
        if (names === null) pdfUnsafe('непонятный /Filter у потока метаданных');
        if (names.length === 0) {
            let end = pdfStreamEnd(ctx, d.entries, start);
            // Неверный /Length у несжатого потока не повод для отказа: затираем до ближайшего endstream.
            if (end < 0) end = ctx.text.indexOf('endstream', start);
            if (end < 0) pdfUnsafe('не удалось определить границы потока метаданных');
            b.fill(0x20, start, end);
            return;
        }
        if (names.length === 1 && names[0] === 'FlateDecode') {
            const end = pdfStreamEnd(ctx, d.entries, start);
            if (end < 0) pdfUnsafe('не удалось определить границы сжатого потока метаданных');
            if (end - start < PDF_EMPTY_ZLIB.length) pdfUnsafe('сжатый поток метаданных слишком короткий');
            // Декодеры останавливаются на конце zlib-потока, а всё после него
            // не читают; поэтому остаток области обнуляется, а не оставляется.
            b.set(PDF_EMPTY_ZLIB, start);
            b.fill(0, start + PDF_EMPTY_ZLIB.length, end);
            return;
        }
        pdfUnsafe('метаданные в неподдерживаемом сжатии');
    }

    // Структурный проход: то, что нельзя найти поиском по тексту — сжатые
    // потоки и идентификатор документа. Меняет buf на месте или бросает исключение.
    function sanitizePdfStructure(buf) {
        const n = buf.length;
        const text = latin1(buf);
        // Шифруются строки и потоки: ни Info, ни XMP, ни object streams не прочитать.
        if (PDF_ENCRYPT_KEY.test(text)) refuse(PDF_MSG_ENCRYPTED);

        const guard = makeGuard();
        const ctx = {
            b: buf, n, text, guard,
            objs: new Map(), // N * 65536 + G → позиция сразу за "obj" (последнее определение)
            budget: { out: INFLATE_MAX_TOTAL, blocks: INFLATE_MAX_BLOCKS },
            idMap: new Map(),
        };

        const objPos = [];
        // Без lookbehind: в Safari < 16.4 он — синтаксическая ошибка всего скрипта.
        for (const m of text.matchAll(/(?:^|[^0-9])(\d+)\s+(\d+)\s+obj\b/g)) {
            guard();
            const pos = m.index + m[0].length;
            objPos.push(pos);
            if (m[1].length <= 10 && m[2].length <= 5) ctx.objs.set(Number(m[1]) * 65536 + Number(m[2]), pos);
        }
        const trailerPos = [];
        for (let i = text.indexOf('trailer'); i !== -1; i = text.indexOf('trailer', i + 7)) {
            guard();
            trailerPos.push(i + 7);
        }

        // Словари разбираются по возрастанию позиции, а всё, что попало внутрь
        // уже разобранного словаря (например "5 0 obj" в тексте строки), —
        // пропускается. Так области разбора не перекрываются и время остаётся
        // линейным даже на специально составленном файле.
        let cursor = 0;
        let oi = 0;
        let ti = 0;
        while (oi < objPos.length || ti < trailerPos.length) {
            guard();
            let pos;
            let isTrailer = false;
            if (ti >= trailerPos.length || (oi < objPos.length && objPos[oi] < trailerPos[ti])) pos = objPos[oi++];
            else { pos = trailerPos[ti++]; isTrailer = true; }
            if (pos < cursor) continue;
            const i = pdfSkipWs(buf, pos, n);
            if (!(buf[i] === 0x3C && buf[i + 1] === 0x3C)) continue;
            const d = pdfParseDict(buf, i, n, guard);
            cursor = d.end;

            const type = isTrailer ? '' : pdfNameValue(buf, d.entries.get('Type'));
            const id = d.entries.get('ID');
            if (isTrailer || type === 'XRef') {
                if (id) randomizePdfId(ctx, id);
            } else if (type === 'ObjStm') {
                checkPdfObjStm(ctx, d);
            } else if (type === 'Metadata' || pdfNameValue(buf, d.entries.get('Subtype')) === 'XML') {
                blankPdfMetadataStream(ctx, d);
            }
        }
    }

    function sanitizePdf(src) {
        // Заголовок %PDF- по спецификации может стоять не в самом начале, а в пределах первого килобайта.
        if (latin1(src.subarray(0, Math.min(1024, src.length))).indexOf('%PDF-') === -1) fail('нет заголовка %PDF-');
        const buf = new Uint8Array(src);
        try {
            sanitizePdfStructure(buf);
        } catch (err) {
            // Всё, что не удалось разобрать или распаковать, — тоже "сохраните заново", а не просто "файл повреждён".
            if (err instanceof MediaSanitizeError && !err.userFacing) pdfUnsafe(err.message);
            throw err;
        }
        return blankPdfMetadata(buf);
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
