// Очистка метаданных PDF (roadmap R14, T6.5). Вынесено дословно из public/media-sanitizer.js, раздел «PDF»: затирание
// ключей Info и XMP пробелами той же длины, минимальный разбор словарей, проверка ObjStm, замена /ID, sanitizePdf и
// blankPdfMetadata (последняя нужна серверу и тестам через _internal). Зависит от sanitize-common.js и sanitize-inflate.js.
// Принципы разбора недоверенных файлов (fail closed, проверка границ, ограниченные циклы, белые списки) - в заголовке
// public/media-sanitizer.js.
// Файл исполняется и в браузере (window.NyxoSanitizePdf, подключается до public/media-sanitizer.js; порядок - в index.html),
// и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./sanitize-common.js'), require('./sanitize-inflate.js'));
    } else {
        root.NyxoSanitizePdf = factory(root.NyxoSanitizeCommon, root.NyxoSanitizeInflate);
    }
})(typeof self !== 'undefined' ? self : this, function (Common, Inflate) {
    'use strict';

    const { MediaSanitizeError, fail, refuse, makeGuard, asciiAt, latin1, PDF_WS } = Common;
    const { INFLATE_MAX_STREAM, INFLATE_MAX_TOTAL, INFLATE_MAX_BLOCKS, inflateSync } = Inflate;

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

    // Бюджет распаковки на файл. Клиент берёт INFLATE_MAX_TOTAL; сервер передаёт меньший (options.maxInflateTotal,
    // lib/metadata-stripper.js): там разбор одного файла занимает поток, общий для всех (повторное ревью W7, Н0).
    // Негодное значение предел не снимает — тогда тоже INFLATE_MAX_TOTAL.
    function inflateBudgetTotal(options) {
        const v = options ? options.maxInflateTotal : undefined;
        return Number.isSafeInteger(v) && v > 0 ? Math.min(v, INFLATE_MAX_TOTAL) : INFLATE_MAX_TOTAL;
    }

    // Структурный проход: то, что нельзя найти поиском по тексту — сжатые
    // потоки и идентификатор документа. Меняет buf на месте или бросает исключение.
    function sanitizePdfStructure(buf, options) {
        const n = buf.length;
        const text = latin1(buf);
        // Шифруются строки и потоки: ни Info, ни XMP, ни object streams не прочитать.
        if (PDF_ENCRYPT_KEY.test(text)) refuse(PDF_MSG_ENCRYPTED);

        const guard = makeGuard();
        const ctx = {
            b: buf, n, text, guard,
            objs: new Map(), // N * 65536 + G → позиция сразу за "obj" (последнее определение)
            budget: { out: inflateBudgetTotal(options), blocks: INFLATE_MAX_BLOCKS },
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

    // options.maxInflateTotal — бюджет распаковки на файл (см. inflateBudgetTotal).
    function sanitizePdf(src, options) {
        // Заголовок %PDF- по спецификации может стоять не в самом начале, а в пределах первого килобайта.
        if (latin1(src.subarray(0, Math.min(1024, src.length))).indexOf('%PDF-') === -1) fail('нет заголовка %PDF-');
        const buf = new Uint8Array(src);
        try {
            sanitizePdfStructure(buf, options);
        } catch (err) {
            // Всё, что не удалось разобрать или распаковать, — тоже "сохраните заново", а не просто "файл повреждён".
            if (err instanceof MediaSanitizeError && !err.userFacing) pdfUnsafe(err.message);
            throw err;
        }
        return blankPdfMetadata(buf);
    }

    return Object.freeze({ blankPdfMetadata, sanitizePdf });
});
