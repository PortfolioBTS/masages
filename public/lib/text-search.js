// Поиск только на устройстве (R6): список чатов фильтруется по названию, а в
// открытом чате ищется по уже загруженным и расшифрованным сообщениям. Запросов на
// сервер нет и открытый текст на диск не пишется (ни localStorage, ни IndexedDB) —
// всё живёт в памяти вкладки. Функции здесь чистые, без DOM и сети: файл
// исполняется и в браузере (window.NyxoTextSearch), и в Node (test/text-search.test.js).
//
//   foldText(text)                 — свёртка для сравнения: без учёта регистра и
//                                    различия е/ё; посимвольная, поэтому индексы
//                                    совпадений указывают в ИСХОДНЫЙ текст;
//   findRanges(folded, query, max) — все непересекающиеся вхождения: [{ start, end }]
//                                    в исходном тексте (UTF-16, как у DOM Range);
//   search(text, query, max)       — то же для обычной строки;
//   collectMatches(entries, query, max)
//                                  — совпадения по списку сообщений в порядке ленты,
//                                    не больше max (по умолчанию 500), флаг capped;
//   filterChats(chats, query)      — чаты, чьё название содержит запрос, закреплённые
//                                    сверху; null — запроса нет, фильтра нет;
//   splitSegments(text, ranges)    — текст по кускам { text, match } для <mark>
//                                    без innerHTML;
//   stepIndex(index, count, dir)   — переход к следующему/предыдущему по кругу;
//   formatCounter(index, count, capped) — «3 из 12».

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoTextSearch = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Предел совпадений на чат: дальше подсвечивать и листать уже бессмысленно.
    const MAX_MATCHES = 500;

    // Свёртка одного символа: нижний регистр и ё → е. toLowerCase у некоторых символов
    // даёт две кодовые единицы (İ → i и точка), поэтому исходные индексы хранятся
    // для каждой единицы свёрнутого текста; когда длина нигде не менялась (почти
    // всегда), массивов нет — индексы совпадают.
    function foldChar(ch) {
        const lower = ch.toLowerCase();
        return lower === 'ё' ? 'е' : lower;
    }

    // { text, source, starts, ends }: text — свёрнутая строка; для кодовой единицы i
    // свёрнутого текста starts[i]..ends[i] — символ исходного текста, из которого она
    // получилась (null — индексы совпадают).
    function foldText(value) {
        const source = value === undefined || value === null ? '' : String(value);
        let text = '';
        let starts = null;
        let ends = null;
        for (let i = 0; i < source.length;) {
            const cp = source.codePointAt(i);
            const size = cp > 0xFFFF ? 2 : 1;
            const folded = foldChar(source.slice(i, i + size));
            if (starts === null && folded.length !== size) {
                // Первое расхождение: до него индексы были тождественны (text.length === i),
                // но парные суррогаты остаются неделимыми.
                starts = [];
                ends = [];
                for (let p = 0; p < i;) {
                    const width = source.codePointAt(p) > 0xFFFF ? 2 : 1;
                    for (let k = 0; k < width; k++) { starts.push(p); ends.push(p + width); }
                    p += width;
                }
            }
            if (starts !== null) {
                for (let k = 0; k < folded.length; k++) { starts.push(i); ends.push(i + size); }
            }
            text += folded;
            i += size;
        }
        return { text, source, starts, ends };
    }

    // Вхождения свёрнутого запроса в свёрнутый текст. needle — строка, уже свёрнутая
    // foldText(...).text. Совпадения не пересекаются: поиск продолжается за концом
    // найденного.
    function findRanges(folded, needle, max = Infinity) {
        const out = [];
        if (!folded || typeof needle !== 'string' || needle.length === 0) return out;
        const hay = folded.text;
        let from = 0;
        while (out.length < max) {
            const at = hay.indexOf(needle, from);
            if (at < 0) break;
            const stop = at + needle.length;
            if (folded.starts === null) {
                out.push({ start: at, end: stop });
            } else {
                out.push({ start: folded.starts[at], end: folded.ends[stop - 1] });
            }
            from = stop;
        }
        return out;
    }

    function search(text, query, max) {
        return findRanges(foldText(text), foldText(String(query || '').trim()).text, max);
    }

    // entries — [{ key, folded }] в порядке ленты (folded — результат foldText);
    // результат — [{ key, start, end }] и capped: true, если совпадений было больше max.
    function collectMatches(entries, query, max = MAX_MATCHES) {
        const needle = foldText(String(query || '').trim()).text;
        const matches = [];
        let capped = false;
        if (needle.length === 0) return { matches, capped };
        for (const entry of entries) {
            if (!entry || !entry.folded) continue;
            const room = max - matches.length;
            // Одно лишнее вхождение — чтобы понять, что предел превышен.
            const found = findRanges(entry.folded, needle, room + 1);
            for (const range of found.slice(0, room)) matches.push({ key: entry.key, start: range.start, end: range.end });
            if (found.length > room) {
                capped = true;
                break;
            }
        }
        return { matches, capped };
    }

    // chats — объекты с name, pinned, archived (как в списке чатов). Архивные
    // участвуют наравне с остальными; закреплённые идут сверху, внутри групп порядок
    // сохраняется.
    function filterChats(chats, query) {
        const needle = foldText(String(query || '').trim()).text;
        if (needle.length === 0) return null;
        const found = [];
        (chats || []).forEach((chat, index) => {
            const ranges = findRanges(foldText(chat && chat.name), needle);
            if (ranges.length > 0) found.push({ chat, ranges, index });
        });
        found.sort((a, b) => (Number(Boolean(b.chat.pinned)) - Number(Boolean(a.chat.pinned))) || (a.index - b.index));
        return found.map(({ chat, ranges }) => ({ chat, ranges }));
    }

    // Текст кусками: совпавшие помечены match: true. Диапазоны по возрастанию, без
    // пересечений (так их отдаёт findRanges); лишнее за пределами текста обрезается.
    function splitSegments(text, ranges) {
        const source = text === undefined || text === null ? '' : String(text);
        const parts = [];
        let at = 0;
        for (const range of ranges || []) {
            const start = Math.max(at, Math.min(source.length, range.start));
            const end = Math.max(start, Math.min(source.length, range.end));
            if (end === start) continue;
            if (start > at) parts.push({ text: source.slice(at, start), match: false });
            parts.push({ text: source.slice(start, end), match: true });
            at = end;
        }
        if (at < source.length) parts.push({ text: source.slice(at), match: false });
        return parts;
    }

    // Следующий (dir > 0) или предыдущий индекс по кругу; без совпадений — -1.
    function stepIndex(index, count, dir) {
        if (!(count > 0)) return -1;
        if (!(index >= 0 && index < count)) return dir < 0 ? count - 1 : 0;
        return (index + (dir < 0 ? -1 : 1) + count) % count;
    }

    function formatCounter(index, count, capped) {
        if (!(count > 0)) return 'Ничего не найдено';
        const base = `${index + 1} из ${count}`;
        return capped ? `${base} (показаны первые ${count})` : base;
    }

    return {
        MAX_MATCHES,
        foldText,
        findRanges,
        search,
        collectMatches,
        filterChats,
        splitSegments,
        stepIndex,
        formatCounter,
    };
});
