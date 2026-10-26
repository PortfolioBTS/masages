'use strict';
// Название комнаты и её аватар (W7 R1 п.11).
//
// Название видят все участники, в том числе новички по ссылке-приглашению, поэтому управляющие и
// двунаправленные символы в нём - способ подделать то, что на экране: U+202E (RLO) разворачивает
// соседний текст, U+2066-2069 изолируют фрагменты, символы нулевой ширины прячут отличия двух
// «одинаковых» названий. Раньше название хранилось как прислано (только trim), а аватар - name.charAt(0):
// для эмодзи и прочих символов вне BMP это половина суррогатной пары, то есть битый символ.

const MAX_ROOM_NAME_LENGTH = 64;

// Символы собираются из кодовых точек, а не записываются в исходнике: невидимые знаки в тексте файла
// не видны ревьюеру и легко теряются при правке.
function charClass(ranges) {
    const part = ([from, to]) => (from === to ? String.fromCodePoint(from) : `${String.fromCodePoint(from)}-${String.fromCodePoint(to)}`);
    return new RegExp(`[${ranges.map(part).join('')}]`, 'gu');
}

// Разрывы строки и табуляции между словами - пробел, а не слипание слов: HT, LF, VT, FF, CR, NEL, LS, PS.
const LINE_BREAKS = charClass([[0x09, 0x0D], [0x85, 0x85], [0x2028, 0x2029]]);

// Удаляемое: C0 и C1, DEL; пробел нулевой ширины (200B) и метки направления (200E-200F); embedding/override
// (202A-202E); невидимые операторы (2060-2064); изоляты (2066-2069); метка порядка байт (FEFF); символ
// замены объекта (FFFC); tag-символы (E0000-E007F). И невидимые «заполнители», из которых складывается «пустое»
// название (повторное ревью W7, Н6): комбинирующий соединитель графем (034F), арабская метка буквы (061C),
// заполнители хангыля (115F, 1160, 3164, FFA0), невидимые гласные кхмерского (17B4, 17B5), монгольский разделитель
// гласных (180E), пустой символ Брайля (2800).
const STRIPPED = charClass([
    [0x00, 0x1F], [0x7F, 0x9F], [0x200B, 0x200B], [0x200E, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x2069],
    [0xFEFF, 0xFEFF], [0xFFFC, 0xFFFC], [0xE0000, 0xE007F],
    [0x034F, 0x034F], [0x061C, 0x061C], [0x115F, 0x1160], [0x17B4, 0x17B5], [0x180E, 0x180E], [0x2800, 0x2800],
    [0x3164, 0x3164], [0xFFA0, 0xFFA0],
]);

// ZWNJ (200C) и ZWJ (200D) нужны письменностям, где они меняют начертание (персидский, арабский, индийские), а ZWJ — ещё
// и эмодзи-последовательностям (семья, флаги, профессии): раньше они снимались везде, и такие названия ломались (Н6).
// Между латиницей, кириллицей и т.п. они только прячут отличия «одинаковых» названий — там их по-прежнему нет.
const JOINERS = charClass([[0x200C, 0x200D]]);
const JOINING_SCRIPT = /[\p{Script=Arabic}\p{Script=Syriac}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Oriya}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}]/u;
const EMOJI_BEFORE_ZWJ = new RegExp(`[\\p{Extended_Pictographic}\\p{Emoji_Modifier}${String.fromCodePoint(0xFE0F)}]`, 'u');
const EMOJI_AFTER_ZWJ = /\p{Extended_Pictographic}/u;
const ZWJ = String.fromCodePoint(0x200D);

function keepJoiner(joiner, before, after) {
    if (!before || !after) return false;
    if (JOINING_SCRIPT.test(before) && JOINING_SCRIPT.test(after)) return true;
    return joiner === ZWJ && EMOJI_BEFORE_ZWJ.test(before) && EMOJI_AFTER_ZWJ.test(after);
}

// Соседи — целые кодовые точки (эмодзи вне BMP — суррогатные пары).
function cleanJoiners(text) {
    return text.replace(JOINERS, (joiner, offset) => {
        const before = Array.from(text.slice(Math.max(0, offset - 2), offset)).pop();
        const after = Array.from(text.slice(offset + 1, offset + 3))[0];
        return keepJoiner(joiner, before, after) ? joiner : '';
    });
}

// Очищенное название: без управляющих и двунаправленных символов, пробелы схлопнуты, края обрезаны.
// Не строка - пустая строка.
function cleanRoomName(raw) {
    if (typeof raw !== 'string') return '';
    return cleanJoiners(raw.replace(LINE_BREAKS, ' ').replace(STRIPPED, '')).replace(/ {2,}/g, ' ').trim();
}

const segmenter = typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function'
    ? new Intl.Segmenter(undefined, { granularity: 'grapheme' })
    : null;

// Аватар - первая графема названия в верхнем регистре (эмодзи с модификаторами и флаги не рвутся);
// у пустого названия - '?'. Графема длиннее MAX_AVATAR_CODE_POINTS (буква с сотней комбинирующих знаков) обрезается
// до первой кодовой точки (Н6): самая длинная эмодзи-последовательность — 10 кодовых точек.
const MAX_AVATAR_CODE_POINTS = 10;

function avatarOfName(name) {
    const text = typeof name === 'string' ? name.trim() : '';
    if (!text) return '?';
    let first = '';
    if (segmenter) {
        const next = segmenter.segment(text)[Symbol.iterator]().next();
        first = next.done ? '' : next.value.segment;
    } else {
        first = Array.from(text)[0] || '';
    }
    const points = Array.from(first);
    if (points.length > MAX_AVATAR_CODE_POINTS) first = points[0];
    return (first || '?').toUpperCase();
}

module.exports = { cleanRoomName, avatarOfName, MAX_ROOM_NAME_LENGTH };
