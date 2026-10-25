'use strict';
// Название комнаты и её аватар (W7 R1 п.11).
//
// Название видят все участники, в том числе новички по ссылке-приглашению, поэтому управляющие и
// двунаправленные символы в нём - способ подделать то, что на экране: U+202E (RLO) разворачивает
// соседний текст, U+2066-2069 изолируют фрагменты, символы нулевой ширины прячут отличия двух
// «одинаковых» названий. Раньше название хранилось как прислано (только trim), а аватар - name.charAt(0):
// для эмодзи и прочих символов вне BMP это половина суррогатной пары, то есть битый символ.

const { sanitizeText } = require('./privacy');

const MAX_ROOM_NAME_LENGTH = 64;

// Символы собираются из кодовых точек, а не записываются в исходнике: невидимые знаки в тексте файла
// не видны ревьюеру и легко теряются при правке.
function charClass(ranges) {
    const part = ([from, to]) => (from === to ? String.fromCodePoint(from) : `${String.fromCodePoint(from)}-${String.fromCodePoint(to)}`);
    return new RegExp(`[${ranges.map(part).join('')}]`, 'gu');
}

// Разрывы строки и табуляции между словами - пробел, а не слипание слов: HT, LF, VT, FF, CR, NEL, LS, PS.
const LINE_BREAKS = charClass([[0x09, 0x0D], [0x85, 0x85], [0x2028, 0x2029]]);

// Удаляемое: C0 и C1, DEL; символы нулевой ширины и метки направления (200B-200F); embedding/override
// (202A-202E); невидимые операторы (2060-2064); изоляты (2066-2069); метка порядка байт (FEFF); символ
// замены объекта (FFFC); tag-символы (E0000-E007F).
const STRIPPED = charClass([
    [0x00, 0x1F], [0x7F, 0x9F], [0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x2069],
    [0xFEFF, 0xFEFF], [0xFFFC, 0xFFFC], [0xE0000, 0xE007F],
]);

// Очищенное название: без управляющих и двунаправленных символов, пробелы схлопнуты, края обрезаны.
// Не строка - пустая строка.
function cleanRoomName(raw) {
    if (typeof raw !== 'string') return '';
    return sanitizeText(raw.replace(LINE_BREAKS, ' ')).replace(STRIPPED, '').replace(/ {2,}/g, ' ').trim();
}

const segmenter = typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function'
    ? new Intl.Segmenter(undefined, { granularity: 'grapheme' })
    : null;

// Аватар - первая графема названия в верхнем регистре (эмодзи с модификаторами и флаги не рвутся);
// у пустого названия - '?'.
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
    return (first || '?').toUpperCase();
}

module.exports = { cleanRoomName, avatarOfName, MAX_ROOM_NAME_LENGTH };
