'use strict';
// Поиск только на устройстве (public/lib/text-search.js, R6): свёртка (регистр,
// ё, суррогатные пары, İ), все вхождения с исходными индексами, предел 500,
// фильтр списка чатов, куски текста для <mark>, переход по совпадениям.
// Запуск: node test/text-search.test.js

const assert = require('assert');
const T = require('../public/lib/text-search.js');

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// Куски исходного текста по найденным диапазонам: так видно, что именно подсветится.
const hits = (text, query) => T.search(text, query).map(r => text.slice(r.start, r.end));

test('foldText: регистр и ё/е, индексы тождественны, когда длина не менялась', () => {
    const folded = T.foldText('Привет, ЁЖИК');
    assert.strictEqual(folded.text, 'привет, ежик');
    assert.strictEqual(folded.starts, null, 'массивов индексов нет, пока длина совпадает');
    assert.strictEqual(T.foldText(null).text, '');
    assert.strictEqual(T.foldText(undefined).text, '');
    assert.strictEqual(T.foldText(42).text, '42');
});

test('поиск без учёта регистра и различия е/ё, в обе стороны', () => {
    assert.deepStrictEqual(hits('Привет, ПРИВЕТ, привет', 'пРиВеТ'), ['Привет', 'ПРИВЕТ', 'привет']);
    assert.deepStrictEqual(hits('Ёлка и ёж', 'елка'), ['Ёлка']);
    assert.deepStrictEqual(hits('елка и еж', 'ЁЛКА'), ['елка']);
    assert.deepStrictEqual(hits('всё', 'все'), ['всё'], 'ё внутри слова: подсвечивается исходная буква');
    assert.deepStrictEqual(hits('Hello World', 'WORLD'), ['World']);
});

test('диапазоны указывают в исходный текст: индексы, а не свёрнутая копия', () => {
    const text = 'Ёжик и ёлка';
    assert.deepStrictEqual(T.search(text, 'ё'), [{ start: 0, end: 1 }, { start: 7, end: 8 }]);
    assert.deepStrictEqual(T.search(text, 'ёлка'), [{ start: 7, end: 11 }]);
    assert.deepStrictEqual(T.search('abc abc', 'abc'), [{ start: 0, end: 3 }, { start: 4, end: 7 }]);
});

test('суррогатные пары: эмодзи и редкие символы не разрываются и не сдвигают индексы', () => {
    const text = '😀 привет 😀 мир';
    assert.deepStrictEqual(hits(text, 'привет'), ['привет']);
    assert.deepStrictEqual(T.search(text, 'мир'), [{ start: 13, end: 16 }]);
    assert.deepStrictEqual(hits(text, '😀'), ['😀', '😀']);
    // Буква вне BMP с регистром (Deseret): свёртка не ломает длину.
    const deseret = '\u{10400}\u{10428}';
    assert.deepStrictEqual(hits(`x${deseret}y`, '\u{10428}'), ['\u{10400}', '\u{10428}']);
});

test('İ (турецкая заглавная I с точкой) даёт две кодовые единицы — индексы всё равно исходные', () => {
    const text = 'İstanbul и Istanbul';
    const folded = T.foldText(text);
    assert.strictEqual(folded.text.length, text.length + 1, 'свёртка İ длиннее на единицу');
    assert.deepStrictEqual(T.search(text, 'stanbul'), [{ start: 1, end: 8 }, { start: 12, end: 19 }]);
    assert.deepStrictEqual(hits(text, 'i'), ['İ', 'I'], 'i находит и İ целиком, и I');
    assert.deepStrictEqual(hits('😀 İ', 'i'), ['İ'], 'индексы после эмодзи верны');
    // Запрос «i» + комбинируемая точка находит İ целиком.
    assert.deepStrictEqual(hits('İ', 'i̇'), ['İ']);
    // Парный суррогат перед первым расхождением остаётся неделимым.
    const mapping = T.foldText('😀İ');
    assert.deepStrictEqual(mapping.starts.slice(0, 2), [0, 0]);
    assert.deepStrictEqual(mapping.ends.slice(0, 2), [2, 2]);
});

test('вхождения не пересекаются; пустой запрос и пустой текст ничего не находят', () => {
    assert.deepStrictEqual(T.search('aaaa', 'aa'), [{ start: 0, end: 2 }, { start: 2, end: 4 }]);
    assert.deepStrictEqual(T.search('aaa', 'aa'), [{ start: 0, end: 2 }]);
    assert.deepStrictEqual(T.search('abc', ''), []);
    assert.deepStrictEqual(T.search('abc', '   '), [], 'запрос из пробелов — пустой');
    assert.deepStrictEqual(T.search('', 'a'), []);
    assert.deepStrictEqual(T.search('abc', 'abcd'), []);
    assert.deepStrictEqual(T.search('abc', null), []);
    assert.deepStrictEqual(T.search('a b', ' '), [], 'пробелы по краям запроса срезаются');
    assert.deepStrictEqual(T.search('a b', 'a b'), [{ start: 0, end: 3 }], 'пробел внутри запроса значим');
});

test('предел числа совпадений в одной строке', () => {
    assert.strictEqual(T.search('a'.repeat(1000), 'a').length, 1000);
    assert.strictEqual(T.search('a'.repeat(1000), 'a', 10).length, 10);
});

test('collectMatches: порядок ленты, ключи сообщений, предел 500 и признак capped', () => {
    const entries = [
        { key: 'm1', folded: T.foldText('Привет мир') },
        { key: 'm2', folded: T.foldText('нет совпадений') },
        { key: 'm3', folded: T.foldText('ещё ПРИВЕТ и привет') },
        { key: 'm4', folded: null },
    ];
    const found = T.collectMatches(entries, 'привет');
    assert.deepStrictEqual(found.matches.map(m => m.key), ['m1', 'm3', 'm3']);
    assert.strictEqual(found.capped, false);
    assert.deepStrictEqual(found.matches[0], { key: 'm1', start: 0, end: 6 });
    assert.deepStrictEqual(T.collectMatches(entries, '  '), { matches: [], capped: false });

    const many = Array.from({ length: 600 }, (_, i) => ({ key: 'k' + i, folded: T.foldText('слово слово') }));
    const capped = T.collectMatches(many, 'слово');
    assert.strictEqual(T.MAX_MATCHES, 500);
    assert.strictEqual(capped.matches.length, 500);
    assert.strictEqual(capped.capped, true);
    // Ровно на пределе — не capped.
    const exact = T.collectMatches(many.slice(0, 250), 'слово');
    assert.strictEqual(exact.matches.length, 500);
    assert.strictEqual(exact.capped, false);
    // Предел обрезает и внутри одного сообщения.
    const one = T.collectMatches([{ key: 'x', folded: T.foldText('а'.repeat(20)) }], 'а', 5);
    assert.strictEqual(one.matches.length, 5);
    assert.strictEqual(one.capped, true);
});

test('filterChats: по названию, закреплённые сверху, архивные участвуют, без запроса — null', () => {
    const chats = [
        { id: 1, name: 'Работа', pinned: false, archived: false },
        { id: 2, name: 'Ёлка (архив)', pinned: false, archived: true },
        { id: 3, name: 'Семья и работа', pinned: true, archived: false },
        { id: 4, name: 'Друзья', pinned: false, archived: false },
        { id: 5, name: 'РАБОТА 2', pinned: false, archived: true },
    ];
    assert.strictEqual(T.filterChats(chats, ''), null);
    assert.strictEqual(T.filterChats(chats, '   '), null);
    assert.strictEqual(T.filterChats(chats, null), null);
    const work = T.filterChats(chats, 'РАБОТ');
    assert.deepStrictEqual(work.map(x => x.chat.id), [3, 1, 5], 'закреплённый первым, дальше порядок списка, архив включён');
    assert.deepStrictEqual(work[0].ranges, [{ start: 8, end: 13 }]);
    assert.deepStrictEqual(T.filterChats(chats, 'елка').map(x => x.chat.id), [2], 'е находит ё');
    assert.deepStrictEqual(T.filterChats(chats, 'нет такого'), []);
    assert.deepStrictEqual(T.filterChats([], 'а'), []);
    assert.deepStrictEqual(T.filterChats(null, 'а'), []);
    assert.deepStrictEqual(T.filterChats([{ id: 9 }, { id: 8, name: null }], 'а'), [], 'чат без названия не падает');
});

test('splitSegments: куски покрывают весь текст, совпавшие помечены', () => {
    assert.deepStrictEqual(T.splitSegments('привет мир', [{ start: 0, end: 6 }]), [
        { text: 'привет', match: true }, { text: ' мир', match: false },
    ]);
    assert.deepStrictEqual(T.splitSegments('aXbXc', [{ start: 1, end: 2 }, { start: 3, end: 4 }]), [
        { text: 'a', match: false }, { text: 'X', match: true }, { text: 'b', match: false },
        { text: 'X', match: true }, { text: 'c', match: false },
    ]);
    assert.deepStrictEqual(T.splitSegments('abc', []), [{ text: 'abc', match: false }]);
    assert.deepStrictEqual(T.splitSegments('', []), []);
    assert.deepStrictEqual(T.splitSegments('abc', [{ start: 0, end: 99 }]), [{ text: 'abc', match: true }], 'диапазон обрезается по тексту');
    assert.deepStrictEqual(T.splitSegments('abc', [{ start: 5, end: 9 }]), [{ text: 'abc', match: false }], 'за текстом — игнорируется');
    const text = 'Привет Мир';
    const joined = T.splitSegments(text, T.search(text, 'мир')).map(s => s.text).join('');
    assert.strictEqual(joined, text, 'склейка кусков равна исходному тексту');
});

test('stepIndex: по кругу вперёд и назад; без совпадений — -1', () => {
    assert.strictEqual(T.stepIndex(0, 3, 1), 1);
    assert.strictEqual(T.stepIndex(2, 3, 1), 0, 'после последнего — первое');
    assert.strictEqual(T.stepIndex(0, 3, -1), 2, 'перед первым — последнее');
    assert.strictEqual(T.stepIndex(-1, 3, 1), 0, 'ещё ничего не выбрано: вперёд — первое');
    assert.strictEqual(T.stepIndex(-1, 3, -1), 2, 'назад — последнее');
    assert.strictEqual(T.stepIndex(5, 3, 1), 0, 'индекс вне диапазона');
    assert.strictEqual(T.stepIndex(0, 0, 1), -1);
    assert.strictEqual(T.stepIndex(0, 1, 1), 0);
});

test('formatCounter: «3 из 12», «Ничего не найдено», пометка предела', () => {
    assert.strictEqual(T.formatCounter(2, 12, false), '3 из 12');
    assert.strictEqual(T.formatCounter(0, 1, false), '1 из 1');
    assert.strictEqual(T.formatCounter(-1, 0, false), 'Ничего не найдено');
    assert.strictEqual(T.formatCounter(0, 500, true), '1 из 500 (показаны первые 500)');
});

test('в текстах библиотеки нет эмодзи', () => {
    const source = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'lib', 'text-search.js'), 'utf8');
    assert.ok(!/\p{Extended_Pictographic}/u.test(source));
});

console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
if (failed > 0) process.exitCode = 1;
