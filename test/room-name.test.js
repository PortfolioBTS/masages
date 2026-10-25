'use strict';
// Название комнаты и аватар (W7 R1 п.11): lib/room-name.js.
// Запуск: node test/room-name.test.js
// Невидимые символы в тесте задаются кодовыми точками (cp), а не записываются в исходнике.

const assert = require('assert');
const { cleanRoomName, avatarOfName, MAX_ROOM_NAME_LENGTH } = require('../lib/room-name');

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

const cp = (...codes) => String.fromCodePoint(...codes);
const hex = (code) => `U+${code.toString(16).toUpperCase()}`;

test('обычное название не меняется, края обрезаются, пробелы схлопываются', () => {
    assert.strictEqual(cleanRoomName('Друзья'), 'Друзья');
    assert.strictEqual(cleanRoomName('  Рабочий   чат  '), 'Рабочий чат');
    assert.strictEqual(cleanRoomName('Чат 🚀 команды'), 'Чат 🚀 команды');
    assert.strictEqual(cleanRoomName('日本語 グループ'), '日本語 グループ');
});

test('двунаправленные символы удаляются: U+202A-202E и U+2066-2069 (подделка порядка букв)', () => {
    for (const code of [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]) {
        assert.strictEqual(cleanRoomName(`adm${cp(code)}in`), 'admin', hex(code));
    }
    assert.strictEqual(cleanRoomName(`${cp(0x202E)}татнорп${cp(0x202C)} группа`), 'татнорп группа');
});

test('символы нулевой ширины и метки направления удаляются: U+200B-200F, U+2060-2064, U+FEFF', () => {
    for (const code of [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF]) {
        assert.strictEqual(cleanRoomName(`ad${cp(code)}min`), 'admin', hex(code));
    }
    // Два «одинаковых» названия, различавшиеся невидимым символом, после очистки равны.
    assert.strictEqual(cleanRoomName('Команда'), cleanRoomName(`Кома${cp(0x200B)}нда`));
});

test('управляющие C0/C1 и DEL удаляются; перевод строки и табуляция между словами дают пробел', () => {
    assert.strictEqual(cleanRoomName(`a${cp(0)}b${cp(7)}c${cp(0x1B)}d${cp(0x7F)}e${cp(0x9F)}f`), 'abcdef');
    assert.strictEqual(cleanRoomName('первая\nвторая'), 'первая вторая');
    assert.strictEqual(cleanRoomName('а\tб\r\nв'), 'а б в');
    assert.strictEqual(cleanRoomName(`строка${cp(0x2028)}другая${cp(0x2029)}третья${cp(0x85)}четвёртая`), 'строка другая третья четвёртая');
});

test('tag-символы (U+E0000-E007F) и символ замены объекта удаляются', () => {
    assert.strictEqual(cleanRoomName(`a${cp(0xE0041, 0xE007F)}b${cp(0xFFFC)}c`), 'abc');
});

test('не строка и состоящее из невидимых символов - пустая строка', () => {
    for (const bad of [undefined, null, 5, {}, [], true]) assert.strictEqual(cleanRoomName(bad), '');
    assert.strictEqual(cleanRoomName(`${cp(0x202E, 0x200B)} ${cp(0x2066, 0x2069, 0)}`), '');
    assert.strictEqual(cleanRoomName('   '), '');
});

test('предел длины - 64, проверяется уже по очищенному названию', () => {
    assert.strictEqual(MAX_ROOM_NAME_LENGTH, 64);
    const padded = `${cp(0x200B).repeat(100)}${'я'.repeat(64)}`;
    assert.strictEqual(cleanRoomName(padded).length, 64);
});

test('аватар - первая графема в верхнем регистре, эмодзи не рвётся на половину суррогатной пары', () => {
    assert.strictEqual(avatarOfName('друзья'), 'Д');
    assert.strictEqual(avatarOfName('abc'), 'A');
    assert.strictEqual(avatarOfName('🚀 запуск'), '🚀');
    assert.strictEqual(avatarOfName('😀'), '😀');
    assert.strictEqual(avatarOfName('👍🏽 палец'), '👍🏽', 'эмодзи с модификатором цвета кожи - одна графема');
    assert.strictEqual(avatarOfName('🇷🇺 Россия'), '🇷🇺', 'флаг - одна графема из двух кодовых точек');
    for (const name of ['🚀 запуск', '😀', '👍🏽 палец', '🇷🇺 Россия', `${cp(0x1D49C)} x`]) {
        const avatar = avatarOfName(name);
        assert.ok(avatar.isWellFormed(), `${name}: одиночного суррогата нет`);
    }
});

test('старое поведение name.charAt(0) на эмодзи давало одиночный суррогат', () => {
    assert.strictEqual('🚀 запуск'.charAt(0).isWellFormed(), false, 'то, что исправлено');
    assert.strictEqual(avatarOfName('🚀 запуск').isWellFormed(), true);
});

test('пустое и не строка: аватар «?»', () => {
    for (const empty of ['', '   ', undefined, null, 5]) assert.strictEqual(avatarOfName(empty), '?');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
