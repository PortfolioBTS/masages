'use strict';
// Строгий разбор недоверенного ввода в ядре E2EE (ревью R4 W7, З7; влияния на безопасность найдено не было, это
// ужесточение): unpadMessage проверяет нули дополнения и длину класса Padmé; decodeFixed и b64decodeCanonical принимают
// только каноническое base64 (алфавит, выравнивание "=", нулевые лишние биты), а не "очищенную" версию строки.
// Запуск: node test/codec-strict.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Codec = require('../public/lib/e2ee-codec.js');

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

const enc = (text) => new TextEncoder().encode(text);

console.log('Строгий разбор: дополнение и base64 (З7)\n');

test('unpadMessage: честное дополнение читается; ненулевые байты дополнения, лишняя или недостающая длина - отказ', () => {
    for (const text of ['', 'a', 'привет', 'x'.repeat(300), 'y'.repeat(5000)]) {
        const padded = Codec.padMessage(enc(text));
        assert.strictEqual(new TextDecoder().decode(Codec.unpadMessage(padded)), text);
    }
    const padded = Codec.padMessage(enc('сообщение'));
    // Ненулевой байт в дополнении.
    const dirty = padded.slice();
    dirty[dirty.length - 1] = 1;
    assert.strictEqual(Codec.unpadMessage(dirty), null);
    // Длина не из класса Padmé: дописанный нулевой байт и обрезанный хвост.
    assert.strictEqual(Codec.unpadMessage(Buffer.concat([padded, Buffer.alloc(1)])), null);
    assert.strictEqual(Codec.unpadMessage(padded.subarray(0, padded.length - 1)), null);
    // Объявленная длина больше буфера; короче заголовка.
    const lying = padded.slice();
    lying[0] = 0xFF;
    assert.strictEqual(Codec.unpadMessage(lying), null);
    assert.strictEqual(Codec.unpadMessage(new Uint8Array(3)), null);
});

test('b64decodeCanonical и decodeFixed: только каноническое base64', () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const good = Codec.b64encode(bytes);
    assert.deepStrictEqual(Array.from(Codec.decodeFixed(good, 32)), Array.from(bytes));
    assert.deepStrictEqual(Array.from(Codec.b64decodeCanonical(good)), Array.from(bytes));
    assert.deepStrictEqual(Array.from(Codec.b64decodeCanonical('')), []);
    // Посторонние символы, переводы строк и пробелы раньше молча вычищались.
    for (const bad of [good.slice(0, 10) + '\n' + good.slice(10), ' ' + good, good + ' ', 
        good.slice(0, -1), good.slice(0, -1) + '==', good + '=', good.slice(0, 20) + '=' + good.slice(21)]) {
        assert.strictEqual(Codec.decodeFixed(bad, 32), null, JSON.stringify(bad));
        assert.strictEqual(Codec.b64decodeCanonical(bad), null, JSON.stringify(bad));
    }
    // URL-вариант алфавита (-, _) вместо +, /.
    const plusSlash = Codec.b64encode(Uint8Array.from([0xfb, 0xff, 0xbf]));
    assert.strictEqual(plusSlash, '+/+/');
    assert.deepStrictEqual(Array.from(Codec.decodeFixed(plusSlash, 3)), [0xfb, 0xff, 0xbf]);
    assert.strictEqual(Codec.decodeFixed('-_-_', 3), null);
    // Лишние (ненулевые) биты в последнем символе: "A" и "B" в конце 32 байт дают один и тот же результат без проверки.
    const sameBytes = good.slice(0, -2) + (good.slice(-2, -1) === 'A' ? 'B' : 'A') + '=';
    assert.strictEqual(Codec.decodeFixed(sameBytes, 32), null, 'неканоническое написание тех же байт');
    assert.strictEqual(Codec.decodeFixed(5, 32), null);
    assert.strictEqual(Codec.b64decodeCanonical(null), null);
});

test('поля конверта ct разбираются каноническим декодером (сообщение комнаты и key-share)', () => {
    const read = (name) => fs.readFileSync(path.join(__dirname, '..', 'public', name), 'utf8');
    assert.match(read('lib/e2ee-formats.js'), /env\.ct === 'string' \? b64decodeCanonical\(env\.ct\)/);
    assert.match(read('e2ee.js'), /envelope\.ct === 'string' \? b64decodeCanonical\(envelope\.ct\)/);
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
