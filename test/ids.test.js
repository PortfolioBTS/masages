'use strict';
// Разбор id из запроса (W7 R1 п.7, R2.7): lib/ids.js и его использование в src/http/params.js.
// Запуск: node test/ids.test.js

const assert = require('assert');
const { toPositiveInt, PG_INT_MAX } = require('../lib/ids');
const params = require('../src/http/params');

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

test('верхняя граница - INTEGER Postgres', () => {
    assert.strictEqual(PG_INT_MAX, 2147483647);
    assert.strictEqual(toPositiveInt(2147483647), 2147483647);
    assert.strictEqual(toPositiveInt('2147483647'), 2147483647);
    assert.strictEqual(toPositiveInt(2147483648), null);
    assert.strictEqual(toPositiveInt('2147483648'), null);
    assert.strictEqual(toPositiveInt('99999999999999999999'), null);
    assert.strictEqual(toPositiveInt(Number.MAX_SAFE_INTEGER), null);
    assert.strictEqual(toPositiveInt(Infinity), null);
});

test('допустимы число и строка из цифр, больше нуля', () => {
    assert.strictEqual(toPositiveInt(1), 1);
    assert.strictEqual(toPositiveInt('1'), 1);
    assert.strictEqual(toPositiveInt('0012'), 12);
    assert.strictEqual(toPositiveInt('1234567890'), 1234567890);
    for (const bad of [0, -1, '0', '-1', 1.5, NaN, '1.5', '5.0', '', ' ', ' 5', '5 ', '1e3', '0x10', '+5', '１２']) {
        assert.strictEqual(toPositiveInt(bad), null, JSON.stringify(bad));
    }
});

test('R2.7: объекты, массивы, boolean и прочее не бросают и дают null', () => {
    const hostile = [
        { toString: 1 }, { valueOf: 1 }, { toString: () => '5' }, { valueOf: () => 5 }, [5], ['5'], [], {}, null, undefined,
        true, false, Symbol('x'), () => 5, 10n, new Date(5), Object.create(null),
    ];
    for (const value of hostile) {
        let result;
        assert.doesNotThrow(() => { result = toPositiveInt(value); }, String(typeof value));
        assert.strictEqual(result, null, String(typeof value));
    }
});

test('src/http/params.js отдаёт тот же разбор', () => {
    assert.strictEqual(params.toPositiveInt, toPositiveInt);
    assert.strictEqual(params.isNonEmptyString(' a '), true);
    assert.strictEqual(params.isNonEmptyString('  '), false);
    assert.strictEqual(params.isNonEmptyString(5), false);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
