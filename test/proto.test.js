'use strict';
// Общий признак версии клиента proto (docs/security/message-ordering.md, 14.1):
// lib/proto.js. Нет поля, оно не целое или меньше PROTO_MIN — клиент устарел;
// значение больше PROTO_CURRENT принимается.
// Запуск: node test/proto.test.js

const assert = require('assert');
const { PROTO_CURRENT, PROTO_MIN, parseProto, isClientOutdated } = require('../lib/proto');

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

test('константы волны 4: текущий и минимальный признак — 4', () => {
    assert.strictEqual(PROTO_CURRENT, 4);
    assert.strictEqual(PROTO_MIN, 4);
    assert.ok(PROTO_CURRENT >= PROTO_MIN);
});

test('parseProto: целое число или строка из цифр (поле формы), остальное - null', () => {
    assert.strictEqual(parseProto(4), 4);
    assert.strictEqual(parseProto('4'), 4);
    assert.strictEqual(parseProto(0), 0);
    assert.strictEqual(parseProto('007'), 7);
    for (const bad of [undefined, null, '', ' 4', '4 ', '4.0', 4.5, -1, '-1', NaN, Infinity, '1e1', '0x4', true, [], {}, '99999999999', 1000, '1000', ['4']]) {
        assert.strictEqual(parseProto(bad), null, String(JSON.stringify(bad)));
    }
});

test('isClientOutdated: нет поля, не целое или меньше PROTO_MIN - устарел; равное и большее - принимается', () => {
    for (const old of [undefined, null, '', 0, 1, 3, '3', 'x', 3.9, -4, NaN, {}, [4], true]) {
        assert.strictEqual(isClientOutdated(old), true, String(JSON.stringify(old)));
    }
    for (const ok of [4, '4', 5, '5', 99, '999']) {
        assert.strictEqual(isClientOutdated(ok), false, String(ok));
    }
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
