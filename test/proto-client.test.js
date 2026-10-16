'use strict';
// Общий признак версии клиента proto в запросах ключей (message-ordering.md, 14.1): клиент E2EE
// шлёт его в PUT /api/keys/identity и POST /api/keys/key-shares, значение равно PROTO_CURRENT сервера.
// Запуск: node test/proto-client.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { PROTO_CURRENT } = require('../lib/proto');

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

const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'e2ee.js'), 'utf8');

test('PROTO_VERSION в e2ee.js равен PROTO_CURRENT сервера', () => {
    const match = /^\s*const PROTO_VERSION = (\d+);/m.exec(source);
    assert.ok(match, 'в e2ee.js нет константы PROTO_VERSION');
    assert.strictEqual(Number(match[1]), PROTO_CURRENT);
});

test('транспорт ключей добавляет proto к putIdentity и postKeyShares', () => {
    assert.ok(source.includes("call('/api/keys/identity', 'PUT', { ...body, proto: PROTO_VERSION })"));
    assert.ok(source.includes("call('/api/keys/key-shares', 'POST', { chatId, shares, proto: PROTO_VERSION })"));
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
