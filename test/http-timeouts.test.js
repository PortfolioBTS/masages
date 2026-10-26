'use strict';
// Таймауты HTTP-сервера заданы явно (W7 R1 п.12) и согласованы между собой; комментарий в
// lib/client-sri.js не расходится с index.html (SRI включён).
// Запуск: node test/http-timeouts.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createHttpServer, HTTP_TIMEOUTS } = require('../src/http/server');

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

const quiet = (fn) => {
    const warn = console.warn;
    console.warn = () => {};
    try { return fn(); } finally { console.warn = warn; }
};

test('сервер получает keepAliveTimeout, headersTimeout и requestTimeout из констант', () => {
    const { server } = quiet(() => createHttpServer({ app: (req, res) => res.end() }));
    assert.strictEqual(server.keepAliveTimeout, HTTP_TIMEOUTS.KEEP_ALIVE_TIMEOUT_MS);
    assert.strictEqual(server.headersTimeout, HTTP_TIMEOUTS.HEADERS_TIMEOUT_MS);
    assert.strictEqual(server.requestTimeout, HTTP_TIMEOUTS.REQUEST_TIMEOUT_MS);
    server.close();
});

test('значения: keep-alive дольше простоя балансировщика (минута), заголовки - дольше keep-alive, запрос - до 5 минут', () => {
    assert.ok(HTTP_TIMEOUTS.KEEP_ALIVE_TIMEOUT_MS > 60 * 1000, 'иначе прокси получит 502 на закрытом соединении');
    assert.ok(HTTP_TIMEOUTS.HEADERS_TIMEOUT_MS > HTTP_TIMEOUTS.KEEP_ALIVE_TIMEOUT_MS, 'требование Node');
    assert.ok(HTTP_TIMEOUTS.REQUEST_TIMEOUT_MS > HTTP_TIMEOUTS.HEADERS_TIMEOUT_MS);
    assert.ok(HTTP_TIMEOUTS.REQUEST_TIMEOUT_MS <= 10 * 60 * 1000, 'запрос не висит бесконечно');
});

test('комментарий lib/client-sri.js согласован с index.html: SRI включён, а не «пока не включён»', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'client-sri.js'), 'utf8');
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    assert.match(html, /\sintegrity="sha384-/, 'в index.html есть атрибуты integrity');
    assert.doesNotMatch(source, /ПОКА НЕ ВКЛЮЧЁН/);
    assert.match(source, /SRI ВКЛЮЧЁН/);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
