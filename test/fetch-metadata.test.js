'use strict';
// Межсайтовые запросы к API (W7 R1 п.5): isCrossSiteApiRequest из lib/security-utils.js.
// Запуск: node test/fetch-metadata.test.js

const assert = require('assert');
const { isCrossSiteApiRequest } = require('../lib/security-utils');

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

test('cross-site к /api и вложенным путям - отклоняется', () => {
    for (const path of ['/api', '/api/', '/api/messages/5', '/api/keys/key-shares/7', '/api/auth']) {
        assert.strictEqual(isCrossSiteApiRequest({ secFetchSite: 'cross-site', path }), true, path);
    }
});

test('same-origin, same-site, none и отсутствие заголовка - проходят (свой клиент, зеркала, адресная строка, curl)', () => {
    for (const secFetchSite of ['same-origin', 'same-site', 'none', undefined, '', 'Cross-Site', 'other']) {
        assert.strictEqual(isCrossSiteApiRequest({ secFetchSite, path: '/api/messages/5' }), false, String(secFetchSite));
    }
});

test('не-API пути (страницы, статика, вложения, сокеты) cross-site не затрагивается', () => {
    for (const path of ['/', '/index.html', '/uploads/abc.jpg', '/socket.io/', '/apiary', '/api-docs', '/health', '/x/api/y', undefined, null]) {
        assert.strictEqual(isCrossSiteApiRequest({ secFetchSite: 'cross-site', path }), false, String(path));
    }
});

test('без аргументов не падает', () => {
    assert.strictEqual(isCrossSiteApiRequest(), false);
    assert.strictEqual(isCrossSiteApiRequest({}), false);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
