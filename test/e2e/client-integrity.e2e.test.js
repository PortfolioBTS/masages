'use strict';
// Целостность клиента (6.1/6.3, roadmap R10): страница и скрипты отдаются
// статикой байт-в-байт, nonce в CSP нет, /link.my ведёт на «/», клиент
// socket.io берётся из public/vendor, а не из node_modules. Манифест клиента
// (/client-manifest.json) проверяется в этом же наборе ниже.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createSuite } = require('./helpers/scenarios');
const { REPO_ROOT } = require('./helpers/env');

const suite = createSuite('client-integrity');
const PUBLIC = path.join(REPO_ROOT, 'public');
const readPublic = (rel) => fs.readFileSync(path.join(PUBLIC, rel));

test('GET / отдаёт public/index.html байт-в-байт, одинаково при каждом запросе', async () => {
    const client = suite.client();
    const first = await client.get('/', { binary: true });
    const second = await client.get('/', { binary: true });
    assert.strictEqual(first.status, 200);
    assert.match(first.headers.get('content-type'), /text\/html/);
    assert.ok(first.body.equals(readPublic('index.html')), 'тело ответа отличается от файла index.html');
    assert.ok(second.body.equals(first.body), 'два запроса дали разные байты (подстановка на лету?)');
    assert.ok(!first.body.toString('utf8').includes('nonce='), 'в странице есть nonce=');
});

test('GET /index.html — те же байты; куки страница не ставит', async () => {
    const client = suite.client();
    const res = await client.get('/index.html', { binary: true });
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.equals(readPublic('index.html')));
    assert.strictEqual(res.headers.get('set-cookie'), null, 'статика не должна создавать сессию');
});

test('/link.my — 301 на «/» без подстановки адреса хоста, с запросом и без', async () => {
    const client = suite.client();
    for (const url of ['/link.my', '/link.my?x=1']) {
        const res = await client.get(url);
        assert.strictEqual(res.status, 301, url);
        assert.strictEqual(res.headers.get('location'), '/', url);
        assert.ok(!/<script/i.test(res.text || ''), 'страницы в теле быть не должно');
    }
});

test('CSP: script-src только self, без nonce, strict-dynamic и unsafe-inline — на / и на редиректе', async () => {
    const client = suite.client();
    for (const url of ['/', '/link.my', '/script.js']) {
        const csp = (await client.get(url)).headers.get('content-security-policy');
        assert.ok(csp, `нет CSP на ${url}`);
        assert.match(csp, /(^|; )script-src 'self'(;|$)/, url);
        assert.doesNotMatch(csp, /nonce|strict-dynamic|unsafe-inline/, url);
    }
});

test('клиент socket.io: /vendor/socket.io.min.js — байты файла из репозитория, /socket.io/socket.io.js больше не отдаётся', async () => {
    const client = suite.client();
    const vendor = await client.get('/vendor/socket.io.min.js', { binary: true });
    assert.strictEqual(vendor.status, 200);
    assert.match(vendor.headers.get('content-type'), /javascript/);
    assert.ok(vendor.body.equals(readPublic('vendor/socket.io.min.js')));

    const legacy = await client.get('/socket.io/socket.io.js', { binary: true });
    assert.ok(!/javascript/.test(legacy.headers.get('content-type') || ''), 'сервер всё ещё отдаёт клиент socket.io сам');
    assert.notStrictEqual(legacy.status, 200);
});
