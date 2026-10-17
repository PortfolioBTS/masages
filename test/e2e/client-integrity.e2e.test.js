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
const crypto = require('crypto');
const { spawnSync } = require('child_process');
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
    for (const url of ['/', '/link.my', '/js/01-state.js']) {
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

// ---- Манифест клиента ----

const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');

test('GET /client-manifest.json: JSON без кук и кэша; тело — те же байты, что собирает scripts/release-manifest.js', async () => {
    const client = suite.client();
    const res = await client.get('/client-manifest.json', { binary: true });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /^application\/json/);
    assert.match(res.headers.get('cache-control'), /no-store/, 'сверка не должна читать манифест из кэша');
    assert.strictEqual(res.headers.get('set-cookie'), null, 'манифест не создаёт сессию');
    assert.strictEqual(res.headers.get('x-client-manifest-sha256'), sha256(res.body));

    const script = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'release-manifest.js'), '--stdout'], { cwd: REPO_ROOT });
    assert.strictEqual(script.status, 0, script.stderr.toString());
    assert.ok(res.body.equals(script.stdout), 'сервер и скрипт релиза отдали разные манифесты');

    const manifest = JSON.parse(res.body.toString('utf8'));
    assert.strictEqual(manifest.format, 'nyxo-client-manifest/1');
    assert.ok(manifest.files.some((file) => file.path === '/vendor/socket.io.min.js'), 'в манифесте нет клиента socket.io');
});

test('каждый файл манифеста сервер отдаёт именно с этим sha256 и размером; «/» — index.html', async () => {
    const client = suite.client();
    const manifest = JSON.parse((await client.get('/client-manifest.json')).text);
    assert.ok(manifest.files.length >= 20);
    for (const file of manifest.files) {
        const res = await client.get(file.path, { binary: true });
        assert.strictEqual(res.status, 200, file.path);
        assert.strictEqual(sha256(res.body), file.sha256, `${file.path}: хэш отдаваемых байтов не совпал с манифестом`);
        assert.strictEqual(res.body.length, file.bytes, file.path);
    }
    const index = manifest.files.find((file) => file.path === manifest.aliases['/']);
    assert.strictEqual(sha256((await client.get('/', { binary: true })).body), index.sha256);
});

test('манифест не меняется между запросами и после перезапуска сервера', async () => {
    const first = await suite.client().get('/client-manifest.json');
    const second = await suite.client().get('/client-manifest.json');
    assert.strictEqual(second.text, first.text);
    await suite.server.restart();
    const afterRestart = await suite.client().get('/client-manifest.json');
    assert.strictEqual(afterRestart.text, first.text);
});
