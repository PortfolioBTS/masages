'use strict';
// Service worker с закреплением кода (6.2, roadmap R10) на настоящем сервере:
// как отдаются /sw.js и его зависимости, что sw.js не входит в манифест клиента,
// как работает аварийное снятие SW_KILL_SWITCH=yes. Сам service worker в браузере
// проверяется вручную (docs/ops/service-worker.md); здесь — то, что ему отдаёт сервер.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createSuite } = require('./helpers/scenarios');
const { REPO_ROOT } = require('./helpers/env');

const suite = createSuite('service-worker');
const PUBLIC = path.join(REPO_ROOT, 'public');
const readPublic = (rel) => fs.readFileSync(path.join(PUBLIC, rel));

test('GET /sw.js: настоящий public/sw.js, JavaScript, Cache-Control no-cache (браузер сверяет скрипт при каждой проверке), без кук', async () => {
    const client = suite.client();
    const res = await client.get('/sw.js', { binary: true });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /javascript/);
    assert.strictEqual(res.headers.get('cache-control'), 'no-cache');
    assert.strictEqual(res.headers.get('set-cookie'), null);
    assert.ok(res.body.equals(readPublic('sw.js')));
    // Корневой scope: заголовок Service-Worker-Allowed не нужен и не отдаётся.
    assert.strictEqual(res.headers.get('service-worker-allowed'), null);
});

test('CSP разрешает воркеры только со своего origin (регистрация sw.js и pow-worker.js)', async () => {
    const csp = (await suite.client().get('/sw.js')).headers.get('content-security-policy');
    assert.match(csp, /(^|; )worker-src 'self'(;|$)/);
    assert.match(csp, /(^|; )connect-src 'self'/, 'SW ходит за манифестом и файлами только на свой origin');
});

test('манифест клиента: sw.js в нём нет, ядро и зависимости SW есть и отдаются теми же байтами', async () => {
    const client = suite.client();
    const manifest = (await client.get('/client-manifest.json')).body;
    const paths = manifest.files.map((file) => file.path);
    assert.ok(!paths.includes('/sw.js'), 'sw.js закрепляет хэш манифеста и не может быть его частью');
    for (const dependency of ['/lib/sw-core.js', '/lib/sw-client.js', '/lib/client-verify.js']) {
        assert.ok(paths.includes(dependency), dependency);
        const res = await client.get(dependency, { binary: true });
        assert.strictEqual(res.status, 200, dependency);
        assert.ok(res.body.equals(readPublic(dependency.slice(1))), dependency);
    }
});

test('страницы для SW не меняются на лету: / и /verify.html — статические байты без кук (закреплённую копию можно сверять с манифестом)', async () => {
    const client = suite.client();
    for (const [url, file] of [['/', 'index.html'], ['/verify.html', 'verify.html']]) {
        const res = await client.get(url, { binary: true });
        assert.strictEqual(res.status, 200, url);
        assert.ok(res.body.equals(readPublic(file)), url);
        assert.strictEqual(res.headers.get('set-cookie'), null, url);
    }
});

test('API и вложения кэшировать нельзя: ответы /api/* без разрешающих кэш заголовков', async () => {
    const res = await suite.client().get('/api/auth');
    assert.match(res.headers.get('cache-control'), /no-store/);
});

test('SW_KILL_SWITCH=yes: /sw.js отдаёт скрипт снятия, остальные файлы — как обычно; "no" и пустое значение ничего не меняют', async () => {
    const killed = await suite.newServer({ env: { SW_KILL_SWITCH: 'yes' }, name: 'kill-switch' }).start();
    const client = killed.client();
    const res = await client.get('/sw.js');
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /javascript/);
    assert.strictEqual(res.headers.get('cache-control'), 'no-cache');
    assert.match(res.text, /registration\.unregister\(\)/);
    assert.match(res.text, /startsWith\('nyxo-'\)/);
    assert.doesNotMatch(res.text, /importScripts/, 'это не закрепляющий SW');
    assert.ok(killed.logs.text().includes('SW_KILL_SWITCH=yes'), 'в логе оператора видно, что переключатель включён');

    const core = await client.get('/lib/sw-core.js', { binary: true });
    assert.ok(core.body.equals(readPublic('lib/sw-core.js')));
    const index = await client.get('/', { binary: true });
    assert.ok(index.body.equals(readPublic('index.html')));

    const manifest = (await client.get('/client-manifest.json')).body;
    assert.ok(!manifest.files.some((file) => file.path === '/sw.js'), 'снятие не добавляет sw.js в манифест');

    for (const value of ['no', '']) {
        const plain = await suite.newServer({ env: { SW_KILL_SWITCH: value }, name: `kill-${value || 'empty'}` }).start();
        const body = await plain.client().get('/sw.js', { binary: true });
        assert.ok(body.body.equals(readPublic('sw.js')), `SW_KILL_SWITCH="${value}" не должен подменять sw.js`);
    }
});
