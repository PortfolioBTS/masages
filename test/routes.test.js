'use strict';
// Точки регистрации маршрутов (lib/routes/index.js) и JSON-404 для /api —
// на настоящем Express в памяти, без БД.
// Запуск: node test/routes.test.js

const assert = require('assert');
const http = require('http');
const express = require('express');
const {
    registerPreSessionRoutes,
    registerApiRoutes,
    registerApiNotFound,
    PRE_SESSION_ROUTES,
    API_ROUTES,
} = require('../lib/routes');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

async function withServer(app, fn) {
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

async function main() {
    console.log('Routes registry tests\n');

    await test('списки модулей пока пусты, регистрация ничего не ломает', () => {
        assert.ok(Array.isArray(PRE_SESSION_ROUTES) && Array.isArray(API_ROUTES));
        const app = express();
        registerPreSessionRoutes(app, {});
        registerApiRoutes(app, {});
    });

    await test('модули регистрируются по порядку списка и получают ctx', () => {
        const calls = [];
        const ctx = { marker: 1 };
        const mods = ['a', 'b'].map(name => ({ register: (app, c) => calls.push([name, c === ctx]) }));
        registerApiRoutes({}, ctx, mods);
        registerPreSessionRoutes({}, ctx, mods.slice().reverse());
        assert.deepStrictEqual(calls, [['a', true], ['b', true], ['b', true], ['a', true]]);
    });

    await test('неизвестный /api/* → 404 JSON; известный маршрут и не-API не задеты', async () => {
        const app = express();
        app.get('/api/known', (req, res) => res.json({ success: true }));
        registerApiNotFound(app);
        await withServer(app, async (base) => {
            const unknown = await fetch(`${base}/api/does-not-exist?x=1`);
            assert.strictEqual(unknown.status, 404);
            assert.match(unknown.headers.get('content-type'), /application\/json/);
            assert.deepStrictEqual(await unknown.json(), { success: false, message: 'Не найдено' });

            const post = await fetch(`${base}/api/nested/path`, { method: 'POST' });
            assert.strictEqual(post.status, 404);
            assert.deepStrictEqual(await post.json(), { success: false, message: 'Не найдено' });

            const bare = await fetch(`${base}/api`);
            assert.strictEqual(bare.status, 404);
            assert.strictEqual((await bare.json()).message, 'Не найдено');

            const known = await fetch(`${base}/api/known`);
            assert.deepStrictEqual(await known.json(), { success: true });

            // Не-API пути — по-прежнему стандартный 404 Express (HTML), не JSON.
            const page = await fetch(`${base}/apix`);
            assert.strictEqual(page.status, 404);
            assert.doesNotMatch(page.headers.get('content-type') || '', /application\/json/);
        });
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
