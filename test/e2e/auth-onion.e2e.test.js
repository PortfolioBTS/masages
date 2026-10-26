'use strict';
// Поле onionUrl в GET /api/auth (контракт волны 1, §3): адрес onion-зеркала
// "http://<56 символов>.onion/" отдаётся ровно при тех же условиях, что
// заголовок Onion-Location — ONION_ADDRESS и ONION_PORT заданы и запрос пришёл
// НЕ через onion; иначе null. Признак onion — порт, на который пришло
// соединение (ONION_PORT), а не заголовки.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { freePort } = require('./helpers/server');
const { TestClient } = require('./helpers/client');
const { testOnionAddress } = require('./helpers/env');

const suite = createSuite('auth-onion', { startServer: false });

const ADDRESS = testOnionAddress('auth-onion');
const ONION_URL = `http://${ADDRESS}/`;

test('через обычный порт onionUrl есть — у гостя и у вошедшего, как и заголовок Onion-Location на страницах', async () => {
    const onionPort = await freePort();
    const server = await suite.startServer({ env: { ONION_ADDRESS: ADDRESS, ONION_PORT: onionPort } });
    suite.onionPort = onionPort;

    const guest = server.client();
    const guestAuth = await guest.auth();
    assert.deepStrictEqual(guestAuth, { authenticated: false, onionUrl: ONION_URL });
    assert.match(guestAuth.onionUrl, /^http:\/\/[a-z2-7]{56}\.onion\/$/);

    const member = server.client();
    await member.registerAnon();
    const auth = await member.auth();
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.onionUrl, ONION_URL);

    // Заголовок — на страницах, не на API; значение того же адреса.
    const page = await guest.get('/');
    assert.strictEqual(page.headers.get('onion-location'), ONION_URL);
    const api = await guest.get('/api/auth');
    assert.strictEqual(api.headers.get('onion-location'), null);
});

test('через ONION_PORT onionUrl = null и заголовка нет — даже если клиент подделал Host и X-Forwarded-*', async () => {
    assert.ok(suite.onionPort, 'предыдущий тест запустил сервер с onion-портом');
    const viaOnion = new TestClient({ baseUrl: `http://127.0.0.1:${suite.onionPort}` });
    const res = await viaOnion.get('/api/auth', { headers: { Host: ADDRESS, 'X-Forwarded-Host': 'example.test', 'X-Forwarded-For': '203.0.113.7' } });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { authenticated: false, onionUrl: null });
    const page = await viaOnion.get('/');
    assert.strictEqual(page.status, 200);
    assert.strictEqual(page.headers.get('onion-location'), null);

    // Обратное: обычный порт с Host вида .onion onion-запросом не становится.
    const direct = suite.server.client();
    const forged = await direct.get('/api/auth', { headers: { 'X-Forwarded-Host': ADDRESS } });
    assert.strictEqual(forged.body.onionUrl, ONION_URL);
});

test('ONION_ADDRESS без ONION_PORT, адрес не v3 или ничего не задано — onionUrl = null', async () => {
    const cases = [
        ['адрес без порта', { ONION_ADDRESS: ADDRESS, ONION_PORT: null }],
        ['порт без адреса', { ONION_ADDRESS: null, ONION_PORT: await freePort() }],
        ['адрес не v3', { ONION_ADDRESS: 'abcdefghijklmnop.onion', ONION_PORT: await freePort() }],
        ['ничего не задано', { ONION_ADDRESS: null, ONION_PORT: null }],
    ];
    for (const [what, env] of cases) {
        const server = suite.newServer({ name: `auth-onion-off`, env });
        await server.start();
        try {
            const res = await server.client().get('/api/auth');
            assert.deepStrictEqual(res.body, { authenticated: false, onionUrl: null }, what);
            assert.strictEqual((await server.client().get('/')).headers.get('onion-location'), null, what);
        } finally {
            await server.stop();
        }
    }
});
