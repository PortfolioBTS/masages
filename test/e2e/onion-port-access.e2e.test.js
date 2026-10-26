'use strict';
// ONION_PORT принимает соединения только из разрешённой сети (W7 R1 п.6). Признак onion-режима -
// сам порт (без лимитов по IP), поэтому чужой адрес не должен до него дотянуться: сокет закрывается
// сразу. Тест подключается с 127.0.0.1: по умолчанию loopback разрешён, а при ONION_ALLOWED_CIDR из
// другой сети - закрыт.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { freePort } = require('./helpers/server');
const { TestClient } = require('./helpers/client');
const { testOnionAddress } = require('./helpers/env');

const suite = createSuite('onion-port-access', { startServer: false });
const ADDRESS = testOnionAddress('onion-port-access');

const onionClient = (port) => new TestClient({ baseUrl: `http://127.0.0.1:${port}` }, { secureContext: true });

test('по умолчанию loopback пускается: запрос через ONION_PORT обслуживается как onion', async () => {
    const onionPort = await freePort();
    await suite.startServer({ name: 'default', env: { ONION_ADDRESS: ADDRESS, ONION_PORT: onionPort } });
    const res = await onionClient(onionPort).get('/api/auth');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { authenticated: false, onionUrl: null }, 'через onion-порт onionUrl = null');
});

test('ONION_ALLOWED_CIDR из чужой сети: соединение с ONION_PORT закрывается, основной порт работает', async () => {
    const onionPort = await freePort();
    const server = await suite.startServer({ name: 'closed', env: { ONION_ADDRESS: ADDRESS, ONION_PORT: onionPort, ONION_ALLOWED_CIDR: '203.0.113.0/24' } });
    await assert.rejects(onionClient(onionPort).get('/api/auth'), (err) => /fetch failed/i.test(err.message), 'соединение оборвано');
    // Основной порт не затронут и не считается onion.
    const main = await server.client().get('/api/auth');
    assert.strictEqual(main.status, 200);
    assert.ok(main.body.onionUrl, 'на основном порту onionUrl есть');
});

test('ONION_ALLOWED_CIDR со своей сетью loopback: соединение принимается', async () => {
    const onionPort = await freePort();
    await suite.startServer({ name: 'custom', env: { ONION_ADDRESS: ADDRESS, ONION_PORT: onionPort, ONION_ALLOWED_CIDR: '127.0.0.0/8' } });
    const res = await onionClient(onionPort).get('/api/auth');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.onionUrl, null);
});

test('только некорректный ONION_ALLOWED_CIDR: действует список по умолчанию, onion не отваливается', async () => {
    const onionPort = await freePort();
    await suite.startServer({ name: 'garbage', env: { ONION_ADDRESS: ADDRESS, ONION_PORT: onionPort, ONION_ALLOWED_CIDR: 'nonsense' } });
    assert.strictEqual((await onionClient(onionPort).get('/api/auth')).status, 200);
});
