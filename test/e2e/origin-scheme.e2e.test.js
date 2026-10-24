'use strict';
// Проверка источника запроса (W7 R1 п.10) на настоящем сервере: схема Origin против
// X-Forwarded-Proto, значение X-Forwarded-Host от доверенного прокси - последнее в списке,
// а при TRUST_PROXY=0 заголовки X-Forwarded-* не учитываются вообще.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('origin-scheme', { startServer: false });

// POST /api/chats с нужными Origin и X-Forwarded-*; клиент заранее получил куки по обычному запросу.
async function postChat(client, headers, origin) {
    await client.csrfToken();
    return client.post('/api/chats', { name: 'Проверка источника' }, { origin, headers });
}

test('TRUST_PROXY=1 (по умолчанию): схема Origin сверяется с X-Forwarded-Proto', async () => {
    const server = await suite.startServer({ name: 'default' });
    const host = new URL(server.baseUrl).host;
    const a = server.client();
    await a.registerAnon();

    const https = await postChat(a, { 'X-Forwarded-Proto': 'https' }, `https://${host}`);
    assert.strictEqual(https.status, 200, JSON.stringify(https.body));
    assert.strictEqual(https.body.success, true);

    const downgrade = await postChat(a, { 'X-Forwarded-Proto': 'https' }, `http://${host}`);
    assert.strictEqual(downgrade.status, 403, 'страница по http того же хоста, запрос по https');
    assert.match(downgrade.body.message, /чужого сайта/);

    const plain = await postChat(a, { 'X-Forwarded-Proto': 'http' }, `http://${host}`);
    assert.strictEqual(plain.status, 200, JSON.stringify(plain.body));
    const mismatch = await postChat(a, { 'X-Forwarded-Proto': 'http' }, `https://${host}`);
    assert.strictEqual(mismatch.status, 403);

    // Протокол неизвестен (нет X-Forwarded-Proto): как раньше, схема не сверяется.
    const unknown = await postChat(a, {}, `http://${host}`);
    assert.strictEqual(unknown.status, 200, JSON.stringify(unknown.body));
});

test('TRUST_PROXY=1: хостом считается значение X-Forwarded-Host, добавленное прокси (последнее), а не присланное клиентом', async () => {
    const server = suite.servers[0];
    const a = server.client();
    await a.registerAnon();
    const forged = await postChat(a, { 'X-Forwarded-Host': 'evil.example, other.example' }, 'https://evil.example');
    assert.strictEqual(forged.status, 403, 'первое (клиентское) значение своим хостом не считается');
    const proxyAdded = await postChat(a, { 'X-Forwarded-Host': 'evil.example, app.example' }, 'https://app.example');
    assert.strictEqual(proxyAdded.status, 200, JSON.stringify(proxyAdded.body));
});

test('TRUST_PROXY=0: X-Forwarded-Host не делает чужой Origin своим, X-Forwarded-Proto игнорируется', async () => {
    const server = await suite.startServer({ name: 'no-proxy', env: { TRUST_PROXY: '0' } });
    const host = new URL(server.baseUrl).host;
    const a = server.client();
    await a.registerAnon();
    const forged = await postChat(a, { 'X-Forwarded-Host': 'evil.example' }, 'https://evil.example');
    assert.strictEqual(forged.status, 403, 'без доверенного прокси хост - только Host');
    const own = await postChat(a, { 'X-Forwarded-Proto': 'https' }, `http://${host}`);
    assert.strictEqual(own.status, 200, JSON.stringify(own.body));
});
