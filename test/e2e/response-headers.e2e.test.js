'use strict';
// Заголовки ответов (W7 R1 п.9): нет «X-Powered-By: Express»; ответы engine.io (/socket.io/) идут мимо
// цепочки Express и раньше не получали заголовков приватности (nosniff, DENY, no-referrer и т.д.).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('response-headers');

const PRIVACY = {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'cross-origin-resource-policy': 'same-origin',
    'cross-origin-opener-policy': 'same-origin',
    'x-xss-protection': '0',
};

test('X-Powered-By нет ни у API, ни у страниц, ни у 404, ни у ошибок', async () => {
    const a = suite.client();
    await a.registerAnon();
    for (const path of ['/', '/api/auth', '/api/chats', '/healthz', '/definitely-not-here', '/api/nope', '/uploads/zzzz.jpg', '/api/messages/%']) {
        const res = await a.get(path);
        assert.strictEqual(res.headers.get('x-powered-by'), null, path);
    }
    const post = await a.post('/api/chats', { name: '' });
    assert.strictEqual(post.headers.get('x-powered-by'), null);
});

test('ответ engine.io на рукопожатие: заголовки приватности и запрет кэширования; X-Powered-By нет', async () => {
    const res = await fetch(`${suite.server.baseUrl}/socket.io/?EIO=4&transport=polling`, { headers: { Origin: suite.server.baseUrl } });
    assert.strictEqual(res.status, 200);
    const body = await res.text();
    assert.match(body, /"sid":"/, 'это настоящее рукопожатие engine.io');
    for (const [name, value] of Object.entries(PRIVACY)) assert.strictEqual(res.headers.get(name), value, name);
    assert.match(res.headers.get('cache-control'), /no-store/);
    assert.strictEqual(res.headers.get('x-powered-by'), null);
});

test('ответ engine.io на следующие запросы сессии (long-polling) тоже с заголовками', async () => {
    const a = suite.client();
    await a.registerAnon();
    const headers = { Origin: suite.server.baseUrl, Cookie: a.jar.header('/socket.io/') };
    const first = await fetch(`${suite.server.baseUrl}/socket.io/?EIO=4&transport=polling`, { headers });
    const sid = JSON.parse((await first.text()).slice(1)).sid;
    const connect = await fetch(`${suite.server.baseUrl}/socket.io/?EIO=4&transport=polling&sid=${sid}`, { method: 'POST', headers, body: '40' });
    await connect.text();
    for (const [name, value] of Object.entries(PRIVACY)) assert.strictEqual(connect.headers.get(name), value, `POST: ${name}`);
    const poll = await fetch(`${suite.server.baseUrl}/socket.io/?EIO=4&transport=polling&sid=${sid}`, { headers });
    await poll.text();
    for (const [name, value] of Object.entries(PRIVACY)) assert.strictEqual(poll.headers.get(name), value, `GET: ${name}`);
    assert.match(poll.headers.get('cache-control'), /no-store/);
});

test('отказанное рукопожатие (чужой Origin): 403 и тоже без X-Powered-By', async () => {
    const res = await fetch(`${suite.server.baseUrl}/socket.io/?EIO=4&transport=polling`, { headers: { Origin: 'https://evil.example' } });
    assert.strictEqual(res.status, 403);
    await res.text();
    assert.strictEqual(res.headers.get('x-powered-by'), null);
});
