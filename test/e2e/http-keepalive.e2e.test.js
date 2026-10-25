'use strict';
// Таймауты HTTP-сервера (W7 R1 п.12): соединение keep-alive живёт дольше умолчания Node (5 с),
// иначе прокси перед приложением отправил бы запрос в уже закрытый сокет и отдал клиенту 502.

const { test } = require('node:test');
const assert = require('assert');
const http = require('http');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('http-keepalive');

function request(agent, url) {
    return new Promise((resolve, reject) => {
        const req = http.get(url, { agent }, (res) => {
            res.resume();
            res.on('end', () => resolve({ status: res.statusCode, reused: req.reusedSocket }));
        });
        req.on('error', reject);
    });
}

test('простаивающее соединение через 6 секунд ещё открыто: второй запрос идёт по тому же сокету', async () => {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    try {
        const url = `${suite.server.baseUrl}/healthz`;
        const first = await request(agent, url);
        assert.strictEqual(first.status, 200);
        assert.strictEqual(first.reused, false);
        await new Promise(resolve => setTimeout(resolve, 6000));
        const second = await request(agent, url);
        assert.strictEqual(second.status, 200);
        assert.strictEqual(second.reused, true, 'сервер не закрыл простаивающее соединение за 6 с (умолчание Node - 5 с)');
    } finally {
        agent.destroy();
    }
});
