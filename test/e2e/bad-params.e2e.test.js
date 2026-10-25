'use strict';
// Некорректные параметры запроса (W7 R1 п.7, R2.7): битое %-кодирование в пути, id вне диапазона
// INTEGER и объекты вместо чисел раньше давали 500 и запись «Unhandled error» в логе (и 22003 из
// Postgres). Теперь это 400/404 или обычный отказ JSON без записи об ошибке сервера.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('bad-params');

test('битое %-кодирование в пути: 400 без записи «Unhandled error»', async () => {
    const a = suite.client();
    await a.registerAnon();
    const mark = suite.server.logs.mark();
    for (const path of [
        '/api/messages/%', '/api/messages/%E0%A4%A', '/api/chats/%zz/participants', '/api/chats/invite/%C0%AF',
        '/api/keys/bundle/%FF', '/api/keys/key-requests/%', '/uploads/%',
    ]) {
        const res = await a.get(path);
        assert.strictEqual(res.status, 400, `${path}: ${res.status} ${JSON.stringify(res.body)}`);
        assert.deepStrictEqual(res.body, { success: false, message: 'Некорректный запрос' }, path);
    }
    // POST/DELETE с битым путём - тоже 400 (CSRF и Origin пройдены).
    const del = await a.del('/api/messages/%E0');
    assert.strictEqual(del.status, 400);
    assert.strictEqual(suite.server.logs.count('Unhandled error', { from: mark }), 0, 'в логе нет «Unhandled error»');
    // Сервер жив и обслуживает обычные запросы.
    assert.strictEqual((await a.get('/api/chats')).status, 200);
});

test('id вне диапазона INTEGER и не числа в пути: отказ JSON, а не 500 из Postgres', async () => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const { memberChat } = await roomWithMember(owner, member);
    const mark = suite.server.logs.mark();
    const huge = ['2147483648', '99999999999', '99999999999999999999', '1e3', '0x10', '5.0', '-1', '0'];
    for (const id of huge) {
        for (const path of [
            `/api/messages/${id}`, `/api/chats/${id}/participants`, `/api/chats/${id}/member-certs`, `/api/keys/key-shares/${id}`,
            `/api/keys/key-requests/${id}`, `/api/chats/${id}/settings`, `/api/chats/invite/${id}`, `/api/keys/bundle/${id}`,
            `/api/chats/${id}/join-requests`,
        ]) {
            const res = await member.get(path);
            assert.ok(res.status < 500, `${path}: ${res.status} ${JSON.stringify(res.body).slice(0, 120)}`);
        }
        for (const [method, path] of [['DELETE', `/api/chats/${id}`], ['POST', `/api/chats/${id}/read`], ['POST', `/api/messages/${id}/set-expiry`], ['PUT', `/api/messages/${id}`]]) {
            const res = await member.request(method, path, { json: { upToSeq: 1, text: 'x', expirySeconds: 60 } });
            assert.ok(res.status < 500, `${method} ${path}: ${res.status} ${JSON.stringify(res.body).slice(0, 120)}`);
        }
    }
    // Нормальный id по-прежнему работает.
    assert.strictEqual((await member.get(`/api/chats/${memberChat.id}/participants`)).status, 200);
    assert.strictEqual(suite.server.logs.count(/22003|out of range for type integer|Unhandled error/, { from: mark }), 0);
});

test('R2.7: объект вместо числа в теле (JSON {"toString":1}) - обычный отказ, не 500', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const mark = suite.server.logs.mark();
    const hostile = { toString: 1 };
    const cases = [
        ['POST', '/api/messages', { chatId: hostile, text: 'x' }],
        ['POST', '/api/messages', { chatId: bot.id, text: 'x', replyToId: hostile }],
        ['POST', '/api/chats', { name: hostile }],
        ['POST', '/api/reactions', { messageId: hostile, emoji: '👍' }],
        ['POST', '/api/keys/key-requests', { chatId: hostile, senderKeyIds: ['AAAAAAAAAAAAAAAAAAAAAA=='] }],
        ['POST', '/api/keys/key-requests/done', { chatId: hostile, senderKeyIds: ['AAAAAAAAAAAAAAAAAAAAAA=='] }],
        ['POST', '/api/keys/key-shares', { chatId: hostile, shares: [] }],
        ['POST', `/api/chats/${bot.id}/member-certs`, { subjectId: hostile }],
        ['POST', '/api/chats/join', { code: hostile }],
        ['POST', '/api/chats/join/preview', { code: hostile }],
        ['POST', `/api/messages/${bot.id}/set-expiry`, { expirySeconds: hostile }],
    ];
    for (const [method, path, json] of cases) {
        const res = await a.request(method, path, { json });
        assert.ok(res.status < 500, `${method} ${path} ${JSON.stringify(json)}: ${res.status} ${JSON.stringify(res.body).slice(0, 120)}`);
    }
    assert.strictEqual(suite.server.logs.count(/Unhandled error|Cannot convert object to primitive/, { from: mark }), 0);
});
