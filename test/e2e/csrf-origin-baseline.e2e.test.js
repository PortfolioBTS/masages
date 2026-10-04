'use strict';
// CSRF и проверка источника: небезопасный запрос без CSRF-токена или с чужим
// Origin — 403; WebSocket-рукопожатие с чужого источника отклоняется
// (Cross-Site WebSocket Hijacking), без сессии — CONNECT_ERROR.
//
// Здесь — поведение текущего кода (токен в куке csrf_token, сверка с
// заголовком X-CSRF-Token). Привязку токена к сессии добавит задача 8.1
// (набор csrf).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('csrf-origin-baseline');
const CSRF_DENIED = { success: false, message: 'Запрещено: неверный CSRF-токен' };
const ORIGIN_DENIED = { success: false, message: 'Запрещено: запрос с чужого сайта' };

test('без CSRF-токена — 403: нет куки, нет заголовка, неверный заголовок', async () => {
    // Самый первый запрос клиента — сразу POST, куки csrf_token ещё нет.
    const fresh = suite.client();
    const first = await fresh.post('/api/chats', { name: 'x' }, { csrf: false });
    assert.strictEqual(first.status, 403);
    assert.deepStrictEqual(first.body, CSRF_DENIED);
    // Даже с заголовком, совпадающим с только что выданной кукой, — нельзя:
    // кука должна существовать ДО запроса.
    const issued = fresh.jar.get('csrf_token');
    assert.ok(issued, 'кука csrf_token выдаётся на любом запросе');

    const a = suite.client();
    await a.registerAnon();
    const noHeader = await a.post('/api/chats', { name: 'x' }, { csrf: false });
    assert.strictEqual(noHeader.status, 403);
    assert.deepStrictEqual(noHeader.body, CSRF_DENIED);
    const wrong = await a.post('/api/chats', { name: 'x' }, { csrf: 'f'.repeat(64) });
    assert.strictEqual(wrong.status, 403);
    assert.deepStrictEqual(wrong.body, CSRF_DENIED);
    // С верным токеном тот же запрос проходит.
    const okRes = await a.post('/api/chats', { name: 'Своя' });
    assert.strictEqual(okRes.status, 200);
    assert.strictEqual(okRes.body.success, true);
});

test('чужой Origin — 403 даже с верным токеном; Sec-Fetch-Site: cross-site без Origin — тоже', async () => {
    const a = suite.client();
    await a.registerAnon();
    const foreign = await a.post('/api/chats', { name: 'x' }, { origin: 'http://evil.example' });
    assert.strictEqual(foreign.status, 403);
    assert.deepStrictEqual(foreign.body, ORIGIN_DENIED);
    const crossSite = await a.post('/api/chats', { name: 'x' }, { origin: null, headers: { 'Sec-Fetch-Site': 'cross-site' } });
    assert.strictEqual(crossSite.status, 403);
    assert.deepStrictEqual(crossSite.body, ORIGIN_DENIED);
    // Безопасные методы с чужим Origin не блокируются (это не меняет состояние).
    const read = await a.get('/api/auth', { origin: 'http://evil.example' });
    assert.strictEqual(read.status, 200);
    assert.strictEqual(read.body.authenticated, true);
});

test('проверки источника и CSRF идут раньше маршрутов: неизвестный /api без токена — 403, с токеном — 404', async () => {
    const a = suite.client();
    const denied = await a.post('/api/does-not-exist', {}, { csrf: false });
    assert.strictEqual(denied.status, 403);
    const notFound = await a.post('/api/does-not-exist', {});
    assert.strictEqual(notFound.status, 404);
    assert.deepStrictEqual(notFound.body, { success: false, message: 'Не найдено' });
});

test('сокет: чужой Origin — отказ рукопожатия, без сессии — «Не авторизован», свой — подключается', async () => {
    const a = suite.client();
    await a.registerAnon();
    await assert.rejects(
        a.socket({ origin: 'http://evil.example' }),
        (err) => err.kind === 'handshake' && err.reason === 'Origin not allowed' && err.status === 403
    );
    const anonymous = suite.client();
    await assert.rejects(anonymous.socket(), (err) => err.kind === 'connect_error' && err.reason === 'Не авторизован');
    const sock = await a.socket();
    assert.strictEqual(sock.connected, true);
    await sock.close();
});
