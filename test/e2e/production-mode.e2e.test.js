'use strict';
// Режим NODE_ENV=production (ревью W7 R5, В-7). Все остальные сквозные наборы идут с NODE_ENV=test, а в production
// меняются два защитных поведения, и ни один тест их не видел:
//   * кука сессии connect.sid: `secure: 'auto'` (Secure по фактическому протоколу запроса), HttpOnly, SameSite=Lax
//     (src/http/middleware/session.js); куки csrf_token и nyxo_pre - Secure по тому же признаку (lib/csrf.js);
//   * Strict-Transport-Security по https (src/http/app.js, lib/privacy.js); по http и для onion заголовка нет.
// Https изображаем так же, как за настоящим прокси: заголовок X-Forwarded-Proto: https (trust proxy = 1).
//
// Что нужно, чтобы production вообще стартовал на тестовой базе: Postgres в контейнере без TLS, а production
// требует либо CA, либо DB_TLS_INSECURE=true; параметр ?sslmode=disable в DATABASE_URL (pg разбирает его после
// явного ssl из конфигурации и выигрывает) оставляет соединение открытым. Тестовые ручки NYXO_TEST_* в production
// - ошибка env-check, поэтому убираем и их.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('production-mode', { startServer: false });

const HSTS_DEFAULT = 'max-age=31536000; includeSubDomains';
const HSTS_PRELOAD = 'max-age=63072000; includeSubDomains; preload';

const PRODUCTION_ENV = Object.freeze({
    NODE_ENV: 'production',
    DB_TLS_INSECURE: 'true',
    NYXO_TEST_MAINTENANCE_MS: null,
});

// Сервер каждого вида поднимается один раз (старт с миграциями - секунды), ключ - имя.
const started = new Map();
function productionServer(extraEnv = {}, name = 'production') {
    if (!started.has(name)) started.set(name, startProduction(extraEnv, name));
    return started.get(name);
}

function startProduction(extraEnv, name) {
    return suite.startServer({
        name,
        env: { ...PRODUCTION_ENV, DATABASE_URL: `${suite.databaseUrl}?sslmode=disable`, ...extraEnv },
    });
}

// Клиент, который ходит «через https-прокси»: заголовок на каждый запрос, Secure-куки принимаются (secureContext).
// Origin - со схемой https, как у настоящего браузера за прокси: сервер сверяет схему Origin с протоколом запроса
// (ревью W7 R1 п.10), и Origin http:// при X-Forwarded-Proto: https отклоняется как чужой сайт.
function httpsClient(server) {
    const client = server.client({ secureContext: true });
    client.originOverride = client.baseUrl.replace(/^http:/, 'https:');
    const request = client.request.bind(client);
    client.request = (method, urlPath, opts = {}) => request(method, urlPath, { ...opts, headers: { 'X-Forwarded-Proto': 'https', ...opts.headers } });
    return client;
}

// Set-Cookie по имени, в виде атрибутов в нижнем регистре: ['connect.sid=...', 'path=/', 'httponly', ...].
function cookieAttrs(res, name) {
    const header = res.headers.getSetCookie().find(line => line.startsWith(`${name}=`));
    if (!header) return null;
    const [, ...attrs] = header.split(';').map(part => part.trim().toLowerCase());
    return attrs;
}

// Регистрация анонима и сырой ответ: в нём Set-Cookie новой сессии.
async function registerRaw(client) {
    const pow = await client.solvePow('register-anon');
    const res = await client.post('/api/register/anonymous', { lifetime: 'tab', pow });
    assert.strictEqual(res.body && res.body.success, true, `регистрация: ${res.text}`);
    return res;
}

test('production по https: connect.sid - Secure, HttpOnly, SameSite=Lax; csrf_token и nyxo_pre - Secure', async () => {
    const server = await productionServer();
    const client = httpsClient(server);
    // Куки CSRF выдаются уже на GET до входа.
    const first = await client.get('/api/auth');
    for (const name of ['csrf_token', 'nyxo_pre']) {
        const attrs = cookieAttrs(first, name);
        assert.ok(attrs, `${name} не выдан`);
        assert.ok(attrs.includes('secure'), `${name} по https без Secure: ${attrs}`);
    }
    const res = await registerRaw(client);
    const session = cookieAttrs(res, 'connect.sid');
    assert.ok(session, 'сессия не выдана');
    assert.ok(session.includes('secure'), `connect.sid по https без Secure: ${session}`);
    assert.ok(session.includes('httponly'), `connect.sid без HttpOnly: ${session}`);
    assert.ok(session.includes('samesite=lax'), `connect.sid не SameSite=Lax: ${session}`);
    // Новый токен CSRF после входа - тоже Secure.
    const token = cookieAttrs(res, 'csrf_token');
    if (token) assert.ok(token.includes('secure'), `csrf_token после входа без Secure: ${token}`);
    // Сессия работает по https: аккаунт виден.
    assert.strictEqual((await client.auth()).authenticated, true);
});

test('production по https: Strict-Transport-Security есть на API и на странице', async () => {
    const server = await productionServer();
    const client = httpsClient(server);
    for (const urlPath of ['/api/auth', '/', '/style.css']) {
        const res = await client.get(urlPath);
        assert.strictEqual(res.headers.get('strict-transport-security'), HSTS_DEFAULT, `${urlPath}: HSTS (статус ${res.status})`);
    }
    // Ошибки тоже: заголовок ставится до маршрутов.
    assert.strictEqual((await client.get('/нет-такого-пути')).headers.get('strict-transport-security'), HSTS_DEFAULT);
});

test('production по обычному http: ни Secure у кук, ни HSTS (иначе вход за прокси без https ломался бы)', async () => {
    const server = await productionServer();
    const client = server.client();
    const first = await client.get('/api/auth');
    assert.strictEqual(first.headers.get('strict-transport-security'), null, 'HSTS по http');
    for (const name of ['csrf_token', 'nyxo_pre']) {
        const attrs = cookieAttrs(first, name);
        assert.ok(attrs && !attrs.includes('secure'), `${name} по http с Secure: ${attrs}`);
    }
    const res = await registerRaw(client);
    const session = cookieAttrs(res, 'connect.sid');
    assert.ok(session, 'сессия не выдана');
    assert.ok(!session.includes('secure'), `connect.sid по http с Secure: ${session}`);
    assert.ok(session.includes('httponly') && session.includes('samesite=lax'), `атрибуты connect.sid: ${session}`);
    assert.strictEqual(res.headers.get('strict-transport-security'), null);
});

test('HSTS_PRELOAD=yes в production: два года, includeSubDomains, preload - и только по https', async () => {
    const server = await productionServer({ HSTS_PRELOAD: 'yes' }, 'production-preload');
    const secure = await httpsClient(server).get('/api/auth');
    assert.strictEqual(secure.headers.get('strict-transport-security'), HSTS_PRELOAD);
    const plain = await server.client().get('/api/auth');
    assert.strictEqual(plain.headers.get('strict-transport-security'), null);
});

test('контроль: тот же запрос через https к серверу NODE_ENV=test - куки без Secure и без HSTS (различие даёт именно режим)', async () => {
    const server = await suite.startServer({ name: 'test-mode' });
    const client = httpsClient(server);
    const first = await client.get('/api/auth');
    assert.strictEqual(first.headers.get('strict-transport-security'), null, 'HSTS вне production');
    const res = await registerRaw(client);
    const session = cookieAttrs(res, 'connect.sid');
    assert.ok(session, 'сессия не выдана');
    assert.ok(!session.includes('secure'), `connect.sid вне production с Secure: ${session}`);
    assert.ok(session.includes('httponly') && session.includes('samesite=lax'), `атрибуты connect.sid: ${session}`);
});
