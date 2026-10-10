'use strict';
// Смоук: старт на пустой базе, идемпотентность миграций, главная страница,
// аноним через PoW, чат с ботом (приветствие и ответ по сокету), фоновые
// задачи; две реплики на одной пустой базе и отказ старта на схеме новее кода.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { createDatabase, dropDatabase, connectPool, schemaSnapshot } = require('./helpers/pg');
const { ServerHandle, spawnServer } = require('./helpers/server');
const { randomSecrets } = require('./helpers/env');

const UNREADABLE = '[Не удалось расшифровать]';
const suite = createSuite('smoke');

// Отдельная пустая база на тест (реплики, версия схемы) — с уборкой.
async function withScratchDatabase(fn) {
    const { name, url } = await createDatabase();
    const db = connectPool(url);
    const servers = [];
    try {
        return await fn({ url, db, servers });
    } finally {
        for (const server of servers) await server.dispose().catch(() => {});
        await db.end().catch(() => {});
        await dropDatabase(name);
    }
}

test('старт на пустой базе: схема создана, версия схемы записана, сервер отвечает', async () => {
    const auth = await suite.client().auth();
    // Контракт этапа 1, §3: onionUrl есть всегда (без onion-сервиса — null).
    assert.deepStrictEqual(auth, { authenticated: false, onionUrl: null });
    const tables = (await suite.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`))
        .rows.map(r => r.table_name);
    for (const table of ['users', 'rooms', 'chats', 'messages', 'room_participants', 'join_requests', 'schema_meta']) {
        assert.ok(tables.includes(table), `нет таблицы ${table}`);
    }
    const meta = (await suite.query('SELECT schema_version, updated_at FROM schema_meta')).rows;
    assert.strictEqual(meta.length, 1);
    assert.strictEqual(meta[0].schema_version, 0);
    assert.strictEqual(meta[0].updated_at.getSeconds(), 0, 'время версии — с точностью до минуты');
    await suite.server.logs.waitFor('База данных инициализирована');
});

test('повторный старт не меняет снимок схемы', async () => {
    const before = await schemaSnapshot(suite.db);
    const mark = suite.server.logs.mark();
    await suite.server.restart();
    await suite.server.logs.waitFor('База данных инициализирована', { from: mark });
    const after = await schemaSnapshot(suite.db);
    assert.deepStrictEqual(after, before);
});

test('GET /: страница, CSP и Permissions-Policy с microphone=()', async () => {
    const res = await suite.client().get('/');
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/html/);
    assert.match(res.body, /<html/i);
    const csp = res.headers.get('content-security-policy');
    assert.ok(csp, 'нет Content-Security-Policy');
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
    assert.match(csp, /object-src 'none'/);
    assert.match(res.headers.get('permissions-policy'), /microphone=\(\)/);
});

test('неизвестный /api/* — JSON 404', async () => {
    const res = await suite.client().get('/api/does-not-exist');
    assert.strictEqual(res.status, 404);
    assert.deepStrictEqual(res.body, { success: false, message: 'Не найдено' });
});

test('аноним через PoW; без решения — отказ', async () => {
    const lazy = suite.client();
    const refused = await lazy.post('/api/register/anonymous', { lifetime: 'tab' });
    assert.strictEqual(refused.body.success, false);
    assert.strictEqual(refused.body.powRequired, true);

    const a = suite.client();
    const user = await a.registerAnon({ lifetime: 'day' });
    assert.strictEqual(user.isAnonymous, true);
    assert.strictEqual(user.anonLifetime, 'day');
    assert.ok(Number.isInteger(user.id));
    const auth = await a.auth();
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.user.id, user.id);
    assert.strictEqual(auth.user.isAnonymous, true);
});

test('чат с ботом: есть сразу после регистрации, с читаемым приветствием', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const { messages } = await a.messages(bot.id);
    assert.strictEqual(messages.length, 1);
    assert.strictEqual(messages[0].sent, 0);
    // Приветствие бот-гида (lib/bot-guide.js): последняя строка — подсказка про гайд.
    assert.match(messages[0].text, /^Добро пожаловать в Nyxo./);
    assert.match(messages[0].text, /Напишите „гайд“, чтобы узнать, как всё устроено$/);
    assert.notStrictEqual(messages[0].text, UNREADABLE);
});

test('ответ бота приходит по сокету', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const sock = await a.socket();
    try {
        // На уже существующие чаты сервер подписывает сокет асинхронно (запрос
        // к базе после подключения), и эхо сообщения, отправленного сразу после
        // connect, может разминуться с подпиской. Поэтому ждём только ответ
        // бота: он приходит через ~1.5 с, когда подписка давно готова.
        // joinChat — вторая, явная подписка на этот чат.
        sock.emit('joinChat', `chat:${bot.id}`);
        const sent = await a.send(bot.id, 'Привет, бот');
        assert.strictEqual(sent.text, 'Привет, бот');
        const reply = await sock.waitFor('newMessage', m => m.chat_id === bot.id && m.sent === 0 && m.seq > sent.seq);
        assert.ok(reply.text.length > 0);
        const { messages } = await a.messages(bot.id);
        assert.ok(messages.some(m => m.id === reply.id && m.text === reply.text));
    } finally {
        await sock.close();
    }
});

test('фоновые задачи идут (тестовая ручка): проходы чистки в логе', async () => {
    const tick = await suite.server.waitForTick(2);
    assert.ok(tick >= 2);
});

test('две реплики одновременно на пустой базе: обе стартуют, миграции — по очереди', async () => {
    await withScratchDatabase(async ({ url, db, servers }) => {
        const secrets = randomSecrets();
        const a = new ServerHandle({ databaseUrl: url, secrets, name: 'smoke-replica-a' });
        const b = new ServerHandle({ databaseUrl: url, secrets, name: 'smoke-replica-b' });
        servers.push(a, b);
        await Promise.all([a.start(), b.start()]);
        const tables = await db.query(`SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public'`);
        assert.ok(tables.rows[0].n > 10);
        // Аккаунт, созданный через одну реплику, виден через другую.
        const viaA = a.client();
        const user = await viaA.registerAnon();
        const viaB = b.client();
        viaB.jar = viaA.jar;
        const auth = await viaB.auth();
        assert.strictEqual(auth.user && auth.user.id, user.id);
    });
});

test('версия схемы в базе новее кода — сервер не стартует и объясняет почему', async () => {
    await withScratchDatabase(async ({ url, db, servers }) => {
        const first = new ServerHandle({ databaseUrl: url, name: 'smoke-schema' });
        servers.push(first);
        await first.start();
        await first.stop();
        await db.query('UPDATE schema_meta SET schema_version = 9999');
        const old = await spawnServer({ databaseUrl: url, name: 'smoke-schema-old' });
        servers.push(old);
        const exit = await old.waitForExit();
        assert.strictEqual(exit.code, 1);
        assert.ok(old.logs.find(/NYXO_SCHEMA_TOO_NEW/), old.logs.tail(20));
        assert.ok(old.logs.find(/версия схемы 9999/), old.logs.tail(20));
    });
});
