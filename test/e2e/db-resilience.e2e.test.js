'use strict';
// Сервер при сбоях Postgres (ревью W7 R2): обрыв соединения посреди транзакции,
// зависшая блокировка, недоступная база. Ожидается: процесс жив, ответ клиенту —
// «занято» (503 busy с Retry-After), а не падение и не зависание.
//
// Воспроизведения ревьюера: dbcrash.test.js и dbfail.test.js (scratchpad R2).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { withAdmin } = require('./helpers/pg');

const suite = createSuite('db-resilience', { env: { PG_POOL_MAX: '10' } });

const lockWaiters = async () => (await suite.query(
    `SELECT count(*)::int AS n FROM pg_stat_activity
     WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`
)).rows[0].n;

// Держит строку комнаты FOR UPDATE, пока выполняется fn: отправка в эту комнату
// встаёт на блокировке внутри своей транзакции.
async function withRoomLocked(roomId, fn) {
    const hold = await suite.db.connect();
    try {
        await hold.query('BEGIN');
        await hold.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId]);
        return await fn();
    } finally {
        await hold.query('ROLLBACK').catch(() => {});
        hold.release();
    }
}

async function roomPair() {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const room = await roomWithMember(owner, member);
    await owner.isRoomChat(room.ownerChat.id);
    return { owner, member, ...room };
}

test('обрыв соединения Postgres посреди транзакции отправки: процесс жив, запрос получил ответ, пул работает', async () => {
    const { owner, roomId, ownerChat } = await roomPair();
    const mark = suite.server.logs.mark();
    const response = await withRoomLocked(roomId, async () => {
        const body = await owner.messageBody(ownerChat.id, 'обрыв', {});
        const pending = owner.post('/api/messages', body);
        await waitUntil(async () => (await lockWaiters()) >= 1, { what: 'отправка ждёт блокировку комнаты' });
        // Как рестарт или failover базы: серверный процесс транзакции убит.
        await suite.query(
            `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`
        );
        return pending;
    });
    assert.strictEqual(typeof response.status, 'number', 'запрос получил HTTP-ответ, а не обрыв соединения');
    assert.ok(!(response.body && response.body.success), 'оборванная отправка не считается успешной');
    await suite.server.logs.waitFor(/\[DB\] Обрыв соединения во время транзакции/, { from: mark });
    assert.ok(suite.server.alive, 'процесс сервера жив');
    assert.ok(!/Необработанное исключение/.test(suite.server.logs.text()), 'обрыв не стал необработанным исключением');
    assert.strictEqual((await owner.get('/healthz')).status, 200);
    // Оборванное соединение закрыто, а не вернулось в пул: следующие запросы идут.
    const after = await owner.send(ownerChat.id, 'после обрыва');
    assert.ok(after.id, 'отправка после обрыва прошла');
    assert.ok(Array.isArray(await owner.chats()));
});

test('зависшая блокировка комнаты: отправки отпускают пул по lock_timeout, посторонний обслуживается без очереди', async () => {
    // Отдельный сервер на ту же базу с коротким lock_timeout: не ждать 5 с умолчания.
    const server = await suite.startServer({ name: 'db-resilience-lock', env: { DB_LOCK_TIMEOUT_MS: '1000' } });
    const owner = server.client({ name: 'владелец' });
    const member = server.client({ name: 'участник' });
    const other = server.client({ name: 'посторонний' });
    await owner.registerAnon();
    await member.registerAnon();
    await other.registerAnon();
    const { roomId, ownerChat } = await roomWithMember(owner, member);
    await owner.isRoomChat(ownerChat.id);
    const bodies = [];
    for (let i = 0; i < 14; i++) bodies.push(await owner.messageBody(ownerChat.id, `очередь ${i}`, {}));
    let auth;
    let authMs;
    const results = await withRoomLocked(roomId, async () => {
        // 14 отправок при пуле 10: без lock_timeout они заняли бы все соединения до снятия замка.
        const sends = bodies.map(body => owner.post('/api/messages', body));
        await waitUntil(async () => (await lockWaiters()) >= 5, { what: 'отправки ждут блокировку комнаты' });
        const started = Date.now();
        auth = await other.get('/api/auth');
        authMs = Date.now() - started;
        return Promise.all(sends);
    });
    // Раньше: 10 с ожидания соединения и 500.
    assert.strictEqual(auth.status, 200, `GET /api/auth постороннего: ${auth.status}`);
    assert.ok(authMs < 4000, `GET /api/auth постороннего ждал ${authMs} мс`);
    for (const res of results) assert.ok(!(res.body && res.body.success), 'отправка под зависшим замком не прошла');
    assert.ok(server.alive);
    // Замок снят — отправка проходит.
    assert.ok((await owner.send(ownerChat.id, 'после замка')).id);
});

test('база недоступна: 503 busy с Retry-After вместо 500, после восстановления — обычная работа', async () => {
    const client = suite.client();
    await client.registerAnon();
    const bot = await client.botChat();
    const allowConnections = (flag) => withAdmin(c => c.query(`ALTER DATABASE "${suite.dbName}" WITH ALLOW_CONNECTIONS ${flag}`));
    let during;
    await allowConnections('false');
    try {
        await withAdmin(c => c.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [suite.dbName]));
        during = {
            auth: await client.get('/api/auth'),
            chats: await client.get('/api/chats'),
            send: await client.post('/api/messages', { chatId: bot.id, text: 'при сбое' }),
        };
    } finally {
        await allowConnections('true');
    }
    for (const [name, res] of Object.entries(during)) {
        assert.strictEqual(res.status, 503, `${name}: ${res.status} ${JSON.stringify(res.body)}`);
        assert.strictEqual(res.body.code, 'busy', name);
        assert.strictEqual(res.headers.get('retry-after'), '5', name);
    }
    assert.ok(suite.server.alive, 'процесс сервера жив');
    await waitUntil(async () => (await client.get('/api/auth')).status === 200, { timeoutMs: 15000, what: 'сервер снова отвечает после восстановления базы' });
    assert.ok((await client.send(bot.id, 'после сбоя')).id);
});
