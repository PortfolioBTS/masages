'use strict';
// Сервер при сбоях Postgres (ревью W7 R2): обрыв соединения посреди транзакции,
// зависшая блокировка, недоступная база. Ожидается: процесс жив, ответ клиенту —
// «занято» (503 busy с Retry-After), а не падение и не зависание.
//
// Воспроизведения ревьюера: dbcrash.test.js и dbfail.test.js (scratchpad R2).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

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
