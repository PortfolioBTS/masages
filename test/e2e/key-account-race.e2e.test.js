'use strict';
// Регистрация identity одновременно с удалением аккаунта (ревью W7 R2.6; воспроизведение —
// race3.test.js ревьюера). У identity_keys и kt_pending нет внешнего ключа на users, и
// регистрация, шедшая вместе с удалением, оставляла kt_pending (а иногда и identity_keys)
// удалённого аккаунта. Теперь регистрация первой берёт users FOR KEY SHARE: либо удаление
// ждёт её и убирает её записи в своей транзакции, либо она после удаления получает 404.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { createSuite, waitUntil } = require('./helpers/scenarios');
const { newIdentity } = require('./helpers/membership');

const suite = createSuite('key-account-race', {
    env: {
        KT_SIGNING_KEY: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
        KT_EPOCH_SECONDS: '3600',
    },
});

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const lockWaiters = async () => (await suite.query(
    `SELECT count(*)::int AS n FROM pg_stat_activity
     WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`
)).rows[0].n;

async function leftovers(userId) {
    const one = async (sql) => (await suite.query(sql, [userId])).rows[0].n;
    return {
        user: await one('SELECT count(*)::int AS n FROM users WHERE id = $1'),
        identity: await one('SELECT count(*)::int AS n FROM identity_keys WHERE user_id = $1'),
        pending: await one('SELECT count(*)::int AS n FROM kt_pending WHERE user_id = $1'),
    };
}

// Держит строку из lockSql, запускает запросы по одному (каждый ждёт, пока встанет
// предыдущий) и отпускает строку.
async function interleave(lockSql, params, starters) {
    const hold = await suite.db.connect();
    const pending = [];
    try {
        await hold.query('BEGIN');
        await hold.query(lockSql, params);
        for (let i = 0; i < starters.length; i++) {
            pending.push(starters[i]());
            await waitUntil(async () => (await lockWaiters()) >= i + 1, { timeoutMs: 8000, what: `запрос ${i + 1} ждёт блокировку` });
        }
        await hold.query('COMMIT');
    } finally {
        await hold.query('ROLLBACK').catch(() => {});
        hold.release();
    }
    return Promise.all(pending);
}

async function freshAccount() {
    const client = suite.client();
    await client.registerAnon();
    await client.get('/api/auth');
    const id = newIdentity();
    const body = { identity_signing_key: b64(id.signPub), identity_dh_key: b64(id.dhPub) };
    return { client, userId: client.user.id, body };
}

test('регистрация раньше удаления: удаление ждёт её и убирает identity_keys и kt_pending', async () => {
    await waitUntil(async () => (await suite.query('SELECT count(*)::int AS n FROM kt_state')).rows[0].n === 1, { what: 'журнал ключей готов' });
    const { client, userId, body } = await freshAccount();
    // Оба запроса встают на kt_state (его держит тест): регистрация уже с KEY SHARE на users,
    // удаление — за ней на строке users.
    const [put, del] = await interleave('SELECT 1 FROM kt_state FOR UPDATE', [], [
        () => client.put('/api/keys/identity', body),
        () => client.post('/api/account/delete', {}),
    ]);
    assert.strictEqual(put.status, 200, JSON.stringify(put.body));
    assert.strictEqual(del.status, 200, JSON.stringify(del.body));
    assert.deepStrictEqual(await leftovers(userId), { user: 0, identity: 0, pending: 0 });
});

test('регистрация после удаления: 404, ничего не записано', async () => {
    const { client, userId, body } = await freshAccount();
    // Строку users держит тест; первым в очереди — удаление, за ним регистрация.
    const [del, put] = await interleave('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [userId], [
        () => client.post('/api/account/delete', {}),
        () => client.put('/api/keys/identity', body),
    ]);
    assert.strictEqual(del.status, 200, JSON.stringify(del.body));
    assert.strictEqual(put.status, 404, JSON.stringify(put.body));
    assert.deepStrictEqual(await leftovers(userId), { user: 0, identity: 0, pending: 0 });
});

test('без принудительного порядка (как в воспроизведении ревьюера): сирот нет', async () => {
    for (let i = 0; i < 4; i++) {
        const { client, userId, body } = await freshAccount();
        await Promise.all([client.put('/api/keys/identity', body), client.post('/api/account/delete', {})]);
        // deleteKeysForUser идёт после COMMIT удаления и не ждётся ответом.
        await waitUntil(async () => {
            const left = await leftovers(userId);
            return left.user === 0 && left.identity === 0 && left.pending === 0;
        }, { timeoutMs: 5000, what: `попытка ${i + 1}: у удалённого аккаунта не осталось ключей` });
    }
    const orphans = (await suite.query(
        `SELECT (SELECT count(*) FROM identity_keys i WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = i.user_id))
              + (SELECT count(*) FROM kt_pending p WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = p.user_id)) AS n`
    )).rows[0].n;
    assert.strictEqual(Number(orphans), 0);
});
