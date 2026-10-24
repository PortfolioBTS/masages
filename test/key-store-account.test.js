'use strict';
// Хранилище ключей и удаление аккаунта (ревью W7 R2.6): lib/key-store.js.
//   * регистрация identity первой берёт users FOR KEY SHARE (порядок блокировок как у
//     удаления аккаунта: users → kt_state → identity_keys → kt_pending); строки users нет —
//     404, ничего не записано, журнал не трогается;
//   * deleteAll (DELETE /api/keys и deleteKeysForUser после удаления аккаунта) удаляет и
//     kt_pending: запись удалённого аккаунта не попадает в эпоху.
// Живые гонки на Postgres — test/e2e/key-account-race.e2e.test.js.
// Запуск: node test/key-store-account.test.js

const assert = require('assert');
const crypto = require('crypto');
const { createKeyStore } = require('../lib/key-store');
const { makeFakeKeyDb } = require('./fake-key-db');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
function keysBody() {
    const sign = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const dh = crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { identity_signing_key: b64(sign), identity_dh_key: b64(dh) };
}

function setup() {
    const db = makeFakeKeyDb();
    const order = [];
    const events = [];
    const withTransaction = async (work) => {
        events.push('BEGIN');
        const client = {
            query: async (sql, params) => {
                order.push(sql.replace(/\s+/g, ' ').trim().split(' ').slice(0, 4).join(' '));
                return { rows: await db.dbAll(sql, params) };
            },
        };
        try {
            const result = await work(client);
            events.push('COMMIT');
            return result;
        } catch (err) {
            events.push('ROLLBACK');
            throw err;
        }
    };
    const kt = {
        enabled: true,
        async lockState() { order.push('kt.lockState'); return { gen: 1, gen_start: 1, open_epoch: 5 }; },
        async registerInTx() { order.push('kt.registerInTx'); return null; },
        hintOf: () => null,
    };
    const deletes = [];
    const dbAll = async (sql, params) => {
        if (/^DELETE FROM/.test(sql)) deletes.push(sql);
        return db.dbAll(sql, params);
    };
    const store = createKeyStore({ dbGet: db.dbGet, dbAll, withTransaction, kt });
    return { db, store, order, events, deletes };
}

async function main() {
    await test('регистрация: сначала users FOR KEY SHARE, затем kt_state и identity_keys', async () => {
        const { store, order, events } = setup();
        const res = await store.call(7, 'PUT', '/internal/v1/keys/identity', keysBody());
        assert.strictEqual(res.status, 200, JSON.stringify(res.data));
        assert.deepStrictEqual(order.slice(0, 3), ['SELECT 1 FROM users', 'kt.lockState', 'INSERT INTO identity_keys (user_id,']);
        assert.deepStrictEqual(events, ['BEGIN', 'COMMIT']);
    });

    await test('аккаунт уже удалён: 404, транзакция откатилась, журнал не тронут, ключей нет', async () => {
        const { db, store, order, events } = setup();
        db.deleteUser(8);
        const res = await store.call(8, 'PUT', '/internal/v1/keys/identity', keysBody());
        assert.strictEqual(res.status, 404);
        assert.strictEqual(res.data.success, false);
        assert.deepStrictEqual(order, ['SELECT 1 FROM users']);
        assert.deepStrictEqual(events, ['BEGIN', 'ROLLBACK']);
        assert.ok(!db._state.identities.has(8));
    });

    await test('deleteAll удаляет и kt_pending, последним', async () => {
        const { store, deletes } = setup();
        await store.call(9, 'PUT', '/internal/v1/keys/identity', keysBody());
        const res = await store.deleteAll(9);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(deletes[deletes.length - 1], 'DELETE FROM kt_pending WHERE user_id = $1');
        assert.ok(deletes.includes('DELETE FROM identity_keys WHERE user_id = $1'));
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
