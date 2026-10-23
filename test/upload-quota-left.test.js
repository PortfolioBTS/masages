'use strict';
// remainingUploadQuota (W7 R1 п.1): остаток квоты для проверки ДО санитайзера.
// Запуск: node test/upload-quota-left.test.js

const assert = require('assert');
const { remainingUploadQuota, WINDOW_DAYS } = require('../lib/upload-quota');

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

function fakeDb(row) {
    const calls = [];
    return { calls, dbGet: async (sql, params) => { calls.push({ sql, params }); return row; } };
}

async function main() {
    await test('строки нет: доступна вся квота', async () => {
        assert.strictEqual(await remainingUploadQuota(fakeDb(null), Buffer.alloc(16), 1000), 1000);
    });

    await test('использовано 300 из 1000: осталось 700 (bigint из pg приходит строкой)', async () => {
        assert.strictEqual(await remainingUploadQuota(fakeDb({ used: '300' }), Buffer.alloc(16), 1000), 700);
    });

    await test('использовано больше квоты (квоту уменьшили): осталось 0, не отрицательное', async () => {
        assert.strictEqual(await remainingUploadQuota(fakeDb({ used: '5000' }), Buffer.alloc(16), 1000), 0);
    });

    await test('запрос: по qkey, окно 30 суток учитывается в SQL (истёкшее окно = 0 использовано)', async () => {
        const db = fakeDb(null);
        const qkey = Buffer.alloc(16, 3);
        await remainingUploadQuota(db, qkey, 1000);
        assert.strictEqual(db.calls.length, 1);
        assert.deepStrictEqual(db.calls[0].params, [qkey]);
        assert.match(db.calls[0].sql, /FROM upload_quota WHERE qkey = \$1::bytea/);
        assert.ok(db.calls[0].sql.includes(`window_start <= current_date - ${WINDOW_DAYS}`));
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exit(1); });
