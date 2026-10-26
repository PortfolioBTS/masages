'use strict';
// Квота вложений под псевдонимом (docs/security/sealed-sender.md, раздел 13):
// lib/upload-quota.js на фейковом клиенте БД. Поведение SQL (окно 30 суток,
// откат при 409, 413) проверяют сквозные тесты на настоящем Postgres.
// Запуск: node test/upload-quota.test.js

const assert = require('assert');
const quota = require('../lib/upload-quota');

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

function fakeClient(rows = [{ '?column?': 1 }]) {
    const calls = [];
    return { calls, query: async (sql, params) => { calls.push({ sql, params }); return { rows, rowCount: rows.length }; } };
}

async function main() {
    await test('схема: таблица без user_id и без внешних ключей, qkey - 16 байт, bytes неотрицательные', async () => {
        const client = fakeClient();
        await quota.initUploadQuotaSchema(client);
        const ddl = client.calls[0].sql;
        assert.match(ddl, /CREATE TABLE IF NOT EXISTS upload_quota/);
        assert.match(ddl, /qkey BYTEA PRIMARY KEY CHECK \(octet_length\(qkey\) = 16\)/);
        assert.match(ddl, /window_start DATE NOT NULL/);
        assert.match(ddl, /bytes BIGINT NOT NULL CHECK \(bytes >= 0\)/);
        assert.doesNotMatch(ddl, /user_id|REFERENCES/i);
    });

    await test('резервирование: окно 30 суток и условие "не больше квоты" в одном операторе, строка вставки возвращается', async () => {
        assert.match(quota.RESERVE_SQL, /ON CONFLICT \(qkey\) DO UPDATE/);
        assert.match(quota.RESERVE_SQL, /current_date - 30/);
        assert.match(quota.RESERVE_SQL, /<= \$3::bigint\s+RETURNING 1/);
        const qkey = Buffer.alloc(16, 7);
        const ok = fakeClient([{ '?column?': 1 }]);
        assert.strictEqual(await quota.reserveUploadQuota(ok, qkey, 1000, 5000), true);
        assert.deepStrictEqual(ok.calls[0].params, [qkey, 1000, 5000]);
        const exhausted = fakeClient([]);
        assert.strictEqual(await quota.reserveUploadQuota(exhausted, qkey, 1000, 5000), false, 'нет строки в RETURNING - квота исчерпана');
    });

    await test('одиночный файл больше квоты отвергается без записи строки (запроса к БД нет)', async () => {
        const client = fakeClient();
        assert.strictEqual(await quota.reserveUploadQuota(client, Buffer.alloc(16), 5001, 5000), false);
        assert.strictEqual(client.calls.length, 0);
        assert.strictEqual(await quota.reserveUploadQuota(client, Buffer.alloc(16), NaN, 5000), false);
        assert.strictEqual(client.calls.length, 0);
    });

    await test('удаление аккаунта: строки по всем псевдонимам одним запросом; пустой список - без запроса', async () => {
        const client = fakeClient([{}, {}]);
        const a = Buffer.alloc(16, 1), b = Buffer.alloc(16, 2);
        assert.strictEqual(await quota.deleteQuotaRows(client, [a, b]), 2);
        assert.match(client.calls[0].sql, /DELETE FROM upload_quota WHERE qkey = ANY\(\$1::bytea\[\]\)/);
        assert.deepStrictEqual(client.calls[0].params, [[a, b]]);
        const none = fakeClient();
        assert.strictEqual(await quota.deleteQuotaRows(none, []), 0);
        assert.strictEqual(none.calls.length, 0);
    });

    await test('суточная задача уборки: окна старше 30 суток удаляются; задача зарегистрирована в реестре lib/jobs', async () => {
        const pool = fakeClient([{}, {}, {}]);
        const [job] = quota.jobs({ pool });
        assert.strictEqual(job.name, 'purgeUploadQuota');
        assert.strictEqual(job.intervalMs, 24 * 60 * 60 * 1000);
        assert.strictEqual(job.maintenance, true);
        assert.strictEqual(await job.run(), 3);
        assert.match(pool.calls[0].sql, /DELETE FROM upload_quota WHERE window_start <= current_date - 30/);
        const registry = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'jobs', 'index.js'), 'utf8');
        assert.match(registry, /require\('\.\.\/upload-quota'\)/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
