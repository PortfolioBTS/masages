'use strict';
// Пачки до исчерпания с бюджетом времени (ревью W7 R2.11): lib/drain-batches.js — на нём
// чистка просроченных анонимов (src/services/accounts.js). Раньше проход брал одну пачку в
// 200 строк раз в 5 минут. Сквозной сценарий с сотнями аккаунтов —
// test/e2e/anon-purge-batches.e2e.test.js.
// Запуск: node test/drain-batches.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { drainBatches } = require('../lib/drain-batches');

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

// Таблица из n строк: выборка — первые limit, кроме skip; handle удаляет строку.
function table(n, { failIds = [] } = {}) {
    const rows = new Map(Array.from({ length: n }, (_, i) => [i + 1, { id: i + 1 }]));
    return {
        rows,
        fetchBatch: async (skip, limit) => [...rows.values()].filter(r => !skip.includes(r.id)).slice(0, limit),
        handle: async (row) => {
            if (failIds.includes(row.id)) throw new Error('сбой удаления');
            rows.delete(row.id);
        },
    };
}

async function main() {
    await test('пачки, пока полные: 450 строк при пачке 200 — за один проход', async () => {
        const t = table(450);
        const result = await drainBatches({ ...t, batchSize: 200, budgetMs: 60000 });
        assert.deepStrictEqual(result, { processed: 450, failed: 0, batches: 3, exhausted: true });
        assert.strictEqual(t.rows.size, 0);
    });

    await test('бюджет времени: проход останавливается, остаток — следующему', async () => {
        const t = table(1000);
        let clock = 0;
        const result = await drainBatches({
            ...t, batchSize: 100, budgetMs: 250,
            clock: () => clock,
            fetchBatch: async (skip, limit) => { clock += 100; return t.fetchBatch(skip, limit); },
        });
        assert.strictEqual(result.exhausted, false);
        assert.strictEqual(result.batches, 3);
        assert.strictEqual(t.rows.size, 700);
    });

    await test('строка с ошибкой больше не выбирается в этом проходе — нет зацикливания', async () => {
        const t = table(5, { failIds: [1, 2] });
        const errors = [];
        const result = await drainBatches({ ...t, batchSize: 2, budgetMs: 60000, onError: (err, row) => errors.push(row.id) });
        assert.deepStrictEqual(result, { processed: 3, failed: 2, batches: 3, exhausted: true });
        assert.deepStrictEqual(errors, [1, 2]);
        assert.deepStrictEqual([...t.rows.keys()], [1, 2]);
    });

    await test('skipIds (открытые сокеты) не выбираются', async () => {
        const t = table(3);
        const seen = [];
        await drainBatches({ ...t, batchSize: 10, budgetMs: 1000, skipIds: [2], fetchBatch: async (skip, limit) => { seen.push(skip); return t.fetchBatch(skip, limit); } });
        assert.deepStrictEqual(seen, [[2]]);
        assert.deepStrictEqual([...t.rows.keys()], [2]);
    });

    await test('чистка анонимов идёт через drainBatches с LIMIT параметром, без «LIMIT 200»', () => {
        const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'services', 'accounts.js'), 'utf8');
        const start = source.indexOf('async function purgeExpiredAnonymousUsers(');
        const body = source.slice(start, source.indexOf('\n    }\n', start));
        assert.match(body, /drainBatches\(/);
        assert.match(body, /LIMIT \$5/);
        assert.doesNotMatch(body, /LIMIT 200/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
