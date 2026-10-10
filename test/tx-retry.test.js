'use strict';
// Повтор транзакции при взаимной блокировке (docs/security/message-ordering.md,
// раздел 8.3): lib/tx-retry.js. Один повтор при 40P01; вторая неудача и любые
// другие ошибки уходят вызывающему как есть (он отвечает 503 busy).
// Запуск: node test/tx-retry.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createTransactionRetry } = require('../lib/tx-retry');

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

const deadlock = () => Object.assign(new Error('deadlock detected'), { code: '40P01' });

// withTransaction на скриптовых исходах: каждая попытка берёт очередной шаг.
function makeHarness(steps) {
    const state = { attempts: 0, warnings: [] };
    const withTransaction = async (work) => {
        const step = steps[state.attempts++];
        if (step instanceof Error) throw step;
        return work({ step });
    };
    const retry = createTransactionRetry({ withTransaction, warn: (message) => state.warnings.push(message) });
    return { retry, state };
}

async function main() {
    await test('успех с первой попытки: повтора и предупреждения нет, результат work возвращается', async () => {
        const { retry, state } = makeHarness(['ok']);
        assert.strictEqual(await retry(async (client) => 'результат ' + client.step), 'результат ok');
        assert.strictEqual(state.attempts, 1);
        assert.deepStrictEqual(state.warnings, []);
    });

    await test('40P01 на первой попытке: транзакция повторяется целиком один раз, предупреждение без id и текста запроса', async () => {
        const { retry, state } = makeHarness([deadlock(), 'второй раз']);
        let calls = 0;
        const result = await retry(async (client) => { calls++; return client.step; });
        assert.strictEqual(result, 'второй раз');
        assert.strictEqual(calls, 1, 'work первой попытки не дошёл до конца: её откатил сам withTransaction');
        assert.strictEqual(state.attempts, 2);
        assert.strictEqual(state.warnings.length, 1);
        assert.match(state.warnings[0], /40P01/);
        assert.ok(!/\d{4,}/.test(state.warnings[0]), 'в предупреждении нет id');
    });

    await test('40P01 и на повторе: ошибка уходит вызывающему (503 busy), третьей попытки нет', async () => {
        const { retry, state } = makeHarness([deadlock(), deadlock(), 'не должно дойти']);
        await assert.rejects(() => retry(async () => 'x'), (err) => err.code === '40P01');
        assert.strictEqual(state.attempts, 2);
        assert.strictEqual(state.warnings.length, 1);
    });

    await test('другие ошибки не повторяются: ни 23505, ни 23503, ни обычное исключение', async () => {
        for (const err of [Object.assign(new Error('dup'), { code: '23505' }), Object.assign(new Error('fk'), { code: '23503' }), new Error('сбой')]) {
            const { retry, state } = makeHarness([err, 'не должно дойти']);
            await assert.rejects(() => retry(async () => 'x'), (thrown) => thrown === err);
            assert.strictEqual(state.attempts, 1);
            assert.deepStrictEqual(state.warnings, []);
        }
    });

    await test('ошибка внутри work при 40P01 тоже повторяется, а warn необязателен', async () => {
        let attempts = 0;
        const retry = createTransactionRetry({
            withTransaction: async (work) => { attempts++; return work({}); },
        });
        let first = true;
        const result = await retry(async () => {
            if (first) { first = false; throw deadlock(); }
            return 'прошло';
        });
        assert.strictEqual(result, 'прошло');
        assert.strictEqual(attempts, 2);
    });

    // Сторожок порядка блокировок: все транзакции раздела 8.2 идут через withTransactionRetry.
    // Прямой withTransaction остаётся только у регистрации (новой строки users ещё никто не ждёт).
    await test('server.js: прямой withTransaction( — только в самой обёртке и при регистрации', () => {
        const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
        const direct = [];
        source.split('\n').forEach((line, i) => {
            if (/\bwithTransaction\(/.test(line) && !/^\s*(\/\/|\*)/.test(line)) direct.push(`${i + 1}: ${line.trim()}`);
        });
        assert.strictEqual(direct.length, 2, 'ожидались определение withTransaction и регистрация:\n' + direct.join('\n'));
        assert.match(direct[0], /async function withTransaction\(work\)/);
        assert.match(direct[1], /insertUserWithBotChat/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
