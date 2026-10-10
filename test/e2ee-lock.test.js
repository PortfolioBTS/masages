'use strict';
// Web Locks между вкладками (docs/security/message-ordering.md, раздел 9.7):
// public/lib/e2ee-lock.js. Настоящих Web Locks в Node нет, поэтому ниже —
// подобие navigator.locks с тем же поведением: запросы с одним именем идут по
// одному в порядке поступления, с разными — независимо; request возвращает
// результат функции.
// Запуск: node test/e2ee-lock.test.js

const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const kem = require('../public/mlkem.js');
const Lock = require('../public/lib/e2ee-lock.js');
const { makeFakeServer } = require('./fake-server');

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

// Подобие navigator.locks (режим exclusive): по очереди на имя.
function makeFakeLocks() {
    const tails = new Map();
    const log = [];
    return {
        log,
        async request(name, options, fn) {
            assert.strictEqual(options.mode, 'exclusive');
            const previous = tails.get(name) || Promise.resolve();
            const run = previous.then(() => {
                log.push('start ' + name);
                return fn();
            });
            tails.set(name, run.then(() => undefined, () => undefined));
            const result = await run;
            log.push('end ' + name);
            return result;
        },
    };
}

async function main() {
    await test('имя блокировки — одно на аккаунт', () => {
        assert.strictEqual(Lock.lockName(7), 'nyxo-e2ee-7');
        assert.notStrictEqual(Lock.lockName(7), Lock.lockName(8));
    });

    await test('без Web Locks: lock = null и предупреждение в консоль', () => {
        const warnings = [];
        for (const locks of [undefined, null, {}, { request: 'нет' }]) {
            assert.strictEqual(Lock.makeLock(locks, 1, (m) => warnings.push(m)), null);
        }
        assert.strictEqual(warnings.length, 4, 'по предупреждению на каждый вызов (клиент создаётся один раз на пользователя)');
        assert.ok(/Web Locks/.test(warnings[0]));
        assert.strictEqual(Lock.makeLock(undefined, 1), null, 'без warn не падает');
    });

    await test('lock(fn): результат и ошибка функции проходят наружу, секции одной вкладки не перекрываются', async () => {
        const locks = makeFakeLocks();
        const lock = Lock.makeLock(locks, 1, () => {});
        assert.strictEqual(await lock(async () => 42), 42);
        await assert.rejects(() => lock(async () => { throw new Error('сбой секции'); }), /сбой секции/);
        assert.strictEqual(await lock(async () => 'после сбоя'), 'после сбоя', 'ошибка не клинит очередь');

        let active = 0, maxActive = 0;
        const slow = () => lock(async () => {
            active++;
            maxActive = Math.max(maxActive, active);
            await new Promise(r => setTimeout(r, 5));
            active--;
        });
        await Promise.all([slow(), slow(), slow()]);
        assert.strictEqual(maxActive, 1, 'в секции одновременно только один');
    });

    await test('разные аккаунты друг друга не блокируют', async () => {
        const locks = makeFakeLocks();
        const lockA = Lock.makeLock(locks, 1);
        const lockB = Lock.makeLock(locks, 2);
        let releaseA;
        const held = lockA(() => new Promise((resolve) => { releaseA = resolve; }));
        await new Promise(r => setTimeout(r, 5));
        assert.strictEqual(await lockB(async () => 'второй аккаунт прошёл'), 'второй аккаунт прошёл');
        releaseA();
        await held;
    });

    await test('две вкладки одного аккаунта (два клиента, одно хранилище) с этой блокировкой выдают разные итерации Sender Key', async () => {
        const roomId = 100;
        const server = makeFakeServer();
        server.addParticipant(roomId, 1, 11);
        server.addParticipant(roomId, 2, 22);
        const storage = new E2EE.MemoryStorage();
        const locks = makeFakeLocks();
        const tab = () => E2EE.createClient({
            userId: 1, storage, transport: server.transportFor(1), kem, lock: Lock.makeLock(locks, 1),
        });
        const tabA = tab();
        const tabB = tab();
        await tabA.init();
        await tabA.ensureRoomSession(11, roomId, [{ id: 1, username: 'a' }, { id: 2, username: 'b' }]);
        const results = await Promise.all(Array.from({ length: 8 }, (_, i) =>
            (i % 2 ? tabB : tabA).encryptOutgoing(roomId, 'сообщение ' + i, { messageId: server.newMessageId() })));
        const iterations = results.map(e => JSON.parse(e).iteration).sort((a, b) => a - b);
        assert.deepStrictEqual(iterations, [0, 1, 2, 3, 4, 5, 6, 7], 'каждая итерация использована ровно один раз');
        assert.ok(locks.log.some(line => line === 'start nyxo-e2ee-1'), 'секции действительно шли через блокировку');
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
