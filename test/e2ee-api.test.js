'use strict';
// Публичный API public/e2ee.js: то, что видят снаружи script.js и тесты.
// Сам протокол проверяет test/e2ee.protocol.test.js; здесь — «форма» модуля и
// швы, заложенные под параллельную работу:
//   - набор методов клиента не меняется незаметно (новый метод — осознанно
//     дописывается в список ниже);
//   - E2eeError и ERROR_CODES экспортируются (init подключит к ним задача
//     про типизированные ошибки);
//   - createClient принимает options.now (часы) и options.lock (внешняя
//     блокировка секций работы с хранилищем).
//
// Запуск: node test/e2ee-api.test.js

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const { makeFakeServer } = require('./fake-server');

const DAY = 24 * 60 * 60 * 1000;

// Методы клиента, которые возвращает createClient. Группы — как в e2ee.js.
const CLIENT_METHODS = [
    // Инициализация и пользователь
    'init',
    'probeSupport',
    'setUserId',

    // Комнаты: Sender Key и key-share
    'ensureRoomSession',
    'syncKeyShares',
    'hasRoomKey',
    'currentSenderKeyId',
    'rotateRoomKey',

    // Состав группы: подписи, приглашения, вход, подтверждение участников
    'noteRoomCreated',
    'signApproval',
    'signInvite',
    'getInviteSecret',
    'dropInviteSecret',
    'prepareJoin',
    'completeJoin',
    'cancelJoinIntent',
    'getJoinIntent',
    'trustMember',
    'vouchForMember',
    'getMembers',
    'runViewChecks',
    'nextRevouchDueMs',

    // Комнаты: ротация ключа и запрос ключа
    'roomKeyDue',
    'requestRoomKeys',
    'answerKeyRequests',

    // Комнаты: хранение ключей на устройстве (архив, срок, бюджет)
    'maintainRoomKeys',
    'setRoomPolicy',

    // Комнаты: «Не хранить историю на устройстве»
    'setRoomHistoryMode',
    'getRoomHistoryMode',
    'forgetRoomHistory',
    'forgetAllNoHistoryRooms',

    // Комнаты: локальная очистка при выходе и имена участников
    'forgetRoom',
    'getRoomMemberNames',

    // Сообщения и файлы
    'encryptOutgoing',
    'decryptIncoming',
    'encryptFile',
    'decryptFile',

    // Identity собеседников и код безопасности
    'checkPeerIdentities',
    'getPeerIdentityStatus',
    'getSafetyNumber',
    'markPeerVerified',
    'acceptPeerIdentityChange',

    // Прозрачность ключей
    'checkTransparency',
    'runKtChecks',
    'getPeerTransparency',
    'overrideLogMismatch',
    'checkApplicantKey',
    'getTransparencyAlerts',
    'dismissTransparencyAlerts',
    'ackSelfEntries',
    'getPendingLogKey',
    'acceptLogKey',
    'startTransparency',
    'stopTransparency',
];

// Имена, которые модуль экспортирует, и их тип.
const MODULE_EXPORTS = {
    createClient: 'function',
    MemoryStorage: 'function',
    makeIndexedDbStorage: 'function',
    makeFetchTransport: 'function',
    deleteLocalData: 'function',
    E2eeError: 'function',
    ERROR_CODES: 'array',
    _internal: 'object',
};

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

// ML-KEM здесь не нужен: init() только генерирует PQ-prekey и проверяет длину
// публичного ключа, поэтому годится заглушка с правильными размерами.
function makeStubKem() {
    return {
        keygen(seed) {
            return { publicKey: new Uint8Array(1184).fill(7), secretKey: seed.slice() };
        },
        encapsulate() { throw new Error('заглушка KEM: encapsulate не нужен'); },
        decapsulate() { throw new Error('заглушка KEM: decapsulate не нужен'); },
    };
}

function makeClient(extra = {}) {
    const server = makeFakeServer();
    const storage = new E2EE.MemoryStorage();
    const client = E2EE.createClient({
        userId: 1,
        storage,
        transport: server.transportFor(1),
        kem: makeStubKem(),
        ...extra,
    });
    return { client, storage, server };
}

(async () => {
    console.log('E2EE public API tests\n');

    await test('createClient returns exactly the documented set of methods', () => {
        const { client } = makeClient();
        const actual = Object.keys(client).sort();
        const expected = CLIENT_METHODS.slice().sort();
        const extra = actual.filter(name => !expected.includes(name));
        const missing = expected.filter(name => !actual.includes(name));
        assert.deepStrictEqual({ extra, missing }, { extra: [], missing: [] },
            'набор методов клиента изменился: новый метод допишите в CLIENT_METHODS (и в этот тест)');
        for (const name of expected) assert.strictEqual(typeof client[name], 'function', name + ' должен быть функцией');
    });

    await test('module exports the documented names with the right types', () => {
        for (const [name, type] of Object.entries(MODULE_EXPORTS)) {
            assert.ok(name in E2EE, `модуль не экспортирует ${name}`);
            if (type === 'array') assert.ok(Array.isArray(E2EE[name]), `${name} должен быть массивом`);
            else assert.strictEqual(typeof E2EE[name], type, `${name} должен быть: ${type}`);
        }
    });

    await test('ERROR_CODES lists the init error codes and cannot be changed', () => {
        assert.deepStrictEqual(Array.from(E2EE.ERROR_CODES), ['unsupported', 'storage', 'network', 'server', 'protocol']);
        assert.ok(Object.isFrozen(E2EE.ERROR_CODES));
    });

    await test('E2eeError is an Error that carries code and, when given, status and cause', () => {
        const cause = new Error('исходная ошибка');
        const err = new E2EE.E2eeError('server', 'сервер ключей недоступен', { status: 503, cause });
        assert.ok(err instanceof Error);
        assert.ok(err instanceof E2EE.E2eeError);
        assert.strictEqual(err.name, 'E2eeError');
        assert.strictEqual(err.code, 'server');
        assert.strictEqual(err.status, 503);
        assert.strictEqual(err.message, 'сервер ключей недоступен');
        assert.strictEqual(err.cause, cause);

        const bare = new E2EE.E2eeError('network');
        assert.strictEqual(bare.code, 'network');
        assert.strictEqual(bare.status, undefined);
        assert.ok(!('status' in bare), 'status не задан — свойства быть не должно');
        assert.match(bare.message, /network/, 'сообщение по умолчанию называет код');
    });

    await test('createClient accepts options.now: prekey dates follow the injected clock', async () => {
        let t = 1700000000000;
        const { client, storage } = makeClient({ now: () => t });
        await client.init();
        const first = await storage.get('spk');
        assert.strictEqual(first.createdAt, t);
        assert.strictEqual((await storage.get('pqpk')).createdAt, t);
        assert.strictEqual(first.keyId, Math.floor(t / 1000), 'id ключей тоже берутся из часов клиента');

        // Через 8 дней prekey просрочен (ротация раз в 7): init() выпускает новый.
        t += 8 * DAY;
        await client.init();
        const second = await storage.get('spk');
        assert.strictEqual(second.createdAt, t);
        assert.notStrictEqual(second.keyId, first.keyId);
        assert.strictEqual((await storage.keys('spkOld:')).length, 1, 'прежний ключ уходит в spkOld:');
    });

    await test('without options.now the client uses the real clock', async () => {
        const { client, storage } = makeClient();
        const before = Date.now();
        await client.init();
        const after = Date.now();
        const createdAt = (await storage.get('spk')).createdAt;
        assert.ok(createdAt >= before && createdAt <= after, `createdAt=${createdAt} вне [${before}, ${after}]`);
    });

    await test('createClient accepts options.lock: sections run through it one at a time', async () => {
        let calls = 0, active = 0, maxActive = 0;
        const lock = async (fn) => {
            calls++;
            active++;
            maxActive = Math.max(maxActive, active);
            try {
                return await fn();
            } finally {
                active--;
            }
        };
        const { client } = makeClient({ lock });
        const result = await client.init();
        assert.ok(calls > 0, 'ни одна секция не прошла через options.lock');
        assert.strictEqual(maxActive, 1, 'клиент не должен просить вторую секцию, пока идёт первая');
        assert.ok(result && typeof result.signPub === 'string', 'результат секций проходит через lock без потерь');
    });

    await test('options.lock failure is an error of the operation, and the client recovers afterwards', async () => {
        let fail = true;
        const lock = (fn) => (fail ? Promise.reject(new Error('блокировка недоступна')) : fn());
        const { client } = makeClient({ lock });
        await assert.rejects(client.init(), /блокировка недоступна/);
        fail = false;
        const result = await client.init();
        assert.ok(result && typeof result.signPub === 'string', 'после сбоя блокировки клиент работает');
    });

    await test('options.now and options.lock that are not functions are ignored', async () => {
        const { client, storage } = makeClient({ now: 'сейчас', lock: {} });
        const before = Date.now();
        await client.init();
        assert.ok((await storage.get('spk')).createdAt >= before);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})();
