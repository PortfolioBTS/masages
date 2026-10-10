'use strict';
// Типизированные ошибки init() (R7, план криптографии, §1.4 и «Тесты» раздела 3):
// интерфейс выбирает текст и «Повторить» по err.code, а не разбором сообщения.
//
//   unsupported — нет X25519/Ed25519/HKDF или модуля ML-KEM;
//   storage     — хранилище ключей устройства отказало;
//   network     — fetch отклонён (TypeError, AbortError);
//   server      — 5xx, 503, 404, 401, 403 у /api/keys/*;
//   protocol    — ответ не того формата, 400 на собственные ключи, неверная длина ML-KEM.
//
// Плюс поля peers и keyHolders результата ensureRoomSession: по ним script.js
// блокирует отправку, если ключ комнаты не дошёл ни до одного участника.
// Запуск: node test/e2ee.init-errors.test.js

const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
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

// KEM с правильными размерами: init() только генерирует PQ-prekey.
function stubKem(overrides = {}) {
    return {
        keygen(seed) { return { publicKey: new Uint8Array(1184).fill(7), secretKey: seed.slice() }; },
        encapsulate() { throw new Error('не нужен'); },
        decapsulate() { throw new Error('не нужен'); },
        ...overrides,
    };
}

function make({ transport, storage, kem } = {}) {
    const server = makeFakeServer();
    const real = server.transportFor(1);
    return {
        server,
        client: E2EE.createClient({
            userId: 1,
            storage: storage || new E2EE.MemoryStorage(),
            transport: transport ? { ...real, ...transport } : real,
            kem: kem || stubKem(),
        }),
    };
}

async function codeOf(promise) {
    try {
        await promise;
    } catch (err) {
        assert.ok(err instanceof E2EE.E2eeError, 'ошибка init() должна быть E2eeError, а пришло: ' + (err && err.stack));
        assert.ok(E2EE.ERROR_CODES.includes(err.code), 'код вне ERROR_CODES: ' + err.code);
        return err;
    }
    assert.fail('init() не должен был завершиться успешно');
}

const domError = (name, message) => Object.assign(new Error(message || name), { name });

async function main() {
    // ---------- network ----------

    await test('транспорт бросает TypeError (fetch отклонён) → network', async () => {
        const { client } = make({ transport: { putIdentity: async () => { throw new TypeError('Failed to fetch'); } } });
        const err = await codeOf(client.init());
        assert.strictEqual(err.code, 'network');
        assert.ok(err.cause instanceof TypeError, 'исходная ошибка сохранена в cause');
    });

    await test('AbortError (таймаут запроса) → network', async () => {
        const { client } = make({ transport: { putSignedPrekey: async () => { throw domError('AbortError', 'aborted'); } } });
        assert.strictEqual((await codeOf(client.init())).code, 'network');
    });

    await test('сбой запроса на последнем шаге (счётчик одноразовых ключей) → network', async () => {
        const { client } = make({ transport: { getOneTimePrekeyCount: async () => { throw new TypeError('Failed to fetch'); } } });
        assert.strictEqual((await codeOf(client.init())).code, 'network');
    });

    // ---------- server ----------

    await test('503 при публикации ключей → server, статус сохранён', async () => {
        const { client } = make({ transport: { putIdentity: async () => ({ status: 503, data: { success: false } }) } });
        const err = await codeOf(client.init());
        assert.strictEqual(err.code, 'server');
        assert.strictEqual(err.status, 503);
    });

    await test('401, 403, 404 и 500 у /api/keys/* → server', async () => {
        for (const status of [401, 403, 404, 500, 502]) {
            const { client } = make({ transport: { putSignedPrekey: async () => ({ status, data: { success: false } }) } });
            const err = await codeOf(client.init());
            assert.strictEqual(err.code, 'server', 'статус ' + status);
            assert.strictEqual(err.status, status);
        }
    });

    // ---------- protocol ----------

    await test('ответ-мусор вместо {status, data} → protocol', async () => {
        for (const garbage of [undefined, null, 'мусор', 42, {}, { data: 'x' }]) {
            const { client } = make({ transport: { putIdentity: async () => garbage } });
            assert.strictEqual((await codeOf(client.init())).code, 'protocol', JSON.stringify(garbage));
        }
    });

    await test('200 без success:true → protocol; 400 на собственные ключи → protocol', async () => {
        for (const res of [{ status: 200, data: {} }, { status: 200, data: { success: false } }, { status: 201, data: { ok: true } }, { status: 400, data: { success: false } }]) {
            const { client } = make({ transport: { putIdentity: async () => res } });
            const err = await codeOf(client.init());
            assert.strictEqual(err.code, 'protocol', JSON.stringify(res));
            assert.strictEqual(err.status, res.status);
        }
    });

    await test('ML-KEM вернул публичный ключ неверной длины → protocol', async () => {
        const kem = stubKem({ keygen: (seed) => ({ publicKey: new Uint8Array(100), secretKey: seed.slice() }) });
        const { client } = make({ kem });
        assert.strictEqual((await codeOf(client.init())).code, 'protocol');
    });

    // ---------- storage ----------

    await test('хранилище бросает исключение → storage', async () => {
        const broken = {
            get: async () => { throw new Error('диск недоступен'); },
            set: async () => { throw new Error('диск недоступен'); },
            delete: async () => { throw new Error('диск недоступен'); },
            keys: async () => { throw new Error('диск недоступен'); },
        };
        const { client } = make({ storage: broken });
        const err = await codeOf(client.init());
        assert.strictEqual(err.code, 'storage');
        assert.strictEqual(err.cause.message, 'диск недоступен');
    });

    await test('ошибки IndexedDB (InvalidStateError, QuotaExceededError, UnknownError) на любом шаге → storage', async () => {
        for (const name of ['InvalidStateError', 'QuotaExceededError', 'UnknownError', 'VersionError']) {
            // Хранилище отказывает не сразу, а на записи после генерации ключей: код не должен зависеть от фазы.
            const inner = new E2EE.MemoryStorage();
            let writes = 0;
            const flaky = {
                get: (key) => inner.get(key),
                keys: (prefix) => inner.keys(prefix),
                delete: (key) => inner.delete(key),
                set: async (key, value) => {
                    if (++writes > 3) throw domError(name);
                    return inner.set(key, value);
                },
            };
            const { client } = make({ storage: flaky });
            assert.strictEqual((await codeOf(client.init())).code, 'storage', name);
        }
    });

    await test('NotSupportedError в хранилище (не умеет хранить ключ нужного вида) → unsupported', async () => {
        const inner = new E2EE.MemoryStorage();
        const picky = {
            get: (key) => inner.get(key),
            keys: (prefix) => inner.keys(prefix),
            delete: (key) => inner.delete(key),
            set: async () => { throw domError('NotSupportedError'); },
        };
        const { client } = make({ storage: picky });
        assert.strictEqual((await codeOf(client.init())).code, 'unsupported');
    });

    // ---------- unsupported ----------

    await test('ML-KEM отсутствует или неполный → unsupported, и до обращения к серверу', async () => {
        for (const kem of [{}, { keygen() {} }, { keygen() {}, encapsulate() {} }]) {
            let touched = false;
            const mark = async () => { touched = true; return { status: 200, data: { success: true } }; };
            const { client } = make({ kem, transport: { putIdentity: mark, getOneTimePrekeyCount: mark } });
            assert.strictEqual((await codeOf(client.init())).code, 'unsupported');
            assert.strictEqual(touched, false, 'на устройстве без нужной криптографии запросов к серверу быть не должно');
        }
    });

    await test('NotSupportedError от KEM при создании prekey → unsupported', async () => {
        const kem = stubKem({ keygen: () => { throw domError('NotSupportedError', 'ML-KEM'); } });
        const { client } = make({ kem });
        assert.strictEqual((await codeOf(client.init())).code, 'unsupported');
    });

    await test('probeSupport: на исправном окружении проходит; отказ не запоминается — после «починки» init() работает', async () => {
        const { client } = make();
        await client.probeSupport();

        let broken = true;
        const kem = stubKem();
        const flaky = { keygen: (...a) => kem.keygen(...a), encapsulate: (...a) => kem.encapsulate(...a), get decapsulate() { return broken ? undefined : kem.decapsulate; } };
        const second = make({ kem: flaky });
        assert.strictEqual((await codeOf(second.client.probeSupport())).code, 'unsupported');
        broken = false;
        await second.client.probeSupport();
        const result = await second.client.init();
        assert.ok(result && typeof result.signPub === 'string');
    });

    // ---------- повтор после сбоя ----------

    await test('после сетевого сбоя тот же клиент повторяет init() и доводит его до конца', async () => {
        let fail = true;
        const real = makeFakeServer().transportFor(1);
        const retrying = E2EE.createClient({
            userId: 1, storage: new E2EE.MemoryStorage(), kem: stubKem(),
            transport: { ...real, putIdentity: async (...args) => { if (fail) throw new TypeError('Failed to fetch'); return real.putIdentity(...args); } },
        });
        assert.strictEqual((await codeOf(retrying.init())).code, 'network');
        fail = false;
        const result = await retrying.init();
        assert.ok(result && typeof result.signPub === 'string');
    });

    // ---------- настоящий транспорт (fetch) ----------

    await test('makeFetchTransport: отказ fetch → network; не JSON → protocol, а 502/503 с HTML → server; JSON проходит', async () => {
        const realFetch = globalThis.fetch;
        try {
            const transport = E2EE.makeFetchTransport();
            globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
            await assert.rejects(transport.putIdentity({}), (err) => err instanceof E2EE.E2eeError && err.code === 'network');

            globalThis.fetch = async () => ({ status: 200, json: async () => { throw new SyntaxError('Unexpected token <'); } });
            await assert.rejects(transport.putIdentity({}), (err) => err.code === 'protocol' && err.status === 200);

            globalThis.fetch = async () => ({ status: 502, json: async () => { throw new SyntaxError('Unexpected token <'); } });
            await assert.rejects(transport.putIdentity({}), (err) => err.code === 'server' && err.status === 502);

            globalThis.fetch = async () => ({ status: 409, json: async () => ({ success: false }) });
            assert.deepStrictEqual(await transport.putIdentity({}), { status: 409, data: { success: false } });
        } finally {
            globalThis.fetch = realFetch;
        }
    });

    await test('init() через настоящий транспорт: 503 с JSON → server, fetch отклонён → network', async () => {
        const realFetch = globalThis.fetch;
        try {
            const mk = () => E2EE.createClient({ userId: 1, storage: new E2EE.MemoryStorage(), kem: stubKem(), transport: E2EE.makeFetchTransport() });
            globalThis.fetch = async () => ({ status: 503, json: async () => ({ success: false }) });
            const unavailable = await codeOf(mk().init());
            assert.strictEqual(unavailable.code, 'server');
            assert.strictEqual(unavailable.status, 503);
            globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
            assert.strictEqual((await codeOf(mk().init())).code, 'network');
        } finally {
            globalThis.fetch = realFetch;
        }
    });

    // ---------- результат ensureRoomSession: peers и keyHolders ----------

    async function roomOf(ids, { failShares = false, notReady = [] } = {}) {
        const ROOM = 100;
        const server = makeFakeServer();
        for (const id of ids) server.addParticipant(ROOM, id, id * 11);
        const clients = {};
        for (const id of ids) {
            let transport = server.transportFor(id);
            if (failShares && id === ids[0]) transport = { ...transport, postKeyShares: async () => ({ status: 503, data: { success: false } }) };
            clients[id] = E2EE.createClient({ userId: id, storage: new E2EE.MemoryStorage(), transport, kem: require('../public/mlkem.js') });
            if (!notReady.includes(id)) await clients[id].init();
        }
        const parts = ids.map(id => ({ id, username: 'user' + id }));
        return { clients, parts, ROOM };
    }

    await test('ensureRoomSession: ключ дошёл до всех — keyHolders равен числу остальных участников', async () => {
        const { clients, parts, ROOM } = await roomOf([1, 2, 3]);
        const result = await clients[1].ensureRoomSession(11, ROOM, parts);
        assert.strictEqual(result.ok, true);
        assert.strictEqual(result.peers, 2);
        assert.strictEqual(result.keyHolders, 2);
        // Повторный вызов: отметки уже стоят, рассылать нечего, счёт тот же.
        const again = await clients[1].ensureRoomSession(11, ROOM, parts);
        assert.strictEqual(again.keyHolders, 2);
    });

    await test('ensureRoomSession: сервер отклонил key-share — ok:false и keyHolders 0 при участниках (отправку блокирует интерфейс)', async () => {
        const { clients, parts, ROOM } = await roomOf([1, 2], { failShares: true });
        const result = await clients[1].ensureRoomSession(11, ROOM, parts);
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.peers, 1);
        assert.strictEqual(result.keyHolders, 0);
    });

    await test('ensureRoomSession: часть участников без E2EE — ключ дошёл до остальных, keyHolders больше нуля', async () => {
        const { clients, parts, ROOM } = await roomOf([1, 2, 3], { notReady: [3] });
        const result = await clients[1].ensureRoomSession(11, ROOM, parts);
        assert.strictEqual(result.peers, 2);
        assert.strictEqual(result.keyHolders, 1);
        assert.ok(result.warnings.some(w => w.userId === 3), 'о третьем участнике есть предупреждение');
    });

    await test('ensureRoomSession: один в комнате — peers 0, keyHolders 0; не участник — то же и ok:false', async () => {
        const { clients, parts, ROOM } = await roomOf([1]);
        const alone = await clients[1].ensureRoomSession(11, ROOM, parts);
        assert.strictEqual(alone.ok, true);
        assert.strictEqual(alone.peers, 0);
        assert.strictEqual(alone.keyHolders, 0);
        const stranger = await clients[1].ensureRoomSession(11, ROOM, [{ id: 7, username: 'user7' }]);
        assert.strictEqual(stranger.ok, false);
        assert.strictEqual(stranger.peers, 0);
    });

    console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
