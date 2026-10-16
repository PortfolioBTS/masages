'use strict';
// Общая оснастка протокольных тестов журнала ключей (test/kt-client.*.test.js): мир из fake-server
// и журнала (test/fake-kt.js), клиенты E2EE с внедрёнными часами, блокировкой и транспортом.
//
// Транспорт клиента проверяет, что НИ ОДИН сетевой вызов не идёт внутри секции withLock (раздел 7.6,
// ревью К6): блокировка клиента помечает свой async-контекст (AsyncLocalStorage), а любой метод
// транспорта в таком контексте записывает нарушение. Параллельные запросы других задач вне секции — не нарушение.

const { AsyncLocalStorage } = require('async_hooks');
const E2EE = require('../public/e2ee.js');
const { makeFakeServer } = require('./fake-server');
const { FakeKt } = require('./fake-kt');

const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const HOUR = 60 * 60 * 1000;
const kem = require('../public/mlkem.js');
const { b64encode } = E2EE._internal;

function makeWorld({ genEpochs = 6, graceEpochs = 4, kt = null, ktOf = null, ktAll = null } = {}) {
    const model = kt || new FakeKt({ genEpochs, graceEpochs });
    const server = makeFakeServer(ktOf ? { kt: ktOf, ktAll } : { kt: model });
    // Часы мира стоят в эпохе, с которой начинается журнал (test/fake-kt.js): иначе голова журнала выглядела бы
    // «давно не обновлявшейся» (stale) с первой секунды.
    const clock = { t: 40000 * HOUR + 5 * 60 * 1000 };
    const world = {
        kt: model, server, clock, genEpochs, graceEpochs, clients: new Map(), lockViolations: [],
        advance(ms) { clock.t += ms; },
    };
    const lockContext = new AsyncLocalStorage();

    // Внутри withLock: любой вызов транспорта — нарушение.
    function guardTransport(transport) {
        return new Proxy(transport, {
            get(target, name) {
                const value = target[name];
                if (typeof value !== 'function') return value;
                return (...args) => {
                    if (lockContext.getStore()) world.lockViolations.push(String(name));
                    return value.apply(target, args);
                };
            },
        });
    }

    // Участник мира: пользователь с хранилищем, часами, записью тревог и таймеров повтора.
    world.addUser = async (userId, { roomId = 100, init = true, storage = new E2EE.MemoryStorage(), transport = null, clientOptions = {} } = {}) => {
        server.addParticipant(roomId, userId, 10 + userId);
        const alerts = [];
        const scheduled = [];
        const client = E2EE.createClient({
            userId, storage, kem, now: () => clock.t,
            transport: guardTransport(transport || server.transportFor(userId)),
            lock: (fn) => lockContext.run(true, fn),
            onTransparencyAlert: (alert) => alerts.push(alert),
            ktGenEpochs: genEpochs, ktGraceEpochs: graceEpochs,
            ktSchedule: (fn, ms) => { scheduled.push({ fn, ms }); return scheduled.length; },
            ...clientOptions,
        });
        const user = { id: userId, client, storage, alerts, scheduled, roomId, chatId: 10 + userId };
        // Проверки журнала «через некоторое время»: голова журнала свежая 30 секунд, поэтому часы сдвигаются.
        user.check = async () => { world.advance(31 * 1000); return client.runKtChecks(); };
        world.clients.set(userId, user);
        if (init) await client.init();
        return user;
    };

    world.participants = (roomId = 100) => server.participantsOf(roomId);

    // ensureRoomSession участника по актуальному составу комнаты.
    world.session = (user) => user.client.ensureRoomSession(user.chatId, user.roomId, world.participants(user.roomId));

    // Забрать ключи комнаты, которые адресовали участнику.
    world.sync = (user) => user.client.syncKeyShares(user.chatId, user.roomId);

    return world;
}

const statusOf = async (user, peerId) => {
    const pin = await user.storage.get('peer:' + peerId);
    return pin && pin.kt ? { ...pin.kt } : null;
};

module.exports = { makeWorld, statusOf, HOUR, b64encode, FakeKt };
