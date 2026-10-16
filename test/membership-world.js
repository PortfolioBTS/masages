'use strict';
// Мир протокольных тестов подписанного состава (test/membership.*.test.js): fake-server с сертификатами,
// настоящие клиенты E2EE (БЕЗ автоподтверждения участников, в отличие от test/membership-harness.js),
// общие часы, проверка «сети в блокировке нет» и перехват всех исходящих запросов (секрет ссылки не должен
// встретиться ни в одном из них).
// Не *.test.js, поэтому раннер юнит-тестов файл сам не запускает.

const { AsyncLocalStorage } = require('async_hooks');

// ML-KEM в Node WebCrypto экспериментальный и шумит предупреждениями — глушим только их.
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const M = require('../public/lib/membership.js');
const mlkem = require('../public/mlkem.js');
const { makeFakeServer } = require('./fake-server');

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const MINUTE = 60 * 1000;
const ROOM = 100;
const chatOf = (id, room = ROOM) => id * 10 + 1 + (room - 100) * 1000;

let passed = 0;
let failed = 0;
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
function finish() {
    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

// Мир: сервер, часы, пользователи. Время - 2027 год: сертификаты свежие относительно часов мира.
function makeWorld({ start = Date.UTC(2027, 0, 15, 12, 0, 0) } = {}) {
    const server = makeFakeServer();
    const clock = { t: start, now: () => clock.t, advance(ms) { clock.t += ms; } };
    const lockContext = new AsyncLocalStorage();
    const world = { server, clock, users: new Map(), lockViolations: [], requests: [], ROOM, failShares: new Set() };

    // Транспорт клиента: ни один вызов не идёт внутри секции withLock; все тела запросов запоминаются.
    function guard(transport, owner) {
        return new Proxy(transport, {
            get(target, name) {
                const value = target[name];
                if (typeof value !== 'function') return value;
                return (...args) => {
                    if (lockContext.getStore()) world.lockViolations.push(String(name));
                    world.requests.push({ name: String(name), args: JSON.stringify(args) });
                    // Сбой сети на отправке key-share (проверка журнала доставок: запись делается ДО сетевого вызова).
                    if (name === 'postKeyShares' && world.failShares.has(owner)) return Promise.reject(new TypeError('fetch failed'));
                    return value.apply(target, args);
                };
            },
        });
    }

    world.addUser = async (id, { init = true, storage = new E2EE.MemoryStorage(), inRoom = false, room = ROOM } = {}) => {
        const client = E2EE.createClient({
            userId: id, storage, kem: mlkem, now: clock.now,
            transport: guard(server.transportFor(id), id),
            lock: (fn) => lockContext.run(true, fn),
        });
        const user = { id, client, storage, room, chatId: chatOf(id, room) };
        world.users.set(id, user);
        if (init) await client.init();
        if (inRoom) server.addParticipant(room, id, user.chatId);
        return user;
    };

    // Перезагрузка вкладки: новый клиент на том же хранилище.
    world.reload = (user) => {
        const client = E2EE.createClient({
            userId: user.id, storage: user.storage, kem: mlkem, now: clock.now,
            transport: guard(server.transportFor(user.id), user.id),
            lock: (fn) => lockContext.run(true, fn),
        });
        const next = { ...user, client };
        world.users.set(user.id, next);
        return next;
    };

    // Ответ GET participants целиком (как отдаёт сервер) и сессия комнаты на его основе.
    world.fetchParticipants = async (user) => (await server.transportFor(user.id).getParticipants(user.chatId)).data;
    world.ensure = async (user) => {
        const data = await world.fetchParticipants(user);
        return user.client.ensureRoomSession(user.chatId, user.room, data.participants, data);
    };
    world.sync = (user) => user.client.syncKeyShares(user.chatId, user.room);

    // Создатель комнаты (5.1).
    world.createRoom = async (creator, name = 'Группа') => {
        server.addParticipant(creator.room, creator.id, creator.chatId);
        await creator.client.noteRoomCreated(creator.room, 'user' + creator.id);
    };

    const keysOf = (id) => {
        const identity = server.identityOf(id);
        return { userId: id, signingKey: identity.identity_signing_key, dhKey: identity.identity_dh_key };
    };
    world.keysOf = keysOf;

    // Вход по одобрению (5.2): заявитель записывает намерение, одобряющий подписывает допуск, сервер добавляет.
    world.approve = async (approver, applicant, { prepare = true } = {}) => {
        if (prepare) await applicant.client.prepareJoin(applicant.room, {});
        const signed = await approver.client.signApproval(approver.room, keysOf(applicant.id));
        server.admit(applicant.room, applicant.id, applicant.chatId, { actorId: approver.id, kind: 1, cert: signed.cert, snap: signed.snap });
        return signed;
    };

    // Ссылка-приглашение (5.3): приглашающий подписывает и сервер хранит; возвращает секрет ссылки.
    world.makeInvite = async (inviter, { ttlSeconds = 7 * 86400 } = {}) => {
        const signed = await inviter.client.signInvite(inviter.room, { ttlSeconds });
        server.setInvite(inviter.room, { cert: signed.cert, snap: signed.snap });
        return signed;
    };

    // Вход по ссылке: предпросмотр отдаёт сертификат приглашения, входящий проверяет его секретом и подписывает join.
    world.joinByLink = async (joiner, invite, { complete = true } = {}) => {
        const stored = server.getInvite(joiner.room);
        const prepared = await joiner.client.prepareJoin(joiner.room, { secret: invite.secret, inviteCert: stored.cert });
        server.admit(joiner.room, joiner.id, joiner.chatId, { actorId: 0, kind: 3, cert: prepared.joinCert, aux: stored.cert });
        if (complete) await joiner.client.completeJoin(joiner.room, stored.snap);
        return prepared;
    };

    // Участник, которому «доверяют все»: клиент злоумышленника для проверки «призрака» - он вручную подтверждает цели.
    world.trustAll = async (user, ids) => {
        await user.client.checkPeerIdentities(ids);
        for (const id of ids) await user.client.trustMember(user.room, id);
    };

    world.stored = (user, name) => user.storage.get(name);
    world.noViolations = () => assert.deepStrictEqual(world.lockViolations, [], 'вызовы сети внутри withLock: ' + world.lockViolations.join(', '));
    return world;
}

const ids = (list) => list.map(x => x.id).sort((a, b) => a - b);

module.exports = {
    assert, E2EE, M, mlkem, makeFakeServer, makeWorld, test, finish, ids,
    HOUR, DAY, MINUTE, ROOM, chatOf,
};
