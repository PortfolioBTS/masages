'use strict';
// Общие помощники протокольных тестов Sender Key (архив, ротация, запрос ключа,
// «не хранить историю»): клиент public/e2ee.js против test/fake-server.js.
// Не *.test.js, поэтому раннер юнит-тестов файл сам не запускает.

// ML-KEM в Node WebCrypto экспериментальный и шумит предупреждениями — глушим только их.
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const mlkem = require('../public/mlkem.js');
const { makeFakeServer } = require('./fake-server');

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

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

// Общие часы: тесты двигают время для сроков в 7 дней, часы и т.п.
function makeClock(start = 1800000000000) {
    const clock = { t: start, now: () => clock.t };
    clock.advance = (ms) => { clock.t += ms; };
    return clock;
}

function makeUser(server, userId, opts = {}) {
    const storage = opts.storage || new E2EE.MemoryStorage();
    const client = E2EE.createClient({
        userId, storage,
        transport: opts.transport || server.transportFor(userId),
        kem: opts.kem || mlkem,
        now: opts.now,
        lock: opts.lock,
    });
    client._storage = storage;
    client._userId = userId;
    return client;
}

// «Перезагрузка вкладки»: новый клиент на том же хранилище и сервере.
function reload(server, client, opts = {}) {
    return makeUser(server, client._userId, Object.assign({ storage: client._storage }, opts));
}

// Комната roomId: участники ids (чат каждого = 10 * id + 1).
function makeRoom(roomId, ids) {
    const server = makeFakeServer();
    for (const id of ids) server.addParticipant(roomId, id, chatOf(id));
    return server;
}
const chatOf = (id) => id * 10 + 1;
const participantsOf = (server, roomId) => server.participantsOf(roomId);

let messageCounter = 6000000;
const nextMessageId = () => String(++messageCounter);

// Шифрует текст и возвращает { env, id } — id сообщения для decryptIncoming.
async function send(client, roomId, text) {
    const id = nextMessageId();
    const env = await client.encryptOutgoing(roomId, text, { messageId: id });
    return { env, id, text, senderId: client._userId };
}

async function read(client, roomId, message) {
    return client.decryptIncoming(roomId, message.senderId, message.env, message.id);
}

async function stored(client, name) {
    return client._storage.get(name);
}

const sizeOf = (value) => JSON.stringify(value).length;

// Детерминированная перестановка (линейный конгруэнтный генератор): тест
// воспроизводим, но порядок доставки не «по возрастанию».
function shuffled(list, seed = 12345) {
    const out = list.slice();
    let s = seed;
    for (let i = out.length - 1; i > 0; i--) {
        s = (s * 1103515245 + 12345) & 0x7fffffff;
        const j = s % (i + 1);
        [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
}

module.exports = {
    assert, E2EE, mlkem, makeFakeServer,
    HOUR, DAY,
    test, finish,
    makeClock, makeUser, reload, makeRoom, chatOf, participantsOf,
    send, read, stored, sizeOf, shuffled, nextMessageId,
};
