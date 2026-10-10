'use strict';
// Ключи комнат в public/script.js: повтор шифрования после needs-room-session,
// плановая ротация после отправки, запрос потерянного ключа, ответ владельца,
// срок исчезающих сообщений для хранилища ключей. script.js — большой браузерный
// скрипт с DOM на верхнем уровне, поэтому исполняется только блок между метками
// «>>> e2ee-room-keys» и «<<< e2ee-room-keys» в песочнице с подставленными глобалами.
// Запуск: node test/e2ee-room-keys-client.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

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

const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'script.js'), 'utf8');
const block = (() => {
    const start = source.indexOf('// >>> e2ee-room-keys');
    const end = source.indexOf('// <<< e2ee-room-keys');
    assert.ok(start > 0 && end > start, 'в script.js нет блока e2ee-room-keys');
    return source.slice(start, end);
})();

const settle = () => new Promise(resolve => setImmediate(resolve));

// Песочница: таймеры управляются тестом, клиент записывает вызовы.
function makeSandbox(overrides = {}) {
    const state = {
        calls: [], ensured: [], timers: [], intervals: [], warnings: [],
        encryptFailures: [],       // что бросать на следующих вызовах encryptOutgoing
        due: false, answer: { resend: [] }, clientMissing: false,
    };
    // Данные из песочницы клонируются: объекты другого контекста vm не равны «своим» по deepStrictEqual.
    const rec = (...entry) => state.calls.push(JSON.parse(JSON.stringify(entry)));
    const client = {
        encryptOutgoing: async (roomId, content, options) => {
            rec('encryptOutgoing', roomId, content, options);
            if (state.encryptFailures.length > 0) throw state.encryptFailures.shift();
            return 'envelope';
        },
        roomKeyDue: async (roomId) => { rec('roomKeyDue', roomId); return state.due; },
        requestRoomKeys: async (chatId, roomId, envelopes) => { rec('requestRoomKeys', chatId, roomId, envelopes); return { requested: envelopes.length }; },
        answerKeyRequests: async (chatId, roomId, requests) => { rec('answerKeyRequests', chatId, roomId, requests); return state.answer; },
        setRoomPolicy: async (roomId, patch) => { rec('setRoomPolicy', roomId, patch); return patch; },
        maintainRoomKeys: async (roomId) => { rec('maintainRoomKeys', roomId); return {}; },
    };
    const context = {
        currentUser: { id: 1 },
        currentChatId: 11,
        currentRoomId: 100,
        e2eeState: 'ready',
        chatListData: [
            { id: 11, room_id: 100, expiry_seconds: 3600 },
            { id: 12, room_id: null, expiry_seconds: 0 },
            { id: 13, room_id: 300, expiry_seconds: 0 },
        ],
        getReadyE2eeClient: async () => (state.clientMissing ? null : client),
        getE2eeClient: () => client,
        ensureE2eeRoomSession: async (chatId, roomId) => { state.ensured.push(JSON.parse(JSON.stringify([chatId, roomId]))); return { ok: true }; },
        findChatMeta: (chatId, roomId) => context.chatListData.find(c => c.room_id != null && Number(c.room_id) === Number(roomId)) || null,
        normalizeExpiry: (value) => { const n = Math.floor(Number(value) || 0); return n > 0 ? n : 0; },
        setTimeout: (fn, ms) => { const timer = { fn, ms, cleared: false }; state.timers.push(timer); return timer; },
        clearTimeout: (timer) => { if (timer) timer.cleared = true; },
        setInterval: (fn, ms) => { const timer = { fn, ms, cleared: false }; state.intervals.push(timer); return timer; },
        clearInterval: (timer) => { if (timer) timer.cleared = true; },
        console: { warn: (...args) => state.warnings.push(args.join(' ')) },
        ...overrides,
    };
    vm.createContext(context);
    vm.runInContext(block + `
        this.api = { encryptForRoom, checkRoomKeyRotation, requestMissingRoomKey, flushKeyRequest, clearPendingKeyRequests,
            handleKeyRequestEvent, syncRoomKeyPolicy, maintainAllRoomKeys, startRoomKeysMaintenance, stopRoomKeysMaintenance,
            KEY_REQUEST_DEBOUNCE_MS, ROOM_KEYS_MAINTENANCE_MS };`, context);
    return { state, client, context, api: context.api };
}

const needsSession = () => Object.assign(new Error('нужна ротация'), { code: 'needs-room-session' });

(async () => {
    console.log('Ключи комнат в script.js\n');

    await test('encryptForRoom: обычное шифрование — без лишних обращений', async () => {
        const { state, client, api } = makeSandbox();
        assert.strictEqual(await api.encryptForRoom(client, 11, 100, 'привет', { messageId: '7000001' }), 'envelope');
        assert.deepStrictEqual(state.calls, [['encryptOutgoing', 100, 'привет', { messageId: '7000001' }]]);
        assert.deepStrictEqual(state.ensured, []);
    });

    await test('encryptForRoom: needs-room-session — ждёт ensureRoomSession и повторяет один раз', async () => {
        const { state, client, api } = makeSandbox();
        state.encryptFailures.push(needsSession());
        assert.strictEqual(await api.encryptForRoom(client, 11, 100, 'привет', { messageId: '7000002' }), 'envelope');
        assert.deepStrictEqual(state.ensured, [[11, 100]]);
        assert.strictEqual(state.calls.filter(c => c[0] === 'encryptOutgoing').length, 2);
    });

    await test('encryptForRoom: повторный отказ и чужие ошибки уходят вызывающему', async () => {
        const first = makeSandbox();
        first.state.encryptFailures.push(needsSession(), needsSession());
        await assert.rejects(first.api.encryptForRoom(first.client, 11, 100, 'x', {}), /нужна ротация/);
        assert.strictEqual(first.state.ensured.length, 1, 'повтор ровно один');
        const second = makeSandbox();
        second.state.encryptFailures.push(new Error('диск'));
        await assert.rejects(second.api.encryptForRoom(second.client, 11, 100, 'x', {}), /диск/);
        assert.deepStrictEqual(second.state.ensured, [], 'прочие ошибки сессию не запускают');
    });

    await test('checkRoomKeyRotation: ключ не просрочен — ничего; просрочен — ensureRoomSession; без комнаты и без клиента — тихо', async () => {
        const idle = makeSandbox();
        await idle.api.checkRoomKeyRotation(11, 100);
        assert.deepStrictEqual(idle.state.ensured, []);
        const due = makeSandbox();
        due.state.due = true;
        await due.api.checkRoomKeyRotation(11, 100);
        assert.deepStrictEqual(due.state.ensured, [[11, 100]]);
        const noRoom = makeSandbox();
        noRoom.state.due = true;
        await noRoom.api.checkRoomKeyRotation(12, null);
        assert.deepStrictEqual(noRoom.state.calls, []);
        const noClient = makeSandbox();
        noClient.state.clientMissing = true;
        await noClient.api.checkRoomKeyRotation(11, 100);
        assert.deepStrictEqual(noClient.state.ensured, []);
    });

    await test('checkRoomKeyRotation: сбой в фоне не выбрасывается, только предупреждение в консоль', async () => {
        const { state, client, api } = makeSandbox();
        client.roomKeyDue = async () => { throw new Error('хранилище'); };
        await api.checkRoomKeyRotation(11, 100);
        assert.ok(state.warnings.some(w => /плановая ротация/.test(w)));
    });

    await test('запрос ключа: конверты открытой комнаты копятся и уходят одним запросом после паузы', async () => {
        const { state, api } = makeSandbox();
        api.requestMissingRoomKey(100, 'env-1');
        api.requestMissingRoomKey(100, 'env-2');
        api.requestMissingRoomKey(100, 'env-1');
        assert.strictEqual(state.timers.filter(t => !t.cleared).length, 1, 'таймер один: предыдущие сброшены');
        assert.strictEqual(state.timers[0].ms, api.KEY_REQUEST_DEBOUNCE_MS);
        assert.deepStrictEqual(state.calls, []);
        await state.timers.find(t => !t.cleared).fn();
        assert.deepStrictEqual(state.calls, [['requestRoomKeys', 11, 100, ['env-1', 'env-2']]]);
    });

    await test('запрос ключа: чужая (не открытая) комната и не строка игнорируются; отмена очищает очередь', async () => {
        const { state, api } = makeSandbox();
        api.requestMissingRoomKey(300, 'env');
        api.requestMissingRoomKey(100, 42);
        api.requestMissingRoomKey(null, 'env');
        assert.strictEqual(state.timers.length, 0);
        api.requestMissingRoomKey(100, 'env');
        api.clearPendingKeyRequests();
        assert.ok(state.timers.every(t => t.cleared));
        await api.flushKeyRequest(100);
        assert.deepStrictEqual(state.calls, []);
    });

    await test('ответ на запрос ключа: событие сокета → answerKeyRequests по чату комнаты → ensureRoomSession при непустом resend', async () => {
        const { state, api } = makeSandbox();
        state.answer = { resend: [2] };
        await api.handleKeyRequestEvent({ roomId: 100, fromUserId: 2, senderKeyIds: ['AAAAAAAAAAAAAAAAAAAAAA=='] });
        assert.deepStrictEqual(state.calls, [['answerKeyRequests', 11, 100, [{ fromUserId: 2, senderKeyIds: ['AAAAAAAAAAAAAAAAAAAAAA=='] }]]]);
        assert.deepStrictEqual(state.ensured, [[11, 100]]);
        state.ensured.length = 0;
        state.answer = { resend: [] };
        await api.handleKeyRequestEvent({ roomId: 100, fromUserId: 3, senderKeyIds: [] });
        assert.deepStrictEqual(state.ensured, [], 'ключ не мой — переотправки нет');
        await api.handleKeyRequestEvent({ roomId: 999, fromUserId: 2, senderKeyIds: [] });
        await api.handleKeyRequestEvent(null);
        assert.strictEqual(state.calls.filter(c => c[0] === 'answerKeyRequests').length, 2, 'неизвестная комната и пустое событие игнорируются');
    });

    await test('срок хранения: syncRoomKeyPolicy передаёт секунды клиенту, мусор сводится к 0', async () => {
        const { state, api } = makeSandbox();
        await api.syncRoomKeyPolicy(100, 3600);
        await api.syncRoomKeyPolicy(100, 'abc');
        await api.syncRoomKeyPolicy(null, 3600);
        assert.deepStrictEqual(state.calls, [
            ['setRoomPolicy', 100, { expirySeconds: 3600 }],
            ['setRoomPolicy', 100, { expirySeconds: 0 }],
        ]);
    });

    await test('обслуживание ключей: раз в час по всем комнатам списка чатов, без чатов-не-комнат; первый запуск через 20 с', async () => {
        const { state, api } = makeSandbox();
        api.startRoomKeysMaintenance();
        assert.strictEqual(state.timers.at(-1).ms, 20 * 1000);
        assert.strictEqual(state.intervals.at(-1).ms, api.ROOM_KEYS_MAINTENANCE_MS);
        assert.strictEqual(api.ROOM_KEYS_MAINTENANCE_MS, 60 * 60 * 1000);
        await api.maintainAllRoomKeys();
        assert.deepStrictEqual(state.calls, [
            ['setRoomPolicy', 100, { expirySeconds: 3600 }], ['maintainRoomKeys', 100],
            ['setRoomPolicy', 300, { expirySeconds: 0 }], ['maintainRoomKeys', 300],
        ]);
        api.stopRoomKeysMaintenance();
        assert.ok(state.intervals.at(-1).cleared && state.timers.at(-1).cleared);
    });

    await test('обслуживание ключей: не работает без входа и пока E2EE не готово; сбой одной комнаты не мешает остальным', async () => {
        const off = makeSandbox({ e2eeState: 'unavailable' });
        await off.api.maintainAllRoomKeys();
        assert.deepStrictEqual(off.state.calls, []);
        const { state, client, api } = makeSandbox();
        let first = true;
        client.setRoomPolicy = async (roomId, patch) => { state.calls.push(['setRoomPolicy', roomId, patch]); if (first) { first = false; throw new Error('сбой'); } };
        await api.maintainAllRoomKeys();
        assert.ok(state.calls.some(c => c[0] === 'maintainRoomKeys' && c[1] === 300), 'вторая комната обслужена');
        assert.ok(state.warnings.some(w => /обслуживание ключей комнаты/.test(w)));
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})();
