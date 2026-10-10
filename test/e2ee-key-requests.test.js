'use strict';
// Запросы ключа Sender Key (lib/e2ee-groups.js, план криптографии, раздел 5):
// POST /api/keys/key-requests, GET /api/keys/key-requests/:chatId,
// POST /api/keys/key-requests/done, лимиты, срок жизни, ретрансляция по сокету.
// БД имитируется в памяти под конкретные запросы модуля.
// Запуск: node test/e2ee-key-requests.test.js

const assert = require('assert');
const crypto = require('crypto');
const {
    registerE2eeGroupRoutes, jobs, purgeExpiredKeyRequests,
    MAX_PENDING_KEY_REQUESTS, KEY_REQUEST_TTL_HOURS, KEY_REQUEST_POSTS_PER_HOUR,
} = require('../lib/e2ee-groups.js');

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

const HOUR = 60 * 60 * 1000;
const keyId = () => crypto.randomBytes(16).toString('base64');

function makeFakeApp() {
    const routes = [];
    const app = {};
    for (const method of ['get', 'post', 'put', 'delete']) app[method] = (path, ...handlers) => { routes.push({ method, path, handlers }); };
    app._find = (method, path) => routes.find(r => r.method === method && r.path === path);
    return app;
}

async function call(app, method, path, { session, params, body } = {}) {
    const route = app._find(method, path);
    assert.ok(route, 'маршрут не зарегистрирован: ' + method + ' ' + path);
    const res = {
        statusCode: 200, body: null, headers: {},
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
        set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    };
    const req = { session: session || null, params: params || {}, query: {}, body: body || {} };
    for (const h of route.handlers) {
        if (res.body !== null) break;
        await h(req, res, () => {});
    }
    return res;
}

function makeFakeIo() {
    const emitted = [];
    return { to(room) { return { emit: (event, payload) => emitted.push({ room, event, payload }) }; }, _emitted: emitted };
}

// Таблицы: chats, room_participants, e2ee_key_requests (с уникальностью и OFFSET-вытеснением).
function makeFakeDb() {
    const chats = [];
    const participants = [];
    const requests = []; // { id, room_id, requester_id, key_id (Buffer), created_hour }
    let nextId = 1;

    async function dbAll(query, params) {
        if (query.includes('FROM chats WHERE id')) {
            const [id, userId] = params;
            return chats.filter(c => Number(c.id) === Number(id) && Number(c.user_id) === Number(userId));
        }
        if (query.includes('FROM room_participants WHERE room_id')) {
            return participants.filter(p => p.room_id === params[0]).map(p => ({ user_id: p.user_id }));
        }
        if (query.includes('FROM e2ee_key_requests') && query.includes('requester_id <> $2')) {
            const [roomId, me, minHour] = params;
            return requests
                .filter(r => r.room_id === roomId && r.requester_id !== me && r.created_hour >= minHour)
                .sort((a, b) => a.id - b.id)
                .slice(0, 500)
                .map(r => ({ requester_id: r.requester_id, key_id: r.key_id }));
        }
        throw new Error('fake db: unhandled query: ' + query);
    }
    async function dbGet(query, params) { return (await dbAll(query, params))[0] || null; }
    async function dbRun(query, params) {
        if (query.startsWith('DELETE FROM e2ee_key_requests WHERE room_id = $1 AND created_hour < $2')) {
            const [roomId, hour] = params;
            const before = requests.length;
            for (let i = requests.length - 1; i >= 0; i--) if (requests[i].room_id === roomId && requests[i].created_hour < hour) requests.splice(i, 1);
            return { rowCount: before - requests.length };
        }
        if (query.startsWith('INSERT INTO e2ee_key_requests')) {
            const [roomId, requesterId, key, hour] = params;
            assert.ok(Buffer.isBuffer(key) && key.length === 16, 'key_id — 16 байт');
            const existing = requests.find(r => r.room_id === roomId && r.requester_id === requesterId && r.key_id.equals(key));
            if (existing) existing.created_hour = hour;
            else requests.push({ id: nextId++, room_id: roomId, requester_id: requesterId, key_id: key, created_hour: hour });
            return { rowCount: 1 };
        }
        if (query.startsWith('DELETE FROM e2ee_key_requests WHERE id IN')) {
            const [roomId, requesterId, offset] = params;
            const scope = requests.filter(r => r.room_id === roomId && r.requester_id === requesterId)
                .sort((a, b) => (b.created_hour - a.created_hour) || (b.id - a.id));
            const victims = new Set(scope.slice(offset).map(r => r.id));
            for (let i = requests.length - 1; i >= 0; i--) if (victims.has(requests[i].id)) requests.splice(i, 1);
            return { rowCount: victims.size };
        }
        if (query.startsWith('DELETE FROM e2ee_key_requests WHERE room_id = $1 AND requester_id = $2 AND key_id = ANY')) {
            const [roomId, requesterId, keys] = params;
            for (let i = requests.length - 1; i >= 0; i--) {
                const r = requests[i];
                if (r.room_id === roomId && r.requester_id === requesterId && keys.some(k => k.equals(r.key_id))) requests.splice(i, 1);
            }
            return { rowCount: 1 };
        }
        throw new Error('fake db: unhandled run: ' + query);
    }
    return { dbGet, dbAll, dbRun, _chats: chats, _participants: participants, _requests: requests };
}

// Комната 100: Alice (1, чат 11), Bob (2, чат 22), Carol (3, чат 33); Dave (4, чат 44) — в другой комнате 200.
function fixture(extra = {}) {
    const app = makeFakeApp();
    const db = makeFakeDb();
    const io = makeFakeIo();
    for (const [id, chat] of [[1, 11], [2, 22], [3, 33]]) {
        db._chats.push({ id: chat, user_id: id, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: id });
    }
    db._chats.push({ id: 44, user_id: 4, room_id: 200 }, { id: 99, user_id: 1, room_id: null });
    db._participants.push({ room_id: 200, user_id: 4 });
    registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io, ...extra });
    return { app, db, io };
}

const post = (app, userId, body) => call(app, 'post', '/api/keys/key-requests', { session: { userId }, body });
const list = (app, userId, chatId) => call(app, 'get', '/api/keys/key-requests/:chatId', { session: { userId }, params: { chatId: String(chatId) } });
const done = (app, userId, body) => call(app, 'post', '/api/keys/key-requests/done', { session: { userId }, body });

(async () => {
    console.log('Запросы ключа Sender Key: маршруты\n');

    await test('маршруты зарегистрированы, без сессии — 401', async () => {
        const { app } = fixture();
        assert.ok(app._find('post', '/api/keys/key-requests'));
        assert.ok(app._find('get', '/api/keys/key-requests/:chatId'));
        assert.ok(app._find('post', '/api/keys/key-requests/done'));
        assert.strictEqual((await call(app, 'post', '/api/keys/key-requests', { body: {} })).statusCode, 401);
        assert.strictEqual((await call(app, 'get', '/api/keys/key-requests/:chatId', { params: { chatId: '11' } })).statusCode, 401);
    });

    await test('запрос ретранслируется остальным участникам комнаты и записывается; запросившему сигнал не уходит', async () => {
        const { app, db, io } = fixture();
        const ids = [keyId(), keyId()];
        const res = await post(app, 2, { chatId: 22, senderKeyIds: ids });
        assert.deepStrictEqual(res.body, { success: true, requested: 2 });
        assert.deepStrictEqual(io._emitted.map(e => e.room).sort(), ['user:1', 'user:3']);
        for (const e of io._emitted) {
            assert.strictEqual(e.event, 'e2eeKeyRequest');
            assert.deepStrictEqual(e.payload, { roomId: 100, fromUserId: 2, senderKeyIds: ids });
        }
        assert.strictEqual(db._requests.length, 2);
        assert.ok(db._requests.every(r => r.room_id === 100 && r.requester_id === 2 && Number.isInteger(r.created_hour)));
    });

    await test('повторный запрос того же ключа не плодит строк и продлевает срок', async () => {
        const { app, db } = fixture();
        const id = keyId();
        const realNow = Date.now;
        try {
            Date.now = () => 1_800_000_000_000;
            await post(app, 2, { chatId: 22, senderKeyIds: [id] });
            const first = db._requests[0].created_hour;
            Date.now = () => 1_800_000_000_000 + 5 * HOUR;
            await post(app, 2, { chatId: 22, senderKeyIds: [id, id] });
            assert.strictEqual(db._requests.length, 1);
            assert.strictEqual(db._requests[0].created_hour, first + 5);
        } finally { Date.now = realNow; }
    });

    await test('некорректные запросы: чужой чат, чат без комнаты, плохие и лишние id', async () => {
        const { app, db } = fixture();
        const ok = keyId();
        assert.strictEqual((await post(app, 2, { chatId: 11, senderKeyIds: [ok] })).body.success, false, 'чат другого пользователя');
        assert.strictEqual((await post(app, 1, { chatId: 99, senderKeyIds: [ok] })).body.success, false, 'чат без комнаты');
        for (const body of [
            { chatId: 22 }, { chatId: 22, senderKeyIds: [] }, { chatId: 'x', senderKeyIds: [ok] },
            { chatId: 22, senderKeyIds: 'abc' },
            { chatId: 22, senderKeyIds: ['короткий'] },
            { chatId: 22, senderKeyIds: [crypto.randomBytes(15).toString('base64')] },
            { chatId: 22, senderKeyIds: [ok.slice(0, -2) + 'A='] },
            { chatId: 22, senderKeyIds: [5] },
            { chatId: 22, senderKeyIds: Array.from({ length: 21 }, keyId) },
        ]) {
            const res = await post(app, 2, body);
            assert.strictEqual(res.statusCode, 400, JSON.stringify(body).slice(0, 80));
        }
        assert.strictEqual(db._requests.length, 0);
    });

    await test('не больше 50 ожидающих строк на пару (запросивший, комната): вытесняются самые старые', async () => {
        const { app, db } = fixture();
        const realNow = Date.now;
        try {
            const all = [];
            for (let i = 0; i < 3; i++) {
                // Лимит запросов — 10 в час, поэтому время идёт вперёд.
                Date.now = () => 1_800_000_000_000 + i * 2 * HOUR;
                const ids = Array.from({ length: 20 }, keyId);
                all.push(...ids);
                assert.strictEqual((await post(app, 2, { chatId: 22, senderKeyIds: ids })).body.success, true);
            }
            const kept = db._requests.map(r => r.key_id.toString('base64'));
            assert.strictEqual(kept.length, MAX_PENDING_KEY_REQUESTS);
            assert.ok(all.slice(10).every(id => kept.includes(id)), 'последние 50 на месте');
            assert.ok(all.slice(0, 10).every(id => !kept.includes(id)), 'первые 10 вытеснены');
        } finally { Date.now = realNow; }
    });

    await test('лимит: не больше 10 запросов в час на пару (пользователь, комната), 429 с Retry-After', async () => {
        const { app, db } = fixture();
        const realNow = Date.now;
        try {
            let now = 1_800_000_000_000;
            Date.now = () => now;
            for (let i = 0; i < KEY_REQUEST_POSTS_PER_HOUR; i++) {
                assert.strictEqual((await post(app, 2, { chatId: 22, senderKeyIds: [keyId()] })).body.success, true, 'запрос ' + (i + 1));
            }
            const limited = await post(app, 2, { chatId: 22, senderKeyIds: [keyId()] });
            assert.strictEqual(limited.statusCode, 429);
            assert.ok(Number(limited.headers['retry-after']) > 0);
            assert.strictEqual(db._requests.length, KEY_REQUEST_POSTS_PER_HOUR, 'отказанный запрос ничего не записал');
            assert.strictEqual((await post(app, 3, { chatId: 33, senderKeyIds: [keyId()] })).body.success, true, 'другой пользователь — своя квота');
            now += 61 * 60 * 1000;
            assert.strictEqual((await post(app, 2, { chatId: 22, senderKeyIds: [keyId()] })).body.success, true, 'через час квота освободилась');
        } finally { Date.now = realNow; }
    });

    await test('лимит в Postgres: хранилище лимита недоступно — 503 busy, запрос не выполняется', async () => {
        const { app, db, io } = fixture({ keyRequestLimiter: { tryConsume: async () => { throw new Error('limits down'); } } });
        const res = await post(app, 2, { chatId: 22, senderKeyIds: [keyId()] });
        assert.strictEqual(res.statusCode, 503);
        assert.strictEqual(res.body.code, 'busy');
        assert.strictEqual(db._requests.length, 0);
        assert.strictEqual(io._emitted.length, 0);
    });

    await test('лимит в Postgres: правило ограничено парой (пользователь, комната)', async () => {
        const calls = [];
        const { app } = fixture({ keyRequestLimiter: { tryConsume: async (lock, rules) => { calls.push({ lock, rules }); return { ok: true, waitMs: [0] }; } } });
        await post(app, 2, { chatId: 22, senderKeyIds: [keyId()] });
        assert.deepStrictEqual(calls, [{ lock: '2', rules: [{ key: 'keyreq:2:100', max: KEY_REQUEST_POSTS_PER_HOUR }] }]);
    });

    await test('GET: владелец видит запросы других участников своей комнаты, а не свои и не чужой комнаты', async () => {
        const { app, db } = fixture();
        const a = keyId(), b = keyId(), c = keyId();
        await post(app, 2, { chatId: 22, senderKeyIds: [a, b] });
        await post(app, 3, { chatId: 33, senderKeyIds: [c] });
        await post(app, 1, { chatId: 11, senderKeyIds: [keyId()] });
        db._requests.push({ id: 999, room_id: 200, requester_id: 4, key_id: crypto.randomBytes(16), created_hour: Math.floor(Date.now() / HOUR) });

        const asAlice = await list(app, 1, 11);
        assert.strictEqual(asAlice.body.success, true);
        assert.strictEqual(asAlice.body.roomId, 100);
        assert.deepStrictEqual(asAlice.body.requests, [
            { fromUserId: 2, senderKeyIds: [a, b] },
            { fromUserId: 3, senderKeyIds: [c] },
        ]);
        const asBob = await list(app, 2, 22);
        assert.deepStrictEqual(asBob.body.requests.map(r => r.fromUserId).sort(), [1, 3], 'своих запросов Боб не видит');
        // Строки не удаляются при чтении: ключ может быть не Алисы, а ответ другого владельца ещё ждёт.
        assert.strictEqual((await list(app, 1, 11)).body.requests.length, 2);
        // Чужой чат и чат без комнаты — пусто.
        assert.deepStrictEqual((await list(app, 2, 11)).body, { success: true, roomId: null, requests: [] });
        assert.deepStrictEqual((await list(app, 1, 99)).body, { success: true, roomId: null, requests: [] });
        assert.deepStrictEqual((await list(app, 1, 'abc')).body, { success: true, roomId: null, requests: [] });
    });

    await test('GET: просроченные (старше 7 суток) строки не отдаются, POST убирает их заодно', async () => {
        const { app, db } = fixture();
        const hour = Math.floor(Date.now() / HOUR);
        const stale = keyId();
        db._requests.push({ id: 500, room_id: 100, requester_id: 2, key_id: Buffer.from(stale, 'base64'), created_hour: hour - KEY_REQUEST_TTL_HOURS - 1 });
        const fresh = keyId();
        db._requests.push({ id: 501, room_id: 100, requester_id: 3, key_id: Buffer.from(fresh, 'base64'), created_hour: hour - KEY_REQUEST_TTL_HOURS });
        const res = await list(app, 1, 11);
        assert.deepStrictEqual(res.body.requests, [{ fromUserId: 3, senderKeyIds: [fresh] }]);
        await post(app, 3, { chatId: 33, senderKeyIds: [keyId()] });
        assert.ok(!db._requests.some(r => r.id === 500), 'просроченная строка убрана при записи');
    });

    await test('done: запросивший стирает свои строки; чужие и строки других комнат не трогает', async () => {
        const { app, db } = fixture();
        const a = keyId(), b = keyId();
        await post(app, 2, { chatId: 22, senderKeyIds: [a, b] });
        await post(app, 3, { chatId: 33, senderKeyIds: [a] });
        assert.strictEqual(db._requests.length, 3);
        assert.strictEqual((await done(app, 3, { chatId: 33, senderKeyIds: [a, b] })).body.success, true);
        assert.deepStrictEqual(db._requests.map(r => `${r.requester_id}:${r.key_id.toString('base64')}`).sort(), [`2:${a}`, `2:${b}`].sort(), 'остались строки Боба');
        assert.strictEqual((await done(app, 2, { chatId: 11, senderKeyIds: [a] })).body.success, false, 'чужой чат');
        assert.strictEqual((await done(app, 2, { chatId: 22, senderKeyIds: ['плохой'] })).statusCode, 400);
        assert.strictEqual((await done(app, 2, { chatId: 22, senderKeyIds: [a] })).body.success, true);
        assert.strictEqual(db._requests.length, 1);
    });

    await test('задача уборки: удаляет строки старше срока и зарегистрирована раз в час', async () => {
        const queries = [];
        const pool = { query: async (sql, params) => { queries.push({ sql, params }); return { rowCount: 3 }; } };
        assert.strictEqual(await purgeExpiredKeyRequests(pool), 3);
        assert.ok(/DELETE FROM e2ee_key_requests WHERE created_hour < \$1/.test(queries[0].sql));
        const hour = Math.floor(Date.now() / HOUR);
        assert.ok(Math.abs(queries[0].params[0] - (hour - KEY_REQUEST_TTL_HOURS)) <= 1);
        const [job] = jobs({ pool });
        assert.strictEqual(job.name, 'purgeKeyRequests');
        assert.strictEqual(job.intervalMs, HOUR);
        assert.strictEqual(job.maintenance, true);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})();
