'use strict';
// Регрессионные тесты серверных маршрутов E2EE:
//   1) require()+регистрация обоих модулей не должна падать — именно так
//      выглядел исходный баг lib/e2ee-proxy.js ("app.put(...) на верхнем
//      уровне, где app ещё не существует" — ReferenceError при require(),
//      до начала прослушивания порта, т.е. crash-loop контейнера).
//   2) Бизнес-логика lib/e2ee-groups.js (резолв chatId->room_id, проверка
//      членства, fetch-and-delete key-share) — против лёгкой in-memory
//      имитации БД, без реального Postgres.
// Запуск: node test/server-routes.test.js

const assert = require('assert');

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

// ---- Лёгкая имитация Express-приложения: просто запоминает
// зарегистрированные маршруты, ничего не поднимает по-настоящему. ----
function makeFakeApp() {
    const routes = [];
    const app = {};
    for (const method of ['get', 'post', 'put', 'delete']) {
        app[method] = (path, ...handlers) => { routes.push({ method, path, handlers }); };
    }
    app._routes = routes;
    app._find = (method, path) => routes.find(r => r.method === method && r.path === path);
    return app;
}

function makeFakeReqRes({ session, params, query, body } = {}) {
    const res = {
        statusCode: 200,
        body: null,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
    };
    const req = { session: session || null, params: params || {}, query: query || {}, body: body || {} };
    return { req, res };
}

// Прогоняет цепочку [mw1, mw2, ..., handler] как это делает Express:
// каждый может либо сам ответить (res.json — тогда останавливаемся),
// либо вызвать next() и передать управление дальше. Middleware вроде
// requireAuth вызывает next() синхронно, не дожидаясь её завершения —
// поэтому next() здесь не рекурсивная точка продолжения (как в реальном
// Express), а просто маркер "иди дальше", и следующий handler всё равно
// await'ится этим циклом, а не потерянным fire-and-forget вызовом.
async function runHandlers(handlers, req, res) {
    for (const h of handlers) {
        if (res.body !== null) return; // предыдущий handler уже ответил
        await h(req, res, () => {});
    }
}

// ---- In-memory имитация БД под конкретные запросы lib/e2ee-groups.js ----
function makeFakeDb() {
    const chats = []; // {id, user_id, room_id}
    const participants = []; // {room_id, user_id, username}
    const keyShares = []; // {id, room_id, sender_id, recipient_id, ciphertext}
    let nextShareId = 1;

    async function dbGet(query, params) {
        const rows = await dbAll(query, params);
        return rows[0] || null;
    }
    async function dbAll(query, params) {
        if (query.includes('FROM chats WHERE id')) {
            // params приходят как строки из req.params — как и в реальном
            // Postgres-драйвере, сравнение с integer-колонкой требует
            // приведения типов (сам pg делает это на уровне протокола).
            const [id, userId] = params;
            return chats.filter(c => Number(c.id) === Number(id) && Number(c.user_id) === Number(userId));
        }
        if (query.includes('FROM users u JOIN room_participants')) {
            const [roomId] = params;
            return participants.filter(p => p.room_id === roomId).map(p => ({ id: p.user_id, username: p.username }));
        }
        if (query.includes('FROM room_participants WHERE room_id')) {
            const [roomId] = params;
            return participants.filter(p => p.room_id === roomId).map(p => ({ user_id: p.user_id }));
        }
        if (query.includes('FROM e2ee_key_shares WHERE room_id')) {
            const [roomId, recipientId] = params;
            return keyShares.filter(s => s.room_id === roomId && s.recipient_id === recipientId)
                .map(s => ({ id: s.id, sender_id: s.sender_id, ciphertext: s.ciphertext }));
        }
        throw new Error('fake db: unhandled query: ' + query);
    }
    async function dbRun(query, params) {
        if (query.startsWith('INSERT INTO e2ee_key_shares')) {
            const [roomId, senderId, recipientId, ciphertext] = params;
            keyShares.push({ id: nextShareId++, room_id: roomId, sender_id: senderId, recipient_id: recipientId, ciphertext });
            return { rowCount: 1 };
        }
        if (query.startsWith('DELETE FROM e2ee_key_shares')) {
            const ids = new Set(params);
            for (let i = keyShares.length - 1; i >= 0; i--) if (ids.has(keyShares[i].id)) keyShares.splice(i, 1);
            return { rowCount: params.length };
        }
        throw new Error('fake db: unhandled run: ' + query);
    }

    return { dbGet, dbAll, dbRun, _chats: chats, _participants: participants, _keyShares: keyShares };
}

function makeFakeIo() {
    const emitted = [];
    return {
        to(room) {
            return { emit: (event, payload) => emitted.push({ room, event, payload }) };
        },
        _emitted: emitted,
    };
}

async function main() {
    console.log('Server route tests\n');

    await test('e2ee-proxy.js: require + registration does not throw (the original bug)', async () => {
        delete require.cache[require.resolve('../lib/e2ee-proxy.js')];
        const { registerE2eeProxyRoutes } = require('../lib/e2ee-proxy.js');
        const app = makeFakeApp();
        registerE2eeProxyRoutes(app); // раньше именно этот вызов (а точнее, его ОТСУТСТВИЕ на верхнем
                                       // уровне модуля) выявлял ReferenceError при самом require()
        const expected = [
            ['put', '/api/keys/identity'],
            ['put', '/api/keys/signed-prekey'],
            ['post', '/api/keys/one-time-prekeys'],
            ['get', '/api/keys/one-time-prekeys/count'],
            ['get', '/api/keys/bundle/:targetUserId'],
            ['delete', '/api/keys'],
        ];
        for (const [method, path] of expected) {
            assert.ok(app._find(method, path), 'missing route ' + method + ' ' + path);
        }
    });

    await test('e2ee-proxy.js: proxied route responds 503 without crashing when KEY_SERVER_SECRET unset', async () => {
        delete process.env.INTERNAL_KEY_SERVER_SECRET;
        delete require.cache[require.resolve('../lib/e2ee-proxy.js')];
        const { registerE2eeProxyRoutes } = require('../lib/e2ee-proxy.js');
        const app = makeFakeApp();
        registerE2eeProxyRoutes(app);
        const route = app._find('get', '/api/keys/one-time-prekeys/count');
        const { req, res } = makeFakeReqRes({ session: { userId: 1 } });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.statusCode, 503);
        assert.strictEqual(res.body.success, false);
    });

    await test('e2ee-proxy.js: unauthenticated request is rejected with 401, not forwarded', async () => {
        delete require.cache[require.resolve('../lib/e2ee-proxy.js')];
        const { registerE2eeProxyRoutes } = require('../lib/e2ee-proxy.js');
        const app = makeFakeApp();
        registerE2eeProxyRoutes(app);
        const route = app._find('delete', '/api/keys');
        const { req, res } = makeFakeReqRes({ session: null });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.statusCode, 401);
    });

    await test('e2ee-proxy.js: non-numeric targetUserId is rejected with 400 before proxying', async () => {
        delete require.cache[require.resolve('../lib/e2ee-proxy.js')];
        const { registerE2eeProxyRoutes } = require('../lib/e2ee-proxy.js');
        const app = makeFakeApp();
        registerE2eeProxyRoutes(app);
        const route = app._find('get', '/api/keys/bundle/:targetUserId');
        const { req, res } = makeFakeReqRes({ session: { userId: 1 }, params: { targetUserId: 'not-a-number' } });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.statusCode, 400);
        assert.strictEqual(res.body.success, false);
    });

    await test('e2ee-groups.js: require + registration does not throw', async () => {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io: makeFakeIo() });
        assert.ok(app._find('get', '/api/chats/:chatId/participants'));
        assert.ok(app._find('post', '/api/keys/key-shares'));
        assert.ok(app._find('get', '/api/keys/key-shares/:chatId'));
    });

    await test('GET participants: returns room members for a chat the caller owns', async () => {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io: makeFakeIo() });
        db._chats.push({ id: 11, user_id: 1, room_id: 100 }, { id: 22, user_id: 2, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });

        const route = app._find('get', '/api/chats/:chatId/participants');
        const { req, res } = makeFakeReqRes({ session: { userId: 1 }, params: { chatId: '11' } });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.roomId, 100);
        assert.deepStrictEqual(res.body.participants.map(p => p.id).sort(), [1, 2]);
    });

    await test('GET participants: a chat without a room (bot/solo) returns an empty list, not an error', async () => {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io: makeFakeIo() });
        db._chats.push({ id: 55, user_id: 1, room_id: null });

        const route = app._find('get', '/api/chats/:chatId/participants');
        const { req, res } = makeFakeReqRes({ session: { userId: 1 }, params: { chatId: '55' } });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.roomId, null);
        assert.deepStrictEqual(res.body.participants, []);
    });

    await test('GET participants: a chat belonging to someone else is not found', async () => {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io: makeFakeIo() });
        db._chats.push({ id: 11, user_id: 1, room_id: 100 });

        const route = app._find('get', '/api/chats/:chatId/participants');
        const { req, res } = makeFakeReqRes({ session: { userId: 999 }, params: { chatId: '11' } });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.body.success, false);
    });

    await test('POST key-shares: rejects a recipient who is not a room member', async () => {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        const io = makeFakeIo();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io });
        db._chats.push({ id: 11, user_id: 1, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });

        const route = app._find('post', '/api/keys/key-shares');
        const { req, res } = makeFakeReqRes({
            session: { userId: 1 },
            body: { chatId: 11, shares: [{ recipientUserId: 999, ciphertext: 'abc' }] },
        });
        await runHandlers(route.handlers, req, res);
        assert.strictEqual(res.body.success, false);
        assert.strictEqual(db._keyShares.length, 0);
        assert.strictEqual(io._emitted.length, 0);
    });

    await test('POST key-shares -> GET key-shares: fetch-and-delete round trip, and pushes a socket notice', async () => {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        const io = makeFakeIo();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io });
        db._chats.push({ id: 11, user_id: 1, room_id: 100 }, { id: 22, user_id: 2, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });

        const postRoute = app._find('post', '/api/keys/key-shares');
        const post1 = makeFakeReqRes({ session: { userId: 1 }, body: { chatId: 11, shares: [{ recipientUserId: 2, ciphertext: 'wrapped-sender-key' }] } });
        await runHandlers(postRoute.handlers, post1.req, post1.res);
        assert.strictEqual(post1.res.body.success, true);
        assert.strictEqual(io._emitted.length, 1);
        assert.strictEqual(io._emitted[0].room, 'user:2');
        assert.strictEqual(io._emitted[0].event, 'e2eeKeyShare');

        const getRoute = app._find('get', '/api/keys/key-shares/:chatId');
        const get1 = makeFakeReqRes({ session: { userId: 2 }, params: { chatId: '22' } });
        await runHandlers(getRoute.handlers, get1.req, get1.res);
        assert.strictEqual(get1.res.body.success, true);
        assert.strictEqual(get1.res.body.shares.length, 1);
        assert.strictEqual(get1.res.body.shares[0].senderId, 1);
        assert.strictEqual(get1.res.body.shares[0].ciphertext, 'wrapped-sender-key');

        // Второй вызов подряд ничего не должен вернуть — уже забрано и удалено.
        const get2 = makeFakeReqRes({ session: { userId: 2 }, params: { chatId: '22' } });
        await runHandlers(getRoute.handlers, get2.req, get2.res);
        assert.strictEqual(get2.res.body.shares.length, 0);
        assert.strictEqual(db._keyShares.length, 0);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exit(1);
}

main().catch(err => { console.error('Test runner crashed:', err); process.exit(1); });
