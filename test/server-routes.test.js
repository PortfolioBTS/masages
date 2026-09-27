'use strict';
// Регрессионные тесты серверных маршрутов E2EE:
//   1) require()+регистрация обоих модулей не должна падать — именно так
//      выглядел исходный баг lib/e2ee-proxy.js ("app.put(...) на верхнем
//      уровне, где app ещё не существует" — ReferenceError при require(),
//      до начала прослушивания порта, т.е. crash-loop контейнера).
//   2) lib/e2ee-proxy.js: доступ к чужим ключам только при общей комнате,
//      фильтрация /api/keys/identities, лимиты на bundle, проксирование
//      pq-prekey — против поддельных dbGet/dbAll и подменённого fetch.
//   3) Бизнес-логика lib/e2ee-groups.js (резолв chatId->room_id, проверка
//      членства, fetch-and-delete key-share, лимиты размера и очереди) —
//      против лёгкой in-memory имитации БД, без реального Postgres.
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
        headers: {},
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
        set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
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

async function call(app, method, path, opts) {
    const route = app._find(method, path);
    assert.ok(route, 'route not registered: ' + method + ' ' + path);
    const { req, res } = makeFakeReqRes(opts);
    await runHandlers(route.handlers, req, res);
    return res;
}

// ---- In-memory имитация БД под конкретные запросы lib/e2ee-*.js ----
function makeFakeDb() {
    const chats = []; // {id, user_id, room_id}
    const participants = []; // {room_id, user_id, username}
    const keyShares = []; // {id, room_id, sender_id, recipient_id, ciphertext}
    let nextShareId = 1;
    const queries = [];

    function roomsOf(userId) {
        return new Set(participants.filter(p => p.user_id === userId).map(p => p.room_id));
    }
    function sharesRoom(a, b) {
        const rooms = roomsOf(a);
        return participants.some(p => p.user_id === b && rooms.has(p.room_id));
    }

    async function dbGet(query, params) {
        const rows = await dbAll(query, params);
        return rows[0] || null;
    }
    async function dbAll(query, params) {
        queries.push({ query, params });
        if (query.includes('FROM room_participants a JOIN room_participants b')) {
            const [userId, target] = params;
            if (query.includes('ANY($2::int[])')) {
                assert.ok(Array.isArray(target), 'ANY() expects an array parameter');
                return target.filter(id => sharesRoom(userId, id)).map(id => ({ user_id: id }));
            }
            return sharesRoom(userId, target) ? [{ '?column?': 1 }] : [];
        }
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
        if (query.includes('COUNT(*)') && query.includes('FROM e2ee_key_shares')) {
            const [roomId, recipientIds] = params;
            const counts = new Map();
            for (const s of keyShares) {
                if (s.room_id === roomId && recipientIds.includes(s.recipient_id)) {
                    counts.set(s.recipient_id, (counts.get(s.recipient_id) || 0) + 1);
                }
            }
            return [...counts].map(([recipient_id, cnt]) => ({ recipient_id, cnt }));
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

    return { dbGet, dbAll, dbRun, _chats: chats, _participants: participants, _keyShares: keyShares, _queries: queries };
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

// ---- Подмена глобального fetch: key-server "отвечает" из handler'а ----
const realFetch = global.fetch;
function installFakeFetch(handler) {
    const calls = [];
    global.fetch = async (url, opts = {}) => {
        const entry = { url: String(url), method: opts.method || 'GET', headers: opts.headers || {}, body: opts.body };
        calls.push(entry);
        const reply = await handler(entry);
        const status = reply.status || 200;
        return {
            status,
            ok: status >= 200 && status < 300,
            json: async () => {
                if (reply.rawText !== undefined) return JSON.parse(reply.rawText);
                return reply.body;
            },
        };
    };
    return calls;
}
function restoreFetch() { global.fetch = realFetch; }

const SECRET = 'test-internal-secret';

// KEY_SERVER_SECRET читается при загрузке модуля — поэтому каждый раз
// свежий require с нужным окружением.
function loadProxy({ secret = SECRET } = {}) {
    if (secret) process.env.INTERNAL_KEY_SERVER_SECRET = secret;
    else delete process.env.INTERNAL_KEY_SERVER_SECRET;
    process.env.KEY_SERVER_URL = 'http://key-server.test';
    delete require.cache[require.resolve('../lib/e2ee-proxy.js')];
    return require('../lib/e2ee-proxy.js');
}

// Пользователи 1, 2, 3 — в комнате 100; 1 и 5 — в комнате 200;
// 4 ни с кем из них комнат не делит.
function makeProxyFixture(opts) {
    const { registerE2eeProxyRoutes } = loadProxy(opts);
    const db = makeFakeDb();
    db._participants.push(
        { room_id: 100, user_id: 1, username: 'alice' },
        { room_id: 100, user_id: 2, username: 'bob' },
        { room_id: 100, user_id: 3, username: 'carol' },
        { room_id: 200, user_id: 1, username: 'alice' },
        { room_id: 200, user_id: 5, username: 'eve' },
        { room_id: 300, user_id: 4, username: 'dave' },
    );
    const app = makeFakeApp();
    registerE2eeProxyRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll });
    return { app, db };
}

async function withFrozenTime(start, fn) {
    const realNow = Date.now;
    let now = start;
    Date.now = () => now;
    try {
        await fn(ms => { now += ms; });
    } finally {
        Date.now = realNow;
    }
}

async function withQuietConsole(fn) {
    const saved = { error: console.error, warn: console.warn };
    const logged = [];
    console.error = (...args) => logged.push(args.join(' '));
    console.warn = (...args) => logged.push(args.join(' '));
    try {
        await fn();
    } finally {
        console.error = saved.error;
        console.warn = saved.warn;
    }
    return logged;
}

async function main() {
    console.log('Server route tests\n');

    // ---------------- lib/e2ee-proxy.js ----------------

    await test('e2ee-proxy.js: require + registration does not throw (the original bug)', async () => {
        const { app } = makeProxyFixture();
        const expected = [
            ['put', '/api/keys/identity'],
            ['put', '/api/keys/signed-prekey'],
            ['put', '/api/keys/pq-prekey'],
            ['post', '/api/keys/one-time-prekeys'],
            ['get', '/api/keys/one-time-prekeys/count'],
            ['get', '/api/keys/identities'],
            ['get', '/api/keys/bundle/:targetUserId'],
            ['delete', '/api/keys'],
        ];
        for (const [method, path] of expected) {
            assert.ok(app._find(method, path), 'missing route ' + method + ' ' + path);
        }
    });

    await test('e2ee-proxy.js: registration without { dbGet, dbAll } fails fast', async () => {
        const { registerE2eeProxyRoutes } = loadProxy();
        assert.throws(() => registerE2eeProxyRoutes(makeFakeApp()), TypeError);
        assert.throws(() => registerE2eeProxyRoutes(makeFakeApp(), { dbGet: async () => null }), TypeError);
    });

    await test('e2ee-proxy.js: proxied route responds 503 without crashing when KEY_SERVER_SECRET unset', async () => {
        const { app } = makeProxyFixture({ secret: null });
        const calls = installFakeFetch(() => ({ body: {} }));
        try {
            for (const [method, path, params] of [
                ['get', '/api/keys/one-time-prekeys/count'],
                ['get', '/api/keys/bundle/:targetUserId', { targetUserId: '2' }],
            ]) {
                const res = await call(app, method, path, { session: { userId: 1 }, params });
                assert.strictEqual(res.statusCode, 503);
                assert.strictEqual(res.body.success, false);
            }
            assert.strictEqual(calls.length, 0);
        } finally {
            restoreFetch();
        }
    });

    await test('e2ee-proxy.js: unauthenticated request is rejected with 401, not forwarded', async () => {
        const { app } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: {} }));
        try {
            for (const [method, path] of [['delete', '/api/keys'], ['get', '/api/keys/identities'], ['put', '/api/keys/pq-prekey']]) {
                const res = await call(app, method, path, { session: null, query: { ids: '1' } });
                assert.strictEqual(res.statusCode, 401);
            }
            assert.strictEqual(calls.length, 0);
        } finally {
            restoreFetch();
        }
    });

    await test('e2ee-proxy.js: non-numeric / out-of-range targetUserId is rejected with 400 before proxying', async () => {
        const { app, db } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: {} }));
        try {
            for (const bad of ['not-a-number', '0', '-1', '1e3', '2147483648', '12abc']) {
                const res = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: bad } });
                assert.strictEqual(res.statusCode, 400, 'targetUserId=' + bad);
                assert.strictEqual(res.body.success, false);
            }
            assert.strictEqual(calls.length, 0);
            assert.strictEqual(db._queries.length, 0);
        } finally {
            restoreFetch();
        }
    });

    await test('bundle: 403 without a shared room, key-server is not called (no OPK drained)', async () => {
        const { app, db } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: {} }));
        try {
            const res = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: '4' } });
            assert.strictEqual(res.statusCode, 403);
            assert.deepStrictEqual(res.body, { success: false, message: 'Нет общего чата с пользователем' });
            assert.strictEqual(calls.length, 0);
            // Проверка — именно запросом по room_participants, с (вызывающий, цель).
            const q = db._queries[0];
            assert.ok(/FROM room_participants a JOIN room_participants b ON a\.room_id = b\.room_id/.test(q.query));
            assert.deepStrictEqual(q.params, [1, 4]);
        } finally {
            restoreFetch();
        }
    });

    await test('bundle: with a shared room the key-server response is passed through as is', async () => {
        const { app } = makeProxyFixture();
        const bundle = { identity_signing_key: 'AAA', pq_prekey: { key_id: 7, public_key: 'PQ', signature: 'SIG' }, one_time_prekey: null };
        const calls = installFakeFetch(() => ({ status: 200, body: bundle }));
        try {
            const res = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: '5' } });
            assert.strictEqual(res.statusCode, 200);
            assert.deepStrictEqual(res.body, bundle);
            assert.strictEqual(calls.length, 1);
            assert.strictEqual(calls[0].url, 'http://key-server.test/internal/v1/keys/bundle/5');
            assert.strictEqual(calls[0].method, 'GET');
            assert.strictEqual(calls[0].headers['X-Internal-Secret'], SECRET);
            assert.strictEqual(calls[0].headers['X-User-Id'], '1');
        } finally {
            restoreFetch();
        }
    });

    await test('bundle: key-server errors keep their status; network failure -> 502', async () => {
        const { app } = makeProxyFixture();
        installFakeFetch(() => ({ status: 404, body: { success: false, message: 'no bundle' } }));
        try {
            const res = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: '2' } });
            assert.strictEqual(res.statusCode, 404);
            assert.strictEqual(res.body.message, 'no bundle');
        } finally {
            restoreFetch();
        }
        installFakeFetch(() => { throw new Error('ECONNREFUSED'); });
        try {
            let res;
            const logged = await withQuietConsole(async () => {
                res = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: '3' } });
            });
            assert.strictEqual(res.statusCode, 502);
            assert.strictEqual(res.body.success, false);
            assert.ok(logged.some(l => l.includes('ECONNREFUSED')));
        } finally {
            restoreFetch();
        }
    });

    await test('bundle: 5 requests per hour per (caller, target) pair, then 429 with Retry-After', async () => {
        const { app } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: { ok: true } }));
        try {
            await withFrozenTime(1_000_000, async (advance) => {
                const get = (userId, target) => call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId }, params: { targetUserId: String(target) } });
                for (let i = 0; i < 5; i++) {
                    assert.strictEqual((await get(1, 2)).statusCode, 200, 'request #' + (i + 1));
                    advance(1000);
                }
                const limited = await get(1, 2);
                assert.strictEqual(limited.statusCode, 429);
                assert.strictEqual(limited.body.success, false);
                assert.ok(/этого пользователя/.test(limited.body.message), limited.body.message);
                assert.ok(Number(limited.headers['retry-after']) > 0);
                assert.strictEqual(calls.length, 5, 'the limited request must not reach the key-server');

                // Другая цель и другой вызывающий — свои счётчики пар.
                assert.strictEqual((await get(1, 3)).statusCode, 200);
                assert.strictEqual((await get(2, 1)).statusCode, 200);

                // Скользящее окно: через час после первого запроса слот освобождается.
                advance(60 * 60 * 1000 - 5000);
                assert.strictEqual((await get(1, 2)).statusCode, 200);
                assert.strictEqual((await get(1, 2)).statusCode, 429);
            });
        } finally {
            restoreFetch();
        }
    });

    await test('bundle: 60 requests per hour per caller across all targets, then 429', async () => {
        const { app, db } = makeProxyFixture();
        // Ещё 12 собеседников в общей комнате с пользователем 1: 13 целей × ≤5 = 65 > 60.
        for (let id = 10; id < 22; id++) db._participants.push({ room_id: 100, user_id: id, username: 'u' + id });
        const targets = [2, 3, 5, ...Array.from({ length: 12 }, (_, i) => 10 + i)];
        installFakeFetch(() => ({ body: {} }));
        try {
            await withFrozenTime(5_000_000, async (advance) => {
                let ok = 0;
                for (const target of targets) {
                    for (let i = 0; i < 5 && ok < 60; i++) {
                        const res = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: String(target) } });
                        assert.strictEqual(res.statusCode, 200);
                        ok++;
                        advance(10);
                    }
                }
                assert.strictEqual(ok, 60);
                const fresh = targets.find((_, i) => i * 5 >= 60); // цель, к которой ещё не обращались
                const limited = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 1 }, params: { targetUserId: String(fresh) } });
                assert.strictEqual(limited.statusCode, 429);
                assert.ok(/шифрования/.test(limited.body.message), limited.body.message);
                // Лимит вызывающего не задевает других пользователей.
                const other = await call(app, 'get', '/api/keys/bundle/:targetUserId', { session: { userId: 2 }, params: { targetUserId: '1' } });
                assert.strictEqual(other.statusCode, 200);
            });
        } finally {
            restoreFetch();
        }
    });

    await test('identities: unshared ids are silently dropped, self allowed, response wrapped', async () => {
        const { app, db } = makeProxyFixture();
        const calls = installFakeFetch(() => ({
            body: {
                identities: [
                    { user_id: 2, identity_signing_key: 's2', identity_dh_key: 'd2' },
                    { user_id: 1, identity_signing_key: 's1', identity_dh_key: 'd1' },
                    // key-server вернул лишнее — прокси всё равно не должен это отдать
                    { user_id: 4, identity_signing_key: 's4', identity_dh_key: 'd4' },
                ],
            },
        }));
        try {
            const res = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids: '4, 2,1,2,3,999' } });
            assert.strictEqual(res.statusCode, 200);
            assert.strictEqual(res.body.success, true);
            assert.deepStrictEqual(res.body.identities.map(i => i.user_id), [2, 1]);
            assert.strictEqual(calls.length, 1);
            assert.strictEqual(calls[0].url, 'http://key-server.test/internal/v1/keys/identities?ids=2,1,3');
            assert.strictEqual(calls[0].headers['X-User-Id'], '1');
            // Один запрос к БД на весь список, а не по запросу на id.
            const accessQueries = db._queries.filter(q => q.query.includes('room_participants a'));
            assert.strictEqual(accessQueries.length, 1);
            assert.ok(accessQueries[0].query.includes('= ANY($2::int[])'));
            assert.deepStrictEqual(accessQueries[0].params, [1, [4, 2, 3, 999]]);
        } finally {
            restoreFetch();
        }
    });

    await test('identities: nothing visible -> empty list without calling the key-server', async () => {
        const { app } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: { identities: [] } }));
        try {
            const res = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids: '4,999' } });
            assert.strictEqual(res.statusCode, 200);
            assert.deepStrictEqual(res.body, { success: true, identities: [] });
            assert.strictEqual(calls.length, 0);
        } finally {
            restoreFetch();
        }
    });

    await test('identities: only self requested -> no DB round trip needed, key-server asked for self', async () => {
        const { app, db } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: { identities: [{ user_id: 1, identity_signing_key: 's', identity_dh_key: 'd' }] } }));
        try {
            const res = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids: '1' } });
            assert.deepStrictEqual(res.body.identities.map(i => i.user_id), [1]);
            assert.strictEqual(calls[0].url, 'http://key-server.test/internal/v1/keys/identities?ids=1');
            assert.strictEqual(db._queries.length, 0);
        } finally {
            restoreFetch();
        }
    });

    await test('identities: malformed or oversized id lists are rejected with 400', async () => {
        const { app } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: { identities: [] } }));
        try {
            const tooMany = Array.from({ length: 201 }, (_, i) => i + 1).join(',');
            for (const ids of [undefined, '', ',', '1,,2', 'a,b', '1;2', '-3', '0', '2147483648', ['1', '2'], tooMany]) {
                const res = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids } });
                assert.strictEqual(res.statusCode, 400, 'ids=' + String(JSON.stringify(ids)).slice(0, 40));
                assert.strictEqual(res.body.success, false);
            }
            assert.strictEqual(calls.length, 0);
            // Ровно 200 разных id (плюс повторы) — допустимо.
            const exactly200 = Array.from({ length: 200 }, (_, i) => i + 1).join(',') + ',1,2,3';
            const ok = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids: exactly200 } });
            assert.strictEqual(ok.statusCode, 200);
            assert.strictEqual(ok.body.success, true);
        } finally {
            restoreFetch();
        }
    });

    await test('identities: key-server error status is passed through; malformed body -> 502', async () => {
        const { app } = makeProxyFixture();
        installFakeFetch(() => ({ status: 400, body: { success: false, message: 'bad ids' } }));
        try {
            const res = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids: '2' } });
            assert.strictEqual(res.statusCode, 400);
            assert.strictEqual(res.body.message, 'bad ids');
        } finally {
            restoreFetch();
        }
        installFakeFetch(() => ({ status: 200, rawText: 'not json' }));
        try {
            const res = await call(app, 'get', '/api/keys/identities', { session: { userId: 1 }, query: { ids: '2' } });
            assert.strictEqual(res.statusCode, 502);
            assert.strictEqual(res.body.success, false);
        } finally {
            restoreFetch();
        }
    });

    await test('pq-prekey: PUT is proxied with the JSON body to the internal endpoint', async () => {
        const { app } = makeProxyFixture();
        const calls = installFakeFetch(() => ({ body: { success: true } }));
        try {
            const body = { key_id: 42, public_key: 'cHVi', signature: 'c2ln' };
            const res = await call(app, 'put', '/api/keys/pq-prekey', { session: { userId: 7 }, body });
            assert.strictEqual(res.statusCode, 200);
            assert.deepStrictEqual(res.body, { success: true });
            assert.strictEqual(calls.length, 1);
            assert.strictEqual(calls[0].url, 'http://key-server.test/internal/v1/keys/pq-prekey');
            assert.strictEqual(calls[0].method, 'PUT');
            assert.strictEqual(calls[0].headers['Content-Type'], 'application/json');
            assert.strictEqual(calls[0].headers['X-User-Id'], '7');
            assert.deepStrictEqual(JSON.parse(calls[0].body), body);
        } finally {
            restoreFetch();
        }
    });

    await test('deleteKeysForUser: best effort DELETE, false without secret', async () => {
        let { deleteKeysForUser } = loadProxy({ secret: null });
        const calls = installFakeFetch(() => ({ status: 200, body: { success: true } }));
        try {
            assert.strictEqual(await deleteKeysForUser(9), false);
            assert.strictEqual(calls.length, 0);
            ({ deleteKeysForUser } = loadProxy());
            assert.strictEqual(await deleteKeysForUser(9), true);
            assert.strictEqual(calls[0].method, 'DELETE');
            assert.strictEqual(calls[0].url, 'http://key-server.test/internal/v1/keys');
            assert.strictEqual(calls[0].headers['X-User-Id'], '9');
        } finally {
            restoreFetch();
        }
    });

    // ---------------- lib/e2ee-groups.js ----------------

    function makeGroupsFixture() {
        const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');
        const app = makeFakeApp();
        const db = makeFakeDb();
        const io = makeFakeIo();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io });
        return { app, db, io };
    }

    await test('e2ee-groups.js: require + registration does not throw', async () => {
        const { app } = makeGroupsFixture();
        assert.ok(app._find('get', '/api/chats/:chatId/participants'));
        assert.ok(app._find('post', '/api/keys/key-shares'));
        assert.ok(app._find('get', '/api/keys/key-shares/:chatId'));
    });

    await test('GET participants: returns room members for a chat the caller owns', async () => {
        const { app, db } = makeGroupsFixture();
        db._chats.push({ id: 11, user_id: 1, room_id: 100 }, { id: 22, user_id: 2, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });

        const res = await call(app, 'get', '/api/chats/:chatId/participants', { session: { userId: 1 }, params: { chatId: '11' } });
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.roomId, 100);
        assert.deepStrictEqual(res.body.participants.map(p => p.id).sort(), [1, 2]);
    });

    await test('GET participants: a chat without a room (bot/solo) returns an empty list, not an error', async () => {
        const { app, db } = makeGroupsFixture();
        db._chats.push({ id: 55, user_id: 1, room_id: null });

        const res = await call(app, 'get', '/api/chats/:chatId/participants', { session: { userId: 1 }, params: { chatId: '55' } });
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.roomId, null);
        assert.deepStrictEqual(res.body.participants, []);
    });

    await test('GET participants: a chat belonging to someone else is not found', async () => {
        const { app, db } = makeGroupsFixture();
        db._chats.push({ id: 11, user_id: 1, room_id: 100 });

        const res = await call(app, 'get', '/api/chats/:chatId/participants', { session: { userId: 999 }, params: { chatId: '11' } });
        assert.strictEqual(res.body.success, false);
    });

    await test('POST key-shares: rejects a recipient who is not a room member', async () => {
        const { app, db, io } = makeGroupsFixture();
        db._chats.push({ id: 11, user_id: 1, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });

        const res = await call(app, 'post', '/api/keys/key-shares', {
            session: { userId: 1 },
            body: { chatId: 11, shares: [{ recipientUserId: 999, ciphertext: 'abc' }] },
        });
        assert.strictEqual(res.body.success, false);
        assert.strictEqual(db._keyShares.length, 0);
        assert.strictEqual(io._emitted.length, 0);
    });

    await test('POST key-shares -> GET key-shares: fetch-and-delete round trip, and pushes a socket notice', async () => {
        const { app, db, io } = makeGroupsFixture();
        db._chats.push({ id: 11, user_id: 1, room_id: 100 }, { id: 22, user_id: 2, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });

        const post1 = await call(app, 'post', '/api/keys/key-shares', { session: { userId: 1 }, body: { chatId: 11, shares: [{ recipientUserId: 2, ciphertext: 'wrapped-sender-key' }] } });
        assert.strictEqual(post1.body.success, true);
        assert.strictEqual(io._emitted.length, 1);
        assert.strictEqual(io._emitted[0].room, 'user:2');
        assert.strictEqual(io._emitted[0].event, 'e2eeKeyShare');

        const get1 = await call(app, 'get', '/api/keys/key-shares/:chatId', { session: { userId: 2 }, params: { chatId: '22' } });
        assert.strictEqual(get1.body.success, true);
        assert.strictEqual(get1.body.shares.length, 1);
        assert.strictEqual(get1.body.shares[0].senderId, 1);
        assert.strictEqual(get1.body.shares[0].ciphertext, 'wrapped-sender-key');

        // Второй вызов подряд ничего не должен вернуть — уже забрано и удалено.
        const get2 = await call(app, 'get', '/api/keys/key-shares/:chatId', { session: { userId: 2 }, params: { chatId: '22' } });
        assert.strictEqual(get2.body.shares.length, 0);
        assert.strictEqual(db._keyShares.length, 0);
    });

    await test('POST key-shares: a post-quantum x3dh-init envelope fits, anything over 8192 chars does not', async () => {
        const { app, db } = makeGroupsFixture();
        db._chats.push({ id: 11, user_id: 1, room_id: 100 });
        db._participants.push({ room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' });
        const b64 = n => Buffer.alloc(n, 7).toString('base64');
        // Реалистичный крупный конверт: ML-KEM-768 ciphertext + ключи + завёрнутый SKDM.
        const envelope = JSON.stringify({
            v: 2, type: 'x3dh-init', iv: b64(12), ct: b64(330),
            senderIdentityDhPub: b64(32), senderIdentitySigningPub: b64(32), senderEphemeralPub: b64(32),
            usedSignedPrekeyId: 9007199254740991, usedOneTimePrekeyId: 9007199254740991, usedPqPrekeyId: 9007199254740991,
            pqCiphertext: b64(1088), counter: 9007199254740991, signature: b64(64),
        });
        assert.ok(envelope.length > 2000 && envelope.length < 4096, 'envelope ' + envelope.length);
        const ok = await call(app, 'post', '/api/keys/key-shares', { session: { userId: 1 }, body: { chatId: 11, shares: [{ recipientUserId: 2, ciphertext: envelope }] } });
        assert.strictEqual(ok.body.success, true);
        const atLimit = await call(app, 'post', '/api/keys/key-shares', { session: { userId: 1 }, body: { chatId: 11, shares: [{ recipientUserId: 2, ciphertext: 'x'.repeat(8192) }] } });
        assert.strictEqual(atLimit.body.success, true);
        const tooBig = await call(app, 'post', '/api/keys/key-shares', { session: { userId: 1 }, body: { chatId: 11, shares: [{ recipientUserId: 2, ciphertext: 'x'.repeat(8193) }] } });
        assert.strictEqual(tooBig.body.success, false);
        assert.strictEqual(db._keyShares.length, 2);
    });

    await test('POST key-shares: at most 1000 undelivered shares per recipient per room', async () => {
        const { app, db, io } = makeGroupsFixture();
        db._chats.push({ id: 11, user_id: 1, room_id: 100 }, { id: 22, user_id: 2, room_id: 100 }, { id: 33, user_id: 1, room_id: 200 });
        db._participants.push(
            { room_id: 100, user_id: 1, username: 'alice' }, { room_id: 100, user_id: 2, username: 'bob' },
            { room_id: 100, user_id: 3, username: 'carol' },
            { room_id: 200, user_id: 1, username: 'alice' }, { room_id: 200, user_id: 2, username: 'bob' },
        );
        for (let i = 0; i < 998; i++) {
            db._keyShares.push({ id: 10_000 + i, room_id: 100, sender_id: 3, recipient_id: 2, ciphertext: 'junk' });
        }
        const post = (chatId, shares) => call(app, 'post', '/api/keys/key-shares', { session: { userId: 1 }, body: { chatId, shares } });

        // 998 + 2 = 1000 — ещё можно.
        const fill = await post(11, [{ recipientUserId: 2, ciphertext: 'a' }, { recipientUserId: 2, ciphertext: 'b' }]);
        assert.strictEqual(fill.body.success, true);

        // 1001-я запись для bob отклоняется целиком — и carol в том же запросе
        // тоже ничего не получает (без частичной доставки).
        const emittedBefore = io._emitted.length;
        const over = await post(11, [{ recipientUserId: 3, ciphertext: 'c' }, { recipientUserId: 2, ciphertext: 'd' }]);
        assert.strictEqual(over.body.success, false);
        assert.ok(/недоставленных/.test(over.body.message), over.body.message);
        assert.strictEqual(db._keyShares.filter(s => s.room_id === 100).length, 1000);
        assert.strictEqual(io._emitted.length, emittedBefore);

        // Лимит — на комнату: в другой комнате bob получает key-share как обычно.
        const otherRoom = await post(33, [{ recipientUserId: 2, ciphertext: 'e' }]);
        assert.strictEqual(otherRoom.body.success, true);

        // Когда bob забрал очередь, отправлять ему снова можно.
        const drained = await call(app, 'get', '/api/keys/key-shares/:chatId', { session: { userId: 2 }, params: { chatId: '22' } });
        assert.strictEqual(drained.body.shares.length, 1000);
        const again = await post(11, [{ recipientUserId: 2, ciphertext: 'f' }]);
        assert.strictEqual(again.body.success, true);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
