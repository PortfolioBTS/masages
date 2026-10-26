'use strict';
// Маршруты журнала ключей (lib/kt-routes.js) против поддельного приложения и сервиса:
// 503 kt-disabled без ключа, разбор параметров, права доступа к доказательствам
// (сам, общая комната, одобряющий для заявителя), лимиты, ошибка сервиса — 500 без подробностей.
// Запросы к настоящей базе проверяют сквозные тесты (test/e2e/key-transparency.e2e.test.js).
// Запуск: node test/kt-routes.test.js

const assert = require('assert');
const { registerKtRoutes, intParam } = require('../lib/kt-routes');

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

function makeApp() {
    const routes = new Map();
    return { get: (path, ...handlers) => routes.set(path, handlers), routes };
}

async function call(app, path, { session = { userId: 5 }, query = {} } = {}) {
    const res = {
        statusCode: 200, body: null, headers: {}, headersSent: false,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; this.headersSent = true; return this; },
        set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    };
    const req = { session, query };
    for (const handler of app.routes.get(path)) {
        if (res.body !== null) break;
        await handler(req, res, () => {});
    }
    return res;
}

const buf = (n, len = 32) => Buffer.alloc(len, n);

function makeKt(overrides = {}) {
    const calls = [];
    const kt = {
        enabled: true,
        calls,
        async getHead() {
            return {
                pub: buf(1), gen: 2, epoch: 100, head: buf(2), sig: buf(3, 64), genStart: 90, prevFinalHead: buf(4),
                keychange: [{ oldPub: buf(5), newPub: buf(6), gen: 2, epoch: 95, sig: buf(7, 64) }],
            };
        },
        async getRoots(gen, from, limit) {
            calls.push(['roots', gen, from, limit]);
            if (gen === 99) return null;
            return { gen, genStart: 90, prevFinalHead: buf(4), from: 90, roots: [buf(8), buf(9)], last: { epoch: 91, head: buf(2), sig: buf(3, 64) } };
        },
        async getProof(userId, gen, epoch) {
            calls.push(['proof', userId, gen, epoch]);
            if (epoch === 404) return null;
            if (epoch === 500) throw new Error('внутренняя подробность');
            return { entries: [buf(10)], bitmap: buf(0, 16), siblings: [buf(11)] };
        },
        async getSelfProofs(userId, gen, from, limit) {
            calls.push(['self', userId, gen, from, limit]);
            return { proofs: [{ epoch: 91, entries: [], bitmap: buf(0, 16), siblings: [] }], next: null };
        },
        ...overrides,
    };
    return kt;
}

// dbGet: общая комната пользователей 5 и 6; заявка пользователя 7 в комнате, где состоит 5.
function makeDb() {
    return async (sql, params) => {
        if (sql.includes('FROM join_requests')) return params[0] === 7 && params[1] === 5 ? { '?column?': 1 } : null;
        if (sql.includes('FROM room_participants')) return (params[0] === 5 && params[1] === 6) ? { '?column?': 1 } : null;
        throw new Error('неожиданный запрос ' + sql);
    };
}

async function main() {
    await test('intParam: только цифры, пределы, undefined — параметра нет', () => {
        assert.strictEqual(intParam(undefined), undefined);
        assert.strictEqual(intParam('12'), 12);
        assert.strictEqual(intParam('0', { min: 1 }), null);
        assert.strictEqual(intParam('-1'), null);
        assert.strictEqual(intParam('1e3'), null);
        assert.strictEqual(intParam(['1']), null);
        assert.strictEqual(intParam('99999999999'), null);
        assert.strictEqual(intParam('2147483648'), null);
    });

    await test('регистрация: четыре маршрута, обязательны dbGet и сервис', () => {
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt: makeKt() });
        assert.deepStrictEqual([...app.routes.keys()].sort(), ['/api/kt/head', '/api/kt/proof', '/api/kt/roots', '/api/kt/self']);
        assert.throws(() => registerKtRoutes(makeApp(), {}), TypeError);
    });

    await test('без сессии — 401; без ключа журнала — 503 kt-disabled, а head — 200 { enabled:false }', async () => {
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt: makeKt({ enabled: false }) });
        for (const path of app.routes.keys()) {
            assert.strictEqual((await call(app, path, { session: null })).statusCode, 401, path);
            const res = await call(app, path, { query: { user: '6', gen: '1', epoch: '1' } });
            assert.strictEqual(res.body.code, 'kt-disabled', path);
            if (path === '/api/kt/head') {
                assert.strictEqual(res.statusCode === undefined ? 200 : res.statusCode, 200, path);
                assert.strictEqual(res.body.enabled, false);
            } else {
                assert.strictEqual(res.statusCode, 503, path);
            }
        }
    });

    await test('head: base64 и цепочка заявлений о смене; журнал без закрытых эпох — 503 kt-not-ready', async () => {
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt: makeKt() });
        const res = await call(app, '/api/kt/head');
        assert.strictEqual(res.statusCode, 200);
        assert.strictEqual(res.body.pub, buf(1).toString('base64'));
        assert.deepStrictEqual([res.body.gen, res.body.epoch, res.body.genStart], [2, 100, 90]);
        assert.strictEqual(res.body.prevFinalHead, buf(4).toString('base64'));
        assert.deepStrictEqual(res.body.keychange, [{ oldPub: buf(5).toString('base64'), newPub: buf(6).toString('base64'), gen: 2, epoch: 95, sig: buf(7, 64).toString('base64') }]);
        const empty = makeApp();
        registerKtRoutes(empty, { dbGet: makeDb(), kt: makeKt({ getHead: async () => null }) });
        const notReady = await call(empty, '/api/kt/head');
        assert.strictEqual(notReady.statusCode, 503);
        assert.strictEqual(notReady.body.code, 'kt-not-ready');
    });

    await test('roots: параметры, по умолчанию from = 0 и limit = 1000, неизвестное поколение — 404', async () => {
        const kt = makeKt();
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt });
        for (const query of [{}, { gen: '0' }, { gen: 'x' }, { gen: '1', from: '-1' }, { gen: '1', limit: '0' }, { gen: ['1', '2'] }]) {
            assert.strictEqual((await call(app, '/api/kt/roots', { query })).statusCode, 400, JSON.stringify(query));
        }
        const ok = await call(app, '/api/kt/roots', { query: { gen: '2' } });
        assert.strictEqual(ok.statusCode, 200);
        assert.deepStrictEqual(kt.calls[0], ['roots', 2, 0, 1000]);
        assert.deepStrictEqual(ok.body.roots, [buf(8).toString('base64'), buf(9).toString('base64')]);
        assert.deepStrictEqual(ok.body.last, { epoch: 91, head: buf(2).toString('base64'), sig: buf(3, 64).toString('base64') });
        const missing = await call(app, '/api/kt/roots', { query: { gen: '99' } });
        assert.strictEqual(missing.statusCode, 404);
        assert.strictEqual(missing.body.code, 'kt-not-found');
    });

    await test('proof: сам, участник общей комнаты и одобряющий для заявителя — да; остальные — 403 без разбора причин', async () => {
        const kt = makeKt();
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt, joinRequestLiveSql: () => 'created_at > NOW()' });
        const query = (user) => ({ user: String(user), gen: '1', epoch: '10' });
        assert.strictEqual((await call(app, '/api/kt/proof', { query: query(5) })).statusCode, 200, 'сам');
        assert.strictEqual((await call(app, '/api/kt/proof', { query: query(6) })).statusCode, 200, 'общая комната');
        assert.strictEqual((await call(app, '/api/kt/proof', { query: query(7) })).statusCode, 200, 'заявитель с открытой заявкой');
        const stranger = await call(app, '/api/kt/proof', { query: query(8) });
        assert.strictEqual(stranger.statusCode, 403);
        assert.strictEqual(stranger.body.code, 'forbidden');
        const nobody = await call(app, '/api/kt/proof', { query: query(123456) });
        assert.deepStrictEqual(nobody.body, stranger.body, 'ответ не различает «нет такого» и «нет доступа»');
        assert.strictEqual(kt.calls.filter(c => c[0] === 'proof').length, 3, 'чужие доказательства не строятся');
        // Без условия «заявка жива» одобряющего нет вовсе.
        const noApprover = makeApp();
        registerKtRoutes(noApprover, { dbGet: makeDb(), kt });
        assert.strictEqual((await call(noApprover, '/api/kt/proof', { query: query(7) })).statusCode, 403);
    });

    await test('proof: тело в base64, эпоха не найдена — 404, ошибка сервиса — 500 без подробностей', async () => {
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt: makeKt() });
        const res = await call(app, '/api/kt/proof', { query: { user: '5', gen: '1', epoch: '10' } });
        assert.deepStrictEqual(res.body, { success: true, entries: [buf(10).toString('base64')], bitmap: buf(0, 16).toString('base64'), siblings: [buf(11).toString('base64')] });
        assert.strictEqual((await call(app, '/api/kt/proof', { query: { user: '5', gen: '1', epoch: '404' } })).statusCode, 404);
        const broken = await call(app, '/api/kt/proof', { query: { user: '5', gen: '1', epoch: '500' } });
        assert.strictEqual(broken.statusCode, 500);
        assert.ok(!JSON.stringify(broken.body).includes('внутренняя подробность'));
        for (const query of [{}, { user: '0', gen: '1', epoch: '1' }, { user: '5', gen: 'a', epoch: '1' }, { user: '5', gen: '1' }]) {
            assert.strictEqual((await call(app, '/api/kt/proof', { query })).statusCode, 400, JSON.stringify(query));
        }
    });

    await test('self: только своя метка (id берётся из сессии), по умолчанию from = 0 и limit = 200', async () => {
        const kt = makeKt();
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt });
        const res = await call(app, '/api/kt/self', { session: { userId: 9 }, query: { gen: '3', user: '5' } });
        assert.strictEqual(res.statusCode, 200);
        assert.deepStrictEqual(kt.calls[0], ['self', 9, 3, 0, 200]);
        assert.deepStrictEqual(res.body.proofs[0], { epoch: 91, entries: [], bitmap: buf(0, 16).toString('base64'), siblings: [] });
        assert.strictEqual(res.body.next, null);
        assert.strictEqual((await call(app, '/api/kt/self', { query: { gen: '0' } })).statusCode, 400);
    });

    await test('лимиты в памяти: пара «кто — чей» ограничена 60 в час, ответ 429 с Retry-After', async () => {
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt: makeKt() });
        const query = { user: '5', gen: '1', epoch: '10' };
        for (let i = 0; i < 60; i++) assert.strictEqual((await call(app, '/api/kt/proof', { query })).statusCode, 200, 'запрос ' + i);
        const res = await call(app, '/api/kt/proof', { query });
        assert.strictEqual(res.statusCode, 429);
        assert.strictEqual(res.body.code, 'rate-limited');
        assert.ok(Number(res.headers['retry-after']) > 0);
        // Другой пользователь не затронут.
        assert.strictEqual((await call(app, '/api/kt/proof', { session: { userId: 6 }, query: { user: '6', gen: '1', epoch: '10' } })).statusCode, 200);
    });

    await test('лимитер в базе: исчерпанный слот — 429, сбой хранилища — 503 busy (лимит закрывается)', async () => {
        const rules = [];
        const limiter = {
            async tryConsume(lockKey, r) {
                rules.push([lockKey, r]);
                if (rules.length === 2) return { ok: false, waitMs: r.map(() => 90000) };
                if (rules.length === 3) throw new Error('хранилище лимита недоступно');
                return { ok: true, waitMs: r.map(() => 0) };
            },
        };
        const app = makeApp();
        registerKtRoutes(app, { dbGet: makeDb(), kt: makeKt(), limiter });
        const ok = await call(app, '/api/kt/head');
        assert.strictEqual(ok.statusCode, 200);
        assert.strictEqual(rules[0][0], '5');
        assert.deepStrictEqual(rules[0][1].map(r => r.key), ['log:5']);
        const refused = await call(app, '/api/kt/head');
        assert.strictEqual(refused.statusCode, 429);
        assert.strictEqual(refused.headers['retry-after'], '90');
        const busy = await call(app, '/api/kt/head');
        assert.strictEqual(busy.statusCode, 503);
        assert.strictEqual(busy.body.code, 'busy');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
