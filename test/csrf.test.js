'use strict';
// Тесты lib/csrf.js (8.1): токен привязан к сессии. Express на loopback,
// сессия подменена простым хранилищем; куки ведёт тот же CookieJar, что и в
// сквозных тестах. Настоящий сервер и порядок middleware проверяют сквозные
// тесты (test/e2e/security-wave2.e2e.test.js).
// Запуск: node test/csrf.test.js

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const { CookieJar, parseSetCookie } = require('./e2e/helpers/cookies');
const { createCsrf, TOKEN_COOKIE, PRE_COOKIE, DENIED_BODY } = require('../lib/csrf');

const SECRET = 'csrf-test-secret-csrf-test-secret-0123456789';

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

// Приложение: cookieParser → «сессия» (кука sid → объект) → CSRF → json →
// маршруты вход / выход / эхо.
function makeApp({ secret = SECRET, onRejected } = {}) {
    const csrf = createCsrf({ secret, onRejected });
    const sessions = new Map();
    const app = express();
    app.set('trust proxy', 1);
    app.use(cookieParser());
    app.use((req, res, next) => {
        const sid = req.cookies.sid;
        if (sid && sessions.has(sid)) {
            req.sessionID = sid;
            req.session = sessions.get(sid);
        } else {
            req.sessionID = crypto.randomBytes(8).toString('hex'); // как у ещё не сохранённой сессии
            req.session = {};
        }
        next();
    });
    app.use(csrf.middleware);
    app.use(express.json());
    app.get('/ping', (req, res) => res.json({ ok: true }));
    app.post('/echo', (req, res) => res.json({ ok: true }));
    app.post('/socket.io/x', (req, res) => res.json({ ok: true }));
    app.post('/login', (req, res) => {
        // Как startUserSession: новая сессия, затем перевыпуск токена.
        const sid = crypto.randomBytes(8).toString('hex');
        const session = { userId: req.body.userId };
        sessions.set(sid, session);
        res.cookie('sid', sid);
        req.sessionID = sid;
        req.session = session;
        csrf.issue(req, res);
        res.json({ ok: true });
    });
    app.post('/logout', (req, res) => {
        sessions.delete(req.sessionID);
        delete req.session;
        res.clearCookie('sid');
        csrf.issue(req, res, { freshPre: true });
        res.json({ ok: true });
    });
    return { app, csrf, sessions };
}

async function withServer(app, fn) {
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
        server.closeAllConnections();
    }
}

// Мини-«браузер»: куки + запросы; header: false — без X-CSRF-Token, строка —
// явный заголовок, по умолчанию — токен из своей куки.
class Browser {
    constructor(base, { secure = false } = {}) {
        this.base = base;
        this.jar = new CookieJar({ secureContext: secure });
        this.secure = secure;
    }
    async request(method, path, { json, header, headers = {} } = {}) {
        const all = { ...headers };
        if (this.secure) all['X-Forwarded-Proto'] = 'https';
        const cookie = this.jar.header(path);
        if (cookie) all.Cookie = cookie;
        if (header === undefined) {
            const own = this.jar.get(TOKEN_COOKIE);
            if (own && method !== 'GET') all['X-CSRF-Token'] = own;
        } else if (header !== false) {
            all['X-CSRF-Token'] = header;
        }
        if (json !== undefined) all['Content-Type'] = 'application/json';
        const response = await fetch(this.base + path, { method, headers: all, body: json === undefined ? undefined : JSON.stringify(json) });
        this.jar.setFromResponse(response, path);
        const text = await response.text();
        let body = text;
        try { body = JSON.parse(text); } catch { /* не JSON */ }
        return { status: response.status, body, setCookies: response.headers.getSetCookie() };
    }
    get(path, opts) { return this.request('GET', path, opts); }
    post(path, json = {}, opts = {}) { return this.request('POST', path, { json, ...opts }); }
    cookie(name) { return this.jar.get(name); }
}

const setCookieNamed = (res, name) => res.setCookies.filter(line => line.startsWith(`${name}=`));

async function main() {
    console.log('CSRF tests\n');

    // --------------------------------------------------------------- токены
    await test('токен: форма rand.HMAC, подходит только своей привязке и своему секрету', () => {
        const a = createCsrf({ secret: SECRET });
        const b = createCsrf({ secret: SECRET + 'x' });
        const token = a.createToken('sid:abc');
        assert.match(token, /^[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/);
        assert.strictEqual(a.verifyToken(token, 'sid:abc'), true);
        assert.strictEqual(a.verifyToken(token, 'sid:abd'), false, 'другая сессия');
        assert.strictEqual(a.verifyToken(token, 'pre:abc'), false, 'другой вид привязки');
        assert.strictEqual(b.verifyToken(token, 'sid:abc'), false, 'другой SESSION_SECRET');
        assert.notStrictEqual(a.createToken('sid:abc'), token, 'rand каждый раз новый');
        // Одинаковая привязка + одинаковый rand дают одинаковую подпись (HMAC детерминирован).
        const [rand, mac] = token.split('.');
        assert.strictEqual(mac, crypto.createHmac('sha256', require('../lib/derive-key').deriveKey(SECRET, 'nyxo-csrf-v1'))
            .update(`sid:abc|${rand}`).digest('base64url'));
    });

    await test('токен: искажённые значения отвергаются без исключений', () => {
        const csrf = createCsrf({ secret: SECRET });
        const token = csrf.createToken('sid:abc');
        const [rand, mac] = token.split('.');
        const flip = (text) => (text[0] === 'A' ? 'B' : 'A') + text.slice(1);
        const bad = [
            undefined, null, 42, {}, [], '', '.', token + 'x', token.slice(1), `${flip(rand)}.${mac}`, `${rand}.${flip(mac)}`,
            `${rand}!${mac}`, `${rand}.${mac.slice(0, -1)}!`, `${rand}.${mac}.${mac}`, 'x'.repeat(200), `${rand}${mac}`, token.replace('.', '='),
        ];
        for (const value of bad) assert.strictEqual(csrf.verifyToken(value, 'sid:abc'), false, JSON.stringify(value));
        assert.strictEqual(csrf.verifyToken(token, undefined), false);
        assert.throws(() => createCsrf({ secret: '' }), TypeError);
    });

    // ---------------------------------------------------------- до входа (pre)
    await test('до входа: GET выдаёт nyxo_pre (httpOnly, Strict, сессионная) и csrf_token (Lax, читаемый, 24 ч)', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            const res = await b.get('/ping');
            assert.strictEqual(res.status, 200);
            const pre = parseSetCookie(setCookieNamed(res, PRE_COOKIE)[0], '/', Date.now());
            const token = parseSetCookie(setCookieNamed(res, TOKEN_COOKIE)[0], '/', Date.now());
            assert.strictEqual(pre.httpOnly, true);
            assert.strictEqual(pre.sameSite, 'strict');
            assert.strictEqual(pre.expiresAt, null, 'сессионная кука: без Max-Age и Expires');
            assert.match(pre.value, /^[A-Za-z0-9_-]{22}$/);
            assert.strictEqual(token.httpOnly, false, 'клиент читает куку из JS');
            assert.strictEqual(token.sameSite, 'lax');
            assert.ok(token.expiresAt - Date.now() > 23 * 3600 * 1000);
            assert.strictEqual(pre.secure, false, 'по http кука без Secure');
        });
    });

    await test('до входа: Secure выставляется по фактическому протоколу (X-Forwarded-Proto)', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const res = await new Browser(base, { secure: true }).get('/ping');
            assert.ok(setCookieNamed(res, PRE_COOKIE)[0].includes('Secure'));
            assert.ok(setCookieNamed(res, TOKEN_COOKIE)[0].includes('Secure'));
        });
    });

    await test('до входа: POST с токеном из куки проходит; повторный GET куку не пересоздаёт', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            const token = b.cookie(TOKEN_COOKIE);
            const again = await b.get('/ping');
            assert.deepStrictEqual(again.setCookies, [], 'валидный токен остаётся на месте');
            const res = await b.post('/echo');
            assert.strictEqual(res.status, 200);
            assert.strictEqual(b.cookie(TOKEN_COOKIE), token);
        });
    });

    await test('первый же POST без кук — 403, но куки для повтора уже выданы', async () => {
        const counted = [];
        const { app } = makeApp({ onRejected: () => counted.push(1) });
        await withServer(app, async (base) => {
            const b = new Browser(base);
            const first = await b.post('/echo', {}, { header: false });
            assert.strictEqual(first.status, 403);
            assert.deepStrictEqual(first.body, DENIED_BODY);
            assert.ok(b.cookie(TOKEN_COOKIE) && b.cookie(PRE_COOKIE));
            assert.strictEqual((await b.post('/echo')).status, 200);
            assert.strictEqual(counted.length, 1);
        });
    });

    await test('403: нет заголовка, заголовок не равен куке, подпись неверна, кука подсажена без nyxo_pre', async () => {
        const { app, csrf } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            const token = b.cookie(TOKEN_COOKIE);
            assert.strictEqual((await b.post('/echo', {}, { header: false })).status, 403);
            // Выдача после отказа заменила токен; снова берём действующий.
            const current = b.cookie(TOKEN_COOKIE);
            assert.strictEqual((await b.post('/echo', {}, { header: token + 'x' })).status, 403);
            assert.strictEqual((await b.post('/echo', {}, { header: crypto.randomBytes(32).toString('hex') })).status, 403);
            assert.strictEqual((await b.post('/echo')).status, 200, 'действующий токен снова принимается');

            // Кука и заголовок совпадают, но токен «чужой»: двойной отправки мало.
            const forged = csrf.createToken('pre:' + 'A'.repeat(22));
            const attacker = new Browser(base);
            await attacker.get('/ping');
            attacker.jar.set(TOKEN_COOKIE, forged);
            const res = await attacker.post('/echo', {}, { header: forged });
            assert.strictEqual(res.status, 403);
            assert.ok(current);
        });
    });

    await test('искажённая кука nyxo_pre заменяется, старый токен перестаёт подходить', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            const oldToken = b.cookie(TOKEN_COOKIE);
            b.jar.set(PRE_COOKIE, 'not valid!', { httpOnly: true });
            const res = await b.post('/echo', {}, { header: oldToken });
            assert.strictEqual(res.status, 403);
            assert.match(b.cookie(PRE_COOKIE), /^[A-Za-z0-9_-]{22}$/);
            assert.strictEqual((await b.post('/echo')).status, 200);
        });
    });

    await test('безопасные методы и /socket.io токеном не проверяются, но куку выдают', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            assert.strictEqual((await b.request('GET', '/ping', { header: 'garbage' })).status, 200);
            assert.strictEqual((await b.request('HEAD', '/ping')).status, 200);
            assert.strictEqual((await b.request('OPTIONS', '/ping')).status < 500, true);
            assert.ok(b.cookie(TOKEN_COOKIE));
            const sock = new Browser(base);
            assert.strictEqual((await sock.post('/socket.io/x', {}, { header: false })).status, 200);
            assert.strictEqual(sock.cookie(TOKEN_COOKIE), undefined, 'для сокета куки не выдаются');
        });
    });

    // --------------------------------------------------------------- после входа
    await test('вход: токен «до входа» отвергается, новый токен выдан в ответе входа и привязан к сессии', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            const preToken = b.cookie(TOKEN_COOKIE);
            const login = await b.post('/login', { userId: 7 });
            assert.strictEqual(login.status, 200, 'сам вход принят с токеном «до входа»');
            assert.strictEqual(setCookieNamed(login, TOKEN_COOKIE).length, 1, 'ровно одна Set-Cookie csrf_token');
            const sessionToken = b.cookie(TOKEN_COOKIE);
            assert.notStrictEqual(sessionToken, preToken);

            // Токен «до входа» — и в куке, и в заголовке — после входа не годится.
            b.jar.set(TOKEN_COOKIE, preToken);
            const stale = await b.post('/echo', {}, { header: preToken });
            assert.strictEqual(stale.status, 403);
            // Отказ выдал новую куку под текущую сессию; клиент повторяет и проходит.
            assert.notStrictEqual(b.cookie(TOKEN_COOKIE), preToken);
            assert.strictEqual((await b.post('/echo')).status, 200);
        });
    });

    await test('токен сессии A не проходит у сессии B (даже вместе со своей кукой)', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const a = new Browser(base);
            const b = new Browser(base);
            await a.get('/ping');
            await b.get('/ping');
            await a.post('/login', { userId: 1 });
            await b.post('/login', { userId: 2 });
            assert.notStrictEqual(a.cookie(TOKEN_COOKIE), b.cookie(TOKEN_COOKIE));
            const tokenA = a.cookie(TOKEN_COOKIE);
            b.jar.set(TOKEN_COOKIE, tokenA);
            assert.strictEqual((await b.post('/echo', {}, { header: tokenA })).status, 403);
            assert.strictEqual((await a.post('/echo')).status, 200, 'у A всё по-прежнему работает');
        });
    });

    await test('новая сессия (смена срока): прежний токен отвергается', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            await b.post('/login', { userId: 3 });
            const first = b.cookie(TOKEN_COOKIE);
            assert.strictEqual((await b.post('/echo')).status, 200);
            await b.post('/login', { userId: 3 }); // regenerate: новый sid
            const second = b.cookie(TOKEN_COOKIE);
            assert.notStrictEqual(second, first);
            b.jar.set(TOKEN_COOKIE, first);
            assert.strictEqual((await b.post('/echo', {}, { header: first })).status, 403);
            assert.strictEqual((await b.post('/echo')).status, 200);
        });
    });

    await test('выход: выдаётся токен «до входа» с новым nyxo_pre; прежние токены не действуют', async () => {
        const { app } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            const pre1 = b.cookie(PRE_COOKIE);
            const preToken = b.cookie(TOKEN_COOKIE);
            await b.post('/login', { userId: 4 });
            const sessionToken = b.cookie(TOKEN_COOKIE);
            const out = await b.post('/logout');
            assert.strictEqual(out.status, 200);
            assert.strictEqual(setCookieNamed(out, TOKEN_COOKIE).length, 1);
            assert.notStrictEqual(b.cookie(PRE_COOKIE), pre1, 'nyxo_pre заменён');
            assert.strictEqual((await b.post('/echo')).status, 200, 'новый токен сразу годится (регистрация без перезагрузки)');
            for (const old of [preToken, sessionToken]) {
                b.jar.set(TOKEN_COOKIE, old);
                assert.strictEqual((await b.post('/echo', {}, { header: old })).status, 403);
            }
        });
    });

    await test('сессия, которой больше нет в хранилище, считается «до входа»', async () => {
        const { app, sessions } = makeApp();
        await withServer(app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            await b.post('/login', { userId: 5 });
            assert.strictEqual((await b.post('/echo')).status, 200);
            sessions.clear(); // срок вышел, сессию убрала чистка
            const res = await b.post('/echo');
            assert.strictEqual(res.status, 403, 'токен был привязан к умершей сессии');
            assert.strictEqual((await b.post('/echo')).status, 200, 'после GET/отказа выдан токен «до входа»');
        });
    });

    await test('смена SESSION_SECRET сбрасывает выданные токены', async () => {
        const first = makeApp({ secret: SECRET });
        const second = makeApp({ secret: SECRET + '-rotated' });
        let token;
        await withServer(first.app, async (base) => {
            const b = new Browser(base);
            await b.get('/ping');
            token = { csrf: b.cookie(TOKEN_COOKIE), pre: b.cookie(PRE_COOKIE) };
        });
        await withServer(second.app, async (base) => {
            const b = new Browser(base);
            b.jar.set(TOKEN_COOKIE, token.csrf);
            b.jar.set(PRE_COOKIE, token.pre, { httpOnly: true });
            assert.strictEqual((await b.post('/echo', {}, { header: token.csrf })).status, 403);
            assert.strictEqual((await b.post('/echo')).status, 200);
        });
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
