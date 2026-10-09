'use strict';
// Вход по почте и паролю удалён (контракт волны 1, §3 «Прочие маршруты», §4
// validateSession; roadmap R0, R2): остались только временные аккаунты.
//
//   * POST /api/register, /api/login, /api/change-password,
//     /api/user/avatar-color и GET /api/security-events — JSON-404
//     {success:false, message:'Не найдено'} при валидном CSRF-токене; без
//     токена небезопасные запросы получают 403 раньше маршрутов;
//   * GET /api/pow/challenge?purpose=register — 400, register-anon — как раньше;
//   * в ответах нет email и пароля: ключи ответов регистрации, /api/auth и
//     /api/user — ровно по контракту;
//   * сессия без isAnonymous (осталась от входа по паролю) недействительна, как
//     и сессия несуществующего пользователя: /api/auth сообщает, что сессия
//     закончилась (reason/expired), а остальное API и сокет её не принимают.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { createSuite } = require('./helpers/scenarios');
const { signSessionCookie, sessionRow, SESSION_COOKIE, LIFETIME_SECONDS } = require('./helpers/anon');

const suite = createSuite('auth-removed');

const NOT_FOUND = { success: false, message: 'Не найдено' };
const REMOVED = [
    ['POST', '/api/register', { email: 'user@example.com', password: 'Passw0rd!x', username: 'user' }],
    ['POST', '/api/login', { email: 'user@example.com', password: 'Passw0rd!x' }],
    ['POST', '/api/change-password', { currentPassword: 'Passw0rd!x', newPassword: 'Passw0rd!y' }],
    ['POST', '/api/user/avatar-color', { color: '#667EEA' }],
    ['GET', '/api/security-events', undefined],
];
// Те же адреса другими методами тоже ничего не отдают.
const OTHER_METHODS = [
    ['GET', '/api/register'], ['GET', '/api/login'], ['GET', '/api/change-password'], ['GET', '/api/user/avatar-color'],
    ['PUT', '/api/login'], ['DELETE', '/api/login'], ['POST', '/api/security-events'], ['DELETE', '/api/security-events'],
];

const keys = (object) => Object.keys(object).sort();
const USER_KEYS = ['anonExpiresAt', 'anonInactivitySeconds', 'anonLifetime', 'id', 'readReceipts', 'uniqueCode', 'username'];
const AUTH_USER_KEYS = [...USER_KEYS, 'isAnonymous'].sort();

// Все ключи JSON на любой глубине.
function allKeys(value, out = new Set()) {
    if (Array.isArray(value)) value.forEach(item => allKeys(item, out));
    else if (value && typeof value === 'object') {
        for (const [key, inner] of Object.entries(value)) { out.add(key); allKeys(inner, out); }
    }
    return out;
}
const LEGACY_FIELD = /email|password|парол|hash/i;

// Сессия, которой нет у клиента-теста естественным путём: строка в таблице и подписанная кука.
async function plantSession(sess) {
    const sid = crypto.randomBytes(24).toString('base64url');
    await suite.query(
        `INSERT INTO session (sid, sess, expire) VALUES ($1, $2::json, NOW() + INTERVAL '1 day')`,
        [sid, JSON.stringify({ cookie: { originalMaxAge: null, expires: null, httpOnly: true, path: '/', sameSite: 'lax' }, ...sess })]
    );
    const client = suite.client();
    client.withCookie(SESSION_COOKIE, signSessionCookie(sid, suite.secrets.SESSION_SECRET));
    return { client, sid };
}

test('удалённые маршруты при валидном CSRF-токене — JSON-404, и в аккаунте, и без него', async () => {
    const guest = suite.client();
    const member = suite.client();
    await member.registerAnon();
    for (const client of [guest, member]) {
        const who = client === guest ? 'без входа' : 'в аккаунте';
        for (const [method, urlPath, body] of REMOVED) {
            const res = await client.request(method, urlPath, { json: body });
            assert.strictEqual(res.status, 404, `${who}: ${method} ${urlPath}`);
            assert.match(res.headers.get('content-type'), /application\/json/);
            assert.deepStrictEqual(res.body, NOT_FOUND, `${who}: ${method} ${urlPath}`);
            assert.deepStrictEqual(res.headers.getSetCookie().filter(h => h.startsWith('connect.sid=')), [], `${who}: ${method} ${urlPath} не должен создавать сессию`);
        }
        for (const [method, urlPath] of OTHER_METHODS) {
            const res = await client.request(method, urlPath, { json: method === 'GET' ? undefined : {} });
            assert.strictEqual(res.status, 404, `${who}: ${method} ${urlPath}`);
            assert.deepStrictEqual(res.body, NOT_FOUND, `${who}: ${method} ${urlPath}`);
        }
    }
    // Вход по паролю не создал сессию.
    assert.deepStrictEqual(await guest.auth(), { authenticated: false, onionUrl: null });
});

test('без CSRF-токена небезопасные запросы к удалённым маршрутам — 403, а не 404', async () => {
    const posts = REMOVED.filter(([method]) => method === 'POST');
    // Нет ни куки, ни заголовка.
    const fresh = suite.client();
    for (const [method, urlPath, body] of posts) {
        const res = await fresh.request(method, urlPath, { json: body, csrf: false });
        assert.strictEqual(res.status, 403, `${method} ${urlPath} без токена`);
        assert.strictEqual(res.body.success, false);
    }
    // Кука есть, заголовка нет и заголовок чужой.
    const holder = suite.client();
    await holder.csrfToken();
    for (const [method, urlPath, body] of posts) {
        assert.strictEqual((await holder.request(method, urlPath, { json: body, csrf: false })).status, 403, `${urlPath}: кука без заголовка`);
        assert.strictEqual((await holder.request(method, urlPath, { json: body, csrf: 'not-the-token' })).status, 403, `${urlPath}: чужой токен`);
    }
    // GET — безопасный метод: токена не требует, но маршрута всё равно нет.
    const getRes = await suite.client().get('/api/security-events');
    assert.strictEqual(getRes.status, 404);
});

test('proof-of-work: purpose=register — 400, register-anon работает; прочие цели тоже 400', async () => {
    const client = suite.client();
    const gone = await client.get('/api/pow/challenge?purpose=register');
    assert.strictEqual(gone.status, 400);
    assert.strictEqual(gone.body.success, false);
    for (const query of ['purpose=login', 'purpose=REGISTER', 'purpose=', 'purpose=register-anon%00', '']) {
        const res = await client.get(`/api/pow/challenge${query ? `?${query}` : ''}`);
        assert.strictEqual(res.status, 400, `?${query}`);
    }
    const live = await client.get('/api/pow/challenge?purpose=register-anon');
    assert.strictEqual(live.status, 200);
    assert.strictEqual(live.body.success, true);
    assert.strictEqual(typeof live.body.token, 'string');
    assert.strictEqual(live.body.difficulty, 8, 'в тестах сложность — POW_DIFFICULTY');
    // Регистрация временного аккаунта по-прежнему работает.
    assert.ok((await client.registerAnon()).id > 0);
});

test('в ответах нет email и пароля; ключи регистрации, /api/auth и /api/user — ровно по контракту', async () => {
    const client = suite.client();
    const pow = await client.solvePow('register-anon');
    const registered = await client.post('/api/register/anonymous', { lifetime: 'day', pow });
    assert.strictEqual(registered.body.success, true, JSON.stringify(registered.body));
    assert.deepStrictEqual(keys(registered.body), ['botChatId', 'success', 'user']);
    assert.deepStrictEqual(keys(registered.body.user), AUTH_USER_KEYS);
    assert.ok(Number.isInteger(registered.body.botChatId) && registered.body.botChatId > 0);
    assert.strictEqual(registered.body.user.isAnonymous, true);
    assert.strictEqual(registered.body.user.readReceipts, false);

    const auth = await client.auth();
    assert.deepStrictEqual(keys(auth), ['authenticated', 'onionUrl', 'user']);
    assert.deepStrictEqual(keys(auth.user), AUTH_USER_KEYS);
    assert.strictEqual(auth.onionUrl, null);

    const info = await client.get('/api/user');
    assert.deepStrictEqual(keys(info.body), ['success', 'user']);
    assert.deepStrictEqual(keys(info.body.user), USER_KEYS, '/api/user: ни email, ни других полей');
    assert.ok(!('email' in info.body.user));
    assert.strictEqual(info.body.user.anonInactivitySeconds, LIFETIME_SECONDS.day);

    // Ни в одном ответе профиля, списка чатов и истории нет полей почты и пароля.
    const bot = await client.botChat();
    const responses = {
        register: registered.body,
        auth,
        user: info.body,
        chats: (await client.get('/api/chats')).body,
        history: (await client.get(`/api/messages/${bot.id}`)).body,
        privacy: (await client.post('/api/user/privacy', { readReceipts: false })).body,
        lifetime: (await client.post('/api/user/lifetime', { lifetime: 'day' })).body,
    };
    for (const [name, body] of Object.entries(responses)) {
        const bad = [...allKeys(body)].filter(key => LEGACY_FIELD.test(key));
        assert.deepStrictEqual(bad, [], `в ответе ${name} остались поля ${bad.join(', ')}`);
    }
});

test('сессия без isAnonymous (от входа по паролю) недействительна: /api/auth — reason expired, API и сокет её не принимают', async () => {
    const holder = suite.client();
    const user = await holder.registerAnon();
    const legacy = () => plantSession({ userId: user.id, username: user.username, uniqueCode: user.uniqueCode, avatar: '#667EEA' });

    // Первый же запрос с такой кукой заканчивает сессию, поэтому на каждый канал — своя подложная сессия.
    const viaAuth = await legacy();
    assert.ok(await sessionRow(suite, viaAuth.sid), 'строка подложной сессии на месте');
    assert.deepStrictEqual(await viaAuth.client.auth(), { authenticated: false, reason: 'expired', expired: true, onionUrl: null });
    assert.strictEqual(await sessionRow(suite, viaAuth.sid), null, 'недействительная сессия удалена');

    const viaApi = await legacy();
    const chats = await viaApi.client.get('/api/chats');
    assert.strictEqual(chats.body.success, false, JSON.stringify(chats.body));
    assert.strictEqual(chats.body.message, 'Не авторизован');

    const viaSocket = await legacy();
    await assert.rejects(
        viaSocket.client.socket(),
        (err) => err.kind === 'connect_error' && /Не авторизован/.test(err.reason || err.message),
        'сокет с легаси-сессией должен получить «Не авторизован»'
    );

    // Настоящая сессия того же пользователя не пострадала.
    assert.strictEqual((await holder.auth()).authenticated, true);
});

test('сессия несуществующего пользователя — то же: reason expired; а гость и просто забытая кука — без reason', async () => {
    const { client, sid } = await plantSession({ userId: 2147483000, username: 'Гость-0000', uniqueCode: 'X', avatar: '#667EEA', isAnonymous: true });
    assert.deepStrictEqual(await client.auth(), { authenticated: false, reason: 'expired', expired: true, onionUrl: null });
    assert.strictEqual(await sessionRow(suite, sid), null);

    // Кука, строки которой нет вовсе (удалена чисткой): сессии «не было» — этих полей нет.
    const forgotten = suite.client();
    forgotten.withCookie(SESSION_COOKIE, signSessionCookie(crypto.randomBytes(24).toString('base64url'), suite.secrets.SESSION_SECRET));
    assert.deepStrictEqual(await forgotten.auth(), { authenticated: false, onionUrl: null });
    assert.deepStrictEqual(await suite.client().auth(), { authenticated: false, onionUrl: null });
});
