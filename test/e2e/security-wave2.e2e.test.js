'use strict';
// Безопасность сервера, волна 2 (T2.3): лимиты и одноразовость PoW в Postgres
// (7.4), мониторинг (7.6), CSRF, привязанный к сессии (8.1), security.txt (8.4).
// Настоящий server.js и настоящий Postgres; рестарт — тот же процесс на той же
// базе. HSTS в этом наборе не проверяется: заголовок бывает только в
// production по https, а production требует TLS до Postgres (тестовый
// контейнер его не поддерживает) — подключение проверяет юнит-тест
// test/hsts.test.js.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { REPO_ROOT, testOnionAddress } = require('./helpers/env');
const { freePort } = require('./helpers/server');
const { solve } = require(path.join(REPO_ROOT, 'public', 'pow-worker.js'));

const METRICS_TOKEN = crypto.randomBytes(32).toString('base64url');
const suite = createSuite('security-wave2', {
    env: {
        METRICS_TOKEN,
        PUBLIC_ORIGIN: 'https://nyxo.example',
        SECURITY_CONTACT: 'mailto:security@nyxo.example',
    },
});

const CSRF_DENIED = { success: false, message: 'Запрещено: неверный CSRF-токен' };
const ORIGIN_DENIED = { success: false, message: 'Запрещено: запрос с чужого сайта' };
const BUSY = { success: false, code: 'busy', message: 'Сервис сейчас занят. Повторите попытку через несколько секунд.' };

const url = (urlPath) => `${suite.server.baseUrl}${urlPath}`;
const sha256Hex = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');
const cookieByName = (client, name) => client.jar.list('/').find(cookie => cookie.name === name);

// Регистрация «сырым» запросом: статус и тело, без исключений.
async function tryRegister(client, pow) {
    const solution = pow || await client.solvePow('register-anon');
    return client.post('/api/register/anonymous', { lifetime: 'tab', pow: solution });
}

// nonce, который НЕ решает задачу (сложность набора — 8 бит: первый байт хэша не нулевой).
function wrongNonce(token) {
    for (let n = 0; ; n++) {
        if (crypto.createHash('sha256').update(`${token}:${n}`, 'utf8').digest()[0] !== 0) return String(n);
    }
}

// Таблицу переименовывают, а не удаляют: запросы к ней падают с 42P01, а
// после теста всё возвращается как было.
async function withTableDown(table, fn) {
    await suite.query(`ALTER TABLE ${table} RENAME TO ${table}_off`);
    try {
        return await fn();
    } finally {
        await suite.query(`ALTER TABLE ${table}_off RENAME TO ${table}`);
    }
}

// ---------------------------------------------------------------- мониторинг

test('/healthz и /readyz: 200, без кук, лимитеров и Onion-Location', async () => {
    for (const probe of ['/healthz', '/readyz']) {
        const res = await fetch(url(probe));
        assert.strictEqual(res.status, 200, probe);
        assert.deepStrictEqual(await res.json(), { status: 'ok' });
        assert.strictEqual(res.headers.get('set-cookie'), null, `${probe}: сессия и куки не создаются`);
        assert.strictEqual(res.headers.get('ratelimit'), null);
        assert.strictEqual(res.headers.get('ratelimit-policy'), null);
        assert.strictEqual(res.headers.get('onion-location'), null);
    }
    // Пробы хостинга приходят часто: лимитера у них нет (apiLimiter — 1000 за 15 минут на /api).
    for (let batch = 0; batch < 22; batch++) {
        const results = await Promise.all(Array.from({ length: 50 }, () => fetch(url('/healthz')).then(async (r) => { await r.arrayBuffer(); return r.status; })));
        assert.ok(results.every(status => status === 200), 'ни одного 429');
    }
});

test('Onion-Location: на страницах есть, на /healthz, /readyz, /metrics и security.txt — нет', async () => {
    const onion = await suite.startServer({ name: 'onion', env: { ONION_ADDRESS: testOnionAddress(), ONION_PORT: await freePort() } });
    try {
        const get = (p) => fetch(`${onion.baseUrl}${p}`, { redirect: 'manual' });
        const page = await get('/');
        await page.arrayBuffer();
        assert.match(page.headers.get('onion-location') || '', /^http:\/\/[a-z2-7]{56}\.onion\/$/, 'для страницы заголовок есть');
        for (const p of ['/healthz', '/readyz', '/metrics', '/security.txt', '/.well-known/security.txt']) {
            const res = await get(p);
            await res.arrayBuffer();
            assert.strictEqual(res.headers.get('onion-location'), null, p);
        }
    } finally {
        await onion.stop();
    }
});

test('/metrics: без токена и с чужим — 404, как у любого адреса; с токеном — Prometheus без id, IP и путей с параметрами', async () => {
    const owner = suite.client({ xff: '10.88.0.1' });
    const member = suite.client({ xff: '10.88.0.2' });
    await owner.registerAnon();
    await member.registerAnon();
    const { roomId, ownerChat, memberChat } = await roomWithMember(owner, member, { name: 'Метрики' });
    await owner.send(ownerChat.id, 'привет');
    await owner.get(`/api/messages/${ownerChat.id}`);
    await member.get(`/api/messages/${memberChat.id}`);
    await owner.get(`/api/chats/${ownerChat.id}/participants`);

    const missing = await fetch(url('/definitely-not-here'));
    // Тело отличается только запрошенным адресом («Cannot GET …»).
    const missingBody = (await missing.text()).replace('/definitely-not-here', '/metrics');
    for (const headers of [{}, { Authorization: 'Bearer wrong-token' }, { Authorization: METRICS_TOKEN }, { Authorization: `Basic ${METRICS_TOKEN}` }]) {
        const res = await fetch(url('/metrics'), { headers });
        assert.strictEqual(res.status, 404, JSON.stringify(headers));
        assert.strictEqual(res.headers.get('content-type'), missing.headers.get('content-type'));
        assert.strictEqual(await res.text(), missingBody, 'ответ неотличим от несуществующего адреса');
    }
    assert.strictEqual((await fetch(url(`/metrics?token=${METRICS_TOKEN}`))).status, 404, 'токен в адресе не принимается');

    const res = await fetch(url('/metrics'), { headers: { Authorization: `Bearer ${METRICS_TOKEN}` } });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /^text\/plain/);
    const text = await res.text();

    assert.match(text, /^# TYPE nyxo_http_requests_total counter$/m);
    assert.match(text, /nyxo_http_requests_total\{method="POST",route="\/api\/register\/anonymous",status="2xx",outcome="ok"\} [2-9]/);
    assert.match(text, /nyxo_registrations_total [2-9]/);
    assert.match(text, /nyxo_pg_pool_connections\{state="total"\}/);
    assert.match(text, /nyxo_uptime_seconds \d+/);
    assert.match(text, /route="\/api\/messages\/:/, 'маршрут с параметром — шаблоном');

    // Ни одного идентификатора и адреса: id комнаты, чатов, пользователей и IP клиентов.
    for (const secret of [owner.user.id, member.user.id, roomId, ownerChat.id, memberChat.id, owner.xff, member.xff]) {
        assert.ok(!text.includes(String(secret)), `в метриках есть ${secret}`);
    }
    for (const labels of text.match(/\{[^}]*\}/g) || []) {
        assert.ok(!/\d{6,}/.test(labels), `подозрительная метка ${labels}`);
        assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(labels), `в метке похоже на IP: ${labels}`);
    }
    assert.ok(!/\/api\/[a-z-]+\/\d+/.test(text), 'путь с числом-параметром попал в метрики');
});

test('security.txt: поля RFC 9116, text/plain, кэш на сутки, без кук; /security.txt → 301', async () => {
    const res = await fetch(url('/.well-known/security.txt'));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'text/plain; charset=utf-8');
    assert.strictEqual(res.headers.get('cache-control'), 'public, max-age=86400');
    assert.strictEqual(res.headers.get('set-cookie'), null);
    const text = await res.text();
    assert.match(text, /^Contact: mailto:security@nyxo\.example$/m);
    assert.match(text, /^Preferred-Languages: ru, en$/m);
    assert.match(text, /^Canonical: https:\/\/nyxo\.example\/\.well-known\/security\.txt$/m);
    assert.match(text, /^Policy: https:\/\/github\.com\/PortfolioBTS\/masages\/blob\/main\/SECURITY\.md$/m);
    const expires = Date.parse(/^Expires: (.+)$/m.exec(text)[1]);
    assert.ok(expires > Date.now() + 150 * 86400 * 1000 && expires < Date.now() + 366 * 86400 * 1000, 'Expires в будущем и не дальше года');

    const short = await fetch(url('/security.txt'), { redirect: 'manual' });
    assert.strictEqual(short.status, 301);
    assert.strictEqual(short.headers.get('location'), '/.well-known/security.txt');
    const followed = await fetch(url('/security.txt'));
    assert.strictEqual(followed.status, 200);
    assert.strictEqual(await followed.text(), text);
});

test('статика кук не выдаёт; куки CSRF выдаёт запрос к API', async () => {
    const page = await fetch(url('/'));
    await page.arrayBuffer();
    assert.strictEqual(page.status, 200);
    assert.strictEqual(page.headers.get('set-cookie'), null);
    const api = await fetch(url('/api/auth'));
    const cookies = api.headers.getSetCookie().map(line => line.split('=')[0]);
    assert.ok(cookies.includes('csrf_token') && cookies.includes('nyxo_pre'), cookies.join(','));
});

// ---------------------------------------------------------------------- CSRF

test('CSRF: токен до входа работает при регистрации и отвергается после входа', async () => {
    const client = suite.client();
    await client.get('/api/auth');
    const preToken = client.jar.get('csrf_token');
    const pre = cookieByName(client, 'nyxo_pre');
    assert.ok(preToken && pre, 'выданы csrf_token и nyxo_pre');
    assert.strictEqual(pre.httpOnly, true);
    assert.strictEqual(pre.sameSite, 'strict');
    assert.strictEqual(pre.expiresAt, null, 'сессионная кука');
    assert.strictEqual(cookieByName(client, 'csrf_token').httpOnly, false);

    await client.registerAnon(); // регистрация идёт с токеном «до входа»
    const sessionToken = client.jar.get('csrf_token');
    assert.notStrictEqual(sessionToken, preToken, 'в ответе регистрации выдан токен под новую сессию');

    client.jar.set('csrf_token', preToken);
    const denied = await client.post('/api/chats', { name: 'x' }, { csrf: preToken });
    assert.strictEqual(denied.status, 403);
    assert.deepStrictEqual(denied.body, CSRF_DENIED);
    assert.notStrictEqual(client.jar.get('csrf_token'), preToken, 'после отказа выдан токен текущей сессии');
    const retry = await client.post('/api/chats', { name: 'x' });
    assert.strictEqual(retry.status, 200);
    assert.strictEqual(retry.body.success, true);
});

test('CSRF: токен, выданный до смены срока, после смены отвергается', async () => {
    const client = suite.client();
    await client.registerAnon();
    const before = client.jar.get('csrf_token');
    const changed = await client.post('/api/user/lifetime', { lifetime: 'day' });
    assert.strictEqual(changed.body.success, true);
    const after = client.jar.get('csrf_token');
    assert.notStrictEqual(after, before, 'новая сессия — новый токен в том же ответе');

    client.jar.set('csrf_token', before);
    const denied = await client.post('/api/chats', { name: 'x' }, { csrf: before });
    assert.strictEqual(denied.status, 403);
    assert.deepStrictEqual(denied.body, CSRF_DENIED);
    assert.strictEqual((await client.post('/api/chats', { name: 'x' })).status, 200);
});

test('CSRF: без заголовка, с чужим значением и токеном другой сессии — 403', async () => {
    const a = suite.client();
    const b = suite.client();
    await a.registerAnon();
    await b.registerAnon();
    const tokenA = a.jar.get('csrf_token');

    assert.strictEqual((await a.post('/api/chats', { name: 'x' }, { csrf: false })).status, 403, 'нет заголовка');
    const wrong = await a.post('/api/chats', { name: 'x' }, { csrf: crypto.randomBytes(32).toString('hex') });
    assert.strictEqual(wrong.status, 403);
    assert.deepStrictEqual(wrong.body, CSRF_DENIED);

    // Токен сессии A у сессии B: и в куке, и в заголовке.
    b.jar.set('csrf_token', tokenA);
    const crossed = await b.post('/api/chats', { name: 'x' }, { csrf: tokenA });
    assert.strictEqual(crossed.status, 403);
    // У A всё работает (кука A после чужого запроса не менялась).
    assert.strictEqual((await a.post('/api/chats', { name: 'y' })).status, 200);
    assert.strictEqual((await b.post('/api/chats', { name: 'z' })).status, 200, 'B получил свой токен и работает');
});

test('CSRF: Origin проверяется первым — чужой источник отвечает «чужой сайт», а не «неверный токен»', async () => {
    const a = suite.client();
    await a.registerAnon();
    const foreign = await a.post('/api/chats', { name: 'x' }, { origin: 'http://evil.example', csrf: 'bad-token' });
    assert.strictEqual(foreign.status, 403);
    assert.deepStrictEqual(foreign.body, ORIGIN_DENIED);
    const metrics = await (await fetch(url('/metrics'), { headers: { Authorization: `Bearer ${METRICS_TOKEN}` } })).text();
    assert.match(metrics, /nyxo_origin_rejected_total [1-9]/);
    assert.match(metrics, /nyxo_csrf_rejected_total [1-9]/);
});

test('CSRF: удаление аккаунта выдаёт новый токен под «до входа» и меняет nyxo_pre', async () => {
    const a = suite.client();
    await a.registerAnon();
    const sessionToken = a.jar.get('csrf_token');
    const pre = cookieByName(a, 'nyxo_pre').value;
    const deleted = await a.post('/api/account/delete', {});
    assert.strictEqual(deleted.body.success, true);
    const cookies = deleted.response.headers.getSetCookie().map(line => line.split('=')[0]);
    assert.ok(cookies.includes('csrf_token') && cookies.includes('nyxo_pre'));
    assert.notStrictEqual(a.jar.get('csrf_token'), sessionToken);
    assert.notStrictEqual(cookieByName(a, 'nyxo_pre').value, pre);
    // Страница не перезагружается: следующий запрос уже проходит проверку токена.
    const next = await a.post('/api/chats', { name: 'x' });
    assert.notStrictEqual(next.status, 403);
    // Прежний токен сессии больше не годится.
    a.jar.set('csrf_token', sessionToken);
    assert.strictEqual((await a.post('/api/chats', { name: 'x' }, { csrf: sessionToken })).status, 403);
});

test('CSRF: токены переживают рестарт сервера (ключ — из SESSION_SECRET)', async () => {
    const client = suite.client();
    await client.registerAnon();
    const token = client.jar.get('csrf_token');
    await suite.server.restart();
    assert.strictEqual((await client.post('/api/chats', { name: 'после рестарта' })).status, 200);
    assert.strictEqual(client.jar.get('csrf_token'), token, 'кука не менялась');
});

// ------------------------------------------------------- лимиты и PoW в Postgres

test('лимит регистрации (10 в час с адреса) лежит в Postgres и переживает рестарт', async () => {
    const xff = '10.201.0.1';
    for (let i = 0; i < 10; i++) await suite.client({ xff }).registerAnon();
    const over = await tryRegister(suite.client({ xff }));
    assert.strictEqual(over.status, 429);
    assert.deepStrictEqual(over.body, { success: false, message: 'Слишком много регистраций. Попробуйте позже.' });
    assert.ok(over.headers.get('ratelimit') || over.headers.get('ratelimit-policy'), 'стандартные заголовки лимитера');

    // В базе — только HMAC: ни адреса, ни имён.
    const rows = (await suite.query(`SELECT k, hits FROM rl_counters WHERE k LIKE 'register:%'`)).rows;
    assert.ok(rows.some(row => row.hits >= 11), 'счётчик адреса дошёл до 11');
    for (const row of rows) {
        assert.match(row.k, /^register:[A-Za-z0-9_-]{43}$/);
        assert.ok(!row.k.includes('10.201'), 'в ключе нет адреса');
    }
    const persistence = (await suite.query(`SELECT relname, relpersistence FROM pg_class WHERE relname IN ('rl_counters', 'rl_buckets', 'pow_used') ORDER BY relname`)).rows;
    assert.deepStrictEqual(persistence, [
        { relname: 'pow_used', relpersistence: 'u' },
        { relname: 'rl_buckets', relpersistence: 'u' },
        { relname: 'rl_counters', relpersistence: 'u' },
    ], 'таблицы UNLOGGED');

    await suite.server.restart();
    const afterRestart = await tryRegister(suite.client({ xff }));
    assert.strictEqual(afterRestart.status, 429, 'после рестарта лимит на месте');
    await suite.client({ xff: '10.201.0.2' }).registerAnon(); // другой адрес не задет
});

test('PoW: решение принимается один раз — повтор отвергается, в том числе после рестарта; неверный nonce задачу не сжигает', async () => {
    const a = suite.client();
    const b = suite.client();
    const { token, nonce } = await a.solvePow('register-anon');

    const bad = await tryRegister(a, { token, nonce: wrongNonce(token) });
    assert.strictEqual(bad.body.powRequired, true);
    assert.strictEqual((await suite.query('SELECT 1 FROM pow_used WHERE token_hash = decode($1, $2)', [sha256Hex(token), 'hex'])).rowCount, 0, 'неверный nonce ничего не записал');

    const accepted = await tryRegister(a, { token, nonce });
    assert.strictEqual(accepted.body.success, true);
    assert.strictEqual((await suite.query('SELECT 1 FROM pow_used WHERE token_hash = decode($1, $2)', [sha256Hex(token), 'hex'])).rowCount, 1);

    const replay = await tryRegister(b, { token, nonce });
    assert.strictEqual(replay.body.success, false);
    assert.strictEqual(replay.body.powRequired, true, 'то же решение вторым клиентом');

    await suite.server.restart();
    const afterRestart = await tryRegister(suite.client(), { token, nonce });
    assert.strictEqual(afterRestart.body.success, false);
    assert.strictEqual(afterRestart.body.powRequired, true, 'и после рестарта');
});

test('PoW: задача, выданная до рестарта, действует и после него (ключ — из SESSION_SECRET)', async () => {
    const client = suite.client();
    const solution = await client.solvePow('register-anon');
    await suite.server.restart();
    const res = await tryRegister(client, solution);
    assert.strictEqual(res.body.success, true);
});

test('сбой хранилища лимитов закрывает лимит: 503 {code:"busy"}, остальной API работает', async () => {
    const client = suite.client({ xff: '10.202.0.1' });
    const pow = await client.solvePow('register-anon');
    const mark = suite.server.logs.mark();
    await withTableDown('rl_counters', async () => {
        const res = await client.post('/api/register/anonymous', { lifetime: 'tab', pow });
        assert.strictEqual(res.status, 503);
        assert.deepStrictEqual(res.body, BUSY);
        assert.strictEqual(res.headers.get('retry-after'), '5');
        // Общий лимит /api — в памяти и от этой таблицы не зависит.
        assert.strictEqual((await client.get('/api/auth')).status, 200);
    });
    const logged = await suite.server.logs.waitFor('[Limits]', { from: mark, timeoutMs: 5000 });
    assert.ok(!JSON.stringify(logged).includes('10.202.0.1'), 'адрес клиента в лог не попал');
    // Таблица вернулась — та же задача PoW ещё не сожжена и регистрация проходит.
    const ok = await client.post('/api/register/anonymous', { lifetime: 'tab', pow });
    assert.strictEqual(ok.body.success, true);
});

test('сбой pow_used: 503 busy, а решение остаётся несожжённым', async () => {
    const client = suite.client({ xff: '10.203.0.1' });
    const pow = await client.solvePow('register-anon');
    await withTableDown('pow_used', async () => {
        const res = await client.post('/api/register/anonymous', { lifetime: 'tab', pow });
        assert.strictEqual(res.status, 503);
        assert.deepStrictEqual(res.body, BUSY);
    });
    const ok = await client.post('/api/register/anonymous', { lifetime: 'tab', pow });
    assert.strictEqual(ok.body.success, true);
});

test('вход по коду: лимит 20 за 15 минут на аккаунт — в Postgres, переживает рестарт', async () => {
    const client = suite.client({ xff: '10.204.0.1' });
    await client.registerAnon();
    for (let i = 0; i < 20; i++) {
        const res = await client.post('/api/chats/join', { code: 'NOPE-NOPE-NOPE' });
        assert.notStrictEqual(res.status, 429, `попытка ${i + 1}`);
    }
    const limited = await client.post('/api/chats/join', { code: 'NOPE-NOPE-NOPE' });
    assert.strictEqual(limited.status, 429);
    assert.deepStrictEqual(limited.body, { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' });
    const rows = (await suite.query(`SELECT k FROM rl_counters WHERE k LIKE 'join-user:%'`)).rows;
    assert.ok(rows.length >= 1);
    for (const row of rows) assert.match(row.k, /^join-user:[A-Za-z0-9_-]{43}$/);

    await suite.server.restart();
    const after = await client.post('/api/chats/join', { code: 'NOPE-NOPE-NOPE' });
    assert.strictEqual(after.status, 429, 'после рестарта лимит на месте');
});

test('выдача bundle ключей: 5 в час на пару, лимит в Postgres без id; сбой хранилища — 503 busy', async () => {
    const owner = suite.client({ xff: '10.205.0.1' });
    const member = suite.client({ xff: '10.205.0.2' });
    await owner.registerAnon();
    await member.registerAnon();
    await roomWithMember(owner, member, { name: 'Ключи' });
    const bundle = () => owner.get(`/api/keys/bundle/${member.user.id}`);

    await withTableDown('rl_buckets', async () => {
        const res = await bundle();
        assert.strictEqual(res.status, 503);
        assert.deepStrictEqual(res.body, BUSY);
    });

    // Ключей у собеседника нет — хранилище отвечает 404, но попытка в квоту засчитана.
    for (let i = 0; i < 5; i++) {
        const res = await bundle();
        assert.ok(res.status !== 429 && res.status !== 503, `запрос ${i + 1}: ${res.status}`);
    }
    const limited = await bundle();
    assert.strictEqual(limited.status, 429);
    assert.ok(Number(limited.headers.get('retry-after')) > 0);
    assert.match(limited.body.message, /этого пользователя/);

    const rows = (await suite.query('SELECT length(k) AS bytes, n FROM rl_buckets')).rows;
    assert.ok(rows.length >= 2 && rows.every(row => row.bytes === 32), 'ключи — только HMAC (32 байта), без id');
    assert.ok(rows.some(row => row.n === 5));

    await suite.server.restart();
    assert.strictEqual((await bundle()).status, 429, 'после рестарта квота пары на месте');
});

test('уборка: просроченные счётчики, корзины и использованные решения PoW удаляются фоновой задачей', async () => {
    await suite.query(`INSERT INTO rl_counters (k, hits, reset_at) VALUES ('test:expired', 1, now() - interval '1 minute'), ('test:live', 1, now() + interval '1 hour')`);
    await suite.query(`INSERT INTO rl_buckets (k, bucket, n) VALUES (decode(repeat('ab', 32), 'hex'), now() - interval '3 hours', 1), (decode(repeat('cd', 32), 'hex'), date_trunc('minute', now()), 1)`);
    await suite.query(`INSERT INTO pow_used (token_hash, expires_at) VALUES (decode(repeat('ab', 32), 'hex'), now() - interval '10 minutes'), (decode(repeat('cd', 32), 'hex'), now() + interval '1 minute')`);

    const left = async () => ({
        counters: (await suite.query(`SELECT k FROM rl_counters WHERE k LIKE 'test:%' ORDER BY k`)).rows.map(row => row.k),
        buckets: (await suite.query(`SELECT encode(k, 'hex') AS k FROM rl_buckets WHERE k IN (decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 32), 'hex'))`)).rows.map(row => row.k.slice(0, 2)),
        pow: (await suite.query(`SELECT encode(token_hash, 'hex') AS k FROM pow_used WHERE token_hash IN (decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 32), 'hex'))`)).rows.map(row => row.k.slice(0, 2)),
    });
    const state = await waitUntil(async () => {
        const now = await left();
        return now.counters.length === 1 && now.buckets.length === 1 && now.pow.length === 1 ? now : null;
    }, { timeoutMs: 20000, what: 'уборка просроченных строк' });
    assert.deepStrictEqual(state, { counters: ['test:live'], buckets: ['cd'], pow: ['cd'] });

    const metrics = await (await fetch(url('/metrics'), { headers: { Authorization: `Bearer ${METRICS_TOKEN}` } })).text();
    assert.match(metrics, /nyxo_job_runs_total\{job="purgeExpiredLimits",result="ok"\} [1-9]/);
});
