'use strict';
// Куки и строки сессий (контракт волны 1, §4; roadmap R2).
//
//   | Продление сессии | если sess.renewBucket !== floor(now / interval)      |
//   | Кука day / week  | maxAge = срок + 15 мин; Set-Cookie при каждом продлении |
//   | Кука tab         | сессионная, без Expires; строку продлевает touch сокетов |
//   | TTL строки       | 24 ч; в БД время огрублено вверх до 5 мин, createdAt нет |
//
// Основной сервер набора идёт с огромным интервалом продления
// (NYXO_TEST_RENEW_INTERVAL_MS = час): «в той же корзине» тогда не зависит от
// того, когда выполнился запрос, а «смену корзины» делает форсированное
// продление (helpers/anon.js#forceRenewal: сбрасывает маркер sess.renewBucket,
// как будто начался новый интервал). Что интервал действительно считается по
// часам, показывает отдельный сервер с интервалом 0,7 с: продления на нём
// приходят сами.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, waitUntil } = require('./helpers/scenarios');
const {
    LIFETIME_MS, COOKIE_EXTRA_MS, SESSION_TTL_MS, BUCKET_MS, HOUR_MS, MINUTE_MS,
    setCookies, sessionCookie, userRow, sessionRow, registerRaw, forceRenewal,
} = require('./helpers/anon');

const RENEW_INTERVAL_MS = 60 * MINUTE_MS;
const suite = createSuite('session-renewal', { env: { NYXO_TEST_RENEW_INTERVAL_MS: RENEW_INTERVAL_MS } });

const SECOND_MS = 1000;
const ceil5 = (ms) => Math.ceil(ms / BUCKET_MS) * BUCKET_MS;
// Cookie: Expires — с точностью до секунды.
const COOKIE_TOLERANCE_MS = 5 * SECOND_MS;
const near = (actual, expected, tolerance, what) =>
    assert.ok(Math.abs(actual - expected) <= tolerance, `${what}: ${new Date(actual).toISOString()} вместо ${new Date(expected).toISOString()} (±${tolerance} мс)`);

// Новый аккаунт: клиент, id, id сессии и момент регистрации.
async function account(lifetime) {
    const client = suite.client();
    const before = Date.now();
    const res = await registerRaw(client, lifetime);
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
    const cookie = sessionCookie(client);
    return { client, user: res.body.user, registration: res, cookie, sid: cookie.sid, at: before };
}

const sessionCookies = (res) => setCookies(res);

test('регистрация: tab — сессионная кука без Expires, day/week — срок + 15 минут; в строке session время огрублено, createdAt нет', async () => {
    for (const lifetime of ['tab', 'day', 'week']) {
        const { registration, user, sid, at } = await account(lifetime);
        const now = Date.now();
        const cookies = sessionCookies(registration);
        assert.strictEqual(cookies.length, 1, `${lifetime}: ровно одна Set-Cookie с сессией`);
        const header = registration.headers.getSetCookie().find(h => h.startsWith('connect.sid='));
        assert.match(header, /;\s*HttpOnly/i, 'кука сессии HttpOnly');
        assert.match(header, /;\s*SameSite=Lax/i);
        assert.match(header, /;\s*Path=\//i);

        const row = await sessionRow(suite, sid);
        assert.ok(row, `${lifetime}: строки session нет`);
        assert.strictEqual(row.sess.userId, user.id);
        assert.strictEqual(row.sess.isAnonymous, true);
        assert.strictEqual(row.sess.anonLifetime, lifetime);
        assert.ok(!('createdAt' in row.sess), `${lifetime}: createdAt не хранится`);
        assert.strictEqual(row.expireMs % BUCKET_MS, 0, `${lifetime}: session.expire не на границе 5 минут`);

        if (lifetime === 'tab') {
            assert.strictEqual(cookies[0].expiresAt, null, 'tab: у куки нет ни Expires, ни Max-Age');
            assert.ok(!/expires=|max-age=/i.test(header), `tab: ${header}`);
            // Строка живёт 24 часа (огрублено вверх).
            assert.ok(row.expireMs >= at + SESSION_TTL_MS && row.expireMs <= ceil5(now + SESSION_TTL_MS), 'tab: session.expire ≈ сейчас + 24 ч');
            assert.ok(!row.sess.cookie.expires, 'tab: в сохранённой куке нет expires');
        } else {
            const maxAge = LIFETIME_MS[lifetime] + COOKIE_EXTRA_MS;
            near(cookies[0].expiresAt, at + maxAge, (now - at) + COOKIE_TOLERANCE_MS + SECOND_MS, `${lifetime}: Expires куки = срок + 15 минут`);
            // В базе — то же, огрублённое вверх до 5 минут; originalMaxAge не «дрожит».
            const stored = Date.parse(row.sess.cookie.expires);
            assert.strictEqual(stored % BUCKET_MS, 0, `${lifetime}: cookie.expires в БД не на границе 5 минут`);
            assert.strictEqual(row.expireMs, stored, `${lifetime}: session.expire = cookie.expires`);
            assert.ok(stored >= at + maxAge && stored <= ceil5(now + maxAge), `${lifetime}: cookie.expires в БД ≈ срок + 15 минут`);
            assert.strictEqual(row.sess.cookie.originalMaxAge, maxAge, `${lifetime}: originalMaxAge`);
        }
    }
});

test('в той же корзине продления нет: ни Set-Cookie, ни записи в session', async () => {
    for (const lifetime of ['tab', 'day', 'week']) {
        const { client, sid } = await account(lifetime);
        const before = await sessionRow(suite, sid);
        for (const urlPath of ['/api/auth', '/api/user', '/api/chats', '/api/auth']) {
            const res = await client.get(urlPath);
            assert.strictEqual(res.status, 200, urlPath);
            assert.deepStrictEqual(sessionCookies(res), [], `${lifetime}: ${urlPath} не должен ставить куку сессии в той же корзине`);
        }
        const after = await sessionRow(suite, sid);
        assert.deepStrictEqual(after, before, `${lifetime}: строка session не меняется`);
    }
});

for (const lifetime of ['day', 'week']) {
    test(`${lifetime}: после смены корзины — Set-Cookie с новым Expires, session.expire сдвинулся; в той же корзине снова тишина`, async () => {
        const { client, sid, cookie: first } = await account(lifetime);
        const maxAge = LIFETIME_MS[lifetime] + COOKIE_EXTRA_MS;

        // Строка и кука «постарели» на 3 часа, а маркер продления устарел: следующий запрос начинает новый интервал.
        const aged = 3 * HOUR_MS;
        await forceRenewal(suite, sid, { rewindExpireMs: aged });
        const stale = await sessionRow(suite, sid);

        const t0 = Date.now();
        const res = await client.get('/api/auth');
        const t1 = Date.now();
        assert.strictEqual(res.body.authenticated, true);
        const cookies = sessionCookies(res);
        assert.strictEqual(cookies.length, 1, 'продление должно прислать куку сессии');
        assert.strictEqual(cookies[0].value, first.value, 'продление не меняет id сессии');
        near(cookies[0].expiresAt, t1 + maxAge, (t1 - t0) + COOKIE_TOLERANCE_MS + SECOND_MS, 'Expires куки сдвинут на срок + 15 минут');
        assert.ok(sessionCookie(client).expiresAt >= cookies[0].expiresAt - 1, 'клиент хранит новую куку');

        const renewed = await sessionRow(suite, sid);
        assert.ok(renewed.expireMs > stale.expireMs + aged - 10 * SECOND_MS, 'session.expire сдвинулся вперёд');
        assert.ok(renewed.expireMs >= t0 + maxAge && renewed.expireMs <= ceil5(t1 + maxAge), 'session.expire ≈ сейчас + срок + 15 минут');
        assert.strictEqual(renewed.expireMs % BUCKET_MS, 0);
        assert.strictEqual(Date.parse(renewed.sess.cookie.expires), renewed.expireMs);
        assert.strictEqual(renewed.sess.renewBucket, Math.floor(t1 / RENEW_INTERVAL_MS), 'маркер продления — номер текущего интервала');

        // Тот же интервал: куки нет, строка не меняется.
        const again = await client.get('/api/auth');
        assert.deepStrictEqual(sessionCookies(again), []);
        assert.deepStrictEqual(await sessionRow(suite, sid), renewed);
    });
}

test('tab: кука остаётся сессионной; строку без сокета никто не продлевает, а touch открытого сокета — продлевает', async () => {
    const { client, sid } = await account('tab');
    const aged = 20 * HOUR_MS;

    // Строка «постарела»: осталось 4 часа. Без открытого сокета и без нового интервала она так и лежит.
    await suite.time.rewindSession(sid, aged);
    const stale = await sessionRow(suite, sid);
    assert.ok(stale.expireMs < Date.now() + 5 * HOUR_MS);
    await suite.server.waitForTick(2);
    assert.strictEqual((await sessionRow(suite, sid)).expireMs, stale.expireMs, 'без сокета touch строку не трогает');

    // Открытый сокет: touch раз в такт обслуживания возвращает строке сутки.
    const sock = await client.socket();
    try {
        const touched = await waitUntil(async () => {
            const row = await sessionRow(suite, sid);
            return row && row.expireMs >= ceil5(Date.now() + SESSION_TTL_MS) - BUCKET_MS ? row : null;
        }, { what: 'touch продлил строку tab-сессии до 24 часов' });
        assert.strictEqual(touched.expireMs % BUCKET_MS, 0);
        assert.ok(!touched.sess.cookie.expires, 'tab: кука по-прежнему без expires');
    } finally {
        await sock.close();
    }

    // Продление по HTTP при смене интервала: куки с Expires не появляется, строка — на сутки вперёд.
    await suite.time.rewindSession(sid, aged);
    await forceRenewal(suite, sid);
    const t0 = Date.now();
    const res = await client.get('/api/auth');
    assert.strictEqual(res.body.authenticated, true);
    for (const cookie of sessionCookies(res)) assert.strictEqual(cookie.expiresAt, null, 'tab: Set-Cookie без Expires');
    assert.strictEqual(sessionCookie(client).expiresAt, null, 'в браузере кука сессионная');
    const renewed = await sessionRow(suite, sid);
    assert.ok(renewed.expireMs >= t0 + SESSION_TTL_MS - SECOND_MS && renewed.expireMs <= ceil5(Date.now() + SESSION_TTL_MS), 'HTTP-продление вернуло строке 24 часа');
});

test('day/week: touch сокета строки не трогает — их срок задаёт сама кука', async () => {
    for (const lifetime of ['day', 'week']) {
        const { client, sid } = await account(lifetime);
        await suite.time.rewindSession(sid, 3 * HOUR_MS);
        const stale = await sessionRow(suite, sid);
        const sock = await client.socket();
        try {
            await suite.server.waitForTick(2);
            assert.strictEqual((await sessionRow(suite, sid)).expireMs, stale.expireMs, `${lifetime}: строка не должна меняться от touch`);
            // Активность аккаунта сокет при этом продлевает (отдельная таблица users).
            assert.ok((await userRow(suite, client.user.id)).lastActiveMs >= ceil5(Date.now() - 5000));
        } finally {
            await sock.close();
        }
    }
});

test('интервал продления считается по часам: на сервере с интервалом 0,7 с продления приходят сами и не чаще раза за интервал', async () => {
    const fast = await suite.startServer({ name: 'session-renewal-fast', env: { NYXO_TEST_RENEW_INTERVAL_MS: 700 } });
    const client = fast.client();
    const registered = await registerRaw(client, 'day');
    assert.strictEqual(registered.body.success, true);
    const sid = sessionCookie(client).sid;
    const maxAge = LIFETIME_MS.day + COOKIE_EXTRA_MS;

    const renewals = [];
    let requests = 0;
    await waitUntil(async () => {
        const res = await client.get('/api/auth');
        requests++;
        const cookies = sessionCookies(res);
        if (cookies.length > 0) renewals.push({ at: Date.now(), expiresAt: cookies[0].expiresAt, requests });
        return renewals.length >= 3;
    }, { timeoutMs: 15000, intervalMs: 50, what: 'три продления сессии на сервере с интервалом 0,7 с' });

    for (const renewal of renewals) near(renewal.expiresAt, renewal.at + maxAge, 2 * COOKIE_TOLERANCE_MS, 'Expires продления');
    assert.ok(renewals[2].expiresAt > renewals[0].expiresAt, 'каждое продление сдвигает срок куки вперёд');
    // Запросов было заметно больше, чем продлений: в одном интервале кука не ставится.
    assert.ok(requests > renewals.length, `продлений ${renewals.length} на ${requests} запросов`);
    const row = await sessionRow(suite, sid);
    assert.ok(row.expireMs >= renewals[2].at + maxAge - SECOND_MS, 'строка session продлевается вместе с кукой');
});
