'use strict';
// Смена срока жизни аккаунта: POST /api/user/lifetime (контракт волны 1, §3).
//
//   запрос:  { lifetime: 'tab' | 'day' | 'week' } — поле обязательно, умолчания нет;
//   ответ:   { success, anonLifetime, anonInactivitySeconds, anonExpiresAt };
//   сервер:  last_active_at -> текущая корзина; сессия пересоздаётся (новый
//            sid) с новым сроком: tab — кука без Expires, day/week — с
//            Expires; CSRF-кука выдаётся заново.
//
// Проверяется: tab -> week даёт куку с Expires, week -> tab — сессионную; старый
// sid недействителен (и для HTTP, и для сокета); неверное или пропущенное
// значение — ошибка без последствий (срок не «съезжает» на умолчание);
// отсчёт нового срока идёт от момента смены.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const {
    LIFETIME_MS, LIFETIME_SECONDS, COOKIE_EXTRA_MS, BUCKET_MS, DAY_MS,
    bucketCeil, setCookies, sessionCookie, userRow, sessionRow,
} = require('./helpers/anon');

const suite = createSuite('lifetime-change');

const COOKIE_TOLERANCE_MS = 6000;

async function account(lifetime) {
    const client = suite.client();
    const user = await client.registerAnon({ lifetime });
    return { client, user, cookie: sessionCookie(client), csrf: await client.csrfToken() };
}

// Копия куки сессии в другом «браузере» (устройстве).
function copyOf(cookie) {
    const other = suite.client();
    other.withCookie('connect.sid', cookie.value);
    return other;
}

const changeLifetime = (client, lifetime, extra = {}) => client.post('/api/user/lifetime', { lifetime, ...extra });

test('tab -> week: ответ по формуле, кука с Expires на неделю и 15 минут, новый sid, новая CSRF-кука', async () => {
    const { client, user, cookie: before, csrf: csrfBefore } = await account('tab');
    const spy = copyOf(before);
    assert.strictEqual((await spy.auth()).authenticated, true, 'копия прежней куки до смены работает');
    // Прошло 10 минут тишины: у tab ещё есть запас, но корзина устарела.
    await suite.query(`UPDATE users SET last_active_at = NOW() - INTERVAL '10 minutes' WHERE id = $1`, [user.id]);

    const t0 = Date.now();
    const res = await changeLifetime(client, 'week');
    const t1 = Date.now();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));

    // last_active_at — текущая корзина (вверх от момента смены), срок — от неё.
    const row = await userRow(suite, user.id);
    assert.strictEqual(row.anon_lifetime, 'week');
    assert.strictEqual(row.lastActiveMs % BUCKET_MS, 0);
    assert.ok(row.lastActiveMs >= bucketCeil(t0) && row.lastActiveMs <= bucketCeil(t1), 'last_active_at — корзина момента смены');
    assert.deepStrictEqual(
        { anonLifetime: res.body.anonLifetime, anonInactivitySeconds: res.body.anonInactivitySeconds, anonExpiresAt: res.body.anonExpiresAt },
        { anonLifetime: 'week', anonInactivitySeconds: LIFETIME_SECONDS.week, anonExpiresAt: new Date(row.lastActiveMs + LIFETIME_MS.week).toISOString() }
    );

    // Кука: другой sid, с Expires.
    const cookies = setCookies(res);
    assert.strictEqual(cookies.length, 1, 'новая кука сессии');
    assert.notStrictEqual(cookies[0].value, before.value, 'sid пересоздан');
    assert.ok(cookies[0].expiresAt !== null, 'у недельной куки есть Expires');
    const expected = t1 + LIFETIME_MS.week + COOKIE_EXTRA_MS;
    assert.ok(Math.abs(cookies[0].expiresAt - expected) <= (t1 - t0) + COOKIE_TOLERANCE_MS, `Expires ${new Date(cookies[0].expiresAt).toISOString()} вместо ${new Date(expected).toISOString()}`);
    const after = sessionCookie(client);
    assert.strictEqual(after.value, cookies[0].value);
    assert.strictEqual(after.expiresAt, cookies[0].expiresAt);

    // CSRF-кука выдана заново.
    const csrf = setCookies(res, 'csrf_token');
    assert.strictEqual(csrf.length, 1, 'сервер выдал новую CSRF-куку');
    assert.notStrictEqual(csrf[0].value, csrfBefore);
    assert.strictEqual(await client.csrfToken(), csrf[0].value);

    // Старый sid недействителен: в базе его нет, копия куки ничего не открывает.
    assert.strictEqual(await sessionRow(suite, before.sid), null, 'строка прежней сессии удалена');
    const dead = await spy.auth();
    assert.strictEqual(dead.authenticated, false);
    assert.strictEqual((await sessionRow(suite, after.sid)).sess.anonLifetime, 'week');

    // Новая сессия работает, и в /api/auth и /api/user — новый срок.
    const auth = await client.auth();
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.user.id, user.id);
    assert.strictEqual(auth.user.anonLifetime, 'week');
    assert.strictEqual(auth.user.anonExpiresAt, res.body.anonExpiresAt);
    assert.strictEqual((await client.get('/api/user')).body.user.anonLifetime, 'week');
    // …в том числе небезопасные запросы с новым CSRF-токеном.
    assert.strictEqual((await client.post('/api/user/privacy', { readReceipts: true })).body.success, true);
});

test('week -> tab: сессионная кука без Expires, anonExpiresAt = null, старая недельная кука недействительна', async () => {
    const { client, user, cookie: before } = await account('week');
    assert.ok(before.expiresAt !== null, 'исходная недельная кука с Expires');
    const spy = copyOf(before);

    const res = await changeLifetime(client, 'tab');
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
    assert.deepStrictEqual(
        { anonLifetime: res.body.anonLifetime, anonInactivitySeconds: res.body.anonInactivitySeconds, anonExpiresAt: res.body.anonExpiresAt },
        { anonLifetime: 'tab', anonInactivitySeconds: 1800, anonExpiresAt: null }
    );

    const cookies = setCookies(res);
    assert.strictEqual(cookies.length, 1);
    assert.notStrictEqual(cookies[0].value, before.value);
    const header = res.headers.getSetCookie().find(h => h.startsWith('connect.sid='));
    assert.ok(!/expires=|max-age=/i.test(header), `кука tab должна быть сессионной: ${header}`);
    assert.strictEqual(cookies[0].expiresAt, null);
    // В «браузере» новая кука заменила прежнюю постоянную: теперь она сессионная.
    assert.strictEqual(sessionCookie(client).expiresAt, null);

    const row = await userRow(suite, user.id);
    assert.strictEqual(row.anon_lifetime, 'tab');
    assert.strictEqual(await sessionRow(suite, before.sid), null);
    assert.strictEqual((await spy.auth()).authenticated, false, 'копия недельной куки недействительна');
    const auth = await client.auth();
    assert.strictEqual(auth.user.anonLifetime, 'tab');
    assert.strictEqual(auth.user.anonExpiresAt, null);
});

test('тот же срок: запрос успешен, сессия всё равно пересоздаётся; для всех трёх значений ответ по формуле', async () => {
    for (const lifetime of ['tab', 'day', 'week']) {
        const { client, user, cookie: before } = await account(lifetime);
        const res = await changeLifetime(client, lifetime);
        assert.strictEqual(res.body.success, true, `${lifetime}: ${JSON.stringify(res.body)}`);
        const row = await userRow(suite, user.id);
        assert.strictEqual(res.body.anonLifetime, lifetime);
        assert.strictEqual(res.body.anonInactivitySeconds, LIFETIME_SECONDS[lifetime]);
        assert.strictEqual(res.body.anonExpiresAt, lifetime === 'tab' ? null : new Date(row.lastActiveMs + LIFETIME_MS[lifetime]).toISOString());
        assert.notStrictEqual(sessionCookie(client).sid, before.sid, `${lifetime}: sid пересоздан`);
        assert.strictEqual(await sessionRow(suite, before.sid), null);
        assert.strictEqual((await client.auth()).authenticated, true);
    }
});

test('новый срок отсчитывается от момента смены: аккаунт с трёхдневным молчанием при смене на day жив и получает свежую корзину', async () => {
    const { client, user } = await account('week');
    await suite.time.rewindUser(user.id, { lastActiveMs: 3 * DAY_MS });
    const stale = (await userRow(suite, user.id)).lastActiveMs;
    const t0 = Date.now();
    const res = await changeLifetime(client, 'day');
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
    const row = await userRow(suite, user.id);
    assert.ok(row.lastActiveMs > stale && row.lastActiveMs >= bucketCeil(t0), 'last_active_at обновлён на текущую корзину');
    assert.strictEqual(res.body.anonExpiresAt, new Date(row.lastActiveMs + LIFETIME_MS.day).toISOString());
    // Без этого сутки при молчании в три дня вышли бы сразу и чистка забрала бы аккаунт.
    await suite.server.waitForTick(2);
    assert.ok(await userRow(suite, user.id), 'аккаунт удалён чисткой сразу после смены срока');
    assert.strictEqual((await client.auth()).authenticated, true);
});

test('неверное или пропущенное значение — ошибка, ничего не меняется (умолчания «tab» нет)', async () => {
    const { client, user, cookie } = await account('week');
    const rowBefore = await userRow(suite, user.id);
    const bad = [
        ['пустая строка', { lifetime: '' }],
        ['неизвестное слово', { lifetime: 'month' }],
        ['другой регистр', { lifetime: 'Week' }],
        ['null', { lifetime: null }],
        ['число', { lifetime: 7 }],
        ['булево', { lifetime: true }],
        ['массив', { lifetime: ['tab'] }],
        ['объект', { lifetime: { value: 'tab' } }],
        ['поля нет', {}],
        ['чужое поле вместо lifetime', { anonLifetime: 'tab' }],
    ];
    for (const [what, body] of bad) {
        const res = await client.post('/api/user/lifetime', body);
        assert.strictEqual(res.body.success, false, `${what}: ${JSON.stringify(res.body)}`);
        assert.ok(typeof res.body.message === 'string' && res.body.message.length > 0, `${what}: нет текста ошибки`);
        assert.deepStrictEqual(setCookies(res), [], `${what}: сессию пересоздавать не из-за чего`);
    }
    // Тело вообще не JSON-объект.
    const raw = await client.post('/api/user/lifetime', undefined, { body: 'lifetime=tab', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    assert.strictEqual(raw.body.success, false);

    const rowAfter = await userRow(suite, user.id);
    assert.strictEqual(rowAfter.anon_lifetime, 'week', 'срок не съехал на умолчание');
    assert.strictEqual(rowAfter.lastActiveMs, rowBefore.lastActiveMs);
    assert.strictEqual(sessionCookie(client).sid, cookie.sid, 'сессия прежняя');
    assert.strictEqual((await client.auth()).user.anonLifetime, 'week');
});

test('без входа — ошибка; без CSRF-токена — 403', async () => {
    const guest = suite.client();
    const res = await changeLifetime(guest, 'week');
    assert.deepStrictEqual(res.body, { success: false, message: 'Не авторизован' });

    const { client, user } = await account('tab');
    const noToken = await client.post('/api/user/lifetime', { lifetime: 'week' }, { csrf: false });
    assert.strictEqual(noToken.status, 403);
    assert.strictEqual((await userRow(suite, user.id)).anon_lifetime, 'tab');
});

test('сокет: со старой кукой подключиться нельзя, с новой — можно (клиент переподключается после смены)', async () => {
    const { client, cookie: before } = await account('tab');
    const oldCookieHeader = `connect.sid=${before.value}`;
    const old = await client.socket({ cookie: oldCookieHeader });
    await old.close();

    const res = await changeLifetime(client, 'day');
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));

    await assert.rejects(
        client.socket({ cookie: oldCookieHeader }),
        (err) => err.kind === 'connect_error' && /Не авторизован/.test(err.reason || err.message),
        'сокет со старой кукой должен получить «Не авторизован»'
    );
    const fresh = await client.socket();
    try {
        assert.ok(fresh.connected, 'с новой кукой сокет подключается');
    } finally {
        await fresh.close();
    }
});

test('смена срока считается активностью и держится при перезапуске сервера', async () => {
    const { client, user } = await account('day');
    await changeLifetime(client, 'week');
    await suite.server.restart();
    const auth = await client.auth();
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.user.id, user.id);
    assert.strictEqual(auth.user.anonLifetime, 'week');
    assert.strictEqual(auth.user.anonInactivitySeconds, LIFETIME_SECONDS.week);
});
