'use strict';
// Продление сессий и огрубление времени в таблице session
// (lib/session-store.js): чистые функции, NyxoPgStore на поддельном пуле и
// настоящий express-session поверх него — Set-Cookie при продлении, кука tab
// без Expires, строка session с огрублённым сроком и без createdAt.
// Запуск: node test/session-renewal.test.js

const assert = require('assert');
const http = require('http');
const express = require('express');
const session = require('express-session');
const store = require('../lib/session-store');
const anon = require('../lib/anon-lifetime');

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

const MIN = 60 * 1000;
const STEP = 5 * MIN;
const DAY = 24 * 60 * MIN;

// Поддельный пул pg: таблица session в памяти и запросы, которые шлёт
// connect-pg-simple (get, destroy, чистка) и NyxoPgStore (set). Объект в
// параметре сериализуется в JSON — как это делает pg.
function makeFakeSessionPool() {
    const rows = new Map(); // sid -> { sess: JSON-строка, expireMs }
    const queries = [];
    return {
        rows,
        queries,
        stored: (sid) => JSON.parse(rows.get(sid).sess),
        async query(text, params = []) {
            const sql = text.replace(/\s+/g, ' ').trim();
            queries.push({ sql, params });
            if (sql.startsWith('INSERT INTO "session" (sess, expire, sid)')) {
                const [sess, expireSeconds, sid] = params;
                rows.set(sid, { sess: JSON.stringify(sess), expireMs: expireSeconds * 1000 });
                return { rows: [{ sid }], rowCount: 1 };
            }
            if (sql.startsWith('SELECT sess FROM "session" WHERE sid = $1')) {
                const [sid, nowSeconds] = params;
                const row = rows.get(sid);
                const live = row && row.expireMs >= nowSeconds * 1000;
                return { rows: live ? [{ sess: JSON.parse(row.sess) }] : [], rowCount: live ? 1 : 0 };
            }
            if (sql.startsWith('DELETE FROM "session" WHERE sid = $1')) {
                const existed = rows.delete(params[0]);
                return { rows: [], rowCount: existed ? 1 : 0 };
            }
            if (sql.startsWith('DELETE FROM "session" WHERE expire < to_timestamp($1)')) {
                for (const [sid, row] of rows) if (row.expireMs < params[0] * 1000) rows.delete(sid);
                return { rows: [], rowCount: 0 };
            }
            throw new Error(`неожиданный запрос: ${sql}`);
        },
    };
}

const inserts = (pool) => pool.queries.filter(q => q.sql.startsWith('INSERT INTO "session"'));

function listen(app) {
    return new Promise((resolve) => {
        const server = http.createServer(app).listen(0, '127.0.0.1', () => resolve(server));
    });
}

function request(server, { method = 'GET', path = '/', cookie } = {}) {
    return new Promise((resolve, reject) => {
        const headers = cookie ? { cookie } : {};
        const req = http.request({ host: '127.0.0.1', port: server.address().port, method, path, headers }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        req.on('error', reject);
        req.end();
    });
}

const sessionCookie = (res) => (res.headers['set-cookie'] || []).find(c => c.startsWith('connect.sid='));
const sidOf = (setCookie) => decodeURIComponent(setCookie.split(';')[0].slice('connect.sid='.length)).slice(2).split('.')[0];

async function main() {
    console.log('Session renewal tests\n');

    await test('coarseSessionForStore: expires and originalMaxAge rounded up to 5 minutes, createdAt dropped, original untouched', () => {
        const cookie = new session.Cookie({ path: '/', httpOnly: true, sameSite: 'lax' });
        cookie.maxAge = anon.anonCookieMaxAgeMs('day');
        cookie.originalMaxAge = anon.anonCookieMaxAgeMs('day') - 1; // как после сеттера maxAge
        const sess = { cookie, userId: 42, isAnonymous: true, anonLifetime: 'day', createdAt: 1790630152260, renewBucket: 7 };
        const stored = store.coarseSessionForStore(sess);
        assert.strictEqual('createdAt' in stored, false);
        assert.strictEqual(sess.createdAt, 1790630152260, 'the session itself keeps its fields');
        const expires = Date.parse(stored.cookie.expires);
        assert.strictEqual(expires % STEP, 0, 'expires on a 5-minute boundary');
        assert.ok(expires >= cookie.expires.getTime() && expires < cookie.expires.getTime() + STEP, 'rounded up, not down');
        assert.strictEqual(stored.cookie.originalMaxAge, DAY + 15 * MIN, 'constant: lifetime + 15 minutes');
        assert.deepStrictEqual(
            { userId: stored.userId, isAnonymous: stored.isAnonymous, anonLifetime: stored.anonLifetime, renewBucket: stored.renewBucket },
            { userId: 42, isAnonymous: true, anonLifetime: 'day', renewBucket: 7 }
        );
        // Кука без срока (tab) — expires и originalMaxAge остаются null.
        const tabCookie = new session.Cookie({ path: '/', httpOnly: true });
        tabCookie.maxAge = null;
        const tab = store.coarseSessionForStore({ cookie: tabCookie, userId: 1, isAnonymous: true });
        assert.strictEqual(tab.cookie.expires, null);
        assert.strictEqual(tab.cookie.originalMaxAge, null);
    });

    await test('sessionRowExpireMs: cookie expiry, otherwise now + 24 h — both on a 5-minute boundary', () => {
        const now = Date.parse('2026-10-03T12:01:01Z');
        assert.strictEqual(store.SESSION_TTL_MS, DAY);
        assert.strictEqual(store.sessionRowExpireMs({ cookie: { expires: null } }, { now }), Date.parse('2026-10-04T12:05:00Z'));
        assert.strictEqual(store.sessionRowExpireMs({ cookie: {} }, { now }), Date.parse('2026-10-04T12:05:00Z'));
        assert.strictEqual(store.sessionRowExpireMs({ cookie: { expires: '2026-10-05T08:00:00.000Z' } }, { now }), Date.parse('2026-10-05T08:00:00Z'));
        assert.strictEqual(store.sessionRowExpireMs({ cookie: { expires: '2026-10-05T08:00:00.001Z' } }, { now }), Date.parse('2026-10-05T08:05:00Z'));
    });

    await test('NyxoPgStore.set: coarse copy and coarse row expiry; get/destroy are the library ones', async () => {
        const pool = makeFakeSessionPool();
        const now = Date.parse('2026-10-03T12:01:01Z');
        const NyxoPgStore = store.createNyxoPgStore(session, { now: () => now });
        const pgStore = new NyxoPgStore({ pool, tableName: 'session', disableTouch: true, pruneSessionInterval: false });
        const tabCookie = new session.Cookie({ path: '/', httpOnly: true });
        tabCookie.maxAge = null;
        await new Promise((resolve, reject) => pgStore.set('sid-tab', { cookie: tabCookie, userId: 5, isAnonymous: true, createdAt: now }, (err) => (err ? reject(err) : resolve())));
        assert.strictEqual(pool.rows.get('sid-tab').expireMs, Date.parse('2026-10-04T12:05:00Z'), 'tab: now + 24 h, rounded up');
        assert.strictEqual('createdAt' in pool.stored('sid-tab'), false);
        assert.strictEqual(pool.stored('sid-tab').cookie.expires, null);

        const weekCookie = new session.Cookie({ path: '/', httpOnly: true });
        store.setSessionCookieLifetime(weekCookie, 'week');
        await new Promise((resolve, reject) => pgStore.set('sid-week', { cookie: weekCookie, userId: 6, isAnonymous: true }, (err) => (err ? reject(err) : resolve())));
        const row = pool.rows.get('sid-week');
        assert.strictEqual(row.expireMs % STEP, 0);
        assert.strictEqual(new Date(row.expireMs).toISOString(), pool.stored('sid-week').cookie.expires, 'row expiry = coarse cookie expiry');

        const loaded = await new Promise((resolve, reject) => pgStore.get('sid-week', (err, sess) => (err ? reject(err) : resolve(sess))));
        assert.strictEqual(loaded.userId, 6);
        await new Promise((resolve, reject) => pgStore.destroy('sid-week', (err) => (err ? reject(err) : resolve())));
        assert.strictEqual(pool.rows.has('sid-week'), false);
    });

    await test('renewSession: marker once per interval; cookie by lifetime; lifetime synced from the account', () => {
        const interval = 5 * MIN;
        const t0 = Date.parse('2026-10-03T12:00:00Z');
        const cookie = new session.Cookie({ path: '/', httpOnly: true });
        cookie.maxAge = 24 * 60 * MIN; // кука новой сессии по умолчанию
        const sess = { cookie, userId: 1, isAnonymous: true, anonLifetime: 'day' };
        assert.strictEqual(store.renewSession(sess, { lifetime: 'day', now: t0, intervalMs: interval }), true);
        assert.strictEqual(sess.renewBucket, anon.renewBucket(t0, interval));
        assert.strictEqual(sess.cookie.originalMaxAge, DAY + 15 * MIN);
        const left = sess.cookie.expires.getTime() - Date.now();
        assert.ok(left > DAY + 14 * MIN && left <= DAY + 15 * MIN, 'day cookie = 24 h + 15 min');
        assert.strictEqual(store.renewSession(sess, { lifetime: 'day', now: t0 + interval - 1, intervalMs: interval }), false, 'same interval');
        assert.strictEqual(store.renewSession(sess, { lifetime: 'day', now: t0 + interval, intervalMs: interval }), true, 'next interval');
        // Срок сменили в другой сессии: сессия и кука подстраиваются.
        assert.strictEqual(store.renewSession(sess, { lifetime: 'tab', now: t0 + 2 * interval, intervalMs: interval }), true);
        assert.strictEqual(sess.anonLifetime, 'tab');
        assert.strictEqual(sess.cookie.expires, null, 'tab — cookie without Expires');
        assert.strictEqual(sess.cookie.originalMaxAge, null);
    });

    await test('extendTabSessions: one UPDATE for online users, only sessions without cookie expiry, GREATEST', async () => {
        const calls = [];
        const dbRun = async (sql, params) => { calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params }); return { rowCount: 2 }; };
        const now = Date.parse('2026-10-03T12:01:01Z');
        assert.strictEqual(await store.extendTabSessions(dbRun, [], { now }), 0);
        assert.strictEqual(await store.extendTabSessions(dbRun, [0, -1, 1.5, '7'], { now }), 0, 'only positive integer ids');
        assert.strictEqual(calls.length, 0, 'nothing to extend — no query');
        assert.strictEqual(await store.extendTabSessions(dbRun, [7, 9, 7], { now }), 2);
        assert.strictEqual(calls.length, 1);
        assert.match(calls[0].sql, /^UPDATE session SET expire = GREATEST\(expire, to_timestamp\(\$2\)\)/);
        assert.match(calls[0].sql, /sess->>'userId' = ANY\(\$1::text\[\]\)/);
        assert.match(calls[0].sql, /sess->'cookie'->>'expires' IS NULL/);
        assert.deepStrictEqual(calls[0].params, [['7', '9'], Date.parse('2026-10-04T12:05:00Z') / 1000]);
    });

    // ---- настоящий express-session поверх NyxoPgStore ----

    const pool = makeFakeSessionPool();
    const NyxoPgStore = store.createNyxoPgStore(session);
    const interval = 60 * 1000;
    let clock = Date.parse('2026-10-03T12:00:00Z');
    const app = express();
    app.use(session({
        store: new NyxoPgStore({ pool, tableName: 'session', disableTouch: true, pruneSessionInterval: false }),
        secret: 'test-secret', resave: false, saveUninitialized: false,
        cookie: { maxAge: DAY, httpOnly: true, sameSite: 'lax', secure: false },
    }));
    // Продление — как в server.js: маркер раз в интервал.
    app.use((req, res, next) => {
        if (req.session.userId) store.renewSession(req.session, { lifetime: req.session.anonLifetime, now: clock, intervalMs: interval });
        next();
    });
    app.post('/start/:lifetime', (req, res, next) => {
        const lifetime = req.params.lifetime;
        req.session.regenerate((err) => {
            if (err) return next(err);
            Object.assign(req.session, {
                userId: 77, isAnonymous: true, anonLifetime: lifetime,
                renewBucket: anon.renewBucket(clock, interval), createdAt: clock,
            });
            store.setSessionCookieLifetime(req.session.cookie, lifetime);
            res.json({ ok: true });
        });
    });
    app.get('/ping', (req, res) => res.json({ userId: req.session.userId || null }));
    const server = await listen(app);

    try {
        await test('express-session: day — Set-Cookie with Expires on start and on renewal, none within the same interval', async () => {
            const started = await request(server, { method: 'POST', path: '/start/day' });
            const setCookie = sessionCookie(started);
            assert.ok(setCookie, 'session cookie issued');
            const expires = Date.parse(/Expires=([^;]+)/.exec(setCookie)[1]);
            assert.ok(Math.abs(expires - (Date.now() + DAY + 15 * MIN)) < 5000, 'Expires = now + 24 h 15 min');
            const sid = sidOf(setCookie);
            const cookie = setCookie.split(';')[0];
            const row = pool.rows.get(sid);
            assert.strictEqual(row.expireMs % STEP, 0, 'row expiry rounded to 5 minutes');
            assert.ok(row.expireMs >= expires - 1000, 'row lives at least as long as the cookie');
            assert.strictEqual('createdAt' in pool.stored(sid), false, 'createdAt is not stored');

            const before = inserts(pool).length;
            const same = await request(server, { path: '/ping', cookie });
            assert.strictEqual(JSON.parse(same.body).userId, 77);
            assert.strictEqual(sessionCookie(same), undefined, 'same interval — no Set-Cookie');
            assert.strictEqual(inserts(pool).length, before, 'same interval — no write to session');

            clock += interval;
            const renewed = await request(server, { path: '/ping', cookie });
            const again = sessionCookie(renewed);
            assert.ok(again && /Expires=/.test(again), 'next interval — Set-Cookie with Expires');
            assert.strictEqual(sidOf(again), sid, 'the same session id');
            assert.strictEqual(inserts(pool).length, before + 1, 'next interval — the row is rewritten');
            assert.strictEqual(pool.stored(sid).renewBucket, anon.renewBucket(clock, interval));
        });

        await test('express-session: tab — cookie without Expires; renewal rewrites the row (24 h) without Set-Cookie', async () => {
            const started = await request(server, { method: 'POST', path: '/start/tab' });
            const setCookie = sessionCookie(started);
            assert.ok(setCookie, 'session cookie issued');
            assert.doesNotMatch(setCookie, /Expires=|Max-Age=/i, 'browser-session cookie');
            const sid = sidOf(setCookie);
            const cookie = setCookie.split(';')[0];
            const firstExpire = pool.rows.get(sid).expireMs;
            assert.ok(Math.abs(firstExpire - (Date.now() + DAY)) <= STEP + 5000, 'row: now + 24 h');

            clock += interval;
            const before = inserts(pool).length;
            const renewed = await request(server, { path: '/ping', cookie });
            assert.strictEqual(JSON.parse(renewed.body).userId, 77);
            assert.strictEqual(sessionCookie(renewed), undefined, 'tab cookie is never re-sent');
            assert.strictEqual(inserts(pool).length, before + 1, 'but the row is rewritten');
            assert.strictEqual(pool.stored(sid).cookie.expires, null);
        });
    } finally {
        server.close();
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
