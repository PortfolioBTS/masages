'use strict';
// Поток запросов мимо API (W7 R1 п.4): раньше /uploads/* и неизвестные пути вне /api/ шли без
// лимитера, а каждый запрос с кукой connect.sid ходил в Postgres за сессией (469 запросов в
// секунду на /uploads и 700 на неизвестные пути занимали пул). Теперь:
//   * сессия грузится только для /api и /uploads;
//   * у /uploads есть лимит по IP (до сессии) и по аккаунту (после неё).

const { test } = require('node:test');
const assert = require('assert');
const cookieSignature = require('cookie-signature');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('uploads-flood', { env: { UPLOADS_IP_PER_MIN: '50', UPLOADS_USER_PER_15MIN: '40' } });

const MISSING_FILE = '/uploads/00000000000000000000000000000000.jpg';

test('неизвестные пути вне /api не загружают сессию: таблица session заблокирована, а ответы идут без задержки', async () => {
    // Подписанная кука с неизвестным id сессии: express-session сверяет подпись и идёт в хранилище.
    const sid = 'a'.repeat(32);
    const cookie = `connect.sid=${encodeURIComponent('s:' + cookieSignature.sign(sid, suite.secrets.SESSION_SECRET))}`;
    const hit = (path) => fetch(`${suite.server.baseUrl}${path}`, { headers: { Cookie: cookie }, signal: AbortSignal.timeout(2000) });

    const locker = await suite.db.connect();
    try {
        await locker.query('BEGIN');
        await locker.query('LOCK TABLE session IN ACCESS EXCLUSIVE MODE');
        // Контроль: запрос, которому сессия нужна, зависает на хранилище.
        await assert.rejects(hit('/api/auth'), (err) => err.name === 'TimeoutError' || err.name === 'AbortError', 'API без сессии не отвечает, пока таблица занята');
        const started = Date.now();
        const results = await Promise.all(Array.from({ length: 30 }, (_, i) => hit(i % 2 ? '/definitely-not-here' : '/wp-login.php')));
        assert.ok(results.every(res => res.status === 404), results.map(res => res.status).join(','));
        await Promise.all(results.map(res => res.arrayBuffer()));
        assert.ok(Date.now() - started < 1500, 'ответы не ждут хранилище сессий');
    } finally {
        await locker.query('ROLLBACK').catch(() => {});
        locker.release();
    }
    // После снятия блокировки API снова отвечает.
    assert.strictEqual((await hit('/api/auth')).status, 200);
});

test('/uploads: лимит по IP - сверх 50 в минуту 429, другой IP не затронут', async () => {
    const flooder = suite.client({ xff: '10.99.0.1' });
    const statuses = [];
    for (let i = 0; i < 60; i++) statuses.push((await flooder.get(MISSING_FILE)).status);
    assert.ok(statuses.slice(0, 50).every(s => s === 401), `первые 50 доходят до обработчика: ${statuses.slice(0, 50)}`);
    assert.ok(statuses.slice(50).every(s => s === 429), `сверх лимита - 429: ${statuses.slice(50)}`);
    const limited = await flooder.get(MISSING_FILE);
    assert.match(limited.body.message, /Слишком много запросов/);
    assert.ok(limited.headers.get('ratelimit') || limited.headers.get('ratelimit-policy') || limited.headers.get('retry-after'), 'заголовки лимита есть');

    const other = suite.client({ xff: '10.99.0.2' });
    assert.strictEqual((await other.get(MISSING_FILE)).status, 401);
    // Лимит относится только к /uploads: API того же IP работает.
    assert.strictEqual((await flooder.get('/api/auth')).status, 200);
});

test('/uploads: лимит по аккаунту - сверх 40 за 15 минут 429, другой аккаунт не затронут', async () => {
    const heavy = suite.client({ xff: '10.99.1.1' });
    const light = suite.client({ xff: '10.99.1.2' });
    await heavy.registerAnon();
    await light.registerAnon();
    // IP меняется от запроса к запросу, чтобы лимит по IP не сработал раньше.
    const statuses = [];
    for (let i = 0; i < 46; i++) {
        statuses.push((await heavy.get(MISSING_FILE, { headers: { 'X-Forwarded-For': `10.99.2.${i % 10}` } })).status);
    }
    assert.ok(statuses.slice(0, 40).every(s => s === 403), `первые 40 - обычный отказ в доступе: ${statuses.slice(0, 40)}`);
    assert.ok(statuses.slice(40).every(s => s === 429), `сверх лимита - 429: ${statuses.slice(40)}`);
    assert.strictEqual((await light.get(MISSING_FILE)).status, 403, 'у другого аккаунта свой счёт');
    assert.strictEqual((await heavy.get('/api/chats')).status, 200, 'API того же аккаунта работает');
});
