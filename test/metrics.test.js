'use strict';
// Тесты lib/metrics.js и lib/routes/health.js (7.6): формат Prometheus,
// метки только по шаблонам маршрутов (никаких id и путей с параметрами),
// ограничение числа серий, /healthz, /readyz и /metrics с токеном.
// Чистый Node: Express поднимается на loopback, база подменена.
// Запуск: node test/metrics.test.js

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const express = require('express');
const { createMetrics, routeLabel, MAX_SERIES } = require('../lib/metrics');
const health = require('../lib/routes/health');
const { PRE_SESSION_ROUTES } = require('../lib/routes');
const { createJobScheduler } = require('../lib/jobs');

const TOR_PATH = path.join(__dirname, '..', 'lib', 'tor-support.js');

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

async function withApp(app, fn) {
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
        server.closeAllConnections();
    }
}

// Значение серии: строка вида name{labels} → число.
function sample(text, selector) {
    const line = text.split('\n').find(l => l.startsWith(selector + ' '));
    return line === undefined ? undefined : Number(line.slice(selector.length + 1));
}

const TOKEN = 'm'.repeat(48);

function healthApp({ ctx, metrics }) {
    const app = express();
    if (metrics) app.use(metrics.httpMiddleware());
    health.register(app, ctx);
    return app;
}

async function main() {
    console.log('Metrics / health tests\n');

    // ---------------------------------------------------------------- формат
    await test('формат: HELP/TYPE, счётчик с метками, экранирование, гистограмма накопительная', () => {
        const metrics = createMetrics();
        const c = metrics.counter('test_events_total', 'Строка\nс переносом', ['kind']);
        c.inc({ kind: 'a"b\\c\nd' });
        c.inc({ kind: 'a"b\\c\nd' }, 2);
        const h = metrics.histogram('test_duration_seconds', 'Время', ['route'], [0.1, 1]);
        h.observe({ route: '/x' }, 0.05);
        h.observe({ route: '/x' }, 0.5);
        h.observe({ route: '/x' }, 5);
        const text = metrics.render();
        assert.ok(text.endsWith('\n'));
        assert.match(text, /# HELP test_events_total Строка\\nс переносом\n# TYPE test_events_total counter\n/);
        assert.match(text, /test_events_total\{kind="a\\"b\\\\c\\nd"\} 3\n/);
        assert.strictEqual(sample(text, 'test_duration_seconds_bucket{route="/x",le="0.1"}'), 1);
        assert.strictEqual(sample(text, 'test_duration_seconds_bucket{route="/x",le="1"}'), 2);
        assert.strictEqual(sample(text, 'test_duration_seconds_bucket{route="/x",le="+Inf"}'), 3);
        assert.strictEqual(sample(text, 'test_duration_seconds_count{route="/x"}'), 3);
        assert.ok(Math.abs(sample(text, 'test_duration_seconds_sum{route="/x"}') - 5.55) < 1e-9);
        metrics.stop();
    });

    await test('некорректные имена и повторная регистрация отвергаются', () => {
        const metrics = createMetrics();
        assert.throws(() => metrics.counter('1bad', 'x'), TypeError);
        assert.throws(() => metrics.counter('ok_total', 'x', ['bad-label']), TypeError);
        assert.throws(() => metrics.histogram('h_seconds', 'x', ['le']), TypeError);
        metrics.counter('dup_total', 'x');
        assert.throws(() => metrics.counter('dup_total', 'x'), /уже есть/);
        metrics.stop();
    });

    await test('число серий ограничено: лишние значения меток сливаются в «other»', () => {
        const metrics = createMetrics();
        const c = metrics.counter('cap_total', 'x', ['v']);
        for (let i = 0; i < MAX_SERIES + 50; i++) c.inc({ v: `value-${i}` });
        const lines = metrics.render().split('\n').filter(l => l.startsWith('cap_total{'));
        assert.strictEqual(lines.length, MAX_SERIES + 1);
        assert.strictEqual(sample(metrics.render(), 'cap_total{v="other"}'), 50);
        c.inc({ v: 'x'.repeat(500) }); // длинное значение обрезается, а не раздувает вывод
        assert.ok(!metrics.render().includes('x'.repeat(100)));
        metrics.stop();
    });

    await test('процесс и внешние источники: uptime, память, пул Postgres, сокеты', () => {
        let nowMs = 1_000_000;
        const metrics = createMetrics({ now: () => nowMs, startedAt: 1_000_000 - 90_000 });
        metrics.attachRuntime({ pool: { totalCount: 4, idleCount: 3, waitingCount: 1 }, io: { engine: { clientsCount: 7 } } });
        const text = metrics.render();
        assert.strictEqual(sample(text, 'nyxo_uptime_seconds'), 90);
        assert.ok(sample(text, 'nyxo_process_memory_bytes{kind="rss"}') > 0);
        assert.ok(sample(text, 'nyxo_process_cpu_seconds_total{mode="user"}') >= 0);
        assert.strictEqual(sample(text, 'nyxo_pg_pool_connections{state="total"}'), 4);
        assert.strictEqual(sample(text, 'nyxo_pg_pool_connections{state="waiting"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_sockets_connected'), 7);
        assert.match(text, /# TYPE nyxo_eventloop_lag_seconds gauge/);
        metrics.stop();
    });

    await test('события приложения: имена метрик и метки', () => {
        const metrics = createMetrics();
        metrics.rateLimited('register');
        metrics.limitStoreError('register');
        metrics.powRejected('replayed');
        metrics.csrfRejected();
        metrics.originRejected();
        metrics.registered();
        metrics.accountsDeleted('expired', 3);
        metrics.accountsDeleted('expired', 0);
        metrics.jobRan('purgeExpiredLimits', true);
        metrics.jobRan('purgeExpiredLimits', false);
        const text = metrics.render();
        assert.strictEqual(sample(text, 'nyxo_rate_limited_total{limiter="register"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_limits_store_errors_total{limiter="register"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_pow_rejected_total{reason="replayed"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_csrf_rejected_total'), 1);
        assert.strictEqual(sample(text, 'nyxo_origin_rejected_total'), 1);
        assert.strictEqual(sample(text, 'nyxo_registrations_total'), 1);
        assert.strictEqual(sample(text, 'nyxo_account_deletions_total{reason="expired"}'), 3);
        assert.strictEqual(sample(text, 'nyxo_job_runs_total{job="purgeExpiredLimits",result="ok"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_job_runs_total{job="purgeExpiredLimits",result="skipped"}'), 1);
        metrics.stop();
    });

    // ------------------------------------------------------------------ HTTP
    await test('HTTP: метка маршрута — шаблон, а не адрес запроса; id нигде не видны', async () => {
        const metrics = createMetrics();
        const app = express();
        app.use(metrics.httpMiddleware());
        app.get('/api/messages/:messageId', (req, res) => res.json({ success: req.params.messageId !== '404' }));
        app.get('/api/chats/:chatId/participants', (req, res) => res.json({ success: true }));
        app.get('/plain', (req, res) => res.send('x'));
        app.get('/boom', (req, res) => res.status(500).send('x'));
        app.use('/api', (req, res) => res.status(404).json({ success: false }));
        app.use((req, res) => res.status(404).send('нет'));
        const secretIds = ['1955890954', '1234567890', '2000000011'];
        await withApp(app, async (base) => {
            for (const id of secretIds) {
                await (await fetch(`${base}/api/messages/${id}?userId=${id}`)).arrayBuffer();
                await (await fetch(`${base}/api/chats/${id}/participants`)).arrayBuffer();
                await (await fetch(`${base}/api/unknown/${id}`)).arrayBuffer();
                await (await fetch(`${base}/static/${id}.png`)).arrayBuffer();
            }
            await (await fetch(`${base}/api/messages/404`)).arrayBuffer();
            await (await fetch(`${base}/plain`)).arrayBuffer();
            await (await fetch(`${base}/boom`)).arrayBuffer();
            await (await fetch(`${base}/plain`, { method: 'POST' })).arrayBuffer();
        });
        const text = metrics.render();
        for (const id of secretIds) assert.ok(!text.includes(id), `id ${id} попал в метрики`);
        assert.ok(!text.includes('userId'), 'query-строка не должна попадать в метрики');
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="/api/messages/:messageId",status="2xx",outcome="ok"}'), 3);
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="/api/messages/:messageId",status="2xx",outcome="fail"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="/api/chats/:chatId/participants",status="2xx",outcome="ok"}'), 3);
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="/api/(unmatched)",status="4xx",outcome="fail"}'), 3);
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="(static)",status="4xx",outcome="none"}'), 3);
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="/boom",status="5xx",outcome="none"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="POST",route="(static)",status="4xx",outcome="none"}'), 1);
        assert.strictEqual(sample(text, 'nyxo_http_request_duration_seconds_count{route="/plain"}'), 1);
        metrics.stop();
    });

    await test('HTTP: нестандартный метод — «OTHER», оборванный запрос — «aborted»', async () => {
        const metrics = createMetrics();
        const app = express();
        app.use(metrics.httpMiddleware());
        app.get('/slow', () => {});
        await withApp(app, async (base) => {
            const controller = new AbortController();
            const pending = fetch(`${base}/slow`, { signal: controller.signal }).catch(() => {});
            await new Promise(resolve => setTimeout(resolve, 100));
            controller.abort();
            await pending;
            await new Promise(resolve => setTimeout(resolve, 100));
            const odd = await fetch(`${base}/x`, { method: 'PROPFIND' });
            await odd.arrayBuffer();
        });
        const text = metrics.render();
        assert.strictEqual(sample(text, 'nyxo_http_requests_total{method="GET",route="/slow",status="aborted",outcome="none"}'), 1);
        assert.match(text, /nyxo_http_requests_total\{method="OTHER",route="\(static\)"/);
        metrics.stop();
    });

    await test('routeLabel: маршрут, сокет, неизвестный API, остальное', () => {
        assert.strictEqual(routeLabel({ route: { path: '/a/:id' }, baseUrl: '' }), '/a/:id');
        assert.strictEqual(routeLabel({ route: { path: '/a/:id' }, baseUrl: '/api' }), '/api/a/:id');
        assert.strictEqual(routeLabel({ route: { path: /x/ } }), '/x/');
        assert.strictEqual(routeLabel({ originalUrl: '/socket.io/?EIO=4&sid=secret' }), '/socket.io/');
        assert.strictEqual(routeLabel({ originalUrl: '/api/nothing/123' }), '/api/(unmatched)');
        assert.strictEqual(routeLabel({ originalUrl: '/app.js?x=1' }), '(static)');
    });

    // ---------------------------------------------------------------- health
    await test('/healthz: 200 {status:"ok"} без обращения к базе; /readyz: starting → ok → unavailable', async () => {
        let queries = 0;
        const ctx = {
            readiness: { migrated: false },
            pool: { query: async () => { queries++; if (ctx.fail) throw new Error('database "secret-name" is down'); return { rows: [{ '?column?': 1 }] }; } },
        };
        const logs = [];
        const original = console.error;
        console.error = (...args) => logs.push(args.join(' '));
        try {
            await withApp(healthApp({ ctx }), async (base) => {
                const healthz = await fetch(`${base}/healthz`);
                assert.strictEqual(healthz.status, 200);
                assert.deepStrictEqual(await healthz.json(), { status: 'ok' });
                assert.strictEqual(queries, 0);

                const starting = await fetch(`${base}/readyz`);
                assert.strictEqual(starting.status, 503);
                assert.deepStrictEqual(await starting.json(), { status: 'starting' });
                assert.strictEqual(queries, 0, 'до конца миграций к базе не ходим');

                ctx.readiness.migrated = true;
                const ready = await fetch(`${base}/readyz`);
                assert.strictEqual(ready.status, 200);
                assert.deepStrictEqual(await ready.json(), { status: 'ok' });
                assert.strictEqual(queries, 1);

                ctx.fail = true;
                const down = await fetch(`${base}/readyz`);
                assert.strictEqual(down.status, 503);
                const body = await down.text();
                assert.deepStrictEqual(JSON.parse(body), { status: 'unavailable' });
                assert.ok(!body.includes('secret-name'), 'причина сбоя не уходит в ответ');
                assert.ok(logs.some(l => l.includes('database "secret-name" is down')), 'причина — в логе');

                // /healthz жив и при упавшей базе.
                assert.strictEqual((await fetch(`${base}/healthz`)).status, 200);
            });
        } finally {
            console.error = original;
        }
    });

    await test('/readyz: база не отвечает дольше 2 секунд — 503', async () => {
        const ctx = { readiness: { migrated: true }, pool: { query: () => new Promise(() => {}) } };
        const original = console.error;
        console.error = () => {};
        try {
            await withApp(healthApp({ ctx }), async (base) => {
                const started = Date.now();
                const res = await fetch(`${base}/readyz`);
                assert.strictEqual(res.status, 503);
                const took = Date.now() - started;
                assert.ok(took >= health.READY_TIMEOUT_MS - 50 && took < health.READY_TIMEOUT_MS + 1500, `ответ за ${took} мс`);
            });
        } finally {
            console.error = original;
        }
    });

    await test('/metrics: только с Bearer-токеном, иначе обычный 404; без METRICS_TOKEN отключён', async () => {
        const metrics = createMetrics();
        metrics.registered();
        const ctx = { metrics, env: { METRICS_TOKEN: TOKEN }, readiness: { migrated: true } };
        const app = healthApp({ ctx, metrics });
        app.use((req, res) => res.status(404).send('обычный 404'));
        await withApp(app, async (base) => {
            const get = (headers) => fetch(`${base}/metrics`, { headers });
            const ok = await get({ Authorization: `Bearer ${TOKEN}` });
            assert.strictEqual(ok.status, 200);
            const type = ok.headers.get('content-type'); // Express сам упорядочивает параметры
            assert.ok(type.startsWith('text/plain;') && type.includes('version=0.0.4') && type.includes('charset=utf-8'), type);
            assert.match(await ok.text(), /nyxo_registrations_total 1/);
            assert.strictEqual((await get({ Authorization: `bearer   ${TOKEN}` })).status, 200, 'схема без учёта регистра');

            for (const headers of [
                {}, { Authorization: 'Bearer wrong' }, { Authorization: `Bearer ${TOKEN}x` }, { Authorization: `Bearer ${TOKEN.slice(1)}` },
                { Authorization: TOKEN }, { Authorization: `Basic ${TOKEN}` }, { Authorization: 'Bearer ' }, { Authorization: `Bearer ${TOKEN} extra` },
            ]) {
                const res = await get(headers);
                assert.strictEqual(res.status, 404, JSON.stringify(headers));
                assert.strictEqual(await res.text(), 'обычный 404', 'ответ неотличим от несуществующего адреса');
            }
            // Токен — не в адресе и не в query.
            assert.strictEqual((await fetch(`${base}/metrics?token=${TOKEN}`)).status, 404);

            ctx.env = {};
            assert.strictEqual((await get({ Authorization: `Bearer ${TOKEN}` })).status, 404, 'токен не задан — отключено');
            assert.strictEqual((await get({ Authorization: 'Bearer ' })).status, 404);
        });
        metrics.stop();
    });

    await test('tokenMatches: пустой токен никогда не подходит', () => {
        assert.strictEqual(health.tokenMatches('Bearer x', ''), false);
        assert.strictEqual(health.tokenMatches('Bearer x', undefined), false);
        assert.strictEqual(health.tokenMatches(undefined, 'x'), false);
        assert.strictEqual(health.tokenMatches('Bearer x', 'x'), true);
    });

    await test('health-маршруты подключены в PRE_SESSION_ROUTES', () => {
        assert.ok(PRE_SESSION_ROUTES.includes(health));
        const routes = [];
        health.register({ get: (p) => routes.push(p) }, {});
        assert.deepStrictEqual(routes, ['/healthz', '/readyz', '/metrics']);
    });

    await test('планировщик задач сообщает метрикам о проходе (onRun); сбой хука на задачу не влияет', async () => {
        const seen = [];
        const reported = [];
        const jobs = createJobScheduler({
            runExclusive: async (name, fn) => { if (name === 'skipped') return false; await fn(); return true; },
            onRun: (name, ran) => { seen.push([name, ran]); if (name === 'bad-hook') throw new Error('hook'); },
            report: (context) => reported.push(context),
            log: () => {},
        });
        jobs.register({ name: 'normal', run: () => {} });
        jobs.register({ name: 'skipped', run: () => {} });
        jobs.register({ name: 'local', run: () => {}, exclusive: false });
        jobs.register({ name: 'bad-hook', run: () => {} });
        assert.strictEqual(await jobs.runJob('normal'), true);
        assert.strictEqual(await jobs.runJob('skipped'), false);
        assert.strictEqual(await jobs.runJob('local'), true);
        assert.strictEqual(await jobs.runJob('bad-hook'), true);
        assert.deepStrictEqual(seen, [['normal', true], ['skipped', false], ['local', true], ['bad-hook', true]]);
        assert.deepStrictEqual(reported, ['[Jobs] onRun']);
    });

    // ----------------------------------------------------------- Onion-Location
    await test('Onion-Location не ставится на служебные адреса, но остаётся на страницах', () => {
        const key = crypto.createHash('sha256').update('metrics-test').digest();
        const version = Buffer.from([3]);
        const checksum = crypto.createHash('sha3-256').update('.onion checksum').update(key).update(version).digest().subarray(0, 2);
        const bytes = Buffer.concat([key, checksum, version]);
        const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
        let bits = '';
        for (const b of bytes) bits += b.toString(2).padStart(8, '0');
        let address = '';
        for (let i = 0; i < bits.length; i += 5) address += alphabet[parseInt(bits.slice(i, i + 5), 2)];
        const saved = { ONION_ADDRESS: process.env.ONION_ADDRESS, ONION_PORT: process.env.ONION_PORT };
        process.env.ONION_ADDRESS = `${address}.onion`;
        process.env.ONION_PORT = '3001';
        delete require.cache[require.resolve(TOR_PATH)];
        let tor;
        try {
            tor = require(TOR_PATH);
        } finally {
            for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
            delete require.cache[require.resolve(TOR_PATH)];
        }
        const headerFor = (url) => {
            const headers = {};
            tor.onionMiddleware(
                { method: 'GET', url, originalUrl: url, headers: {}, socket: {} },
                { setHeader: (name, value) => { headers[name.toLowerCase()] = value; } },
                () => {}
            );
            return headers['onion-location'];
        };
        assert.strictEqual(headerFor('/'), `http://${address}.onion/`);
        assert.strictEqual(headerFor('/link.my'), `http://${address}.onion/link.my`);
        for (const url of ['/healthz', '/readyz', '/metrics', '/security.txt', '/.well-known/security.txt', '/api/auth']) {
            assert.strictEqual(headerFor(url), undefined, url);
        }
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
