'use strict';
// security.txt (8.4, RFC 9116): lib/security-txt.js, маршруты
// lib/routes/well-known.js и предупреждения env-check. Express — на loopback.
// Запуск: node test/security-txt.test.js

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const {
    DEFAULT_CONTACT,
    POLICY_URL,
    isValidContact,
    parseContacts,
    parsePublicOrigin,
    resolveExpires,
    resolveSecurityTxtConfig,
    buildSecurityTxt,
} = require('../lib/security-txt');
const wellKnown = require('../lib/routes/well-known');
const { PRE_SESSION_ROUTES } = require('../lib/routes');
const { checkEnv } = require('../lib/env-check');

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

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 9, 9, 15, 30, 0);
const field = (text, name) => text.split('\n').filter(line => line.startsWith(`${name}: `)).map(line => line.slice(name.length + 2));

async function withApp(env, fn) {
    const app = express();
    // Как в server.js: глобальные заголовки закрывают кэш.
    app.use((req, res, next) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.set('Surrogate-Control', 'no-store');
        res.set('Cross-Origin-Resource-Policy', 'same-origin');
        next();
    });
    wellKnown.register(app, { env });
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
        server.closeAllConnections();
    }
}

const rnd = (n = 32) => crypto.randomBytes(n).toString('base64url');
function goodEnv(extra = {}) {
    return Object.assign({
        SESSION_SECRET: rnd(48),
        MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
        // Ключ журнала ключей: без него в production есть предупреждение «журнал выключен».
        KT_SIGNING_KEY: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
        DATABASE_URL: `postgresql://postgres:${rnd(24)}@postgres.railway.internal:5432/railway`,
        NODE_ENV: 'production',
        RAILWAY_ENVIRONMENT_NAME: 'production',
        RAILWAY_VOLUME_MOUNT_PATH: '/data',
    }, extra);
}

async function main() {
    console.log('security.txt tests\n');

    await test('по умолчанию: Contact — GitHub Security Advisories, Expires — скользящий, ru/en, Policy на SECURITY.md', () => {
        const text = buildSecurityTxt(resolveSecurityTxtConfig({}, { now: NOW }), NOW);
        assert.deepStrictEqual(field(text, 'Contact'), ['https://github.com/PortfolioBTS/masages/security/advisories/new']);
        assert.strictEqual(DEFAULT_CONTACT, field(text, 'Contact')[0]);
        assert.deepStrictEqual(field(text, 'Preferred-Languages'), ['ru, en']);
        assert.deepStrictEqual(field(text, 'Policy'), [POLICY_URL]);
        assert.match(POLICY_URL, /\/SECURITY\.md$/);
        assert.deepStrictEqual(field(text, 'Canonical'), [], 'без PUBLIC_ORIGIN Canonical не выводится, Host не используется');
        assert.ok(text.endsWith('\n') && !text.includes('\r'), 'LF-строки, перевод строки в конце');
        // Скользящий срок: конец суток через 180 дней (RFC: меньше года, в будущем).
        const [expires] = field(text, 'Expires');
        assert.strictEqual(expires, '2027-04-07T00:00:00Z');
        assert.ok(Date.parse(expires) - NOW >= 179 * DAY && Date.parse(expires) - NOW <= 180 * DAY);
        assert.match(expires, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    });

    await test('обязательные поля RFC 9116 на месте и каждое — по одному разу (Expires)', () => {
        const text = buildSecurityTxt(resolveSecurityTxtConfig({ SECURITY_CONTACT: 'mailto:sec@example.org, https://example.org/report' }, { now: NOW }), NOW);
        assert.deepStrictEqual(field(text, 'Contact'), ['mailto:sec@example.org', 'https://example.org/report']);
        assert.strictEqual(field(text, 'Expires').length, 1);
        assert.ok(text.indexOf('Contact:') < text.indexOf('Expires:'));
    });

    await test('скользящий срок следует за временем запроса и всегда в будущем', () => {
        const config = resolveSecurityTxtConfig({}, { now: NOW });
        for (const shift of [0, 1, 40, 365, 1000, 5000]) {
            const now = NOW + shift * DAY;
            const expires = Date.parse(field(buildSecurityTxt(config, now), 'Expires')[0]);
            assert.ok(expires > now + 170 * DAY && expires < now + 181 * DAY, `сдвиг ${shift} дн.`);
        }
    });

    await test('Canonical: из PUBLIC_ORIGIN (только https без пути) и из onion', () => {
        const withOrigin = buildSecurityTxt(resolveSecurityTxtConfig({ PUBLIC_ORIGIN: 'https://nyxo.example' }, { now: NOW }), NOW);
        assert.deepStrictEqual(field(withOrigin, 'Canonical'), ['https://nyxo.example/.well-known/security.txt']);
        const both = buildSecurityTxt(resolveSecurityTxtConfig({ PUBLIC_ORIGIN: 'https://nyxo.example:8443/' }, { now: NOW, onion: { address: 'abc.onion', port: 3001 } }), NOW);
        assert.deepStrictEqual(field(both, 'Canonical'), [
            'https://nyxo.example:8443/.well-known/security.txt',
            'http://abc.onion/.well-known/security.txt',
        ]);
        for (const bad of ['http://nyxo.example', 'nyxo.example', 'https://nyxo.example/path', 'https://u:p@nyxo.example', 'https://nyxo.example?x=1', 'ftp://x', '', undefined, 'https://nyxo.example\nPolicy: https://evil.example']) {
            assert.strictEqual(parsePublicOrigin(bad), null, JSON.stringify(bad));
        }
    });

    await test('SECURITY_CONTACT: допустимы https, mailto, tel; прочее и инъекции полей отбрасываются', () => {
        for (const ok of ['https://example.org/security', 'mailto:security@example.org', 'tel:+7-495-000-00-00', 'tel:+1(555)123-4567']) {
            assert.strictEqual(isValidContact(ok), true, ok);
        }
        for (const bad of [
            'http://example.org', 'javascript:alert(1)', 'ftp://example.org', 'example.org', 'mailto:', 'mailto:no-at-sign', 'tel:12345',
            'https://', 'https://user:pass@example.org', 'https://example.org/a b', 'https://example.org/\nExpires: 2999-01-01T00:00:00Z',
            `https://example.org/${'a'.repeat(400)}`, '',
        ]) {
            assert.strictEqual(isValidContact(bad), false, JSON.stringify(bad.slice(0, 50)));
        }
        const parsed = parseContacts('https://a.example/x, bad, https://a.example/x mailto:s@a.example');
        assert.deepStrictEqual(parsed.contacts, ['https://a.example/x', 'mailto:s@a.example']);
        assert.deepStrictEqual(parsed.invalid, ['bad']);
        assert.strictEqual(parsed.usingDefault, false);
        const none = parseContacts('bad, worse');
        assert.deepStrictEqual(none.contacts, [DEFAULT_CONTACT]);
        assert.strictEqual(none.usingDefault, true);
        assert.deepStrictEqual(parseContacts(undefined).contacts, [DEFAULT_CONTACT]);
    });

    await test('SECURITY_TXT_EXPIRES: будущая дата не дальше года принимается; остальное — скользящий срок с причиной', () => {
        const date = resolveExpires('2027-03-01', NOW);
        assert.strictEqual(date.fixed, true);
        assert.strictEqual(date.date.toISOString(), '2027-03-01T23:59:59.000Z', 'дата без времени — до конца суток');
        const exact = resolveExpires('2027-03-01T12:00:00Z', NOW);
        assert.strictEqual(exact.date.toISOString(), '2027-03-01T12:00:00.000Z');
        assert.strictEqual(resolveExpires('2027-03-01T15:00:00+03:00', NOW).date.toISOString(), '2027-03-01T12:00:00.000Z');
        assert.strictEqual(resolveExpires('2026-10-20', NOW).expiresSoon, true, 'меньше 30 дней — пометка');
        assert.strictEqual(resolveExpires('2027-03-01', NOW).expiresSoon, false);

        for (const [bad, why] of [
            ['2026-10-08', /прошла/], ['2028-01-01', /год/], ['завтра', /ISO/], ['2027-02-31', /ISO/], ['2027-13-01', /ISO/],
            ['2027-03-01T12:00:00', /ISO/], ['1893456000', /ISO/], ['2027-03-01\nContact: x', /ISO/],
        ]) {
            const result = resolveExpires(bad, NOW);
            assert.strictEqual(result.fixed, false, bad);
            assert.match(result.problem, why, bad);
            assert.strictEqual(result.date.toISOString(), '2027-04-07T00:00:00.000Z', 'откат к скользящему сроку');
        }
        assert.strictEqual(resolveExpires(undefined, NOW).problem, null);
        assert.strictEqual(resolveExpires('  ', NOW).problem, null);
    });

    await test('фиксированный Expires в файле; когда срок прошёл — файл переходит на скользящий, а не устаревает', () => {
        const config = resolveSecurityTxtConfig({ SECURITY_TXT_EXPIRES: '2027-03-01T12:00:00Z' }, { now: NOW });
        assert.strictEqual(field(buildSecurityTxt(config, NOW), 'Expires')[0], '2027-03-01T12:00:00Z');
        const later = Date.UTC(2027, 2, 2);
        const expires = Date.parse(field(buildSecurityTxt(config, later), 'Expires')[0]);
        assert.ok(expires > later, 'Expires в прошлом недопустим');
    });

    await test('маршруты: файл — text/plain utf-8, публичный кэш сутки, без кук; /security.txt → 301', async () => {
        await withApp({ PUBLIC_ORIGIN: 'https://nyxo.example' }, async (base) => {
            const res = await fetch(`${base}/.well-known/security.txt`);
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.headers.get('content-type'), 'text/plain; charset=utf-8');
            assert.strictEqual(res.headers.get('cache-control'), 'public, max-age=86400');
            for (const name of ['pragma', 'expires', 'surrogate-control']) assert.strictEqual(res.headers.get(name), null, name);
            assert.strictEqual(res.headers.get('cross-origin-resource-policy'), 'cross-origin');
            assert.strictEqual(res.headers.get('access-control-allow-origin'), '*');
            assert.strictEqual(res.headers.get('set-cookie'), null);
            const text = await res.text();
            assert.deepStrictEqual(field(text, 'Canonical'), ['https://nyxo.example/.well-known/security.txt']);
            assert.ok(Date.parse(field(text, 'Expires')[0]) > Date.now());

            const head = await fetch(`${base}/.well-known/security.txt`, { method: 'HEAD' });
            assert.strictEqual(head.status, 200);

            const short = await fetch(`${base}/security.txt`, { redirect: 'manual', headers: { Host: 'evil.example' } });
            assert.strictEqual(short.status, 301);
            assert.strictEqual(short.headers.get('location'), '/.well-known/security.txt', 'Host запроса в Location не попадает');
        });
    });

    await test('Host из запроса в файл не попадает', async () => {
        await withApp({}, async (base) => {
            const res = await new Promise((resolve, reject) => {
                const req = http.request(`${base}/.well-known/security.txt`, { headers: { Host: 'evil.example', 'X-Forwarded-Host': 'evil2.example' } }, (response) => {
                    let body = '';
                    response.setEncoding('utf8');
                    response.on('data', chunk => { body += chunk; });
                    response.on('end', () => resolve(body));
                });
                req.on('error', reject);
                req.end();
            });
            assert.ok(!res.includes('evil'), res);
        });
    });

    await test('маршруты подключены в PRE_SESSION_ROUTES и регистрируются без настроек', () => {
        assert.ok(PRE_SESSION_ROUTES.includes(wellKnown));
        const paths = [];
        wellKnown.register({ get: (p) => paths.push(p) }, {});
        assert.deepStrictEqual(paths, ['/.well-known/security.txt', '/security.txt']);
    });

    await test('env-check: некорректные SECURITY_CONTACT, SECURITY_TXT_EXPIRES, PUBLIC_ORIGIN — предупреждения', () => {
        assert.deepStrictEqual(checkEnv(goodEnv({
            SECURITY_CONTACT: 'mailto:sec@example.org', SECURITY_TXT_EXPIRES: '2999-01-01', PUBLIC_ORIGIN: 'https://nyxo.example',
        })).warnings.filter(w => /SECURITY|PUBLIC/.test(w.name)).map(w => w.name), ['SECURITY_TXT_EXPIRES'], 'дата дальше года — предупреждение');

        const ok = checkEnv(goodEnv({
            SECURITY_CONTACT: 'mailto:sec@example.org', SECURITY_TXT_EXPIRES: new Date(Date.now() + 100 * DAY).toISOString(), PUBLIC_ORIGIN: 'https://nyxo.example',
        }));
        assert.deepStrictEqual(ok.warnings, []);
        assert.deepStrictEqual(ok.errors, []);

        const bad = checkEnv(goodEnv({ SECURITY_CONTACT: 'bad, mailto:sec@example.org', PUBLIC_ORIGIN: 'http://nyxo.example' }));
        const byName = Object.fromEntries(bad.warnings.map(w => [w.name, w.message]));
        assert.match(byName.SECURITY_CONTACT, /пропущено некорректных адресов: 1/);
        assert.ok(!/по умолчанию/.test(byName.SECURITY_CONTACT), 'один адрес остался — по умолчанию не нужен');
        assert.match(byName.PUBLIC_ORIGIN, /https:\/\/домен/);

        const allBad = checkEnv(goodEnv({ SECURITY_CONTACT: 'bad' }));
        assert.match(allBad.warnings[0].message, /по умолчанию/);

        const soon = checkEnv(goodEnv({ SECURITY_TXT_EXPIRES: new Date(Date.now() + 10 * DAY).toISOString() }));
        assert.match(soon.warnings.find(w => w.name === 'SECURITY_TXT_EXPIRES').message, /30 дней/);
        const past = checkEnv(goodEnv({ SECURITY_TXT_EXPIRES: '2020-01-01' }));
        assert.match(past.warnings.find(w => w.name === 'SECURITY_TXT_EXPIRES').message, /прошла.*скользящий срок/);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
