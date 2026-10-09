'use strict';
// HSTS и HSTS preload (8.3): getHstsHeader из lib/privacy.js и предупреждения
// env-check про HSTS_PRELOAD. Запуск: node test/hsts.test.js

const assert = require('assert');
const crypto = require('crypto');
const { getHstsHeader, createHstsMiddleware } = require('../lib/privacy');
const { checkEnv } = require('../lib/env-check');

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const rnd = (n = 32) => crypto.randomBytes(n).toString('base64url');
function goodEnv(extra = {}) {
    return Object.assign({
        SESSION_SECRET: rnd(48),
        MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
        DATABASE_URL: `postgresql://postgres:${rnd(24)}@postgres.railway.internal:5432/railway`,
        NODE_ENV: 'production',
        RAILWAY_ENVIRONMENT_NAME: 'production',
        RAILWAY_VOLUME_MOUNT_PATH: '/data',
    }, extra);
}

console.log('HSTS tests\n');

const BASE = 'max-age=31536000; includeSubDomains';
const PRELOAD = 'max-age=63072000; includeSubDomains; preload';

test('по умолчанию — год и includeSubDomains, без preload', () => {
    assert.strictEqual(getHstsHeader({ production: true, secure: true, onion: false, preload: false }), BASE);
    assert.strictEqual(getHstsHeader({ production: true, secure: true, onion: undefined, preload: undefined }), BASE);
});

test('HSTS_PRELOAD=yes — два года, includeSubDomains и preload', () => {
    assert.strictEqual(getHstsHeader({ production: true, secure: true, onion: false, preload: true }), PRELOAD);
});

test('заголовка нет: не production, не https, onion — при любом preload', () => {
    for (const preload of [false, true]) {
        assert.strictEqual(getHstsHeader({ production: false, secure: true, onion: false, preload }), null, 'не production');
        assert.strictEqual(getHstsHeader({ production: true, secure: false, onion: false, preload }), null, 'не https');
        assert.strictEqual(getHstsHeader({ production: true, secure: true, onion: true, preload }), null, 'onion');
        assert.strictEqual(getHstsHeader({ production: false, secure: false, onion: true, preload }), null);
    }
});

test('preload — требования hstspreload.org: год и больше, includeSubDomains, preload', () => {
    const value = getHstsHeader({ production: true, secure: true, onion: false, preload: true });
    const maxAge = Number(/max-age=(\d+)/.exec(value)[1]);
    assert.ok(maxAge >= 31536000);
    assert.ok(/;\s*includeSubDomains/.test(value) && /;\s*preload$/.test(value));
});

test('middleware: заголовок по req.secure и req.isOnion, next() вызывается всегда', () => {
    const run = (options, req) => {
        const headers = {};
        let called = 0;
        createHstsMiddleware(options)(req, { set: (name, value) => { headers[name] = value; } }, () => { called++; });
        assert.strictEqual(called, 1);
        return headers['Strict-Transport-Security'];
    };
    const prod = { production: true, preload: false };
    assert.strictEqual(run(prod, { secure: true, isOnion: false }), BASE);
    assert.strictEqual(run({ production: true, preload: true }, { secure: true }), PRELOAD);
    assert.strictEqual(run(prod, { secure: false }), undefined);
    assert.strictEqual(run(prod, { secure: true, isOnion: true }), undefined);
    assert.strictEqual(run({ production: false, preload: true }, { secure: true }), undefined);
});

test('env-check: HSTS_PRELOAD=yes в production — предупреждение о рисках, не ошибка', () => {
    const r = checkEnv(goodEnv({ HSTS_PRELOAD: 'yes' }));
    assert.deepStrictEqual(r.errors, []);
    const warnings = r.warnings.filter(w => w.name === 'HSTS_PRELOAD');
    assert.strictEqual(warnings.length, 1);
    assert.match(warnings[0].message, /preload/);
    assert.match(warnings[0].message, /месяцы/);
    assert.match(warnings[0].message, /поддомен/);
    assert.match(warnings[0].message, /hstspreload\.org/);
    assert.match(warnings[0].message, /up\.railway\.app/);
});

test('env-check: HSTS_PRELOAD=yes вне production — ещё и «не действует»', () => {
    const r = checkEnv({ ...goodEnv({ HSTS_PRELOAD: 'yes' }), NODE_ENV: 'development', RAILWAY_ENVIRONMENT_NAME: undefined });
    const messages = r.warnings.filter(w => w.name === 'HSTS_PRELOAD').map(w => w.message);
    assert.strictEqual(messages.length, 2);
    assert.ok(messages.some(m => /NODE_ENV=production/.test(m)));
});

test('env-check: HSTS_PRELOAD не задан или "no" — тишина; прочие значения — предупреждение', () => {
    assert.deepStrictEqual(checkEnv(goodEnv()).warnings, []);
    assert.deepStrictEqual(checkEnv(goodEnv({ HSTS_PRELOAD: 'no' })).warnings, []);
    assert.deepStrictEqual(checkEnv(goodEnv({ HSTS_PRELOAD: '' })).warnings, []);
    for (const value of ['true', 'YES', '1', 'on']) {
        const r = checkEnv(goodEnv({ HSTS_PRELOAD: value }));
        assert.strictEqual(r.warnings.filter(w => w.name === 'HSTS_PRELOAD').length, 1, value);
        assert.match(r.warnings[0].message, /только "yes"/);
    }
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
