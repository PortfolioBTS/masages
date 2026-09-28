'use strict';
// Проверка настроек и секретов (lib/env-check.js).
// Запуск: node test/env-check.test.js

const assert = require('assert');
const crypto = require('crypto');
const { checkEnv, formatEnvReport, _internal } = require('../lib/env-check');

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
const names = (list) => list.map(x => x.name);
const has = (list, name, re) => list.some(x => x.name.includes(name) && (!re || re.test(x.message)));

function main() {
    console.log('Env check tests\n');

    test('a correct Railway configuration has no errors and no warnings', () => {
        const r = checkEnv(goodEnv());
        assert.deepStrictEqual(r.errors, []);
        assert.deepStrictEqual(r.warnings, []);
        assert.ok(has(r.info, 'E2EE_KEY_STORE', /встроенном/));
    });

    test('missing required secrets are errors', () => {
        const r = checkEnv({});
        for (const n of ['SESSION_SECRET', 'MESSAGE_ENCRYPTION_KEY', 'DATABASE_URL']) assert.ok(names(r.errors).includes(n), n);
    });

    test('placeholders, short and low-entropy secrets are caught', () => {
        assert.ok(has(checkEnv(goodEnv({ SESSION_SECRET: 'your_random_secret_min_32_chars_xx' })).errors, 'SESSION_SECRET', /заглушку/));
        assert.ok(has(checkEnv(goodEnv({ SESSION_SECRET: 'Zq8#kd02' })).errors, 'SESSION_SECRET', /коротк/));
        assert.ok(has(checkEnv(goodEnv({ SESSION_SECRET: 'ab'.repeat(20) })).warnings, 'SESSION_SECRET', /случайное/));
    });

    test('message key must be base64 of exactly 32 bytes; PREVIOUS keys checked too', () => {
        assert.ok(has(checkEnv(goodEnv({ MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(16).toString('base64') })).errors, 'MESSAGE_ENCRYPTION_KEY', /32 байт/));
        assert.ok(has(checkEnv(goodEnv({ MESSAGE_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64') })).errors, 'MESSAGE_ENCRYPTION_KEY', /случайным/));
        assert.ok(has(checkEnv(goodEnv({ MESSAGE_ENCRYPTION_KEY_PREVIOUS: 'nope' })).errors, 'MESSAGE_ENCRYPTION_KEY_PREVIOUS'));
    });

    test('leaked secrets are recognised by SHA-256 (values are never stored)', () => {
        const leakedSession = rnd(48), leakedPw = rnd(24), leakedKs = rnd(48);
        const leaked = {
            SESSION_SECRET: [_internal.sha256(leakedSession)],
            DATABASE_PASSWORD: [_internal.sha256(leakedPw)],
            INTERNAL_KEY_SERVER_SECRET: [_internal.sha256(leakedKs)],
        };
        const r = checkEnv(goodEnv({
            SESSION_SECRET: leakedSession,
            DATABASE_URL: `postgresql://postgres:${leakedPw}@postgres.railway.internal:5432/railway`,
            INTERNAL_KEY_SERVER_SECRET: leakedKs,
        }), { leaked });
        assert.ok(has(r.errors, 'SESSION_SECRET', /утёкшим/));
        assert.ok(has(r.errors, 'DATABASE_URL', /утёкшим/));
        assert.ok(has(r.errors, 'INTERNAL_KEY_SERVER_SECRET', /утёкшим/));
        const report = formatEnvReport(r);
        for (const v of [leakedSession, leakedPw, leakedKs]) assert.ok(!report.includes(v), 'report must not contain secret values');
    });

    test('NODE_ENV must be production on Railway', () => {
        assert.ok(has(checkEnv(goodEnv({ NODE_ENV: '' })).errors, 'NODE_ENV', /production/));
        assert.ok(!has(checkEnv(goodEnv({ NODE_ENV: 'development', RAILWAY_ENVIRONMENT_NAME: '' })).errors, 'NODE_ENV'), 'local dev is fine');
    });

    test('database TLS policy in production and DB_CA_CERT format', () => {
        const publicDb = goodEnv({ DATABASE_URL: `postgresql://postgres:${rnd(24)}@roundhouse.proxy.rlwy.net:41234/railway` });
        assert.ok(has(checkEnv(publicDb).errors, 'DB_CA_CERT', /CA/));
        assert.deepStrictEqual(checkEnv(Object.assign({}, publicDb, { DB_TLS_INSECURE: 'true' })).errors, []);
        assert.ok(has(checkEnv(goodEnv({ DB_CA_CERT: 'not a cert' })).errors, 'DB_CA_CERT', /PEM/));
    });

    test('key store: leftovers without E2EE_KEY_STORE=remote are warned; remote needs a reachable non-loopback URL on Railway', () => {
        const leftovers = checkEnv(goodEnv({ INTERNAL_KEY_SERVER_SECRET: rnd(48), KEY_SERVER_URL: 'http://127.0.0.1:7420' }));
        assert.deepStrictEqual(leftovers.errors, []);
        assert.ok(has(leftovers.warnings, 'INTERNAL_KEY_SERVER_SECRET', /удалить/));
        const remoteLoopback = checkEnv(goodEnv({ E2EE_KEY_STORE: 'remote', INTERNAL_KEY_SERVER_SECRET: rnd(48), KEY_SERVER_URL: 'http://127.0.0.1:7420' }));
        assert.ok(has(remoteLoopback.errors, 'KEY_SERVER_URL', /этот же контейнер/));
        const remoteNoSecret = checkEnv(goodEnv({ E2EE_KEY_STORE: 'remote', KEY_SERVER_URL: 'http://keys.railway.internal:7420' }));
        assert.ok(has(remoteNoSecret.errors, 'INTERNAL_KEY_SERVER_SECRET', /не задан/));
        const remoteOk = checkEnv(goodEnv({ E2EE_KEY_STORE: 'remote', INTERNAL_KEY_SERVER_SECRET: rnd(48), KEY_SERVER_URL: 'http://keys.railway.internal:7420' }));
        assert.deepStrictEqual(remoteOk.errors, []);
    });

    test('the same value reused for two secrets is an error', () => {
        const same = rnd(48);
        const r = checkEnv(goodEnv({ SESSION_SECRET: same, PASSWORD_PEPPER: same }));
        assert.ok(has(r.errors, 'SESSION_SECRET / PASSWORD_PEPPER', /одинаковые/));
    });

    test('Railway without a volume for attachments, onion port clash, anon-service without secret', () => {
        assert.ok(has(checkEnv(goodEnv({ RAILWAY_VOLUME_MOUNT_PATH: '' })).warnings, 'UPLOADS_DIR', /volume/));
        assert.ok(has(checkEnv(goodEnv({ ONION_PORT: '3000' })).errors, 'ONION_PORT', /PORT/));
        assert.ok(has(checkEnv(goodEnv({ ANON_SERVICE_URL: 'http://anon.railway.internal:8080' })).warnings, 'ANON_SERVICE_SECRET'));
    });

    test('loopback detection', () => {
        for (const h of ['localhost', '127.0.0.1', '127.1.2.3', '::1', '[::1]', '0.0.0.0']) assert.ok(_internal.isLoopbackHost(h), h);
        for (const h of ['keys.railway.internal', '10.0.0.1']) assert.ok(!_internal.isLoopbackHost(h), h);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main();
