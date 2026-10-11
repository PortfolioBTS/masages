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
        // Ключ журнала ключей: без него в production есть предупреждение «журнал выключен».
        KT_SIGNING_KEY: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
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
        assert.ok(!has(r.info, 'E2EE_KEY_STORE'), 'no note about the key store: there is only one way to store keys now');
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

    test('variables of the removed services: one "not used" warning listing only those that are set, never an error', () => {
        const all = {
            E2EE_KEY_STORE: 'remote', KEY_SERVER_URL: 'http://127.0.0.1:7420', INTERNAL_KEY_SERVER_SECRET: rnd(48),
            ANON_SERVICE_URL: 'http://anon.railway.internal:8080', ANON_SERVICE_SECRET: rnd(48),
        };
        assert.deepStrictEqual(checkEnv(goodEnv()).warnings, []);
        const stale = checkEnv(goodEnv(all));
        assert.deepStrictEqual(stale.errors, [], 'a leftover remote setup does not fail the check');
        assert.strictEqual(stale.warnings.length, 1, 'one warning for all of them');
        assert.ok(has(stale.warnings, 'E2EE_KEY_STORE', /не используется.*удалите/));
        assert.deepStrictEqual(stale.warnings[0].name.split(', ').sort(), Object.keys(all).sort());
        // Только заданные: пустая переменная в список не попадает.
        const partial = checkEnv(goodEnv({ ANON_SERVICE_URL: 'http://anon.railway.internal:8080', KEY_SERVER_URL: '  ' }));
        assert.deepStrictEqual(names(partial.warnings), ['ANON_SERVICE_URL']);
        // Значения в отчёт не попадают.
        const report = formatEnvReport(stale);
        for (const secret of [all.INTERNAL_KEY_SERVER_SECRET, all.ANON_SERVICE_SECRET, all.KEY_SERVER_URL]) {
            assert.ok(!report.includes(secret), 'report must not contain values');
        }
        // Секрет удалённого сервиса больше не сравнивается с живыми секретами
        // как «одинаковые значения» — для ANON_SERVICE_SECRET это просто мусор в окружении.
        const same = rnd(48);
        assert.deepStrictEqual(checkEnv(goodEnv({ SESSION_SECRET: same, ANON_SERVICE_SECRET: same })).errors, []);
    });

    test('a leaked INTERNAL_KEY_SERVER_SECRET stays an error even though the variable is not used any more', () => {
        const value = rnd(48);
        const leaked = { INTERNAL_KEY_SERVER_SECRET: [_internal.sha256(value)] };
        const r = checkEnv(goodEnv({ INTERNAL_KEY_SERVER_SECRET: value }), { leaked });
        assert.ok(has(r.errors, 'INTERNAL_KEY_SERVER_SECRET', /утёкшим/));
        assert.ok(has(r.warnings, 'INTERNAL_KEY_SERVER_SECRET', /не используется/));
        assert.ok(!formatEnvReport(r).includes(value), 'report must not contain the value');
        // Не утёкшее значение той же переменной — только предупреждение.
        assert.deepStrictEqual(checkEnv(goodEnv({ INTERNAL_KEY_SERVER_SECRET: rnd(48) }), { leaked }).errors, []);
    });

    test('the same value reused for two secrets is an error', () => {
        // base64 от 32 байт годится и как SESSION_SECRET, и как ключ сообщений.
        const same = crypto.randomBytes(32).toString('base64');
        const r = checkEnv(goodEnv({ SESSION_SECRET: same, MESSAGE_ENCRYPTION_KEY: same }));
        assert.ok(has(r.errors, 'SESSION_SECRET / MESSAGE_ENCRYPTION_KEY', /одинаковые/));
    });

    test('PASSWORD_PEPPER and HIBP_CHECK: in the common "not used" warning, not checked, not compared as secrets', () => {
        const pepper = rnd(48);
        const r = checkEnv(goodEnv({ PASSWORD_PEPPER: pepper, HIBP_CHECK: 'true', ANON_SERVICE_URL: 'http://anon.railway.internal:8080' }));
        assert.deepStrictEqual(r.errors, []);
        assert.strictEqual(r.warnings.length, 1, 'one warning for all unused variables');
        assert.deepStrictEqual(r.warnings[0].name.split(', ').sort(), ['ANON_SERVICE_URL', 'HIBP_CHECK', 'PASSWORD_PEPPER']);
        assert.match(r.warnings[0].message, /не используется.*удалите/);
        assert.deepStrictEqual(r.info, [], 'no note about keeping the pepper any more');
        // Заглушка или короткое значение — больше не ошибка: переменная не проверяется.
        assert.deepStrictEqual(checkEnv(goodEnv({ PASSWORD_PEPPER: 'changeme' })).errors, []);
        // И не сравнивается с живыми секретами.
        const same = rnd(48);
        assert.deepStrictEqual(checkEnv(goodEnv({ SESSION_SECRET: same, PASSWORD_PEPPER: same })).errors, []);
        assert.ok(!formatEnvReport(r).includes(pepper), 'report must not contain the value');
    });

    test('Railway without a volume for attachments, onion port clash', () => {
        assert.ok(has(checkEnv(goodEnv({ RAILWAY_VOLUME_MOUNT_PATH: '' })).warnings, 'UPLOADS_DIR', /volume/));
        assert.ok(has(checkEnv(goodEnv({ ONION_PORT: '3000' })).errors, 'ONION_PORT', /PORT/));
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main();
