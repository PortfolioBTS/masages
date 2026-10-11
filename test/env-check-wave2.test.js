'use strict';
// env-check: METRICS_TOKEN (7.6) и новые переменные волны 2 в .env.example.
// Запуск: node test/env-check-wave2.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
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
        // Ключ журнала ключей: без него в production есть предупреждение «журнал выключен».
        KT_SIGNING_KEY: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
        DATABASE_URL: `postgresql://postgres:${rnd(24)}@postgres.railway.internal:5432/railway`,
        NODE_ENV: 'production',
        RAILWAY_ENVIRONMENT_NAME: 'production',
        RAILWAY_VOLUME_MOUNT_PATH: '/data',
    }, extra);
}
const named = (list, name) => list.filter(x => x.name.includes(name));

console.log('Env check (wave 2) tests\n');

test('METRICS_TOKEN не задан — тишина (эндпоинт просто отключён)', () => {
    const r = checkEnv(goodEnv());
    assert.deepStrictEqual(r.errors, []);
    assert.deepStrictEqual(r.warnings, []);
});

test('METRICS_TOKEN: случайное значение от 32 символов — всё в порядке', () => {
    const r = checkEnv(goodEnv({ METRICS_TOKEN: rnd(32) }));
    assert.deepStrictEqual(r.errors, []);
    assert.deepStrictEqual(r.warnings, []);
});

test('METRICS_TOKEN: короткий, заглушка и не-Bearer символы — ошибки', () => {
    assert.strictEqual(named(checkEnv(goodEnv({ METRICS_TOKEN: 'abc123' })).errors, 'METRICS_TOKEN').length, 1, 'короткий');
    assert.strictEqual(named(checkEnv(goodEnv({ METRICS_TOKEN: 'change_me_change_me_change_me_change_me' })).errors, 'METRICS_TOKEN').length >= 1, true, 'заглушка');
    const spaced = checkEnv(goodEnv({ METRICS_TOKEN: `${rnd(20)} ${rnd(20)}` }));
    assert.match(named(spaced.errors, 'METRICS_TOKEN')[0].message, /Authorization: Bearer/);
    const quoted = checkEnv(goodEnv({ METRICS_TOKEN: `"${rnd(40)}"` }));
    assert.strictEqual(named(quoted.errors, 'METRICS_TOKEN').length, 1);
});

test('METRICS_TOKEN не должен совпадать с другими секретами', () => {
    const secret = rnd(48);
    const r = checkEnv(goodEnv({ SESSION_SECRET: secret, METRICS_TOKEN: secret }));
    assert.ok(r.errors.some(e => /SESSION_SECRET \/ METRICS_TOKEN/.test(e.name)));
});

test('.env.example описывает новые переменные закомментированными строками', () => {
    const text = fs.readFileSync(path.join(__dirname, '..', '.env.example'), 'utf8');
    for (const name of ['METRICS_TOKEN', 'HSTS_PRELOAD', 'SECURITY_CONTACT', 'SECURITY_TXT_EXPIRES', 'PUBLIC_ORIGIN']) {
        assert.match(text, new RegExp(`^# ${name}=`, 'm'), name);
    }
    assert.ok(!/^(METRICS_TOKEN|HSTS_PRELOAD)=./m.test(text), 'значения по умолчанию не заданы');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
