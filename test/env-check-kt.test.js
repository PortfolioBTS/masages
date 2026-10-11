'use strict';
// Проверка настроек журнала ключей (lib/env-check.js, docs/security/key-transparency.md, 6.6):
// KT_SIGNING_KEY и KT_SIGNING_KEY_PREVIOUS — Ed25519 в base64 PKCS#8; без ключа в production
// предупреждение «журнал выключен»; тестовые ручки KT_* в production — ошибка; значение ключа
// в отчёт не попадает.
// Запуск: node test/env-check-kt.test.js

const assert = require('assert');
const crypto = require('crypto');
const { checkEnv, formatEnvReport } = require('../lib/env-check');

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
const newKey = () => crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
function baseEnv(extra = {}) {
    return Object.assign({
        SESSION_SECRET: rnd(48),
        MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
        DATABASE_URL: `postgresql://postgres:${rnd(24)}@postgres.railway.internal:5432/railway`,
        NODE_ENV: 'production',
        RAILWAY_ENVIRONMENT_NAME: 'production',
        RAILWAY_VOLUME_MOUNT_PATH: '/data',
    }, extra);
}
const has = (list, name, re) => list.some(x => x.name.includes(name) && (!re || re.test(x.message)));

test('в production без KT_SIGNING_KEY — предупреждение «журнал ключей выключен», не ошибка', () => {
    const r = checkEnv(baseEnv());
    assert.deepStrictEqual(r.errors, []);
    assert.ok(has(r.warnings, 'KT_SIGNING_KEY', /журнал ключей выключен/));
    // Вне production тишина: локальный запуск обходится без ключа.
    const dev = checkEnv(baseEnv({ NODE_ENV: 'development', RAILWAY_ENVIRONMENT_NAME: undefined, RAILWAY_VOLUME_MOUNT_PATH: undefined }));
    assert.ok(!has(dev.warnings, 'KT_SIGNING_KEY'));
});

test('настоящий Ed25519 в base64 PKCS#8 принимается, значение ключа в отчёт не попадает', () => {
    const key = newKey();
    const r = checkEnv(baseEnv({ KT_SIGNING_KEY: key }));
    assert.deepStrictEqual(r.errors, []);
    assert.deepStrictEqual(r.warnings, []);
    assert.ok(!formatEnvReport(r).includes(key));
});

test('не base64, не PKCS#8, не Ed25519 — ошибка без значения ключа', () => {
    for (const [value, re] of [
        ['не base64!', /base64/],
        [Buffer.from('мусор').toString('base64'), /PKCS#8/],
        [crypto.generateKeyPairSync('x25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), /Ed25519/],
    ]) {
        const r = checkEnv(baseEnv({ KT_SIGNING_KEY: value }));
        assert.ok(has(r.errors, 'KT_SIGNING_KEY', re), value);
        assert.ok(!formatEnvReport(r).includes(value), 'значение в отчёт не попадает');
    }
});

test('KT_SIGNING_KEY_PREVIOUS: проверяется так же; без текущего ключа и равный ему — предупреждения', () => {
    const key = newKey();
    assert.deepStrictEqual(checkEnv(baseEnv({ KT_SIGNING_KEY: key, KT_SIGNING_KEY_PREVIOUS: newKey() })).errors, []);
    assert.ok(has(checkEnv(baseEnv({ KT_SIGNING_KEY: key, KT_SIGNING_KEY_PREVIOUS: 'мусор' })).errors, 'KT_SIGNING_KEY_PREVIOUS'));
    assert.ok(has(checkEnv(baseEnv({ KT_SIGNING_KEY_PREVIOUS: newKey() })).warnings, 'KT_SIGNING_KEY_PREVIOUS', /без KT_SIGNING_KEY/));
    assert.ok(has(checkEnv(baseEnv({ KT_SIGNING_KEY: key, KT_SIGNING_KEY_PREVIOUS: key })).warnings, 'KT_SIGNING_KEY_PREVIOUS', /совпадает/));
});

test('ключ журнала не должен совпадать с другим секретом', () => {
    const key = newKey();
    const r = checkEnv(baseEnv({ KT_SIGNING_KEY: key, METRICS_TOKEN: key.replace(/[+/=]/g, 'a') }));
    assert.ok(!has(r.errors, 'KT_SIGNING_KEY / '), 'разные значения — не совпадение');
    const same = checkEnv(baseEnv({ KT_SIGNING_KEY: key, SESSION_SECRET: key }));
    assert.ok(has(same.errors, 'SESSION_SECRET / KT_SIGNING_KEY', /одинаковые/) || has(same.errors, 'KT_SIGNING_KEY', /одинаковые/));
});

test('тестовые ручки журнала в production — ошибка, вне production и не в test — предупреждение, в test — тишина', () => {
    const knobs = { KT_EPOCH_SECONDS: '2', KT_GENERATION_EPOCHS: '5', KT_GRACE_EPOCHS: '3', KT_COMPACT_MIN: '2' };
    const prod = checkEnv(baseEnv({ KT_SIGNING_KEY: newKey(), ...knobs }));
    assert.ok(has(prod.errors, 'KT_EPOCH_SECONDS', /NODE_ENV=production/));
    for (const name of Object.keys(knobs)) assert.ok(has(prod.errors, name), name);
    const dev = checkEnv(baseEnv({ NODE_ENV: 'development', RAILWAY_ENVIRONMENT_NAME: undefined, RAILWAY_VOLUME_MOUNT_PATH: undefined, ...knobs }));
    assert.ok(has(dev.warnings, 'KT_EPOCH_SECONDS', /NODE_ENV=test/));
    const test_ = checkEnv(baseEnv({ NODE_ENV: 'test', RAILWAY_ENVIRONMENT_NAME: undefined, RAILWAY_VOLUME_MOUNT_PATH: undefined, ...knobs }));
    assert.ok(!has(test_.errors, 'KT_') && !has(test_.warnings, 'KT_EPOCH'));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
