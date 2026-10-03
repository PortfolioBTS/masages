'use strict';
// Тестовые ручки NYXO_TEST_* в проверке окружения (lib/env-check.js):
// в production — ошибка, вне test — предупреждение, в test — тихо.
// Запуск: node test/env-test-knobs.test.js

const assert = require('assert');
const crypto = require('crypto');
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
const knobIssues = (list) => list.filter(x => x.name.includes('NYXO_TEST_'));

function main() {
    console.log('Env test knobs tests\n');

    test('без NYXO_TEST_* production-конфигурация остаётся чистой', () => {
        const r = checkEnv(baseEnv());
        assert.deepStrictEqual(r.errors, []);
        assert.deepStrictEqual(r.warnings, []);
    });

    test('NYXO_TEST_MAINTENANCE_MS при NODE_ENV=production — ошибка', () => {
        const r = checkEnv(baseEnv({ NYXO_TEST_MAINTENANCE_MS: '300' }));
        const issues = knobIssues(r.errors);
        assert.strictEqual(issues.length, 1);
        assert.match(issues[0].name, /NYXO_TEST_MAINTENANCE_MS/);
        assert.match(issues[0].message, /production/);
    });

    test('любая NYXO_TEST_* (в том числе будущие и пустые) в production — ошибка с именами всех', () => {
        const r = checkEnv(baseEnv({ NYXO_TEST_RENEW_INTERVAL_MS: '1000', NYXO_TEST_SOMETHING_NEW: '' }));
        const issues = knobIssues(r.errors);
        assert.strictEqual(issues.length, 1);
        assert.match(issues[0].name, /NYXO_TEST_RENEW_INTERVAL_MS/);
        assert.match(issues[0].name, /NYXO_TEST_SOMETHING_NEW/);
    });

    test('значение ручки в отчёт не попадает', () => {
        const r = checkEnv(baseEnv({ NYXO_TEST_MAINTENANCE_MS: '987654321' }));
        assert.ok(!JSON.stringify(r).includes('987654321'));
    });

    test('при NODE_ENV=test ручки допустимы — ни ошибок, ни предупреждений о них', () => {
        const env = baseEnv({ NODE_ENV: 'test', NYXO_TEST_MAINTENANCE_MS: '300', NYXO_TEST_RENEW_INTERVAL_MS: '500' });
        delete env.RAILWAY_ENVIRONMENT_NAME;
        const r = checkEnv(env);
        assert.deepStrictEqual(knobIssues(r.errors), []);
        assert.deepStrictEqual(knobIssues(r.warnings), []);
    });

    test('вне test и production (разработка) — предупреждение, что ручка не применяется', () => {
        const env = baseEnv({ NODE_ENV: 'development', NYXO_TEST_MAINTENANCE_MS: '300' });
        delete env.RAILWAY_ENVIRONMENT_NAME;
        const r = checkEnv(env);
        assert.deepStrictEqual(knobIssues(r.errors), []);
        const warnings = knobIssues(r.warnings);
        assert.strictEqual(warnings.length, 1);
        assert.match(warnings[0].message, /NODE_ENV=test/);
    });

    test('похожие имена без префикса NYXO_TEST_ не считаются ручками', () => {
        const r = checkEnv(baseEnv({ NYXO_TESTING: '1', MY_NYXO_TEST_X: '1' }));
        assert.deepStrictEqual(knobIssues(r.errors), []);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main();
