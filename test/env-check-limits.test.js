'use strict';
// Лимиты сервера из T7.2: числовые переменные проверяются env-check, а каждая описана
// в .env.example и docs/ops/deploy-railway.md (при добавлении лимита - строка в NUMERIC_KNOBS).
// Запуск: node test/env-check-limits.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { checkEnv, NUMERIC_KNOBS } = require('../lib/env-check');

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
        KT_SIGNING_KEY: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
        DATABASE_URL: `postgresql://postgres:${rnd(24)}@postgres.railway.internal:5432/railway`,
        NODE_ENV: 'production',
        RAILWAY_ENVIRONMENT_NAME: 'production',
        RAILWAY_VOLUME_MOUNT_PATH: '/data',
    }, extra);
}
const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

console.log('Env check (лимиты T7.2) tests\n');

test('без переменных лимитов предупреждений о них нет', () => {
    const r = checkEnv(goodEnv());
    for (const knob of NUMERIC_KNOBS) assert.strictEqual(r.warnings.filter(w => w.name === knob.name).length, 0, knob.name);
});

test('допустимые значения принимаются, граничные и мусорные - предупреждение с умолчанием', () => {
    for (const knob of NUMERIC_KNOBS) {
        for (const ok of [knob.min, knob.max, knob.def]) {
            const r = checkEnv(goodEnv({ [knob.name]: String(ok) }));
            assert.strictEqual(r.warnings.filter(w => w.name === knob.name).length, 0, `${knob.name}=${ok}`);
        }
        // Дробное допустимо только у настроек в мегабайтах; экспонента и шестнадцатеричная запись - никогда.
        const bads = ['abc', '1e1', '0x10', String(knob.max + 1), String(knob.min - 1), '-1'].concat(knob.float ? [] : ['1.5']);
        for (const bad of bads) {
            const r = checkEnv(goodEnv({ [knob.name]: bad }));
            const warnings = r.warnings.filter(w => w.name === knob.name);
            assert.strictEqual(warnings.length, 1, `${knob.name}=${bad}`);
            assert.ok(warnings[0].message.includes(String(knob.def)), 'в предупреждении - используемое умолчание');
        }
    }
});

test('каждая числовая настройка описана в .env.example и docs/ops/deploy-railway.md', () => {
    const example = read('.env.example');
    const deploy = read('docs/ops/deploy-railway.md');
    for (const knob of NUMERIC_KNOBS) {
        assert.ok(example.includes(knob.name), `${knob.name} нет в .env.example`);
        assert.ok(deploy.includes('`' + knob.name + '`'), `${knob.name} нет в deploy-railway.md`);
    }
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
