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

// Повторное ревью W7, Н2: env-check и сервер разбирали одни и те же переменные по-разному (разные регулярные
// выражения и пределы): env-check писал «будет использовано умолчание», а сервер брал значение как есть — и наоборот.
// Теперь разбор один (lib/numeric-knobs.js): что env-check назвал, то сервер и берёт.
const MB = 1024 * 1024;
const { _internal: stripper } = require('../lib/metadata-stripper');
const { resolveAccountLimits } = require('../lib/account-limits');
const { resolveDbSessionTimeouts } = require('../src/db/pool');
const { resolveSocketEventRates } = require('../src/realtime/socket-handlers');
const SERVER_VALUE = {
    IMAGE_MAX_PIXELS: (env) => stripper.resolveImageLimits(env).maxPixels,
    IMAGE_MAX_FRAMES: (env) => stripper.resolveImageLimits(env).maxFrames,
    UPLOAD_PROCESS_CONCURRENCY: (env) => stripper.resolveProcessLimits(env).concurrency,
    UPLOAD_PROCESS_QUEUE: (env) => stripper.resolveProcessLimits(env).maxQueue,
    REGISTER_GLOBAL_PER_MIN: (env) => resolveAccountLimits(env).registerGlobalPerMin,
    REGISTER_PACE_PER_MIN: (env) => resolveAccountLimits(env).registerPacePerMin,
    TEXT_QUOTA_MB_PER_DAY: (env) => resolveAccountLimits(env).textQuotaBytesPerDay / MB,
    ROOMS_PER_USER_MAX: (env) => resolveAccountLimits(env).roomsPerUserMax,
    UPLOAD_MIN_FREE_MB: (env) => resolveAccountLimits(env).uploadMinFreeBytes / MB,
    UPLOADS_IP_PER_MIN: (env) => resolveAccountLimits(env).uploadsIpPerMin,
    UPLOADS_USER_PER_15MIN: (env) => resolveAccountLimits(env).uploadsUserPer15Min,
    OPEN_UPLOADS_PER_10MIN: (env) => resolveAccountLimits(env).openUploadsPer10Min,
    SOCKET_EVENT_RATE: (env) => resolveSocketEventRates(env).rate,
    SOCKET_EVENT_BURST: (env) => resolveSocketEventRates(env).burst,
    DB_STATEMENT_TIMEOUT_MS: (env) => resolveDbSessionTimeouts(env).statement_timeout,
    DB_LOCK_TIMEOUT_MS: (env) => resolveDbSessionTimeouts(env).lock_timeout,
    DB_IDLE_TX_TIMEOUT_MS: (env) => resolveDbSessionTimeouts(env).idle_in_transaction_session_timeout,
};

test('у каждой числовой настройки есть разбор на сервере', () => {
    assert.deepStrictEqual(Object.keys(SERVER_VALUE).sort(), NUMERIC_KNOBS.map(k => k.name).sort());
});

test('сервер берёт ровно то значение, которое называет env-check (Н2)', () => {
    for (const knob of NUMERIC_KNOBS) {
        const raws = [knob.min, knob.max, knob.def, knob.min - 1, knob.max + 1, knob.max * 10, '0', '-1', '1e1', '0x10', '1.5',
            '0.0005', 'abc', ' 12 ', '00012', '', '1234567890', String(Math.floor((knob.min + knob.max) / 2))].map(String);
        for (const raw of raws) {
            const env = goodEnv({ [knob.name]: raw });
            const warned = checkEnv(env).warnings.some(w => w.name === knob.name);
            const expected = warned || raw.trim() === '' ? knob.def : Number(raw);
            const got = SERVER_VALUE[knob.name](env);
            // Мегабайты сервер хранит в байтах (с округлением вниз) — сравнение с точностью до байта.
            const same = knob.float ? Math.abs(got - expected) * MB < 1 : got === expected;
            assert.ok(same, `${knob.name}=${JSON.stringify(raw)}: env-check ${warned ? 'предупредил (умолчание ' + knob.def + ')' : 'принял'}, сервер взял ${got}`);
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
