'use strict';
// Кому можно подключаться к ONION_PORT (W7 R1 п.6): lib/onion-access.js и проверка в env-check.
// Запуск: node test/onion-access.test.js

const assert = require('assert');
const crypto = require('crypto');
const { createOnionAllowList } = require('../lib/onion-access');
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

test('по умолчанию пускаются loopback и частные адреса (IPv4, IPv6, IPv4 в IPv6)', () => {
    const list = createOnionAllowList('');
    for (const ok of [
        '127.0.0.1', '10.0.0.5', '10.255.255.255', '172.16.0.1', '172.31.255.254', '192.168.1.1', '169.254.1.1',
        '::1', 'fd12:3456::7', 'fc00::1', 'fe80::1', '::ffff:10.1.2.3', '::ffff:127.0.0.1', '::ffff:192.168.0.9',
    ]) assert.strictEqual(list.allows(ok), true, ok);
});

test('по умолчанию публичные адреса не пускаются', () => {
    const list = createOnionAllowList(undefined);
    for (const bad of [
        '8.8.8.8', '203.0.113.7', '172.15.0.1', '172.32.0.1', '11.0.0.1', '192.169.0.1', '100.64.0.1',
        '2001:db8::1', '2606:4700::1', '::ffff:8.8.8.8', '::', '0.0.0.0',
    ]) assert.strictEqual(list.allows(bad), false, bad);
});

test('мусорный и пустой адрес не пускается (сокет без remoteAddress)', () => {
    const list = createOnionAllowList('');
    for (const bad of [undefined, null, '', 'localhost', '10.0.0', '10.0.0.0.1', '10.0.0.1/8', 42]) {
        assert.strictEqual(list.allows(bad), false, String(bad));
    }
});

test('ONION_ALLOWED_CIDR заменяет список по умолчанию', () => {
    const list = createOnionAllowList('10.8.0.0/16, fd00:1::/32 ,192.0.2.7');
    assert.strictEqual(list.custom, true);
    assert.deepStrictEqual(list.invalid, []);
    for (const ok of ['10.8.0.1', '10.8.255.255', 'fd00:1::5', '192.0.2.7', '::ffff:10.8.1.1']) assert.strictEqual(list.allows(ok), true, ok);
    for (const bad of ['127.0.0.1', '10.9.0.1', '192.0.2.8', 'fd00:2::1', '::1', '192.168.1.1']) assert.strictEqual(list.allows(bad), false, bad);
});

test('некорректные записи пропускаются; если корректных нет - список по умолчанию', () => {
    const mixed = createOnionAllowList('10.8.0.0/16, nonsense, 10.0.0.0/33, 1.2.3.4/x, ::1/129, 1/2/3');
    assert.strictEqual(mixed.custom, true);
    assert.deepStrictEqual(mixed.invalid, ['nonsense', '10.0.0.0/33', '1.2.3.4/x', '::1/129', '1/2/3']);
    assert.strictEqual(mixed.allows('10.8.1.1'), true);
    assert.strictEqual(mixed.allows('127.0.0.1'), false);

    const none = createOnionAllowList('nonsense, 999.1.1.1');
    assert.strictEqual(none.custom, false);
    assert.strictEqual(none.invalid.length, 2);
    assert.strictEqual(none.allows('127.0.0.1'), true, 'без корректных записей onion не отваливается');
    assert.strictEqual(none.allows('8.8.8.8'), false);
});

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
const named = (list, name) => list.filter(x => x.name === name);

test('env-check: частные CIDR - без замечаний; публичные и 0.0.0.0/0 - предупреждение; мусор - предупреждение', () => {
    const base = { ONION_ADDRESS: 'a'.repeat(56) + '.onion', ONION_PORT: '3001' };
    assert.strictEqual(named(checkEnv(goodEnv({ ...base, ONION_ALLOWED_CIDR: '10.8.0.0/16, fd00:1::/32' })).warnings, 'ONION_ALLOWED_CIDR').length, 0);
    for (const cidr of ['0.0.0.0/0', '::/0', '203.0.113.0/24', '10.8.0.0/16, 8.8.8.8']) {
        const warnings = named(checkEnv(goodEnv({ ...base, ONION_ALLOWED_CIDR: cidr })).warnings, 'ONION_ALLOWED_CIDR');
        assert.strictEqual(warnings.length, 1, cidr);
        assert.match(warnings[0].message, /вне частных сетей/);
    }
    const garbage = named(checkEnv(goodEnv({ ...base, ONION_ALLOWED_CIDR: 'nonsense' })).warnings, 'ONION_ALLOWED_CIDR');
    assert.strictEqual(garbage.length, 1);
    assert.match(garbage[0].message, /по умолчанию/);
});

test('env-check: без ONION_ALLOWED_CIDR при заданном ONION_PORT - только справка о списке по умолчанию', () => {
    const result = checkEnv(goodEnv({ ONION_ADDRESS: 'a'.repeat(56) + '.onion', ONION_PORT: '3001' }));
    assert.strictEqual(named(result.warnings, 'ONION_ALLOWED_CIDR').length, 0);
    assert.strictEqual(named(result.info, 'ONION_ALLOWED_CIDR').length, 1);
    assert.strictEqual(named(checkEnv(goodEnv()).info, 'ONION_ALLOWED_CIDR').length, 0, 'без onion-порта справки нет');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
