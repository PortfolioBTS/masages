'use strict';
// Проверка источника запроса (W7 R1 п.10): схема Origin сверяется с протоколом запроса, а
// X-Forwarded-Host/-Proto принимаются только от доверенного прокси (TRUST_PROXY).
// Запуск: node test/origin-scheme.test.js

const assert = require('assert');
const crypto = require('crypto');
const { isRequestOriginAllowed, parseAllowedOrigins } = require('../lib/security-utils');
const { parseTrustProxy, resolveTrustProxy, proxyHeaderValue } = require('../lib/trust-proxy');
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

const allowed = parseAllowedOrigins('');
const check = (args) => isRequestOriginAllowed({ allowed, host: 'app.example', ...args });

test('схема Origin должна совпасть с протоколом запроса, когда он известен', () => {
    assert.strictEqual(check({ origin: 'https://app.example', protocol: 'https' }), true);
    assert.strictEqual(check({ origin: 'http://app.example', protocol: 'http' }), true);
    assert.strictEqual(check({ origin: 'http://app.example', protocol: 'https' }), false, 'страница по http не ходит в https-API');
    assert.strictEqual(check({ origin: 'https://app.example', protocol: 'http' }), false);
});

test('протокол неизвестен - схема не сверяется (разработка по http без прокси)', () => {
    for (const protocol of [undefined, null, '']) {
        assert.strictEqual(check({ origin: 'http://app.example', protocol }), true);
        assert.strictEqual(check({ origin: 'https://app.example', protocol }), true);
    }
});

test('порт по умолчанию не мешает: https://app.example:443 и Host: app.example:443', () => {
    assert.strictEqual(check({ origin: 'https://app.example:443', host: 'app.example:443', protocol: 'https' }), true);
    assert.strictEqual(check({ origin: 'http://app.example:80', host: 'app.example', protocol: 'http' }), true);
});

test('onion: страница по http://…onion приходит как «защищённая» - схема не проверяется', () => {
    const onion = 'a'.repeat(56) + '.onion';
    const isOnionHost = (host) => host === onion;
    assert.strictEqual(isRequestOriginAllowed({ allowed, host: onion, origin: `http://${onion}`, protocol: 'https', isOnionHost }), true);
    assert.strictEqual(isRequestOriginAllowed({ allowed, host: 'app.example', origin: `http://${onion}`, protocol: 'https', isOnionHost }), true);
});

test('чужой хост по-прежнему отклоняется, а запись ALLOWED_ORIGINS со схемой разрешает свой источник', () => {
    assert.strictEqual(check({ origin: 'https://evil.example', protocol: 'https' }), false);
    const mirror = parseAllowedOrigins('https://mirror.example');
    assert.strictEqual(isRequestOriginAllowed({ allowed: mirror, host: 'app.example', origin: 'https://mirror.example', protocol: 'https' }), true);
    // Тот же хост, другая схема - но явная запись разрешает.
    const explicit = parseAllowedOrigins('http://app.example');
    assert.strictEqual(isRequestOriginAllowed({ allowed: explicit, host: 'app.example', origin: 'http://app.example', protocol: 'https' }), true);
});

test('TRUST_PROXY: умолчание 1, 0/false/no/off - без прокси, мусор и значения больше 1 - ошибка настройки с умолчанием 1', () => {
    assert.deepStrictEqual(parseTrustProxy(undefined), { hops: 1, valid: true });
    assert.deepStrictEqual(parseTrustProxy(''), { hops: 1, valid: true });
    assert.deepStrictEqual(parseTrustProxy('1'), { hops: 1, valid: true });
    for (const off of ['0', 'false', 'FALSE', ' no ', 'off']) assert.deepStrictEqual(parseTrustProxy(off), { hops: 0, valid: true }, off);
    for (const bad of ['2', '3', 'abc', 'yes', '-1', '1.5', 'true']) assert.deepStrictEqual(parseTrustProxy(bad), { hops: 1, valid: false }, bad);
    assert.strictEqual(resolveTrustProxy({ TRUST_PROXY: '0' }), 0);
    assert.strictEqual(resolveTrustProxy({}), 1);
});

test('значение от доверенного прокси - последнее в списке; без прокси или без заголовка - null', () => {
    assert.strictEqual(proxyHeaderValue('evil.example, app.example', 1), 'app.example');
    assert.strictEqual(proxyHeaderValue('app.example', 1), 'app.example');
    assert.strictEqual(proxyHeaderValue(' a , b , c ', 1), 'c');
    assert.strictEqual(proxyHeaderValue(['evil.example', 'app.example'], 1), 'app.example');
    assert.strictEqual(proxyHeaderValue('evil.example', 0), null);
    for (const empty of [undefined, null, '', ' , ', 5, {}]) assert.strictEqual(proxyHeaderValue(empty, 1), null, String(empty));
});

// createOrigin читает окружение при создании.
function originWith(env) {
    const saved = {};
    for (const [k, v] of Object.entries(env)) { saved[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    try {
        delete require.cache[require.resolve('../src/http/middleware/origin')];
        return require('../src/http/middleware/origin').createOrigin();
    } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
}
const req = (headers, encrypted = false) => ({ headers, socket: { encrypted } });

test('isTrustedOrigin при TRUST_PROXY=1: хост из последнего X-Forwarded-Host, схема из X-Forwarded-Proto', () => {
    const { isTrustedOrigin } = originWith({ TRUST_PROXY: undefined });
    const headers = { origin: 'https://app.example', host: 'internal:3000', 'x-forwarded-host': 'app.example', 'x-forwarded-proto': 'https' };
    assert.strictEqual(isTrustedOrigin(headers, req(headers)), true);
    const spoofed = { origin: 'https://evil.example', host: 'internal:3000', 'x-forwarded-host': 'evil.example, app.example', 'x-forwarded-proto': 'https' };
    assert.strictEqual(isTrustedOrigin(spoofed, req(spoofed)), false, 'присланное клиентом (первое) значение не считается своим хостом');
    const downgrade = { origin: 'http://app.example', host: 'internal:3000', 'x-forwarded-host': 'app.example', 'x-forwarded-proto': 'https' };
    assert.strictEqual(isTrustedOrigin(downgrade, req(downgrade)), false, 'http-страница в https-API');
    const unknownProto = { origin: 'http://app.example', host: 'app.example' };
    assert.strictEqual(isTrustedOrigin(unknownProto, req(unknownProto)), true, 'протокол неизвестен - схема не сверяется');
    assert.strictEqual(isTrustedOrigin(unknownProto), true, 'без req (сокет без запроса) тоже');
});

test('isTrustedOrigin: сокет ONION_PORT - схема не сверяется (onionMiddleware ставит X-Forwarded-Proto: https, а у страницы Origin http)', () => {
    const { isTrustedOrigin } = originWith({});
    const onionSocket = {};
    require('../lib/tor-support')._internal.markOnionSocket(onionSocket);
    const headers = { origin: 'http://127.0.0.1:3001', host: '127.0.0.1:3001', 'x-forwarded-proto': 'https' };
    assert.strictEqual(isTrustedOrigin(headers, { headers, socket: onionSocket }), true);
    assert.strictEqual(isTrustedOrigin(headers, { headers, socket: {} }), false, 'тот же запрос с обычного сокета отклоняется');
});

test('isTrustedOrigin: TLS на самом сокете даёт протокол https без заголовков', () => {
    const { isTrustedOrigin } = originWith({ TRUST_PROXY: '0' });
    const headers = { origin: 'http://localhost:3000', host: 'localhost:3000' };
    assert.strictEqual(isTrustedOrigin(headers, req(headers, true)), false);
    const secure = { origin: 'https://localhost:3000', host: 'localhost:3000' };
    assert.strictEqual(isTrustedOrigin(secure, req(secure, true)), true);
});

test('isTrustedOrigin при TRUST_PROXY=0: X-Forwarded-Host и X-Forwarded-Proto игнорируются, хостом считается Host', () => {
    const { isTrustedOrigin, trustProxyHops } = originWith({ TRUST_PROXY: '0' });
    assert.strictEqual(trustProxyHops, 0);
    const forged = { origin: 'https://evil.example', host: 'app.example', 'x-forwarded-host': 'evil.example', 'x-forwarded-proto': 'https' };
    assert.strictEqual(isTrustedOrigin(forged, req(forged)), false);
    const own = { origin: 'http://app.example', host: 'app.example', 'x-forwarded-proto': 'https' };
    assert.strictEqual(isTrustedOrigin(own, req(own)), true, 'протокол из заголовка не используется - схема не сверяется');
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

test('env-check: TRUST_PROXY - мусор и 0 на Railway дают предупреждение, 1 и пусто - нет', () => {
    assert.strictEqual(named(checkEnv(goodEnv()).warnings, 'TRUST_PROXY').length, 0);
    assert.strictEqual(named(checkEnv(goodEnv({ TRUST_PROXY: '1' })).warnings, 'TRUST_PROXY').length, 0);
    const bad = named(checkEnv(goodEnv({ TRUST_PROXY: '3' })).warnings, 'TRUST_PROXY');
    assert.strictEqual(bad.length, 1);
    assert.match(bad[0].message, /допустимо 1/);
    const off = named(checkEnv(goodEnv({ TRUST_PROXY: '0' })).warnings, 'TRUST_PROXY');
    assert.strictEqual(off.length, 1);
    assert.match(off[0].message, /адрес прокси/);
    const { RAILWAY_ENVIRONMENT_NAME, ...local } = goodEnv({ TRUST_PROXY: '0' });
    assert.strictEqual(named(checkEnv(local).warnings, 'TRUST_PROXY').length, 0, 'вне Railway 0 - обычный выбор');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
