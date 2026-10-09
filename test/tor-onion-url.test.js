'use strict';
// onionUrlFor (lib/tor-support.js): поле onionUrl в GET /api/auth и заголовок
// Onion-Location строятся одной функцией и при одних условиях (контракт
// этапа 1, §3): ONION_ADDRESS и ONION_PORT заданы, а запрос пришёл не через
// onion-порт. Тест перебирает сочетания настроек и тип соединения и сверяет:
// onionUrl не null ровно тогда, когда GET страницы получает Onion-Location,
// и заголовок — это onionUrl плюс путь запроса. Чистый Node, без сети.
// Запуск: node test/tor-onion-url.test.js

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');

const TOR_PATH = path.join(__dirname, '..', 'lib', 'tor-support.js');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// Свежий экземпляр модуля с заданным окружением: ONION_ADDRESS и ONION_PORT
// читаются при загрузке. Предупреждения модуля о кривых значениях
// глушатся — их проверяет test/pow.test.js.
function loadFresh(env) {
    const saved = {};
    const originalWarn = console.warn;
    for (const [key, value] of Object.entries(env)) {
        saved[key] = process.env[key];
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
    }
    console.warn = () => {};
    delete require.cache[require.resolve(TOR_PATH)];
    try {
        return require(TOR_PATH);
    } finally {
        console.warn = originalWarn;
        for (const [key, value] of Object.entries(saved)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
    }
}

// Синтаксически верный v3-адрес: контрольная сумма — как в rend-spec-v3,
// но независимо от кода модуля.
function makeOnionAddress(seed) {
    const pubkey = crypto.createHash('sha256').update(seed).digest();
    const version = Buffer.from([3]);
    const checksum = crypto.createHash('sha3-256')
        .update('.onion checksum').update(pubkey).update(version).digest().subarray(0, 2);
    const bytes = Buffer.concat([pubkey, checksum, version]);
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    let bitsStr = '';
    for (const b of bytes) bitsStr += b.toString(2).padStart(8, '0');
    let out = '';
    for (let i = 0; i < bitsStr.length; i += 5) out += alphabet[parseInt(bitsStr.slice(i, i + 5), 2)];
    return `${out}.onion`;
}

function makeReq({ method = 'GET', url = '/', socket = {} } = {}) {
    return { method, url, originalUrl: url, headers: { host: 'nyxo.up.railway.app' }, socket };
}

// Заголовок Onion-Location, который onionMiddleware поставил бы на ответ.
function onionLocationOf(tor, req) {
    const headers = {};
    let nextCalled = false;
    tor.onionMiddleware(req, { setHeader: (name, value) => { headers[name.toLowerCase()] = value; } }, () => {
        nextCalled = true;
    });
    assert.ok(nextCalled, 'next() must be called');
    return headers['onion-location'];
}

async function main() {
    const ONION = makeOnionAddress('nyxo-onion-url');

    const configs = [
        { name: 'ONION_ADDRESS + ONION_PORT', env: { ONION_ADDRESS: ONION, ONION_PORT: '9999' }, enabled: true },
        { name: 'no ONION_PORT', env: { ONION_ADDRESS: ONION, ONION_PORT: undefined }, enabled: false },
        { name: 'no ONION_ADDRESS', env: { ONION_ADDRESS: undefined, ONION_PORT: '9999' }, enabled: false },
        { name: 'nothing set', env: { ONION_ADDRESS: undefined, ONION_PORT: undefined }, enabled: false },
        { name: 'invalid ONION_ADDRESS', env: { ONION_ADDRESS: 'example.onion', ONION_PORT: '9999' }, enabled: false },
        { name: 'invalid ONION_PORT', env: { ONION_ADDRESS: ONION, ONION_PORT: '70000' }, enabled: false },
    ];

    for (const config of configs) {
        const tor = loadFresh(config.env);
        await test(`${config.name}: onionUrl and Onion-Location agree (clearnet and onion socket)`, () => {
            for (const viaOnion of [false, true]) {
                const socket = {};
                if (viaOnion) tor._internal.markOnionSocket(socket);
                const expected = config.enabled && !viaOnion ? `http://${ONION}/` : null;
                const where = `${config.name}, ${viaOnion ? 'onion' : 'clearnet'}`;

                // GET /api/auth: заголовка нет (это не страница), но поле
                // onionUrl считается той же функцией по тому же соединению.
                const authReq = makeReq({ url: '/api/auth', socket });
                assert.strictEqual(onionLocationOf(tor, authReq), undefined, `${where}: no header on API`);
                assert.strictEqual(tor.onionUrlFor(authReq), expected, `${where}: onionUrl`);

                for (const url of ['/', '/chat?room=5&x=%20y', '/style.css']) {
                    const req = makeReq({ url, socket });
                    const header = onionLocationOf(tor, req);
                    const onionUrl = tor.onionUrlFor(req);
                    assert.strictEqual(onionUrl, expected, `${where} ${url}: onionUrl`);
                    assert.strictEqual(header, onionUrl === null ? undefined : onionUrl + url.slice(1),
                        `${where} ${url}: Onion-Location = onionUrl + path`);
                }
            }
        });
    }

    await test('onionUrl format: http://<56 base32>.onion/', () => {
        const tor = loadFresh({ ONION_ADDRESS: ONION.toUpperCase(), ONION_PORT: '9999' });
        const onionUrl = tor.onionUrlFor(makeReq());
        assert.match(onionUrl, /^http:\/\/[a-z2-7]{56}\.onion\/$/);
        assert.strictEqual(onionUrl, `http://${ONION}/`, 'lower-cased address from ONION_ADDRESS');
    });

    await test('onionUrlFor tolerates a request without socket', () => {
        const on = loadFresh({ ONION_ADDRESS: ONION, ONION_PORT: '9999' });
        const off = loadFresh({ ONION_ADDRESS: undefined, ONION_PORT: undefined });
        assert.strictEqual(on.onionUrlFor({}), `http://${ONION}/`);
        assert.strictEqual(on.onionUrlFor(undefined), `http://${ONION}/`);
        assert.strictEqual(off.onionUrlFor({}), null);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
