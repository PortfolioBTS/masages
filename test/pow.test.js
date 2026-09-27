'use strict';
// Тесты proof-of-work (lib/pow.js + public/pow-worker.js) и onion-поддержки
// (lib/tor-support.js). Чистый Node: без БД и внешней сети (Express и
// express-session поднимаются только на loopback, чтобы проверить, как
// onionMiddleware взаимодействует с trust proxy и Secure-кукой сессии).
// Запуск: node test/pow.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const vm = require('vm');

const WORKER_PATH = path.join(__dirname, '..', 'public', 'pow-worker.js');
const POW_PATH = path.join(__dirname, '..', 'lib', 'pow.js');
const TOR_PATH = path.join(__dirname, '..', 'lib', 'tor-support.js');

const worker = require(WORKER_PATH);

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

// Свежий экземпляр модуля с заданным окружением (значения читаются при
// загрузке). Возвращает модуль и всё, что он успел написать в console.warn.
function loadFresh(modulePath, env) {
    const saved = {};
    const warnings = [];
    const originalWarn = console.warn;
    for (const [key, value] of Object.entries(env)) {
        saved[key] = process.env[key];
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
    }
    console.warn = (...args) => warnings.push(args.join(' '));
    delete require.cache[require.resolve(modulePath)];
    try {
        return { mod: require(modulePath), warnings };
    } finally {
        console.warn = originalWarn;
        for (const [key, value] of Object.entries(saved)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
    }
}

function sha256Hex(str) {
    return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function leadingZeroBits(hex) {
    let bits = 0;
    for (const ch of hex) {
        const nibble = parseInt(ch, 16);
        if (nibble === 0) { bits += 4; continue; }
        return bits + Math.clz32(nibble) - 28;
    }
    return bits;
}

// Nonce, у которого ровно `bits` ведущих нулевых бит (для проверки "почти").
function findNonceWithExactBits(token, bits) {
    for (let n = 0; ; n++) {
        if (leadingZeroBits(sha256Hex(`${token}:${n}`)) === bits) return String(n);
    }
}

function decodePayload(token) {
    return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

function encodePayload(payload) {
    return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

// Произвольный синтаксически верный v3-адрес: контрольная сумма считается
// так же, как в rend-spec-v3, но независимо от кода модуля.
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

function makeReq({ method = 'GET', url = '/', headers = {}, socket = {} } = {}) {
    return { method, url, originalUrl: url, headers: { ...headers }, socket };
}

// Свободный TCP-порт (ONION_PORT читается при загрузке модуля, поэтому
// порт нужен заранее, а не через listen(0)).
function freePort() {
    return new Promise((resolve, reject) => {
        const probe = require('net').createServer();
        probe.once('error', reject);
        probe.listen(0, '127.0.0.1', () => {
            const { port } = probe.address();
            probe.close(() => resolve(port));
        });
    });
}

function requestPort(port, { path: reqPath = '/', headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path: reqPath, headers }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        req.on('error', reject);
        req.end();
    });
}

function makeRes() {
    const headers = {};
    return { headers, setHeader: (name, value) => { headers[name.toLowerCase()] = value; } };
}

function runMiddleware(middleware, req, res) {
    let called = false;
    middleware(req, res, () => { called = true; });
    assert.ok(called, 'next() must be called');
}

function listen(app) {
    return new Promise((resolve) => {
        const server = http.createServer(app).listen(0, '127.0.0.1', () => resolve(server));
    });
}

function request(server, { path: reqPath = '/', headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port: server.address().port, path: reqPath, headers }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        req.on('error', reject);
        req.end();
    });
}

async function main() {
    console.log('PoW / Tor tests\n');

    // ---------------------------------------------------------------- SHA-256
    await test('worker sha256 matches node:crypto on edge and random lengths', () => {
        const lengths = [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 1000, 4096];
        for (let i = 0; i < 64; i++) lengths.push(crypto.randomInt(0, 300));
        for (const len of lengths) {
            const bytes = crypto.randomBytes(len);
            const actual = Buffer.from(worker.sha256(new Uint8Array(bytes))).toString('hex');
            const expected = crypto.createHash('sha256').update(bytes).digest('hex');
            assert.strictEqual(actual, expected, `length ${len}`);
        }
        assert.strictEqual(Buffer.from(worker.sha256(new Uint8Array(0))).toString('hex'),
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        assert.throws(() => worker.sha256('abc'), TypeError);
    });

    await test('worker solve: correct for every prefix length (1- and 2-block tails) and digit growth', () => {
        // Длины 1..140 покрывают все положения ':' внутри блока, включая те,
        // где хвост + nonce + добивка не помещаются в один блок.
        for (let len = 1; len <= 140; len++) {
            const token = crypto.randomBytes(len).toString('base64url').slice(0, len);
            const nonce = worker.solve(token, 8);
            assert.match(nonce, /^[0-9]{1,20}$/);
            assert.ok(leadingZeroBits(sha256Hex(`${token}:${nonce}`)) >= 8, `len ${len}`);
        }
        // При d = 12 nonce в среднем ~4096 — перебор проходит через 1, 2, 3 и
        // 4 цифры, то есть через пересборку хвоста при росте длины.
        let crossed = 0;
        for (let i = 0; i < 20; i++) {
            const token = crypto.randomBytes(100).toString('base64url');
            const nonce = worker.solve(token, 12);
            if (nonce.length >= 3) crossed++;
            assert.ok(leadingZeroBits(sha256Hex(`${token}:${nonce}`)) >= 12);
            // Первое же подходящее число: у всех меньших nonce нулей меньше.
            for (let n = 0; n < Number(nonce); n++) {
                assert.ok(leadingZeroBits(sha256Hex(`${token}:${n}`)) < 12, 'solve must return the first hit');
            }
        }
        assert.ok(crossed > 0, 'at least one run must grow past two digits');
        assert.strictEqual(worker.solve('anything', 0), '0');
    });

    await test('worker solve rejects bad input', () => {
        assert.throws(() => worker.solve('', 8), TypeError);
        assert.throws(() => worker.solve(123, 8), TypeError);
        assert.throws(() => worker.solve('t', 8.5), RangeError);
        assert.throws(() => worker.solve('t', -1), RangeError);
        assert.throws(() => worker.solve('t', '8'), RangeError);
    });

    await test('pow-worker.js runs as a classic Web Worker (onmessage -> postMessage)', () => {
        const code = fs.readFileSync(WORKER_PATH, 'utf8');
        // CSP script-src 'self': никакого eval/new Function/importScripts.
        assert.ok(!/\beval\s*\(|new\s+Function\s*\(|importScripts\s*\(/.test(code), 'no eval / importScripts');
        const posted = [];
        const self = { postMessage: (msg) => posted.push(msg) };
        vm.runInContext(code, vm.createContext({ self, TextEncoder }), { filename: 'pow-worker.js' });
        assert.strictEqual(typeof self.onmessage, 'function', 'worker must register onmessage');
        const token = crypto.randomBytes(40).toString('base64url');
        self.onmessage({ data: { token, difficulty: 10 } });
        assert.strictEqual(posted.length, 1);
        assert.strictEqual(typeof posted[0].nonce, 'string');
        assert.ok(leadingZeroBits(sha256Hex(`${token}:${posted[0].nonce}`)) >= 10);
        // В Node файл экспортирует функции и не трогает глобальный onmessage.
        assert.deepStrictEqual(Object.keys(worker).sort(), ['sha256', 'solve']);
        assert.strictEqual(typeof globalThis.onmessage, 'undefined');
    });

    // -------------------------------------------------------------------- PoW
    const { mod: pow, warnings: defaultWarnings } = loadFresh(POW_PATH, { POW_DIFFICULTY: undefined });

    await test('default difficulty is 18 and challenge has the documented shape', () => {
        assert.deepStrictEqual(defaultWarnings, []);
        const { token, difficulty } = pow.createChallenge('register');
        assert.strictEqual(difficulty, 18);
        assert.match(token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
        const payload = decodePayload(token);
        assert.deepStrictEqual(Object.keys(payload).sort(), ['d', 'e', 'p', 's', 'v']);
        assert.strictEqual(payload.p, 'register');
        assert.strictEqual(payload.d, 18);
        assert.strictEqual(Buffer.from(payload.s, 'base64url').length, 16);
        const ttl = payload.e - Date.now();
        assert.ok(ttl > 4.9 * 60 * 1000 && ttl <= 5 * 60 * 1000, 'expires in 5 minutes');
        assert.notStrictEqual(pow.createChallenge('register').token, token, 'salt makes tokens unique');
    });

    await test('solve -> verifySolution is true, and the same solution is single-use', () => {
        for (const purpose of ['register', 'register-anon']) {
            const { token, difficulty } = pow.createChallenge(purpose);
            const nonce = worker.solve(token, difficulty);
            assert.strictEqual(pow.verifySolution({ token, nonce }, purpose), true);
            assert.strictEqual(pow.verifySolution({ token, nonce }, purpose), false, 'replay must fail');
        }
    });

    await test('a wrong nonce does not burn the challenge', () => {
        const { token, difficulty } = pow.createChallenge('register');
        const nonce = worker.solve(token, difficulty);
        const bad = findNonceWithExactBits(token, 0);
        assert.strictEqual(pow.verifySolution({ token, nonce: bad }, 'register'), false);
        assert.strictEqual(pow.verifySolution({ token, nonce }, 'register'), true);
    });

    await test('purpose mismatch and unknown purpose are rejected', () => {
        const { token, difficulty } = pow.createChallenge('register');
        const nonce = worker.solve(token, difficulty);
        assert.strictEqual(pow.verifySolution({ token, nonce }, 'register-anon'), false);
        assert.strictEqual(pow.verifySolution({ token, nonce }, 'login'), false);
        assert.strictEqual(pow.verifySolution({ token, nonce }, undefined), false);
        assert.throws(() => pow.createChallenge('login'));
        assert.throws(() => pow.createChallenge(undefined));
        assert.throws(() => pow.createChallenge({ toString: () => 'register' }));
        // Отказ по purpose не должен был пометить токен использованным.
        assert.strictEqual(pow.verifySolution({ token, nonce }, 'register'), true);
    });

    await test('expired challenge is rejected (injected clock)', () => {
        const t0 = Date.now();
        try {
            pow._setNowForTests(() => t0);
            const a = pow.createChallenge('register');
            const b = pow.createChallenge('register');
            const nonceA = worker.solve(a.token, a.difficulty);
            const nonceB = worker.solve(b.token, b.difficulty);
            pow._setNowForTests(() => t0 + 5 * 60 * 1000 - 1);
            assert.strictEqual(pow.verifySolution({ token: a.token, nonce: nonceA }, 'register'), true, 'valid until the last ms');
            pow._setNowForTests(() => t0 + 5 * 60 * 1000);
            assert.strictEqual(pow.verifySolution({ token: b.token, nonce: nonceB }, 'register'), false, 'expired');
        } finally {
            pow._setNowForTests();
        }
    });

    await test('forged tokens are rejected: edited difficulty/purpose, broken HMAC, non-canonical signature, other process', () => {
        const { token } = pow.createChallenge('register');
        const [payloadB64, sig] = token.split('.');
        const payload = decodePayload(token);

        // Понизили сложность в payload, подпись старая. nonce подобран под d=8,
        // чтобы отказ был именно из-за подписи, а не из-за хэша.
        const easier = `${encodePayload({ ...payload, d: 8 })}.${sig}`;
        assert.strictEqual(pow.verifySolution({ token: easier, nonce: worker.solve(easier, 8) }, 'register'), false);

        const otherPurpose = `${encodePayload({ ...payload, p: 'register-anon' })}.${sig}`;
        assert.strictEqual(pow.verifySolution({ token: otherPurpose, nonce: worker.solve(otherPurpose, 18) }, 'register-anon'), false);

        const flipped = sig[0] === 'A' ? 'B' + sig.slice(1) : 'A' + sig.slice(1);
        const brokenHmac = `${payloadB64}.${flipped}`;
        assert.strictEqual(pow.verifySolution({ token: brokenHmac, nonce: worker.solve(brokenHmac, 18) }, 'register'), false);

        // Те же 32 байта подписи другой строкой (младшие неиспользуемые биты
        // последнего символа): решение нельзя "переупаковать" в новый токен.
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        const lastIndex = alphabet.indexOf(sig[sig.length - 1]);
        const altSig = sig.slice(0, -1) + alphabet[lastIndex ^ 1];
        assert.deepStrictEqual(Buffer.from(altSig, 'base64url'), Buffer.from(sig, 'base64url'), 'same bytes');
        const aliased = `${payloadB64}.${altSig}`;
        assert.strictEqual(pow.verifySolution({ token: aliased, nonce: worker.solve(aliased, 18) }, 'register'), false);

        // Токен другого процесса (другой случайный ключ HMAC).
        const { mod: otherPow } = loadFresh(POW_PATH, { POW_DIFFICULTY: undefined });
        const foreign = otherPow.createChallenge('register');
        assert.strictEqual(pow.verifySolution({ token: foreign.token, nonce: worker.solve(foreign.token, 18) }, 'register'), false);

        // Мусор вместо токена.
        for (const bad of ['', '.', 'abc', `${token}.x`, `.${sig}`, `${payloadB64}.`, 'x'.repeat(600), `${payloadB64}!.${sig}`]) {
            assert.strictEqual(pow.verifySolution({ token: bad, nonce: '1' }, 'register'), false, JSON.stringify(bad.slice(0, 20)));
        }
        // Оригинал при этом по-прежнему решаем.
        assert.strictEqual(pow.verifySolution({ token, nonce: worker.solve(token, 18) }, 'register'), true);
    });

    await test('malformed solutions and nonces are rejected', () => {
        const { token, difficulty } = pow.createChallenge('register');
        const nonce = worker.solve(token, difficulty);
        for (const bad of [null, undefined, 'x', 42, [token, nonce], { token }, { nonce }, { token: 1, nonce }]) {
            assert.strictEqual(pow.verifySolution(bad, 'register'), false);
        }
        const badNonces = [
            Number(nonce), '', ' 1', '1 ', '-1', '+1', '1e5', '0x1f', '12a', '١٢', '1.0',
            '1'.repeat(21), '0'.repeat(21)
        ];
        for (const bad of badNonces) {
            assert.strictEqual(pow.verifySolution({ token, nonce: bad }, 'register'), false, JSON.stringify(bad));
        }
        // Ведущие нули допустимы (это всё ещё цифры, ≤ 20 символов): решение,
        // найденное с ними, принимается.
        assert.strictEqual(pow.verifySolution({ token, nonce }, 'register'), true);
    });

    await test('insufficient leading zero bits (near miss d-1) is rejected', () => {
        const { mod: easyPow } = loadFresh(POW_PATH, { POW_DIFFICULTY: '12' });
        const { token, difficulty } = easyPow.createChallenge('register');
        assert.strictEqual(difficulty, 12);
        const nearMiss = findNonceWithExactBits(token, 11);
        assert.strictEqual(leadingZeroBits(sha256Hex(`${token}:${nearMiss}`)), 11);
        assert.strictEqual(easyPow.verifySolution({ token, nonce: nearMiss }, 'register'), false);
        const exact = findNonceWithExactBits(token, 12);
        assert.strictEqual(easyPow.verifySolution({ token, nonce: exact }, 'register'), true);
    });

    await test('POW_DIFFICULTY: accepted range 8..28, anything else falls back to 18 with a warning', () => {
        for (const value of ['8', '20', '28']) {
            const { mod, warnings } = loadFresh(POW_PATH, { POW_DIFFICULTY: value });
            assert.strictEqual(mod.createChallenge('register').difficulty, Number(value));
            assert.deepStrictEqual(warnings, []);
        }
        for (const value of ['7', '29', '18.5', 'abc', '-3', '1e1', '0x10', ' 20', '020']) {
            const { mod, warnings } = loadFresh(POW_PATH, { POW_DIFFICULTY: value });
            assert.strictEqual(mod.createChallenge('register').difficulty, 18, value);
            assert.strictEqual(warnings.length, 1, value);
        }
    });

    await test('used-token registry is purged after expiry', () => {
        const { mod } = loadFresh(POW_PATH, { POW_DIFFICULTY: '8' });
        const t0 = Date.now();
        mod._setNowForTests(() => t0);
        for (let i = 0; i < 5; i++) {
            const { token, difficulty } = mod.createChallenge('register-anon');
            assert.strictEqual(mod.verifySolution({ token, nonce: worker.solve(token, difficulty) }, 'register-anon'), true);
        }
        assert.strictEqual(mod._internal.usedCount(), 5);
        mod._internal.purgeUsed();
        assert.strictEqual(mod._internal.usedCount(), 5, 'not expired yet');
        mod._setNowForTests(() => t0 + 5 * 60 * 1000);
        mod._internal.purgeUsed();
        assert.strictEqual(mod._internal.usedCount(), 0);
    });

    await test('solve timing at difficulty 18 (informational)', () => {
        const runs = 10;
        let hashes = 0;
        const started = process.hrtime.bigint();
        for (let i = 0; i < runs; i++) {
            const { token, difficulty } = pow.createChallenge('register');
            const nonce = worker.solve(token, difficulty);
            hashes += Number(nonce) + 1;
            assert.strictEqual(pow.verifySolution({ token, nonce }, 'register'), true);
        }
        const seconds = Number(process.hrtime.bigint() - started) / 1e9;
        console.log(`        info: d=18, ${runs} решений, в среднем ${(seconds / runs * 1000).toFixed(0)} мс, ` +
            `${(hashes / seconds / 1e6).toFixed(2)} млн хэшей/с`);
    });

    // ------------------------------------------------------------------- Tor
    const ONION = makeOnionAddress('nyxo-test');

    await test('ONION_ADDRESS: v3 with valid checksum accepted, everything else -> null + warning', () => {
        const unset = loadFresh(TOR_PATH, { ONION_ADDRESS: undefined });
        assert.strictEqual(unset.mod.ONION_ADDRESS, null);
        assert.deepStrictEqual(unset.warnings, []);

        const ok = loadFresh(TOR_PATH, { ONION_ADDRESS: `  ${ONION.toUpperCase()} `, ONION_PORT: '9999' });
        assert.strictEqual(ok.mod.ONION_ADDRESS, ONION, 'trimmed and lower-cased');
        assert.deepStrictEqual(ok.warnings, []);

        // Реальные адреса (torproject.org, duckduckgo) — страховка от
        // симметричной ошибки в кодировании base32/контрольной суммы.
        const { isValidOnionV3 } = ok.mod._internal;
        assert.ok(isValidOnionV3('2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion'));
        assert.ok(isValidOnionV3('duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'));

        const typo = ONION.slice(0, 10) + (ONION[10] === 'a' ? 'b' : 'a') + ONION.slice(11);
        const invalid = [
            typo,                                   // опечатка -> контрольная сумма не сходится
            `http://${ONION}`,
            `${ONION}/`,
            ONION.replace('.onion', ''),
            'expyuzz4wqqyqhjn.onion',               // v2 (16 символов)
            `${ONION.slice(0, 55)}1.onion`,         // '1' нет в base32
            'example.com'
        ];
        for (const value of invalid) {
            const res = loadFresh(TOR_PATH, { ONION_ADDRESS: value });
            assert.strictEqual(res.mod.ONION_ADDRESS, null, value);
            assert.strictEqual(res.warnings.length, 1, value);
        }
    });

    const ONION_PORT = await freePort();
    const { mod: tor } = loadFresh(TOR_PATH, { ONION_ADDRESS: ONION, ONION_PORT: String(ONION_PORT) });
    const { mod: torOff } = loadFresh(TOR_PATH, { ONION_ADDRESS: undefined, ONION_PORT: undefined });

    await test('ONION_PORT: parsed; ONION_ADDRESS without ONION_PORT disables onion mode with a warning', () => {
        assert.strictEqual(tor.ONION_PORT, ONION_PORT);
        const noPort = loadFresh(TOR_PATH, { ONION_ADDRESS: ONION, ONION_PORT: undefined });
        assert.strictEqual(noPort.mod.ONION_PORT, null);
        assert.strictEqual(noPort.warnings.length, 1);
        const bad = loadFresh(TOR_PATH, { ONION_ADDRESS: ONION, ONION_PORT: '70000' });
        assert.strictEqual(bad.mod.ONION_PORT, null);
        // Без порта Onion-Location не рекламируется, а Host ничего не решает.
        const req = makeReq({ headers: { host: ONION } });
        const res = makeRes();
        runMiddleware(noPort.mod.onionMiddleware, req, res);
        assert.strictEqual(req.isOnion, false);
        assert.strictEqual(res.headers['onion-location'], undefined);
    });

    await test('isOnionHost normalizes port, case and trailing dot', () => {
        assert.strictEqual(tor.isOnionHost(ONION), true);
        assert.strictEqual(tor.isOnionHost(`${ONION}:80`), true);
        assert.strictEqual(tor.isOnionHost(`${ONION.toUpperCase()}.`), true);
        assert.strictEqual(tor.isOnionHost(`evil.${ONION}`), false);
        assert.strictEqual(tor.isOnionHost(`${ONION}.evil.com`), false);
        assert.strictEqual(tor.isOnionHost('nyxo.up.railway.app'), false);
        assert.strictEqual(tor.isOnionHost(undefined), false);
        assert.strictEqual(tor.isOnionHost(['x']), false);
        assert.strictEqual(torOff.isOnionHost(ONION), false);
        assert.strictEqual(torOff.isOnionHost(''), false);
    });

    await test('onionMiddleware: onion socket is marked, forwarding headers dropped, treated as secure', () => {
        const socket = {};
        tor._internal.markOnionSocket(socket);
        const req = makeReq({
            socket,
            headers: {
                host: ONION,
                'x-forwarded-for': '6.6.6.6',
                'x-forwarded-host': 'evil.example',
                'x-real-ip': '6.6.6.6',
                'cf-connecting-ip': '6.6.6.6',
                forwarded: 'for=6.6.6.6',
                'x-forwarded-proto': 'http',
                cookie: 'a=b'
            }
        });
        const res = makeRes();
        runMiddleware(tor.onionMiddleware, req, res);
        assert.strictEqual(req.isOnion, true);
        for (const h of ['x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'cf-connecting-ip', 'forwarded']) {
            assert.strictEqual(req.headers[h], undefined, h);
        }
        assert.strictEqual(req.headers['x-forwarded-proto'], 'https');
        assert.strictEqual(req.headers.cookie, 'a=b', 'other headers untouched');
        assert.strictEqual(res.headers['onion-location'], undefined, 'no Onion-Location inside onion');
    });

    await test('onionMiddleware: Onion-Location only on clearnet GET page requests', () => {
        const cases = [
            { method: 'GET', url: '/', expect: `http://${ONION}/` },
            { method: 'GET', url: '/chat?room=5&x=%20y', expect: `http://${ONION}/chat?room=5&x=%20y` },
            { method: 'GET', url: '/style.css', expect: `http://${ONION}/style.css` },
            { method: 'GET', url: '/api/auth', expect: undefined },
            { method: 'GET', url: '/api', expect: undefined },
            { method: 'GET', url: '/socket.io/?EIO=4&transport=polling', expect: undefined },
            { method: 'GET', url: '/uploads/abc.bin', expect: undefined },
            { method: 'POST', url: '/', expect: undefined },
            { method: 'HEAD', url: '/', expect: undefined },
            { method: 'GET', url: '/a b', expect: undefined },
            { method: 'GET', url: '/é', expect: undefined }
        ];
        for (const { method, url, expect } of cases) {
            const req = makeReq({ method, url, headers: { host: 'nyxo.up.railway.app', 'x-forwarded-for': '1.2.3.4' } });
            const res = makeRes();
            runMiddleware(tor.onionMiddleware, req, res);
            assert.strictEqual(req.isOnion, false);
            assert.strictEqual(res.headers['onion-location'], expect, `${method} ${url}`);
            assert.strictEqual(req.headers['x-forwarded-for'], '1.2.3.4', 'clearnet headers untouched');
        }
        // Onion-Host на обычном (не onion) сокете — подделка: не onion.
        const spoofed = makeReq({ headers: { host: ONION, 'x-forwarded-for': '6.6.6.6' } });
        runMiddleware(tor.onionMiddleware, spoofed, makeRes());
        assert.strictEqual(spoofed.isOnion, false);
        assert.strictEqual(spoofed.headers['x-forwarded-for'], '6.6.6.6', 'left for trust proxy, not treated as onion');
        // Без ONION_ADDRESS — ничего не делает.
        const req = makeReq({ headers: { host: ONION, 'x-forwarded-for': '1.2.3.4' } });
        const res = makeRes();
        runMiddleware(torOff.onionMiddleware, req, res);
        assert.strictEqual(req.isOnion, false);
        assert.strictEqual(res.headers['onion-location'], undefined);
        assert.strictEqual(req.headers['x-forwarded-for'], '1.2.3.4');
    });

    await test('express integration: onion port marks sockets, spoofed headers ignored, Secure session cookie issued', async () => {
        const express = require('express');
        const session = require('express-session');
        const app = express();
        app.set('trust proxy', 1);
        app.use(tor.onionMiddleware);
        app.use(session({
            secret: 'test', resave: false, saveUninitialized: false, proxy: true,
            cookie: { httpOnly: true, secure: true, sameSite: 'none' }
        }));
        app.get('/', (req, res) => {
            req.session.seen = true;
            res.json({ ip: req.ip, hostname: req.hostname, secure: req.secure, isOnion: req.isOnion });
        });
        const server = await listen(app);
        const onionListener = await new Promise((resolve) => {
            const l = tor.listenOnionPort(server, '127.0.0.1', () => resolve(l));
        });
        try {
            // Через onion-порт — даже с чужим Host и подделанными заголовками.
            const viaOnion = await requestPort(ONION_PORT, {
                headers: { host: 'nyxo.up.railway.app', 'x-forwarded-for': '6.6.6.6', 'x-forwarded-host': 'evil.example' }
            });
            const body = JSON.parse(viaOnion.body);
            assert.strictEqual(body.isOnion, true);
            assert.match(body.ip, /127\.0\.0\.1$/, 'client-supplied X-Forwarded-For must not become req.ip');
            assert.strictEqual(body.hostname, 'nyxo.up.railway.app', 'X-Forwarded-Host from the client is dropped');
            assert.strictEqual(body.secure, true);
            const cookie = (viaOnion.headers['set-cookie'] || []).join(';');
            assert.match(cookie, /connect\.sid=.*Secure/i, 'session cookie must be issued over onion');
            assert.strictEqual(viaOnion.headers['onion-location'], undefined);

            // Публичный порт: ни Host, ни X-Forwarded-Host не делают запрос onion.
            for (const headers of [
                { host: 'nyxo.up.railway.app', 'x-forwarded-host': ONION, 'x-forwarded-proto': 'https' },
                { host: ONION },
            ]) {
                const spoof = await request(server, { headers });
                assert.strictEqual(JSON.parse(spoof.body).isOnion, false, JSON.stringify(headers));
                assert.strictEqual(spoof.headers['onion-location'], `http://${ONION}/`);
            }
        } finally {
            onionListener.close();
            server.close();
        }
    });

    await test('listenOnionPort: disabled without ONION_PORT and for an HTTPS main server', () => {
        assert.strictEqual(torOff.listenOnionPort(http.createServer(), '127.0.0.1'), null);
        const warnings = [];
        const originalWarn = console.warn;
        console.warn = (...args) => warnings.push(args.join(' '));
        try {
            assert.strictEqual(tor.listenOnionPort(require('https').createServer(), '127.0.0.1'), null);
        } finally {
            console.warn = originalWarn;
        }
        assert.strictEqual(warnings.length, 1);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
