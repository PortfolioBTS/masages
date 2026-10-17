'use strict';
// Открытый ключ журнала ключей в манифесте релиза (T5.4, roadmap R10, docs/security/key-transparency.md, раздел 11):
//   * манифест получает keys.kt только при заданном ключе, иначе байты прежние;
//   * сервер (lib/routes/client-manifest.js, ключ из KT_SIGNING_KEY) и релиз (scripts/release-manifest.js,
//     --kt-key или KT_PUBLIC_KEY) дают байт в байт один манифест;
//   * ключ проходит строгую проверку Ed25519 (оба отрицательных вектора signed-membership.md 6.6 и восемь точек малого порядка);
//   * клиент (public/lib/kt-client.js, fetchManifestKey) берёт ключ из /client-manifest.json и сверяет с ним ключ
//     журнала при первом закреплении: несовпадение — тревога key-changed (reason manifest);
//   * разбор и сравнение манифестов (public/lib/client-verify.js) учитывают keys.kt.
// Запуск: node test/client-manifest-kt-key.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { readClientScript, clientScriptFiles } = require('./client-script-source');
const { spawnSync } = require('child_process');

const manifestLib = require('../lib/client-manifest');
const releaseScript = require('../scripts/release-manifest');
const manifestRoute = require('../lib/routes/client-manifest');
const verifyLib = require('../public/lib/client-verify');
const KtClient = require('../public/lib/kt-client');
const strict = require('../public/lib/ed25519-strict');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const SCRIPT = path.join(ROOT, 'scripts', 'release-manifest.js');

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

const tmpDirs = [];
function makeTmp() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-ktkey-'));
    tmpDirs.push(dir);
    return dir;
}
process.on('exit', () => { for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true }); });

// Настоящий ключ журнала: пара Ed25519, как у сервера (KT_SIGNING_KEY — base64 PKCS#8).
function newLogKey() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    return {
        pkcs8: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
        pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
    };
}

// Небольшой каталог public/ для быстрых и независимых от репозитория проверок.
function syntheticPublic() {
    const dir = makeTmp();
    fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html>\n');
    fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(1);\n');
    return dir;
}

function runScript(args, env = {}) {
    const clean = { ...process.env };
    for (const name of ['GITHUB_SHA', 'SOURCE_DATE_EPOCH', 'KT_PUBLIC_KEY']) delete clean[name];
    return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, env: { ...clean, ...env }, encoding: 'utf8' });
}

const ONE = '0100000000000000000000000000000000000000000000000000000000000000';
const ONE_SIGN = '0100000000000000000000000000000000000000000000000000000000000080';
const b64Hex = (hex) => Buffer.from(hex, 'hex').toString('base64');
// Тот же ключ с ненулевыми лишними битами в последнем символе (два младших бита 43-го символа base64 у 32 байт обязаны быть нулями).
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const nonCanonical = (key) => key.slice(0, 42) + ALPHABET[ALPHABET.indexOf(key[42]) | 1] + '=';
const FIXED = { version: '1.2.3', commit: 'a'.repeat(40), epoch: 1800000000, nodeVersion: 'v24.0.0' };

(async () => {
    console.log('Ключ журнала в манифесте релиза\n');

    // ===================== Манифест =====================

    await test('без ключа манифест прежний: поля keys нет, байты не зависят от параметров', () => {
        const dir = syntheticPublic();
        const plain = manifestLib.buildManifestText(dir);
        for (const none of [undefined, null, '', '   ']) {
            assert.strictEqual(manifestLib.buildManifestText(dir, { ktKey: none }), plain, JSON.stringify(none));
        }
        assert.deepStrictEqual(Object.keys(JSON.parse(plain)), ['format', 'aliases', 'files']);
    });

    await test('с ключом: keys.kt идёт последним полем, остальное содержимое то же, хэш манифеста другой', () => {
        const dir = syntheticPublic();
        const key = newLogKey().pub;
        const plain = JSON.parse(manifestLib.buildManifestText(dir));
        const text = manifestLib.buildManifestText(dir, { ktKey: key });
        const withKey = JSON.parse(text);
        assert.deepStrictEqual(Object.keys(withKey), ['format', 'aliases', 'files', 'keys']);
        assert.deepStrictEqual(withKey.keys, { kt: key });
        assert.deepStrictEqual({ ...withKey, keys: undefined }, { ...plain, keys: undefined });
        assert.notStrictEqual(manifestLib.manifestSha256(text), manifestLib.manifestSha256(manifestLib.buildManifestText(dir)));
        assert.strictEqual(manifestLib.buildManifestText(dir, { ktKey: key }), text, 'детерминированно');
        assert.ok(text.endsWith('\n') && !text.includes('\r'));
    });

    await test('ключ проверяется: длина, base64, каноничность, оба вектора 6.6, восемь точек малого порядка, y >= p', () => {
        const dir = syntheticPublic();
        const good = newLogKey().pub;
        assert.strictEqual(manifestLib.normalizeKtKey(good), good);
        assert.strictEqual(manifestLib.normalizeKtKey('  ' + good + '\n'), good, 'пробелы вокруг отбрасываются');
        const bad = {
            'не строка': 42,
            'пустой по длине': Buffer.alloc(0).toString('base64') + 'AAAA',
            '31 байт': crypto.randomBytes(31).toString('base64'),
            '33 байта': crypto.randomBytes(33).toString('base64'),
            'не base64': '!!!!' + good.slice(4),
            'url-safe алфавит': good.replace(/\+/g, '-').replace(/\//g, '_') + 'x',
            'без выравнивания': good.replace(/=+$/, ''),
            'неканоническое (лишние биты)': nonCanonical(good),
            'единичная точка 01 00…00': b64Hex(ONE),
            '01 00…00 80 (x = 0, бит знака 1)': b64Hex(ONE_SIGN),
            'ec ff…ff ff': b64Hex('ec' + 'ff'.repeat(31)),
            'y >= p': b64Hex('ed' + 'ff'.repeat(30) + '7f'),
            'нулевой ключ': Buffer.alloc(32).toString('base64'),
        };
        for (const hex of strict.SMALL_ORDER_ENCODINGS) bad['малый порядок ' + hex] = b64Hex(hex);
        for (const [what, key] of Object.entries(bad)) {
            assert.throws(() => manifestLib.normalizeKtKey(key), /ключ журнала/, what);
            assert.throws(() => manifestLib.buildManifest(dir, { ktKey: key }), /ключ журнала/, what);
        }
    });

    // ===================== Сервер и релиз =====================

    await test('релиз и сервер дают один манифест байт в байт; release.json повторяет ключ; без ключа поля keys нет', () => {
        const dir = syntheticPublic();
        const key = newLogKey().pub;
        const provider = manifestLib.createManifestProvider(dir, { ktKey: key });
        const release = releaseScript.buildReleaseFiles({ publicDir: dir, ...FIXED, ktKey: key });
        assert.strictEqual(release.manifestText, provider.get().text, 'манифест релиза = манифест сервера');
        assert.strictEqual(manifestLib.manifestSha256(release.manifestText), provider.get().sha256);
        const info = JSON.parse(release.releaseText);
        assert.deepStrictEqual(info.keys, { kt: key });
        assert.strictEqual(info.manifest.sha256, provider.get().sha256);
        const without = releaseScript.buildReleaseFiles({ publicDir: dir, ...FIXED });
        assert.ok(!('keys' in JSON.parse(without.releaseText)));
        assert.strictEqual(without.manifestText, manifestLib.buildManifestText(dir));
        assert.throws(() => releaseScript.buildReleaseFiles({ publicDir: dir, ...FIXED, ktKey: b64Hex(ONE) }), /ключ журнала/);
        assert.throws(() => manifestLib.createManifestProvider(dir, { ktKey: 'мусор' }), /ключ журнала/);
    });

    await test('сервер: ключ выводится из KT_SIGNING_KEY; без ключа или с испорченным ключом манифест без keys', () => {
        const key = newLogKey();
        assert.strictEqual(manifestRoute.ktPublicKeyFromEnv({ KT_SIGNING_KEY: key.pkcs8 }), key.pub);
        assert.strictEqual(manifestRoute.ktPublicKeyFromEnv({ KT_SIGNING_KEY: '  ' + key.pkcs8 + '\n' }), key.pub);
        assert.strictEqual(manifestRoute.ktPublicKeyFromEnv({}), null);
        assert.strictEqual(manifestRoute.ktPublicKeyFromEnv({ KT_SIGNING_KEY: '' }), null);
        assert.strictEqual(manifestRoute.ktPublicKeyFromEnv(undefined), null);
        const originalError = console.error;
        const logged = [];
        console.error = (...args) => logged.push(args.join(' '));
        try {
            assert.strictEqual(manifestRoute.ktPublicKeyFromEnv({ KT_SIGNING_KEY: 'не ключ' }), null);
        } finally {
            console.error = originalError;
        }
        assert.ok(logged.length > 0 && !logged.join('\n').includes('не ключ'), 'сбой записан в лог, значение ключа в лог не попадает');
    });

    await test('маршрут GET /client-manifest.json отдаёт манифест с ключом из KT_SIGNING_KEY и заголовком хэша', () => {
        const dir = syntheticPublic();
        const key = newLogKey();
        const handlers = {};
        manifestRoute.register({ get: (route, handler) => { handlers[route] = handler; } }, { publicDir: dir, env: { KT_SIGNING_KEY: key.pkcs8 } });
        const headers = {};
        let body = null;
        handlers[manifestRoute.MANIFEST_PATH]({}, { set: (name, value) => { headers[name] = value; }, send: (value) => { body = value; } });
        const expected = manifestLib.buildManifestText(dir, { ktKey: key.pub });
        assert.strictEqual(Buffer.from(body).toString('utf8'), expected);
        assert.strictEqual(headers['X-Client-Manifest-Sha256'], manifestLib.manifestSha256(expected));
        assert.strictEqual(verifyLib.ktKeyOf(JSON.parse(expected)), key.pub);

        const plainHandlers = {};
        manifestRoute.register({ get: (route, handler) => { plainHandlers[route] = handler; } }, { publicDir: dir, env: {} });
        let plainBody = null;
        plainHandlers[manifestRoute.MANIFEST_PATH]({}, { set() {}, send: (value) => { plainBody = value; } });
        assert.strictEqual(Buffer.from(plainBody).toString('utf8'), manifestLib.buildManifestText(dir), 'журнал выключен — манифест прежний');
    });

    await test('скрипт: --kt-key, KT_PUBLIC_KEY, приоритет параметра, --stdout и --manifest-only дают один манифест; плохой ключ — код 1', () => {
        const key = newLogKey().pub;
        const other = newLogKey().pub;
        const expected = manifestLib.buildManifestText(PUBLIC_DIR, { ktKey: key });

        const viaFlag = runScript(['--stdout', '--kt-key', key]);
        assert.strictEqual(viaFlag.status, 0, viaFlag.stderr);
        assert.strictEqual(viaFlag.stdout, expected);

        const viaEnv = runScript(['--stdout'], { KT_PUBLIC_KEY: key });
        assert.strictEqual(viaEnv.stdout, expected);

        const flagWins = runScript(['--stdout', '--kt-key', key], { KT_PUBLIC_KEY: other });
        assert.strictEqual(flagWins.stdout, expected, 'параметр важнее переменной');

        const empty = runScript(['--stdout'], { KT_PUBLIC_KEY: '' });
        assert.strictEqual(empty.stdout, manifestLib.buildManifestText(PUBLIC_DIR), 'пустая переменная репозитория (Actions) = ключа нет');

        const outDir = makeTmp();
        const only = runScript(['--manifest-only', '--out', outDir, '--kt-key', key]);
        assert.strictEqual(only.status, 0, only.stderr);
        assert.strictEqual(fs.readFileSync(path.join(outDir, 'client-manifest.json'), 'utf8'), expected);

        const full = runScript(['--out', outDir, '--allow-dirty', '--kt-key', key], { GITHUB_SHA: 'b'.repeat(40), SOURCE_DATE_EPOCH: '1800000000' });
        assert.strictEqual(full.status, 0, full.stderr);
        assert.strictEqual(fs.readFileSync(path.join(outDir, 'client-manifest.json'), 'utf8'), expected);
        const info = JSON.parse(fs.readFileSync(path.join(outDir, 'release.json'), 'utf8'));
        assert.deepStrictEqual(info.keys, { kt: key });
        assert.strictEqual(info.manifest.sha256, manifestLib.manifestSha256(expected));
        assert.ok(full.stdout.includes(key), 'ключ напечатан в итоге сборки');

        const noKey = runScript(['--out', outDir, '--allow-dirty'], { GITHUB_SHA: 'b'.repeat(40), SOURCE_DATE_EPOCH: '1800000000' });
        assert.strictEqual(noKey.status, 0, noKey.stderr);
        assert.ok(!('keys' in JSON.parse(fs.readFileSync(path.join(outDir, 'release.json'), 'utf8'))));
        assert.match(noKey.stdout, /Ключ журнала ключей не задан/);

        for (const [args, env, source] of [
            [['--stdout', '--kt-key', b64Hex(ONE)], {}, /--kt-key: ключ журнала/],
            [['--stdout', '--kt-key', b64Hex(ONE_SIGN)], {}, /--kt-key: ключ журнала/],
            [['--stdout', '--kt-key', 'мусор'], {}, /--kt-key: ключ журнала/],
            [['--stdout'], { KT_PUBLIC_KEY: crypto.randomBytes(31).toString('base64') }, /KT_PUBLIC_KEY: ключ журнала/],
            [['--stdout', '--kt-key'], {}, /--kt-key/],
            [['--stdout', '--kt-key', ''], {}, /--kt-key/],
        ]) {
            const bad = runScript(args, env);
            assert.strictEqual(bad.status, 1, args.join(' '));
            assert.match(bad.stderr, source, args.join(' '));
            assert.strictEqual(bad.stdout, '', 'при ошибке манифест не печатается');
        }
    });

    // ===================== Разбор и сравнение манифестов =====================

    await test('parseManifest: keys.kt необязателен; форма строгая (объект, каноническое base64 ровно 32 байт)', () => {
        const dir = syntheticPublic();
        const key = newLogKey().pub;
        const plain = manifestLib.buildManifestText(dir);
        assert.strictEqual(verifyLib.parseManifest(plain).keys, undefined);
        assert.strictEqual(verifyLib.ktKeyOf(verifyLib.parseManifest(plain)), null);
        const parsed = verifyLib.parseManifest(manifestLib.buildManifestText(dir, { ktKey: key }));
        assert.strictEqual(verifyLib.ktKeyOf(parsed), key);
        assert.strictEqual(manifestLib.parseManifest, verifyLib.parseManifest, 'один разбор для сервера, скрипта и страницы');
        const withKeys = (keys) => JSON.stringify({ ...JSON.parse(plain), keys });
        verifyLib.parseManifest(withKeys({}));
        for (const [what, keys] of Object.entries({
            'не объект': 'kt', 'массив': [], 'null': null,
            'kt числом': { kt: 5 }, 'kt пустой': { kt: '' }, 'kt короткий': { kt: key.slice(0, 40) },
            'kt длиннее': { kt: key + 'AAAA' }, 'kt в url-алфавите': { kt: key.replace(/\+/g, '-') + '!' },
            'kt неканонический': { kt: nonCanonical(key) },
        })) {
            assert.throws(() => verifyLib.parseManifest(withKeys(keys)), /keys/, what);
        }
    });

    await test('diffManifests: другой, лишний или пропавший ключ журнала — keyChanged, same = false; одинаковые ключи — same', () => {
        const dir = syntheticPublic();
        const a = newLogKey().pub;
        const b = newLogKey().pub;
        const parse = (key) => verifyLib.parseManifest(manifestLib.buildManifestText(dir, { ktKey: key }));
        assert.deepStrictEqual(verifyLib.diffManifests(parse(a), parse(a)), { onlyInReference: [], onlyInServed: [], changed: [], keyChanged: false, same: true });
        for (const [reference, served] of [[a, b], [a, null], [null, a]]) {
            const diff = verifyLib.diffManifests(parse(reference), parse(served));
            assert.strictEqual(diff.keyChanged, true);
            assert.strictEqual(diff.same, false);
            assert.deepStrictEqual([diff.onlyInReference, diff.onlyInServed, diff.changed], [[], [], []], 'файлы те же');
        }
        assert.strictEqual(verifyLib.diffManifests(parse(null), parse(null)).same, true);
    });

    await test('scripts/verify-deployment.js: манифест сайта с другим ключом журнала, чем в релизе, — расхождение с понятной причиной', async () => {
        const { spawn } = require('child_process');
        const http = require('http');
        const dir = syntheticPublic();
        const keyOfRelease = newLogKey().pub;
        const keyOfServer = newLogKey().pub;
        const served = manifestLib.createManifestProvider(dir, { ktKey: keyOfServer }).get();
        const server = http.createServer((req, res) => {
            if (req.url === '/client-manifest.json') { res.setHeader('Content-Type', 'application/json'); res.end(served.buffer); return; }
            const rel = req.url === '/' ? '/index.html' : req.url;
            const file = path.join(dir, ...rel.split('/').filter(Boolean));
            if (fs.existsSync(file)) { res.end(fs.readFileSync(file)); return; }
            res.statusCode = 404; res.end('нет');
        });
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        try {
            const referenceFile = path.join(makeTmp(), 'client-manifest.json');
            fs.writeFileSync(referenceFile, manifestLib.buildManifestText(dir, { ktKey: keyOfRelease }));
            const result = await new Promise((resolve) => {
                const child = spawn(process.execPath, [path.join(ROOT, 'scripts', 'verify-deployment.js'), 'http://127.0.0.1:' + server.address().port, '--manifest', referenceFile], { cwd: ROOT });
                let out = '';
                child.stdout.on('data', (d) => { out += d; });
                child.stderr.on('data', (d) => { out += d; });
                child.on('close', (code) => resolve({ code, out }));
            });
            assert.strictEqual(result.code, 1, result.out);
            assert.match(result.out, /другой ключ журнала ключей \(keys\.kt\)/);
        } finally {
            await new Promise((resolve) => server.close(resolve));
        }
    });

    // ===================== Клиент =====================

    const fakeFetch = (reply) => {
        const calls = [];
        const fn = async (url, init) => { calls.push({ url, init }); return typeof reply === 'function' ? reply(url, init) : reply; };
        fn.calls = calls;
        return fn;
    };
    const okResponse = (text) => ({ ok: true, status: 200, text: async () => text });

    await test('клиент: fetchManifestKey берёт keys.kt из /client-manifest.json без кук и кэша, любая неудача — null', async () => {
        const dir = syntheticPublic();
        const key = newLogKey().pub;
        const fetchOk = fakeFetch(okResponse(manifestLib.buildManifestText(dir, { ktKey: key })));
        assert.strictEqual(await KtClient.fetchManifestKey(fetchOk), key);
        assert.strictEqual(fetchOk.calls.length, 1);
        assert.strictEqual(fetchOk.calls[0].url, '/client-manifest.json');
        assert.strictEqual(fetchOk.calls[0].init.credentials, 'omit');
        assert.strictEqual(fetchOk.calls[0].init.cache, 'no-store');
        assert.strictEqual(fetchOk.calls[0].init.redirect, 'error');

        const nulls = {
            'в манифесте нет ключа': okResponse(manifestLib.buildManifestText(dir)),
            'не JSON': okResponse('<html>'),
            'пустой ответ': okResponse(''),
            'keys не объект': okResponse(JSON.stringify({ keys: 'x' })),
            'kt не строка': okResponse(JSON.stringify({ keys: { kt: 5 } })),
            'kt неверной длины': okResponse(JSON.stringify({ keys: { kt: crypto.randomBytes(31).toString('base64') } })),
            'kt неканонический': okResponse(JSON.stringify({ keys: { kt: nonCanonical(key) } })),
            'kt малого порядка (единичная точка)': okResponse(JSON.stringify({ keys: { kt: b64Hex(ONE) } })),
            'kt малого порядка (x = 0, бит знака 1)': okResponse(JSON.stringify({ keys: { kt: b64Hex(ONE_SIGN) } })),
            'ответ не 200': { ok: false, status: 503, text: async () => manifestLib.buildManifestText(dir, { ktKey: key }) },
            'слишком большой ответ': okResponse('x'.repeat(5 * 1024 * 1024)),
            'нет ответа': null,
        };
        for (const [what, response] of Object.entries(nulls)) {
            assert.strictEqual(await KtClient.fetchManifestKey(fakeFetch(response)), null, what);
        }
        assert.strictEqual(await KtClient.fetchManifestKey(async () => { throw new TypeError('network'); }), null, 'сеть упала');
        // Зависший запрос: AbortSignal.timeout прерывает его, клиент получает null и работает дальше (TOFU).
        const hanging = (url, init) => new Promise((resolve, reject) => {
            assert.ok(init.signal, 'у запроса есть сигнал отмены');
            init.signal.addEventListener('abort', () => reject(init.signal.reason));
        });
        // Таймер AbortSignal.timeout в Node не удерживает процесс, поэтому на время проверки держим свой.
        const keepAlive = setTimeout(() => {}, 5000);
        try {
            assert.strictEqual(await KtClient.fetchManifestKey(hanging, { timeoutMs: 20 }), null, 'ответ не пришёл за срок');
        } finally {
            clearTimeout(keepAlive);
        }
        assert.strictEqual(KtClient.manifestKeyFromText(JSON.stringify({ keys: { kt: key } })), key);
    });

    await test('клиент: ключ журнала при первом закреплении сверяется с манифестом, полученным через fetchManifestKey', async () => {
        const E2EE = require('../public/e2ee.js');
        require('./membership-harness').install(E2EE);
        const { makeWorld } = require('./kt-harness');
        const { newLogKey: newHarnessKey } = require('./fake-kt');
        const dir = syntheticPublic();
        const manifestWith = (pub) => fakeFetch(okResponse(manifestLib.buildManifestText(dir, { ktKey: Buffer.from(pub).toString('base64') })));

        // Манифест называет другой ключ: тревога key-changed (manifest), ключ не закреплён.
        const world = makeWorld();
        const wrong = manifestWith(newHarnessKey().pub);
        const alice = await world.addUser(1, { clientOptions: { ktManifestKey: () => KtClient.fetchManifestKey(wrong) } });
        await world.kt.closeEpoch();
        await alice.check();
        const alert = alice.alerts.find(a => a.kind === 'key-changed');
        assert.ok(alert, alice.alerts.map(a => a.kind).join());
        assert.strictEqual(alert.reason, 'manifest');
        assert.strictEqual(await alice.storage.get('kt:pub'), null);
        assert.strictEqual(wrong.calls.length >= 1, true, 'манифест запрошен');

        // Манифест называет ключ сервера: тревог нет, ключ закреплён.
        const honest = makeWorld();
        const right = manifestWith(honest.kt.key.pub);
        const bob = await honest.addUser(1, { clientOptions: { ktManifestKey: () => KtClient.fetchManifestKey(right) } });
        await honest.kt.closeEpoch();
        await bob.check();
        assert.deepStrictEqual(bob.alerts, []);
        assert.ok(await bob.storage.get('kt:pub'));

        // В манифесте ключа нет (журнал без релиза с ключом) или манифест недоступен: закрепление как раньше (TOFU), без тревог.
        for (const reply of [okResponse(manifestLib.buildManifestText(dir)), null, { ok: false, status: 500, text: async () => '' }]) {
            const world3 = makeWorld();
            const carol = await world3.addUser(1, { clientOptions: { ktManifestKey: () => KtClient.fetchManifestKey(fakeFetch(reply)) } });
            await world3.kt.closeEpoch();
            await carol.check();
            assert.deepStrictEqual(carol.alerts, [], JSON.stringify(reply && reply.status));
            assert.ok(await carol.storage.get('kt:pub'));
        }
    });

    await test('script.js подключает ktManifestKey к клиенту E2EE, а kt-client.js загружается до него', () => {
        const script = readClientScript();
        assert.match(script, /ktManifestKey: \(\) => \(typeof NyxoKtClient !== 'undefined' \? NyxoKtClient\.fetchManifestKey\(\) : null\)/);
        const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
        assert.ok(html.indexOf('lib/kt-client.js') > 0 && html.indexOf('lib/kt-client.js') < html.indexOf(`src="${clientScriptFiles()[0]}"`));
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
