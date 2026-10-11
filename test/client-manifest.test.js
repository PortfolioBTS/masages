'use strict';
// Манифест клиента (6.1/6.3, roadmap R10): lib/client-manifest.js,
// GET /client-manifest.json (lib/routes/client-manifest.js) и
// scripts/release-manifest.js.
//
// Главное, что охраняется: манифест ДЕТЕРМИНИРОВАН (два прогона — одни байты,
// порядок не зависит от ОС и локали, только LF), в нём ВСЕ файлы статики и
// клиент socket.io из vendor, ничего лишнего (commit, время, версии), а то, что
// отдаёт сервер, и то, что кладёт в релиз скрипт, — один и тот же файл.
// Сквозная проверка «сервер отдаёт те же байты» — test/e2e/client-integrity.
// Запуск: node test/client-manifest.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const manifestLib = require('../lib/client-manifest');
const clientManifestRoute = require('../lib/routes/client-manifest');
const releaseScript = require('../scripts/release-manifest');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const SCRIPT = path.join(ROOT, 'scripts', 'release-manifest.js');

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

const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');
const tmpDirs = [];
function makeTmp(label) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `nyxo-${label}-`));
    tmpDirs.push(dir);
    return dir;
}
function writeTree(root, files) {
    for (const [rel, content] of Object.entries(files)) {
        const target = path.join(root, ...rel.split('/'));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, content);
    }
}
process.on('exit', () => {
    for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

// Скрипт релиза в отдельном процессе; окружение — только то, что передано (без git-зависимостей).
function runScript(args, env = {}) {
    const clean = { ...process.env };
    delete clean.GITHUB_SHA;
    delete clean.SOURCE_DATE_EPOCH;
    return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, env: { ...clean, ...env }, encoding: 'buffer' });
}

console.log('Client manifest tests\n');

const FIXED_COMMIT = 'a'.repeat(40);

// ---------- Манифест по настоящему public/ ----------

test('два построения подряд дают одни и те же байты', () => {
    assert.strictEqual(manifestLib.buildManifestText(PUBLIC_DIR), manifestLib.buildManifestText(PUBLIC_DIR));
});

test('в манифесте все файлы статики (кроме точечных, uploads и sw.js) и клиент socket.io из vendor', () => {
    const onDisk = fs.readdirSync(PUBLIC_DIR, { recursive: true, withFileTypes: true })
        .filter((entry) => entry.isFile())
        .map((entry) => '/' + path.relative(PUBLIC_DIR, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'))
        .filter((url) => !url.split('/').some((part) => part.startsWith('.')) && !url.startsWith('/uploads/') && url !== '/sw.js');
    const inManifest = manifestLib.buildManifest(PUBLIC_DIR).files.map((file) => file.path);
    assert.deepStrictEqual([...inManifest].sort(), [...onDisk].sort());
    for (const required of ['/index.html', '/vendor/socket.io.min.js', '/e2ee.js', '/script.js', '/pow-worker.js', '/style.css', '/vendor/qrcode.js']) {
        assert.ok(inManifest.includes(required), `в манифесте нет ${required}`);
    }
});

test('записи верны: sha256, sri (sha384 base64) и bytes пересчитываются независимо', () => {
    for (const entry of manifestLib.buildManifest(PUBLIC_DIR).files) {
        const bytes = fs.readFileSync(path.join(PUBLIC_DIR, ...entry.path.split('/').filter(Boolean)));
        assert.strictEqual(entry.sha256, sha256(bytes), entry.path);
        assert.strictEqual(entry.sri, 'sha384-' + crypto.createHash('sha384').update(bytes).digest('base64'), entry.path);
        assert.strictEqual(entry.bytes, bytes.length, entry.path);
    }
});

test('формат: только format/aliases/files, записи path/sha256/sri/bytes; без commit, времени, версий', () => {
    const manifest = JSON.parse(manifestLib.buildManifestText(PUBLIC_DIR));
    assert.deepStrictEqual(Object.keys(manifest), ['format', 'aliases', 'files']);
    assert.strictEqual(manifest.format, 'nyxo-client-manifest/1');
    assert.deepStrictEqual(manifest.aliases, { '/': '/index.html' });
    for (const entry of manifest.files) assert.deepStrictEqual(Object.keys(entry), ['path', 'sha256', 'sri', 'bytes']);
    const text = manifestLib.buildManifestText(PUBLIC_DIR);
    assert.doesNotMatch(text, /commit|created|"node"|"version"|SOURCE_DATE/i, 'в манифест попало то, что должно быть в release.json');
    assert.doesNotMatch(text, /\b[0-9a-f]{40}\b/, 'в манифесте не должно быть sha коммита');
});

test('пути отсортированы по кодовым единицам, без повторов', () => {
    const paths = manifestLib.buildManifest(PUBLIC_DIR).files.map((file) => file.path);
    assert.deepStrictEqual(paths, [...paths].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
    assert.strictEqual(new Set(paths).size, paths.length);
});

test('только LF: ни одного CR, один перевод строки в конце, отступ в 2 пробела, повторная сериализация даёт тот же текст', () => {
    const text = manifestLib.buildManifestText(PUBLIC_DIR);
    assert.ok(!text.includes('\r'));
    assert.ok(text.endsWith('}\n') && !text.endsWith('\n\n'));
    assert.match(text, /^\{\n {2}"format"/);
    assert.strictEqual(manifestLib.serializeManifest(JSON.parse(text)), text);
});

test('текстовые файлы public/ без CR: хэши одинаковы на Windows и Linux (.gitattributes: eol=lf)', () => {
    const textExt = new Set(['.js', '.html', '.css', '.svg', '.webmanifest', '.json', '.txt', '.map']);
    const withCr = manifestLib.listClientFiles(PUBLIC_DIR).filter((url) => {
        if (!textExt.has(path.extname(url))) return false;
        return fs.readFileSync(path.join(PUBLIC_DIR, ...url.split('/').filter(Boolean))).includes(0x0d);
    });
    assert.deepStrictEqual(withCr, [], 'файлы с CR: ' + withCr.join(', '));
    assert.match(fs.readFileSync(path.join(ROOT, '.gitattributes'), 'utf8'), /^\* text=auto eol=lf$/m);
});

test('manifestSha256 — sha256 байтов текста; parseManifest принимает свой манифест', () => {
    const text = manifestLib.buildManifestText(PUBLIC_DIR);
    assert.strictEqual(manifestLib.manifestSha256(text), sha256(Buffer.from(text, 'utf8')));
    assert.strictEqual(manifestLib.parseManifest(text).files.length, manifestLib.listClientFiles(PUBLIC_DIR).length);
});

// ---------- На синтетическом public/ ----------

test('порядок записей не зависит от порядка создания файлов и от локали (заглавные раньше строчных)', () => {
    const a = makeTmp('order-a');
    const b = makeTmp('order-b');
    writeTree(a, { 'index.html': 'x', 'a.js': '1', 'B.js': '2', 'lib/z.js': '3', 'lib/A.js': '4' });
    writeTree(b, { 'lib/A.js': '4', 'lib/z.js': '3', 'B.js': '2', 'a.js': '1', 'index.html': 'x' });
    assert.strictEqual(manifestLib.buildManifestText(a), manifestLib.buildManifestText(b));
    assert.deepStrictEqual(manifestLib.listClientFiles(a), ['/B.js', '/a.js', '/index.html', '/lib/A.js', '/lib/z.js']);
});

test('точечные файлы и каталоги, uploads и sw.js в манифест не входят; пустой файл входит', () => {
    const dir = makeTmp('skip');
    writeTree(dir, {
        'index.html': 'x', '.hidden': 'h', '.well-known/x.txt': 'w', 'uploads/user-file.bin': 'u',
        'sw.js': 'sw', 'lib/.secret.js': 's', 'empty.js': '', 'uploads.js': 'ok',
    });
    assert.deepStrictEqual(manifestLib.listClientFiles(dir), ['/empty.js', '/index.html', '/uploads.js']);
    const empty = manifestLib.buildManifest(dir).files.find((file) => file.path === '/empty.js');
    assert.strictEqual(empty.bytes, 0);
    assert.strictEqual(empty.sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('без index.html манифеста нет; символическая ссылка в public/ — ошибка, а не молчаливый пропуск', () => {
    const empty = makeTmp('noindex');
    writeTree(empty, { 'a.js': '1' });
    assert.throws(() => manifestLib.buildManifest(empty), /нет \/index\.html/);

    const linked = makeTmp('symlink');
    writeTree(linked, { 'index.html': 'x', 'real.js': 'r' });
    try {
        fs.symlinkSync(path.join(linked, 'real.js'), path.join(linked, 'link.js'));
    } catch (err) {
        console.log('       (симлинки недоступны на этой машине — часть проверки пропущена: ' + err.code + ')');
        return;
    }
    assert.throws(() => manifestLib.buildManifest(linked), /обычные файлы/);
});

test('parseManifest отвергает чужой формат, битые записи, повторы и алиас на неизвестный файл', () => {
    const good = JSON.parse(manifestLib.buildManifestText(PUBLIC_DIR));
    const clone = () => JSON.parse(JSON.stringify(good));
    const reject = (mutate, pattern) => {
        const data = clone();
        mutate(data);
        assert.throws(() => manifestLib.parseManifest(JSON.stringify(data)), pattern);
    };
    assert.throws(() => manifestLib.parseManifest('не json'), /JSON/);
    reject((d) => { d.format = 'другой/1'; }, /формат/);
    reject((d) => { d.files = []; }, /files/);
    reject((d) => { d.files[0].sha256 = 'abc'; }, /некорректная запись/);
    reject((d) => { d.files[0].sri = 'sha256-xxx'; }, /некорректная запись/);
    reject((d) => { d.files[0].path = '/../etc/passwd'; }, /некорректная запись/);
    reject((d) => { d.files[0].bytes = -1; }, /некорректная запись/);
    reject((d) => { d.files.push({ ...d.files[0] }); }, /повторяется/);
    reject((d) => { d.aliases['/'] = '/нет-такого.js'; }, /алиас/);
});

test('createManifestProvider: кэширует, пока файлы не менялись, и пересчитывает после правки', () => {
    const dir = makeTmp('provider');
    writeTree(dir, { 'index.html': 'one', 'a.js': 'a' });
    const provider = manifestLib.createManifestProvider(dir);
    const first = provider.get();
    assert.strictEqual(provider.get(), first, 'без изменений ответ берётся из кэша');
    assert.strictEqual(first.text, manifestLib.buildManifestText(dir));
    assert.strictEqual(first.sha256, manifestLib.manifestSha256(first.text));
    assert.ok(Buffer.isBuffer(first.buffer) && first.buffer.toString('utf8') === first.text);

    fs.writeFileSync(path.join(dir, 'a.js'), 'changed!');
    const second = provider.get();
    assert.notStrictEqual(second.sha256, first.sha256);
    assert.strictEqual(second.text, manifestLib.buildManifestText(dir));
    fs.writeFileSync(path.join(dir, 'b.js'), 'new file');
    assert.ok(provider.get().text.includes('"/b.js"'), 'новый файл попадает в манифест');
    fs.rmSync(path.join(dir, 'b.js'));
    assert.ok(!provider.get().text.includes('"/b.js"'), 'удалённый файл уходит из манифеста');

    assert.throws(() => manifestLib.createManifestProvider(path.join(dir, 'нет-такого-каталога')), /ENOENT/);
});

// ---------- Маршрут ----------

test('маршрут GET /client-manifest.json: адрес, тип, отпечаток в заголовке, тело — байты манифеста', () => {
    const routes = new Map();
    clientManifestRoute.register({ get: (url, handler) => routes.set(url, handler) }, {});
    assert.deepStrictEqual([...routes.keys()], ['/client-manifest.json']);
    const headers = {};
    let body;
    routes.get('/client-manifest.json')({}, { set: (name, value) => { headers[name.toLowerCase()] = value; }, send: (data) => { body = data; } });
    assert.strictEqual(headers['content-type'], 'application/json; charset=utf-8');
    assert.ok(Buffer.isBuffer(body));
    assert.strictEqual(body.toString('utf8'), manifestLib.buildManifestText(PUBLIC_DIR));
    assert.strictEqual(headers['x-client-manifest-sha256'], sha256(body));
});

test('маршрут зарегистрирован среди маршрутов до сессии', () => {
    const routesIndex = fs.readFileSync(path.join(ROOT, 'lib', 'routes', 'index.js'), 'utf8');
    assert.match(routesIndex, /PRE_SESSION_ROUTES = \[[^\]]*require\('\.\/client-manifest'\)/s);
});

// ---------- Скрипт релиза ----------

test('buildReleaseFiles: манифест тот же, release.json с commit и временем коммита, SHA256SUMS в формате sha256sum', () => {
    const epoch = 1760000000;
    const files = releaseScript.buildReleaseFiles({ version: '2.1.0', commit: FIXED_COMMIT, epoch, nodeVersion: 'v24.0.0' });
    assert.strictEqual(files.manifestText, manifestLib.buildManifestText(PUBLIC_DIR));
    const release = JSON.parse(files.releaseText);
    assert.deepStrictEqual(Object.keys(release), ['format', 'version', 'commit', 'created', 'node', 'manifest', 'serviceWorker']);
    const swBytes = fs.readFileSync(path.join(PUBLIC_DIR, 'sw.js'));
    assert.deepStrictEqual(release.serviceWorker, { file: 'sw.js', sha256: sha256(swBytes), bytes: swBytes.length }, 'хэш sw.js публикуется отдельно: в манифесте его нет');
    assert.strictEqual(release.format, 'nyxo-release/1');
    assert.strictEqual(release.version, '2.1.0');
    assert.strictEqual(release.commit, FIXED_COMMIT);
    assert.strictEqual(release.created, new Date(epoch * 1000).toISOString());
    assert.strictEqual(release.node, 'v24.0.0');
    assert.strictEqual(release.manifest.sha256, manifestLib.manifestSha256(files.manifestText));
    assert.strictEqual(release.manifest.bytes, Buffer.byteLength(files.manifestText));
    assert.ok(files.releaseText.endsWith('}\n') && !files.releaseText.includes('\r'));

    const lines = files.sumsText.split('\n');
    assert.strictEqual(lines.pop(), '', 'файл кончается переводом строки');
    assert.strictEqual(lines.length, release.manifest.files);
    for (const line of lines) {
        const match = /^([0-9a-f]{64}) {2}(\S.*)$/.exec(line);
        assert.ok(match, 'формат sha256sum: ' + line);
        assert.strictEqual(match[1], sha256(fs.readFileSync(path.join(PUBLIC_DIR, ...match[2].split('/')))), match[2]);
    }
});

test('скрипт: --manifest-only, --stdout и полный запуск дают один и тот же client-manifest.json; два запуска — одни байты', () => {
    const expected = Buffer.from(manifestLib.buildManifestText(PUBLIC_DIR), 'utf8');
    const outA = makeTmp('rel-a');
    const outB = makeTmp('rel-b');
    const env = { GITHUB_SHA: FIXED_COMMIT, SOURCE_DATE_EPOCH: '1760000000' };

    const onlyManifest = runScript(['--manifest-only', '--out', outA]);
    assert.strictEqual(onlyManifest.status, 0, onlyManifest.stderr.toString());
    assert.ok(fs.readFileSync(path.join(outA, 'client-manifest.json')).equals(expected));
    assert.deepStrictEqual(fs.readdirSync(outA), ['client-manifest.json'], '--manifest-only не пишет остального');

    const stdout = runScript(['--stdout']);
    assert.strictEqual(stdout.status, 0, stdout.stderr.toString());
    assert.ok(stdout.stdout.equals(expected), 'stdout ≠ манифест (на Windows это ловит перевод строк)');

    const run1 = runScript(['--out', outA], env);
    const run2 = runScript(['--out', outB], env);
    assert.strictEqual(run1.status, 0, run1.stderr.toString());
    assert.strictEqual(run2.status, 0, run2.stderr.toString());
    for (const name of ['client-manifest.json', 'release.json', 'SHA256SUMS']) {
        const first = fs.readFileSync(path.join(outA, name));
        assert.ok(first.equals(fs.readFileSync(path.join(outB, name))), `${name}: два запуска дали разные байты`);
        assert.ok(!first.includes(0x0d), `${name}: есть CR`);
    }
    assert.ok(fs.readFileSync(path.join(outA, 'client-manifest.json')).equals(expected));
    const release = JSON.parse(fs.readFileSync(path.join(outA, 'release.json'), 'utf8'));
    assert.strictEqual(release.commit, FIXED_COMMIT);
    assert.strictEqual(release.created, '2025-10-09T08:53:20.000Z');
    assert.strictEqual(release.version, JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version);
    assert.strictEqual(release.manifest.sha256, sha256(expected));
});

test('скрипт: некорректные GITHUB_SHA и SOURCE_DATE_EPOCH и неизвестный параметр — код 1 с понятным текстом', () => {
    const out = makeTmp('rel-bad');
    const badSha = runScript(['--out', out], { GITHUB_SHA: 'main', SOURCE_DATE_EPOCH: '1' });
    assert.strictEqual(badSha.status, 1);
    assert.match(badSha.stderr.toString(), /GITHUB_SHA/);
    const badEpoch = runScript(['--out', out], { GITHUB_SHA: FIXED_COMMIT, SOURCE_DATE_EPOCH: 'вчера' });
    assert.strictEqual(badEpoch.status, 1);
    assert.match(badEpoch.stderr.toString(), /SOURCE_DATE_EPOCH/);
    const unknown = runScript(['--nope']);
    assert.strictEqual(unknown.status, 1);
    assert.match(unknown.stderr.toString(), /неизвестный параметр/);
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
