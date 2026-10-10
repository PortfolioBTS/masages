'use strict';
// Сверка развёртывания (6.1/6.3, roadmap R10): общая логика public/lib/client-verify.js,
// консольный scripts/verify-deployment.js и статическая страница public/verify.html.
//
// Скрипт проверяется на настоящем HTTP-сервере из node:http, который отдаёт
// синтетический public/: честный сайт, подмену одного файла, 404, редирект,
// манифест с чужим составом. Страница — статическими проверками (инлайн-кода нет,
// идентификаторы из verify.js есть в разметке, честный текст на месте, ссылки живы).
// Запуск: node test/verify-deployment.test.js

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const clientVerify = require('../public/lib/client-verify');
const manifestLib = require('../lib/client-manifest');
const verifyScript = require('../scripts/verify-deployment');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const SCRIPT = path.join(ROOT, 'scripts', 'verify-deployment.js');

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
function makeSite(files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-verify-'));
    tmpDirs.push(dir);
    for (const [rel, content] of Object.entries(files)) {
        const target = path.join(dir, ...rel.split('/'));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, content);
    }
    return dir;
}
process.on('exit', () => {
    for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

const SITE_FILES = { 'index.html': '<!doctype html><title>x</title>', 'e2ee.js': 'console.log("e2ee")', 'lib/a.js': 'a()', 'style.css': 'body{}' };

// Сайт в памяти: путь -> { status, body, headers }. Тесты меняют записи, чтобы изобразить подмену.
async function startSite(publicDir) {
    const manifestText = manifestLib.buildManifestText(publicDir);
    const routes = new Map();
    for (const urlPath of manifestLib.listClientFiles(publicDir)) {
        routes.set(urlPath, { status: 200, body: fs.readFileSync(path.join(publicDir, ...urlPath.split('/').filter(Boolean))) });
    }
    routes.set('/', { ...routes.get('/index.html') });
    routes.set('/client-manifest.json', { status: 200, body: Buffer.from(manifestText, 'utf8') });
    const server = http.createServer((req, res) => {
        const route = routes.get(req.url.split('?')[0]) || { status: 404, body: Buffer.from('нет') };
        res.writeHead(route.status, route.headers || {});
        res.end(route.body);
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return {
        url: `http://127.0.0.1:${server.address().port}`,
        routes,
        manifestText,
        close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }),
    };
}

// Асинхронно: сайт для проверки живёт в этом же процессе, и синхронный spawnSync остановил бы его ответы.
function runCli(args) {
    return new Promise((resolve) => {
        execFile(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: 'utf8' }, (error, stdout, stderr) => {
            resolve({ status: error ? error.code : 0, stdout, stderr });
        });
    });
}

(async () => {
    console.log('Deployment verification tests\n');

    // ---------- Общая логика ----------

    const publicDir = makeSite(SITE_FILES);
    const goodText = manifestLib.buildManifestText(publicDir);
    const good = clientVerify.parseManifest(goodText);
    const observedGood = () => {
        const seen = {};
        for (const file of good.files) seen[file.path] = { sha256: file.sha256, bytes: file.bytes };
        seen['/'] = { sha256: good.files.find((f) => f.path === '/index.html').sha256, bytes: good.files.find((f) => f.path === '/index.html').bytes };
        return seen;
    };

    await test('toHex и pathsToFetch: файлы манифеста и «/»', () => {
        assert.strictEqual(clientVerify.toHex(new Uint8Array([0, 15, 255])), '000fff');
        assert.strictEqual(clientVerify.toHex(new Uint8Array([1, 2]).buffer), '0102');
        assert.deepStrictEqual(clientVerify.pathsToFetch(good), [...good.files.map((f) => f.path), '/']);
    });

    await test('compareObserved: всё совпало — ok, записи на файлы и «/»', () => {
        const result = clientVerify.compareObserved(good, observedGood());
        assert.strictEqual(result.ok, true);
        assert.deepStrictEqual(result.problems, []);
        assert.strictEqual(result.entries.length, good.files.length + 1);
        assert.ok(result.entries.every((e) => e.state === 'match'));
    });

    await test('compareObserved: другой хэш, другой размер, ошибка, нет ответа — по отдельности и с понятным текстом', () => {
        const seen = observedGood();
        seen['/e2ee.js'] = { sha256: 'f'.repeat(64), bytes: seen['/e2ee.js'].bytes };
        seen['/style.css'] = { sha256: good.files.find((f) => f.path === '/style.css').sha256, bytes: 999 };
        seen['/lib/a.js'] = { error: 'HTTP 404' };
        delete seen['/index.html'];
        const result = clientVerify.compareObserved(good, seen);
        assert.strictEqual(result.ok, false);
        const states = Object.fromEntries(result.entries.map((e) => [e.path, e.state]));
        assert.strictEqual(states['/e2ee.js'], 'mismatch');
        assert.strictEqual(states['/style.css'], 'mismatch');
        assert.strictEqual(states['/lib/a.js'], 'error');
        assert.strictEqual(states['/index.html'], 'not-checked');
        assert.match(result.problems.join('\n'), /\/style\.css: размер 999 вместо/);
        assert.match(result.problems.join('\n'), /\/lib\/a\.js: HTTP 404/);
    });

    await test('diffManifests: изменён, лишний, пропавший', () => {
        const other = JSON.parse(goodText);
        other.files[0].sha256 = 'e'.repeat(64);
        const removed = other.files.pop();
        other.files.push({ ...removed, path: '/extra.js' });
        const diff = clientVerify.diffManifests(good, other);
        assert.deepStrictEqual(diff.changed, [good.files[0].path]);
        assert.deepStrictEqual(diff.onlyInServed, ['/extra.js']);
        assert.deepStrictEqual(diff.onlyInReference, [removed.path]);
        assert.strictEqual(diff.same, false);
        assert.strictEqual(clientVerify.diffManifests(good, good).same, true);
    });

    await test('formatSums — формат sha256sum без «/»; describeOutcome честно говорит про свой сервер', () => {
        const result = clientVerify.compareObserved(good, observedGood());
        const sums = clientVerify.formatSums(result.entries);
        const lines = sums.trimEnd().split('\n');
        assert.strictEqual(lines.length, good.files.length);
        for (const line of lines) assert.match(line, /^[0-9a-f]{64} {2}\S+$/);
        assert.ok(!sums.includes('  \n') && !/ {2}$/m.test(sums));
        assert.match(clientVerify.describeOutcome({ ok: true, total: 5, mode: 'self', problems: [] }), /не доказательство/);
        assert.match(clientVerify.describeOutcome({ ok: true, total: 5, mode: 'reference', problems: [] }), /эталонным манифестом/);
        assert.match(clientVerify.describeOutcome({ ok: false, total: 5, mode: 'reference', problems: ['a', 'b'] }), /расхождения \(2\)/);
    });

    // ---------- Адрес сайта ----------

    await test('normalizeBaseUrl: origin без пути; http только для localhost и .onion; логин в адресе — отказ', () => {
        const n = verifyScript.normalizeBaseUrl;
        assert.strictEqual(n('https://chat.example.com/some/path?x=1'), 'https://chat.example.com');
        assert.strictEqual(n('http://localhost:3133/'), 'http://localhost:3133');
        assert.strictEqual(n('http://t33.localhost:3133'), 'http://t33.localhost:3133');
        assert.strictEqual(n('http://127.0.0.1:8080'), 'http://127.0.0.1:8080');
        assert.strictEqual(n('http://abcdefghijklmnop.onion'), 'http://abcdefghijklmnop.onion');
        assert.throws(() => n('http://chat.example.com'), /http:\/\//);
        assert.strictEqual(n('http://chat.example.com', { allowHttp: true }), 'http://chat.example.com');
        assert.throws(() => n('https://user:pw@chat.example.com'), /логина/);
        assert.throws(() => n('ftp://x'), /http/);
        assert.throws(() => n('не адрес'), /не адрес сайта/);
    });

    await test('parseArgs: адрес обязателен, неизвестные параметры и дубли — ошибка', () => {
        const p = verifyScript.parseArgs;
        assert.deepStrictEqual(p(['https://x.example', '--manifest', 'm.json', '--timeout', '500']),
            { url: 'https://x.example', manifest: 'm.json', allowHttp: false, timeoutMs: 500 });
        assert.throws(() => p([]), /укажите адрес/);
        assert.throws(() => p(['https://a', 'https://b']), /дважды/);
        assert.throws(() => p(['https://a', '--nope']), /неизвестный параметр/);
        assert.throws(() => p(['https://a', '--manifest']), /--manifest/);
        assert.throws(() => p(['https://a', '--timeout', 'abc']), /--timeout/);
    });

    // ---------- Скрипт на живом HTTP-сервере ----------

    await test('честный сайт: с эталоном и без — ОК, манифест сайта совпал с эталоном', async () => {
        const site = await startSite(publicDir);
        try {
            const self = await verifyScript.verifyDeployment({ baseUrl: site.url });
            assert.strictEqual(self.ok, true, self.problems.join('; '));
            assert.strictEqual(self.mode, 'self');
            assert.match(verifyScript.formatReport(self), /НЕ независимый/);

            const reference = await verifyScript.verifyDeployment({ baseUrl: site.url, referenceText: site.manifestText });
            assert.strictEqual(reference.ok, true, reference.problems.join('; '));
            assert.strictEqual(reference.mode, 'reference');
            assert.strictEqual(reference.entries.length, good.files.length + 1);
            assert.strictEqual(reference.referenceSha256, reference.servedManifestSha256);
            assert.match(verifyScript.formatReport(reference), /Результат: ОК/);
        } finally {
            await site.close();
        }
    });

    await test('подмена одного файла при честном манифесте сайта: эталон ловит, самопроверка по манифесту сайта — тоже (файл ≠ манифест)', async () => {
        const site = await startSite(publicDir);
        try {
            site.routes.set('/e2ee.js', { status: 200, body: Buffer.from('console.log("EVIL")') });
            const report = await verifyScript.verifyDeployment({ baseUrl: site.url, referenceText: site.manifestText });
            assert.strictEqual(report.ok, false);
            assert.ok(report.problems.some((p) => p.startsWith('/e2ee.js')), report.problems.join('; '));
            const text = verifyScript.formatReport(report);
            assert.match(text, /РАСХОЖДЕНИЕ \/e2ee\.js/);
            assert.match(text, /ожидался [0-9a-f]{64}, получен [0-9a-f]{64}/);
            assert.match(text, /ЕСТЬ РАСХОЖДЕНИЯ/);
        } finally {
            await site.close();
        }
    });

    await test('злонамеренный сервер: подменил файл И манифест — самопроверка этого не видит, эталон из релиза видит', async () => {
        const site = await startSite(publicDir);
        try {
            const evil = Buffer.from('console.log("EVIL")');
            const evilDir = makeSite({ ...SITE_FILES, 'e2ee.js': evil });
            const evilManifest = manifestLib.buildManifestText(evilDir);
            site.routes.set('/e2ee.js', { status: 200, body: evil });
            site.routes.set('/client-manifest.json', { status: 200, body: Buffer.from(evilManifest, 'utf8') });

            const self = await verifyScript.verifyDeployment({ baseUrl: site.url });
            assert.strictEqual(self.ok, true, 'самопроверка не может отличить подмену — это и есть оговорка в документации');

            const reference = await verifyScript.verifyDeployment({ baseUrl: site.url, referenceText: site.manifestText });
            assert.strictEqual(reference.ok, false);
            assert.match(reference.problems.join('\n'), /манифест сайта отличается от эталона \(другие хэши: \/e2ee\.js\)/);
            assert.match(reference.problems.join('\n'), /^\/e2ee\.js: хэш не совпал/m);
        } finally {
            await site.close();
        }
    });

    await test('404, редирект и лишний файл в манифесте сайта — расхождения', async () => {
        const site = await startSite(publicDir);
        try {
            site.routes.set('/lib/a.js', { status: 404, body: Buffer.from('нет') });
            site.routes.set('/style.css', { status: 301, headers: { Location: '/elsewhere.css' }, body: Buffer.alloc(0) });
            const extraDir = makeSite({ ...SITE_FILES, 'extra.js': 'x' });
            site.routes.set('/client-manifest.json', { status: 200, body: Buffer.from(manifestLib.buildManifestText(extraDir), 'utf8') });
            const report = await verifyScript.verifyDeployment({ baseUrl: site.url, referenceText: site.manifestText });
            assert.strictEqual(report.ok, false);
            const problems = report.problems.join('\n');
            assert.match(problems, /\/lib\/a\.js: HTTP 404/);
            assert.match(problems, /\/style\.css: HTTP 301/);
            assert.match(problems, /лишние файлы: \/extra\.js/);
        } finally {
            await site.close();
        }
    });

    await test('манифеста нет и эталона нет — «проверить не удалось»; сайт недоступен — тоже без исключения', async () => {
        const site = await startSite(publicDir);
        try {
            site.routes.set('/client-manifest.json', { status: 404, body: Buffer.from('нет') });
            const report = await verifyScript.verifyDeployment({ baseUrl: site.url });
            assert.strictEqual(report.unverifiable, true);
            assert.strictEqual(report.ok, false);
            assert.match(verifyScript.formatReport(report), /ПРОВЕРИТЬ НЕ УДАЛОСЬ/);
        } finally {
            await site.close();
        }
        const dead = await verifyScript.verifyDeployment({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 1500 });
        assert.strictEqual(dead.ok, false);
        assert.strictEqual(dead.unverifiable, true);
    });

    await test('битый эталонный манифест — ошибка, а не молчаливое «всё хорошо»', async () => {
        const site = await startSite(publicDir);
        try {
            await assert.rejects(verifyScript.verifyDeployment({ baseUrl: site.url, referenceText: '{"format":"чужой"}' }), /формат/);
        } finally {
            await site.close();
        }
    });

    await test('CLI: код 0 при совпадении, 1 при подмене, 2 без аргументов и при недоступном эталоне', async () => {
        const site = await startSite(publicDir);
        try {
            const reference = path.join(makeSite({}), 'client-manifest.json');
            fs.writeFileSync(reference, site.manifestText);
            const ok = await runCli([site.url, '--manifest', reference]);
            assert.strictEqual(ok.status, 0, ok.stdout + ok.stderr);
            assert.match(ok.stdout, /Результат: ОК/);

            site.routes.set('/lib/a.js', { status: 200, body: Buffer.from('EVIL') });
            const bad = await runCli([site.url, '--manifest', reference]);
            assert.strictEqual(bad.status, 1, bad.stdout + bad.stderr);
            assert.match(bad.stdout, /РАСХОЖДЕНИЕ \/lib\/a\.js/);

            assert.strictEqual((await runCli([])).status, 2);
            const missing = await runCli([site.url, '--manifest', path.join(os.tmpdir(), 'nyxo-нет-такого-файла.json')]);
            assert.strictEqual(missing.status, 2);
            assert.match(missing.stderr, /не читается/);
            assert.strictEqual((await runCli(['http://example.com'])).status, 2);
        } finally {
            await site.close();
        }
    });

    await test('настоящий public/ в синтетическом сайте: сверка проходит (манифест репозитория согласован с файлами)', async () => {
        const site = await startSite(PUBLIC_DIR);
        try {
            const report = await verifyScript.verifyDeployment({ baseUrl: site.url, referenceText: manifestLib.buildManifestText(PUBLIC_DIR) });
            assert.strictEqual(report.ok, true, report.problems.join('; '));
            assert.ok(report.entries.length > 20);
        } finally {
            await site.close();
        }
    });

    // ---------- Страница /verify.html ----------

    const html = fs.readFileSync(path.join(PUBLIC_DIR, 'verify.html'), 'utf8');
    const pageJs = fs.readFileSync(path.join(PUBLIC_DIR, 'verify.js'), 'utf8');

    await test('verify.html: без инлайн-скриптов, стилей и обработчиков on*= (CSP их не пропустит)', () => {
        assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), 'есть <script> без src');
        assert.ok(!/<style\b/i.test(html), 'есть <style>');
        assert.ok(!/\sstyle\s*=/i.test(html), 'есть атрибут style=');
        assert.ok(!/\son[a-z]+\s*=/i.test(html), 'есть обработчик on*=');
        assert.ok(!/\sintegrity\s*=/i.test(html), 'SRI пока не включён');
    });

    await test('verify.html: каждый подключённый файл существует, общая логика грузится раньше страницы', () => {
        const refs = [...html.matchAll(/(?:src|href)="([^"#]+)"/g)].map((m) => m[1]).filter((u) => !/^(?:https?:)?\/\//.test(u) && u !== '/');
        assert.ok(refs.includes('lib/client-verify.js') && refs.includes('verify.js') && refs.includes('verify.css'));
        for (const ref of refs) assert.ok(fs.existsSync(path.join(PUBLIC_DIR, ref)), `нет файла ${ref}`);
        assert.ok(html.indexOf('lib/client-verify.js') < html.indexOf('src="verify.js"'));
    });

    await test('verify.js: каждый id, который он ищет, есть в verify.html, и id не повторяются', () => {
        const wanted = new Set([...pageJs.matchAll(/\$\('([\w-]+)'\)/g)].map((m) => m[1]));
        assert.ok(wanted.size >= 10);
        const ids = [...html.matchAll(/\sid="([\w-]+)"/g)].map((m) => m[1]);
        assert.strictEqual(new Set(ids).size, ids.length, 'повторяющиеся id');
        for (const id of wanted) assert.ok(ids.includes(id), `в verify.html нет id="${id}"`);
        assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(pageJs), 'вывод только через textContent');
    });

    await test('verify.html: честная оговорка и ссылка на ручную проверку на месте', () => {
        const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
        assert.match(text, /Что эта страница НЕ доказывает/);
        assert.match(text, /с одного и того же сервера/);
        assert.match(text, /ничего не доказывает против злонамеренного сервера/);
        assert.match(text, /sha256sum/);
        assert.match(text, /Get-FileHash/);
        const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
        const repo = pkg.repository.url.replace(/\.git$/, '');
        assert.ok(html.includes(`${repo}/blob/main/docs/VERIFY.md`), 'ссылка на docs/VERIFY.md должна вести в репозиторий из package.json');
        assert.ok(fs.existsSync(path.join(ROOT, 'docs', 'VERIFY.md')), 'ссылка ведёт на несуществующий документ');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})();
