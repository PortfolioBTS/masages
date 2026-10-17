'use strict';
// SRI для index.html (lib/client-sri.js, scripts/update-sri.js), 6.1 / roadmap R10.
//
// Инструмент готов, а атрибуты integrity в index.html ПОКА НЕ ВКЛЮЧЕНЫ: их
// включат после разбиения файлов клиента (волна 6). Поэтому тест «SRI актуален»
// работает по переключателю SRI_ENABLED:
//   false (сейчас) — в index.html не должно быть ни одного integrity: частично
//                    включённый SRI опаснее выключенного (устаревший хэш
//                    молча ломает загрузку страницы), так что включать надо
//                    осознанно — переставив этот флаг;
//   true           — у каждого своего <script src> и <link rel="stylesheet">
//                    есть integrity, и он совпадает с файлом в public/ (иначе
//                    браузер откажется выполнять скрипт и клиент не запустится).
// Логика разбора и расчёта проверяется на выдуманных страницах независимо от флага.
// Запуск: node test/client-sri.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { clientScriptFiles } = require('./client-script-source');
const { spawnSync } = require('child_process');
const { applySri, findSriTags, hasAnyIntegrity, localUrlPath } = require('../lib/client-sri');

// Волна 6: поставить true, выполнить `node scripts/update-sri.js`, пересобрать манифест.
const SRI_ENABLED = false;

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const INDEX = path.join(PUBLIC_DIR, 'index.html');

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

const sri = (text) => 'sha384-' + crypto.createHash('sha384').update(Buffer.from(text)).digest('base64');
const FILES = { '/a.js': 'alert(1)', '/s.css': 'body{}', '/lib/b.js': 'b()' };
const read = (urlPath) => (urlPath in FILES ? Buffer.from(FILES[urlPath]) : null);

console.log('Client SRI tests\n');

test('добавляет integrity после src/href; регистр имени тега и прочие атрибуты сохраняются', () => {
    const html = '<SCRIPT src="a.js" defer></SCRIPT>\n<link rel="stylesheet" href="/s.css" media="all">\n<script src=\'lib/b.js\'></script>';
    const result = applySri(html, read);
    assert.strictEqual(result.html,
        `<SCRIPT src="a.js" integrity="${sri('alert(1)')}" defer></SCRIPT>\n` +
        `<link rel="stylesheet" href="/s.css" integrity="${sri('body{}')}" media="all">\n` +
        `<script src='lib/b.js' integrity="${sri('b()')}"></script>`);
    assert.deepStrictEqual(result.tags.map((tag) => tag.status), ['missing', 'missing', 'missing']);
});

test('идемпотентно: второй проход ничего не меняет; устаревший хэш заменяется', () => {
    const once = applySri('<script src="a.js"></script>', read).html;
    const again = applySri(once, read);
    assert.strictEqual(again.html, once);
    assert.deepStrictEqual(again.tags.map((tag) => tag.status), ['ok']);
    const stale = once.replace(/integrity="[^"]*"/, 'integrity="sha384-AAAA"');
    const fixed = applySri(stale, read);
    assert.strictEqual(fixed.tags[0].status, 'stale');
    assert.strictEqual(fixed.html, once);
});

test('не трогает чужие адреса, иконки, manifest, preload, inline-скрипты и data:', () => {
    const html = [
        '<link rel="icon" href="icons/favicon.svg">',
        '<link rel="manifest" href="manifest.webmanifest">',
        '<link rel="apple-touch-icon" href="icons/apple-touch-icon.png">',
        '<link rel="preload" href="a.js" as="script">',
        '<script src="https://cdn.example.com/x.js"></script>',
        '<script src="//cdn.example.com/x.js"></script>',
        '<script src="data:text/javascript,1"></script>',
        '<script>var inline = 1;</script>',
    ].join('\n');
    const result = applySri(html, read);
    assert.strictEqual(result.html, html);
    assert.deepStrictEqual(result.tags, []);
});

test('remove убирает integrity, остальное оставляет', () => {
    const withSri = applySri('<script src="a.js" defer></script><link rel="stylesheet" href="s.css">', read).html;
    assert.ok(hasAnyIntegrity(withSri));
    const removed = applySri(withSri, read, { remove: true }).html;
    assert.strictEqual(removed, '<script src="a.js" defer></script><link rel="stylesheet" href="s.css">');
    assert.ok(!hasAnyIntegrity(removed));
});

test('файла нет — статус no-file, страница не меняется', () => {
    const html = '<script src="нет-такого.js"></script>';
    const result = applySri(html, read);
    assert.strictEqual(result.html, html);
    assert.strictEqual(result.tags[0].status, 'no-file');
});

test('localUrlPath: относительные и корневые адреса, без запроса и якоря; чужие — null', () => {
    assert.strictEqual(localUrlPath('a.js'), '/a.js');
    assert.strictEqual(localUrlPath('/lib/b.js?v=1#x'), '/lib/b.js');
    for (const foreign of ['http://x/y.js', 'https://x/y.js', '//x/y.js', 'data:,1', 'blob:abc', '#top', '']) {
        assert.strictEqual(localUrlPath(foreign), null, foreign);
    }
});

test('findSriTags находит все скрипты и стили настоящего index.html', () => {
    const html = fs.readFileSync(INDEX, 'utf8');
    const tags = findSriTags(html);
    assert.ok(tags.length >= 10, 'в index.html найдено подозрительно мало тегов: ' + tags.length);
    for (const required of [...clientScriptFiles().map((file) => '/' + file), '/e2ee.js', '/css/tokens.css', '/css/responsive.css', '/vendor/socket.io.min.js']) {
        assert.ok(tags.some((tag) => tag.urlPath === required), `нет ${required}`);
    }
    // pow-worker.js — Worker, а не <script>: у него нет integrity, он не должен попасть сюда.
    assert.ok(!tags.some((tag) => tag.urlPath === '/pow-worker.js'));
});

const readPublic = (urlPath) => {
    const file = path.join(PUBLIC_DIR, ...urlPath.split('/').filter(Boolean));
    return fs.existsSync(file) ? fs.readFileSync(file) : null;
};

if (!SRI_ENABLED) {
    test('SRI ещё не включён (волна 6): в index.html нет ни одного integrity', () => {
        const html = fs.readFileSync(INDEX, 'utf8');
        assert.ok(!hasAnyIntegrity(html),
            'в index.html появились integrity: чтобы включить SRI, поставьте SRI_ENABLED = true в этом тесте и обновите атрибуты (node scripts/update-sri.js)');
        assert.ok(!/\sintegrity\s*=/i.test(html));
    });
    console.log('  skip - «SRI актуален»: выключено до волны 6 (SRI_ENABLED = false)');
} else {
    test('SRI актуален: у каждого своего скрипта и стиля в index.html верный integrity', () => {
        const result = applySri(fs.readFileSync(INDEX, 'utf8'), readPublic);
        const bad = result.tags.filter((tag) => tag.status !== 'ok');
        assert.deepStrictEqual(bad.map((tag) => `${tag.url}: ${tag.status}`), [], 'запустите node scripts/update-sri.js и пересоберите манифест');
    });
}

test('scripts/update-sri.js --check: пока SRI выключен, сообщает об отсутствующих атрибутах (код 1), когда включён — код 0', () => {
    const run = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'update-sri.js'), '--check'], { cwd: ROOT, encoding: 'utf8' });
    assert.strictEqual(run.status, SRI_ENABLED ? 0 : 1, run.stdout + run.stderr);
    if (!SRI_ENABLED) assert.match(run.stderr, /нет integrity: \/js\/01-state\.js/);
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
