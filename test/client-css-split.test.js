'use strict';
// Стили клиента разбиты на public/css/*.css (волна 6, раньше — один public/style.css).
// Каскад теперь зависит от порядка <link> в index.html, а каждый файл браузер
// разбирает отдельно: ошибка в одном (незакрытая скобка, @import) тихо ломает
// соседние правила. Эти проверки держат разбиение в рабочем состоянии.
// Запуск: node test/client-css-split.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { cssFiles } = require('./client-css');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const CSS_DIR = path.join(PUBLIC_DIR, 'css');
const MAX_LINES = 1200;

// Порядок — это порядок каскада: токены первыми, адаптив и доступность последними
// (их правила намеренно перебивают остальные при равной специфичности).
const EXPECTED_ORDER = [
    'css/tokens.css', 'css/controls.css', 'css/auth.css', 'css/app-shell.css', 'css/messages.css',
    'css/composer.css', 'css/modals.css', 'css/popups.css', 'css/responsive.css',
];

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

const readCss = (href) => fs.readFileSync(path.join(PUBLIC_DIR, ...href.split('/')), 'utf8');

// Глубина вложенности {} в конце файла и наименьшая по пути; комментарии и строки пропускаются.
function braceDepth(source) {
    const backslash = String.fromCharCode(92);
    let depth = 0, lowest = 0, i = 0;
    while (i < source.length) {
        const char = source[i];
        if (char === '/' && source[i + 1] === '*') {
            const end = source.indexOf('*/', i + 2);
            if (end < 0) return { depth: NaN, lowest: NaN };      // незакрытый комментарий
            i = end + 2;
            continue;
        }
        if (char === '"' || char === "'") {
            let k = i + 1;
            while (k < source.length && source[k] !== char) k += source[k] === backslash ? 2 : 1;
            i = k + 1;
            continue;
        }
        if (char === '{') depth++;
        if (char === '}') { depth--; if (depth < lowest) lowest = depth; }
        i++;
    }
    return { depth, lowest };
}

test('index.html подключает части стилей в порядке каскада; старого style.css нет', () => {
    assert.deepStrictEqual(cssFiles(), EXPECTED_ORDER);
    assert.ok(!fs.existsSync(path.join(PUBLIC_DIR, 'style.css')), 'public/style.css должен быть удалён: две копии стилей разъедутся');
});

test('в public/css нет файлов, которые index.html не подключает', () => {
    assert.deepStrictEqual(fs.readdirSync(CSS_DIR).sort(), EXPECTED_ORDER.map((href) => href.slice('css/'.length)).sort());
});

test('каждый файл: заголовок с собственным именем, не длиннее ' + MAX_LINES + ' строк, LF, строка в конце', () => {
    for (const href of EXPECTED_ORDER) {
        const text = readCss(href);
        assert.ok(text.startsWith(`/* ${href} — `), `${href}: файл должен начинаться комментарием «что здесь и откуда вынесено»`);
        assert.ok(text.split('\n').length - 1 <= MAX_LINES, `${href}: больше ${MAX_LINES} строк`);
        assert.ok(!text.includes('\r'), `${href}: CR в тексте (репозиторий — только LF)`);
        assert.ok(text.endsWith('\n'), `${href}: файл должен заканчиваться переводом строки`);
    }
});

test('каждый файл разбирается сам по себе: скобки сбалансированы, нет @import и @charset', () => {
    for (const href of EXPECTED_ORDER) {
        const text = readCss(href);
        const { depth, lowest } = braceDepth(text);
        assert.strictEqual(depth, 0, `${href}: не закрыта скобка (глубина в конце ${depth})`);
        assert.strictEqual(lowest, 0, `${href}: лишняя закрывающая скобка`);
        // @import подтянул бы файл в обход порядка <link>, @charset допустим только первым в файле.
        assert.doesNotMatch(text, /@import|@charset/, `${href}: @import и @charset не нужны`);
    }
});

console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
if (failed > 0) process.exitCode = 1;
