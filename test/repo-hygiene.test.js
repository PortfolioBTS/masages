'use strict';
// Гигиена репозитория: все текстовые файлы в git хранятся с LF.
//
// От этого зависят SHA-256 файлов клиента в релизе и на странице сверки
// (этап 6): на Windows и в CI хэши должны совпадать байт в байт. Правило
// закреплено в .gitattributes; тест ловит файл, добавленный в обход него
// (например, скопированный с CRLF до появления атрибутов).
//
// Без git (архив исходников без .git) проверять нечего — тест пропускается.
// Запуск: node test/repo-hygiene.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

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

function gitLsFilesEol() {
    const run = spawnSync('git', ['ls-files', '--eol'], { cwd: ROOT, encoding: 'utf8' });
    if (run.error || run.status !== 0) return null;
    // Строка: "i/lf    w/lf    attr/text eol=lf      	путь" — путь после таба.
    return run.stdout.split('\n').filter(Boolean).map((line) => {
        const tab = line.indexOf('\t');
        const [index] = line.slice(0, tab).trim().split(/\s+/);
        return { index, file: line.slice(tab + 1) };
    });
}

console.log('Repo hygiene tests\n');

test('.gitattributes pins LF for all text files', () => {
    const attrs = fs.readFileSync(path.join(ROOT, '.gitattributes'), 'utf8');
    assert.match(attrs, /^\*\s+text=auto\s+eol=lf\s*$/m);
});

const entries = gitLsFilesEol();
if (!entries) {
    console.log('  skip - git недоступен, проверка окончаний строк пропущена');
} else {
    test('no tracked file is stored with CRLF', () => {
        const crlf = entries.filter(e => e.index === 'i/crlf' || e.index === 'i/mixed').map(e => `${e.index} ${e.file}`);
        assert.deepStrictEqual(crlf, [], 'файлы с CRLF в индексе git:\n' + crlf.join('\n'));
    });
}

// Тест-ловушка: раннер test/run-unit.js судит о файле по коду выхода. Файл с мини-харнессом, который
// считает failed, но не выставляет process.exitCode, никогда не покраснеет (так было с e2ee-modules.test.js,
// ревью W7 R5, В-1). Достаточно, чтобы файл ставил код выхода сам или вызывал итоговую функцию общего
// харнесса (HARNESSES: модуль → вызов), который код выхода ставит; комментарии не в счёт.
const HARNESSES = [
    { module: 'sender-keys-helpers', call: /^\s*finish\(\);/m },
    { module: 'membership-world', call: /^\s*finish\(\);/m },
    { module: 'client-vm', call: /^\s*(await\s+)?done\(\);/m },
];
const stripComments = (source) => source.split('\n').filter(line => !/^\s*\/\//.test(line)).join('\n');
const SETS_EXIT = /process\.exitCode\s*=|process\.exit\s*\(/;

test('каждый test/*.test.js умеет падать: ставит process.exitCode / process.exit или вызывает итог харнесса', () => {
    const files = fs.readdirSync(__dirname).filter(name => name.endsWith('.test.js')).sort();
    assert.ok(files.length > 50, 'не нашли тестовые файлы в ' + __dirname);
    const silent = files.filter((name) => {
        const source = stripComments(fs.readFileSync(path.join(__dirname, name), 'utf8'));
        if (SETS_EXIT.test(source)) return false;
        return !HARNESSES.some(h => h.call.test(source) && new RegExp(`require\\('\\./${h.module}'\\)`).test(source));
    });
    assert.deepStrictEqual(silent, [], 'эти тесты не выставляют код выхода и не смогут покраснеть:\n' + silent.join('\n'));
});

test('общие харнессы из HARNESSES сами ставят код выхода при упавших тестах', () => {
    for (const { module } of HARNESSES) {
        const source = stripComments(fs.readFileSync(path.join(__dirname, module + '.js'), 'utf8'));
        assert.match(source, /if \(failed > 0\) process\.exitCode = 1;/, module + '.js не ставит process.exitCode');
    }
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
