'use strict';
// Охрана workflow релиза и сторожа (6.1/6.3, roadmap R10): release.yml и watchdog.yml.
// Общие правила CI (SHA-пины, верхний permissions, persist-credentials) проверяет
// test/workflows.test.js; здесь — то, что относится именно к этим двум файлам.
// Парсера YAML в проекте нет, поэтому проверки построчные, по форме, в которой
// файлы написаны (как в workflows.test.js).
//
//  - релиз запускается на теге v*, права на запись есть только у job release, а
//    публикация и аттестация — только на теге (ручной запуск — репетиция);
//  - манифест сравнивается между ОС (cmp), а не принимается на веру;
//  - сторож выключен, пока не задана переменная репозитория WATCHDOG_URL, и
//    сверяет продакшен с манифестом релиза, а не с самим собой;
//  - в блоках run нет подстановок ${{ }}: значения из контекста GitHub идут через
//    env (иначе тег или переменная превращаются во внедрение команд в shell).
// Запуск: node test/release-workflows.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const WORKFLOWS_DIR = path.join(__dirname, '..', '.github', 'workflows');
const read = (name) => fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8').replace(/\r\n/g, '\n');

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

const indentOf = (line) => line.length - line.trimStart().length;

// Текст job-а: от строки «  <имя>:» до следующего job-а (отступ 2) или конца файла.
function jobBlock(text, job) {
    const lines = text.split('\n');
    const start = lines.findIndex((line) => line === `  ${job}:`);
    assert.ok(start >= 0, `нет job «${job}»`);
    let end = start + 1;
    while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > 2)) end++;
    return lines.slice(start, end).join('\n');
}

// Блок шага (от строки «- …» до следующей строки того же отступа), в котором стоит подстрока.
function stepContaining(text, needle) {
    const lines = text.split('\n');
    const at = lines.findIndex((line) => line.includes(needle));
    assert.ok(at >= 0, `нет «${needle}»`);
    let start = at;
    while (start > 0 && !/^\s*-\s/.test(lines[start])) start--;
    const base = indentOf(lines[start]);
    let end = start + 1;
    while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > base)) end++;
    return lines.slice(start, end).join('\n');
}

// Все строки внутри многострочных блоков `run: |`.
function runBlockLines(text) {
    const lines = text.split('\n');
    const found = [];
    for (let i = 0; i < lines.length; i++) {
        if (!/^\s*run:\s*[|>]/.test(lines[i])) continue;
        const base = indentOf(lines[i]);
        for (let j = i + 1; j < lines.length && (lines[j].trim() === '' || indentOf(lines[j]) > base); j++) {
            found.push({ line: j + 1, text: lines[j] });
        }
    }
    // Однострочные `run: команда`.
    lines.forEach((text1, index) => {
        if (/^\s*run:\s*[^|>\s]/.test(text1)) found.push({ line: index + 1, text: text1 });
    });
    return found;
}

console.log('Release workflow guard tests\n');

const release = read('release.yml');
const watchdog = read('watchdog.yml');

test('release.yml: запуск на теге v* и вручную; верхний permissions — только чтение', () => {
    assert.match(release, /^on:\n {2}push:\n {4}tags: \['v\*'\]\n {2}workflow_dispatch:/m);
    assert.match(release, /^permissions:\n {2}contents: read\n/m);
});

test('release.yml: права на запись — только у job release; build — только чтение', () => {
    const build = jobBlock(release, 'build');
    const publish = jobBlock(release, 'release');
    assert.ok(!/:\s*write\b/.test(build), 'у build нет прав на запись');
    for (const permission of ['contents: write', 'id-token: write', 'attestations: write']) {
        assert.ok(publish.includes(permission), `у release нет «${permission}»`);
    }
    // Комментарии пропускаем: в них права упоминаются словами.
    const code = release.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n');
    const writes = code.match(/:\s*write\b/g) || [];
    assert.strictEqual(writes.length, 3, 'прав на запись должно быть ровно три, и все — у release');
});

test('release.yml: сборка на Ubuntu и Windows с npm ci, npm test и scripts/release-manifest.js', () => {
    const build = jobBlock(release, 'build');
    assert.match(build, /os: \[ubuntu-latest, windows-latest\]/);
    for (const command of ['npm ci', 'npm test', 'node scripts/release-manifest.js']) {
        assert.ok(build.includes(command), `в build нет «${command}»`);
    }
});

test('release.yml: файлы с двух ОС сравниваются через cmp до публикации', () => {
    const publish = jobBlock(release, 'release');
    assert.match(publish, /needs: build/);
    assert.match(publish, /cmp "artifacts\/release-ubuntu-latest\/\$name" "artifacts\/release-windows-latest\/\$name"/);
    assert.ok(publish.indexOf('cmp ') < publish.indexOf('gh release create'), 'сравнение должно идти раньше публикации');
});

test('release.yml: аттестация и создание Release — только на теге, ручной запуск — репетиция', () => {
    for (const needle of ['actions/attest-build-provenance@', 'gh release create']) {
        const step = stepContaining(release, needle);
        assert.match(step, /if: \$\{\{ github\.ref_type == 'tag' \}\}/, `шаг с «${needle}» должен выполняться только на теге`);
    }
    assert.match(stepContaining(release, 'attest-build-provenance@'), /release\/client-manifest\.json/);
    assert.match(stepContaining(release, 'gh release create'), /--verify-tag/);
});

test('release.yml: тег сверяется с версией и commit из release.json до публикации', () => {
    const step = stepContaining(release, 'Тег совпадает с версией');
    assert.match(step, /jq -r \.version release\/release\.json/);
    assert.match(step, /\$GITHUB_SHA/);
    assert.ok(release.indexOf('Тег совпадает с версией') < release.indexOf('Создать GitHub Release'));
});

test('watchdog.yml: расписание раз в сутки, ручной запуск, выключен без переменной WATCHDOG_URL', () => {
    assert.match(watchdog, /^on:\n {2}schedule:\n(?: {4}#.*\n)* {4}- cron: '\d+ \d+ \* \* \*'\n {2}workflow_dispatch:/m);
    const job = jobBlock(watchdog, 'verify');
    assert.match(job, /if: \$\{\{ vars\.WATCHDOG_URL != '' \}\}/);
    assert.match(job, /SITE_URL: \$\{\{ vars\.WATCHDOG_URL \}\}/);
    assert.match(watchdog, /^permissions:\n {2}contents: read\n/m);
    assert.match(job, /issues: write/);
});

test('watchdog.yml: эталон — манифест последнего релиза с проверкой аттестации, а не манифест сайта', () => {
    assert.match(watchdog, /gh release download --repo "\$REPO" --pattern client-manifest\.json/);
    assert.match(watchdog, /gh attestation verify watchdog\/client-manifest\.json --repo "\$REPO"/);
    assert.match(watchdog, /node scripts\/verify-deployment\.js "\$SITE_URL" --manifest watchdog\/client-manifest\.json/);
});

test('watchdog.yml: при расхождении (код 1) открывается или дополняется issue, при коде 2 запуск красный без issue о подмене', () => {
    assert.match(stepContaining(watchdog, 'gh issue create'), /steps\.verify\.outputs\.code == '1'/);
    assert.match(watchdog, /gh issue comment "\$number"/);
    assert.match(stepContaining(watchdog, 'Сверка не выполнена'), /code != '0' && steps\.verify\.outputs\.code != '1'/);
});

test('в блоках run обоих workflow нет подстановок ${{ }}: значения контекста идут через env', () => {
    const problems = [];
    for (const [name, text] of [['release.yml', release], ['watchdog.yml', watchdog]]) {
        for (const { line, text: code } of runBlockLines(text)) {
            if (code.includes('${{')) problems.push(`${name}:${line}: ${code.trim()}`);
        }
    }
    assert.deepStrictEqual(problems, [], '\n' + problems.join('\n'));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
