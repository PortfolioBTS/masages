'use strict';
// Страж конфигурации CI (пункт 7.1): .github/workflows/*.yml и dependabot.yml.
// Парсера YAML в проекте нет (и добавлять зависимость ради этого незачем), поэтому
// проверки построчные и намеренно простые — по форме, в которой файлы написаны.
//
// Что охраняется и почему:
//  - каждое `uses:` закреплено полным SHA коммита с версией в комментарии: тег в
//    чужом репозитории можно перепривязать на другой код, SHA — нельзя;
//  - у одного репозитория действий одна версия на все workflow (Dependabot
//    обновляет их одним PR, расхождение значит ручную правку);
//  - у каждого checkout persist-credentials: false — токен не остаётся в .git
//    и не доступен последующим шагам;
//  - у каждого workflow верхний `permissions:` — без него токен получает права
//    по настройке репозитория, то есть потенциально на запись;
//  - образы в `docker run` закреплены digest;
//  - имена jobs, которые перечислены в docs/dev/ci.md как обязательные проверки в
//    защите main, существуют: переименование молча сняло бы проверку с защиты;
//  - Dependabot покрывает все три экосистемы.
//
// Без каталога .github (архив исходников) проверять нечего — тест пропускается.
// Запуск: node test/workflows.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const GITHUB_DIR = path.join(ROOT, '.github');
const WORKFLOWS_DIR = path.join(GITHUB_DIR, 'workflows');

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

// Файл -> строки без \r (на случай чекаута с CRLF).
const readLines = (file) => fs.readFileSync(file, 'utf8').split('\n').map((line) => line.replace(/\r$/, ''));
const indentOf = (line) => line.length - line.trimStart().length;

// Все `uses:` файла: { line (с 1), spec, comment }.
function findUses(lines) {
    const found = [];
    lines.forEach((text, index) => {
        const match = /^\s*(?:-\s+)?uses:\s*(\S+?)(?:\s+#\s*(.*))?\s*$/.exec(text);
        if (!match) return;
        found.push({ line: index + 1, spec: match[1].replace(/^['"]|['"]$/g, ''), comment: (match[2] || '').trim() });
    });
    return found;
}

// Блок шага, в котором стоит строка `uses:` (индекс с 0): от строки «- …» до
// следующей строки того же или меньшего отступа.
function stepBlock(lines, usesIndex) {
    let start = usesIndex;
    while (start > 0 && !/^\s*-\s/.test(lines[start])) start--;
    const base = indentOf(lines[start]);
    let end = start + 1;
    while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > base)) end++;
    return lines.slice(start, end).join('\n');
}

// Строки с обратным слэшем в конце склеиваются: `docker run … \` + образ на следующей.
function joinContinuations(lines) {
    const joined = [];
    let buffer = '';
    for (const text of lines) {
        if (/\\\s*$/.test(text)) {
            buffer += text.replace(/\\\s*$/, ' ');
        } else {
            joined.push(buffer + text);
            buffer = '';
        }
    }
    if (buffer) joined.push(buffer);
    return joined;
}

console.log('CI configuration guard tests\n');

if (!fs.existsSync(WORKFLOWS_DIR)) {
    console.log('  skip - нет каталога .github/workflows (архив исходников), проверка пропущена');
} else {
    const files = fs.readdirSync(WORKFLOWS_DIR).filter((name) => /\.ya?ml$/.test(name)).sort();

    test('there is at least one workflow', () => {
        assert.ok(files.length > 0, 'в .github/workflows нет файлов');
    });

    test('every uses: is pinned to a full commit SHA with a version comment', () => {
        const problems = [];
        for (const name of files) {
            for (const use of findUses(readLines(path.join(WORKFLOWS_DIR, name)))) {
                const where = `${name}:${use.line}: ${use.spec}`;
                if (use.spec.startsWith('./')) continue; // локальное действие — версия та же, что у репозитория
                if (use.spec.startsWith('docker://')) {
                    if (!/@sha256:[0-9a-f]{64}$/.test(use.spec)) problems.push(`${where} — образ без digest`);
                    continue;
                }
                if (!/^[\w.-]+\/[\w.-]+(\/[\w./-]+)?@[0-9a-f]{40}$/.test(use.spec)) {
                    problems.push(`${where} — нужен полный SHA коммита (40 hex), а не тег или ветка`);
                    continue;
                }
                if (!/^v\d+(\.\d+){0,2}(\s|$)/.test(use.comment)) {
                    problems.push(`${where} — после SHA нужен комментарий с версией вида «# v1.2.3»`);
                }
            }
        }
        assert.deepStrictEqual(problems, [], '\n' + problems.join('\n'));
    });

    test('one repository of actions is pinned to one SHA across all workflows', () => {
        const byRepo = new Map(); // owner/repo -> Map(sha -> места)
        for (const name of files) {
            for (const use of findUses(readLines(path.join(WORKFLOWS_DIR, name)))) {
                const match = /^([\w.-]+\/[\w.-]+)(?:\/[\w./-]+)?@([0-9a-f]{40})$/.exec(use.spec);
                if (!match) continue;
                if (!byRepo.has(match[1])) byRepo.set(match[1], new Map());
                const shas = byRepo.get(match[1]);
                if (!shas.has(match[2])) shas.set(match[2], []);
                shas.get(match[2]).push(`${name}:${use.line}`);
            }
        }
        const problems = [];
        for (const [repo, shas] of byRepo) {
            if (shas.size > 1) problems.push(`${repo}: ${[...shas].map(([sha, at]) => `${sha.slice(0, 10)} (${at.join(', ')})`).join(' vs ')}`);
        }
        assert.deepStrictEqual(problems, [], '\n' + problems.join('\n'));
    });

    test('every checkout step sets persist-credentials: false', () => {
        const problems = [];
        for (const name of files) {
            const lines = readLines(path.join(WORKFLOWS_DIR, name));
            lines.forEach((text, index) => {
                if (!/uses:\s*actions\/checkout@/.test(text)) return;
                if (!/^\s*persist-credentials:\s*false\s*$/m.test(stepBlock(lines, index))) {
                    problems.push(`${name}:${index + 1}`);
                }
            });
        }
        assert.deepStrictEqual(problems, [], 'checkout без persist-credentials: false:\n' + problems.join('\n'));
    });

    test('every workflow declares top-level permissions', () => {
        const without = files.filter((name) => !readLines(path.join(WORKFLOWS_DIR, name)).some((line) => /^permissions:/.test(line)));
        assert.deepStrictEqual(without, [], 'нет верхнего permissions: ' + without.join(', '));
    });

    test('docker run images are pinned by digest', () => {
        const problems = [];
        for (const name of files) {
            // Комментарии пропускаем: в них «docker run» упоминается словами.
            const code = readLines(path.join(WORKFLOWS_DIR, name)).filter((line) => !/^\s*#/.test(line));
            joinContinuations(code).forEach((text) => {
                if (/\bdocker run\b/.test(text) && !/@sha256:[0-9a-f]{64}/.test(text)) problems.push(`${name}: ${text.trim()}`);
            });
        }
        assert.deepStrictEqual(problems, [], '\n' + problems.join('\n'));
    });

    test('job names required for branch protection exist (docs/dev/ci.md)', () => {
        const jobNames = (name) => readLines(path.join(WORKFLOWS_DIR, name))
            .map((line) => /^ {2}([\w-]+):\s*$/.exec(line))
            .filter(Boolean)
            .map((match) => match[1]);
        const required = { 'ci.yml': ['unit', 'e2e', 'audit', 'workflows-lint'], 'codeql.yml': ['analyze'] };
        for (const [name, jobs] of Object.entries(required)) {
            assert.ok(files.includes(name), `нет ${name}`);
            const present = jobNames(name);
            for (const job of jobs) assert.ok(present.includes(job), `в ${name} нет job «${job}» (есть: ${present.join(', ')})`);
        }
        const ci = fs.readFileSync(path.join(WORKFLOWS_DIR, 'ci.yml'), 'utf8');
        assert.match(ci, /os:\s*\[ubuntu-latest,\s*windows-latest\]/, 'unit должен идти на Ubuntu и на Windows');
    });
}

const dependabotFile = path.join(GITHUB_DIR, 'dependabot.yml');
if (!fs.existsSync(GITHUB_DIR)) {
    console.log('  skip - нет каталога .github (архив исходников), проверка Dependabot пропущена');
} else {
    test('dependabot.yml covers npm, github-actions and the tor-service image', () => {
        assert.ok(fs.existsSync(dependabotFile), 'нет .github/dependabot.yml');
        const text = fs.readFileSync(dependabotFile, 'utf8');
        assert.match(text, /^version:\s*2\s*$/m);
        // Блоки списка updates: от «- package-ecosystem:» до следующего такого.
        const blocks = text.split(/^ {2}- (?=package-ecosystem:)/m).slice(1);
        const covered = blocks.map((block) => {
            const ecosystem = /package-ecosystem:\s*(\S+)/.exec(block);
            const directory = /^\s*directory:\s*(\S+)/m.exec(block);
            return `${ecosystem && ecosystem[1]} ${directory && directory[1]}`;
        });
        for (const expected of ['npm /', 'github-actions /', 'docker /tor-service']) {
            assert.ok(covered.includes(expected), `нет записи «${expected}» (есть: ${covered.join('; ')})`);
        }
        assert.ok(fs.existsSync(path.join(ROOT, 'tor-service', 'Dockerfile')), 'каталог docker-записи должен существовать');
    });
}

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
