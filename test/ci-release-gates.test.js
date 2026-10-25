'use strict';
// Страж условий релиза и образов в CI (ревью W7 R5, З-10 и З-11):
//  - релиз зависит не только от юнит-тестов (build), но и от сквозных тестов и аудита зависимостей на том же
//    коммите: иначе тег на коммите без зелёного e2e выпустил бы релиз (З-11а). Jobs e2e и audit в release.yml -
//    копии jobs из ci.yml, и проверка требует, чтобы копии не разошлись;
//  - образ Postgres в сервисах закреплён и тегом, и digest (З-11б; тег в реестре можно перепривязать), один и тот же
//    везде: workflows.test.js проверяет digest только у `docker run`;
//  - смоук в браузере (job browser) работает на ubuntu с Postgres, но в условия релиза не входит, пока не доказал
//    стабильность (З-11в); никакой job, кроме coverage, не глотает падение через continue-on-error;
//  - покрытие (З-10) - отдельный информативный job и скрипт test:coverage, не блокирующие ничего (З-10).
// Парсера YAML в проекте нет, проверки построчные (как в workflows.test.js).
// Запуск: node test/ci-release-gates.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const WORKFLOWS_DIR = path.join(ROOT, '.github', 'workflows');

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

console.log('CI and release gates guard tests\n');

if (!fs.existsSync(WORKFLOWS_DIR)) {
    console.log('  skip - нет каталога .github/workflows (архив исходников), проверка пропущена');
} else {
    const read = (name) => fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8').replace(/\r\n/g, '\n');
    const indentOf = (line) => line.length - line.trimStart().length;
    const ci = read('ci.yml');
    const release = read('release.yml');

    // Текст job-а: от строки «  <имя>:» до следующего job-а (отступ 2); null, если job нет.
    function jobBlock(text, job) {
        const lines = text.split('\n');
        const start = lines.findIndex((line) => line === `  ${job}:`);
        if (start < 0) return null;
        let end = start + 1;
        while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > 2)) end++;
        return lines.slice(start, end).join('\n');
    }
    const mustJob = (text, job, file) => {
        const block = jobBlock(text, job);
        assert.ok(block, `в ${file} нет job «${job}»`);
        return block;
    };
    const jobNames = (text) => text.split('\n').map((line) => /^ {2}([\w-]+):\s*$/.exec(line)).filter(Boolean).map((m) => m[1]);
    const code = (block) => block.split('\n').filter((line) => !/^\s*#/.test(line));

    // Значимые строки job-а для сравнения копий: действия, команды, образ, адрес базы, переменные сервиса.
    // Шаги выгрузки артефактов (логи упавшего ci) в копии не нужны.
    function significant(block) {
        return code(block)
            .filter((line) => /^\s*(?:- )?(uses:|run:|image:|E2E_DATABASE_URL:|POSTGRES_|node-version:|--health)/.test(line))
            .filter((line) => !/upload-artifact/.test(line))
            .map((line) => line.trim());
    }

    test('release.yml: job release ждёт build, e2e и audit', () => {
        const publish = mustJob(release, 'release', 'release.yml');
        const needs = /^\s*needs:\s*\[([^\]]*)\]/m.exec(publish);
        assert.ok(needs, 'у release нет needs: [...]');
        const list = needs[1].split(',').map((item) => item.trim());
        for (const job of ['build', 'e2e', 'audit']) assert.ok(list.includes(job), `release не ждёт «${job}» (needs: ${list.join(', ')})`);
    });

    test('release.yml: jobs e2e и audit - копии jobs из ci.yml (команды, действия, образ, адрес базы)', () => {
        for (const job of ['e2e', 'audit']) {
            const inCi = significant(mustJob(ci, job, 'ci.yml'));
            const inRelease = significant(mustJob(release, job, 'release.yml'));
            assert.ok(inCi.some((line) => /^run: npm run test:e2e$|^run: node scripts\/audit-check\.js$/.test(line)), `в ci.yml job ${job} не запускает ожидаемую проверку`);
            assert.deepStrictEqual(inRelease, inCi, `job ${job} в release.yml разошёлся с ci.yml`);
        }
    });

    test('release.yml: e2e и audit не глотают падение (нет continue-on-error), права только на чтение', () => {
        for (const job of ['build', 'e2e', 'audit']) {
            const block = code(mustJob(release, job, 'release.yml')).join('\n');
            assert.ok(!/continue-on-error/.test(block), `у ${job} есть continue-on-error`);
            assert.ok(!/:\s*write\b/.test(block), `у ${job} есть права на запись`);
        }
    });

    test('образ Postgres в сервисах закреплён тегом и digest, один и тот же в ci.yml и release.yml', () => {
        const images = [];
        for (const [file, text] of [['ci.yml', ci], ['release.yml', release]]) {
            code(text).forEach((line) => {
                const match = /^\s*image:\s*(\S+)\s*$/.exec(line);
                if (match) images.push({ file, image: match[1] });
            });
        }
        assert.ok(images.length >= 3, `ожидались сервисы e2e и browser в ci.yml и e2e в release.yml: ${JSON.stringify(images)}`);
        for (const { file, image } of images) {
            assert.match(image, /^postgres:16-alpine@sha256:[0-9a-f]{64}$/, `${file}: образ «${image}» без тега+digest`);
        }
        assert.strictEqual(new Set(images.map((item) => item.image)).size, 1, 'digest образа различается между jobs: ' + JSON.stringify(images));
    });

    test('смоук в браузере: job browser на ubuntu с Postgres и npm run test:browser, но не условие релиза', () => {
        const browser = mustJob(ci, 'browser', 'ci.yml');
        assert.match(browser, /runs-on: ubuntu-latest/);
        assert.match(browser, /run: npm run test:browser/);
        assert.match(browser, /E2E_DATABASE_URL: postgresql:\/\/nyxo:nyxo-ci-only@127\.0\.0\.1:5432\/postgres/);
        assert.match(browser, /name: browser-screens/, 'снимки экрана сохраняются');
        assert.ok(!jobNames(release).includes('browser'), 'смоук в браузере не должен быть job-ом релиза');
        const needs = /^\s*needs:\s*\[([^\]]*)\]/m.exec(mustJob(release, 'release', 'release.yml'));
        assert.ok(needs && !/browser/.test(needs[1]), 'release не должен ждать browser');
        // Причина и условие ввода в защиту - рядом с job, чтобы их не потеряли.
        assert.match(ci, /НЕ входит в\s+# обязательные проверки защиты main/, 'у job browser пропало пояснение, почему он не обязателен');
    });

    test('continue-on-error есть только у информативного job coverage', () => {
        const withContinue = [];
        for (const file of fs.readdirSync(WORKFLOWS_DIR).filter((name) => /\.ya?ml$/.test(name))) {
            const text = read(file);
            for (const job of jobNames(text)) {
                const block = jobBlock(text, job);
                if (block && code(block).some((line) => /^\s*continue-on-error:\s*true/.test(line))) withContinue.push(`${file}:${job}`);
            }
        }
        assert.deepStrictEqual(withContinue, ['ci.yml:coverage']);
    });

    test('покрытие: job coverage информативный (не блокирует), запускает npm run test:coverage, отчёт в сводку и артефакт', () => {
        const coverage = mustJob(ci, 'coverage', 'ci.yml');
        assert.match(coverage, /continue-on-error: true/);
        assert.match(coverage, /run: \|\n\s+set -o pipefail\n\s+npm run test:coverage/);
        assert.match(coverage, /GITHUB_STEP_SUMMARY/);
        assert.match(coverage, /name: coverage-unit/);
        // Не в списке обязательных проверок (workflows.test.js, docs/dev/ci.md) и не в условиях релиза.
        assert.ok(!jobNames(release).includes('coverage'));
    });

    test('package.json: скрипт test:coverage - node --test с покрытием по src, lib, public без vendor, без новых зависимостей', () => {
        const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
        const script = pkg.scripts['test:coverage'];
        assert.ok(script, 'нет скрипта test:coverage');
        assert.match(script, /--experimental-test-coverage/);
        for (const dir of ['src', 'lib', 'public']) assert.ok(script.includes(`--test-coverage-include=${dir}/**`), `покрытие не включает ${dir}`);
        assert.ok(script.includes('--test-coverage-exclude=public/vendor/**'), 'чужой клиент socket.io попал бы в покрытие');
        assert.ok(script.includes('test/*.test.js'), 'не указаны файлы юнит-тестов');
        assert.strictEqual(pkg.devDependencies, undefined, 'покрытие не должно требовать новых зависимостей');
    });
}

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
