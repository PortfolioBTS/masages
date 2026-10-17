'use strict';
// Раннер смоука в настоящем браузере (npm run test:browser).
//
//   node test/browser/run.js [--docker] [--headed] [--grep <шаблон>] [--junit <файл>] [подстроки имён файлов…]
//
// * Браузер ищется по CHROME_PATH, затем в типичных местах (helpers/find-browser.js).
//   Не найден: локально — понятное сообщение и код 0 (пропуск), в CI (переменная
//   CI) — код 1: смоук, который молча не запустился, хуже красного.
// * Postgres — как у сквозных тестов: E2E_DATABASE_URL (админ-URL с правом CREATE
//   DATABASE) или --docker (временный postgres:16-alpine на время прогона).
// * --headed — показывать окна браузера (отладка; то же, что NYXO_BROWSER_HEADED=1).
// * Запускает node --test с явным списком test/browser/*.browser.test.js: файлы
//   по одному (каждый поднимает несколько процессов браузера), тайм-аут теста 3 мин.
// * Упавший набор оставляет снимки вкладок в test/browser/.screens (FAIL-*.png), а
//   логи серверов — в test/e2e/.logs (общая диагностика харнесса).

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { describeUrl, tryQuery, startDockerPostgres } = require('../e2e/helpers/postgres-docker');
const { findBrowser, isCi } = require('./helpers/find-browser');
const { BrowserProfile } = require('./helpers/browser');
const { SCREENS_DIR } = require('./helpers/page');

const BROWSER_DIR = __dirname;
const REPO_ROOT = path.resolve(BROWSER_DIR, '..', '..');

function parseArgs(argv) {
    const opts = { docker: false, headed: false, grep: null, junit: null, filters: [] };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--docker') opts.docker = true;
        else if (arg === '--headed') opts.headed = true;
        else if (arg === '--grep') opts.grep = argv[++i];
        else if (arg.startsWith('--grep=')) opts.grep = arg.slice('--grep='.length);
        else if (arg === '--junit') opts.junit = argv[++i];
        else if (arg.startsWith('--junit=')) opts.junit = arg.slice('--junit='.length);
        else if (arg.startsWith('--')) throw new Error(`неизвестный параметр ${arg}`);
        else opts.filters.push(arg);
    }
    if (opts.grep === undefined || opts.junit === undefined) throw new Error('у --grep и --junit должно быть значение');
    return opts;
}

const HINT = `Смоуку в браузере нужен Postgres 16 с правом CREATE DATABASE — тот же, что у сквозных тестов:
  1) npm run test:browser -- --docker — временный контейнер на время прогона (нужен Docker);
  2) E2E_DATABASE_URL=postgresql://<пользователь>:<пароль>@127.0.0.1:55432/postgres npm run test:browser
Подробнее — docs/dev/testing.md.`;

function testFiles(filters) {
    return fs.readdirSync(BROWSER_DIR)
        .filter(name => name.endsWith('.browser.test.js'))
        .filter(name => filters.length === 0 || filters.some(f => name.includes(f)))
        .sort()
        .map(name => path.join(BROWSER_DIR, name));
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const files = testFiles(opts.filters);
    if (files.length === 0) {
        console.error(opts.filters.length > 0 ? `Нет наборов test/browser/*.browser.test.js, подходящих под: ${opts.filters.join(', ')}` : 'В test/browser нет наборов *.browser.test.js');
        return 1;
    }

    let found;
    try {
        found = findBrowser();
    } catch (err) {
        console.error(`[browser] ${err.message}`);
        return 1;
    }
    if (!found) {
        const message = 'Chrome/Chromium не найден: установите Chrome или задайте путь в CHROME_PATH (например, CHROME_PATH="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe").';
        if (isCi()) {
            console.error(`[browser] ${message} В CI браузер обязателен — смоук не может быть пропущен.`);
            return 1;
        }
        console.log(`[browser] ПРОПУЩЕНО: ${message}`);
        return 0;
    }

    // Пробный запуск: заодно видно версию и сразу понятно, если браузер не стартует.
    let product;
    const probe = await BrowserProfile.launch({ name: 'version', executable: found.path, headed: opts.headed, env: process.env });
    try {
        ({ product } = await probe.version());
    } finally {
        await probe.close();
    }
    console.log(`[browser] ${product}: ${found.path} (${found.source === 'CHROME_PATH' ? 'из CHROME_PATH' : 'найден поиском'})`);

    let docker = null;
    let url = process.env.E2E_DATABASE_URL;
    if (opts.docker) {
        docker = await startDockerPostgres({ label: 'browser' });
        url = docker.url;
        console.log(`[browser] Временный Postgres: контейнер ${docker.name}, ${describeUrl(url)}`);
    } else if (!url) {
        console.error(HINT);
        return 1;
    }
    const cleanup = () => { if (docker) { docker.stop(); docker = null; } };
    for (const signal of ['SIGINT', 'SIGTERM']) {
        process.on(signal, () => { cleanup(); process.exit(130); });
    }

    try {
        const err = await tryQuery(url);
        if (err) {
            console.error(`[browser] Нет подключения к Postgres ${describeUrl(url)}: ${err.message}\n\n${HINT}`);
            return 1;
        }
        process.env.E2E_DATABASE_URL = url;
        const { dropStaleDatabases } = require('../e2e/helpers/pg');
        const dropped = await dropStaleDatabases();
        if (dropped.length > 0) console.log(`[browser] Удалены базы упавших прогонов: ${dropped.length}`);

        const nodeArgs = ['--test', '--test-concurrency=1', '--test-timeout=180000', '--test-force-exit'];
        if (opts.grep) nodeArgs.push(`--test-name-pattern=${opts.grep}`);
        nodeArgs.push('--test-reporter=spec', '--test-reporter-destination=stdout');
        if (opts.junit) nodeArgs.push('--test-reporter=junit', `--test-reporter-destination=${opts.junit}`);
        nodeArgs.push(...files);
        console.log(`[browser] Postgres ${describeUrl(url)}, наборов: ${files.length}`);
        const startedAt = Date.now();
        const env = { ...process.env, E2E_DATABASE_URL: url };
        if (opts.headed) env.NYXO_BROWSER_HEADED = '1';
        const code = await new Promise((resolve) => {
            const child = spawn(process.execPath, nodeArgs, { cwd: REPO_ROOT, stdio: 'inherit', env });
            child.on('exit', (exitCode, signal) => resolve(signal ? 1 : exitCode));
        });
        reportSaved(startedAt);
        return code;
    } finally {
        cleanup();
    }
}

// Свежие снимки сбоев и логи серверов: прогон напоминает, где искать причины.
function reportSaved(sinceMs) {
    let fresh = [];
    try {
        fresh = fs.readdirSync(SCREENS_DIR).filter(name => name.startsWith('FAIL-') && fs.statSync(path.join(SCREENS_DIR, name)).mtimeMs >= sinceMs);
    } catch {
        return;
    }
    if (fresh.length > 0) console.log(`[browser] Снимки упавших сценариев сохранены в ${path.relative(REPO_ROOT, SCREENS_DIR)} (файлов: ${fresh.length}); логи серверов — в test/e2e/.logs`);
}

main().then(
    (code) => { process.exitCode = code; },
    (err) => { console.error(`[browser] ${err.message}`); process.exitCode = 1; }
);
