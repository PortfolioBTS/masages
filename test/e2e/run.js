'use strict';
// Раннер сквозных тестов (npm run test:e2e).
//
//   node test/e2e/run.js [--docker] [--grep <шаблон>] [--junit <файл>] [подстроки имён файлов…]
//
// * E2E_DATABASE_URL — админ-URL Postgres 16 (нужно право CREATE DATABASE);
//   без него — подсказка и код 1. --docker — поднять временный
//   postgres:16-alpine (пароль только в памяти, данные в tmpfs, fsync
//   выключен) и удалить его после прогона.
// * Проверяет подключение и удаляет базы упавших прогонов старше 2 ч (по
//   времени в имени — базы параллельного прогона не задеваются).
// * Запускает node --test с явным списком test/e2e/*.e2e.test.js: каждый
//   файл — отдельным процессом, по 2 одновременно, тайм-аут теста 60 с;
//   --grep превращается в --test-name-pattern; --junit — ещё и отчёт JUnit.

const { spawn, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const E2E_DIR = __dirname;
const REPO_ROOT = path.resolve(E2E_DIR, '..', '..');

function parseArgs(argv) {
    const opts = { docker: false, grep: null, junit: null, filters: [] };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--docker') opts.docker = true;
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

const HINT = `Сквозным тестам нужен Postgres 16 с правом CREATE DATABASE. Варианты:
  1) npm run test:e2e:docker — временный контейнер на время прогона (нужен Docker);
  2) постоянный контейнер:
       docker run -d --name nyxo-pg-test -e POSTGRES_USER=nyxo -e POSTGRES_PASSWORD=<пароль> \\
         -p 127.0.0.1:55432:5432 postgres:16-alpine
     и E2E_DATABASE_URL=postgresql://nyxo:<пароль>@127.0.0.1:55432/postgres npm run test:e2e
Подробнее — docs/dev/testing.md.`;

// Адрес без пароля — для сообщений.
function describeUrl(url) {
    try {
        const u = new URL(url);
        return `${u.hostname}:${u.port || 5432}`;
    } catch {
        return '(некорректный URL)';
    }
}

async function tryQuery(url) {
    const client = new Client({ connectionString: url, connectionTimeoutMillis: 3000 });
    try {
        await client.connect();
        await client.query('SELECT 1');
        return null;
    } catch (err) {
        return err;
    } finally {
        await client.end().catch(() => {});
    }
}

// Ожидание готовности Postgres: повторные попытки подключения до срока.
async function waitForPostgres(url, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const err = await tryQuery(url);
        if (!err) return;
        if (Date.now() > deadline) throw new Error(`Postgres ${describeUrl(url)} не ответил за ${timeoutMs / 1000} с: ${err.message}`);
        await new Promise(resolve => setTimeout(resolve, 250));
    }
}

async function startDockerPostgres() {
    const password = crypto.randomBytes(24).toString('base64url');
    const name = `nyxo-e2e-${process.pid}-${crypto.randomBytes(3).toString('hex')}`;
    // Пароль — через окружение docker CLI («-e ИМЯ» без значения), а не в
    // аргументах командной строки.
    const id = execFileSync('docker', [
        'run', '-d', '--rm', '--name', name,
        '-e', 'POSTGRES_USER=nyxo', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=postgres',
        '--tmpfs', '/var/lib/postgresql/data:rw',
        '-p', '127.0.0.1::5432',
        'postgres:16-alpine',
        '-c', 'fsync=off', '-c', 'synchronous_commit=off', '-c', 'full_page_writes=off', '-c', 'max_connections=300',
    ], { encoding: 'utf8', env: { ...process.env, POSTGRES_PASSWORD: password } }).trim();
    const stop = () => {
        try { execFileSync('docker', ['rm', '-f', id], { stdio: 'ignore' }); } catch { /* уже удалён */ }
    };
    try {
        const mapping = execFileSync('docker', ['port', id, '5432/tcp'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0];
        const port = mapping.split(':').pop();
        const url = `postgresql://nyxo:${encodeURIComponent(password)}@127.0.0.1:${port}/postgres`;
        console.log(`[e2e] Временный Postgres: контейнер ${name}, 127.0.0.1:${port}`);
        await waitForPostgres(url, 60000);
        return { url, stop };
    } catch (err) {
        stop();
        throw err;
    }
}

function testFiles(filters) {
    return fs.readdirSync(E2E_DIR)
        .filter(name => name.endsWith('.e2e.test.js'))
        .filter(name => filters.length === 0 || filters.some(f => name.includes(f)))
        .sort()
        .map(name => path.join(E2E_DIR, name));
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const files = testFiles(opts.filters);
    if (files.length === 0) {
        console.error(opts.filters.length > 0 ? `Нет наборов test/e2e/*.e2e.test.js, подходящих под: ${opts.filters.join(', ')}` : 'В test/e2e нет наборов *.e2e.test.js');
        return 1;
    }

    let docker = null;
    let url = process.env.E2E_DATABASE_URL;
    if (opts.docker) {
        docker = await startDockerPostgres();
        url = docker.url;
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
            console.error(`[e2e] Нет подключения к Postgres ${describeUrl(url)}: ${err.message}\n\n${HINT}`);
            return 1;
        }
        // Хвосты упавших прогонов (helpers/pg.js — тот же шаблон имён).
        process.env.E2E_DATABASE_URL = url;
        const { dropStaleDatabases } = require('./helpers/pg');
        const dropped = await dropStaleDatabases();
        if (dropped.length > 0) console.log(`[e2e] Удалены базы упавших прогонов: ${dropped.length}`);

        const nodeArgs = ['--test', '--test-concurrency=2', '--test-timeout=60000', '--test-force-exit'];
        if (opts.grep) nodeArgs.push(`--test-name-pattern=${opts.grep}`);
        nodeArgs.push('--test-reporter=spec', '--test-reporter-destination=stdout');
        if (opts.junit) nodeArgs.push('--test-reporter=junit', `--test-reporter-destination=${opts.junit}`);
        nodeArgs.push(...files);
        console.log(`[e2e] Postgres ${describeUrl(url)}, наборов: ${files.length}`);
        const code = await new Promise((resolve) => {
            const child = spawn(process.execPath, nodeArgs, {
                cwd: REPO_ROOT,
                stdio: 'inherit',
                env: { ...process.env, E2E_DATABASE_URL: url },
            });
            child.on('exit', (exitCode, signal) => resolve(signal ? 1 : exitCode));
        });
        return code;
    } finally {
        cleanup();
    }
}

main().then(
    (code) => { process.exitCode = code; },
    (err) => { console.error(`[e2e] ${err.message}`); process.exitCode = 1; }
);
