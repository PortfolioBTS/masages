'use strict';
// Локальный сервер для ручной проверки интерфейса (встроенный браузер,
// docs/dev/testing.md):
//
//   npm run dev:local -- --port 3101 [--onion]           (временный Postgres в Docker)
//   node scripts/dev-local.js --port 3101 [--onion]      (база на E2E_DATABASE_URL)
//
//   --docker   временный postgres:16-alpine: пароль только в памяти, данные в
//              tmpfs; контейнер удаляется при выходе;
//              без него — своя база nyxo_dev_<время>_<rand> на E2E_DATABASE_URL,
//              удаляется при выходе;
//   --port N   порт сервера (по умолчанию 3000); у каждого, кто проверяет
//              интерфейс параллельно, — свой порт: разные origin не делят куки;
//   --onion    валидный тестовый ONION_ADDRESS и свободный внутренний ONION_PORT
//              (ссылка на onion-зеркало в интерфейсе).
//
// Секреты — случайные в памяти, POW_DIFFICULTY=8, NODE_ENV=development,
// cwd — временная папка: .env разработчика и сертификаты localhost+1*.pem
// не подхватываются, сервер идёт по HTTP. Остановка — Ctrl+C.

const { spawn, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SERVER_ENTRY, systemEnv, randomSecrets, testOnionAddress } = require('../test/e2e/helpers/env');
const { startDockerPostgres, describeUrl, tryQuery } = require('../test/e2e/helpers/postgres-docker');
const { freePort } = require('../test/e2e/helpers/server');

const CHILD_GUARD = path.join(__dirname, '..', 'test', 'e2e', 'helpers', 'child-guard.js');
const DEV_DB_RE = /^nyxo_dev_(\d{10})_[a-z0-9]+$/;
const DEV_DB_STALE_MS = 24 * 60 * 60 * 1000;

function parseArgs(argv) {
    const opts = { docker: false, port: 3000, onion: false };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--docker') opts.docker = true;
        else if (arg === '--onion') opts.onion = true;
        else if (arg === '--port' || arg.startsWith('--port=')) {
            const raw = arg === '--port' ? argv[++i] : arg.slice('--port='.length);
            opts.port = Number(raw);
            if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) throw new Error(`--port: нужен номер порта, а не «${raw}»`);
        } else {
            throw new Error(`неизвестный параметр ${arg} (есть --docker, --port N, --onion)`);
        }
    }
    return opts;
}

// Контейнеры прошлых запусков, которые не удалились (процесс убит без
// Ctrl+C): в имени — pid запустившего процесса, живых не трогаем.
function removeOrphanContainers() {
    let names = [];
    try {
        names = execFileSync('docker', ['ps', '-a', '--filter', 'name=nyxo-dev-', '--format', '{{.Names}}'], { encoding: 'utf8' })
            .split(/\r?\n/).filter(Boolean);
    } catch {
        return;
    }
    for (const name of names) {
        const pid = Number((/^nyxo-dev-(\d+)-/.exec(name) || [])[1]);
        let alive = false;
        try { process.kill(pid, 0); alive = true; } catch (err) { alive = err.code === 'EPERM'; }
        if (pid && !alive) {
            try { execFileSync('docker', ['rm', '-f', name], { stdio: 'ignore' }); } catch { /* уже удалён */ }
        }
    }
}

async function withClient(url, fn) {
    const { Client } = require('pg');
    const client = new Client({ connectionString: url });
    await client.connect();
    try {
        return await fn(client);
    } finally {
        await client.end();
    }
}

// Своя база на запуск; базы прошлых запусков старше суток удаляются.
async function createDevDatabase(adminUrl) {
    const name = `nyxo_dev_${Math.floor(Date.now() / 1000)}_${crypto.randomBytes(4).toString('hex')}`;
    await withClient(adminUrl, async (client) => {
        const { rows } = await client.query(`SELECT datname FROM pg_database WHERE datname LIKE 'nyxo\\_dev\\_%'`);
        for (const { datname } of rows) {
            const match = DEV_DB_RE.exec(datname);
            if (match && Date.now() - Number(match[1]) * 1000 > DEV_DB_STALE_MS) {
                await client.query(`DROP DATABASE IF EXISTS "${datname}" WITH (FORCE)`);
            }
        }
        await client.query(`CREATE DATABASE "${name}" TEMPLATE template0 ENCODING 'UTF8'`);
    });
    const url = new URL(adminUrl);
    url.pathname = `/${name}`;
    return { name, url: url.toString() };
}

async function waitReady(baseUrl, child, timeoutMs = 60000) {
    const deadline = Date.now() + timeoutMs;
    while (child.exitCode === null) {
        try {
            const res = await fetch(`${baseUrl}/api/auth`, { signal: AbortSignal.timeout(2000) });
            await res.arrayBuffer();
            if (res.status === 200) return true;
        } catch {
            // ещё не слушает порт
        }
        if (Date.now() > deadline) return false;
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    return false;
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const cleanups = [];
    const cleanup = async () => {
        while (cleanups.length > 0) {
            try { await cleanups.pop()(); } catch (err) { console.error(`[dev-local] уборка: ${err.message}`); }
        }
    };

    try {
        let adminUrl = process.env.E2E_DATABASE_URL;
        if (opts.docker) {
            removeOrphanContainers();
            console.log('[dev-local] Запускаю временный Postgres в Docker…');
            const docker = await startDockerPostgres({ label: 'dev' });
            cleanups.push(() => docker.stop());
            adminUrl = docker.url;
        } else if (!adminUrl) {
            throw new Error('нужен --docker или E2E_DATABASE_URL (админ-URL Postgres 16), см. docs/dev/testing.md');
        }
        const err = await tryQuery(adminUrl);
        if (err) throw new Error(`нет подключения к Postgres ${describeUrl(adminUrl)}: ${err.message}`);
        const db = await createDevDatabase(adminUrl);
        cleanups.push(() => withClient(adminUrl, client => client.query(`DROP DATABASE IF EXISTS "${db.name}" WITH (FORCE)`)));

        const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-dev-'));
        cleanups.push(() => fs.rmSync(workDir, { recursive: true, force: true }));

        const env = {
            ...systemEnv(),
            NODE_ENV: 'development',
            HOST: '127.0.0.1',
            PORT: String(opts.port),
            DATABASE_URL: db.url,
            ...randomSecrets(),
            POW_DIFFICULTY: '8',
            UPLOADS_DIR: path.join(workDir, 'uploads'),
        };
        if (opts.onion) {
            env.ONION_ADDRESS = testOnionAddress(`nyxo-dev-local-${opts.port}`);
            env.ONION_PORT = String(await freePort());
        }

        const child = spawn(process.execPath, ['--require', CHILD_GUARD, SERVER_ENTRY], {
            cwd: workDir,
            env,
            stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
            windowsHide: true,
        });
        const exited = new Promise(resolve => child.once('exit', resolve));
        cleanups.push(async () => {
            if (child.exitCode === null && child.signalCode === null) {
                child.kill();
                await exited;
            }
        });

        let stopping = false;
        const stop = async (code) => {
            if (stopping) return;
            stopping = true;
            await cleanup();
            process.exit(code);
        };
        for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => stop(130));

        const baseUrl = `http://127.0.0.1:${opts.port}`;
        if (!(await waitReady(baseUrl, child))) {
            console.error('[dev-local] Сервер не запустился — см. лог выше.');
            return stop(1);
        }
        console.log(`\n[dev-local] Готово: http://localhost:${opts.port}  (второй пользователь — ${baseUrl}: другие куки)`);
        console.log(`[dev-local] База ${db.name} на ${describeUrl(adminUrl)}${opts.docker ? ' (временный контейнер)' : ''} — удалится при выходе.`);
        if (opts.onion) console.log(`[dev-local] Onion: ${env.ONION_ADDRESS} (внутренний порт ${env.ONION_PORT})`);
        console.log('[dev-local] Остановка — Ctrl+C.');

        const code = await exited;
        return stop(stopping ? 130 : (code === 0 ? 0 : 1));
    } catch (err) {
        console.error(`[dev-local] ${err.message}`);
        await cleanup();
        process.exitCode = 1;
    }
}

main();
