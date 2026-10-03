'use strict';
// Временный Postgres 16 в Docker — для npm run test:e2e:docker и
// npm run dev:local: пароль генерируется и живёт только в памяти процесса
// (в docker CLI он уходит через окружение, а не аргументом командной
// строки), данные — в tmpfs, fsync выключен. Контейнер удаляется stop().

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const { Client } = require('pg');

// Адрес без пароля — для сообщений.
function describeUrl(url) {
    try {
        const u = new URL(url);
        return `${u.hostname}:${u.port || 5432}`;
    } catch {
        return '(некорректный URL)';
    }
}

// null — подключение есть; иначе ошибка подключения.
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

// Ожидание готовности: повторные подключения до срока (Postgres в
// контейнере сначала инициализирует кластер и перезапускается).
async function waitForPostgres(url, timeoutMs = 60000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const err = await tryQuery(url);
        if (!err) return;
        if (Date.now() > deadline) throw new Error(`Postgres ${describeUrl(url)} не ответил за ${timeoutMs / 1000} с: ${err.message}`);
        await new Promise(resolve => setTimeout(resolve, 250));
    }
}

// → { url, name, stop() }; url — админ-URL (пользователь nyxo, база postgres).
async function startDockerPostgres({ label = 'e2e' } = {}) {
    const password = crypto.randomBytes(24).toString('base64url');
    const name = `nyxo-${label}-${process.pid}-${crypto.randomBytes(3).toString('hex')}`;
    let id;
    try {
        id = execFileSync('docker', [
            'run', '-d', '--rm', '--name', name,
            '-e', 'POSTGRES_USER=nyxo', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=postgres',
            '--tmpfs', '/var/lib/postgresql/data:rw',
            '-p', '127.0.0.1::5432',
            'postgres:16-alpine',
            '-c', 'fsync=off', '-c', 'synchronous_commit=off', '-c', 'full_page_writes=off', '-c', 'max_connections=300',
        ], { encoding: 'utf8', env: { ...process.env, POSTGRES_PASSWORD: password }, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    } catch (err) {
        throw new Error(`не удалось запустить контейнер postgres:16-alpine (Docker запущен?): ${String(err.stderr || err.message).trim()}`);
    }
    const stop = () => {
        try { execFileSync('docker', ['rm', '-f', id], { stdio: 'ignore' }); } catch { /* уже удалён */ }
    };
    try {
        const mapping = execFileSync('docker', ['port', id, '5432/tcp'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0];
        const port = mapping.split(':').pop();
        const url = `postgresql://nyxo:${encodeURIComponent(password)}@127.0.0.1:${port}/postgres`;
        await waitForPostgres(url);
        return { url, name, stop };
    } catch (err) {
        stop();
        throw err;
    }
}

module.exports = { describeUrl, tryQuery, waitForPostgres, startDockerPostgres };
