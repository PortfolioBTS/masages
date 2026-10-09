'use strict';
// Базы данных сквозных тестов: своя база на каждый файл-набор.
//
// Имя — nyxo_e2e_<unixtime>_<rand>: время создания зашито в имя, поэтому
// раннер удаляет «хвосты» упавших прогонов (старше 2 ч), не трогая базы
// параллельного прогона из другого worktree. Удаляются только базы с таким
// шаблоном имени — ничего чужого на сервере Postgres.

const crypto = require('crypto');
const { Client, Pool } = require('pg');
const { adminDatabaseUrl } = require('./env');

const DB_NAME_RE = /^nyxo_e2e_(\d{10})_[a-z0-9]+$/;
const STALE_AFTER_MS = 2 * 60 * 60 * 1000;
// Подключение админ-клиента не должно висеть до тайм-аута хука (2 мин): на
// занятом сервере лучше быстро упасть и повторить.
const ADMIN_CONNECT_TIMEOUT_MS = 10000;

// Временные сбои сервера Postgres, при которых создание и удаление базы
// стоит повторить: общий контейнер делят несколько прогонов (разные
// worktree), и при пиковой нагрузке кончаются слоты соединений
// (max_connections). Раньше такой сбой в after-хуке давал «tests N, fail 1»
// без единой строки в test/e2e/.logs: все тесты набора зелёные, а упал хук.
// Коды SQLSTATE: 53300 — слишком много клиентов, 57P03 — сервер ещё
// запускается, 08* — обрыв соединения, 55006 — база занята (DROP при
// одновременном подключении). Сетевые коды Node — обрыв сокета.
const TRANSIENT_SQLSTATES = new Set(['53300', '57P01', '57P02', '57P03', '08000', '08001', '08003', '08004', '08006', '55006']);
const TRANSIENT_NET_CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN']);
const TRANSIENT_MESSAGE_RE = /too many clients|remaining connection slots|Connection terminated|timeout expired|system is (?:starting up|shutting down)/i;

function isTransientDbError(err) {
    if (!err) return false;
    if (TRANSIENT_SQLSTATES.has(err.code) || TRANSIENT_NET_CODES.has(err.code)) return true;
    return TRANSIENT_MESSAGE_RE.test(String(err.message));
}

const defaultSleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Повтор fn при временных сбоях БД: до attempts попыток, пауза растёт
// линейно (baseDelayMs, 2×, 3× …). Это не «ожидание события» в тесте, а
// ограниченный бэкофф инфраструктуры; нетранзиентная ошибка пробрасывается
// сразу.
async function withRetry(fn, { attempts = 5, baseDelayMs = 200, isTransient = isTransientDbError, sleep = defaultSleep } = {}) {
    for (let attempt = 1; ; attempt++) {
        try {
            return await fn();
        } catch (err) {
            if (attempt >= attempts || !isTransient(err)) throw err;
            await sleep(baseDelayMs * attempt);
        }
    }
}

function newDatabaseName() {
    return `nyxo_e2e_${Math.floor(Date.now() / 1000)}_${crypto.randomBytes(4).toString('hex')}`;
}

function databaseUrl(name) {
    const url = new URL(adminDatabaseUrl());
    url.pathname = `/${name}`;
    return url.toString();
}

function assertTestDatabaseName(name) {
    if (!DB_NAME_RE.test(name)) throw new Error(`не тестовая база: ${name}`);
}

async function withAdmin(fn) {
    const client = new Client({ connectionString: adminDatabaseUrl(), connectionTimeoutMillis: ADMIN_CONNECT_TIMEOUT_MS });
    // Обрыв простаивающего соединения не должен становиться необработанным
    // 'error' и ронять процесс набора.
    client.on('error', () => {});
    await client.connect();
    try {
        return await fn(client);
    } finally {
        await client.end().catch(() => {});
    }
}

async function createDatabase() {
    const name = newDatabaseName();
    let failedBefore = false;
    await withRetry(async () => {
        try {
            await withAdmin(client => client.query(`CREATE DATABASE "${name}" TEMPLATE template0 ENCODING 'UTF8'`));
        } catch (err) {
            // 42P04 после обрыва соединения: прошлая попытка на самом деле
            // успела создать базу, ответ потерялся — это успех.
            if (failedBefore && err.code === '42P04') return;
            failedBefore = true;
            throw err;
        }
    });
    return { name, url: databaseUrl(name) };
}

// WITH (FORCE) — закрыть соединения, которые остались от упавшего сервера.
async function dropDatabase(name) {
    assertTestDatabaseName(name);
    await withRetry(() => withAdmin(client => client.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`)));
}

async function dropStaleDatabases({ olderThanMs = STALE_AFTER_MS, now = Date.now() } = {}) {
    return withAdmin(async (client) => {
        const { rows } = await client.query(`SELECT datname FROM pg_database WHERE datname LIKE 'nyxo\\_e2e\\_%'`);
        const dropped = [];
        for (const { datname } of rows) {
            const match = DB_NAME_RE.exec(datname);
            if (!match || now - Number(match[1]) * 1000 < olderThanMs) continue;
            // Одна не удалившаяся база (её как раз удаляет другой прогон) не
            // должна ронять весь прогон: она останется до следующей уборки.
            try {
                await client.query(`DROP DATABASE IF EXISTS "${datname}" WITH (FORCE)`);
                dropped.push(datname);
            } catch (err) {
                if (!isTransientDbError(err)) throw err;
            }
        }
        return dropped;
    });
}

// Пул для прямых запросов теста к базе набора (проверки, перемотка времени).
function connectPool(url) {
    const pool = new Pool({ connectionString: url, max: 2 });
    pool.on('error', () => {});
    return pool;
}

// Для вариантов миграции, которым нужна пустая база внутри набора.
async function resetSchema(db) {
    await db.query('DROP SCHEMA public CASCADE');
    await db.query('CREATE SCHEMA public');
}

// Снимок схемы public: таблицы и колонки (тип, NULL, DEFAULT), индексы,
// ограничения, функции. Для проверки «повторный старт ничего не меняет».
async function schemaSnapshot(db) {
    const columns = await db.query(`
        SELECT table_name, column_name, data_type, is_nullable, column_default
        FROM information_schema.columns WHERE table_schema = 'public'
        ORDER BY table_name, column_name`);
    const indexes = await db.query(`
        SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'
        ORDER BY tablename, indexname`);
    const constraints = await db.query(`
        SELECT c.conrelid::regclass::text AS table_name, c.conname, pg_get_constraintdef(c.oid) AS def
        FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE n.nspname = 'public' ORDER BY 1, 2`);
    const functions = await db.query(`
        SELECT p.proname, md5(p.prosrc) AS src FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' ORDER BY 1`);
    return {
        columns: columns.rows,
        indexes: indexes.rows,
        constraints: constraints.rows,
        functions: functions.rows,
    };
}

module.exports = {
    DB_NAME_RE,
    STALE_AFTER_MS,
    isTransientDbError,
    withRetry,
    newDatabaseName,
    databaseUrl,
    withAdmin,
    createDatabase,
    dropDatabase,
    dropStaleDatabases,
    connectPool,
    resetSchema,
    schemaSnapshot,
};
