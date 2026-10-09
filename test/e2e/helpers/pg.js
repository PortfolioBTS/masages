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
    const client = new Client({ connectionString: adminDatabaseUrl() });
    await client.connect();
    try {
        return await fn(client);
    } finally {
        await client.end();
    }
}

async function createDatabase() {
    const name = newDatabaseName();
    await withAdmin(client => client.query(`CREATE DATABASE "${name}" TEMPLATE template0 ENCODING 'UTF8'`));
    return { name, url: databaseUrl(name) };
}

// WITH (FORCE) — закрыть соединения, которые остались от упавшего сервера.
async function dropDatabase(name) {
    assertTestDatabaseName(name);
    await withAdmin(client => client.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`));
}

async function dropStaleDatabases({ olderThanMs = STALE_AFTER_MS, now = Date.now() } = {}) {
    return withAdmin(async (client) => {
        const { rows } = await client.query(`SELECT datname FROM pg_database WHERE datname LIKE 'nyxo\\_e2e\\_%'`);
        const dropped = [];
        for (const { datname } of rows) {
            const match = DB_NAME_RE.exec(datname);
            if (!match || now - Number(match[1]) * 1000 < olderThanMs) continue;
            await client.query(`DROP DATABASE IF EXISTS "${datname}" WITH (FORCE)`);
            dropped.push(datname);
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
