'use strict';
// Миграции схемы, которые выполняются ПОСЛЕ шагов initDatabase (server.js).
//
// Каждая миграция — отдельный файл в этой папке, lib/migrations/NNNN-<имя>.js:
//
//     module.exports = {
//         id: 'NNNN-<имя>',            // ровно имя файла без .js
//         async up({ pool, client, log, config }) { ... },
//     };
//
// Отдельные файлы вместо новых строк в initDatabase — чтобы параллельные
// задачи не правили одну и ту же функцию (конфликт слияния на каждом
// слиянии). Номера: волна N — диапазон N00–N99 (docs/dev/migrations.md).
//
// Порядок и повторы. Раннер находит файлы сам и при КАЖДОМ старте
// выполняет ВСЕ миграции по возрастанию номера, под блокировкой миграций
// (lib/advisory-locks.js). Поэтому каждая миграция обязана быть
// идемпотентной: проверить состояние схемы или данных и ничего не делать,
// если всё уже сделано. Пропускать «уже применённые» по номеру нельзя:
// задачи сливаются не по порядку номеров, и миграция 0105, слитая после
// 0110, иначе не выполнилась бы никогда. Миграция может выполниться и
// дважды за старт: при lock_timeout (55P03) всё повторяется с начала.
//
// ctx: pool — пул сервера (на время миграций с lock_timeout); client —
// соединение, которое держит блокировку миграций (тоже с lock_timeout),
// для транзакций: BEGIN/COMMIT/ROLLBACK миграция делает сама и не
// оставляет транзакцию открытой; log — console.log; config — настройки
// сервера (isProduction, uploadsDir, env).
//
// schema_meta — одна строка: schema_version (наибольший номер миграции,
// известный коду, который её записал) и updated_at (до минуты — точнее не
// нужно). Если версия в базе НОВЕЕ, чем знает этот код, сервер не
// стартует: старый код на новой схеме мог бы испортить данные.

const fs = require('fs');
const path = require('path');

const MIGRATION_FILE_RE = /^(\d{4})-([a-z0-9]+(?:-[a-z0-9]+)*)\.js$/;
const SCHEMA_TOO_NEW = 'NYXO_SCHEMA_TOO_NEW';

// Ошибки в файлах миграций — при старте, до первого соединения с базой.
function loadMigrations(dir = __dirname) {
    const where = (file) => `${path.basename(dir)}/${file}`;
    const files = fs.readdirSync(dir).filter(name => name.endsWith('.js') && name !== 'index.js');
    const byNumber = new Map();
    const migrations = [];
    for (const file of files) {
        const match = MIGRATION_FILE_RE.exec(file);
        if (!match) {
            throw new Error(`${where(file)}: имя миграции должно быть NNNN-имя.js (четыре цифры, затем латиница в нижнем регистре, цифры и дефисы)`);
        }
        const number = Number(match[1]);
        if (number === 0) throw new Error(`${where(file)}: номер 0000 занят — версия схемы 0 значит «миграций нет»`);
        if (byNumber.has(number)) throw new Error(`${where(file)}: номер ${match[1]} уже у ${byNumber.get(number)}`);
        byNumber.set(number, file);
        const id = file.slice(0, -'.js'.length);
        const mod = require(path.join(dir, file));
        if (!mod || mod.id !== id) throw new Error(`${where(file)}: экспорт id должен быть '${id}'`);
        if (typeof mod.up !== 'function') throw new Error(`${where(file)}: нет функции up(ctx)`);
        migrations.push({ number, id, up: mod.up });
    }
    return migrations.sort((a, b) => a.number - b.number);
}

async function readSchemaVersion(db) {
    const table = await db.query(`SELECT to_regclass('schema_meta') IS NOT NULL AS present`);
    if (!table.rows[0] || !table.rows[0].present) return 0;
    const meta = await db.query('SELECT schema_version FROM schema_meta LIMIT 1');
    return meta.rows[0] ? Number(meta.rows[0].schema_version) : 0;
}

function assertSchemaKnown(dbVersion, codeVersion) {
    if (dbVersion <= codeVersion) return;
    const err = new Error(
        `база обновлена более новой версией сервера: версия схемы ${dbVersion}, этот код знает только до ${codeVersion}. `
        + 'Старый код на новой схеме не запускается — разверните новую версию или восстановите базу из резервной копии'
    );
    err.code = SCHEMA_TOO_NEW;
    throw err;
}

async function writeSchemaVersion(db, version) {
    await db.query(`
        CREATE TABLE IF NOT EXISTS schema_meta (
            singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
            schema_version INTEGER NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
    `);
    // Строка меняется только вместе с версией: updated_at — когда схема
    // стала такой, а не время последнего старта.
    const result = await db.query(
        `INSERT INTO schema_meta (singleton, schema_version, updated_at)
         VALUES (TRUE, $1, date_trunc('minute', NOW()))
         ON CONFLICT (singleton) DO UPDATE
         SET schema_version = EXCLUDED.schema_version, updated_at = EXCLUDED.updated_at
         WHERE schema_meta.schema_version <> EXCLUDED.schema_version`,
        [version]
    );
    return result.rowCount > 0;
}

// Под блокировкой миграций: проверка версии → initialSteps (initDatabase) →
// все миграции по порядку → запись версии.
async function migrateSchema({ pool, client, migrations, initialSteps, log = console.log, config = {} }) {
    const codeVersion = migrations.length > 0 ? migrations[migrations.length - 1].number : 0;
    const dbVersion = await readSchemaVersion(client);
    assertSchemaKnown(dbVersion, codeVersion);
    if (initialSteps) await initialSteps();
    const ctx = Object.freeze({ pool, client, log, config });
    for (const migration of migrations) {
        await migration.up(ctx);
    }
    await writeSchemaVersion(client, codeVersion);
    if (codeVersion !== dbVersion) log(`[DB] Версия схемы: ${dbVersion} → ${codeVersion} (миграций в lib/migrations: ${migrations.length})`);
    return { dbVersion, codeVersion };
}

module.exports = {
    loadMigrations,
    migrateSchema,
    readSchemaVersion,
    writeSchemaVersion,
    assertSchemaKnown,
    SCHEMA_TOO_NEW,
    MIGRATION_FILE_RE,
};
