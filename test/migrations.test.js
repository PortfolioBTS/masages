'use strict';
// Раннер миграций lib/migrations/ и версия схемы в schema_meta — против
// временных папок с файлами миграций и поддельного клиента БД. На
// настоящем Postgres (повторный старт, отказ при версии новее кода) — в
// test/e2e/smoke.e2e.test.js.
// Запуск: node test/migrations.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
    loadMigrations,
    migrateSchema,
    assertSchemaKnown,
    SCHEMA_TOO_NEW,
} = require('../lib/migrations');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const tempDirs = [];
// Папка с файлами { имя: содержимое }; trace — глобальный массив, куда
// миграции пишут, что выполнились.
function migrationsDir(files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-migrations-'));
    tempDirs.push(dir);
    for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
    return dir;
}
const migrationSource = (id) => `module.exports = { id: '${id}', async up(ctx) { global.__nyxoMigrationTrace.push(['${id}', Object.keys(ctx).sort().join(',')]); } };\n`;

// Поддельный клиент: version — содержимое schema_meta (null — таблицы нет).
function makeFakeDb(version) {
    const queries = [];
    return {
        queries,
        state: { version },
        async query(sql, params) {
            queries.push(sql.replace(/\s+/g, ' ').trim());
            if (sql.includes('to_regclass')) return { rows: [{ present: this.state.version !== null }] };
            if (sql.startsWith('SELECT schema_version')) return { rows: this.state.version === null ? [] : [{ schema_version: this.state.version }] };
            if (sql.includes('INSERT INTO schema_meta')) {
                const changed = this.state.version !== params[0];
                this.state.version = params[0];
                return { rowCount: changed ? 1 : 0, rows: [] };
            }
            return { rows: [], rowCount: 0 };
        },
    };
}

async function main() {
    console.log('Migrations tests\n');
    global.__nyxoMigrationTrace = [];

    await test('папка репозитория lib/migrations загружается (index.js — не миграция)', () => {
        const list = loadMigrations();
        assert.ok(Array.isArray(list));
        for (const m of list) assert.match(m.id, /^\d{4}-[a-z0-9-]+$/);
    });

    await test('файлы находятся сами и сортируются по номеру; не-.js и index.js пропускаются', () => {
        const dir = migrationsDir({
            '0201-second.js': migrationSource('0201-second'),
            '0105-first.js': migrationSource('0105-first'),
            'README.md': '# не миграция\n',
            'index.js': 'throw new Error("index.js не должен загружаться как миграция");\n',
        });
        const list = loadMigrations(dir);
        assert.deepStrictEqual(list.map(m => [m.number, m.id]), [[105, '0105-first'], [201, '0201-second']]);
    });

    await test('ошибки в файлах: имя, повтор номера, номер 0000, id не совпадает, нет up', () => {
        const cases = [
            [{ '105-short.js': migrationSource('105-short') }, /NNNN-имя\.js/],
            [{ '0105-Upper.js': migrationSource('0105-Upper') }, /NNNN-имя\.js/],
            [{ '0105-a.js': migrationSource('0105-a'), '0105-b.js': migrationSource('0105-b') }, /уже у/],
            [{ '0000-zero.js': migrationSource('0000-zero') }, /0000/],
            [{ '0106-name.js': migrationSource('0106-other') }, /id должен быть '0106-name'/],
            [{ '0107-noup.js': "module.exports = { id: '0107-noup' };\n" }, /нет функции up/],
        ];
        for (const [files, re] of cases) {
            assert.throws(() => loadMigrations(migrationsDir(files)), re, JSON.stringify(Object.keys(files)));
        }
    });

    await test('пустая база: initDatabase, затем все миграции по порядку с ctx, затем версия', async () => {
        global.__nyxoMigrationTrace = [];
        const migrations = loadMigrations(migrationsDir({
            '0102-b.js': migrationSource('0102-b'),
            '0101-a.js': migrationSource('0101-a'),
        }));
        const db = makeFakeDb(null);
        const order = [];
        const logs = [];
        const result = await migrateSchema({
            pool: { name: 'pool' }, client: db, migrations, config: { isProduction: false },
            initialSteps: async () => { order.push('initDatabase'); global.__nyxoMigrationTrace.push(['initDatabase']); },
            log: (line) => logs.push(line),
        });
        assert.deepStrictEqual(result, { dbVersion: 0, codeVersion: 102 });
        assert.deepStrictEqual(global.__nyxoMigrationTrace, [
            ['initDatabase'],
            ['0101-a', 'client,config,log,pool'],
            ['0102-b', 'client,config,log,pool'],
        ]);
        assert.strictEqual(db.state.version, 102);
        assert.ok(db.queries.some(q => q.startsWith('CREATE TABLE IF NOT EXISTS schema_meta')));
        assert.ok(db.queries.some(q => q.includes("date_trunc('minute', NOW())")));
        assert.ok(logs.some(l => /0 → 102/.test(l)));
    });

    await test('та же версия: миграции всё равно выполняются (идемпотентны), строка не меняется, лог молчит', async () => {
        global.__nyxoMigrationTrace = [];
        const migrations = loadMigrations(migrationsDir({ '0101-a.js': migrationSource('0101-a') }));
        const db = makeFakeDb(101);
        const logs = [];
        await migrateSchema({ pool: {}, client: db, migrations, log: (l) => logs.push(l) });
        assert.deepStrictEqual(global.__nyxoMigrationTrace.map(t => t[0]), ['0101-a']);
        assert.strictEqual(db.state.version, 101);
        assert.deepStrictEqual(logs, []);
    });

    await test('версия в базе новее кода — отказ ДО initDatabase и миграций, понятная ошибка', async () => {
        global.__nyxoMigrationTrace = [];
        const migrations = loadMigrations(migrationsDir({ '0101-a.js': migrationSource('0101-a') }));
        const db = makeFakeDb(250);
        let initCalled = false;
        await assert.rejects(
            migrateSchema({ pool: {}, client: db, migrations, initialSteps: async () => { initCalled = true; }, log: () => {} }),
            (err) => err.code === SCHEMA_TOO_NEW && /250/.test(err.message) && /101/.test(err.message)
        );
        assert.strictEqual(initCalled, false);
        assert.deepStrictEqual(global.__nyxoMigrationTrace, []);
        assert.strictEqual(db.state.version, 250);
    });

    await test('без миграций версия кода — 0; база с версией 0 подходит, с 1 — нет', () => {
        assert.doesNotThrow(() => assertSchemaKnown(0, 0));
        assert.throws(() => assertSchemaKnown(1, 0), (err) => err.code === SCHEMA_TOO_NEW);
    });

    await test('упавшая миграция останавливает раннер, версия не записывается', async () => {
        const dir = migrationsDir({
            '0101-ok.js': migrationSource('0101-ok'),
            '0102-boom.js': "module.exports = { id: '0102-boom', async up() { throw new Error('сбой миграции'); } };\n",
            '0103-never.js': migrationSource('0103-never'),
        });
        global.__nyxoMigrationTrace = [];
        const db = makeFakeDb(null);
        await assert.rejects(migrateSchema({ pool: {}, client: db, migrations: loadMigrations(dir), log: () => {} }), /сбой миграции/);
        assert.deepStrictEqual(global.__nyxoMigrationTrace.map(t => t[0]), ['0101-ok']);
        assert.strictEqual(db.state.version, null);
    });

    for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
