'use strict';
// Инициализация базы при старте: миграции под advisory-блокировкой (lib/advisory-locks.js) и
// файлы lib/migrations/. Порт открывается только после неё (src/lifecycle.js). Вынесено из server.js.

const { Pool } = require('pg');
// Несколько экземпляров сервера на одной базе (миграции и фоновые задачи
// под advisory-блокировками) и запись ошибок в лог без id из detail.
const { runMigrationsExclusive } = require('../../lib/advisory-locks');
const { loadMigrations, migrateSchema } = require('../../lib/migrations');

function createMigrations(ctx) {
    const { IS_PRODUCTION, UPLOADS_DIR, DB_POOL_CONFIG, pool, initDatabase } = ctx;

    // Миграции — под advisory-блокировкой (lib/advisory-locks.js): два
    // одновременно стартующих экземпляра (реплики, деплой без простоя) раньше
    // выполняли DDL наперегонки, и один из них падал. На время миграций у их
    // запросов короткий lock_timeout: DDL, не дождавшийся блокировки таблицы
    // (её держат запросы работающего экземпляра), не стоит в очереди,
    // задерживая за собой все запросы к этой таблице, а падает, и миграции
    // повторяются целиком (они идемпотентны). Не помогли и повторы — сервер
    // выходит с ошибкой, хостинг его перезапускает.
    //
    // Новые изменения схемы — не в initDatabase, а файлами lib/migrations/
    // (см. lib/migrations/index.js): они выполняются после initDatabase, а
    // версия схемы в schema_meta не даёт старому коду стартовать на новой схеме.
    async function initDatabaseExclusive() {
        // DUMP_CA=true — служебный режим (TLS к базе ещё не настроен): он
        // завершает процесс в начале initDatabase и не должен ждать соединения.
        if (process.env.DUMP_CA === 'true') return initDatabase();
        // Файлы миграций читаются до первого соединения: ошибка в них — сразу.
        const migrations = loadMigrations();
        return runMigrationsExclusive(pool, ({ client }) => migrateSchema({
            pool,
            client,
            migrations,
            initialSteps: initDatabase,
            config: Object.freeze({ isProduction: IS_PRODUCTION, uploadsDir: UPLOADS_DIR, env: process.env }),
        }), {
            createMigrationPool: (options) => new Pool({ ...DB_POOL_CONFIG, ...options }),
        });
    }

    return { initDatabaseExclusive };
}

module.exports = { createMigrations };
