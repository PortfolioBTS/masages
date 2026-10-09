'use strict';
// Advisory-блокировки Postgres: несколько экземпляров сервера на одной базе
// (реплики; деплой, когда новый экземпляр стартует рядом с работающим).
//
// * runMigrationsExclusive — миграции при старте выполняет только один
//   экземпляр за раз. Раньше два одновременно стартующих выполняли
//   CREATE TABLE / CREATE INDEX наперегонки, и второй падал на конфликте
//   системного каталога. Теперь второй ждёт первого и проходит миграции
//   вхолостую — они идемпотентны.
// * createRunExclusive — фоновая задача (чистка просроченного) в каждый
//   момент выполняется одним экземпляром; если её уже выполняет другой,
//   запуск просто пропускается.
//
// Блокировки сессионные: Postgres снимает их сам, когда соединение
// закрывается, — упавший экземпляр не оставит базу запертой.

const crypto = require('crypto');
const { logError } = require('./log-error');

// Ключ блокировки по имени: первые 8 байт SHA-256 как знаковое 64-битное
// число (тип bigint в Postgres). Префикс 'nyxo:' — чтобы не совпасть с
// блокировками других приложений на той же базе.
function advisoryLockKey(name) {
    return crypto.createHash('sha256').update(`nyxo:${name}`, 'utf8').digest().readBigInt64BE(0).toString();
}

const MIGRATION_LOCK_KEY = advisoryLockKey('migrations');
// Сколько DDL ждёт блокировку таблицы и сколько раз миграции повторяются
// целиком, если не дождался. Короткое ожидание с повторами, а не одно
// длинное и выход: при деплое старый экземпляр обычно уже остановлен, и
// перезапуск сервера по ошибке — это простой, а повтор через пару секунд
// почти всегда проходит.
const DEFAULT_MIGRATION_LOCK_TIMEOUT_MS = 2500;
const DEFAULT_MIGRATION_ATTEMPTS = 5;
// SQLSTATE lock_not_available: запрос не дождался блокировки за lock_timeout.
const LOCK_NOT_AVAILABLE = '55P03';

const TRY_LOCK_SQL = 'SELECT pg_try_advisory_lock($1::bigint) AS locked';
const LOCK_SQL = 'SELECT pg_advisory_lock($1::bigint)';
const UNLOCK_SQL = 'SELECT pg_advisory_unlock($1::bigint)';

// Методы пула, которые на время миграций уходят во временный пул.
const ROUTED_METHODS = ['query', 'connect'];

// migrate({ pool, client, attempt }) выполняется под блокировкой
// MIGRATION_LOCK_KEY. Её держит client — отдельный клиент основного пула;
// сама блокировка ждётся без ограничения: миграции другого экземпляра
// могут идти долго, а если он упадёт, Postgres снимет её сам.
//
// У всех запросов миграций — lock_timeout. Без него ALTER TABLE / CREATE
// INDEX на работающей базе ждал бы блокировки таблицы, пока идут запросы
// другого экземпляра, а все новые запросы к таблице стояли бы в очереди за
// ним. С lock_timeout такой запрос падает с 55P03, и migrate() повторяется
// целиком (до attempts раз): все шаги миграций идемпотентны.
//
// Запросы миграций идут через pool.query / pool.connect (так написан
// initDatabase), поэтому на время migrate() эти два метода пула
// направляются во временный пул, у каждого соединения которого стоит
// lock_timeout; после миграций он закрывается, и обычным запросам
// lock_timeout не достаётся. У client lock_timeout ставится после взятия
// блокировки и сбрасывается перед возвратом в пул.
//
// createMigrationPool(options) — фабрика пула с теми же параметрами
// подключения, что у основного (options: max, onConnect).
async function runMigrationsExclusive(pool, migrate, {
    createMigrationPool,
    lockTimeoutMs = DEFAULT_MIGRATION_LOCK_TIMEOUT_MS,
    attempts = DEFAULT_MIGRATION_ATTEMPTS,
    log = console.log,
    report = logError,
} = {}) {
    if (typeof createMigrationPool !== 'function') throw new TypeError('createMigrationPool обязателен');
    const timeoutMs = Math.trunc(Number(lockTimeoutMs));
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new RangeError('lockTimeoutMs должен быть положительным числом');
    const maxAttempts = Math.max(1, Math.trunc(Number(attempts)) || 1);
    const setLockTimeout = `SET lock_timeout = ${timeoutMs}`;

    const client = await pool.connect();
    let locked = false;
    let timeoutSet = false;
    let brokenClient = null;
    let migrationPool = null;
    const saved = [];
    try {
        try {
            const tried = await client.query(TRY_LOCK_SQL, [MIGRATION_LOCK_KEY]);
            if (!(tried.rows[0] && tried.rows[0].locked === true)) {
                log('[DB] Схему сейчас обновляет другой экземпляр сервера — ждём окончания его миграций');
                await client.query(LOCK_SQL, [MIGRATION_LOCK_KEY]);
            }
            locked = true;
            await client.query(setLockTimeout);
            timeoutSet = true;
        } catch (err) {
            // Ошибка на клиенте блокировки — состояние его сессии неизвестно:
            // соединение закрывается, а не возвращается в пул.
            brokenClient = err;
            throw err;
        }

        migrationPool = createMigrationPool({ max: 2, onConnect: (c) => c.query(setLockTimeout) });
        if (typeof migrationPool.on === 'function') {
            migrationPool.on('error', (err) => report('[DB] Ошибка простаивающего соединения миграций', err));
        }
        for (const method of ROUTED_METHODS) {
            saved.push([method, Object.getOwnPropertyDescriptor(pool, method)]);
            pool[method] = migrationPool[method].bind(migrationPool);
        }

        for (let attempt = 1; ; attempt++) {
            try {
                return await migrate({ pool, client, attempt });
            } catch (err) {
                if (!err || err.code !== LOCK_NOT_AVAILABLE || attempt >= maxAttempts) throw err;
                log(`[DB] Миграция не дождалась блокировки таблицы за ${timeoutMs} мс (попытка ${attempt} из ${maxAttempts}) — повтор`);
            }
        }
    } finally {
        for (const [method, descriptor] of saved) {
            if (descriptor) Object.defineProperty(pool, method, descriptor);
            else delete pool[method];
        }
        if (migrationPool) {
            await migrationPool.end().catch((err) => report('[DB] Не удалось закрыть пул миграций', err));
        }
        if (!brokenClient && (locked || timeoutSet)) {
            try {
                if (timeoutSet) await client.query('RESET lock_timeout');
                if (locked) await client.query(UNLOCK_SQL, [MIGRATION_LOCK_KEY]);
            } catch (err) {
                // Не снятая блокировка (или lock_timeout) остались бы у
                // соединения в пуле навсегда — закрытие соединения снимает их.
                brokenClient = err;
                report('[DB] Не удалось снять блокировку миграций', err);
            }
        }
        client.release(brokenClient || undefined);
    }
}

// Возвращает runExclusive(jobName, fn) → true, если fn выполнилась
// полностью; false — если запуск пропущен (задачу выполняет другой
// экземпляр или прошлый запуск в этом же процессе ещё не закончился) или fn
// упала (ошибка уже в логе, без деталей — logError).
//
// Блокировка держится на отдельном соединении всё время задачи, а запросы
// самой задачи идут через основной пул. Поэтому lockPool должен быть
// отдельным маленьким пулом: из основного (в тестах PG_POOL_MAX=3) клиенты
// блокировок нескольких задач заняли бы все соединения, и сами задачи ждали
// бы свободного.
function createRunExclusive(lockPool, { report = logError } = {}) {
    return async function runExclusive(jobName, fn) {
        const key = advisoryLockKey(`job:${jobName}`);
        let client;
        try {
            client = await lockPool.connect();
        } catch (err) {
            report(`[Jobs] ${jobName}: нет соединения для блокировки`, err);
            return false;
        }
        let locked = false;
        let broken = null;
        try {
            try {
                const result = await client.query(TRY_LOCK_SQL, [key]);
                locked = Boolean(result.rows[0] && result.rows[0].locked === true);
            } catch (err) {
                broken = err;
                report(`[Jobs] ${jobName}: не удалось взять блокировку`, err);
                return false;
            }
            if (!locked) return false;
            try {
                await fn();
                return true;
            } catch (err) {
                report(`[Jobs] ${jobName}`, err);
                return false;
            }
        } finally {
            if (locked) {
                try {
                    await client.query(UNLOCK_SQL, [key]);
                } catch (err) {
                    broken = err;
                    report(`[Jobs] ${jobName}: не удалось снять блокировку`, err);
                }
            }
            // С ошибкой соединение закрывается, а не возвращается в пул:
            // вместе с ним Postgres снимает и блокировку.
            client.release(broken || undefined);
        }
    };
}

module.exports = {
    advisoryLockKey,
    runMigrationsExclusive,
    createRunExclusive,
    MIGRATION_LOCK_KEY,
    DEFAULT_MIGRATION_LOCK_TIMEOUT_MS,
    DEFAULT_MIGRATION_ATTEMPTS,
    LOCK_NOT_AVAILABLE,
};
