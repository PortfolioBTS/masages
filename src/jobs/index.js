'use strict';
// Фоновые задачи процесса: реестр lib/jobs, пул блокировок и задачи самого сервера (чистка
// просроченных анонимов и заявок, продление открытых сокетов, временные файлы). Задачи lib-модулей
// добавляет registerJobModules. Запускает их src/lifecycle.js после открытия порта.
// Вынесено из server.js.

const { Pool } = require('pg');
const { cleanupStaleTempFiles } = require('../../lib/metadata-stripper');
const { ANON_SOCKET_ACTIVITY_INTERVAL_MS } = require('../../lib/anon-lifetime');
// Сессии в Postgres с огрублением времени, их продление и активность
// анонимов (контракт этапа 1, §4).
const { extendTabSessions } = require('../../lib/session-store');
// Несколько экземпляров сервера на одной базе (миграции и фоновые задачи
// под advisory-блокировками) и запись ошибок в лог без id из detail.
const { createRunExclusive } = require('../../lib/advisory-locks');
const { logError } = require('../../lib/log-error');
// Реестр фоновых задач (под runExclusive) и тестовая ручка NYXO_TEST_MAINTENANCE_MS.
const { createJobScheduler, registerJobModules } = require('../../lib/jobs');
// Огрубление времени сообщений и файлов (раздел 11 контракта).
const { orphanAgeThresholdMs } = require('../../lib/coarse-time');

// Тестовые ручки сквозных тестов (NYXO_TEST_*, docs/dev/testing.md):
// действуют ТОЛЬКО при NODE_ENV=test, в production env-check считает их
// ошибкой. Целое число мс > 0, иначе null.
function testKnobMs(name) {
    if (process.env.NODE_ENV !== 'test') return null;
    const value = Number(process.env[name]);
    return Number.isInteger(value) && value > 0 ? value : null;
}

function createJobs(ctx) {
    const {
        UPLOADS_DIR, metrics, userSocketCount, DB_POOL_CONFIG, dbRun, anonActivity, purgeExpiredJoinRequests,
        purgeExpiredAnonymousUsers, serverContext,
    } = ctx;

    // ---- Фоновые задачи (lib/jobs/index.js) ----
    //
    // По умолчанию задача идёт под runExclusive (lib/advisory-locks.js): в
    // каждый момент её выполняет один экземпляр сервера на базу, у остальных
    // запуск пропускается. Клиенты блокировок — из отдельного маленького пула:
    // блокировка держит соединение всю задачу, а в основном пуле (в тестах
    // PG_POOL_MAX=3) они отнимали бы соединения у самих задач.
    const jobLockPool = new Pool({ ...DB_POOL_CONFIG, max: 4 });
    jobLockPool.on('error', (err) => logError('[DB] Ошибка простаивающего соединения блокировок', err));

    const jobs = createJobScheduler({
        runExclusive: createRunExclusive(jobLockPool),
        // Задачи с maintenance: true — каждые N мс вместо минут.
        maintenanceMs: testKnobMs('NYXO_TEST_MAINTENANCE_MS'),
        onRun: metrics.jobRan,
    });
    // Анонимы проверяются каждые 5 минут: самый короткий срок — 30 минут
    // без активности, и опоздание с удалением не должно быть сравнимо с ним.
    jobs.register({
        name: 'purgeExpiredAnonymousUsers', run: purgeExpiredAnonymousUsers,
        firstDelayMs: 60 * 1000, intervalMs: 5 * 60 * 1000, maintenance: true, testTick: true,
    });
    // Открытые сокеты ЭТОГО процесса (у каждого экземпляра свои, поэтому без
    // блокировки), раз в 2,5 минуты: активность их пользователей одним UPDATE и
    // строки tab-сессий (кука без срока) — ещё 24 часа: HTTP-ответа, который
    // пересохранил бы строку, может не быть часами, пока вкладка открыта.
    jobs.register({
        name: 'touchOnlineSockets',
        run: async () => {
            const online = userSocketCount.keys();
            await anonActivity.touch(online);
            await extendTabSessions(dbRun, online);
        },
        intervalMs: ANON_SOCKET_ACTIVITY_INTERVAL_MS, exclusive: false, maintenance: true,
    });
    jobs.register({
        name: 'purgeExpiredJoinRequests', run: purgeExpiredJoinRequests,
        firstDelayMs: 90 * 1000, intervalMs: 60 * 60 * 1000, maintenance: true,
    });
    // Брошенные временные файлы обработки вложений — в папке этого процесса.
    // Порог возраста — не меньше двух часов: mtime файлов округлён вниз до часа
    // (coarsenFileTimes), и свежий файл выглядит старше настоящего возраста.
    jobs.register({
        name: 'cleanupStaleTempFiles', run: () => cleanupStaleTempFiles(UPLOADS_DIR, orphanAgeThresholdMs(60 * 60 * 1000)),
        intervalMs: 60 * 60 * 1000, exclusive: false,
    });
    // Задачи lib-модулей (JOB_MODULES в lib/jobs/index.js).
    registerJobModules(jobs, serverContext);

    return { jobs };
}

module.exports = { createJobs };
