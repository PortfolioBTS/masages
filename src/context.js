'use strict';
// Общие объекты контекста сервера. Вынесено из server.js.
// createBase: теги автора сообщений, метрики процесса и флаг готовности (readiness).
// createKtContext: сервис журнала ключей и serverContext — замороженный контекст для lib/routes
// и lib/jobs (точки расширения R13).

// Журнал ключей (прозрачность ключей, docs/security/key-transparency.md): сервис с базой,
// маршруты /api/kt/*; задачи эпох регистрируются через JOB_MODULES (lib/jobs).
const { createKtService } = require('../lib/kt-service');
// Метрики Prometheus без id и IP; отдаёт их GET /metrics по токену (lib/routes/health.js).
const { createMetrics } = require('../lib/metrics');
const { logError } = require('../lib/log-error');

function createBase() {
    // Тег автора сообщения комнаты и псевдоним квоты (docs/security/sealed-sender.md):
    // ключи те же, что у message-crypto (MESSAGE_ENCRYPTION_KEY и …_PREVIOUS).
    const authorTags = require('../lib/author-tag').createAuthorTagsFromEnvironment();

    // Метрики процесса: счётчики событий и HTTP по шаблону маршрута (lib/metrics.js).
    const metrics = createMetrics();
    // Готовность для GET /readyz: порт открывается только после миграций, но флаг
    // явный — проба не должна зависеть от порядка запуска.
    const readiness = { migrated: false };

    return { authorTags, metrics, readiness };
}

function createKtContext(ctx) {
    const { IS_PRODUCTION, metrics, readiness, io, pool, dbGet, dbAll, dbRun, withTransaction } = ctx;

    // Журнал ключей: без KT_SIGNING_KEY сервис выключен (kt.enabled = false) — регистраций
    // и задачи эпох нет, kt в ответах null, /api/kt/* отвечает 503. Длина эпохи и поколения —
    // константы протокола; тестовые ручки KT_* действуют только при NODE_ENV=test.
    const kt = createKtService({ pool, withTransaction, onEpochClosed: metrics.ktEpochClosed });
    metrics.attachKt(() => kt.stats());

    // serverContext — общий контекст маршрутов и задач из lib/ (lib/jobs).
    const serverContext = Object.freeze({
        pool, dbGet, dbAll, dbRun, withTransaction, io, logError, isProduction: IS_PRODUCTION, kt,
        // Мониторинг и security.txt (lib/routes/health.js, lib/routes/well-known.js).
        metrics, readiness, env: process.env,
    });

    return { kt, serverContext };
}

module.exports = { createBase, createKtContext };
