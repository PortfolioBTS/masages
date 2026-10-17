'use strict';
// Общие объекты контекста сервера. Вынесено из server.js.
// createBase: теги автора сообщений, метрики процесса и флаг готовности (readiness).

// Метрики Prometheus без id и IP; отдаёт их GET /metrics по токену (lib/routes/health.js).
const { createMetrics } = require('../lib/metrics');

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

module.exports = { createBase };
