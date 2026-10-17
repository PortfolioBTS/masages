'use strict';
// Политика источника запросов: разрешённые «чужие» Origin (ALLOWED_ORIGINS) и isTrustedOrigin,
// которой пользуются проверка небезопасных методов и рукопожатие socket.io.
// Вынесено из server.js.

const { parseAllowedOrigins, isRequestOriginAllowed } = require('../../../lib/security-utils');
// Onion-сервис (контейнер tor-service/)
const { isOnionHost } = require('../../../lib/tor-support');

function createOrigin() {
    // Разрешённые "чужие" источники (свои домены-зеркала). Свой хост и
    // onion-адрес разрешены и без этого списка.
    const ALLOWED_ORIGINS = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
    if (ALLOWED_ORIGINS.invalid.length > 0) {
        console.warn('[Origin] ALLOWED_ORIGINS: пропущены некорректные записи:', ALLOWED_ORIGINS.invalid.join(', '));
    }

    // Запрос пришёл со страницы самого мессенджера (см. isRequestOriginAllowed).
    function isTrustedOrigin(headers) {
        return isRequestOriginAllowed({
            origin: headers.origin,
            host: headers.host,
            forwardedHost: headers['x-forwarded-host'],
            secFetchSite: headers['sec-fetch-site'],
            allowed: ALLOWED_ORIGINS,
            isOnionHost,
        });
    }

    return { isTrustedOrigin };
}

module.exports = { createOrigin };
