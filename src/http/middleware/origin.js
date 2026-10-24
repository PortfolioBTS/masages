'use strict';
// Политика источника запросов: разрешённые «чужие» Origin (ALLOWED_ORIGINS) и isTrustedOrigin,
// которой пользуются проверка небезопасных методов и рукопожатие socket.io.
// Вынесено из server.js.

const { parseAllowedOrigins, isRequestOriginAllowed } = require('../../../lib/security-utils');
// Onion-сервис (контейнер tor-service/)
const { isOnionHost } = require('../../../lib/tor-support');
// Доверенные прокси (TRUST_PROXY): X-Forwarded-Host и X-Forwarded-Proto принимаются только от них.
const { resolveTrustProxy, proxyHeaderValue } = require('../../../lib/trust-proxy');

function createOrigin() {
    // Разрешённые "чужие" источники (свои домены-зеркала). Свой хост и
    // onion-адрес разрешены и без этого списка.
    const ALLOWED_ORIGINS = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
    if (ALLOWED_ORIGINS.invalid.length > 0) {
        console.warn('[Origin] ALLOWED_ORIGINS: пропущены некорректные записи:', ALLOWED_ORIGINS.invalid.join(', '));
    }
    const trustProxyHops = resolveTrustProxy(process.env);

    // Протокол, которым запрос пришёл к приложению: TLS на самом сокете (разработка с mkcert) или
    // X-Forwarded-Proto от доверенного прокси (Railway завершает TLS у себя). Неизвестен - undefined:
    // схема Origin тогда не сверяется (простая разработка по http без прокси).
    function requestProtocol(req) {
        if (req && req.socket && req.socket.encrypted) return 'https';
        const forwarded = proxyHeaderValue(req && req.headers && req.headers['x-forwarded-proto'], trustProxyHops);
        const proto = forwarded ? forwarded.toLowerCase() : null;
        return proto === 'http' || proto === 'https' ? proto : undefined;
    }

    // Запрос пришёл со страницы самого мессенджера (см. isRequestOriginAllowed). req нужен для протокола;
    // без него (юнит-тесты) схема не сверяется. X-Forwarded-Host учитывается только при доверенном прокси,
    // и берётся значение, добавленное им (последнее в списке), а не присланное клиентом (R1 п.10).
    function isTrustedOrigin(headers, req) {
        return isRequestOriginAllowed({
            origin: headers.origin,
            host: headers.host,
            forwardedHost: proxyHeaderValue(headers['x-forwarded-host'], trustProxyHops),
            secFetchSite: headers['sec-fetch-site'],
            allowed: ALLOWED_ORIGINS,
            isOnionHost,
            protocol: req ? requestProtocol(req) : undefined,
        });
    }

    return { isTrustedOrigin, trustProxyHops };
}

module.exports = { createOrigin };
