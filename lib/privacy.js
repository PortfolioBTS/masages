// Мелкие помощники приватности, которые использует сервер (src/http/app.js, маршруты сообщений).

// Удаляет из открытого текста zero-width символы: невидимые метки из них
// позволяют "подписать" копию текста и потом узнать, чья именно утекла.
function sanitizeText(text) {
    if (!text || typeof text !== 'string') return text;
    return text.replace(/[​-‍﻿]/g, '');
}

// Заголовки, которые src/http/app.js ставит на каждый ответ.
function getPrivacyHeaders() {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        // Встроенный XSS-фильтр браузеров устарел и сам бывал источником
        // утечек (через него можно было выборочно "выключать" скрипты
        // страницы); OWASP рекомендует явно выключать его значением 0, а
        // защищаться CSP.
        'X-XSS-Protection': '0',
        // Ни полный URL, ни даже origin не уходят на сторонние ресурсы при
        // переходе по ссылке из чата.
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    };
}

// Strict-Transport-Security или null. HSTS — только для настоящего https в
// production и не для onion: по http браузер заголовок игнорирует, а в
// разработке он «залипал» бы на localhost; onion-сервис отдаётся по http (TLS
// там даёт сам Tor).
//
// preload (HSTS_PRELOAD=yes) — осознанный выбор владельца домена: два года,
// includeSubDomains и preload. Попадание в список preload браузеров нельзя
// быстро отменить (удаление занимает месяцы), а includeSubDomains заставит
// ВСЕ поддомены работать по https. Поэтому без флага — прежний год без preload.
function getHstsHeader({ production, secure, onion, preload }) {
    if (!production || !secure || onion) return null;
    return preload
        ? 'max-age=63072000; includeSubDomains; preload'
        : 'max-age=31536000; includeSubDomains';
}

// Middleware с HSTS для src/http/app.js: req.secure — фактический протокол (с
// учётом X-Forwarded-Proto от доверенного прокси), req.isOnion ставит
// onionMiddleware.
function createHstsMiddleware({ production, preload }) {
    return function hstsMiddleware(req, res, next) {
        const value = getHstsHeader({ production, secure: req.secure, onion: req.isOnion, preload });
        if (value) res.set('Strict-Transport-Security', value);
        next();
    };
}

module.exports = {
    sanitizeText,
    getPrivacyHeaders,
    getHstsHeader,
    createHstsMiddleware
};
