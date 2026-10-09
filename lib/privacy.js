// Мелкие помощники приватности, которые использует server.js.

// Удаляет из открытого текста zero-width символы: невидимые метки из них
// позволяют "подписать" копию текста и потом узнать, чья именно утекла.
function sanitizeText(text) {
    if (!text || typeof text !== 'string') return text;
    return text.replace(/[​-‍﻿]/g, '');
}

// Заголовки, которые server.js ставит на каждый ответ.
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

module.exports = {
    sanitizeText,
    getPrivacyHeaders
};
