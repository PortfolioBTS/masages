// Мелкие помощники приватности, которые использует server.js.

// Случайная задержка вокруг проверки пароля: вместе с bcrypt по фиктивному
// хэшу для несуществующего email размывает разницу во времени ответа, по
// которой можно было бы перебирать зарегистрированные адреса.
async function addRandomDelay(minMs = 10, maxMs = 50) {
    const delay = Math.random() * (maxMs - minMs) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
}

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
    addRandomDelay,
    sanitizeText,
    getPrivacyHeaders
};
