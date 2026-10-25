'use strict';
// Токен-бакет: до `capacity` событий разом (всплеск) и `refillPerSecond` в секунду
// в среднем. take() — взять одно событие; false - лимит исчерпан.
// Нужен сокетам (src/realtime/socket-handlers.js): сервер от клиента событий почти не
// ждёт, а поток пустых событий без ограничителя - бесплатная нагрузка на процесс.

function createTokenBucket({ capacity, refillPerSecond, now = Date.now }) {
    let tokens = capacity;
    let last = now();
    return {
        take() {
            const t = now();
            tokens = Math.min(capacity, tokens + ((t - last) / 1000) * refillPerSecond);
            last = t;
            if (tokens < 1) return false;
            tokens -= 1;
            return true;
        },
    };
}

module.exports = { createTokenBucket };
