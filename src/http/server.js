'use strict';
// HTTP-сервер вокруг приложения Express: в production — http (TLS заканчивается на прокси),
// при разработке — https, если рядом лежат сертификаты localhost+1*.pem. Вынесено из server.js.

const http = require('http');
const https = require('https');
const fs = require('fs');

// Таймауты заданы явно (W7 R1 п.12), а не берутся из умолчаний Node (5 с, 60 с):
//   * keepAliveTimeout больше простоя соединения у прокси (балансировщики держат его около минуты):
//     если приложение закроет соединение раньше, прокси пошлёт по нему запрос в уже закрытый сокет и
//     отдаст клиенту 502;
//   * headersTimeout больше keepAliveTimeout (требование Node: иначе простаивающее соединение может
//     закрыться раньше времени) и ограничивает медленную отправку заголовков;
//   * requestTimeout - на весь запрос целиком: загрузка вложения до 50 МБ с телефона по медленной сети.
const KEEP_ALIVE_TIMEOUT_MS = 65 * 1000;
const HEADERS_TIMEOUT_MS = 66 * 1000;
const REQUEST_TIMEOUT_MS = 5 * 60 * 1000;

function createHttpServer(ctx) {
    const { app } = ctx;

    let server;
    if (process.env.NODE_ENV === 'production') {
        server = http.createServer(app);
    } else {
        const sslOptions = {
            key: fs.existsSync('./localhost+1-key.pem') ? fs.readFileSync('./localhost+1-key.pem') : null,
            cert: fs.existsSync('./localhost+1.pem') ? fs.readFileSync('./localhost+1.pem') : null,
        };
        if (sslOptions.key && sslOptions.cert) {
            server = https.createServer(sslOptions, app);
        } else {
            console.warn('SSL сертификаты не найдены. Запуск HTTP сервера.');
            server = http.createServer(app);
        }
    }

    server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
    server.headersTimeout = HEADERS_TIMEOUT_MS;
    server.requestTimeout = REQUEST_TIMEOUT_MS;

    return { server };
}

module.exports = { createHttpServer, HTTP_TIMEOUTS: { KEEP_ALIVE_TIMEOUT_MS, HEADERS_TIMEOUT_MS, REQUEST_TIMEOUT_MS } };
