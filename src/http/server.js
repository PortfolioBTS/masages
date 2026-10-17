'use strict';
// HTTP-сервер вокруг приложения Express: в production — http (TLS заканчивается на прокси),
// при разработке — https, если рядом лежат сертификаты localhost+1*.pem. Вынесено из server.js.

const http = require('http');
const https = require('https');
const fs = require('fs');

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

    return { server };
}

module.exports = { createHttpServer };
