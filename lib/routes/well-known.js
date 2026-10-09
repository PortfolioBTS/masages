'use strict';
// /.well-known/security.txt и его короткий адрес /security.txt (8.4).
// Регистрируется до sessionMiddleware (PRE_SESSION_ROUTES): сессия и куки
// файлу не нужны, поэтому его можно отдавать публичному кэшу. Текст и
// настройки — в lib/security-txt.js.

const { ONION_ADDRESS, ONION_PORT } = require('../tor-support');
const { resolveSecurityTxtConfig, buildSecurityTxt, WELL_KNOWN_PATH } = require('../security-txt');

const CACHE_CONTROL = 'public, max-age=86400';

function register(app, ctx) {
    const onion = ONION_ADDRESS && ONION_PORT ? { address: ONION_ADDRESS, port: ONION_PORT } : null;
    const config = resolveSecurityTxtConfig((ctx && ctx.env) || {}, { onion });

    app.get(WELL_KNOWN_PATH, (req, res) => {
        // Глобальные заголовки закрывают кэш (no-store) — здесь он нужен;
        // файл публичный и одинаков для всех. CORP/CORS открыты, чтобы его
        // могли читать сторонние инструменты и страницы исследователей.
        res.set('Cache-Control', CACHE_CONTROL);
        res.removeHeader('Pragma');
        res.removeHeader('Expires');
        res.removeHeader('Surrogate-Control');
        res.set('Cross-Origin-Resource-Policy', 'cross-origin');
        res.set('Access-Control-Allow-Origin', '*');
        res.type('text/plain; charset=utf-8').send(buildSecurityTxt(config));
    });

    // Относительный Location: адрес хоста из запроса в ответ не попадает.
    app.get('/security.txt', (req, res) => {
        res.set('Cache-Control', CACHE_CONTROL);
        res.redirect(301, WELL_KNOWN_PATH);
    });
}

module.exports = { register };
