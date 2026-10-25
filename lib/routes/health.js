'use strict';
// Мониторинг (7.6): /healthz, /readyz, /metrics. Регистрируется до
// sessionMiddleware (PRE_SESSION_ROUTES): сессия этим адресам не нужна и
// создаваться не должна, лимитеров на них нет (лимитер /api их не видит), а
// Onion-Location для них не ставится (isPagePath в lib/tor-support.js).
//
//   GET /healthz — процесс жив: 200 {status:'ok'} без обращения к базе.
//   GET /readyz  — готов принимать трафик: миграции завершены и база
//                  отвечает на SELECT 1 за 2 секунды; иначе 503. Это адрес для
//                  healthcheck хостинга: во время деплоя трафик не уйдёт на
//                  экземпляр, который ещё не может работать.
//   GET /metrics — Prometheus, только с заголовком Authorization: Bearer
//                  $METRICS_TOKEN; без токена (и когда METRICS_TOKEN не задан)
//                  ответ такой же, как у любого несуществующего адреса, — 404.
//
// В ответах health-адресов нет деталей (версий, текстов ошибок, имён хостов):
// статус — одно слово. Причина сбоя пишется в лог, а не в ответ.
//
// ctx (собирает src/context.js): pool, metrics (lib/metrics.js), readiness
// ({ migrated }), env. Всё читается в момент запроса.

const crypto = require('crypto');
const { createErrorReporter } = require('../pg-limits');

const READY_TIMEOUT_MS = 2000;
const BEARER_RE = /^Bearer[ \t]+(\S+)$/i;
const METRICS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

const sha256 = (value) => crypto.createHash('sha256').update(String(value), 'utf8').digest();

// Сравнение через SHA-256 обеих сторон: одинаковая длина для
// timingSafeEqual и никакой утечки длины токена по времени ответа.
function tokenMatches(header, token) {
    if (typeof token !== 'string' || token === '' || typeof header !== 'string') return false;
    const match = BEARER_RE.exec(header.trim());
    return Boolean(match) && crypto.timingSafeEqual(sha256(match[1]), sha256(token));
}

function checkDatabase(pool, timeoutMs) {
    let timer;
    const timeout = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`база не ответила за ${timeoutMs} мс`)), timeoutMs);
    });
    return Promise.race([pool.query('SELECT 1'), timeout]).finally(() => clearTimeout(timer));
}

function register(app, ctx) {
    // Падающая база не должна забивать лог каждой пробой healthcheck.
    const report = createErrorReporter();

    app.get('/healthz', (req, res) => {
        res.json({ status: 'ok' });
    });

    app.get('/readyz', async (req, res) => {
        if (!ctx.readiness || !ctx.readiness.migrated) return res.status(503).json({ status: 'starting' });
        try {
            await checkDatabase(ctx.pool, READY_TIMEOUT_MS);
        } catch (err) {
            report('readyz', err);
            return res.status(503).json({ status: 'unavailable' });
        }
        res.json({ status: 'ok' });
    });

    app.get('/metrics', (req, res, next) => {
        const token = ctx.env && ctx.env.METRICS_TOKEN;
        if (!ctx.metrics || !tokenMatches(req.headers.authorization, token)) return next();
        res.set('Content-Type', METRICS_CONTENT_TYPE);
        res.send(ctx.metrics.render());
    });
}

module.exports = { register, tokenMatches, READY_TIMEOUT_MS };
