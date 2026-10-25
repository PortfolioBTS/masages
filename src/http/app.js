'use strict';
// Цепочка middleware и маршрутов приложения: configureApp(ctx) регистрирует их на app из
// http/create-app.js.
// ПОРЯДОК вызовов в configureApp — тот же, что был в server.js: Express применяет middleware
// в порядке регистрации, и от него зависит безопасность (заголовки, Origin, сессия, CSRF,
// лимитер /api, только потом маршруты). Менять порядок нельзя без отдельного разбора.

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const { getPrivacyHeaders, createHstsMiddleware } = require('../../lib/privacy');
const { createSwKillSwitch } = require('../../lib/sw-kill-switch');
const { buildContentSecurityPolicy, isCrossSiteApiRequest } = require('../../lib/security-utils');
// Сессии в Postgres с огрублением времени, их продление и активность
// анонимов (контракт этапа 1, §4).
const { renewSession } = require('../../lib/session-store');
// Onion-сервис (контейнер tor-service/)
const { onionMiddleware } = require('../../lib/tor-support');
// Точки регистрации маршрутов из lib/routes/ и JSON-404 для /api.
const { registerPreSessionRoutes, registerApiNotFound } = require('../../lib/routes');
const { installBodyParsers } = require('./middleware/body-parsers');
const { registerRoutes } = require('./routes/index');
const { installErrorHandler } = require('./middleware/error-handler');

// Небезопасные методы — только со своих страниц (см. isTrustedOrigin).
// Второй рубеж к CSRF-токену ниже: SameSite=Lax и токен защищают от
// межсайтовых форм, а проверка Origin — ещё и от поддоменов/соседних
// сайтов, которые могут подсадить свою csrf_token-куку.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Разрешает браузеру хранить ответ, но перед каждым использованием
// сверяться с сервером (If-None-Match/If-Modified-Since -> 304 без тела).
// Раньше глобальный 'no-store' заставлял заново скачивать CSS/JS и каждую
// картинку чата при каждом открытии.
function setRevalidateCacheHeaders(res, isPrivate) {
    res.set('Cache-Control', isPrivate ? 'private, no-cache' : 'no-cache');
    res.removeHeader('Pragma');
    res.removeHeader('Expires');
    res.removeHeader('Surrogate-Control');
}

function configureApp(ctx) {
    const {
        ROOT_DIR, IS_PRODUCTION, HSTS_PRELOAD, SESSION_RENEW_MS, metrics, app, resolveRealIp, isTrustedOrigin,
        apiLimiter, uploadsIpLimiter, uploadsUserLimiter, csrf, httpSessionMiddleware, anonActivity, serverContext,
    } = ctx;

    // Самым первым: признак onion-запроса (req.isOnion) нужен лимитерам и
    // заголовкам ниже, а у onion-запроса onionMiddleware ещё и вычищает
    // присланные клиентом X-Forwarded-* — прокси перед приложением там нет.
    // Метрики HTTP — самым первым, чтобы считать и отказы всех проверок ниже.
    app.use(metrics.httpMiddleware());
    app.use(onionMiddleware);

    app.use((req, res, next) => {
        // req.ip уже учитывает 1 доверенный хоп (trust proxy = 1), то есть это IP,
        // который реально подключился к Railway — Cloudflare edge, если трафик шёл
        // через CF, либо настоящий IP клиента, если Railway-домен открыт напрямую.
        // У onion-запроса это адрес контейнера tor — один на всех onion-клиентов,
        // поэтому лимиты ниже для onion по IP не считаются.
        req.realIp = resolveRealIp(req.headers, req.ip);
        next();
    });

    // Заголовки — первыми, чтобы их получил любой ответ, включая отказы
    // проверок источника и CSRF ниже.
    app.use((req, res, next) => {
        // Усиленные заголовки приватности (nosniff, DENY, no-referrer, COOP/COEP...
        // — см. lib/privacy.js). Здесь они больше не дублируются и не
        // перезаписываются: раньше Referrer-Policy тут же подменялся на
        // strict-origin-when-cross-origin, и на сторонние сайты уходил origin.
        res.set(getPrivacyHeaders());

        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.set('Surrogate-Control', 'no-store');
        res.set('X-Robots-Tag', 'noindex, nofollow');
        // Политика — buildContentSecurityPolicy (lib/security-utils.js). Без
        // 'unsafe-inline' в script-src и style-src (инлайн-кода в index.html нет,
        // поэтому nonce не нужен — а значит, нет и шаблонизации страницы: она
        // отдаётся статикой байт-в-байт, и её хэш из манифеста клиента сверяется
        // с релизом) и без "ws: wss:" (любой хост) в connect-src: только
        // WebSocket своего хоста. Схема ws/wss — по тому, как страница открыта:
        // onion-сервис отдаётся по http (TLS там даёт сам Tor), хотя
        // onionMiddleware и помечает такой запрос защищённым.
        res.set('Content-Security-Policy', buildContentSecurityPolicy({
            host: req.headers.host,
            secure: req.secure && !req.isOnion,
        }));
        next();
    });
    // HSTS — только для настоящего https в production и не для onion; preload — по
    // HSTS_PRELOAD=yes (риски — в env-check). См. getHstsHeader в lib/privacy.js.
    app.use(createHstsMiddleware({ production: IS_PRODUCTION, preload: HSTS_PRELOAD }));

    app.use((req, res, next) => {
        // Межсайтовый запрос к API отклоняется при любом методе, в том числе GET по переходу с чужой
        // страницы: у части GET есть побочные эффекты (отметка «прочитано», выдача ключей), а кука
        // SameSite=Lax при таком переходе уходит (W7 R1 п.5). Sec-Fetch-Site подделать со страницы нельзя.
        if (isCrossSiteApiRequest({ secFetchSite: req.headers['sec-fetch-site'], path: req.path })) {
            metrics.originRejected();
            return res.status(403).json({ success: false, message: 'Запрещено: запрос с чужого сайта' });
        }
        if (SAFE_METHODS.has(req.method) || isTrustedOrigin(req.headers, req)) return next();
        metrics.originRejected();
        res.status(403).json({ success: false, message: 'Запрещено: запрос с чужого сайта' });
    });

    app.use(cookieParser());

    // CSRF-токен (lib/csrf.js) проверяется ниже, после sessionMiddleware: токен
    // привязан к сессии, и ему нужен её id. Статике (CSS, JS, иконки) токен не
    // нужен, поэтому она раздаётся раньше и кук не получает.

    // Аварийное снятие service worker (SW_KILL_SWITCH=yes, lib/sw-kill-switch.js):
    // подменяет только /sw.js и обязано стоять до статики, иначе та отдаст настоящий файл.
    app.use(createSwKillSwitch(process.env));

    // Статика раздаётся ДО sessionMiddleware: ей сессия не нужна, а раньше
    // каждый запрос за CSS/JS/иконкой ходил в Postgres за сессией.
    app.use(express.static(path.join(ROOT_DIR, 'public'), {
        setHeaders: (res) => setRevalidateCacheHeaders(res, false),
    }));

    // /link.my раньше отдавал index.html со вставленным nonce. Теперь страница
    // всегда статическая, один адрес — «/»; старые закладки уходят туда 301.
    // Относительный Location: адрес хоста из запроса в ответ не попадает.
    app.get('/link.my', (req, res) => {
        res.redirect(301, '/');
    });

    // Маршруты из lib/routes/ (см. lib/routes/index.js): здесь — те, которым
    // сессия не нужна; ниже, после лимитера /api/, — обычные маршруты API.
    registerPreSessionRoutes(app, serverContext);

    // Выдача вложений: лимит по IP стоит ДО сессии (поток запросов с кукой не должен ходить в БД),
    // лимит по аккаунту - после неё и проверки сессии (ниже).
    app.use('/uploads', uploadsIpLimiter);

    // Сессия грузится только для /api и /uploads (httpSessionMiddleware): остальным путям она не нужна.
    app.use(httpSessionMiddleware);

    // Сессия проверяется на КАЖДОМ запросе (validateSession). Недействительная
    // (без isAnonymous — от прежней версии с постоянными аккаунтами) или истёкшая
    // заменяется пустой, а /api/auth сообщит клиенту, что сессия закончилась
    // (req.authEnded). Живая — это активность: корзина в БД пишется раз в
    // корзину, и запись ждётся, потому что ответы ниже читают last_active_at.
    // И продление сессии раз в интервал (renewSession): строка session
    // пересохраняется, кука day/week уходит заново с новым Expires. app.use не
    // оборачивается wrapAsync, поэтому ошибки — вручную в next.
    app.use((req, res, next) => {
        const sess = req.session;
        if (!sess || !sess.userId) return next();
        const userId = sess.userId;
        anonActivity.validateSession(sess).then(async (verdict) => {
            if (verdict !== 'ok') {
                return req.session.regenerate((err) => {
                    req.authEnded = verdict;
                    next(err);
                });
            }
            await anonActivity.noteActivity(userId);
            renewSession(sess, {
                lifetime: anonActivity.lifetimeOf(userId) || sess.anonLifetime,
                now: Date.now(),
                intervalMs: SESSION_RENEW_MS,
            });
            next();
        }).catch(next);
    });

    // CSRF: после sessionMiddleware и проверки сессии (привязка — id сессии, а у
    // запроса без входа, например регистрации, — кука nyxo_pre) и до разбора тела.
    // Источник небезопасного запроса проверен ещё раньше (isTrustedOrigin).
    app.use(csrf.middleware);

    app.use('/uploads', uploadsUserLimiter);

    // Разбор тела запроса: парсеры и их порядок — в middleware/body-parsers.js.
    installBodyParsers(app);

    // Лимит на /api/ — ДО регистрации маршрутов из lib/: Express применяет
    // middleware в порядке регистрации, и раньше /api/keys/* и
    // /api/chats/:id/participants шли мимо лимита.
    app.use('/api/', apiLimiter);

    registerRoutes(app, ctx);

    // После ВСЕХ маршрутов: неизвестный /api/* — JSON-404.
    registerApiNotFound(app);

    installErrorHandler(app);
}

module.exports = { configureApp };
