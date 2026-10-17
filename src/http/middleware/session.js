'use strict';
// Сессия и CSRF: CSRF-токен, привязанный к сессии, хранилище сессий в Postgres, sessionMiddleware,
// начало и конец сессии пользователя. Вынесено из server.js.

const session = require('express-session');
// Сессии в Postgres с огрублением времени, их продление и активность
// анонимов (контракт этапа 1, §4).
const { createNyxoPgStore } = require('../../../lib/session-store');
// CSRF-токен, привязанный к сессии (кука csrf_token + заголовок X-CSRF-Token).
const { createCsrf } = require('../../../lib/csrf');
const { logError } = require('../../../lib/log-error');

function createSession(ctx) {
    const { IS_PRODUCTION, sessionSecret, metrics, pool } = ctx;

    // CSRF-токен привязан к сессии: ключ выводится из SESSION_SECRET (HKDF), так что
    // смена секрета заодно сбрасывает все выданные токены.
    const csrf = createCsrf({ secret: sessionSecret, onRejected: metrics.csrfRejected });

    // NyxoPgStore (lib/session-store.js) — стор connect-pg-simple, который пишет
    // время в таблицу session огрублённым до 5 минут и без createdAt.
    const NyxoPgStore = createNyxoPgStore(session);
    const sessionMiddleware = session({
        store: new NyxoPgStore({
            pool: pool,
            tableName: 'session',
            createTableIfMissing: true,
            // touch стора писал бы строку session на КАЖДЫЙ запрос. Сессия
            // продлевается явно: маркером renewSession не чаще раза в интервал
            // (middleware после sessionMiddleware) и touch открытых сокетов.
            disableTouch: true
        }),
        secret: sessionSecret,
        resave: false,
        saveUninitialized: false,
        proxy: true,
        cookie: {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true,
            // 'auto' — Secure по фактическому протоколу запроса (req.secure с
            // учётом X-Forwarded-Proto от доверенного прокси; для .onion его
            // выставляет onionMiddleware). Жёсткий secure: true ломал вход везде,
            // где до приложения доходит plain http.
            secure: IS_PRODUCTION ? 'auto' : false,
            // Раньше в production было 'none' — кука уходила с любого сайта, в том
            // числе в межсайтовое WebSocket-рукопожатие и POST-формы. 'lax'
            // оставляет её только своим запросам и переходам по ссылке.
            sameSite: 'lax'
        }
    });

    // Новая сессия с защитой от фиксации (regenerate): id сессии, который был
    // у браузера до регистрации, к аккаунту не привязывается.
    function startUserSession(req, fields) {
        return new Promise((resolve, reject) => {
            req.session.regenerate((err) => {
                if (err) return reject(err);
                Object.assign(req.session, fields);
                // Новая сессия — новая привязка CSRF-токена: токен «до входа» или от
                // прежней сессии больше не подходит, клиент получает новый в этом же ответе.
                csrf.issue(req, req.res);
                resolve();
            });
        });
    }

    // Завершает сессию после удаления аккаунта. Clear-Site-Data: "cache" —
    // браузер выбрасывает кэш сайта (страницы, вложения), чтобы на общем
    // устройстве не оставалось следов переписки.
    function endSession(req, res, message) {
        req.session.destroy((err) => {
            if (err) logError('[Account] Не удалось удалить сессию', err);
            res.clearCookie('connect.sid');
            // CSRF-куку не удаляем, а выдаём новую (под привязку «до входа», с новым
            // nyxo_pre): страница после удаления не перезагружается, и следующая
            // регистрация без куки получила бы 403 «неверный CSRF-токен».
            csrf.issue(req, res, { freshPre: true });
            res.set('Clear-Site-Data', '"cache"');
            res.json({ success: true, message });
        });
    }

    return { csrf, sessionMiddleware, startUserSession, endSession };
}

module.exports = { createSession };
