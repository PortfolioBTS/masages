'use strict';
// CSRF-токен, привязанный к сессии (roadmap R11, план сервера 8.1).
//
// Было: случайный токен в куке csrf_token, сверяемый с заголовком
// X-CSRF-Token. Такой токен не связан с сессией: кто-то, сумевший подсадить
// браузеру свою куку csrf_token (с соседнего поддомена), мог подставить и
// свой заголовок. Теперь токен подписан сервером и привязан к тому, кто его
// получил:
//
//   токен = rand '.' HMAC(K, привязка '|' rand),
//   K = HKDF(SESSION_SECRET, 'nyxo-csrf-v1'), rand — 128 случайных бит.
//
// Привязка:
//   * вошёл в аккаунт — 'sid:' + id сессии. Новая сессия (вход, смена срока
//     жизни) — новая привязка: старый токен перестаёт подходить;
//   * не вошёл — 'pre:' + значение куки nyxo_pre (128 случайных бит, httpOnly,
//     SameSite=Strict, сессионная; в базе не хранится). Это нужно, чтобы
//     запрос регистрации тоже был защищён, хотя сессии у него ещё нет.
// Токен «до входа» после входа не подходит: привязка уже другая.
//
// Доставка клиенту не изменилась: кука csrf_token (читаема из JS) и заголовок
// X-CSRF-Token. Токен принимается, только если заголовок равен куке И подпись
// верна для текущей привязки (сравнение — timingSafeEqual). Нет куки или она
// не подходит привязке — на ЛЮБОМ запросе выдаётся новая, поэтому клиент,
// получивший 403, просто делает GET и повторяет запрос.
//
// Порядок в src/http/app.js: проверка Origin — первой (раньше всего, см. там), эта
// проверка — после sessionMiddleware (нужен id сессии) и до разбора тела.

const crypto = require('crypto');
const { deriveKey } = require('./derive-key');

const TOKEN_COOKIE = 'csrf_token';
const PRE_COOKIE = 'nyxo_pre';
const COOKIE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// 16 байт в base64url — 22 символа; HMAC-SHA256 — 43.
const RAND_LENGTH = 22;
const MAC_LENGTH = 43;
const MAX_TOKEN_LENGTH = 128;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const PRE_RE = /^[A-Za-z0-9_-]{22}$/;
const DENIED_BODY = Object.freeze({ success: false, message: 'Запрещено: неверный CSRF-токен' });

// Сравнение строк за постоянное время; разная длина — сразу false.
function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const left = Buffer.from(a, 'utf8');
    const right = Buffer.from(b, 'utf8');
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// Убирает ещё не отправленные Set-Cookie с этим именем: перевыдача в том же
// ответе заменяет прежнюю куку, а не добавляет вторую.
function dropPendingCookie(res, name) {
    const current = res.getHeader('Set-Cookie');
    if (!current) return;
    const kept = (Array.isArray(current) ? current : [current]).filter(line => !String(line).startsWith(`${name}=`));
    if (kept.length > 0) res.setHeader('Set-Cookie', kept);
    else res.removeHeader('Set-Cookie');
}

// secret — SESSION_SECRET; onRejected() — для метрик.
function createCsrf({ secret, onRejected = () => {} }) {
    const key = deriveKey(secret, 'nyxo-csrf-v1');

    const sign = (binding, rand) =>
        crypto.createHmac('sha256', key).update(`${binding}|${rand}`, 'utf8').digest('base64url');

    function createToken(binding) {
        const rand = crypto.randomBytes(16).toString('base64url');
        return `${rand}.${sign(binding, rand)}`;
    }

    // Токен подходит привязке? Форма проверяется строго до подписи.
    function verifyToken(token, binding) {
        if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH || typeof binding !== 'string') return false;
        if (token.length !== RAND_LENGTH + 1 + MAC_LENGTH || token[RAND_LENGTH] !== '.') return false;
        const rand = token.slice(0, RAND_LENGTH);
        const mac = token.slice(RAND_LENGTH + 1);
        if (!B64URL_RE.test(rand) || !B64URL_RE.test(mac)) return false;
        return safeEqual(mac, sign(binding, rand));
    }

    const sessionBinding = (req) =>
        (req.session && req.session.userId && req.sessionID ? `sid:${req.sessionID}` : null);

    function currentPre(req) {
        const value = req.cookies && req.cookies[PRE_COOKIE];
        return typeof value === 'string' && PRE_RE.test(value) ? value : null;
    }

    // Secure — по фактическому протоколу запроса: .onion и разработка по http
    // иначе не получили бы куку вовсе.
    function setPreCookie(req, res) {
        const pre = crypto.randomBytes(16).toString('base64url');
        dropPendingCookie(res, PRE_COOKIE);
        res.cookie(PRE_COOKIE, pre, { httpOnly: true, sameSite: 'strict', secure: Boolean(req.secure), path: '/' });
        if (req.cookies) req.cookies[PRE_COOKIE] = pre;
        return pre;
    }

    function setTokenCookie(req, res, token) {
        dropPendingCookie(res, TOKEN_COOKIE);
        res.cookie(TOKEN_COOKIE, token, {
            httpOnly: false,
            sameSite: 'lax',
            secure: Boolean(req.secure),
            maxAge: COOKIE_MAX_AGE_MS,
        });
    }

    // Выдаёт токен под ТЕКУЩУЮ привязку и ставит куку. Вызывается после
    // regenerate сессии (регистрация, смена срока) и при завершении сессии.
    // freshPre — заменить и nyxo_pre: после выхода токены от прежнего «до
    // входа» не должны ожидать нового аккаунта в том же браузере.
    function issue(req, res, { freshPre = false } = {}) {
        let binding = sessionBinding(req);
        if (!binding) {
            const pre = (!freshPre && currentPre(req)) || setPreCookie(req, res);
            binding = `pre:${pre}`;
        }
        const token = createToken(binding);
        setTokenCookie(req, res, token);
        return token;
    }

    function middleware(req, res, next) {
        // Сокеты проверяют источник сами (allowRequest); сюда они не доходят,
        // но путь исключён явно.
        if (req.path.startsWith('/socket.io')) return next();

        let binding = sessionBinding(req);
        if (!binding) {
            const pre = currentPre(req) || setPreCookie(req, res);
            binding = `pre:${pre}`;
        }
        const cookieToken = req.cookies && req.cookies[TOKEN_COOKIE];
        const cookieValid = verifyToken(cookieToken, binding);
        // Нет куки или она не от этой привязки — выдаём новую на любом методе,
        // чтобы следующий запрос клиента (после 403 он делает GET) был
        // принят. Сам этот запрос, если он небезопасный, ниже отклоняется.
        if (!cookieValid) setTokenCookie(req, res, createToken(binding));

        if (SAFE_METHODS.has(req.method)) return next();

        const headerToken = req.headers['x-csrf-token'];
        if (!cookieValid || !safeEqual(headerToken, cookieToken)) {
            onRejected();
            return res.status(403).json(DENIED_BODY);
        }
        next();
    }

    return { middleware, issue, createToken, verifyToken };
}

module.exports = { createCsrf, TOKEN_COOKIE, PRE_COOKIE, DENIED_BODY };
