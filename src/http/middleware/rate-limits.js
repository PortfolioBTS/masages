'use strict';
// Лимиты запросов: общий лимит /api (в памяти) и точные лимиты в Postgres (lib/pg-limits.js:
// регистрация, вход в комнату, выдача ключей, одноразовость PoW). Вынесено из server.js.

const rateLimit = require('express-rate-limit');
const { setSecret: setPowSecret } = require('../../../lib/pow');
// Точные лимиты и одноразовость PoW в Postgres (UNLOGGED-таблицы, ключи — HMAC).
const { createPgLimits, LimitStoreError, respondBusy } = require('../../../lib/pg-limits');
// Суточный объём текста на аккаунт (W7 R1 п.3).
const { createTextQuota } = require('../../../lib/text-quota');

const { ipKeyGenerator } = rateLimit;

const rateLimitKeyGenerator = (req) => ipKeyGenerator(req.realIp || req.ip);
const sessionUserId = (req) => (req.session && req.session.userId) || null;
const RATE_LIMIT_DEFAULTS = { standardHeaders: true, legacyHeaders: false };

function createRateLimits(ctx) {
    const { sessionSecret, metrics, pool, ACCOUNT_LIMITS } = ctx;

    // Точные лимиты (регистрация, вход по коду, выдача ключей) и одноразовость PoW
    // живут в Postgres и создаются ниже, из того же пула и SESSION_SECRET
    // (lib/pg-limits.js). Здесь — общий лимит /api, он только в памяти.

    // 300 запросов за 15 минут (~1 в 3 секунды) активный пользователь чата
    // выбирал за несколько минут — особенно когда клиент перезапрашивал
    // список чатов на каждое входящее сообщение — после чего всё приложение
    // "висло" с ошибкой на 15 минут. Залогиненных считаем по аккаунту (за
    // одним NAT или onion-адресом их много), остальных — по IP. Неавторизованные
    // onion-запросы не считаются: у них один IP на всех, и любой исчерпал бы
    // общую квоту за всех onion-посетителей. Их открытый маршрут (регистрация)
    // защищён proof-of-work, а от флуда — защита самого onion-сервиса (см.
    // tor-service/README.md).
    const apiLimiter = rateLimit({
        ...RATE_LIMIT_DEFAULTS,
        windowMs: 15 * 60 * 1000,
        max: 1000,
        skip: (req) => req.isOnion && !sessionUserId(req),
        keyGenerator: (req) => (sessionUserId(req) ? `user:${sessionUserId(req)}` : rateLimitKeyGenerator(req)),
        message: { success: false, message: 'Слишком много запросов. Попробуйте позже.' }
    });

    // ---- Точные лимиты в Postgres (lib/pg-limits.js, roadmap R11) ----
    //
    // Регистрация, вход по коду, выдача bundle ключей и одноразовость решений PoW
    // переживают рестарт: счётчики лежат в UNLOGGED-таблицах, ключи клиентов (IP,
    // id) — только как HMAC от SESSION_SECRET. Ошибка хранилища закрывает лимит:
    // 503 {success:false, code:'busy'}. Ключ PoW тоже выводится из SESSION_SECRET,
    // чтобы выданные задачи действовали и после рестарта.
    setPowSecret(sessionSecret);
    const pgLimits = createPgLimits({
        pool,
        secret: sessionSecret,
        hooks: { limited: metrics.rateLimited, storeError: metrics.limitStoreError },
    });
    const powUsedStore = pgLimits.powUsedStore();
    const bundleLimiter = pgLimits.slidingLimiter('bundle');
    // Отправки key-share (30 в час на пару «пользователь, комната») и запросы ключа (10 в час).
    const keyShareLimiter = pgLimits.slidingLimiter('keyshare');
    const keyRequestLimiter = pgLimits.slidingLimiter('keyreq');
    // Публикация и чтение сертификатов состава (signed-membership.md, 7.2).
    const memberCertLimiter = pgLimits.slidingLimiter('memcert');

    // Массовую регистрацию сдерживает proof-of-work (lib/pow.js). IP-лимит остался
    // мягким и только для clearnet: для onion он запер бы регистрацию всем сразу
    // (общий IP контейнера tor).
    const registerLimiter = pgLimits.rateLimiter('register', {
        windowMs: 60 * 60 * 1000,
        max: 10,
        skip: (req) => req.isOnion,
        keyGenerator: rateLimitKeyGenerator,
        message: { success: false, message: 'Слишком много регистраций. Попробуйте позже.' }
    });

    // Глобальный потолок регистраций в минуту (W7 R1 п.3), в том числе onion: IP-лимит
    // выше там не действует, а PoW (~0,14 с на аккаунт) сам по себе массовость не останавливает.
    // Проверяется ПОСЛЕ успешного PoW (registerGlobalGate): запросы без решённой задачи
    // потолок не расходуют, иначе любой забил бы его мусором. Рядом растёт сложность PoW
    // (src/services/pow.js): потолок - последняя линия, а не основной рубеж.
    const registerGlobalLimiter = pgLimits.rateLimiter('register-all', {
        windowMs: 60 * 1000,
        max: ACCOUNT_LIMITS.registerGlobalPerMin,
        keyGenerator: () => 'all',
    });
    // true - регистрировать можно; false - ответ (429 или 503 busy) уже отправлен.
    async function registerGlobalGate(res) {
        try {
            const { totalHits, resetTime } = await registerGlobalLimiter.store.increment('all');
            if (totalHits <= ACCOUNT_LIMITS.registerGlobalPerMin) return true;
            metrics.rateLimited('register-all');
            const waitSeconds = Math.max(1, Math.ceil((new Date(resetTime).getTime() - Date.now()) / 1000));
            res.set('Retry-After', String(waitSeconds));
            res.status(429).json({
                success: false, code: 'registration-busy',
                message: 'Сейчас регистрируется слишком много аккаунтов. Повторите через минуту.',
            });
            return false;
        } catch (err) {
            if (!(err instanceof LimitStoreError)) throw err;
            metrics.limitStoreError('register-all');
            respondBusy(res);
            return false;
        }
    }

    // Суточный объём текста сообщений на аккаунт (lib/text-quota.js).
    const textQuota = createTextQuota({ pool, secret: sessionSecret, limitBytes: ACCOUNT_LIMITS.textQuotaBytesPerDay });

    // Вход в комнату по коду: даже 130-битный код не должен перебираться
    // с бесконечной скоростью, и утёкший список кодов — массово проверяться.
    const joinUserLimiter = pgLimits.rateLimiter('join-user', {
        windowMs: 15 * 60 * 1000,
        max: 20,
        skip: (req) => !sessionUserId(req),
        keyGenerator: (req) => `user:${sessionUserId(req)}`,
        message: { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' }
    });
    const joinIpLimiter = pgLimits.rateLimiter('join-ip', {
        windowMs: 15 * 60 * 1000,
        max: 60,
        skip: (req) => req.isOnion,
        keyGenerator: rateLimitKeyGenerator,
        message: { success: false, message: 'Слишком много попыток входа в чат. Попробуйте позже.' }
    });

    return {
        apiLimiter, pgLimits, powUsedStore, bundleLimiter, keyShareLimiter, keyRequestLimiter,
        memberCertLimiter, registerLimiter, joinUserLimiter, joinIpLimiter, registerGlobalGate, textQuota,
    };
}

module.exports = { createRateLimits };
