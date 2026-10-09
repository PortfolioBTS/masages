'use strict';
// Точные лимиты в Postgres (roadmap R11, план сервера 7.4).
//
// Зачем. Лимиты в памяти процесса обнулялись при каждом рестарте и деплое:
// регистрацию, перебор кодов приглашений, выдачу ключей и повторное
// предъявление решения proof-of-work можно было «перезапустить» вместе с
// сервером. Точные лимиты — регистрация, вход по коду, PoW и выдача ключей —
// живут в Postgres. Общий лимит /api остаётся в памяти: он грубый, и его
// потеря при рестарте безвредна.
//
// Что в базе (DDL — initPgLimitsSchema, он вызывается из initDatabase):
//   * rl_counters — счётчики фиксированного окна для express-rate-limit;
//   * rl_buckets  — минутные корзины для скользящего окна (выдача bundle);
//   * pow_used    — хэши уже предъявленных решений PoW.
// Все три таблицы UNLOGGED: без журнала записи в них дёшевы, а потеря при
// аварии Postgres безвредна — лимиты просто начнутся заново (для pow_used
// это значит, что решение, выданное не больше 5 минут назад, можно
// предъявить повторно; такое окно возможно только при падении самой базы).
//
// Что в таблицах НЕ лежит: ни IP, ни id. Ключ клиента проходит через
// HMAC-SHA256 с ключом, выведенным из SESSION_SECRET (HKDF, метка
// 'nyxo-rl-v1'), и в таблицу попадает только результат. Дамп таблиц без
// секрета не позволяет ни узнать адрес, ни проверить догадку «этот IP тут
// был». Побочное следствие: смена SESSION_SECRET обнуляет все лимиты.
//
// При ошибке хранилища (недоступна база, нет таблицы, таймаут) точный лимит
// ЗАКРЫВАЕТСЯ: ответ 503 {success:false, code:'busy'}. Открывать лимит при
// сбое нельзя — именно в сбой его и обходят.

const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { deriveKey } = require('./derive-key');
const { logError } = require('./log-error');

const KEY_LABEL = 'nyxo-rl-v1';
const DEFAULT_TIMEOUT_MS = 3000;
// Окно скользящего лимитера (выдача bundle) — час из минутных корзин.
const SLIDING_BUCKET_MS = 60 * 1000;
const MAX_SLIDING_WINDOW_MS = 60 * 60 * 1000;
// Корзины хранятся с запасом: чистка идёт по часам БД, а окно считается по
// ним же, но лишний час страхует от расхождения часов реплик.
const BUCKET_RETENTION_MS = 2 * MAX_SLIDING_WINDOW_MS;
// Запас на расхождение часов приложения и БД: токен PoW ещё действителен
// по часам приложения, когда его строку уже можно было бы убрать по часам БД.
const POW_RETENTION_MARGIN_MS = 60 * 1000;
// Пространство двухключевых advisory-блокировок скользящего лимитера: не
// пересекается с 64-битными ключами lib/advisory-locks.js (миграции, задачи).
const ADVISORY_NAMESPACE = 0x4e524c31; // 'NRL1'
const SCOPE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const REPORT_INTERVAL_MS = 10 * 1000;

const BUSY_RESPONSE = Object.freeze({
    success: false,
    code: 'busy',
    message: 'Сервис сейчас занят. Повторите попытку через несколько секунд.',
});

// ---- Схема ----

async function initPgLimitsSchema(pool) {
    // Окно фиксированное: reset_at — конец окна; просроченную строку
    // increment перезапускает сам, а убирает уборка. fillfactor оставляет
    // место под HOT-обновления счётчика.
    await pool.query(`
        CREATE UNLOGGED TABLE IF NOT EXISTS rl_counters (
            k TEXT PRIMARY KEY,
            hits INT NOT NULL,
            reset_at TIMESTAMPTZ NOT NULL
        ) WITH (fillfactor = 70)
    `);
    await pool.query(`
        CREATE UNLOGGED TABLE IF NOT EXISTS rl_buckets (
            k BYTEA NOT NULL,
            bucket TIMESTAMPTZ NOT NULL,
            n INT NOT NULL,
            PRIMARY KEY (k, bucket)
        )
    `);
    await pool.query(`
        CREATE UNLOGGED TABLE IF NOT EXISTS pow_used (
            token_hash BYTEA PRIMARY KEY,
            expires_at TIMESTAMPTZ NOT NULL
        )
    `);
}

// ---- Ошибки и вспомогательное ----

// Любой сбой хранилища лимитов. Отдельный класс нужен, чтобы отличить его от
// прочих ошибок middleware: только он превращается в 503 {code:'busy'}.
class LimitStoreError extends Error {
    constructor(message, cause) {
        super(message);
        this.name = 'LimitStoreError';
        this.code = 'LIMIT_STORE_UNAVAILABLE';
        this.cause = cause;
    }
}

function withTimeout(promise, ms, what) {
    let timer;
    const timeout = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${what}: нет ответа за ${ms} мс`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Соединение из пула с ограничением ожидания: при исчерпанном пуле лимит
// должен отвечать «занято» быстро, а не висеть до таймаута драйвера. Если
// соединение пришло после таймаута, оно возвращается в пул.
async function acquireClient(pool, timeoutMs) {
    const pending = pool.connect();
    try {
        return await withTimeout(pending, timeoutMs, 'соединение с базой');
    } catch (err) {
        pending.then((client) => client.release(), () => {});
        throw err;
    }
}

// Не больше одной записи в лог в REPORT_INTERVAL_MS на каждый лимитер: при
// упавшей базе каждый запрос приносит ту же ошибку, и лог не должен тонуть.
function createErrorReporter({ log = logError, intervalMs = REPORT_INTERVAL_MS, now = Date.now } = {}) {
    const state = new Map();
    return (scope, err) => {
        const entry = state.get(scope) || { at: -Infinity, skipped: 0 };
        state.set(scope, entry);
        if (now() - entry.at < intervalMs) {
            entry.skipped++;
            return;
        }
        const extra = entry.skipped > 0 ? ` (ещё ${entry.skipped} таких же ошибок за последние секунды)` : '';
        entry.at = now();
        entry.skipped = 0;
        log(`[Limits] Хранилище лимитов «${scope}» недоступно${extra}`, err && err.cause ? err.cause : err);
    };
}

function respondBusy(res) {
    if (res.headersSent) return;
    res.set('Retry-After', '5');
    res.status(503).json(BUSY_RESPONSE);
}

// ---- Ключи ----

// HMAC ключа клиента. scope (имя лимитера) входит в подпись: один и тот же IP
// у двух лимитеров даёт разные значения и не связывается между таблицами.
function createLimitKeys(secret) {
    const key = deriveKey(secret, KEY_LABEL);
    const digest = (scope, clientKey) =>
        crypto.createHmac('sha256', key).update(`${scope}\u0000${clientKey}`, 'utf8').digest();
    return {
        digest,
        // Ключ строки rl_counters: имя лимитера открыто (оно не секрет и
        // позволяет сбросить лимитер целиком), клиент — только как HMAC.
        text: (scope, clientKey) => `${scope}:${digest(scope, clientKey).toString('base64url')}`,
    };
}

// ---- Стор express-rate-limit v8: фиксированное окно ----

// Один экземпляр на лимитер: express-rate-limit запрещает делить стор между
// лимитерами, а localKeys=false и уникальный prefix говорят ему, что ключи
// лежат во внешнем хранилище и различаются по имени лимитера.
function createPgRateLimitStore({ pool, keys, scope, windowMs, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (typeof scope !== 'string' || !SCOPE_RE.test(scope)) throw new TypeError('createPgRateLimitStore: некорректное имя лимитера');
    let currentWindowMs = windowMs;
    const keyOf = (clientKey) => keys.text(scope, clientKey);

    async function run(text, params) {
        try {
            return await withTimeout(pool.query(text, params), timeoutMs, 'запрос к счётчикам');
        } catch (err) {
            throw new LimitStoreError('Счётчики лимитов недоступны', err);
        }
    }

    return {
        localKeys: false,
        prefix: `${scope}:`,

        init(options) {
            if (Number.isFinite(options && options.windowMs) && options.windowMs > 0) currentWindowMs = options.windowMs;
        },

        async get(clientKey) {
            const { rows } = await run('SELECT hits, reset_at FROM rl_counters WHERE k = $1 AND reset_at > now()', [keyOf(clientKey)]);
            return rows.length === 0 ? undefined : { totalHits: rows[0].hits, resetTime: rows[0].reset_at };
        },

        // Один upsert: просроченная строка начинается заново (счёт 1, новое
        // окно), живая считает дальше и конец окна не двигает.
        async increment(clientKey) {
            if (!Number.isFinite(currentWindowMs) || currentWindowMs <= 0) {
                throw new LimitStoreError('Окно лимитера не задано', null);
            }
            const { rows } = await run(
                `INSERT INTO rl_counters (k, hits, reset_at)
                 VALUES ($1, 1, now() + $2::float8 * interval '1 millisecond')
                 ON CONFLICT (k) DO UPDATE SET
                     hits = CASE WHEN rl_counters.reset_at <= now() THEN 1 ELSE rl_counters.hits + 1 END,
                     reset_at = CASE WHEN rl_counters.reset_at <= now() THEN EXCLUDED.reset_at ELSE rl_counters.reset_at END
                 RETURNING hits, reset_at`,
                [keyOf(clientKey), currentWindowMs]
            );
            return { totalHits: rows[0].hits, resetTime: rows[0].reset_at };
        },

        async decrement(clientKey) {
            await run('UPDATE rl_counters SET hits = GREATEST(hits - 1, 0) WHERE k = $1', [keyOf(clientKey)]);
        },

        async resetKey(clientKey) {
            await run('DELETE FROM rl_counters WHERE k = $1', [keyOf(clientKey)]);
        },

        // starts_with, а не LIKE: в имени лимитера нет спецсимволов, но и
        // думать об экранировании не приходится.
        async resetAll() {
            await run('DELETE FROM rl_counters WHERE starts_with(k, $1)', [`${scope}:`]);
        },
    };
}

// middleware express-rate-limit поверх Postgres-стора. Ошибка стора —
// 503 {code:'busy'} (лимит закрывается), прочие ошибки идут дальше как есть.
function createPgRateLimiter({
    pool, keys, scope, windowMs, max, message, skip, keyGenerator,
    hooks = {}, timeoutMs = DEFAULT_TIMEOUT_MS, report = createErrorReporter(),
}) {
    const store = createPgRateLimitStore({ pool, keys, scope, windowMs, timeoutMs });
    const limiter = rateLimit({
        standardHeaders: true,
        legacyHeaders: false,
        windowMs,
        max,
        message,
        skip,
        keyGenerator,
        store,
        passOnStoreError: false,
        handler: (req, res, next, options) => {
            if (hooks.limited) hooks.limited(scope);
            res.status(options.statusCode);
            res.send(options.message);
        },
    });
    function pgRateLimiter(req, res, next) {
        limiter(req, res, (err) => {
            if (err instanceof LimitStoreError) {
                if (hooks.storeError) hooks.storeError(scope);
                report(scope, err);
                return respondBusy(res);
            }
            next(err);
        });
    }
    pgRateLimiter.store = store;
    return pgRateLimiter;
}

// ---- Скользящее окно (выдача bundle ключей) ----

// tryConsume(lockKey, rules) — атомарно проверить и учесть набор лимитов:
//   rules = [{ key, max }, …] — ключи клиента (как для HMAC), max — сколько
//   разрешено за окно. Если хоть одно правило исчерпано, не учитывается
//   НИЧЕГО (отказанный запрос не тратит квоту других правил). Результат:
//   { ok, waitMs: [мс до освобождения слота по каждому правилу, 0 — слот есть] }.
// lockKey сериализует одновременные запросы одного клиента (advisory-
// блокировка в транзакции), иначе два параллельных запроса оба увидели бы
// свободный слот. Ключи правил должны включать lockKey (у bundle это
// вызывающий и пара «вызывающий — цель»).
function createPgSlidingLimiter({ pool, keys, scope, windowMs = MAX_SLIDING_WINDOW_MS, timeoutMs = DEFAULT_TIMEOUT_MS, hooks = {}, report = createErrorReporter() }) {
    if (typeof scope !== 'string' || !SCOPE_RE.test(scope)) throw new TypeError('createPgSlidingLimiter: некорректное имя лимитера');
    if (!Number.isInteger(windowMs) || windowMs <= 0 || windowMs > MAX_SLIDING_WINDOW_MS || windowMs % SLIDING_BUCKET_MS !== 0) {
        throw new RangeError('createPgSlidingLimiter: окно — целое число минут, не больше часа');
    }
    const windowMinutes = windowMs / SLIDING_BUCKET_MS;
    const statementTimeout = Math.trunc(timeoutMs);
    if (!Number.isInteger(statementTimeout) || statementTimeout <= 0) throw new RangeError('createPgSlidingLimiter: timeoutMs должен быть целым > 0');

    async function tryConsume(lockKey, rules) {
        if (!Array.isArray(rules) || rules.length === 0) throw new TypeError('tryConsume: нужен хотя бы один лимит');
        const hexes = rules.map(rule => keys.digest(`${scope}-bucket`, rule.key).toString('hex'));
        if (new Set(hexes).size !== hexes.length) throw new TypeError('tryConsume: ключи правил должны различаться');
        const lock = keys.digest(`${scope}-lock`, lockKey).readInt32BE(0);

        let client;
        let broken = false;
        try {
            client = await acquireClient(pool, timeoutMs);
            await client.query(`BEGIN; SET LOCAL statement_timeout = ${statementTimeout}`);
            await client.query('SELECT pg_advisory_xact_lock($1::int, $2::int)', [ADVISORY_NAMESPACE, lock]);
            // Окно — последние windowMinutes корзин, считая текущую. Слот
            // освободится, когда самая старая корзина выйдет из окна.
            const { rows } = await client.query(
                `SELECT encode(k, 'hex') AS k, SUM(n)::int AS total,
                        (EXTRACT(EPOCH FROM (MIN(bucket) + $2::int * interval '1 minute' - now())) * 1000)::float8 AS wait_ms
                 FROM rl_buckets
                 WHERE k = ANY(SELECT decode(h, 'hex') FROM unnest($1::text[]) AS t(h))
                   AND bucket > date_trunc('minute', now()) - $2::int * interval '1 minute'
                 GROUP BY k`,
                [hexes, windowMinutes]
            );
            const byKey = new Map(rows.map(row => [row.k, row]));
            const waitMs = rules.map((rule, i) => {
                const row = byKey.get(hexes[i]);
                if (!row || row.total < rule.max) return 0;
                return Math.max(1000, Math.ceil(row.wait_ms));
            });
            const ok = waitMs.every(wait => wait === 0);
            if (ok) {
                await client.query(
                    `INSERT INTO rl_buckets (k, bucket, n)
                     SELECT decode(h, 'hex'), date_trunc('minute', now()), 1 FROM unnest($1::text[]) AS t(h)
                     ON CONFLICT (k, bucket) DO UPDATE SET n = rl_buckets.n + 1`,
                    [hexes]
                );
            }
            await client.query('COMMIT');
            return { ok, waitMs };
        } catch (err) {
            if (client) {
                try { await client.query('ROLLBACK'); } catch { broken = true; }
            }
            if (hooks.storeError) hooks.storeError(scope);
            const wrapped = new LimitStoreError('Корзины лимитов недоступны', err);
            report(scope, wrapped);
            throw wrapped;
        } finally {
            if (client) client.release(broken ? true : undefined);
        }
    }

    return { tryConsume };
}

// ---- Одноразовость решений PoW ----

// consume(tokenHash, expiresAtMs) → true, если решение предъявлено впервые.
function createPgPowUsedStore({ pool, timeoutMs = DEFAULT_TIMEOUT_MS, hooks = {}, report = createErrorReporter() }) {
    return {
        async consume(tokenHash, expiresAtMs) {
            try {
                const result = await withTimeout(pool.query(
                    `INSERT INTO pow_used (token_hash, expires_at)
                     VALUES ($1, to_timestamp($2::float8 / 1000))
                     ON CONFLICT (token_hash) DO NOTHING`,
                    [tokenHash, expiresAtMs]
                ), timeoutMs, 'запрос к pow_used');
                return result.rowCount === 1;
            } catch (err) {
                if (hooks.storeError) hooks.storeError('pow');
                const wrapped = new LimitStoreError('Хранилище решений PoW недоступно', err);
                report('pow', wrapped);
                throw wrapped;
            }
        },
    };
}

// ---- Уборка ----

// Удаляет просроченное; возвращает числа удалённых строк (для тестов и лога).
async function purgeExpiredLimits(pool) {
    const counters = await pool.query('DELETE FROM rl_counters WHERE reset_at <= now()');
    const buckets = await pool.query(
        `DELETE FROM rl_buckets WHERE bucket < date_trunc('minute', now()) - $1::float8 * interval '1 millisecond'`,
        [BUCKET_RETENTION_MS]
    );
    const pow = await pool.query(
        `DELETE FROM pow_used WHERE expires_at < now() - $1::float8 * interval '1 millisecond'`,
        [POW_RETENTION_MARGIN_MS]
    );
    return { counters: counters.rowCount, buckets: buckets.rowCount, pow: pow.rowCount };
}

// Задачи для реестра lib/jobs (JOB_MODULES): раз в минуту, под runExclusive —
// чистит один экземпляр на базу.
function jobs(ctx) {
    return [{
        name: 'purgeExpiredLimits',
        run: () => purgeExpiredLimits(ctx.pool),
        firstDelayMs: 60 * 1000,
        intervalMs: 60 * 1000,
        maintenance: true,
    }];
}

// ---- Сборка для сервера ----

// secret — SESSION_SECRET; hooks — { limited(scope), storeError(scope) }
// для метрик (lib/metrics.js), оба необязательны.
function createPgLimits({ pool, secret, hooks = {}, timeoutMs = DEFAULT_TIMEOUT_MS, report = createErrorReporter() }) {
    if (!pool || typeof pool.query !== 'function') throw new TypeError('createPgLimits: нужен pool');
    const keys = createLimitKeys(secret);
    return {
        keys,
        rateLimiter: (scope, options) => createPgRateLimiter({ pool, keys, scope, hooks, timeoutMs, report, ...options }),
        slidingLimiter: (scope, options = {}) => createPgSlidingLimiter({ pool, keys, scope, hooks, timeoutMs, report, ...options }),
        powUsedStore: () => createPgPowUsedStore({ pool, hooks, timeoutMs, report }),
    };
}

module.exports = {
    BUSY_RESPONSE,
    LimitStoreError,
    initPgLimitsSchema,
    createLimitKeys,
    createPgLimits,
    createPgRateLimitStore,
    createPgRateLimiter,
    createPgSlidingLimiter,
    createPgPowUsedStore,
    createErrorReporter,
    purgeExpiredLimits,
    jobs,
    respondBusy,
};
