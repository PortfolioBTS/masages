'use strict';
// Пул соединений с Postgres: проверка TLS-настроек базы, DB_POOL_CONFIG (общие параметры для
// основного пула и служебных), пул и три помощника dbGet/dbAll/dbRun. Вынесено из server.js.

const { Pool } = require('pg');
const { resolveDbTlsConfig } = require('../../lib/security-utils');
const { logError } = require('../../lib/log-error');
const { NUMERIC_KNOBS } = require('../../lib/env-check');

// Таймауты сессии Postgres (ревью W7 R2.4) — параметрами соединения, у каждой сессии пулов
// сервера. Без них один долгий замок (зависшая транзакция, блокировка строки комнаты) держал
// все соединения пула: запросы вставали в очередь за ним, и даже посторонний GET /api/auth
// ждал 10 с и получал 500.
//   * lock_timeout — сколько запрос ждёт блокировку; дальше 55P03, клиенту 503 busy;
//   * statement_timeout — предел одного запроса (57014);
//   * idle_in_transaction_session_timeout — открытая и брошенная транзакция (код, который
//     ждёт чего-то вне базы с BEGIN) не держит блокировки дольше этого срока.
// Миграции снимают их у своих сессий сами (lib/advisory-locks.js). Значения — DB_*_TIMEOUT_MS;
// вне диапазона lib/env-check.js (NUMERIC_KNOBS) — умолчание (env-check об этом предупреждает).
const SESSION_TIMEOUTS = [
    ['statement_timeout', 'DB_STATEMENT_TIMEOUT_MS'],
    ['lock_timeout', 'DB_LOCK_TIMEOUT_MS'],
    ['idle_in_transaction_session_timeout', 'DB_IDLE_TX_TIMEOUT_MS'],
];

function resolveDbSessionTimeouts(env = process.env) {
    const timeouts = {};
    for (const [param, name] of SESSION_TIMEOUTS) {
        const knob = NUMERIC_KNOBS.find(k => k.name === name);
        const raw = typeof env[name] === 'string' ? env[name].trim() : '';
        const value = Number(raw);
        timeouts[param] = raw !== '' && Number.isInteger(value) && value >= knob.min && value <= knob.max ? value : knob.def;
    }
    return timeouts;
}

function createPool(ctx) {
    const { metrics, io } = ctx;

    // TLS до Postgres (см. resolveDbTlsConfig): в production без DB_CA_CERT
    // сервер стартует только в приватной сети Railway или с явным
    // DB_TLS_INSECURE=true. Исключение — DUMP_CA=true: этот режим как раз и
    // нужен, чтобы получить цепочку для DB_CA_CERT, и пулом он не пользуется.
    const dbTls = resolveDbTlsConfig({
        nodeEnv: process.env.NODE_ENV,
        databaseUrl: process.env.DATABASE_URL,
        caCert: process.env.DB_CA_CERT,
        insecure: process.env.DB_TLS_INSECURE === 'true',
    });
    if (dbTls.error && process.env.DUMP_CA !== 'true') {
        console.error(dbTls.error);
        process.exit(1);
    }
    if (dbTls.info) console.log(dbTls.info);
    if (dbTls.warning) console.warn(dbTls.warning);
    const sslConfig = dbTls.ssl;

    // Параметры подключения — общие для основного пула и служебных (пул
    // миграций и пул блокировок фоновых задач, см. lib/advisory-locks.js).
    const DB_POOL_CONFIG = {
        connectionString: process.env.DATABASE_URL,
        ssl: sslConfig,
        max: Number(process.env.PG_POOL_MAX) || 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
        ...resolveDbSessionTimeouts(process.env),
    };
    const pool = new Pool(DB_POOL_CONFIG);
    metrics.attachRuntime({ pool, io });
    // Без обработчика 'error' обрыв простаивающего соединения (рестарт или
    // failover Postgres, сетевой сбой) — необработанное событие 'error',
    // которое завершает весь процесс.
    pool.on('error', (err) => {
        logError('[DB] Ошибка простаивающего соединения', err);
    });

    async function dbGet(query, params = []) {
        const result = await pool.query(query, params);
        return result.rows[0] || null;
    }

    async function dbAll(query, params = []) {
        const result = await pool.query(query, params);
        return result.rows;
    }

    async function dbRun(query, params = []) {
        const result = await pool.query(query, params);
        return result;
    }

    return { DB_POOL_CONFIG, pool, dbGet, dbAll, dbRun };
}

module.exports = { createPool, resolveDbSessionTimeouts };
