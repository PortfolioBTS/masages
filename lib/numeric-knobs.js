'use strict';
// Числовые настройки лимитов сервера (T7.2) и их единый разбор (повторное ревью W7, Н2).
//
// Значение — целое (или число в мегабайтах у float) в диапазоне [min, max]; иначе берётся умолчание def. Раньше
// lib/env-check.js и модули сервера разбирали одни и те же переменные по-разному: env-check писал «будет использовано
// умолчание», а сервер брал значение как есть (и наоборот). Теперь и env-check (предупреждение), и сервер
// (knobValue) идут через parseKnob: что названо в предупреждении, то сервер и берёт.
// Новые лимиты дописываются сюда же, в .env.example и docs/ops/deploy-railway.md (test/env-check-limits.test.js).

const NUMERIC_KNOBS = Object.freeze([
    { name: 'IMAGE_MAX_PIXELS', min: 100000, max: 268000000, def: 24000000, note: 'предел пикселей изображения при очистке метаданных (у анимации - на все кадры)' },
    { name: 'IMAGE_MAX_FRAMES', min: 1, max: 10000, def: 500, note: 'предел кадров GIF/WebP' },
    { name: 'UPLOAD_PROCESS_CONCURRENCY', min: 1, max: 8, def: 1, note: 'сколько вложений обрабатывается одновременно' },
    { name: 'REGISTER_GLOBAL_PER_MIN', min: 1, max: 100000, def: 120, note: 'потолок регистраций в минуту на весь сервер, в том числе через onion' },
    { name: 'REGISTER_PACE_PER_MIN', min: 1, max: 100000, def: 20, note: 'обычный темп регистраций в минуту: выше него растёт сложность proof-of-work' },
    { name: 'TEXT_QUOTA_MB_PER_DAY', min: 0.001, max: 2000, def: 20, float: true, note: 'суточный объём текста сообщений на аккаунт, МБ' },
    { name: 'ROOMS_PER_USER_MAX', min: 1, max: 100000, def: 50, note: 'сколько комнат может быть у одного аккаунта' },
    { name: 'UPLOAD_MIN_FREE_MB', min: 0.001, max: 1000000000, def: 256, float: true, note: 'порог свободного места папки вложений, МБ: ниже - новые загрузки отклоняются' },
    { name: 'UPLOADS_IP_PER_MIN', min: 10, max: 1000000, def: 600, note: 'запросов выдачи вложений в минуту с одного IP (до загрузки сессии)' },
    { name: 'UPLOADS_USER_PER_15MIN', min: 10, max: 10000000, def: 3000, note: 'запросов выдачи вложений за 15 минут с одного аккаунта' },
    { name: 'OPEN_UPLOADS_PER_10MIN', min: 1, max: 100000, def: 20, note: 'открытых вложений (в чат с ботом) за 10 минут на аккаунт; проверяется до записи файла на диск' },
    { name: 'SOCKET_EVENT_RATE', min: 1, max: 1000, def: 5, note: 'событий в секунду от одного сокета в среднем; превышение закрывает сокет' },
    { name: 'SOCKET_EVENT_BURST', min: 1, max: 10000, def: 20, note: 'всплеск событий сокета' },
    { name: 'UPLOAD_PROCESS_QUEUE', min: 0, max: 100, def: 4, note: 'сколько вложений ждёт очереди обработки (дальше - 503)' },
    // Таймауты сессии Postgres (W7 R2.4, src/db/pool.js): у миграций свои (lib/advisory-locks.js).
    { name: 'DB_STATEMENT_TIMEOUT_MS', min: 1000, max: 600000, def: 30000, note: 'предел времени одного запроса к базе, мс' },
    { name: 'DB_LOCK_TIMEOUT_MS', min: 100, max: 600000, def: 5000, note: 'сколько запрос ждёт блокировку строки или таблицы, мс' },
    { name: 'DB_IDLE_TX_TIMEOUT_MS', min: 1000, max: 3600000, def: 30000, note: 'предел простоя открытой транзакции, мс' },
].map(Object.freeze));

const BY_NAME = new Map(NUMERIC_KNOBS.map((knob) => [knob.name, knob]));

// Только десятичная запись: Number() принял бы и '1e3', и '0x10'. Дробное — только у настроек в мегабайтах.
const INT_RE = /^\d{1,9}$/;
const FLOAT_RE = /^\d{1,10}(\.\d{1,6})?$/;

function knobByName(name) {
    const knob = BY_NAME.get(name);
    if (!knob) throw new Error(`Нет числовой настройки ${name}`);
    return knob;
}

// Число из строки окружения или null (переменной нет либо значение негодно — тогда действует def).
function parseKnob(knob, raw) {
    const text = typeof raw === 'string' ? raw.trim() : '';
    if (!text || !(knob.float ? FLOAT_RE : INT_RE).test(text)) return null;
    const n = Number(text);
    return n >= knob.min && n <= knob.max ? n : null;
}

// Значение, которое берёт сервер: из окружения или умолчание.
function knobValue(env, name) {
    const knob = knobByName(name);
    const parsed = parseKnob(knob, env ? env[name] : undefined);
    return parsed === null ? knob.def : parsed;
}

module.exports = { NUMERIC_KNOBS, parseKnob, knobValue, knobByName };
