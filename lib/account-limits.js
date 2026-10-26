'use strict';
// Лимиты против массовых аккаунтов и разрастания хранилища (W7 R1 п.3). Значения читаются
// из окружения один раз при старте (src/config.js); неверные значения заменяются
// умолчаниями, а lib/env-check.js говорит оператору об этом предупреждением.
//
//   REGISTER_GLOBAL_PER_MIN  - потолок регистраций в минуту на весь сервер, в том числе onion
//                              (у onion один IP на всех, IP-лимит там не действует);
//   REGISTER_PACE_PER_MIN    - обычный темп регистраций: выше него растёт сложность PoW
//                              (+1 бит на каждое удвоение темпа, не больше +6);
//   TEXT_QUOTA_MB_PER_DAY    - суточный объём текста сообщений (конвертов) одного аккаунта;
//   ROOMS_PER_USER_MAX       - сколько комнат у одного аккаунта (создано и вступлений);
//   UPLOADS_IP_PER_MIN, UPLOADS_USER_PER_15MIN - выдача вложений (/uploads): запросов в минуту с одного IP и
//                              в 15 минут с одного аккаунта;
//   UPLOAD_MIN_FREE_MB       - порог свободного места папки вложений: ниже - новые загрузки отклоняются;
//   OPEN_UPLOADS_PER_10MIN   - открытых вложений (в чат с ботом) за 10 минут на аккаунт: каждое сервер разбирает сам
//                              (повторное ревью W7, Н0), поэтому частота ограничена до записи файла на диск.

const { knobValue, knobByName } = require('./numeric-knobs');

// Значения и их проверка — lib/numeric-knobs.js: тот же разбор, что у env-check (повторное ревью W7, Н2).
const LIMIT_KNOBS = [
    'REGISTER_GLOBAL_PER_MIN', 'REGISTER_PACE_PER_MIN', 'TEXT_QUOTA_MB_PER_DAY', 'ROOMS_PER_USER_MAX', 'UPLOAD_MIN_FREE_MB',
    'UPLOADS_IP_PER_MIN', 'UPLOADS_USER_PER_15MIN', 'OPEN_UPLOADS_PER_10MIN',
];
const DEFAULTS = Object.freeze(Object.fromEntries(LIMIT_KNOBS.map((name) => [name, knobByName(name).def])));

function resolveAccountLimits(env = process.env) {
    return Object.freeze({
        registerGlobalPerMin: knobValue(env, 'REGISTER_GLOBAL_PER_MIN'),
        registerPacePerMin: knobValue(env, 'REGISTER_PACE_PER_MIN'),
        // Счётчик в rl_counters.hits (INT): потолок - 2^31-1 байт.
        textQuotaBytesPerDay: Math.min(2147483647, Math.floor(knobValue(env, 'TEXT_QUOTA_MB_PER_DAY') * 1024 * 1024)),
        roomsPerUserMax: knobValue(env, 'ROOMS_PER_USER_MAX'),
        uploadMinFreeBytes: Math.floor(knobValue(env, 'UPLOAD_MIN_FREE_MB') * 1024 * 1024),
        uploadsIpPerMin: knobValue(env, 'UPLOADS_IP_PER_MIN'),
        uploadsUserPer15Min: knobValue(env, 'UPLOADS_USER_PER_15MIN'),
        openUploadsPer10Min: knobValue(env, 'OPEN_UPLOADS_PER_10MIN'),
    });
}

// Тексты отказов (клиент показывает message как есть).
const TEXT_QUOTA_MESSAGE = 'Суточный объём сообщений исчерпан. Продолжите позже: лимит обновляется в течение суток.';
const roomsLimitMessage = (max) => `Достигнут предел числа групп на аккаунте (${max}). Выйдите из ненужных групп.`;
const STORAGE_FULL_MESSAGE = 'Хранилище вложений почти заполнено. Отправка файлов временно недоступна.';
const openUploadsLimitMessage = (max) => `Слишком много файлов в чат с ботом: не больше ${max} за 10 минут. Повторите позже.`;

module.exports = {
    DEFAULTS, resolveAccountLimits, TEXT_QUOTA_MESSAGE, roomsLimitMessage, STORAGE_FULL_MESSAGE, openUploadsLimitMessage,
};
