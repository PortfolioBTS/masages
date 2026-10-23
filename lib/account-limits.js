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
//   UPLOAD_MIN_FREE_MB       - порог свободного места папки вложений: ниже - новые загрузки отклоняются.

const DEFAULTS = Object.freeze({
    REGISTER_GLOBAL_PER_MIN: 120,
    REGISTER_PACE_PER_MIN: 20,
    TEXT_QUOTA_MB_PER_DAY: 20,
    ROOMS_PER_USER_MAX: 50,
    UPLOAD_MIN_FREE_MB: 256,
});

function intOr(value, fallback) {
    const n = typeof value === 'string' && /^\d{1,9}$/.test(value.trim()) ? Number(value) : NaN;
    return Number.isInteger(n) && n >= 1 ? n : fallback;
}

function megabytesOr(value, fallbackMb) {
    const n = typeof value === 'string' && /^\d{1,9}(\.\d{1,6})?$/.test(value.trim()) ? Number(value) : NaN;
    return n > 0 ? n : fallbackMb;
}

function resolveAccountLimits(env = process.env) {
    return Object.freeze({
        registerGlobalPerMin: intOr(env.REGISTER_GLOBAL_PER_MIN, DEFAULTS.REGISTER_GLOBAL_PER_MIN),
        registerPacePerMin: intOr(env.REGISTER_PACE_PER_MIN, DEFAULTS.REGISTER_PACE_PER_MIN),
        // Счётчик в rl_counters.hits (INT): потолок - 2^31-1 байт.
        textQuotaBytesPerDay: Math.min(2147483647, Math.floor(megabytesOr(env.TEXT_QUOTA_MB_PER_DAY, DEFAULTS.TEXT_QUOTA_MB_PER_DAY) * 1024 * 1024)),
        roomsPerUserMax: intOr(env.ROOMS_PER_USER_MAX, DEFAULTS.ROOMS_PER_USER_MAX),
        uploadMinFreeBytes: Math.floor(megabytesOr(env.UPLOAD_MIN_FREE_MB, DEFAULTS.UPLOAD_MIN_FREE_MB) * 1024 * 1024),
    });
}

// Тексты отказов (клиент показывает message как есть).
const TEXT_QUOTA_MESSAGE = 'Суточный объём сообщений исчерпан. Продолжите позже: лимит обновляется в течение суток.';
const roomsLimitMessage = (max) => `Достигнут предел числа групп на аккаунте (${max}). Выйдите из ненужных групп.`;
const STORAGE_FULL_MESSAGE = 'Хранилище вложений почти заполнено. Отправка файлов временно недоступна.';

module.exports = { DEFAULTS, resolveAccountLimits, TEXT_QUOTA_MESSAGE, roomsLimitMessage, STORAGE_FULL_MESSAGE };
