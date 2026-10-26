'use strict';
// Проверка proof-of-work при регистрации (lib/pow.js) и ответ при отказе. Вынесено из server.js.

const { consumeSolution, BASE_DIFFICULTY, MAX_DIFFICULTY } = require('../../lib/pow');
// Темп регистраций -> добавка к сложности PoW (W7 R1 п.3).
const { createRegistrationPressure } = require('../../lib/registration-pressure');
// Точные лимиты и одноразовость PoW в Postgres (UNLOGGED-таблицы, ключи — HMAC).
const { LimitStoreError, respondBusy } = require('../../lib/pg-limits');
const { logError } = require('../../lib/log-error');

// Proof-of-work (lib/pow.js): решение одноразовое и привязано к цели.
// Цель одна — регистрация временного аккаунта; ?purpose=register — 400.
const POW_PURPOSES = new Set(['register-anon']);
const POW_FAILED_RESPONSE = { success: false, message: 'Не пройдена проверка proof-of-work', powRequired: true };

function createPow(ctx) {
    const { metrics, powUsedStore, ACCOUNT_LIMITS } = ctx;

    // Сложность растёт вместе с темпом удачных регистраций за минуту: при наплыве
    // ботов каждый новый аккаунт дороже (+1 бит на каждое удвоение темпа сверх обычного),
    // а при обычной нагрузке остаётся базовой (POW_DIFFICULTY, 18 бит).
    const registrationPressure = createRegistrationPressure({ pace: ACCOUNT_LIMITS.registerPacePerMin });
    function currentPowDifficulty() {
        return Math.min(MAX_DIFFICULTY, BASE_DIFFICULTY + registrationPressure.extraBits());
    }
    const noteRegistration = () => registrationPressure.note();

    // 'ok' | 'invalid' | 'replayed' | 'busy'. Задача сжигается в Postgres
    // (pow_used) только у решения, прошедшего проверку, — неверный nonce её не
    // тратит. Хранилище не отвечает — 'busy': регистрацию без проверки
    // одноразовости не пропускаем (лимит закрывается), а решение остаётся
    // несожжённым — клиент повторит его позже.
    async function checkPow(req, purpose) {
        const solution = req.body && req.body.pow;
        if (!solution || typeof solution !== 'object') return 'invalid';
        try {
            // Токен, выданный до наплыва по лёгкой цене, не принимается: клиент берёт новую задачу.
            return await consumeSolution(solution, purpose, powUsedStore, { minDifficulty: currentPowDifficulty() });
        } catch (err) {
            // Сбой хранилища уже записан в лог самим хранилищем.
            if (!(err instanceof LimitStoreError)) logError('[PoW] Ошибка проверки решения', err);
            return 'busy';
        }
    }

    function respondPowFailure(res, verdict) {
        metrics.powRejected(verdict);
        if (verdict === 'busy') return respondBusy(res);
        return res.json(POW_FAILED_RESPONSE);
    }

    return { checkPow, respondPowFailure, currentPowDifficulty, noteRegistration };
}

module.exports = { createPow, POW_PURPOSES };
