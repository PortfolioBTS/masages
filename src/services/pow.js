'use strict';
// Проверка proof-of-work при регистрации (lib/pow.js) и ответ при отказе. Вынесено из server.js.

const { consumeSolution } = require('../../lib/pow');
// Точные лимиты и одноразовость PoW в Postgres (UNLOGGED-таблицы, ключи — HMAC).
const { LimitStoreError, respondBusy } = require('../../lib/pg-limits');
const { logError } = require('../../lib/log-error');

// Proof-of-work (lib/pow.js): решение одноразовое и привязано к цели.
// Цель одна — регистрация временного аккаунта; ?purpose=register — 400.
const POW_PURPOSES = new Set(['register-anon']);
const POW_FAILED_RESPONSE = { success: false, message: 'Не пройдена проверка proof-of-work', powRequired: true };

function createPow(ctx) {
    const { metrics, powUsedStore } = ctx;

    // 'ok' | 'invalid' | 'replayed' | 'busy'. Задача сжигается в Postgres
    // (pow_used) только у решения, прошедшего проверку, — неверный nonce её не
    // тратит. Хранилище не отвечает — 'busy': регистрацию без проверки
    // одноразовости не пропускаем (лимит закрывается), а решение остаётся
    // несожжённым — клиент повторит его позже.
    async function checkPow(req, purpose) {
        const solution = req.body && req.body.pow;
        if (!solution || typeof solution !== 'object') return 'invalid';
        try {
            return await consumeSolution(solution, purpose, powUsedStore);
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

    return { checkPow, respondPowFailure };
}

module.exports = { createPow, POW_PURPOSES };
