'use strict';
// Давление регистраций: сколько аккаунтов создано за последнюю минуту и насколько из-за
// этого поднять сложность proof-of-work (W7 R1 п.3). Считаются только УДАЧНЫЕ регистрации:
// запросы задач (GET /api/pow/challenge) дёшевы, и по ним любой поднял бы сложность всем.
// Состояние в памяти процесса (реплика одна, docs/ops/scaling.md): после рестарта счёт
// обнуляется, а жёсткий потолок регистраций в минуту живёт в Postgres (rate-limits.js).

const WINDOW_MS = 60 * 1000;
const MAX_EXTRA_BITS = 6;

function createRegistrationPressure({ pace, windowMs = WINDOW_MS, now = Date.now }) {
    const times = [];
    function prune() {
        const edge = now() - windowMs;
        while (times.length > 0 && times[0] <= edge) times.shift();
    }
    return {
        note() {
            times.push(now());
            prune();
        },
        count() {
            prune();
            return times.length;
        },
        // Ниже обычного темпа - 0; на уровне pace - 1 бит; каждое удвоение темпа - ещё бит.
        // Бит удваивает цену аккаунта для бота: +3 бита (темп x4) - в 8 раз дороже.
        extraBits() {
            prune();
            if (times.length < pace) return 0;
            return Math.min(MAX_EXTRA_BITS, 1 + Math.floor(Math.log2(times.length / pace)));
        },
    };
}

module.exports = { createRegistrationPressure, MAX_EXTRA_BITS, WINDOW_MS };
