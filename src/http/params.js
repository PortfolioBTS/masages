'use strict';
// Разбор значений запроса: непустая строка и положительное целое. Вынесено из server.js.

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';
const toPositiveInt = (value) => {
    const n = Number(value);
    return Number.isInteger(n) && n > 0 ? n : null;
};

module.exports = { toPositiveInt, isNonEmptyString };
