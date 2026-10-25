'use strict';
// Разбор значений запроса: непустая строка и положительное целое. Вынесено из server.js.
// toPositiveInt - в lib/ids.js (его же используют маршруты из lib/): только число или строка из
// цифр, не больше 2147483647 (INTEGER в Postgres).

const { toPositiveInt } = require('../../lib/ids');

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

module.exports = { toPositiveInt, isNonEmptyString };
