'use strict';
// Разбор id из запроса (W7 R1 п.7, R2.7). Один разбор на все маршруты: раньше Number(value) пускал
// и '1e3', и '0x10', и ' 5', не имел верхней границы (id больше INTEGER доходил до Postgres и
// давал 22003 -> 500), а Number({ toString: 1 }) бросал TypeError (500 на вложенном объекте в теле).

// Наибольшее значение INTEGER в Postgres: id таблиц - serial, курсоры - integer.
const PG_INT_MAX = 2147483647;

// Положительное целое 1..PG_INT_MAX или null. Принимаются только число (целое) и строка из
// десятичных цифр; всё остальное (объект, массив, boolean, null, '1e3', '0x10', ' 5', '5.0') - null.
function toPositiveInt(value) {
    let n;
    if (typeof value === 'number') n = value;
    else if (typeof value === 'string' && /^\d{1,10}$/.test(value)) n = Number(value);
    else return null;
    return Number.isInteger(n) && n >= 1 && n <= PG_INT_MAX ? n : null;
}

module.exports = { PG_INT_MAX, toPositiveInt };
