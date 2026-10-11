'use strict';
// Общий признак версии клиента `proto` (docs/security/message-ordering.md, 14.1).
//
// Волна 4 меняет контракт нескольких изменяющих запросов сразу (отправка в
// комнату, ключи, сертификаты состава, журнал ключей). Вместо отдельных
// маркеров на каждый запрос все такие запросы несут одно целое поле `proto`.
// Нет поля, оно не целое или меньше PROTO_MIN — 400 client-outdated
// (CLIENT_OUTDATED из lib/message-ids.js): старая вкладка получает одну
// понятную ошибку «Обновите страницу». Значение больше PROTO_CURRENT принимается.
//
// Клиент берёт значение из одной константы (PROTO_VERSION в public/script.js),
// сервер — отсюда; test/proto.test.js сверяет, что они равны. Менять признак
// можно только вместе с несовместным изменением контракта.
//
// Для multipart/form-data (POST /api/messages/file) поле приходит строкой и
// проверяется в fileFilter multer до приёма файла: клиент кладёт `proto` в
// FormData ДО поля file.

const PROTO_CURRENT = 4;
const PROTO_MIN = 4;

// Целое 0..999 из числа или из строки цифр (поле формы); иначе null. Длина
// ограничена, чтобы "99999999999999999999" не превратилось в Infinity-подобное
// значение «новее всех».
function parseProto(value) {
    if (typeof value === 'number') return Number.isInteger(value) && value >= 0 && value <= 999 ? value : null;
    if (typeof value === 'string' && /^\d{1,3}$/.test(value)) return Number(value);
    return null;
}

// true — клиент слишком старый (или не прислал признак вовсе).
function isClientOutdated(value) {
    const proto = parseProto(value);
    return proto === null || proto < PROTO_MIN;
}

module.exports = { PROTO_CURRENT, PROTO_MIN, parseProto, isClientOutdated };
