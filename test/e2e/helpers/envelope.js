'use strict';
// Поддельные E2EE-конверты для сквозных тестов сервера (R7).
//
// Сервер принимает в комнату только конверт правильной формы
// (lib/e2ee-envelope.js), но расшифровать его не может, поэтому настоящая
// криптография тестам сервера не нужна. fakeEnvelope(метка) даёт конверт с
// верными длинами и каноническим base64, детерминированный по метке: одна и та
// же метка — один и тот же текст (повтор запроса идемпотентен, разные метки —
// разное содержимое, как у настоящих сообщений). Метка лежит внутри ct,
// поэтому labelOf() возвращает её обратно — тест проверяет, что сервер отдал
// именно то, что приняла.

const crypto = require('crypto');

const MIN_CT_BYTES = 272;

function fakeEnvelope(label, { iteration = 0 } = {}) {
    const text = String(label);
    const digest = crypto.createHash('sha512').update(text).digest();
    const labelBytes = Buffer.from(text, 'utf8');
    const ct = Buffer.alloc(Math.max(MIN_CT_BYTES, 4 + labelBytes.length));
    ct.writeUInt32BE(labelBytes.length, 0);
    labelBytes.copy(ct, 4);
    return JSON.stringify({
        v: 2, alg: 'senderkey-v2',
        senderKeyId: digest.subarray(0, 16).toString('base64'),
        iteration,
        iv: digest.subarray(16, 28).toString('base64'),
        ct: ct.toString('base64'),
        sig: digest.subarray(0, 64).toString('base64'),
    });
}

// Метка из конверта, собранного fakeEnvelope; null — это не он.
function labelOf(envelopeText) {
    try {
        const ct = Buffer.from(JSON.parse(envelopeText).ct, 'base64');
        return ct.subarray(4, 4 + ct.readUInt32BE(0)).toString('utf8');
    } catch {
        return null;
    }
}

module.exports = { fakeEnvelope, labelOf, MIN_CT_BYTES };
