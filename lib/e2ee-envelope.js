'use strict';
// Форма E2EE-конверта (R7, план криптографии, раздел 3). Сервер не может
// расшифровать сообщение, но обязан не принимать в комнату ничего, кроме
// конверта, который выпускает клиент (public/e2ee.js, encryptOutgoing):
//
//   { v:2, alg:'senderkey-v2', senderKeyId, iteration, iv, ct, sig }
//
// Без этой проверки «шифрованным» мог назваться любой открытый текст: флаг
// encrypted присылает сам клиент. Проверка только формы — подлинность и
// расшифровку по-прежнему проверяют получатели.
//
// * v === 2 и alg === 'senderkey-v2'; v1 для новых сообщений запрещён;
// * senderKeyId — base64 ровно 16 байт (24 символа);
// * iteration — целое от 0 до 2^32-1;
// * iv — base64 ровно 12 байт (16 символов);
// * sig — base64 ровно 64 байта (88 символов);
// * ct — base64 не короче 272 байт: 256 байт минимума дополнения Padmé
//   (MSG_PAD_MIN в e2ee.js) плюс 16 байт тега AES-GCM;
// * других ключей верхнего уровня нет, и все перечисленные есть;
// * вся строка не длиннее 12000 символов.
//
// base64 — каноническое (стандартный алфавит, с '=' и нулевыми лишними
// битами): клиент сравнивает ключи и подписи строками, поэтому несколько
// написаний одних и тех же байт не нужны.

const MAX_ENVELOPE_LENGTH = 12000;
const KEY_ID_BYTES = 16;
const IV_BYTES = 12;
const SIG_BYTES = 64;
const MIN_CT_BYTES = 272;
const MAX_ITERATION = 0xFFFFFFFF;

const ENVELOPE_KEYS = Object.freeze(['alg', 'ct', 'iteration', 'iv', 'senderKeyId', 'sig', 'v']);
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

// Байты канонического base64 или null. Buffer.from(…, 'base64') снисходителен
// (пропускает чужие символы и недостающие '='), поэтому результат
// кодируется обратно и сравнивается со входом: совпало — написание единственное.
function decodeCanonicalBase64(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 || !BASE64_RE.test(value)) return null;
    const bytes = Buffer.from(value, 'base64');
    return bytes.toString('base64') === value ? bytes : null;
}

function hasBytes(value, length) {
    const bytes = decodeCanonicalBase64(value);
    return bytes !== null && bytes.length === length;
}

// true — text это JSON-конверт senderkey-v2 правильной формы.
function isE2eeEnvelopeShape(text) {
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_ENVELOPE_LENGTH) return false;
    let envelope;
    try {
        envelope = JSON.parse(text);
    } catch {
        return false;
    }
    if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) return false;

    // Ровно семь ключей: лишний ключ верхнего уровня — это место, куда можно
    // положить открытый текст или метку, которую сервер потом сохранит.
    const keys = Object.keys(envelope).sort();
    if (keys.length !== ENVELOPE_KEYS.length || keys.some((key, i) => key !== ENVELOPE_KEYS[i])) return false;

    if (envelope.v !== 2 || envelope.alg !== 'senderkey-v2') return false;
    if (!hasBytes(envelope.senderKeyId, KEY_ID_BYTES)) return false;
    if (!Number.isInteger(envelope.iteration) || envelope.iteration < 0 || envelope.iteration > MAX_ITERATION) return false;
    if (!hasBytes(envelope.iv, IV_BYTES)) return false;
    if (!hasBytes(envelope.sig, SIG_BYTES)) return false;
    const ct = decodeCanonicalBase64(envelope.ct);
    return ct !== null && ct.length >= MIN_CT_BYTES;
}

// Тела ответов 400: { success:false, code, message } (message-ordering.md, раздел 14).
// Тексты видит пользователь старой вкладки, поэтому в них — что сделать.
const E2EE_REQUIRED = Object.freeze({
    success: false,
    code: 'e2ee-required',
    message: 'Обновите страницу: в группах сообщения отправляются только со сквозным шифрованием',
});
const BAD_ENVELOPE = Object.freeze({
    success: false,
    code: 'bad-envelope',
    message: 'Обновите страницу: сообщение зашифровано в неверном формате',
});
// Чат с ботом: расшифровать конверт там некому.
const E2EE_NOT_ALLOWED = Object.freeze({
    success: false,
    code: 'e2ee-not-allowed',
    message: 'В чате с ботом сообщения не шифруются: отправьте обычный текст',
});

module.exports = {
    MAX_ENVELOPE_LENGTH,
    MIN_CT_BYTES,
    isE2eeEnvelopeShape,
    E2EE_REQUIRED,
    BAD_ENVELOPE,
    E2EE_NOT_ALLOWED,
};
