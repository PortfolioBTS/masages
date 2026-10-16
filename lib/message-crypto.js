// Шифрование текста сообщений "на лету" перед записью в БД (encryption at
// rest). Ключи живут только в переменных окружения на сервере — в самой БД
// (и в любом её бэкапе/дампе/утечке) остаётся только шифротекст.
//
// Два формата записи:
//
//   enc:v3:<kid>:<iv>:<tag>:<ct> — СТРОКИ КОМНАТ (docs/security/sealed-sender.md,
//     раздел 7). Шифруется не сам MESSAGE_ENCRYPTION_KEY, а производный ключ
//     K_enc3 = HKDF-SHA256(ключ, "nyxo-msg-enc-v3"): один исходный ключ не
//     работает напрямую в трёх ролях (enc:v2 бота, тег автора, enc:v3). AAD —
//     messageAadV3: комната, id сообщения и author_tag строки. Пользователя в
//     AAD нет: в строке комнаты нет user_id, автора знает только клиент.
//   enc:v2:<kid>:<iv>:<tag>:<ct> — только ЧАТ С БОТОМ (сырой ключ, AAD
//     "nyxo:msg:v2:chat=<c>:user=<u>"). Для комнат v2 больше не пишется и не
//     читается.
//
//   kid — первые 8 hex SHA-256 исходного ключа. По нему при чтении выбирается
//         ключ: текущий MESSAGE_ENCRYPTION_KEY или один из
//         MESSAGE_ENCRYPTION_KEY_PREVIOUS (через запятую, только для
//         расшифровки). Так ключ можно сменить без одномоментной
//         перешифровки всей таблицы: новые записи идут под новым ключом,
//         старые читаются старым, пока он указан в PREVIOUS. Но для строк
//         комнат тег автора и AAD тоже зависят от ключа: полная смена ключа —
//         процедура docs/ops/message-key-rotation.md (scripts/retag-messages.js).
//   iv/tag/ct — base64; AES-256-GCM, 12-байтный nonce, 16-байтный тег.
//   Без AAD запись не шифруется и не расшифровывается вовсе (исключение, а не
//   молчаливое шифрование без привязки).
// Старый формат enc:v1:<iv>:<tag>:<ct> (без kid и без AAD) и строки без
// префикса читает только decryptText — для чата с ботом; в комнате запись без
// префикса enc:v3 — всегда "[Не удалось расшифровать]": иначе записывающий в БД
// подложил бы открытый текст или перенёс старую запись (decryptRoomText).
//
// ВАЖНО — что это защищает, а что нет:
//   ✅ Дамп/бэкап базы, утечка у хостера БД, кто-то с read-доступом к Postgres —
//      видит только "enc:v3:...", без ключа это бессмысленный набор байт.
//   ✅ Подмену при записи в БД (v3): шифротекст, перенесённый в другую комнату,
//      под другой id или под другой author_tag, не расшифруется — вместо чужого
//      текста будет "[Не удалось расшифровать]". В v2 перенос внутри комнаты
//      был возможен (id при INSERT был неизвестен).
//   ❌ Удаление строк, откат БД к старому бэкапу и смену seq (его в AAD нет).
//   ❌ Компрометацию самого сервера приложения: у кого есть переменные
//      окружения и доступ к процессу, тот расшифрует всё точно так же, как
//      это делает сам сервер при каждом чтении, и вычислит любой author_tag.
//      Это шифрование "на стороне сервера", а не end-to-end. "Не может
//      прочитать никто, включая нас" — это E2EE (public/e2ee.js): у таких
//      сообщений здесь шифруется уже непрозрачный для сервера конверт.

const crypto = require('crypto');
const { deriveKey } = require('./derive-key');
const { logError } = require('./log-error');

const ALGORITHM = 'aes-256-gcm';
const PREFIX_V1 = 'enc:v1:';
const PREFIX_V2 = 'enc:v2:';
const PREFIX_V3 = 'enc:v3:';
// Метка вывода ключа шифрования строк комнат (sealed-sender.md, 6.4): ровно одна
// цель, другим выводам (тег автора, квота) эта метка не служит.
const LABEL_ENC3 = 'nyxo-msg-enc-v3';
const IV_BYTES = 12; // рекомендованный размер nonce для GCM
const TAG_BYTES = 16;
const DECRYPT_FAILED = '[Не удалось расшифровать]';

const KEY_HINT =
    'Сгенерируй ключ командой:\n' +
    '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"\n' +
    'и добавь его в .env / переменные окружения перед запуском сервера.';

function parseKey(raw, envName) {
    const key = Buffer.from(raw.trim(), 'base64');
    if (key.length !== 32) {
        throw new Error(`${envName}: каждый ключ должен декодироваться из base64 ровно в 32 байта (256 бит). ${KEY_HINT}`);
    }
    return key;
}

function keyId(key) {
    return crypto.createHash('sha256').update(key).digest('hex').slice(0, 8);
}

function loadKeys() {
    const raw = process.env.MESSAGE_ENCRYPTION_KEY;
    if (!raw) throw new Error(`MESSAGE_ENCRYPTION_KEY не задан. ${KEY_HINT}`);
    const current = parseKey(raw, 'MESSAGE_ENCRYPTION_KEY');
    const previous = (process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
        .map(s => parseKey(s, 'MESSAGE_ENCRYPTION_KEY_PREVIOUS'));

    const byKid = new Map();
    const enc3ByKid = new Map();
    const all = [];
    for (const key of [current, ...previous]) {
        const kid = keyId(key);
        const known = byKid.get(kid);
        if (known) {
            if (known.equals(key)) continue; // тот же ключ указан дважды — не страшно
            // 32 бита kid: совпадение у двух разных ключей почти невероятно,
            // но если случилось — по kid нельзя однозначно выбрать ключ.
            throw new Error('Два разных ключа сообщений дают одинаковый kid — сгенерируй новый MESSAGE_ENCRYPTION_KEY.');
        }
        byKid.set(kid, key);
        // HKDF берёт 32 байта после parseKey (а не текст переменной окружения):
        // так K_enc3 совпадает с контрольным вектором документа.
        enc3ByKid.set(kid, deriveKey(key, LABEL_ENC3));
        all.push(key);
    }
    return { current, currentKid: keyId(current), byKid, enc3ByKid, all };
}

// Ключи читаются один раз при старте процесса — если они невалидны, сервер
// не должен подниматься и молча писать сообщения в открытом виде (fail
// closed, а не fail open).
const KEYS = loadKeys();

function requireAad(aad) {
    if (typeof aad !== 'string' || aad === '') {
        // Ошибка программиста, а не данных: v2 без привязки к месту хранения
        // терял бы весь смысл, поэтому падаем громко, а не шифруем "как-нибудь".
        throw new Error('[MessageCrypto] Для enc:v2 обязателен AAD — передай messageAad(message).');
    }
    return Buffer.from(aad, 'utf8');
}

// Приводит id к положительному целому. pg отдаёт INTEGER числом, параметры
// маршрутов приходят строкой — AAD от обоих должен совпадать. Мусор — это
// ошибка вызывающего кода, а не "нет значения".
function normalizeId(value, field) {
    if (value === null || value === undefined) return null;
    const n = typeof value === 'number' ? value
        : (typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : NaN);
    if (!Number.isSafeInteger(n) || n <= 0) throw new TypeError(`messageAad: некорректный ${field}`);
    return n;
}

// AAD записи enc:v2 — ТОЛЬКО чат с ботом: чат и владелец. Сообщения комнат
// шифруются enc:v3 (messageAadV3): в строке комнаты нет user_id.
function messageAad(message) {
    const { room_id, chat_id, user_id } = message || {};
    if (normalizeId(room_id, 'room_id') !== null) {
        throw new TypeError('messageAad: сообщения комнат шифруются enc:v3 (messageAadV3)');
    }
    const user = normalizeId(user_id, 'user_id');
    if (user === null) throw new TypeError('messageAad: нужен user_id');
    const chat = normalizeId(chat_id, 'chat_id');
    if (chat !== null) return `nyxo:msg:v2:chat=${chat}:user=${user}`;
    throw new TypeError('messageAad: нужен chat_id');
}

// author_tag строки комнаты → 32 строчных hex-символа. pg отдаёт BYTEA как
// Buffer; строка принимается только в этом же виде (регистр и длина — часть
// AAD, нестрогий разбор дал бы два разных AAD для одного тега).
function tagHex(authorTag) {
    if (Buffer.isBuffer(authorTag)) {
        if (authorTag.length !== 16) throw new TypeError('messageAadV3: author_tag — ровно 16 байт');
        return authorTag.toString('hex');
    }
    if (typeof authorTag === 'string' && /^[0-9a-f]{32}$/.test(authorTag)) return authorTag;
    throw new TypeError('messageAadV3: author_tag — 16 байт или 32 строчных hex-символа');
}

const AAD_V3_RE = /^nyxo:msg:v3:room=[1-9]\d*:id=[1-9]\d*:tag=[0-9a-f]{32}$/;

// AAD записи enc:v3 (sealed-sender.md, раздел 7):
//   nyxo:msg:v3:room=<room_id>:id=<id>:tag=<author_tag_hex>
// room_id и id — десятичные без ведущих нулей. Пользователь и chat_id не входят:
// шифротекст привязан к комнате, к строке и к псевдониму автора, но не к
// учётной записи. Тег берётся ИЗ строки (при правке он не пересчитывается).
function messageAadV3(message) {
    const { room_id, id, author_tag } = message || {};
    const room = normalizeId(room_id, 'room_id');
    const messageId = normalizeId(id, 'id');
    if (room === null) throw new TypeError('messageAadV3: нужен room_id');
    if (messageId === null) throw new TypeError('messageAadV3: нужен id');
    return `nyxo:msg:v3:room=${room}:id=${messageId}:tag=${tagHex(author_tag)}`;
}

function requireAadV3(aad) {
    if (typeof aad !== 'string' || !AAD_V3_RE.test(aad)) {
        throw new Error('[MessageCrypto] Для enc:v3 обязателен AAD — передай messageAadV3(row).');
    }
    return Buffer.from(aad, 'utf8');
}

function sealGcm(key, kid, prefix, plainText, aadBytes) {
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(aadBytes);
    const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
    return prefix + [
        kid,
        iv.toString('base64'),
        cipher.getAuthTag().toString('base64'),
        encrypted.toString('base64'),
    ].join(':');
}

// Шифрует текст ЧАТА С БОТОМ (enc:v2) перед вставкой в БД. null/undefined
// проходят насквозь — это осознанные "пустые" значения полей, а не текст
// сообщения.
function encryptText(plainText, aad) {
    if (plainText === null || plainText === undefined) return plainText;
    const aadBytes = requireAad(aad);
    return sealGcm(KEYS.current, KEYS.currentKid, PREFIX_V2, plainText, aadBytes);
}

// Шифрует текст строки КОМНАТЫ (enc:v3) на ключе K_enc3 текущего
// MESSAGE_ENCRYPTION_KEY. aad — messageAadV3(строка): id и author_tag известны
// до вставки (id выбирает клиент, тег считает приложение от того же created_at).
function encryptRoomText(plainText, aad) {
    if (plainText === null || plainText === undefined) return plainText;
    const aadBytes = requireAadV3(aad);
    return sealGcm(KEYS.enc3ByKid.get(KEYS.currentKid), KEYS.currentKid, PREFIX_V3, plainText, aadBytes);
}

function gcmDecrypt(key, ivB64, tagB64, dataB64, aadBytes) {
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    // Длина тега проверяется явно (и задана в authTagLength): иначе GCM
    // принял бы и укороченный тег, а подделать 4-байтный тег несложно.
    if (iv.length !== IV_BYTES || authTag.length !== TAG_BYTES) {
        throw new Error('некорректная длина nonce или тега');
    }
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
    if (aadBytes) decipher.setAAD(aadBytes);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}

// body — запись без префикса: <kid>:<iv>:<tag>:<ct>; keys — kid → ключ шифрования.
function decryptSealed(body, aadBytes, keys, label) {
    const parts = body.split(':');
    if (parts.length !== 4) throw new Error(`некорректный формат ${label}`);
    const [kid, ivB64, tagB64, dataB64] = parts;
    const key = keys.get(kid);
    if (!key) {
        throw new Error(`нет ключа с kid=${kid} ни в MESSAGE_ENCRYPTION_KEY, ни в MESSAGE_ENCRYPTION_KEY_PREVIOUS`);
    }
    return gcmDecrypt(key, ivB64, tagB64, dataB64, aadBytes);
}

// v1 не хранит kid: пробуем текущий ключ, затем предыдущие. Неверный ключ
// GCM гарантированно отвергает по тегу, так что "не тот" ключ не выдаст мусор.
function decryptV1(body) {
    const parts = body.split(':');
    if (parts.length !== 3) throw new Error('некорректный формат enc:v1');
    let lastError;
    for (const key of KEYS.all) {
        try {
            return gcmDecrypt(key, parts[0], parts[1], parts[2], null);
        } catch (err) {
            lastError = err;
        }
    }
    throw lastError;
}

// Битые данные, неверный ключ или чужой AAD (запись перенесена в другую
// комнату/строку) — не роняем запрос целиком, но и не показываем мусор как
// будто это нормальный текст.
function failed(err) {
    logError('[MessageCrypto] Не удалось расшифровать сообщение', err);
    return DECRYPT_FAILED;
}

// Расшифровывает значение ЧАТА С БОТОМ, прочитанное из БД. aad обязателен для
// записей v2 (без него — исключение); для v1 и строк без префикса он не
// используется. Строки без нашего префикса возвращаются как есть — это
// служебные плейсхолдеры (например, "[Сообщение удалено]"), которые и не
// шифровались. Запись комнаты (enc:v3) здесь не читается: у неё свой AAD и
// своя строгость, см. decryptRoomText.
function decryptText(stored, aad) {
    if (stored === null || stored === undefined) return stored;
    if (typeof stored !== 'string') return stored;
    if (stored.startsWith(PREFIX_V3)) return failed(new Error('запись enc:v3 читается только как строка комнаты'));
    const isV2 = stored.startsWith(PREFIX_V2);
    if (!isV2 && !stored.startsWith(PREFIX_V1)) return stored;
    const aadBytes = isV2 ? requireAad(aad) : null;
    try {
        return isV2
            ? decryptSealed(stored.slice(PREFIX_V2.length), aadBytes, KEYS.byKid, 'enc:v2')
            : decryptV1(stored.slice(PREFIX_V1.length));
    } catch (err) {
        return failed(err);
    }
}

// Расшифровывает значение СТРОКИ КОМНАТЫ. Принимается только enc:v3 с верным
// AAD: запись без префикса, enc:v1 и enc:v2 в комнате — "[Не удалось
// расшифровать]" (R0: таких записей нет, а подложить их может только
// записывающий в БД). Исключение — null/undefined: пустое значение.
function decryptRoomText(stored, aad) {
    if (stored === null || stored === undefined) return stored;
    const aadBytes = requireAadV3(aad);
    if (typeof stored !== 'string' || !stored.startsWith(PREFIX_V3)) {
        return failed(new Error('в комнате принимается только enc:v3'));
    }
    try {
        return decryptSealed(stored.slice(PREFIX_V3.length), aadBytes, KEYS.enc3ByKid, 'enc:v3');
    } catch (err) {
        return failed(err);
    }
}

// Ключи сообщений для производных меток (тег автора, псевдоним квоты): текущий
// первым, затем MESSAGE_ENCRYPTION_KEY_PREVIOUS. Это те же 32 байта после
// parseKey, что и вход HKDF у K_enc3. Копии: вызывающий не может изменить ключи
// модуля.
function messageKeyRing() {
    return KEYS.all.map(key => ({ kid: keyId(key), ikm: Buffer.from(key) }));
}

module.exports = {
    encryptText, decryptText, messageAad,
    encryptRoomText, decryptRoomText, messageAadV3,
    messageKeyRing,
    DECRYPT_FAILED,
};
