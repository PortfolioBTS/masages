// Шифрование текста сообщений "на лету" перед записью в БД (encryption at
// rest). Ключи живут только в переменных окружения на сервере — в самой БД
// (и в любом её бэкапе/дампе/утечке) остаётся только шифротекст.
//
// Формат записи (пишется сейчас): enc:v2:<kid>:<iv>:<tag>:<ct>
//   kid — первые 8 hex SHA-256 ключа. По нему при чтении выбирается ключ:
//         текущий MESSAGE_ENCRYPTION_KEY или один из
//         MESSAGE_ENCRYPTION_KEY_PREVIOUS (через запятую, только для
//         расшифровки). Так ключ можно сменить без одномоментной
//         перешифровки всей таблицы: новые записи идут под новым ключом,
//         старые читаются старым, пока он указан в PREVIOUS.
//   iv/tag/ct — base64; AES-256-GCM, 12-байтный nonce, 16-байтный тег.
//   AAD — строка messageAad(): комната (для личного/бот-чата — чат) и
//         отправитель. Без AAD v2 не шифруется и не расшифровывается вовсе
//         (исключение, а не молчаливое шифрование без привязки).
// Старый формат enc:v1:<iv>:<tag>:<ct> (без kid и без AAD) только читается;
// строки без префикса (записи до включения шифрования, служебные
// плейсхолдеры) отдаются как есть.
//
// ВАЖНО — что это защищает, а что нет:
//   ✅ Дамп/бэкап базы, утечка у хостера БД, кто-то с read-доступом к Postgres —
//      видит только "enc:v2:...", без ключа это бессмысленный набор байт.
//   ✅ Подмену при записи в БД (v2): шифротекст, перенесённый в другую
//      комнату/чат или в строку другого отправителя, не расшифруется —
//      вместо чужого текста будет "[Не удалось расшифровать]". Раньше
//      (v1) такой перенос проходил незаметно.
//   ❌ Перестановку и повтор сообщений ВНУТРИ одной комнаты от одного и того
//      же отправителя, удаление строк и откат БД к старому бэкапу: id
//      сообщения при INSERT ещё неизвестен, поэтому в AAD его нет.
//   ❌ Записи v1 и строки без префикса: у них нет привязки, и тот, кто может
//      писать в БД, может подставить их куда угодно (или вписать открытый
//      текст). Закрывается только перешифровкой старых записей в v2.
//   ❌ Компрометацию самого сервера приложения: у кого есть переменные
//      окружения и доступ к процессу, тот расшифрует всё точно так же, как
//      это делает сам сервер при каждом чтении. Это шифрование "на стороне
//      сервера", а не end-to-end. "Не может прочитать никто, включая нас" —
//      это E2EE (public/e2ee.js): у таких сообщений здесь шифруется уже
//      непрозрачный для сервера конверт.

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const PREFIX_V1 = 'enc:v1:';
const PREFIX_V2 = 'enc:v2:';
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
        all.push(key);
    }
    return { current, currentKid: keyId(current), byKid, all };
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

// AAD сообщения. Для сообщений комнаты chat_id сюда НЕ входит: это
// персональная строка отправителя, и при удалении его чата messages.chat_id
// обнуляется (ON DELETE SET NULL) — запись перестала бы расшифровываться у
// остальных участников. room_id стабилен (строки удаляются вместе с комнатой).
function messageAad(message) {
    const { room_id, chat_id, user_id } = message || {};
    const user = normalizeId(user_id, 'user_id');
    if (user === null) throw new TypeError('messageAad: нужен user_id');
    const room = normalizeId(room_id, 'room_id');
    if (room !== null) return `nyxo:msg:v2:room=${room}:user=${user}`;
    const chat = normalizeId(chat_id, 'chat_id');
    if (chat !== null) return `nyxo:msg:v2:chat=${chat}:user=${user}`;
    throw new TypeError('messageAad: нужен room_id или chat_id');
}

// Шифрует текст перед вставкой в БД. null/undefined проходят насквозь —
// это осознанные "пустые" значения полей, а не текст сообщения.
function encryptText(plainText, aad) {
    if (plainText === null || plainText === undefined) return plainText;
    const aadBytes = requireAad(aad);
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, KEYS.current, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(aadBytes);
    const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
    return PREFIX_V2 + [
        KEYS.currentKid,
        iv.toString('base64'),
        cipher.getAuthTag().toString('base64'),
        encrypted.toString('base64'),
    ].join(':');
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

function decryptV2(body, aadBytes) {
    const parts = body.split(':');
    if (parts.length !== 4) throw new Error('некорректный формат enc:v2');
    const [kid, ivB64, tagB64, dataB64] = parts;
    const key = KEYS.byKid.get(kid);
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

// Расшифровывает значение, прочитанное из БД. aad обязателен для записей v2
// (без него — исключение); для v1 и строк без префикса он не используется.
// Строки без нашего префикса возвращаются как есть — это либо старые
// записи, созданные ДО включения шифрования, либо служебные плейсхолдеры
// (например, "[Сообщение удалено]"), которые и не шифровались.
function decryptText(stored, aad) {
    if (stored === null || stored === undefined) return stored;
    if (typeof stored !== 'string') return stored;
    const isV2 = stored.startsWith(PREFIX_V2);
    if (!isV2 && !stored.startsWith(PREFIX_V1)) return stored;
    const aadBytes = isV2 ? requireAad(aad) : null;
    try {
        return isV2 ? decryptV2(stored.slice(PREFIX_V2.length), aadBytes) : decryptV1(stored.slice(PREFIX_V1.length));
    } catch (err) {
        // Битые данные, неверный ключ или чужой AAD (запись перенесена в
        // другую комнату/строку) — не роняем запрос целиком, но и не
        // показываем мусор как будто это нормальный текст.
        console.error('[MessageCrypto] Не удалось расшифровать сообщение:', err.message);
        return DECRYPT_FAILED;
    }
}

module.exports = { encryptText, decryptText, messageAad };
