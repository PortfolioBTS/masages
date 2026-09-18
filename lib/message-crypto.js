// Шифрование текста сообщений "на лету" перед записью в БД (encryption at
// rest). Ключ живёт только в переменной окружения на сервере — в самой БД
// (и в любом её бэкапе/дампе/утечке) остаётся только шифротекст.
//
// ВАЖНО — что это защищает, а что нет:
//   ✅ Дамп/бэкап базы, утечка у хостера БД, кто-то с read-доступом к Postgres —
//      видит только "enc:v1:...", без ключа это бессмысленный набор байт.
//   ❌ Не защищает от компрометации самого сервера приложения: тот, у кого
//      есть переменные окружения (MESSAGE_ENCRYPTION_KEY) и доступ к процессу,
//      расшифрует всё точно так же, как это делает сам сервер при каждом
//      чтении. Это шифрование "на стороне сервера", а не end-to-end —
//      сервер как посредник технически может прочитать сообщения.
//   Настоящее "не может прочитать вообще никто, включая нас" — это уже E2EE
//   (шифрование в браузере до отправки, сервер видит только шифротекст и
//   ключа не хранит вообще). Инфраструктура под это в проекте частично есть
//   (e2ee-key-server), но клиентская часть — отдельная, более крупная задача.

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const PREFIX = 'enc:v1:';

function loadKey() {
    const raw = process.env.MESSAGE_ENCRYPTION_KEY;
    if (!raw) {
        throw new Error(
            'MESSAGE_ENCRYPTION_KEY не задан. Сгенерируй ключ командой:\n' +
            '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"\n' +
            'и добавь его в .env / переменные окружения перед запуском сервера.'
        );
    }
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) {
        throw new Error('MESSAGE_ENCRYPTION_KEY должен декодироваться из base64 ровно в 32 байта (256 бит).');
    }
    return key;
}

// Ключ читается один раз при старте процесса — если он невалиден, сервер
// не должен подниматься и молча писать сообщения в открытом виде (fail
// closed, а не fail open).
const KEY = loadKey();

// Шифрует текст перед вставкой в БД. null/undefined проходят насквозь —
// это осознанные "пустые" значения полей, а не текст сообщения.
function encryptText(plainText) {
    if (plainText === null || plainText === undefined) return plainText;
    const iv = crypto.randomBytes(12); // рекомендованный размер nonce для GCM
    const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
    const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return PREFIX + [iv.toString('base64'), authTag.toString('base64'), encrypted.toString('base64')].join(':');
}

// Расшифровывает значение, прочитанное из БД. Строки без нашего префикса
// возвращаются как есть — это либо старые записи, созданные ДО включения
// шифрования, либо служебные плейсхолдеры (например, "[Сообщение удалено]"),
// которые и не шифровались. Так старые данные не ломаются при первом же чтении.
function decryptText(stored) {
    if (stored === null || stored === undefined) return stored;
    if (typeof stored !== 'string' || !stored.startsWith(PREFIX)) return stored;
    try {
        const [ivB64, tagB64, dataB64] = stored.slice(PREFIX.length).split(':');
        const iv = Buffer.from(ivB64, 'base64');
        const authTag = Buffer.from(tagB64, 'base64');
        const data = Buffer.from(dataB64, 'base64');
        const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
        decipher.setAuthTag(authTag);
        return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    } catch (err) {
        // Битые данные или неверный ключ — не роняем запрос целиком, но и не
        // показываем мусор как будто это нормальный текст.
        console.error('[MessageCrypto] Не удалось расшифровать сообщение:', err.message);
        return '[Не удалось расшифровать]';
    }
}

module.exports = { encryptText, decryptText };
