// Хэширование паролей и политика выбора пароля.
//
// Формат нового хэша: "$nyxo1$" + bcrypt(cost 12) от
//   base64(HMAC-SHA256(key, utf8(NFKC(password)))).
//
// Зачем HMAC перед bcrypt: bcrypt молча использует только первые 72 байта
// входа. Пароль до 256 символов в UTF-8 может занимать сотни байт (кириллица —
// 2 байта на символ, эмодзи — 4), и два длинных пароля с общим началом в
// 72 байта (для кириллицы это всего 36 символов) дали бы один и тот же хэш:
// хвост в проверке просто не участвует. HMAC-SHA256 сжимает пароль любой
// длины в 32 байта; base64 превращает их в 44 ASCII-символа — меньше 72 и без
// нулевых байт (часть реализаций bcrypt обрезает вход на \0, поэтому сырые
// байты HMAC туда не подаются).
//
// key — секрет PASSWORD_PEPPER, если задан: он хранится вне БД, и утёкший
// дамп без него нельзя перебирать офлайн. Если не задан — фиксированная
// доменная метка (схема всё равно решает проблему 72 байт). PASSWORD_PEPPER
// нельзя менять или терять после запуска: все хэши $nyxo1$ перестанут
// сходиться, и пользователям придётся восстанавливать доступ.
//
// NFKC (NIST SP 800-63B): один и тот же пароль, набранный на разных
// устройствах в разных формах Unicode (составная «й» или «и» + комбинирующий
// знак), должен давать один хэш.
//
// Старые хэши ($2a$/$2b$/$2y$ — bcrypt от пароля напрямую) по-прежнему
// проверяются; needsRehash() подсказывает серверу перехэшировать их при
// ближайшем успешном входе, пока пароль известен в открытом виде.

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const BCRYPT_COST = 12;
const NYXO1_PREFIX = '$nyxo1$';
const BCRYPT_RE = /^\$2[aby]\$(\d{2})\$/;
const PEPPER = Buffer.from(process.env.PASSWORD_PEPPER || 'nyxo:password-prehash:v1', 'utf8');

const MIN_LENGTH = 8;
const MAX_LENGTH = 256;
const HIBP_TIMEOUT_MS = 3000;

function prehash(password) {
    return crypto.createHmac('sha256', PEPPER).update(password.normalize('NFKC'), 'utf8').digest('base64');
}

async function hashPassword(password) {
    if (typeof password !== 'string') throw new TypeError('hashPassword: пароль должен быть строкой');
    return NYXO1_PREFIX + await bcrypt.hash(prehash(password), BCRYPT_COST);
}

async function verifyPassword(password, stored) {
    if (typeof password !== 'string' || typeof stored !== 'string') return false;
    try {
        if (stored.startsWith(NYXO1_PREFIX)) {
            return await bcrypt.compare(prehash(password), stored.slice(NYXO1_PREFIX.length));
        }
        if (BCRYPT_RE.test(stored)) return await bcrypt.compare(password, stored);
    } catch (err) {
        console.error('[Passwords] Ошибка проверки пароля:', err.message);
    }
    return false;
}

// true — хэш стоит пересчитать при ближайшем успешном входе: старый формат
// (обрезка на 72 байтах) или $nyxo1$ с cost ниже текущего.
function needsRehash(stored) {
    if (typeof stored !== 'string') return false;
    if (BCRYPT_RE.test(stored)) return true;
    if (stored.startsWith(NYXO1_PREFIX)) {
        const match = BCRYPT_RE.exec(stored.slice(NYXO1_PREFIX.length));
        return Boolean(match) && Number(match[1]) < BCRYPT_COST;
    }
    return false;
}

// Хэш без известного пароля: server.js проверяет пароль и тогда, когда
// пользователь не найден, чтобы время ответа не выдавало существование
// email. Формат новый — проверка идёт по той же (более дорогой) ветке, что
// и у настоящих хэшей.
const DUMMY_PASSWORD_HASH = NYXO1_PREFIX + bcrypt.hashSync(prehash(crypto.randomBytes(32).toString('hex')), BCRYPT_COST);

// ---- Политика (NIST SP 800-63B): длина, блок-лист, контекст ----
// Требований к составу символов нет намеренно: NIST их не рекомендует —
// они дают предсказуемые "Password1!" и не добавляют стойкости.

// Самые частые пароли из публичных утечек, включая русскоязычные и
// "раскладочные" (слово, набранное не в той раскладке: gfhjkm = «пароль»).
// Короче 8 символов здесь ничего нет — такие и так отсекает проверка длины.
// Сравнение — в нижнем регистре и во всех трёх вариантах: как есть, в
// русской и в латинской раскладке (см. switchLayout), так что «ghbdtn123»
// ловится записью «привет123», а «йцукенгш» — записью «qwertyui».
const COMMON_PASSWORDS = new Set(`
    12345678 123456789 1234567890 12345678910 1234567891 0123456789 01234567
    11111111 111111111 1111111111 00000000 000000000 0000000000 22222222
    55555555 66666666 77777777 88888888 99999999 12341234 12344321 12121212
    123123123 123321123 87654321 987654321 0987654321 11223344 11112222
    123654789 147258369 159753456 159357456 741852963 963852741 789456123
    456123789 147852369 123698745 112233445566 1234512345 1234554321
    19841984 19851985 19861986 19871987 19901990 20002000 20202020 12345qwert
    password password1 password12 password123 password1234 password2
    password01 passw0rd p@ssw0rd p@ssword pa$$word password! mypassword
    mypassword1 nopassword passpass pass1234 pass12345 changeme changeme1
    qwertyui qwertyuiop qwerty12 qwerty123 qwerty1234 qwerty12345
    qwertyqwerty qwertyuiop123 qwe123qwe qweqweqwe qweasdzxc qweasd123
    qwerasdf qwer1234 1234qwer 123qwe123 1q2w3e4r 1q2w3e4r5 1q2w3e4r5t
    1q2w3e4r5t6y q1w2e3r4 q1w2e3r4t5 q1w2e3r4t5y6 1qaz2wsx 1qaz2wsx3edc
    1qazxsw2 zaq12wsx zaq1zaq1 zaq1xsw2 zaq!2wsx !qaz2wsx xsw21qaz
    qazwsxedc qazwsx123 qwaszx12 asdfghjk asdfghjkl asdf1234 asdfasdf
    asdasdasd zxcvbnm1 zxcvbnm123 zxczxczxc zxcasdqwe azertyuiop azerty123
    qwertz123 abc12345 abcd1234 abcdefgh aa123456 a1234567 a12345678
    a123456789 1234567a 12345678a 123456789a 123456789q q1234567 12345678q
    test1234 test12345 admin123 admin1234 administrator root1234 toor1234
    guest123 default1 welcome1 welcome123 letmein1 letmein123 secret123
    hello123 hello1234 iloveyou iloveyou1 lovelove loveyou1 sunshine
    princess football football1 baseball superman batman123 starwars
    trustno1 whatever computer internet michelle jennifer corvette
    mercedes mustang1 master123 monkey123 dragon123 shadow123 killer123
    matrix123 hunter12 freedom1 liverpool chelsea1 arsenal1 barcelona
    pokemon1 minecraft fortnite samsung1 google123 yandex123 windows7
    windows10 unknown1
    parol123 privet123 ljubov123 lyubov123 natasha1 maksim123 moskva123
    russia123 rossiya1 solnyshko kotenok1 zaichik1 dima1234 sasha123
    пароль12 пароль123 пароль1234 мойпароль паролька
    йцукенгш йцукенгшщз йцукен123 фывапролд фывапролдж ячсмитьбю
    привет123 приветик здравствуй люблютебя любовь123 солнышко
    александр анастасия екатерина валентина кристина шоколадка локомотив
    спартак1 мамапапа котенок1 зайчонок наташа123 максим123 москва123
    россия123
`.trim().split(/\s+/));

// Раскладка ЙЦУКЕН поверх QWERTY — по позициям клавиш.
const EN_KEYS = Array.from("qwertyuiop[]asdfghjkl;'zxcvbnm,.`");
const RU_KEYS = Array.from('йцукенгшщзхъфывапролджэячсмитьбюё');
const EN_TO_RU = new Map(EN_KEYS.map((c, i) => [c, RU_KEYS[i]]));
const RU_TO_EN = new Map(RU_KEYS.map((c, i) => [c, EN_KEYS[i]]));

function switchLayout(text, map) {
    return Array.from(text, c => map.get(c) || c).join('');
}

function isCommonPassword(lower) {
    return COMMON_PASSWORDS.has(lower)
        || COMMON_PASSWORDS.has(switchLayout(lower, EN_TO_RU))
        || COMMON_PASSWORDS.has(switchLayout(lower, RU_TO_EN));
}

// Повтор короткого фрагмента (aaaaaaaa, 12121212, abcabcabc, passpass) или
// сплошная последовательность (12345678, abcdefgh, 98765432) — NIST
// называет такие пароли в числе обязательных к отклонению.
function isTrivialPattern(lower) {
    const chars = Array.from(lower);
    for (let unit = 1; unit <= 4 && unit * 2 <= chars.length; unit++) {
        if (chars.length % unit !== 0) continue;
        if (chars.every((c, i) => c === chars[i % unit])) return true;
    }
    const codes = chars.map(c => c.codePointAt(0));
    const step = codes[1] - codes[0];
    return (step === 1 || step === -1) && codes.every((c, i) => i === 0 || c - codes[i - 1] === step);
}

function normalizeContext(value) {
    return typeof value === 'string' ? value.normalize('NFKC').toLowerCase().trim() : '';
}

// Пароль совпадает с name или (при длине name ≥ 4) содержит его. Короткие
// имена не проверяются на вхождение — иначе "ann" запрещало бы любые пароли
// со слогом "ann".
function containsIdentifier(lower, name) {
    if (!name) return false;
    return lower === name || (name.length >= 4 && lower.includes(name));
}

// k-anonymity запрос к Have I Been Pwned: наружу уходят только первые 5 hex
// SHA-1 пароля, сравнение хвоста — локально. Add-Padding дополняет ответ
// фиктивными строками, чтобы по его размеру нельзя было судить о префиксе.
async function isPwnedPassword(password) {
    const sha1 = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': 'nyxo-messenger' },
        signal: AbortSignal.timeout(HIBP_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.text();
    for (const line of body.split('\n')) {
        const [hashSuffix, count] = line.trim().split(':');
        // У строк-заполнителей счётчик 0 — это не совпадение.
        if (hashSuffix === suffix && Number(count) > 0) return true;
    }
    return false;
}

// Возвращает текст ошибки по-русски или null, если пароль подходит.
async function checkPasswordPolicy(password, { username, email } = {}) {
    if (typeof password !== 'string') return 'Некорректный пароль';
    // Длина — в символах Unicode (кодовых точках), как требует NIST:
    // эмодзи — один символ, а не две UTF-16-единицы.
    const length = Array.from(password).length;
    if (length < MIN_LENGTH) return `Пароль должен содержать минимум ${MIN_LENGTH} символов`;
    if (length > MAX_LENGTH) return `Пароль не должен быть длиннее ${MAX_LENGTH} символов`;

    const lower = password.normalize('NFKC').toLowerCase();
    if (isCommonPassword(lower)) return 'Этот пароль слишком распространён — выберите другой';
    if (isTrivialPattern(lower)) return 'Пароль из повторяющихся или идущих подряд символов слишком простой';

    if (containsIdentifier(lower, normalizeContext(username))) {
        return 'Пароль не должен совпадать с именем пользователя или содержать его';
    }
    const emailLocal = normalizeContext(email).split('@')[0];
    if (containsIdentifier(lower, emailLocal)) {
        return 'Пароль не должен совпадать с адресом почты или содержать его';
    }

    // Проверка по утечкам — обращение к третьей стороне, поэтому только по
    // явному HIBP_CHECK=true. Недоступность сервиса не мешает регистрации
    // (fail open): блок-лист выше уже отсёк самое частое.
    if (process.env.HIBP_CHECK === 'true') {
        try {
            if (await isPwnedPassword(password)) {
                return 'Этот пароль встречается в известных утечках — выберите другой';
            }
        } catch (err) {
            console.warn('[Passwords] Проверка по утечкам (HIBP) недоступна, пропускаем:', err.message);
        }
    }
    return null;
}

module.exports = {
    hashPassword,
    verifyPassword,
    needsRehash,
    checkPasswordPolicy,
    DUMMY_PASSWORD_HASH,
};
