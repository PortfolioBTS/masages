// Чистые функции безопасности сервера (без БД, сети и глобального
// состояния) — вынесены из server.js, чтобы их можно было проверить
// тестами (test/security-utils.test.js), не поднимая Postgres.

const crypto = require('crypto');

// ---- Случайные строки ----

// Равномерный выбор символа из алфавита: байт, попавший в "хвост"
// [256 - 256 % n, 256), отбрасывается (rejection sampling). Прежний
// вариант bytes[i] % n для алфавита из 62 символов выдавал первые 8
// символов (256 % 62 = 8) заметно чаще остальных. Для алфавита из 32
// символов хвоста нет (256 % 32 == 0) — там ни один байт не теряется.
function randomString(alphabet, length, randomBytes = crypto.randomBytes) {
    const n = alphabet.length;
    if (n < 2 || n > 256) throw new RangeError('Алфавит должен содержать от 2 до 256 символов');
    const limit = 256 - (256 % n);
    let out = '';
    while (out.length < length) {
        const bytes = randomBytes(Math.max(16, (length - out.length) * 2));
        for (const b of bytes) {
            if (b >= limit) continue;
            out += alphabet[b % n];
            if (out.length === length) break;
        }
    }
    return out;
}

// Персональный код пользователя (users.unique_code).
const UNIQUE_CODE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UNIQUE_CODE_LENGTH = 8;

function generateUniqueCode(randomBytes) {
    return randomString(UNIQUE_CODE_ALPHABET, UNIQUE_CODE_LENGTH, randomBytes);
}

// ---- Инвайт-коды комнат ----
//
// Раньше код был из 6 символов (~30 бит) и бессрочный: его можно было
// перебрать, а утёкший код открывал комнату навсегда. Теперь 26 символов
// алфавита без похожих друг на друга 0/O и 1/I (32^26 = 2^130) и срок
// жизни (rooms.code_expires_at).
const INVITE_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const INVITE_CODE_LENGTH = 26;
const INVITE_CODE_RE = new RegExp(`^[${INVITE_CODE_ALPHABET}]{${INVITE_CODE_LENGTH}}$`);

function generateInviteCode(randomBytes) {
    return randomString(INVITE_CODE_ALPHABET, INVITE_CODE_LENGTH, randomBytes);
}

// Код, введённый человеком: регистр не важен, пробелы и дефисы (клиент
// может показывать код группами через дефис) выбрасываются.
function normalizeInviteCode(input) {
    if (typeof input !== 'string') return '';
    return input.replace(/[\s\-‐-―]+/g, '').toUpperCase();
}

function isValidInviteCode(code) {
    return typeof code === 'string' && INVITE_CODE_RE.test(code);
}

// NULL-срок (строка, созданная старой версией сервера) — тоже истёкший:
// лучше попросить перевыпустить код, чем пустить по бессрочному.
function isInviteExpired(expiresAt, now = Date.now()) {
    if (expiresAt === null || expiresAt === undefined) return true;
    const time = new Date(expiresAt).getTime();
    return !Number.isFinite(time) || time <= now;
}

// ---- Вложения ----

const ALLOWED_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/webm', 'video/quicktime',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
    'application/pdf', 'text/plain',
];

// Жёсткий маппинг mimetype -> расширение на диске. Расширение НИКОГДА не
// берётся из file.originalname (см. п.2 аудита): имя, присланное клиентом —
// это просто строка, и path.extname() от неё может вернуть что угодно вплоть
// до '.png"><svg onload=alert(1)>', что затем всплывает в file_url и рискует
// быть вставлено как HTML. Здесь расширение выбирается только из этого
// фиксированного списка по уже провалидированному через ALLOWED_MIME_TYPES
// mimetype, так что итоговое имя файла всегда полностью предсказуемо.
const MIME_EXTENSIONS = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'video/mp4': '.mp4',
    'video/webm': '.webm',
    'video/quicktime': '.mov',
    'audio/mpeg': '.mp3',
    'audio/ogg': '.ogg',
    'audio/wav': '.wav',
    'audio/webm': '.weba',
    'application/pdf': '.pdf',
    'text/plain': '.txt',
};

// E2EE-вложение: сервер получает только шифротекст (клиент шлёт Blob),
// тип и имя настоящего файла лежат внутри E2EE-конверта.
const ENCRYPTED_FILE_MIME = 'application/octet-stream';
const ENCRYPTED_FILE_EXTENSION = '.bin';

// Имя вложения, которое видят участники чата. Исходное имя файла
// ("IMG_20260914_Ivanov.png", "Паспорт Петрова.pdf") — это метаданные
// ровно того рода, что снимает metadata-stripper с содержимого: оно
// больше не хранится и не логируется, вместо него — имя по типу.
const ANONYMIZED_FILE_NAMES = {
    'image/jpeg': 'photo.jpg',
    'image/png': 'photo.png',
    'image/gif': 'photo.gif',
    'image/webp': 'photo.webp',
    'video/mp4': 'video.mp4',
    'video/webm': 'video.webm',
    'video/quicktime': 'video.mov',
    'audio/mpeg': 'audio.mp3',
    'audio/ogg': 'audio.ogg',
    'audio/wav': 'audio.wav',
    'audio/webm': 'audio.webm',
    'application/pdf': 'document.pdf',
    'text/plain': 'text.txt',
};
const FALLBACK_FILE_NAME = 'file';
// Все имена, которые может выдать anonymizedFileName, — по этому списку
// миграция старых вложений узнаёт уже обезличенные строки.
const ALL_ANONYMIZED_FILE_NAMES = [...new Set([...Object.values(ANONYMIZED_FILE_NAMES), FALLBACK_FILE_NAME])];

function anonymizedFileName(mimeType) {
    return Object.prototype.hasOwnProperty.call(ANONYMIZED_FILE_NAMES, mimeType)
        ? ANONYMIZED_FILE_NAMES[mimeType]
        : FALLBACK_FILE_NAME;
}

// ---- Проверка источника запроса (CSRF / Cross-Site WebSocket Hijacking) ----

// Хост в каноническом виде: нижний регистр, без порта по умолчанию.
// Схема здесь неизвестна (заголовок Host её не несёт), поэтому снимаются
// оба стандартных порта.
function normalizeHost(value) {
    if (typeof value !== 'string') return null;
    const host = value.trim().toLowerCase().replace(/:(80|443)$/, '');
    if (!host || host.length > 260) return null;
    return host;
}

// X-Forwarded-Host может прийти списком через запятую — берётся первый.
function firstHeaderValue(value) {
    if (Array.isArray(value)) value = value[0];
    if (typeof value !== 'string') return null;
    return value.split(',')[0].trim() || null;
}

// Origin — это только scheme://host[:port]. 'null' (sandbox-iframe,
// file://, часть редиректов), путь, логин/пароль или не-http(s) схема —
// признак подделки, такой Origin не принадлежит ни одному сайту.
function parseOrigin(origin) {
    if (typeof origin !== 'string' || origin === '' || origin === 'null') return null;
    let url;
    try {
        url = new URL(origin);
    } catch (_) {
        return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
    return { origin: url.origin, host: normalizeHost(url.host) };
}

// ALLOWED_ORIGINS="https://app.example.com, admin.example.com": запись со
// схемой сравнивается с Origin целиком, запись без схемы — только по хосту.
function parseAllowedOrigins(value) {
    const origins = new Set();
    const hosts = new Set();
    const invalid = [];
    for (const raw of String(value || '').split(',')) {
        const entry = raw.trim();
        if (!entry) continue;
        if (entry.includes('://')) {
            const parsed = parseOrigin(entry.replace(/\/+$/, ''));
            if (parsed) origins.add(parsed.origin);
            else invalid.push(entry);
        } else {
            const host = normalizeHost(entry);
            if (host && !/[/\s]/.test(host)) hosts.add(host);
            else invalid.push(entry);
        }
    }
    return { origins, hosts, invalid };
}

// Решение "свой ли это запрос" — одно и то же для рукопожатия Socket.io
// и для небезопасных HTTP-методов.
//
// Браузер всегда шлёт Origin при WebSocket-рукопожатии и при POST/PUT/
// DELETE, а страница злоумышленника не может его подменить. Разрешено:
//   * Origin с тем же хостом, что и сам запрос (Host или X-Forwarded-Host —
//     последний браузерная страница тоже выставить не может);
//   * хост из ALLOWED_ORIGINS;
//   * onion-адрес сервиса (isOnionHost).
// Без Origin (polling-XHR с той же страницы его может не слать, как и
// не-браузерные клиенты, для которых CSWSH не угроза) запрос пропускается,
// только если браузер не пометил его как межсайтовый (Sec-Fetch-Site).
function isRequestOriginAllowed({ origin, host, forwardedHost, secFetchSite, allowed, isOnionHost } = {}) {
    if (origin === undefined || origin === null || origin === '') {
        return secFetchSite !== 'cross-site';
    }
    const parsed = parseOrigin(origin);
    if (!parsed || !parsed.host) return false;
    const targets = [normalizeHost(host), normalizeHost(firstHeaderValue(forwardedHost))].filter(Boolean);
    if (targets.includes(parsed.host)) return true;
    if (allowed && (allowed.hosts.has(parsed.host) || allowed.origins.has(parsed.origin))) return true;
    if (typeof isOnionHost === 'function' && isOnionHost(parsed.host)) return true;
    return false;
}

// ---- Заголовки ----

// Хост из заголовка Host попадает внутрь CSP — только строго валидное
// имя (или [IPv6]) с необязательным портом: иначе "Host: a; script-src *"
// дописал бы в политику свою директиву.
const CSP_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/;
const CSP_NONCE_RE = /^[A-Za-z0-9+/_-]+=*$/;

function buildContentSecurityPolicy({ nonce, host, secure } = {}) {
    if (typeof nonce !== 'string' || !CSP_NONCE_RE.test(nonce)) throw new TypeError('Некорректный CSP nonce');
    const normalizedHost = typeof host === 'string' ? host.trim().toLowerCase() : '';
    // WebSocket того же хоста указан явно: не все браузеры считают ws(s)://
    // частью 'self'. Схема — по тому, как пришёл сам запрос (.onion — http).
    const wsSource = CSP_HOST_RE.test(normalizedHost) ? ` ${secure ? 'wss' : 'ws'}://${normalizedHost}` : '';
    return [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}'`,
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self'",
        `connect-src 'self'${wsSource}`,
        "media-src 'self' blob:",
        "worker-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
    ].join('; ');
}

// ---- TLS до Postgres ----

// В production соединение с БД без проверки сертификата допустимо только
// там, где MITM не грозит: в приватной сети Railway (*.railway.internal,
// трафик между сервисами и так шифрует сама платформа) — или при явном
// DB_TLS_INSECURE=true. Во всех остальных случаях сервер не стартует:
// раньше rejectUnauthorized=false молча применялся к любому хосту, в том
// числе к публичному прокси БД.
function resolveDbTlsConfig({ nodeEnv, databaseUrl, caCert, insecure } = {}) {
    if (nodeEnv !== 'production') return { ssl: false };
    if (caCert) {
        return {
            ssl: { ca: caCert, rejectUnauthorized: true },
            info: '[SSL] production: rejectUnauthorized=true, CA закреплён через DB_CA_CERT',
        };
    }
    let host = null;
    try {
        host = new URL(databaseUrl).hostname.toLowerCase();
    } catch (_) { /* host остаётся null */ }
    const hint = 'Чтобы включить проверку сертификата, запустите сервер один раз с DUMP_CA=true, ' +
        'скопируйте цепочку сертификатов в переменную DB_CA_CERT и перезапустите.';
    if (host && host.endsWith('.railway.internal')) {
        return {
            ssl: { rejectUnauthorized: false },
            warning: `[SSL] production: DB_CA_CERT не задан — сертификат Postgres не проверяется. ` +
                `Допущено только потому, что ${host} — приватная сеть Railway. ${hint}`,
        };
    }
    if (insecure) {
        return {
            ssl: { rejectUnauthorized: false },
            warning: '[SSL] ВНИМАНИЕ: DB_TLS_INSECURE=true — сертификат Postgres не проверяется, ' +
                `соединение с БД${host ? ` (${host})` : ''} уязвимо для MITM. ${hint}`,
        };
    }
    return {
        ssl: false,
        error: `[SSL] production: DB_CA_CERT не задан, а хост БД${host ? ` (${host})` : ''} не в приватной сети Railway ` +
            '(*.railway.internal). Соединение без проверки сертификата уязвимо для MITM, поэтому сервер не запускается. ' +
            `${hint} Осознанно отключить проверку можно переменной DB_TLS_INSECURE=true.`,
    };
}

// ---- Мелочи ----

// Счётчик подключений по ключу (пользователь, IP): запись удаляется,
// когда счётчик доходит до нуля, — Map не растёт от разовых посетителей.
function createCounter() {
    const counts = new Map();
    return {
        get: (key) => counts.get(key) || 0,
        increment: (key) => counts.set(key, (counts.get(key) || 0) + 1),
        decrement: (key) => {
            const next = (counts.get(key) || 0) - 1;
            if (next <= 0) counts.delete(key);
            else counts.set(key, next);
        },
        size: () => counts.size,
        keys: () => [...counts.keys()],
    };
}

// ---- Журнал безопасности ----

// Грубое семейство клиента по User-Agent для журнала входов: «Chrome ·
// Windows», «Firefox · Android», «Safari · iOS». Сама строка User-Agent не
// хранится — в ней версии браузера и ОС, по которым устройство легко
// отличить от соседних, — только название из фиксированного набора ниже,
// поэтому в БД не может попасть ничего, что прислал клиент. IP не
// сохраняется вовсе. Порядок проверок важен: у Edge, Opera, Яндекса и
// Samsung в строке есть и "Chrome", у Chrome — "Safari".
const UA_BROWSERS = [
    [/\bEdg(?:e|A|iOS)?\//, 'Edge'],
    [/\b(?:OPR|Opera|OPT)\//, 'Opera'],
    [/\bYaBrowser\//, 'Яндекс Браузер'],
    [/\bSamsungBrowser\//, 'Samsung Internet'],
    [/\b(?:Firefox|FxiOS)\//, 'Firefox'],
    [/\b(?:Chrome|CriOS|Chromium)\//, 'Chrome'],
    [/\bVersion\/[\d.]+.*\bSafari\//, 'Safari'],
];
const UA_SYSTEMS = [
    [/\b(?:iPhone|iPad|iPod)\b/, 'iOS'],
    [/\bAndroid\b/, 'Android'],
    [/\bWindows\b/, 'Windows'],
    [/\bCrOS\b/, 'ChromeOS'],
    [/\b(?:Macintosh|Mac OS X)\b/, 'macOS'],
    [/\b(?:Linux|X11)\b/, 'Linux'],
];
const UNKNOWN_CLIENT = 'Неизвестный клиент';
const MAX_USER_AGENT_LENGTH = 512;

function classifyUserAgent(userAgent) {
    if (typeof userAgent !== 'string' || userAgent.trim() === '') return UNKNOWN_CLIENT;
    // Длинная строка — не браузер; обрезка заодно ограничивает работу регулярок.
    const ua = userAgent.slice(0, MAX_USER_AGENT_LENGTH);
    const browser = (UA_BROWSERS.find(([re]) => re.test(ua)) || [])[1];
    const system = (UA_SYSTEMS.find(([re]) => re.test(ua)) || [])[1];
    if (browser && system) return `${browser} · ${system}`;
    return browser || system || UNKNOWN_CLIENT;
}

// Ключ лимитера по email: регистр и пробелы по краям не должны давать
// "новый" аккаунт для счётчика попыток.
function normalizeEmail(email) {
    return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

// Положительное число из переменной окружения или значение по умолчанию.
function positiveNumberOr(value, fallback) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

module.exports = {
    randomString,
    UNIQUE_CODE_ALPHABET,
    UNIQUE_CODE_LENGTH,
    generateUniqueCode,
    INVITE_CODE_ALPHABET,
    INVITE_CODE_LENGTH,
    generateInviteCode,
    normalizeInviteCode,
    isValidInviteCode,
    isInviteExpired,
    ALLOWED_MIME_TYPES,
    MIME_EXTENSIONS,
    ENCRYPTED_FILE_MIME,
    ENCRYPTED_FILE_EXTENSION,
    ANONYMIZED_FILE_NAMES,
    ALL_ANONYMIZED_FILE_NAMES,
    anonymizedFileName,
    normalizeHost,
    parseOrigin,
    parseAllowedOrigins,
    isRequestOriginAllowed,
    buildContentSecurityPolicy,
    resolveDbTlsConfig,
    createCounter,
    normalizeEmail,
    positiveNumberOr,
    UNKNOWN_CLIENT,
    classifyUserAgent,
};
