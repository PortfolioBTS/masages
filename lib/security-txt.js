'use strict';
// /.well-known/security.txt по RFC 9116 (8.4): куда писать об уязвимости.
//
// Файл строится из настроек, а не лежит в public/: express.static не отдаёт
// точечные пути, а Expires должен быть свежим — устаревший security.txt по
// стандарту считается недействительным. Если срок не задан, он скользящий:
// конец суток через 180 дней от момента запроса.
//
// Настройки (все необязательны):
//   SECURITY_CONTACT      — адреса для сообщений, через запятую или пробел:
//                           https://…, mailto:…, tel:+…. По умолчанию — форма
//                           приватных отчётов GitHub Security Advisories.
//   SECURITY_TXT_EXPIRES  — фиксированный срок, ISO 8601 (2027-03-01 или
//                           2027-03-01T12:00:00Z); не в прошлом и не дальше
//                           года. Иначе — скользящий.
//   PUBLIC_ORIGIN         — публичный адрес сайта, https://домен. Из него
//                           строится Canonical. Адрес из заголовка Host для
//                           этого брать нельзя: ответ кэшируется (public), и
//                           чужой Host попал бы в кэш.

const REPO_URL = 'https://github.com/PortfolioBTS/masages';
const DEFAULT_CONTACT = `${REPO_URL}/security/advisories/new`;
const POLICY_URL = `${REPO_URL}/blob/main/SECURITY.md`;
const WELL_KNOWN_PATH = '/.well-known/security.txt';
const ROLLING_DAYS = 180;
const MAX_EXPIRES_DAYS = 366;
const SOON_DAYS = 30;
const MAX_VALUE_LENGTH = 300;
const DAY_MS = 24 * 60 * 60 * 1000;
const EXPIRES_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2}))?$/;
// Пробелы, управляющие символы (в том числе перевод строки) и разделители строк Unicode.
function hasControlOrSpace(value) {
    for (const ch of value) {
        const code = ch.codePointAt(0);
        if (code <= 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) return true;
    }
    return false;
}

// Один адрес связи: https:, mailto: или tel:. Пробелы и управляющие символы
// (в том числе перевод строки — через него в файл попало бы чужое поле)
// недопустимы.
function isValidContact(value) {
    if (typeof value !== 'string' || value === '' || value.length > MAX_VALUE_LENGTH || hasControlOrSpace(value)) return false;
    let url;
    try { url = new URL(value); } catch { return false; }
    if (url.protocol === 'https:') return url.hostname !== '' && !url.username && !url.password;
    if (url.protocol === 'mailto:') return /^mailto:[^@\s,;?]+@[^@\s,;?]+\.[^@\s,;?]+(\?.*)?$/i.test(value);
    if (url.protocol === 'tel:') return /^tel:\+[0-9][0-9().-]{4,30}$/.test(value);
    return false;
}

// SECURITY_CONTACT → { contacts, invalid, usingDefault }.
function parseContacts(raw) {
    const items = typeof raw === 'string' ? raw.split(/[\s,]+/).filter(Boolean) : [];
    const contacts = [];
    const invalid = [];
    for (const item of items) {
        if (!isValidContact(item)) invalid.push(item);
        else if (!contacts.includes(item)) contacts.push(item);
    }
    if (contacts.length === 0) return { contacts: [DEFAULT_CONTACT], invalid, usingDefault: true };
    return { contacts, invalid, usingDefault: false };
}

// PUBLIC_ORIGIN → 'https://host[:port]' или null.
function parsePublicOrigin(raw) {
    if (typeof raw !== 'string' || raw.trim() === '') return null;
    const value = raw.trim();
    if (value.length > MAX_VALUE_LENGTH || hasControlOrSpace(value)) return null;
    let url;
    try { url = new URL(value); } catch { return null; }
    if (url.protocol !== 'https:' || url.hostname === '' || url.username || url.password) return null;
    if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) return null;
    return url.origin;
}

// Начало суток (UTC), в которые попадает момент ms.
const startOfUtcDay = (ms) => Math.floor(ms / DAY_MS) * DAY_MS;

// SECURITY_TXT_EXPIRES → { date, fixed, problem }. Годится только дата в
// будущем и не дальше MAX_EXPIRES_DAYS; иначе — скользящий срок, а problem
// говорит, что было не так (для env-check). Дата без времени — конец этих суток.
function resolveExpires(raw, now = Date.now()) {
    const rolling = (problem) => ({ date: new Date(startOfUtcDay(now + ROLLING_DAYS * DAY_MS)), fixed: false, problem });
    if (typeof raw !== 'string' || raw.trim() === '') return rolling(null);
    const value = raw.trim();
    if (!EXPIRES_RE.test(value)) return rolling('не дата ISO 8601 (например 2027-03-01 или 2027-03-01T12:00:00Z)');
    // Date.parse молча переносит 31 февраля на март — день проверяем сами.
    const [year, month, day] = value.slice(0, 10).split('-').map(Number);
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed) || month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()) {
        return rolling('не дата ISO 8601');
    }
    const ms = value.length === 10 ? parsed + DAY_MS - 1000 : parsed;
    if (ms <= now) return rolling('дата уже прошла');
    if (ms > now + MAX_EXPIRES_DAYS * DAY_MS) return rolling('дальше чем через год — RFC 9116 рекомендует меньше года');
    const date = new Date(ms);
    return {
        date,
        fixed: true,
        problem: null,
        expiresSoon: ms - now < SOON_DAYS * DAY_MS,
    };
}

// Настройки из окружения. onion — { address, port } из lib/tor-support.js.
function resolveSecurityTxtConfig(env = {}, { now = Date.now(), onion = null } = {}) {
    const contacts = parseContacts(env.SECURITY_CONTACT);
    const expires = resolveExpires(env.SECURITY_TXT_EXPIRES, now);
    const origin = parsePublicOrigin(env.PUBLIC_ORIGIN);
    const canonicals = [];
    if (origin) canonicals.push(`${origin}${WELL_KNOWN_PATH}`);
    if (onion && onion.address && onion.port) canonicals.push(`http://${onion.address}${WELL_KNOWN_PATH}`);
    return { contacts: contacts.contacts, canonicals, fixedExpires: expires.fixed ? expires.date : null };
}

const formatDate = (date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');

// Текст файла. config — resolveSecurityTxtConfig; Expires пересчитывается на
// каждый запрос (скользящий срок), фиксированный — берётся как есть.
function buildSecurityTxt(config, now = Date.now()) {
    const expires = config.fixedExpires && config.fixedExpires.getTime() > now
        ? config.fixedExpires
        : new Date(startOfUtcDay(now + ROLLING_DAYS * DAY_MS));
    const lines = [
        ...config.contacts.map(contact => `Contact: ${contact}`),
        `Expires: ${formatDate(expires)}`,
        'Preferred-Languages: ru, en',
        ...config.canonicals.map(url => `Canonical: ${url}`),
        `Policy: ${POLICY_URL}`,
    ];
    return `${lines.join('\n')}\n`;
}

module.exports = {
    DEFAULT_CONTACT,
    POLICY_URL,
    WELL_KNOWN_PATH,
    ROLLING_DAYS,
    isValidContact,
    parseContacts,
    parsePublicOrigin,
    resolveExpires,
    resolveSecurityTxtConfig,
    buildSecurityTxt,
};
