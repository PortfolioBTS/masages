'use strict';
// Proof-of-work для регистрации вместо жёсткого лимита по IP.
//
// Почему: лимит "3 регистрации в час с IP" фактически запирал пользователей
// Tor — у них общий exit-IP с тысячами других людей, а через onion-сервис
// все вообще приходят с одного адреса контейнера tor. PoW делает массовую
// регистрацию дорогой для бота (каждый аккаунт — ~2^difficulty хэшей), но не
// зависит от того, откуда пришёл человек.
//
// Схема без состояния на сервере до момента проверки:
//   token = base64url(JSON {v, p, s, e, d}) + '.' + base64url(HMAC-SHA256)
//   p — назначение (сейчас одно: register-anon), s — случайная соль,
//   e — срок действия (мс), d — сложность.
// Клиент (public/pow-worker.js) ищет nonce из цифр, при котором
// SHA-256(utf8(token + ':' + nonce)) начинается с d нулевых бит.
//
// Ключ HMAC выводится из SESSION_SECRET (HKDF, метка 'nyxo-pow-v1'; setSecret
// вызывает server.js): задача, выданная до рестарта или другой репликой,
// остаётся действительной. Пока секрет не задан (юнит-тесты, отдельные
// скрипты), ключ случайный на процесс. Смена SESSION_SECRET делает все
// выданные задачи недействительными — клиент просто запросит новую.
//
// Одноразовость — отдельная часть: проверка решения (checkSolution) ничего не
// меняет, а «сжигает» задачу consumeSolution через внешнее хранилище
// (lib/pg-limits.js — таблица pow_used в Postgres), поэтому повтор не
// проходит ни после рестарта, ни на другой реплике. Неверный nonce задачу не
// сжигает: consume вызывается только для решения, которое прошло проверку.

const crypto = require('crypto');
const { deriveKey } = require('./derive-key');

// Назначение входит в подпись: решение одной цели не годится для другой.
// Цели register больше нет — аккаунты только временные (register-anon).
const PURPOSES = new Set(['register-anon']);
const TOKEN_VERSION = 1;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_DIFFICULTY = 18;
const MIN_DIFFICULTY = 8;
const MAX_DIFFICULTY = 28;
// Настоящий токен ~150 символов; всё заметно длиннее отбрасываем, не хэшируя.
const MAX_TOKEN_LENGTH = 512;
const NONCE_RE = /^[0-9]{1,20}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const PURGE_INTERVAL_MS = 60 * 1000;

function parseDifficulty(raw) {
    if (raw === undefined || raw === '') return DEFAULT_DIFFICULTY;
    // Только десятичные цифры: Number() принял бы и '1e1', и '0x10'.
    const value = /^[0-9]{1,2}$/.test(raw) ? Number(raw) : NaN;
    if (value >= MIN_DIFFICULTY && value <= MAX_DIFFICULTY) return value;
    console.warn(`[PoW] POW_DIFFICULTY должен быть целым от ${MIN_DIFFICULTY} до ${MAX_DIFFICULTY}; используется ${DEFAULT_DIFFICULTY}`);
    return DEFAULT_DIFFICULTY;
}

const DIFFICULTY = parseDifficulty(process.env.POW_DIFFICULTY);
let hmacKey = crypto.randomBytes(32);

// Ключ подписи задач из SESSION_SECRET. Вызывается один раз при старте
// сервера, до выдачи первой задачи.
function setSecret(secret) {
    hmacKey = deriveKey(secret, 'nyxo-pow-v1');
}

let now = Date.now;
// Подмена часов для тестов (проверка истечения срока без ожидания 5 минут).
// Без аргумента — возврат к Date.now.
function _setNowForTests(fn) {
    now = typeof fn === 'function' ? fn : Date.now;
}

// Использованные токены -> срок их действия — только для verifySolution (один
// процесс, без базы). Сервер использует consumeSolution с хранилищем в
// Postgres, а эта карта нужна юнит-тестам и скриптам. После истечения срока
// токен и так отвергается, поэтому запись можно забыть. Рост карты ограничен
// самой ценой PoW: каждая запись — это решённая задача.
const usedTokens = new Map();

function purgeUsed() {
    const t = now();
    for (const [token, expiresAt] of usedTokens) {
        if (expiresAt <= t) usedTokens.delete(token);
    }
}
// unref: таймер очистки не должен держать процесс (тесты, graceful shutdown).
setInterval(purgeUsed, PURGE_INTERVAL_MS).unref();

function sign(payloadB64) {
    return crypto.createHmac('sha256', hmacKey).update(payloadB64).digest('base64url');
}

function leadingZeroBits(bytes) {
    let bits = 0;
    for (const byte of bytes) {
        if (byte === 0) { bits += 8; continue; }
        return bits + Math.clz32(byte) - 24;
    }
    return bits;
}

function createChallenge(purpose) {
    if (!PURPOSES.has(purpose)) throw new Error('Недопустимое назначение proof-of-work');
    const payload = {
        v: TOKEN_VERSION,
        p: purpose,
        s: crypto.randomBytes(16).toString('base64url'),
        e: now() + CHALLENGE_TTL_MS,
        d: DIFFICULTY
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    return { token: `${payloadB64}.${sign(payloadB64)}`, difficulty: DIFFICULTY };
}

// Токен разбирается строго: подпись сравнивается как каноническая
// base64url-строка, а не как декодированные байты — Buffer.from(..., 'base64url')
// прощает мусор и лишние биты в последнем символе, и одно и то же решение
// можно было бы предъявить под несколькими "разными" токенами.
function readToken(token, purpose) {
    const dot = token.indexOf('.');
    if (dot <= 0 || dot !== token.lastIndexOf('.')) return null;
    const payloadB64 = token.slice(0, dot);
    const given = Buffer.from(token.slice(dot + 1), 'utf8');
    const expected = Buffer.from(sign(payloadB64), 'utf8');
    if (!B64URL_RE.test(payloadB64) || given.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(given, expected)) return null;

    let payload;
    try {
        payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch {
        return null;
    }
    if (!payload || payload.v !== TOKEN_VERSION || payload.p !== purpose) return null;
    if (!Number.isSafeInteger(payload.e) || payload.e <= now()) return null;
    if (!Number.isInteger(payload.d) || payload.d < MIN_DIFFICULTY || payload.d > MAX_DIFFICULTY) return null;
    return payload;
}

// Проверка решения без побочных эффектов: подпись, назначение, срок,
// сложность. Возвращает { token, expiresAt } или null. Использован ли токен
// раньше — не знает: это дело consumeSolution.
function checkSolution(solution, purpose) {
    if (!PURPOSES.has(purpose) || !solution || typeof solution !== 'object') return null;
    const { token, nonce } = solution;
    if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return null;
    if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) return null;

    const payload = readToken(token, purpose);
    if (!payload) return null;

    const digest = crypto.createHash('sha256').update(`${token}:${nonce}`, 'utf8').digest();
    if (leadingZeroBits(digest) < payload.d) return null;
    return { token, expiresAt: payload.e };
}

// Проверяет решение и сжигает задачу в usedStore.consume(sha256(token),
// expiresAtMs) → Promise<boolean> (true — впервые). Результат: 'ok' |
// 'invalid' (не прошло проверку; задача не сожжена) | 'replayed' (уже
// предъявляли). Ошибка хранилища пробрасывается: вызывающий отвечает «занято»,
// а не пропускает запрос.
async function consumeSolution(solution, purpose, usedStore) {
    if (!usedStore || typeof usedStore.consume !== 'function') {
        throw new TypeError('consumeSolution: нужно хранилище с методом consume()');
    }
    const checked = checkSolution(solution, purpose);
    if (!checked) return 'invalid';
    const tokenHash = crypto.createHash('sha256').update(checked.token, 'utf8').digest();
    return (await usedStore.consume(tokenHash, checked.expiresAt)) ? 'ok' : 'replayed';
}

// Синхронный вариант с памятью процесса: проверка + одноразовость без базы.
function verifySolution(solution, purpose) {
    const checked = checkSolution(solution, purpose);
    if (!checked || usedTokens.has(checked.token)) return false;
    // Помечаем только верное решение: неверный nonce не должен "сжигать"
    // задачу, которую клиент ещё может решить.
    usedTokens.set(checked.token, checked.expiresAt);
    return true;
}

module.exports = {
    createChallenge,
    checkSolution,
    consumeSolution,
    verifySolution,
    setSecret,
    _setNowForTests,
    _internal: { purgeUsed, usedCount: () => usedTokens.size }
};
