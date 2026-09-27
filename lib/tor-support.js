'use strict';
// Onion-сервис Nyxo: то, что нужно самому приложению.
//
// Раньше здесь была номинальная "поддержка Tor": логгер искал ".onion" в
// X-Forwarded-For (где его не бывает никогда), а ENABLE_TOR_ROUTING только
// проверял SOCKS-прокси при старте и ничего не маршрутизировал. Теперь сам
// onion-сервис — отдельный контейнер tor-service/ (tor + socat), который
// пробрасывает соединения из сети Tor в приложение по private network
// Railway. Приложению остаётся узнать, что запрос пришёл через onion, и
// подсказать Tor Browser, что у сайта есть onion-адрес (Onion-Location).
//
// Признак onion — ПОРТ, на который пришло соединение, а не заголовки.
// tor-service подключается к отдельному внутреннему порту ONION_PORT,
// который доступен только из private network и не опубликован наружу.
// Раньше признак брался из заголовка Host, но клиент внутри Tor может
// прислать любой Host (например, домен Railway) — и тогда его запрос
// считался бы обычным, а подделанный X-Forwarded-For становился бы его
// "IP" для лимитов. Сокет, принятый на ONION_PORT, подделать нельзя.

const crypto = require('crypto');
const net = require('net');
const https = require('https');

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const ONION_V3_RE = /^[a-z2-7]{56}\.onion$/;
const ONION_V3_VERSION = 3;

// Заголовки, которые добавляет обратный прокси. У onion-запроса прокси
// перед приложением нет (tor -> socat -> приложение), значит всё это прислал
// сам клиент — и при trust proxy = 1 Express поверил бы подделанному
// X-Forwarded-For (обход лимитов по IP) или X-Forwarded-Host.
const FORWARDING_HEADERS = [
    'forwarded',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-forwarded-proto',
    'x-real-ip',
    'cf-connecting-ip',
    'cf-connecting-ipv6',
    'true-client-ip'
];

// Onion-Location подставляем только в "безопасный" URL: печатный ASCII без
// пробелов. Иначе setHeader бросил бы исключение на экзотическом запросе.
const SAFE_URL_RE = /^\/[\x21-\x7e]*$/;

// v3-адрес = base32(pubkey[32] ‖ checksum[2] ‖ version[1]), где
// checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ version)[0..2], version = 3
// (rend-spec-v3). Контрольная сумма ловит опечатку при копировании адреса из
// лога tor-service — иначе Onion-Location уводил бы пользователей в никуда.
function isValidOnionV3(host) {
    if (typeof host !== 'string' || !ONION_V3_RE.test(host)) return false;
    const bytes = Buffer.alloc(35);
    let acc = 0, bits = 0, j = 0;
    for (let i = 0; i < 56; i++) {
        acc = ((acc << 5) | BASE32_ALPHABET.indexOf(host[i])) & 0xfff;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes[j++] = (acc >>> bits) & 0xff;
        }
    }
    const pubkey = bytes.subarray(0, 32);
    if (bytes[34] !== ONION_V3_VERSION) return false;
    const checksum = crypto.createHash('sha3-256')
        .update('.onion checksum')
        .update(pubkey)
        .update(Buffer.from([ONION_V3_VERSION]))
        .digest();
    return checksum[0] === bytes[32] && checksum[1] === bytes[33];
}

function parseOnionAddress(raw) {
    if (typeof raw !== 'string' || raw.trim() === '') return null;
    const host = raw.trim().toLowerCase();
    if (isValidOnionV3(host)) return host;
    console.warn('[Tor] ONION_ADDRESS игнорируется: нужен v3-адрес вида <56 символов base32>.onion ' +
        '(без http:// и слэшей) с верной контрольной суммой');
    return null;
}

const ONION_ADDRESS = parseOnionAddress(process.env.ONION_ADDRESS);

function parsePort(raw) {
    if (typeof raw !== 'string' || raw.trim() === '') return null;
    const port = Number(raw.trim());
    if (Number.isInteger(port) && port > 0 && port < 65536) return port;
    console.warn('[Tor] ONION_PORT игнорируется: нужен номер порта 1..65535');
    return null;
}

const ONION_PORT = parsePort(process.env.ONION_PORT);
if (ONION_ADDRESS && !ONION_PORT) {
    console.warn('[Tor] ONION_ADDRESS задан без ONION_PORT: onion-режим выключен. ' +
        'Без отдельного порта onion-запрос нельзя надёжно отличить от обычного (см. tor-service/README.md)');
}

// Сокеты, принятые на ONION_PORT. WeakSet — чтобы закрытые соединения не
// удерживались в памяти.
const onionSockets = new WeakSet();

function isOnionSocket(socket) {
    return Boolean(socket) && onionSockets.has(socket);
}

// Слушает ONION_PORT и передаёт принятые соединения в основной HTTP-сервер
// (emit('connection') — штатный способ подать сокет в http.Server: дальше
// им занимается тот же парсер, Express и Socket.io, что и основной порт).
// Возвращает net.Server или null, если onion-режим выключен.
function listenOnionPort(httpServer, host, onListening) {
    if (!ONION_PORT) return null;
    if (httpServer instanceof https.Server) {
        // Локальная разработка с mkcert: основной сервер ждёт TLS, а tor-service
        // присылает обычный HTTP. Onion в такой конфигурации не нужен.
        console.warn('[Tor] ONION_PORT не используется: основной сервер работает по HTTPS (режим разработки)');
        return null;
    }
    const listener = net.createServer((socket) => {
        onionSockets.add(socket);
        httpServer.emit('connection', socket);
    });
    listener.on('error', (err) => {
        console.error(`[Tor] Не удалось слушать ONION_PORT ${ONION_PORT}:`, err.message);
    });
    listener.listen(ONION_PORT, host, onListening);
    return listener;
}

// Host: "<адрес>.onion", "<адрес>.onion:80", "<адрес>.onion." — всё это один хост.
// Используется только для сверки Origin (страница, открытая по onion-адресу,
// шлёт Origin http://<адрес>.onion), но не как признак onion-соединения.
function isOnionHost(hostHeader) {
    if (!ONION_ADDRESS || typeof hostHeader !== 'string') return false;
    let host = hostHeader.trim().toLowerCase().replace(/:\d*$/, '');
    if (host.endsWith('.')) host = host.slice(0, -1);
    return host === ONION_ADDRESS;
}

function isPagePath(pathname) {
    return !(pathname === '/api' || pathname.startsWith('/api/') ||
        pathname.startsWith('/socket.io') ||
        pathname.startsWith('/uploads/'));
}

// Признак onion — сокет, принятый на ONION_PORT (см. шапку файла): ни Host,
// ни X-Forwarded-Host тут ничего не решают.
function onionMiddleware(req, res, next) {
    req.isOnion = isOnionSocket(req.socket);
    if (req.isOnion) {
        for (const name of FORWARDING_HEADERS) delete req.headers[name];
        // Onion-соединение зашифровано и аутентифицировано самим адресом
        // (адрес — это открытый ключ сервиса), и Tor Browser считает .onion
        // защищённым контекстом. Без этого express-session (proxy: true) не
        // выдал бы Secure-куку сессии по http://…onion — вход через onion был
        // бы невозможен в production.
        req.headers['x-forwarded-proto'] = 'https';
    } else if (ONION_ADDRESS && ONION_PORT && req.method === 'GET') {
        const url = req.originalUrl || req.url || '/';
        if (SAFE_URL_RE.test(url) && isPagePath(url.split('?', 1)[0])) {
            res.setHeader('Onion-Location', `http://${ONION_ADDRESS}${url}`);
        }
    }
    next();
}

module.exports = {
    ONION_ADDRESS,
    ONION_PORT,
    onionMiddleware,
    isOnionHost,
    isOnionSocket,
    listenOnionPort,
    _internal: { isValidOnionV3, markOnionSocket: (socket) => onionSockets.add(socket) }
};
