const { SocksProxyAgent } = require('socks-proxy-agent');

// Tor/SOCKS5 прокси конфигурация
const TOR_PROXY_HOST = process.env.TOR_PROXY_HOST || '127.0.0.1';
const TOR_PROXY_PORT = process.env.TOR_PROXY_PORT || 9050;
const ENABLE_TOR_ROUTING = process.env.ENABLE_TOR_ROUTING === 'true';

// Создание SOCKS5 агента для Tor
function createTorAgent() {
    if (!ENABLE_TOR_ROUTING) {
        return null;
    }

    const proxyUrl = `socks5://${TOR_PROXY_HOST}:${TOR_PROXY_PORT}`;
    return new SocksProxyAgent(proxyUrl);
}

// Проверка доступности Tor
async function checkTorConnection() {
    if (!ENABLE_TOR_ROUTING) {
        return { available: false, message: 'Tor routing disabled' };
    }

    try {
        const agent = createTorAgent();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch('https://check.torproject.org/api/ip', {
            agent,
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        const data = await response.json();

        return {
            available: true,
            isTor: data.IsTor || false,
            ip: data.IP
        };
    } catch (error) {
        console.error('[Tor] Connection check failed:', error.message);
        return {
            available: false,
            message: error.message
        };
    }
}

// Обертка для fetch через Tor
async function fetchViaTor(url, options = {}) {
    if (!ENABLE_TOR_ROUTING) {
        return fetch(url, options);
    }

    const agent = createTorAgent();
    return fetch(url, {
        ...options,
        agent
    });
}

// Генерация .onion адреса для hidden service (информационная функция)
function generateOnionAddress() {
    const crypto = require('crypto');

    // Это упрощенная версия для демонстрации
    // Реальный .onion адрес генерируется через Tor
    const randomBytes = crypto.randomBytes(35);
    const base32 = randomBytes.toString('base64')
        .replace(/\+/g, '')
        .replace(/\//g, '')
        .replace(/=/g, '')
        .toLowerCase()
        .slice(0, 56);

    return `${base32}.onion`;
}

// Настройка Tor Hidden Service
function getTorHiddenServiceConfig() {
    return {
        enabled: ENABLE_TOR_ROUTING,
        socksPort: TOR_PROXY_PORT,
        socksHost: TOR_PROXY_HOST,
        // Конфигурация для torrc файла
        hiddenServiceConfig: `
# Hidden Service Configuration for Nyxo Messenger
HiddenServiceDir /var/lib/tor/nyxo/
HiddenServicePort 80 127.0.0.1:${process.env.PORT || 3000}
HiddenServiceVersion 3
        `.trim()
    };
}

// Middleware для логирования анонимных подключений
function torConnectionLogger(req, res, next) {
    if (ENABLE_TOR_ROUTING) {
        const forwardedFor = req.headers['x-forwarded-for'];
        if (forwardedFor && forwardedFor.includes('.onion')) {
            console.log('[Tor] Onion service connection detected');
            req.isTorConnection = true;
        }
    }
    next();
}

module.exports = {
    createTorAgent,
    checkTorConnection,
    fetchViaTor,
    generateOnionAddress,
    getTorHiddenServiceConfig,
    torConnectionLogger,
    ENABLE_TOR_ROUTING
};
