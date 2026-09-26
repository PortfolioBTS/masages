const https = require('https');
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

    // socks5h — DNS-резолв тоже через Tor, иначе имя хоста утекает в
    // обычный DNS мимо прокси.
    const proxyUrl = `socks5h://${TOR_PROXY_HOST}:${TOR_PROXY_PORT}`;
    return new SocksProxyAgent(proxyUrl);
}

// GET + JSON через https-модуль. Встроенный fetch (undici) опцию `agent`
// молча игнорирует — раньше "проверка Tor" шла напрямую, мимо прокси.
function httpsGetJson(url, agent, timeoutMs) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { agent, timeout: timeoutMs }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                body += chunk;
                if (body.length > 1024 * 1024) req.destroy(new Error('Слишком большой ответ'));
            });
            res.on('end', () => {
                try { resolve(JSON.parse(body)); } catch (err) { reject(err); }
            });
        });
        req.on('timeout', () => req.destroy(new Error('Таймаут')));
        req.on('error', reject);
    });
}

// Проверка доступности Tor
async function checkTorConnection() {
    if (!ENABLE_TOR_ROUTING) {
        return { available: false, message: 'Tor routing disabled' };
    }

    try {
        const data = await httpsGetJson('https://check.torproject.org/api/ip', createTorAgent(), 10000);
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
    getTorHiddenServiceConfig,
    torConnectionLogger,
    ENABLE_TOR_ROUTING
};
