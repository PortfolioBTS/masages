'use strict';
// Настоящий IP клиента за прокси: CF-Connecting-IP принимается только если запрос физически
// пришёл с адреса Cloudflare (список диапазонов — DEFAULT_CLOUDFLARE_IP_RANGES, его можно заменить
// переменной CF_IP_RANGES). Вынесено из server.js.

const net = require('net');

// === Верификация CF-Connecting-IP (см. https://www.cloudflare.com/ips/) ===
// Список подтверждён на 2026-08-10. CF-Connecting-IP — это просто HTTP-заголовок,
// который любой клиент может подставить сам. Доверять ему можно только если сам
// запрос физически пришёл с IP-адреса Cloudflare — иначе, обращаясь напрямую на
// публичный *.up.railway.app домен, атакующий получает "новый IP" на каждый
// запрос и обнуляет все rate-limit'ы по IP (регистрация, вход в комнаты, API).
// Список можно переопределить через переменную окружения CF_IP_RANGES
// (через запятую), если Cloudflare обновит диапазоны.
const DEFAULT_CLOUDFLARE_IP_RANGES = [
    // IPv4
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    // IPv6
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function createRealIp() {
    const cloudflareBlockList = new net.BlockList();
    (function loadCloudflareRanges() {
        const ranges = process.env.CF_IP_RANGES
            ? process.env.CF_IP_RANGES.split(',').map(s => s.trim()).filter(Boolean)
            : DEFAULT_CLOUDFLARE_IP_RANGES;
        for (const cidr of ranges) {
            const [addr, prefixStr] = cidr.split('/');
            const type = net.isIP(addr);
            if (!type || !prefixStr) {
                console.warn('[CF] Пропущен некорректный диапазон:', cidr);
                continue;
            }
            cloudflareBlockList.addSubnet(addr, Number(prefixStr), type === 6 ? 'ipv6' : 'ipv4');
        }
    })();

    function isFromCloudflare(ip) {
        if (!ip) return false;
        const clean = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
        const type = net.isIP(clean);
        if (!type) return false;
        try {
            return cloudflareBlockList.check(clean, type === 6 ? 'ipv6' : 'ipv4');
        } catch (e) {
            return false;
        }
    }

    // connectingIp — адрес, с которого запрос физически пришёл на наш доверенный
    // прокси (Railway), а не значение из легко подделываемых заголовков.
    function resolveRealIp(headers, connectingIp) {
        const cfIp = headers['cf-connecting-ip'];
        if (cfIp && isFromCloudflare(connectingIp)) {
            return cfIp.split(',')[0].trim();
        }
        return connectingIp;
    }

    return { resolveRealIp };
}

module.exports = { createRealIp };
