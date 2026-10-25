'use strict';
// Кому разрешено подключаться к ONION_PORT (W7 R1 п.6).
//
// Признак onion-запроса - сам порт: сокет, принятый на ONION_PORT, считается пришедшим из сети
// Tor, и для него отключены лимиты по IP (у всех onion-клиентов один адрес контейнера tor).
// Порт слушает тот же HOST, что и основной (0.0.0.0), и если его опубликовать наружу или он
// окажется достижим, любой получил бы режим onion без IP-лимитов. Поэтому соединение с ONION_PORT
// принимается только с частных и loopback-адресов (private network Railway, docker-сеть, локальный
// tor-service), остальные закрываются сразу.
//
// ONION_ALLOWED_CIDR - своя сеть: список CIDR через запятую (10.8.0.0/16, fd00:1::/32, 192.0.2.7).
// Если задан, ЗАМЕНЯЕТ список по умолчанию (строже). Некорректные записи пропускаются, а если
// не осталось ни одной корректной - действует список по умолчанию (иначе onion молча отвалился бы).

const net = require('net');

const DEFAULT_RANGES = Object.freeze([
    ['127.0.0.0', 8, 'ipv4'], ['10.0.0.0', 8, 'ipv4'], ['172.16.0.0', 12, 'ipv4'], ['192.168.0.0', 16, 'ipv4'],
    ['169.254.0.0', 16, 'ipv4'],
    ['::1', 128, 'ipv6'], ['fc00::', 7, 'ipv6'], ['fe80::', 10, 'ipv6'],
]);

function addDefaults(list) {
    for (const [address, prefix, family] of DEFAULT_RANGES) list.addSubnet(address, prefix, family);
}

// Разбор одной записи "адрес" или "адрес/префикс" -> { address, prefix, family } или null.
function parseCidr(entry) {
    const [address, prefixText, extra] = entry.split('/');
    if (extra !== undefined) return null;
    const family = net.isIP(address);
    if (!family) return null;
    const maxPrefix = family === 4 ? 32 : 128;
    let prefix = maxPrefix;
    if (prefixText !== undefined) {
        if (!/^\d{1,3}$/.test(prefixText)) return null;
        prefix = Number(prefixText);
        if (prefix > maxPrefix) return null;
    }
    return { address, prefix, family: family === 4 ? 'ipv4' : 'ipv6' };
}

function createOnionAllowList(cidrText) {
    const list = new net.BlockList();
    const invalid = [];
    let custom = 0;
    for (const raw of String(cidrText || '').split(',')) {
        const entry = raw.trim();
        if (!entry) continue;
        const parsed = parseCidr(entry);
        if (!parsed) { invalid.push(entry); continue; }
        list.addSubnet(parsed.address, parsed.prefix, parsed.family);
        custom++;
    }
    if (custom === 0) addDefaults(list);
    return {
        invalid,
        custom: custom > 0,
        // remoteAddress - socket.remoteAddress ('::ffff:10.0.0.5' для IPv4 на двойном стеке).
        allows(remoteAddress) {
            const family = net.isIP(remoteAddress);
            if (!family) return false;
            return list.check(remoteAddress, family === 4 ? 'ipv4' : 'ipv6');
        },
    };
}

module.exports = { createOnionAllowList, DEFAULT_RANGES };
