const crypto = require('crypto');

// Добавление случайной задержки для защиты от timing attacks
async function addRandomDelay(minMs = 10, maxMs = 50) {
    const delay = Math.random() * (maxMs - minMs) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
}

// Padding для сообщений для защиты от traffic analysis
function padMessage(text, targetSize = 256) {
    const currentLength = Buffer.byteLength(text, 'utf8');
    if (currentLength >= targetSize) {
        return text;
    }

    const paddingLength = targetSize - currentLength;
    const padding = crypto.randomBytes(Math.ceil(paddingLength / 2)).toString('hex').slice(0, paddingLength);
    return text + '\0' + padding;
}

function unpadMessage(paddedText) {
    const nullIndex = paddedText.indexOf('\0');
    return nullIndex >= 0 ? paddedText.substring(0, nullIndex) : paddedText;
}

// Генерация случайного шума для временных интервалов
function addTimingNoise(baseTimestamp, noiseRangeMs = 2000) {
    const noise = Math.floor(Math.random() * noiseRangeMs) - (noiseRangeMs / 2);
    return baseTimestamp + noise;
}

// Удаление метаданных из текстовых строк
function sanitizeText(text) {
    if (!text || typeof text !== 'string') return text;

    // Удаляем zero-width characters которые могут использоваться для fingerprinting
    return text.replace(/[​-‍﻿]/g, '');
}

// Генерация анонимного fingerprint для сессии
function generateSessionFingerprint() {
    return crypto.randomBytes(32).toString('hex');
}

// Проверка на потенциально опасные метаданные в JSON
function stripDangerousMetadata(obj) {
    const dangerous = ['__proto__', 'constructor', 'prototype'];
    const cleaned = {};

    for (const key in obj) {
        if (obj.hasOwnProperty(key) && !dangerous.includes(key)) {
            if (typeof obj[key] === 'object' && obj[key] !== null) {
                cleaned[key] = stripDangerousMetadata(obj[key]);
            } else {
                cleaned[key] = obj[key];
            }
        }
    }

    return cleaned;
}

// Создание secure headers для анонимности
function getPrivacyHeaders() {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    };
}

// Очистка IP адреса для логирования (частичная анонимизация)
function anonymizeIP(ip) {
    if (!ip) return '0.0.0.0';

    const parts = ip.split('.');
    if (parts.length === 4) {
        // IPv4: сохраняем первые два октета, обнуляем последние два
        return `${parts[0]}.${parts[1]}.0.0`;
    }

    // IPv6: сохраняем первые 4 сегмента
    const ipv6Parts = ip.split(':');
    if (ipv6Parts.length >= 4) {
        return ipv6Parts.slice(0, 4).join(':') + '::';
    }

    return '0.0.0.0';
}

// Генерация безопасного случайного токена
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('base64url');
}

// Хеширование для конфиденциальных данных
function hashSensitiveData(data, salt = null) {
    const actualSalt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(data, actualSalt, 100000, 64, 'sha512').toString('hex');
    return { hash, salt: actualSalt };
}

module.exports = {
    addRandomDelay,
    padMessage,
    unpadMessage,
    addTimingNoise,
    sanitizeText,
    generateSessionFingerprint,
    stripDangerousMetadata,
    getPrivacyHeaders,
    anonymizeIP,
    generateSecureToken,
    hashSensitiveData
};
