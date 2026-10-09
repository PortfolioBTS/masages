'use strict';
// Пути и окружение сквозных тестов.
//
// Сервер получает ЯВНЫЙ набор переменных, а не копию process.env: у
// разработчика в окружении может оказаться что угодно (DATABASE_URL боевой
// базы, NODE_OPTIONS, ANON_SERVICE_URL), и тест не должен от этого зависеть.

const path = require('path');
const crypto = require('crypto');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server.js');
const E2E_DIR = path.resolve(__dirname, '..');
const FIXTURES_DIR = path.join(E2E_DIR, 'fixtures');
// Куда сохраняются логи и причины сбоев упавших наборов. Переменная
// NYXO_E2E_LOGS_DIR — для проверки самого харнесса (harness-failures): набор
// запускает вложенные прогоны и смотрит, что они оставили, не засоряя
// настоящую папку.
const LOGS_DIR = process.env.NYXO_E2E_LOGS_DIR
    ? path.resolve(process.env.NYXO_E2E_LOGS_DIR)
    : path.join(E2E_DIR, '.logs');

// Админ-URL тестового Postgres (с правом CREATE DATABASE). Пароль — только
// в переменной окружения, в коде и файлах его нет.
function adminDatabaseUrl() {
    const url = process.env.E2E_DATABASE_URL;
    if (!url) {
        throw new Error('E2E_DATABASE_URL не задан — запускайте наборы через npm run test:e2e (см. docs/dev/testing.md)');
    }
    return url;
}

// Системные переменные, без которых процесс работает неправильно (PATH,
// SystemRoot — сеть на Windows, TEMP — временные файлы). Регистр имён —
// как в process.env: на Windows там бывает «Path».
const SYSTEM_VARS = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE']);

function systemEnv() {
    const env = {};
    for (const [name, value] of Object.entries(process.env)) {
        if (SYSTEM_VARS.has(name.toUpperCase())) env[name] = value;
    }
    return env;
}

// Секреты сервера — случайные на каждый набор (у легаси-фикстуры — свои,
// см. helpers/legacy.js).
function randomSecrets() {
    return {
        SESSION_SECRET: crypto.randomBytes(32).toString('base64url'),
        MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
    };
}

function base32(bytes) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    let out = '';
    let value = 0;
    let bits = 0;
    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
    return out;
}

// Валидный v3-адрес .onion для тестов и локального запуска (сервер
// проверяет контрольную сумму): base32(ключ ‖ checksum ‖ 0x03), checksum =
// SHA3-256(".onion checksum" ‖ ключ ‖ 0x03)[0..2]. «Ключ» — SHA-256 от
// строки, а не настоящий ключ ed25519: такой onion-сервис никто не поднимет.
function testOnionAddress(seed = 'nyxo-test-onion') {
    const key = crypto.createHash('sha256').update(seed, 'utf8').digest();
    const version = Buffer.from([3]);
    const checksum = crypto.createHash('sha3-256').update('.onion checksum').update(key).update(version).digest().subarray(0, 2);
    return `${base32(Buffer.concat([key, checksum, version]))}.onion`;
}

// Окружение процесса server.js. extra переопределяет значения по умолчанию;
// значение null или undefined убирает переменную.
function serverEnv({ databaseUrl, port, uploadsDir, secrets, extra = {} }) {
    const env = {
        ...systemEnv(),
        NODE_ENV: 'test',
        HOST: '127.0.0.1',
        PORT: String(port),
        DATABASE_URL: databaseUrl,
        ...secrets,
        POW_DIFFICULTY: '8',
        UPLOADS_DIR: uploadsDir,
        PG_POOL_MAX: '3',
        CLEANUP_INTERVAL_MS: '500',
        NYXO_TEST_MAINTENANCE_MS: '300',
    };
    for (const [name, value] of Object.entries(extra)) {
        if (value === undefined || value === null) delete env[name];
        else env[name] = String(value);
    }
    return env;
}

module.exports = {
    REPO_ROOT,
    SERVER_ENTRY,
    E2E_DIR,
    FIXTURES_DIR,
    LOGS_DIR,
    adminDatabaseUrl,
    systemEnv,
    randomSecrets,
    serverEnv,
    testOnionAddress,
};
