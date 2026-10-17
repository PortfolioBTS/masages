'use strict';
// Манифест клиента (6.1/6.3, roadmap R10): список всех файлов, которые сервер
// отдаёт браузеру из public/, с их хэшами. Это единственный источник правды
// для трёх потребителей: маршрут GET /client-manifest.json (lib/routes/
// client-manifest.js), скрипт релиза scripts/release-manifest.js и проверка
// развёртывания scripts/verify-deployment.js.
//
// Манифест ДЕТЕРМИНИРОВАН: он зависит только от байтов файлов и их путей. В нём
// нет commit, времени сборки, версии Node, версии пакета — всё это лежит в
// отдельном файле релиза (release.json). Поэтому тот же коммит даёт тот же
// манифест на любой машине, а манифест, который отдаёт работающий сервер,
// совпадает с тем, что скрипт собирает из тега, байт в байт. Для этого:
//   * пути отсортированы по кодовым единицам UTF-16 (не по локали);
//   * ключи объектов идут в порядке, заданном здесь, а не порядком обхода каталога;
//   * JSON — с отступом в 2 пробела, переводы строк LF, один LF в конце;
//   * хэшируются байты файла как они лежат на диске. .gitattributes
//     (`* text=auto eol=lf`) гарантирует LF и на Windows; тест репозитория
//     проверяет, что в текстовых файлах public/ нет CR.
//
// Что считается клиентом: всё, что отдаёт express.static из public/, кроме
// точечных файлов и каталогов (express.static их не отдаёт), каталога uploads
// (пользовательские файлы, не код) и /sw.js: service worker закрепляет хэш
// манифеста, и включать в манифест собственный хэш ему нельзя (R10).
// «/» — это тот же index.html (aliases), отдельной записью он не повторяется.
// Динамические ответы (/.well-known/security.txt, /healthz) — не код клиента.
//
// SRI-значения (sri: sha384-…) лежат в манифесте на будущее: атрибуты
// integrity в index.html пока не включены (волна 6, scripts/update-sri.js).
//
// Ключ журнала ключей (roadmap R10, docs/security/key-transparency.md, раздел 11). Если оператор включил журнал,
// в манифест после files добавляется keys: { kt: <открытый ключ журнала, base64, 32 байта> }. Клиент при первом
// закреплении ключа журнала сверяет его с этим значением (public/lib/kt-client.js, fetchManifestKey). Манифест по-прежнему
// детерминирован: он зависит от байтов файлов и ключа, который оператор называет явно (scripts/release-manifest.js
// --kt-key или KT_PUBLIC_KEY; сервер берёт тот же ключ из KT_SIGNING_KEY), и никогда — от времени и окружения.
// Ключ — отдельный параметр, а не файл в public/: он принадлежит развёртыванию, а не коду, и без него манифест
// (журнал выключен) байт в байт прежний.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Строгая проверка точки Ed25519: ключ журнала, который клиент будет считать корнем доверия, не должен быть
// ключом малого порядка или неканонической кодировкой (signed-membership.md, 6.1). Тот же файл исполняет браузер.
const ed25519Strict = require('../public/lib/ed25519-strict.js');

// Формат и разбор чужого манифеста живут в общем файле: его же исполняет страница
// /verify.html в браузере (public/lib/client-verify.js), и расхождений между ними быть не должно.
const { MANIFEST_FORMAT, parseManifest } = require('../public/lib/client-verify');

// Адрес -> файл, которым он отвечает.
const ALIASES = Object.freeze({ '/': '/index.html' });

// Что не входит в манифест (пути от корня сайта).
const EXCLUDED_PATHS = Object.freeze(['/sw.js']);
const EXCLUDED_TOP_DIRS = Object.freeze(['uploads']);

function sha256Hex(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Значение для атрибута integrity: sha384 в base64 (браузеры поддерживают sha256/384/512).
function sriOf(buffer) {
    return 'sha384-' + crypto.createHash('sha384').update(buffer).digest('base64');
}

// Сравнение по кодовым единицам, а не localeCompare: порядок не должен зависеть от ОС и локали.
function compareCodeUnits(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

// Пути файлов в public/ от корня сайта ("/lib/invite.js"), отсортированные.
function listClientFiles(publicDir) {
    const found = [];
    const walk = (absDir, urlDir) => {
        for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
            if (entry.name.startsWith('.')) continue;
            if (urlDir === '' && EXCLUDED_TOP_DIRS.includes(entry.name)) continue;
            const abs = path.join(absDir, entry.name);
            const url = `${urlDir}/${entry.name}`;
            if (entry.isDirectory()) {
                walk(abs, url);
            } else if (entry.isFile()) {
                if (!EXCLUDED_PATHS.includes(url)) found.push(url);
            } else {
                // express.static пошёл бы по ссылке и отдал бы файл, которого нет в манифесте.
                throw new Error(`В public/ только обычные файлы и каталоги, а ${url} — нет (ссылка?)`);
            }
        }
    };
    walk(publicDir, '');
    return found.sort(compareCodeUnits);
}

function describeFile(publicDir, urlPath) {
    const bytes = fs.readFileSync(path.join(publicDir, ...urlPath.split('/').filter(Boolean)));
    return { path: urlPath, sha256: sha256Hex(bytes), sri: sriOf(bytes), bytes: bytes.length };
}

// Открытый ключ журнала из параметра релиза или сервера: каноническое base64 ровно 32 байт, строгая проверка Ed25519.
// Пустое значение (undefined, null, '') — «ключа нет». Бросает Error с понятным текстом, значение в текст не входит.
function normalizeKtKey(value) {
    if (value === undefined || value === null) return null;
    if (typeof value !== 'string') throw new Error('ключ журнала должен быть строкой base64');
    const text = value.trim();
    if (text === '') return null;
    const bytes = Buffer.from(text, 'base64');
    if (bytes.toString('base64') !== text) throw new Error('ключ журнала: не каноническое base64 (нужны алфавит A-Za-z0-9+/ и "=" до кратности четырём)');
    if (bytes.length !== 32) throw new Error('ключ журнала: нужно ровно 32 байта (открытый ключ Ed25519), а не ' + bytes.length);
    if (!ed25519Strict.isStrictKey(new Uint8Array(bytes))) throw new Error('ключ журнала: недопустимая точка Ed25519 (малый порядок или неканоническая кодировка)');
    return text;
}

// Объект манифеста. Порядок ключей — часть формата. options.ktKey — открытый ключ журнала (см. выше): без него
// поля keys в манифесте нет вовсе, и байты те же, что до появления ключа.
function buildManifest(publicDir, options = {}) {
    const files = listClientFiles(publicDir).map((urlPath) => describeFile(publicDir, urlPath));
    for (const target of Object.values(ALIASES)) {
        if (!files.some((file) => file.path === target)) throw new Error(`В public/ нет ${target}`);
    }
    const manifest = { format: MANIFEST_FORMAT, aliases: { ...ALIASES }, files };
    const ktKey = normalizeKtKey(options.ktKey);
    if (ktKey) manifest.keys = { kt: ktKey };
    return manifest;
}

// Канонические байты манифеста: то, что отдаёт сервер и кладёт в релиз скрипт.
function serializeManifest(manifest) {
    return JSON.stringify(manifest, null, 2) + '\n';
}

function buildManifestText(publicDir, options = {}) {
    return serializeManifest(buildManifest(publicDir, options));
}

// Хэш самого манифеста — короткий отпечаток версии клиента для людей и service worker.
function manifestSha256(text) {
    return sha256Hex(Buffer.from(text, 'utf8'));
}

// Манифест для сервера: байты считаются при старте, а дальше пересчитываются,
// только если у какого-то файла изменились размер или время правки (в
// разработке public/ правят на ходу, в продакшене он неизменен). Запрос
// манифеста без аутентификации не должен каждый раз хэшировать мегабайты.
function createManifestProvider(publicDir, options = {}) {
    const ktKey = normalizeKtKey(options.ktKey);
    let signature = null;
    let cached = null;

    const currentSignature = () => listClientFiles(publicDir).map((urlPath) => {
        const stat = fs.statSync(path.join(publicDir, ...urlPath.split('/').filter(Boolean)));
        return `${urlPath}\0${stat.size}\0${stat.mtimeMs}`;
    }).join('\n');

    function get() {
        const now = currentSignature();
        if (!cached || now !== signature) {
            const text = buildManifestText(publicDir, { ktKey });
            cached = { text, buffer: Buffer.from(text, 'utf8'), sha256: manifestSha256(text) };
            signature = now;
        }
        return cached;
    }

    get(); // упасть при старте, если public/ не читается, а не на первом запросе
    return { get };
}

module.exports = {
    MANIFEST_FORMAT,
    ALIASES,
    EXCLUDED_PATHS,
    sha256Hex,
    sriOf,
    listClientFiles,
    buildManifest,
    serializeManifest,
    buildManifestText,
    manifestSha256,
    normalizeKtKey,
    parseManifest,
    createManifestProvider,
};
