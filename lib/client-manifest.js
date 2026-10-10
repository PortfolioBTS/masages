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

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MANIFEST_FORMAT = 'nyxo-client-manifest/1';

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

// Объект манифеста. Порядок ключей — часть формата.
function buildManifest(publicDir) {
    const files = listClientFiles(publicDir).map((urlPath) => describeFile(publicDir, urlPath));
    for (const target of Object.values(ALIASES)) {
        if (!files.some((file) => file.path === target)) throw new Error(`В public/ нет ${target}`);
    }
    return { format: MANIFEST_FORMAT, aliases: { ...ALIASES }, files };
}

// Канонические байты манифеста: то, что отдаёт сервер и кладёт в релиз скрипт.
function serializeManifest(manifest) {
    return JSON.stringify(manifest, null, 2) + '\n';
}

function buildManifestText(publicDir) {
    return serializeManifest(buildManifest(publicDir));
}

// Хэш самого манифеста — короткий отпечаток версии клиента для людей и service worker.
function manifestSha256(text) {
    return sha256Hex(Buffer.from(text, 'utf8'));
}

// Разбор и проверка формы манифеста, пришедшего извне (verify-deployment, страница сверки).
// Возвращает объект или бросает ошибку с понятным текстом.
function parseManifest(text) {
    let data;
    try {
        data = JSON.parse(text);
    } catch (err) {
        throw new Error('манифест не разбирается как JSON: ' + err.message);
    }
    if (!data || data.format !== MANIFEST_FORMAT) throw new Error(`неизвестный формат манифеста: ${data && data.format}`);
    if (!Array.isArray(data.files) || data.files.length === 0) throw new Error('в манифесте нет списка files');
    const seen = new Set();
    for (const file of data.files) {
        const ok = file && typeof file.path === 'string' && file.path.startsWith('/') && !file.path.includes('..') &&
            /^[0-9a-f]{64}$/.test(file.sha256) && /^sha384-[A-Za-z0-9+/]{64}$/.test(file.sri) &&
            Number.isSafeInteger(file.bytes) && file.bytes >= 0;
        if (!ok) throw new Error(`некорректная запись манифеста: ${JSON.stringify(file)}`);
        if (seen.has(file.path)) throw new Error(`путь повторяется в манифесте: ${file.path}`);
        seen.add(file.path);
    }
    const aliases = data.aliases || {};
    for (const [from, to] of Object.entries(aliases)) {
        if (typeof from !== 'string' || !from.startsWith('/') || !seen.has(to)) throw new Error(`алиас ${from} ведёт на неизвестный файл`);
    }
    return data;
}

// Манифест для сервера: байты считаются при старте, а дальше пересчитываются,
// только если у какого-то файла изменились размер или время правки (в
// разработке public/ правят на ходу, в продакшене он неизменен). Запрос
// манифеста без аутентификации не должен каждый раз хэшировать мегабайты.
function createManifestProvider(publicDir) {
    let signature = null;
    let cached = null;

    const currentSignature = () => listClientFiles(publicDir).map((urlPath) => {
        const stat = fs.statSync(path.join(publicDir, ...urlPath.split('/').filter(Boolean)));
        return `${urlPath}\0${stat.size}\0${stat.mtimeMs}`;
    }).join('\n');

    function get() {
        const now = currentSignature();
        if (!cached || now !== signature) {
            const text = buildManifestText(publicDir);
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
    parseManifest,
    createManifestProvider,
};
