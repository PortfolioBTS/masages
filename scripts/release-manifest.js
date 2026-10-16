#!/usr/bin/env node
'use strict';
// Сборка релизных файлов клиента (6.1/6.3, roadmap R10). Ничего не собирает и
// не минифицирует: «сборка» клиента — это сами файлы public/, так что
//   git checkout vX.Y.Z && npm ci && node scripts/release-manifest.js
// даёт те же байты, что получил релиз, на любой ОС.
//
// Что записывается в каталог (по умолчанию release/):
//   client-manifest.json — манифест lib/client-manifest.js. БАЙТ В БАЙТ тот же
//                          файл, что отдаёт сервер по /client-manifest.json;
//                          в нём нет commit, времени и версии Node;
//   release.json         — всё, что от этого зависит: версия из package.json,
//                          commit, время коммита (SOURCE_DATE_EPOCH, не время
//                          запуска), версия Node, хэш манифеста и хэш sw.js
//                          (service worker в манифест не входит — он закрепляет
//                          хэш манифеста, — поэтому его хэш публикуется отдельно);
//   SHA256SUMS           — хэши файлов public/ в формате sha256sum; проверка:
//                          cd public && sha256sum -c ../release/SHA256SUMS.
//
// Запуск: node scripts/release-manifest.js [--out <каталог>] [--manifest-only] [--stdout] [--allow-dirty]
//   --manifest-only  только client-manifest.json: git не нужен
//   --stdout         манифест в stdout, файлы не пишутся (удобно для sha256sum)
//   --allow-dirty    собрать при незакоммиченных правках (для проверки на своей
//                    машине; в релизе так нельзя: commit не описывал бы файлы)
// Переменные: GITHUB_SHA — commit, если git недоступен; SOURCE_DATE_EPOCH —
// время в секундах (иначе время коммита из git).

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const clientManifest = require('../lib/client-manifest');
const { logError } = require('../lib/log-error');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const RELEASE_FORMAT = 'nyxo-release/1';
const MANIFEST_FILE = 'client-manifest.json';
const RELEASE_FILE = 'release.json';
const SUMS_FILE = 'SHA256SUMS';

function git(args) {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function resolveCommit(env) {
    const fromEnv = env.GITHUB_SHA;
    if (fromEnv) {
        if (!/^[0-9a-f]{40}$/.test(fromEnv)) throw new Error('GITHUB_SHA должен быть полным sha коммита (40 hex)');
        return fromEnv;
    }
    return git(['rev-parse', 'HEAD']);
}

function resolveEpoch(env) {
    const raw = env.SOURCE_DATE_EPOCH !== undefined && env.SOURCE_DATE_EPOCH !== '' ? env.SOURCE_DATE_EPOCH : git(['log', '-1', '--format=%ct']);
    if (!/^\d{1,12}$/.test(raw)) throw new Error('SOURCE_DATE_EPOCH — целое число секунд');
    return Number(raw);
}

// Три файла релиза в виде текстов. Чистая функция: всё внешнее приходит параметрами.
function buildReleaseFiles({ publicDir = PUBLIC_DIR, version, commit, epoch, nodeVersion }) {
    const manifest = clientManifest.buildManifest(publicDir);
    const manifestText = clientManifest.serializeManifest(manifest);
    const release = {
        format: RELEASE_FORMAT,
        version,
        commit,
        created: new Date(epoch * 1000).toISOString(),
        node: nodeVersion,
        manifest: {
            file: MANIFEST_FILE,
            sha256: clientManifest.manifestSha256(manifestText),
            bytes: Buffer.byteLength(manifestText, 'utf8'),
            files: manifest.files.length,
        },
    };
    // sw.js вне манифеста (R10): его хэш лежит здесь, и страница сверки показывает хэш того sw.js,
    // который сервер отдаёт сейчас. Без файла (синтетический каталог в тестах) поле не пишется.
    const swPath = path.join(publicDir, 'sw.js');
    if (fs.existsSync(swPath)) {
        const bytes = fs.readFileSync(swPath);
        release.serviceWorker = { file: 'sw.js', sha256: clientManifest.sha256Hex(bytes), bytes: bytes.length };
    }
    const sums = manifest.files.map((file) => `${file.sha256}  ${file.path.slice(1)}\n`).join('');
    return { manifestText, releaseText: JSON.stringify(release, null, 2) + '\n', sumsText: sums };
}

function parseArgs(argv) {
    const opts = { out: path.join(ROOT, 'release'), manifestOnly: false, stdout: false, allowDirty: false };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--out') opts.out = path.resolve(argv[++i] || '');
        else if (arg === '--manifest-only') opts.manifestOnly = true;
        else if (arg === '--stdout') opts.stdout = true;
        else if (arg === '--allow-dirty') opts.allowDirty = true;
        else throw new Error(`неизвестный параметр ${arg}`);
    }
    if (!opts.out) throw new Error('у --out должен быть каталог');
    return opts;
}

function main(argv, env) {
    const opts = parseArgs(argv);
    if (opts.stdout) {
        process.stdout.write(clientManifest.buildManifestText(PUBLIC_DIR));
        return;
    }
    fs.mkdirSync(opts.out, { recursive: true });
    if (opts.manifestOnly) {
        fs.writeFileSync(path.join(opts.out, MANIFEST_FILE), clientManifest.buildManifestText(PUBLIC_DIR));
        console.log(`Манифест записан: ${path.join(opts.out, MANIFEST_FILE)}`);
        return;
    }
    if (!opts.allowDirty && !env.GITHUB_SHA && git(['status', '--porcelain']) !== '') {
        throw new Error('В рабочем каталоге есть незакоммиченные правки: commit в release.json не описывал бы файлы. Закоммитьте или добавьте --allow-dirty.');
    }
    const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
    const files = buildReleaseFiles({ version, commit: resolveCommit(env), epoch: resolveEpoch(env), nodeVersion: process.version });
    // Запись без перевода строк по правилам ОС: fs.writeFileSync пишет строку как есть.
    fs.writeFileSync(path.join(opts.out, MANIFEST_FILE), files.manifestText);
    fs.writeFileSync(path.join(opts.out, RELEASE_FILE), files.releaseText);
    fs.writeFileSync(path.join(opts.out, SUMS_FILE), files.sumsText);
    const release = JSON.parse(files.releaseText);
    console.log(`Релиз ${release.version} (${release.commit.slice(0, 12)}), файлов клиента: ${release.manifest.files}`);
    console.log(`Манифест sha256: ${release.manifest.sha256}`);
    console.log(`Записано в ${opts.out}: ${MANIFEST_FILE}, ${RELEASE_FILE}, ${SUMS_FILE}`);
}

if (require.main === module) {
    try {
        main(process.argv.slice(2), process.env);
    } catch (err) {
        logError('Ошибка', err);
        process.exitCode = 1;
    }
}

module.exports = { buildReleaseFiles, parseArgs, RELEASE_FORMAT, MANIFEST_FILE, RELEASE_FILE, SUMS_FILE };
