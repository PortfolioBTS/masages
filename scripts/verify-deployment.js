#!/usr/bin/env node
'use strict';
// Сверка работающего сайта с манифестом клиента (6.1/6.3, roadmap R10): скачивает
// каждый файл манифеста (и «/») по адресу сайта и сравнивает sha256 и размер.
//
//   node scripts/verify-deployment.js <url> [--manifest <файл>] [--allow-http] [--timeout <мс>]
//
//   <url>          адрес сайта, например https://chat.example.com (путь отбрасывается);
//   --manifest     ЭТАЛОН — client-manifest.json из GitHub Release (скачайте его другим
//                  каналом, чем сам сайт). Без него эталоном служит манифест, который
//                  отдаёт сам сайт: такая проверка ловит неполный деплой и кэш, но НЕ
//                  подмену сервера (он отдаст манифест под свои файлы) — скрипт
//                  предупреждает об этом;
//   --allow-http   разрешить http:// для не локальных адресов (по умолчанию отказ:
//                  сверка по открытому каналу ничего не стоит; localhost и .onion
//                  разрешены без флага);
//   --timeout      тайм-аут одного запроса, мс (по умолчанию 20000).
//
// Код выхода: 0 — всё совпало; 1 — есть расхождения; 2 — не удалось проверить
// (неверные аргументы, нет сети, эталон не читается).
//
// Запускать надо на СВОЁМ устройстве или в CI (так делает watchdog.yml): тогда
// злонамеренный сервер не может подсунуть проверяющему другой код. Страница
// /verify.html на том же сервере такой гарантии не даёт.

const fs = require('fs');
const crypto = require('crypto');
const verify = require('../public/lib/client-verify');

const DEFAULT_TIMEOUT_MS = 20000;
const CONCURRENCY = 4;
const MANIFEST_PATH = '/client-manifest.json';

class UsageError extends Error {}

function sha256Hex(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

function isLocalOrOnionHost(hostname) {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '::1' || host.endsWith('.onion');
}

// Адрес сайта -> origin без хвоста; http для чужих хостов — только с allowHttp.
function normalizeBaseUrl(raw, { allowHttp = false } = {}) {
    let url;
    try {
        url = new URL(raw);
    } catch {
        throw new UsageError(`не адрес сайта: ${raw}`);
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new UsageError('нужен адрес http:// или https://');
    if (url.username || url.password) throw new UsageError('в адресе не должно быть логина и пароля');
    if (url.protocol === 'http:' && !allowHttp && !isLocalOrOnionHost(url.hostname)) {
        throw new UsageError('http:// для не локального адреса отвергнут: по открытому каналу сверка ничего не доказывает (--allow-http, если вы понимаете риск)');
    }
    return url.origin;
}

async function fetchBytes(fetchImpl, base, urlPath, timeoutMs) {
    // no-store: не брать файл из кэша; redirect manual: перенаправление — тоже расхождение.
    const res = await fetchImpl(base + urlPath, { cache: 'no-store', redirect: 'manual', credentials: 'omit', signal: AbortSignal.timeout(timeoutMs) });
    if (res.status !== 200) return { error: `HTTP ${res.status}` };
    return { bytes: Buffer.from(await res.arrayBuffer()) };
}

// Обход списка с ограниченной параллельностью; порядок результатов не важен.
async function mapLimit(items, limit, fn) {
    const results = new Array(items.length);
    let next = 0;
    const worker = async () => {
        while (next < items.length) {
            const index = next++;
            results[index] = await fn(items[index]);
        }
    };
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
    return results;
}

// Основная функция (без вывода): отчёт о сверке.
//   referenceText — текст эталонного манифеста или null (тогда эталон — манифест сайта).
async function verifyDeployment({ baseUrl, referenceText = null, fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    const report = {
        baseUrl,
        mode: referenceText === null ? 'self' : 'reference',
        referenceSha256: null,
        servedManifestSha256: null,
        manifestDiff: null,
        entries: [],
        problems: [],
        unverifiable: false,
        ok: false,
    };

    let served;
    try {
        const got = await fetchBytes(fetchImpl, baseUrl, MANIFEST_PATH, timeoutMs);
        if (got.error) throw new Error(got.error);
        report.servedManifestSha256 = sha256Hex(got.bytes);
        served = { text: got.bytes.toString('utf8'), parsed: verify.parseManifest(got.bytes.toString('utf8')) };
    } catch (err) {
        report.problems.push(`манифест сайта (${MANIFEST_PATH}) не получен: ${err.message}`);
        if (referenceText === null) {
            report.unverifiable = true; // сверять не с чем
            return report;
        }
    }

    let manifest;
    if (referenceText === null) {
        manifest = served.parsed;
    } else {
        manifest = verify.parseManifest(referenceText); // ошибка эталона — ошибка запуска, не расхождение
        report.referenceSha256 = sha256Hex(Buffer.from(referenceText, 'utf8'));
        if (served) {
            report.manifestDiff = verify.diffManifests(manifest, served.parsed);
            if (served.text !== referenceText) {
                const diff = report.manifestDiff;
                const parts = [];
                if (diff.changed.length) parts.push(`другие хэши: ${diff.changed.join(', ')}`);
                if (diff.onlyInServed.length) parts.push(`лишние файлы: ${diff.onlyInServed.join(', ')}`);
                if (diff.onlyInReference.length) parts.push(`нет файлов: ${diff.onlyInReference.join(', ')}`);
                if (diff.keyChanged) parts.push('другой ключ журнала ключей (keys.kt)');
                report.problems.push('манифест сайта отличается от эталона' + (parts.length ? ' (' + parts.join('; ') + ')' : ' (состав тот же, байты разные)'));
            }
        }
    }

    const wanted = verify.pathsToFetch(manifest);
    const seen = {};
    await mapLimit(wanted, CONCURRENCY, async (urlPath) => {
        try {
            const got = await fetchBytes(fetchImpl, baseUrl, urlPath, timeoutMs);
            seen[urlPath] = got.error ? { error: got.error } : { sha256: sha256Hex(got.bytes), bytes: got.bytes.length };
        } catch (err) {
            seen[urlPath] = { error: (err && err.name === 'TimeoutError') ? 'тайм-аут' : `запрос не удался: ${err && err.message ? err.message : err}` };
        }
    });
    const compared = verify.compareObserved(manifest, seen);
    report.entries = compared.entries;
    report.problems.push(...compared.problems);
    report.ok = report.problems.length === 0;
    return report;
}

function formatReport(report) {
    const lines = [];
    const matched = report.entries.filter((entry) => entry.state === 'match').length;
    lines.push(`Сайт: ${report.baseUrl}`);
    if (report.mode === 'reference') lines.push(`Эталон: манифест из файла, sha256 ${report.referenceSha256}`);
    else lines.push('Эталон: манифест самого сайта (НЕ независимый: не защищает от подмены сервера, укажите --manifest из релиза)');
    if (report.servedManifestSha256) lines.push(`Манифест сайта: sha256 ${report.servedManifestSha256}`);
    lines.push(`Файлов совпало: ${matched} из ${report.entries.length}`);
    for (const problem of report.problems) lines.push(`  РАСХОЖДЕНИЕ ${problem}`);
    for (const entry of report.entries) {
        if (entry.state === 'mismatch' && entry.actual && entry.actual !== entry.expected) {
            lines.push(`    ${entry.path}: ожидался ${entry.expected}, получен ${entry.actual}`);
        }
    }
    if (report.unverifiable) lines.push('Результат: ПРОВЕРИТЬ НЕ УДАЛОСЬ (сверять не с чем)');
    else lines.push(report.ok ? 'Результат: ОК' : 'Результат: ЕСТЬ РАСХОЖДЕНИЯ');
    return lines.join('\n') + '\n';
}

function parseArgs(argv) {
    const opts = { url: null, manifest: null, allowHttp: false, timeoutMs: DEFAULT_TIMEOUT_MS };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--manifest') opts.manifest = argv[++i];
        else if (arg === '--allow-http') opts.allowHttp = true;
        else if (arg === '--timeout') opts.timeoutMs = Number(argv[++i]);
        else if (arg.startsWith('--')) throw new UsageError(`неизвестный параметр ${arg}`);
        else if (opts.url === null) opts.url = arg;
        else throw new UsageError('адрес сайта указан дважды');
    }
    if (!opts.url) throw new UsageError('укажите адрес сайта: node scripts/verify-deployment.js <url> [--manifest <файл>]');
    if (opts.manifest === undefined || opts.manifest === '') throw new UsageError('у --manifest должен быть путь к файлу');
    if (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs < 100) throw new UsageError('--timeout — число миллисекунд, не меньше 100');
    return opts;
}

async function main(argv) {
    const opts = parseArgs(argv);
    const baseUrl = normalizeBaseUrl(opts.url, { allowHttp: opts.allowHttp });
    let referenceText = null;
    if (opts.manifest) {
        try {
            referenceText = fs.readFileSync(opts.manifest, 'utf8');
        } catch (err) {
            throw new UsageError(`эталонный манифест не читается: ${err.message}`);
        }
    }
    let report;
    try {
        report = await verifyDeployment({ baseUrl, referenceText, timeoutMs: opts.timeoutMs });
    } catch (err) {
        throw new UsageError(`эталонный манифест не годится: ${err.message}`);
    }
    process.stdout.write(formatReport(report));
    // Манифест сайта не получен и эталона нет — проверить нечего: это сбой проверки, а не «расхождение».
    if (report.unverifiable) return 2;
    return report.ok ? 0 : 1;
}

if (require.main === module) {
    main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (err) => {
        console.error('Ошибка: ' + (err && err.message ? err.message : err));
        process.exitCode = 2;
    });
}

module.exports = { verifyDeployment, formatReport, normalizeBaseUrl, parseArgs, isLocalOrOnionHost, UsageError };
