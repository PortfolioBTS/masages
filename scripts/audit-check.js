#!/usr/bin/env node
'use strict';
// Проверка зависимостей по политике проекта (пункт 7.1 плана): разбирает отчёт
// `npm audit --json` и решает, ронять ли сборку. Сам `npm audit` умеет только
// «падать при любой находке выше порога» — для двух порогов (прод и dev),
// исключений со сроком и сводки в CI этого мало.
//
// Политика и почему она такая:
//  - прод-зависимости (npm audit --omit=dev): падение на high и critical. Это
//    код, который исполняется на сервере и принимает чужие данные;
//  - остальные (dev): падение только на critical. Инструменты разработки не
//    обрабатывают данные пользователей, high в них не должен останавливать
//    сборку — такие находки видны в сводке;
//  - moderate и low сборку не роняют: они попадают в сводку
//    ($GITHUB_STEP_SUMMARY), дальше их отслеживают оповещения Dependabot;
//  - исключения — audit-allowlist.json:
//      {"exceptions":[{"id":"GHSA-xxxx-xxxx-xxxx","reason":"…","expires":"YYYY-MM-DD"}]}
//    Исключение действует до конца указанного дня (UTC). Просроченное
//    исключение роняет сборку, даже если уязвимость уже исправлена: иначе
//    «временное» исключение остаётся в списке навсегда.
//
// Политика применяется к уникальным advisory (GHSA), а не к пакетам. У пакета,
// затронутого только через зависимость (via: ["ws"]), собственной уязвимости
// нет: его серьёзность — производная. Поэтому исключение на корневой advisory
// закрывает всю цепочку, а несвязанные находки в тех же пакетах остаются.
//
// Запуск:
//   node scripts/audit-check.js          сам запускает npm audit дважды: --omit=dev и все
//                                        зависимости (нужны сеть и package-lock.json)
//   node scripts/audit-check.js --stdin  читает отчёт из stdin, без сети (для тестов): либо один
//                                        отчёт npm audit (его advisory считаются прод — самая
//                                        строгая политика), либо {"prod": <отчёт>, "all": <отчёт>}
//   --allowlist <файл>                   другой файл исключений (по умолчанию audit-allowlist.json в корне)
//
// Код выхода: 0 — политика соблюдена; 1 — есть нарушения или просроченные
// исключения; 2 — не удалось получить или разобрать отчёт либо файл
// исключений (сбой среды, а не политики: сеть, реестр, формат).

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DEFAULT_ALLOWLIST = path.join(ROOT, 'audit-allowlist.json');

const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'];
const PROD_FAIL_LEVEL = 'high';
const ALL_FAIL_LEVEL = 'critical';

const GHSA_RE = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i;
const GHSA_EXACT_RE = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const USAGE = [
    'Использование: node scripts/audit-check.js [--stdin] [--allowlist <файл>]',
    '  без флагов      запускает npm audit (прод и все зависимости) и проверяет по политике',
    '  --stdin         читает JSON из stdin: отчёт npm audit или {"prod": …, "all": …}',
    '  --allowlist     файл исключений (по умолчанию audit-allowlist.json в корне репозитория)',
    'Код выхода: 0 — ок, 1 — нарушения политики, 2 — сбой получения или разбора отчёта.',
].join('\n');

// Сбой входных данных (отчёт npm, файл исключений, аргументы). Это не
// нарушение политики, а поломка среды, поэтому код выхода другой (2).
class AuditInputError extends Error {
    constructor(message) {
        super(message);
        this.name = 'AuditInputError';
    }
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const rank = (severity) => SEVERITIES.indexOf(severity);

// Управляющие символы C0/C1 и разделители строк Юникода. Разделители (код 2028 и 2029 в
// шестнадцатеричной записи) собираются из кодов, а не пишутся в литерале: литерал с ними в
// регулярном выражении — синтаксическая ошибка.
const CONTROL_CHARS = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f' + String.fromCharCode(0x2028, 0x2029) + ']+', 'g');

// Текст advisory приходит из внешней базы и попадает в лог CI и в Markdown-
// сводку. Управляющие символы убираем: иначе перевод строки в названии дал бы
// строку вывода, начинающуюся с `::` — а раннер Actions исполняет такие строки
// как свои команды (ведущие пробелы он отбрасывает). По той же причине `::` в
// самом начале текста разбавляется пробелом; в середине (IPv6 в названиях)
// он безопасен и остаётся как есть. Длина ограничена.
function clean(text, max = 200) {
    const flat = String(text === undefined || text === null ? '' : text)
        .replace(CONTROL_CHARS, ' ')
        .trim()
        .replace(/^::/, ': :');
    return flat.length > max ? flat.slice(0, max - 1) + '…' : flat;
}

function safeUrl(url) {
    return typeof url === 'string' && /^https:\/\/\S+$/.test(url) ? clean(url, 300) : '';
}

// Канонический вид идентификатора: «GHSA» заглавными, остальное строчными —
// так его показывает GitHub. Сравнение исключений идёт по нему.
function normalizeGhsa(text) {
    return 'GHSA-' + String(text).slice(5).toLowerCase();
}

function isValidDate(text) {
    if (typeof text !== 'string' || !DATE_RE.test(text)) return false;
    const date = new Date(text + 'T00:00:00Z');
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === text;
}

function advisoryId(via) {
    const fromUrl = typeof via.url === 'string' ? GHSA_RE.exec(via.url) : null;
    if (fromUrl) return normalizeGhsa(fromUrl[0]);
    // Запасной вариант — числовой идентификатор реестра. Такой advisory нельзя
    // внести в исключения (там допустимы только GHSA), он всегда учитывается.
    if (via.source !== undefined && via.source !== null && via.source !== '') return `npm-${via.source}`;
    throw new AuditInputError('в отчёте есть advisory без url и source — для него нельзя построить идентификатор');
}

// Наибольшая серьёзность, о которой сообщает metadata.vulnerabilities (счётчики
// по пакетам). -1 — блока нет или все счётчики нулевые.
function metadataMaxRank(report) {
    const counts = isObject(report.metadata) ? report.metadata.vulnerabilities : null;
    if (!isObject(counts)) return -1;
    let max = -1;
    for (const severity of SEVERITIES) {
        if (Number(counts[severity]) > 0) max = Math.max(max, rank(severity));
    }
    return max;
}

// Отчёт npm audit v7+ -> Map<id, advisory>. Advisory — это объекты в via[];
// строки в via[] — ссылки на другие уязвимые пакеты цепочки, своих advisory
// у них нет (их находки лежат в записи того пакета).
function parseAuditReport(report, label = 'отчёт') {
    if (!isObject(report)) throw new AuditInputError(`${label}: ожидался JSON-объект`);
    if (report.error) {
        const details = [report.message, report.error.summary, report.error.detail]
            .filter((part) => typeof part === 'string' && part.trim())
            .map((part) => clean(part, 300));
        throw new AuditInputError(`${label}: npm audit сообщил об ошибке${details.length ? ': ' + details.join('; ') : ''}`);
    }
    if (report.auditReportVersion !== 2 || !isObject(report.vulnerabilities)) {
        const hint = typeof report.message === 'string' && report.message ? `: ${clean(report.message, 300)}` : '';
        throw new AuditInputError(`${label}: неподдерживаемый формат (нужен auditReportVersion 2 из npm 7+)${hint}`);
    }

    const advisories = new Map();
    for (const [pkg, entry] of Object.entries(report.vulnerabilities)) {
        if (!isObject(entry) || !Array.isArray(entry.via)) {
            throw new AuditInputError(`${label}: запись «${clean(pkg, 80)}» не похожа на формат npm audit (нет via)`);
        }
        for (const via of entry.via) {
            if (typeof via === 'string') continue;
            if (!isObject(via)) throw new AuditInputError(`${label}: в via пакета «${clean(pkg, 80)}» неожиданное значение`);
            const severity = typeof via.severity === 'string' ? via.severity.toLowerCase() : '';
            if (!SEVERITIES.includes(severity)) {
                throw new AuditInputError(`${label}: неизвестная серьёзность «${clean(via.severity, 40)}» у пакета «${clean(pkg, 80)}»`);
            }
            const id = advisoryId(via);
            const name = typeof via.name === 'string' && via.name ? via.name : pkg;
            const known = advisories.get(id);
            if (known) {
                known.packages.add(name);
                if (rank(severity) > rank(known.severity)) known.severity = severity;
                continue;
            }
            advisories.set(id, { id, severity, title: clean(via.title), url: safeUrl(via.url), packages: new Set([name]) });
        }
    }

    // Страховка от «тихого» пропуска: если npm однажды изменит форму via[], а
    // metadata по-прежнему сообщит о находках, лучше упасть с понятной
    // причиной, чем решить, что всё чисто.
    const parsedMax = Math.max(-1, ...[...advisories.values()].map((a) => rank(a.severity)));
    if (metadataMaxRank(report) > parsedMax) {
        throw new AuditInputError(`${label}: metadata сообщает о находках серьёзности ${SEVERITIES[metadataMaxRank(report)]}, а в vulnerabilities таких advisory не найдено — формат отчёта изменился?`);
    }
    return advisories;
}

// Файл исключений -> список {id, reason, expires} в каноническом виде.
function validateAllowlist(data, source = 'audit-allowlist.json') {
    if (!isObject(data) || !Array.isArray(data.exceptions)) {
        throw new AuditInputError(`${source}: ожидается объект {"exceptions": [...]}`);
    }
    const seen = new Set();
    return data.exceptions.map((item, index) => {
        const where = `${source}: exceptions[${index}]`;
        if (!isObject(item)) throw new AuditInputError(`${where}: ожидается объект`);
        const rawId = typeof item.id === 'string' ? item.id.trim() : '';
        if (!GHSA_EXACT_RE.test(rawId)) throw new AuditInputError(`${where}: id должен быть вида GHSA-xxxx-xxxx-xxxx`);
        const id = normalizeGhsa(rawId);
        if (seen.has(id)) throw new AuditInputError(`${where}: исключение ${id} указано дважды`);
        seen.add(id);
        const reason = typeof item.reason === 'string' ? item.reason.trim() : '';
        if (!reason) throw new AuditInputError(`${where}: нужна причина (reason) — зачем исключение и что сделано для обхода риска`);
        if (!isValidDate(item.expires)) throw new AuditInputError(`${where}: expires — существующая дата в формате YYYY-MM-DD`);
        return { id, reason, expires: item.expires };
    });
}

// Без файла исключений (по умолчанию) — исключений нет: так строже. Явно
// указанный --allowlist, которого нет, — ошибка (опечатка в пути не должна
// молча отключать исключения или маскировать причину падения).
function loadAllowlist(file, { required = false } = {}) {
    let text;
    try {
        text = fs.readFileSync(file, 'utf8');
    } catch (err) {
        if (err.code === 'ENOENT' && !required) return [];
        throw new AuditInputError(`не удалось прочитать файл исключений ${file}: ${err.message}`);
    }
    let data;
    try {
        data = JSON.parse(text.replace(/^﻿/, ''));
    } catch (err) {
        throw new AuditInputError(`${path.basename(file)}: некорректный JSON: ${err.message}`);
    }
    return validateAllowlist(data, path.basename(file));
}

function zeroCounts() {
    return Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
}

// prod, all — Map из parseAuditReport. all === null означает «отдельного
// отчёта по всем зависимостям нет»: тогда всё считается прод-зависимостями.
// today — 'YYYY-MM-DD' по UTC; строки этого вида сравниваются как даты.
function evaluate({ prod, all = null, exceptions = [], today }) {
    if (!DATE_RE.test(String(today))) throw new TypeError('today: ожидается строка YYYY-MM-DD');

    // Один и тот же advisory в обоих отчётах — прод (он есть в --omit=dev);
    // «только dev» — то, что видно лишь в полном отчёте.
    const merged = new Map();
    const put = (advisory, scope) => {
        const known = merged.get(advisory.id);
        if (!known) {
            merged.set(advisory.id, { ...advisory, packages: new Set(advisory.packages), scope });
            return;
        }
        if (scope === 'prod') known.scope = 'prod';
        for (const name of advisory.packages) known.packages.add(name);
        if (rank(advisory.severity) > rank(known.severity)) known.severity = advisory.severity;
    };
    for (const advisory of (all || prod).values()) put(advisory, 'dev');
    for (const advisory of prod.values()) put(advisory, 'prod');

    const bySeverity = (a, b) => rank(b.severity) - rank(a.severity) || a.id.localeCompare(b.id);
    const advisories = [...merged.values()]
        .map((a) => ({ ...a, packages: [...a.packages].sort() }))
        .sort(bySeverity);

    const byId = new Map(exceptions.map((exception) => [exception.id, exception]));
    const result = {
        blocking: [],
        excepted: [],
        nonBlocking: [],
        expired: [],
        unused: [],
        counts: { prod: zeroCounts(), dev: zeroCounts() },
        total: advisories.length,
    };
    const used = new Set();
    for (const advisory of advisories) {
        result.counts[advisory.scope][advisory.severity] += 1;
        const threshold = advisory.scope === 'prod' ? PROD_FAIL_LEVEL : ALL_FAIL_LEVEL;
        if (rank(advisory.severity) < rank(threshold)) {
            result.nonBlocking.push(advisory);
            continue;
        }
        const exception = byId.get(advisory.id);
        if (exception && exception.expires >= today) {
            used.add(exception.id);
            result.excepted.push({ ...advisory, exception });
        } else {
            result.blocking.push(advisory);
        }
    }
    for (const exception of exceptions) {
        if (exception.expires < today) result.expired.push(exception);
        else if (!used.has(exception.id)) result.unused.push(exception);
    }
    result.ok = result.blocking.length === 0 && result.expired.length === 0;
    return result;
}

const SCOPE_LABEL = { prod: 'прод', dev: 'dev' };
const countsLine = (counts) => SEVERITIES.slice().reverse().map((s) => `${s} ${counts[s]}`).join(', ');

function advisoryLines(advisory, { link = false } = {}) {
    const lines = [`  ${advisory.severity.padEnd(8)}  ${advisory.id}  [${SCOPE_LABEL[advisory.scope]}] ${advisory.packages.join(', ')}`];
    if (link) {
        if (advisory.title) lines.push(`            ${advisory.title}`);
        if (advisory.url) lines.push(`            ${advisory.url}`);
    }
    return lines;
}

function formatText(result, today) {
    const lines = [];
    lines.push(`npm audit: проверка по политике проекта (на ${today}, UTC)`);
    lines.push(`Политика: прод-зависимости — падение на ${PROD_FAIL_LEVEL} и выше; только dev — на ${ALL_FAIL_LEVEL}; остальное — лишь в сводке.`);
    lines.push('');
    lines.push(`Уникальных advisory: ${result.total}`);
    lines.push(`  прод:       ${countsLine(result.counts.prod)}`);
    lines.push(`  только dev: ${countsLine(result.counts.dev)}`);

    if (result.blocking.length > 0) {
        lines.push('', `НАРУШЕНИЯ — блокируют сборку (${result.blocking.length}):`);
        for (const advisory of result.blocking) lines.push(...advisoryLines(advisory, { link: true }));
    }
    if (result.expired.length > 0) {
        lines.push('', `ПРОСРОЧЕННЫЕ ИСКЛЮЧЕНИЯ — блокируют сборку (${result.expired.length}):`);
        for (const exception of result.expired) {
            lines.push(`  ${exception.id}  истекло ${exception.expires}: ${clean(exception.reason, 160)}`);
        }
        lines.push('  Удалите исключение из audit-allowlist.json или продлите его с новым обоснованием.');
    }
    if (result.excepted.length > 0) {
        lines.push('', `Закрыто исключениями (${result.excepted.length}):`);
        for (const advisory of result.excepted) {
            lines.push(...advisoryLines(advisory));
            lines.push(`            до ${advisory.exception.expires}: ${clean(advisory.exception.reason, 160)}`);
        }
    }
    if (result.nonBlocking.length > 0) {
        lines.push('', `Не блокируют сборку (${result.nonBlocking.length}):`);
        for (const advisory of result.nonBlocking) {
            lines.push(...advisoryLines(advisory));
            if (advisory.title) lines.push(`            ${advisory.title}`);
        }
    }
    if (result.unused.length > 0) {
        lines.push('', `Исключения, которые ничего не закрывают — их можно удалить (${result.unused.length}):`);
        for (const exception of result.unused) lines.push(`  ${exception.id}  до ${exception.expires}`);
    }

    lines.push('');
    if (result.ok) {
        lines.push('ИТОГ: ОК — нарушений политики нет.');
    } else {
        lines.push(`ИТОГ: ПРОВАЛ — нарушений: ${result.blocking.length}, просроченных исключений: ${result.expired.length}.`);
        if (result.blocking.length > 0) {
            lines.push('Как исправить: обновить зависимость (npm audit fix, затем npm test); если исправления нет — временное исключение в audit-allowlist.json с причиной и сроком.');
        }
    }
    return lines.join('\n');
}

// Ячейка Markdown-таблицы: текст внешний, поэтому экранируем всё, что ломает
// таблицу или превращается в разметку и HTML.
function mdCell(text) {
    return clean(text, 300)
        .replace(/\\/g, '\\\\')
        .replace(/\|/g, '\\|')
        .replace(/[<>&`]/g, (ch) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '`': "'" }[ch]));
}

function formatMarkdown(result, today) {
    const lines = [];
    lines.push(`## npm audit: ${result.ok ? 'ОК' : 'ПРОВАЛ'}`, '');
    lines.push(`Политика на ${today} (UTC): прод-зависимости — падение на ${PROD_FAIL_LEVEL} и выше; только dev — на ${ALL_FAIL_LEVEL}; остальное — лишь в сводке.`, '');
    lines.push('| Область | ' + SEVERITIES.slice().reverse().join(' | ') + ' |');
    lines.push('|---|' + SEVERITIES.map(() => '---:|').join(''));
    for (const scope of ['prod', 'dev']) {
        const name = scope === 'prod' ? 'Прод-зависимости' : 'Только dev';
        lines.push(`| ${name} | ` + SEVERITIES.slice().reverse().map((s) => result.counts[scope][s]).join(' | ') + ' |');
    }

    const table = (title, rows, extraHeader, extraCell) => {
        if (rows.length === 0) return;
        lines.push('', `### ${title} (${rows.length})`, '');
        lines.push(`| Серьёзность | Advisory | Область | Пакеты | Описание |${extraHeader ? ` ${extraHeader} |` : ''}`);
        lines.push(`|---|---|---|---|---|${extraHeader ? '---|' : ''}`);
        for (const a of rows) {
            const id = a.url ? `[${a.id}](${a.url})` : a.id;
            lines.push(`| ${a.severity} | ${id} | ${SCOPE_LABEL[a.scope]} | ${mdCell(a.packages.join(', '))} | ${mdCell(a.title)} |${extraHeader ? ` ${extraCell(a)} |` : ''}`);
        }
    };
    table('Нарушения — блокируют сборку', result.blocking);
    if (result.expired.length > 0) {
        lines.push('', `### Просроченные исключения — блокируют сборку (${result.expired.length})`, '');
        lines.push('| Advisory | Истекло | Причина |', '|---|---|---|');
        for (const e of result.expired) lines.push(`| ${e.id} | ${e.expires} | ${mdCell(e.reason)} |`);
    }
    table('Закрыто исключениями', result.excepted, 'До / причина', (a) => `${a.exception.expires}: ${mdCell(a.exception.reason)}`);
    table('Не блокируют сборку', result.nonBlocking);
    if (result.unused.length > 0) {
        lines.push('', `Исключения, которые ничего не закрывают (можно удалить): ${result.unused.map((e) => e.id).join(', ')}`);
    }
    return lines.join('\n');
}

// Запуск npm audit. Код выхода npm здесь не показатель: при найденных
// уязвимостях он 1, но JSON выводится в любом случае — разбирается именно он.
// Команда одной строкой через оболочку: так одинаково работает npm.cmd на
// Windows (прямой запуск .cmd без shell в Node 24 невозможен), а аргументы —
// константы, подстановок из внешних данных нет.
function runNpmAudit(extraArgs, spawn = spawnSync) {
    const command = ['npm', 'audit', '--json', ...extraArgs].join(' ');
    const run = spawn(command, {
        cwd: ROOT,
        encoding: 'utf8',
        shell: true,
        windowsHide: true,
        maxBuffer: 64 * 1024 * 1024,
    });
    if (run.error) throw new AuditInputError(`не удалось запустить «${command}»: ${run.error.message}`);
    const stdout = String(run.stdout || '').trim();
    const stderr = clean(String(run.stderr || '').trim().split('\n').slice(0, 3).join(' '), 300);
    if (!stdout) throw new AuditInputError(`«${command}» ничего не вывел (код ${run.status})${stderr ? ': ' + stderr : ''}`);
    try {
        return JSON.parse(stdout);
    } catch (err) {
        throw new AuditInputError(`вывод «${command}» — не JSON (код ${run.status})${stderr ? ': ' + stderr : ''}`);
    }
}

async function readStdin(stream = process.stdin) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks).toString('utf8');
}

function parseJson(text, label) {
    try {
        return JSON.parse(String(text).replace(/^﻿/, ''));
    } catch (err) {
        throw new AuditInputError(`${label}: некорректный JSON: ${err.message}`);
    }
}

function splitStdinInput(input) {
    if (!isObject(input)) throw new AuditInputError('stdin: ожидался JSON-объект');
    if ('auditReportVersion' in input || 'vulnerabilities' in input || 'error' in input) return { prod: input, all: null };
    if (isObject(input.prod)) return { prod: input.prod, all: isObject(input.all) ? input.all : null };
    throw new AuditInputError('stdin: ожидался отчёт npm audit или {"prod": …, "all": …}');
}

function parseArgs(argv) {
    const args = { stdin: false, allowlist: null, help: false };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--stdin') args.stdin = true;
        else if (arg === '--help' || arg === '-h') args.help = true;
        else if (arg === '--allowlist') {
            args.allowlist = argv[++i];
            if (!args.allowlist) throw new AuditInputError('--allowlist требует путь к файлу');
        } else if (arg.startsWith('--allowlist=')) {
            args.allowlist = arg.slice('--allowlist='.length);
            if (!args.allowlist) throw new AuditInputError('--allowlist требует путь к файлу');
        } else {
            throw new AuditInputError(`неизвестный аргумент «${clean(arg, 60)}»\n${USAGE}`);
        }
    }
    return args;
}

// Сводка шага GitHub Actions. Ошибка записи не должна менять решение по
// политике — только предупреждение.
function writeStepSummary(markdown, env, warn) {
    const file = env.GITHUB_STEP_SUMMARY;
    if (!file) return;
    try {
        fs.appendFileSync(file, markdown + '\n');
    } catch (err) {
        warn(`npm audit: не удалось записать сводку в GITHUB_STEP_SUMMARY: ${err.message}`);
    }
}

// io — подмена ввода-вывода для тестов: out, err, runAudit, readInput, now.
async function main(argv = process.argv.slice(2), env = process.env, io = {}) {
    const out = io.out || ((text) => process.stdout.write(text + '\n'));
    const err = io.err || ((text) => process.stderr.write(text + '\n'));
    const runAudit = io.runAudit || runNpmAudit;
    const readInput = io.readInput || readStdin;
    try {
        const args = parseArgs(argv);
        if (args.help) {
            out(USAGE);
            return 0;
        }
        const exceptions = args.allowlist
            ? loadAllowlist(path.resolve(args.allowlist), { required: true })
            : loadAllowlist(DEFAULT_ALLOWLIST);

        let prodReport;
        let allReport = null;
        if (args.stdin) {
            ({ prod: prodReport, all: allReport } = splitStdinInput(parseJson(await readInput(), 'stdin')));
        } else {
            prodReport = await runAudit(['--omit=dev']);
            allReport = await runAudit([]);
        }
        const prod = parseAuditReport(prodReport, 'отчёт по прод-зависимостям');
        const all = allReport ? parseAuditReport(allReport, 'отчёт по всем зависимостям') : null;

        const today = (io.now ? io.now() : new Date()).toISOString().slice(0, 10);
        const result = evaluate({ prod, all, exceptions, today });
        out(formatText(result, today));
        writeStepSummary(formatMarkdown(result, today), env, err);
        return result.ok ? 0 : 1;
    } catch (error) {
        if (error instanceof AuditInputError) {
            err(`npm audit: ${error.message}`);
            return 2;
        }
        throw error;
    }
}

if (require.main === module) {
    main().then(
        (code) => { process.exitCode = code; },
        (error) => {
            console.error(error && error.stack ? error.stack : error);
            process.exitCode = 2;
        },
    );
}

module.exports = {
    SEVERITIES,
    PROD_FAIL_LEVEL,
    ALL_FAIL_LEVEL,
    DEFAULT_ALLOWLIST,
    AuditInputError,
    parseAuditReport,
    validateAllowlist,
    loadAllowlist,
    evaluate,
    formatText,
    formatMarkdown,
    runNpmAudit,
    parseArgs,
    main,
};
