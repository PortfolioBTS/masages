'use strict';
// Тест-запрет для логов сервера (пункт 4.7 плана, T5.2): в server.js, lib/** и
// scripts/*.js ни один вывод в лог не принимает идентификаторы пользователей,
// комнат, чатов, сообщений, IP, sid, имена файлов и коды, а ошибки идут только
// через logError (lib/log-error.js), а не объектом в console.*.
//
// Это эвристика по тексту, а не доказательство: она ловит типичную ошибку —
// console.log(`… ${userId}`) или console.error('…', error). Настоящую проверку
// делает сквозной набор test/e2e/logs-clean.e2e.test.js: он прогоняет сценарий
// и ищет id, IP, имена и коды в живом логе.
//
// Как работает:
//  1. maskSource гасит комментарии, содержимое строк и текст шаблонов (остаются
//     только выражения ${…}), поэтому слова из текстов сообщений («Get chats
//     error», «ID комнаты») ничего не значат, а скобки в строках не мешают;
//  2. находятся вызовы console.log/warn/error/info/debug, process.stdout/
//     stderr.write и «подставных» логгеров lib/ (log, warn, report, error,
//     logError — их передают параметром);
//  3. в аргументах ищутся запрещённые имена (ALWAYS_BAD) и, только у console.*,
//     любое упоминание объекта ошибки;
//  4. ссылки на console без вызова (log = console.log) тоже считаются: через них
//     в код приходит логгер, который эта проверка уже не видит.
//
// Разрешение — по тексту вызова, с обоснованием (ALLOW). Разрешение, которое
// больше ничего не разрешает, — ошибка: устаревшая запись не должна копиться.
//
// Запуск: node test/log-guard.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.message ? err.message : err);
    }
}

// ---------- Маска исходника ----------

// Возвращает текст той же длины и с теми же переводами строк: комментарии и
// содержимое строк заменены пробелами, текст шаблонов тоже, выражения ${…}
// остались. ok = false, если разбор закончился внутри строки, шаблона или
// комментария: значит, токенайзер сбился и результату верить нельзя.
function maskSource(src) {
    const out = src.split('');
    const n = src.length;
    const blank = (from, to) => { for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' '; };
    const templateBraces = [];
    let braceDepth = 0;
    let inTemplate = false;
    let lastSignificant = '';
    let lastWord = '';
    let i = 0;
    let ok = true;
    // «/» после этих знаков и слов — начало регулярного выражения, а не деление.
    const REGEX_PRECEDERS = '(,=:[!&|?{};+-*%<>~^';
    const REGEX_WORDS = new Set(['return', 'typeof', 'case', 'in', 'of', 'delete', 'void', 'throw', 'new', 'else', 'do']);

    while (i < n) {
        const ch = src[i];
        if (inTemplate) {
            if (ch === '\\') { blank(i, i + 2); i += 2; continue; }
            if (ch === '`') { inTemplate = false; lastSignificant = '`'; i++; continue; }
            if (ch === '$' && src[i + 1] === '{') {
                templateBraces.push(braceDepth);
                braceDepth++;
                inTemplate = false;
                lastSignificant = '{';
                i += 2;
                continue;
            }
            blank(i, i + 1);
            i++;
            continue;
        }
        if (ch === '/' && src[i + 1] === '/') {
            const end = src.indexOf('\n', i);
            const stop = end === -1 ? n : end;
            blank(i, stop);
            i = stop;
            continue;
        }
        if (ch === '/' && src[i + 1] === '*') {
            const end = src.indexOf('*/', i + 2);
            if (end === -1) { ok = false; blank(i, n); break; }
            blank(i, end + 2);
            i = end + 2;
            continue;
        }
        if (ch === '"' || ch === "'") {
            let j = i + 1;
            while (j < n && src[j] !== ch && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
            if (src[j] !== ch) { ok = false; }
            blank(i + 1, j);
            i = j + 1;
            lastSignificant = ch;
            continue;
        }
        if (ch === '`') { inTemplate = true; i++; continue; }
        if (ch === '/') {
            const prevIsRegexStart = lastSignificant === '' || REGEX_PRECEDERS.includes(lastSignificant) || REGEX_WORDS.has(lastWord);
            if (prevIsRegexStart) {
                let j = i + 1;
                let inClass = false;
                while (j < n && src[j] !== '\n') {
                    if (src[j] === '\\') { j += 2; continue; }
                    if (src[j] === '[') inClass = true;
                    else if (src[j] === ']') inClass = false;
                    else if (src[j] === '/' && !inClass) break;
                    j++;
                }
                if (src[j] === '/') {
                    blank(i + 1, j);
                    i = j + 1;
                    lastSignificant = '/';
                    lastWord = '';
                    continue;
                }
            }
        }
        if (ch === '{') braceDepth++;
        if (ch === '}') {
            braceDepth--;
            if (templateBraces.length > 0 && templateBraces[templateBraces.length - 1] === braceDepth) {
                templateBraces.pop();
                inTemplate = true;
                i++;
                continue;
            }
        }
        if (/[\w$]/.test(ch)) {
            let j = i;
            while (j < n && /[\w$]/.test(src[j])) j++;
            lastWord = src.slice(i, j);
            lastSignificant = 'w';
            i = j;
            continue;
        }
        if (!/\s/.test(ch)) { lastSignificant = ch; lastWord = ''; }
        i++;
    }
    if (inTemplate || templateBraces.length > 0) ok = false;
    return { masked: out.join(''), ok };
}

// ---------- Поиск вызовов ----------

const CONSOLE_CALL = /\bconsole\s*\.\s*(?:log|warn|error|info|debug|trace)\s*\(/g;
const CONSOLE_REF = /\bconsole\s*\.\s*(?:log|warn|error|info|debug|trace)\b(?!\s*\()/g;
const STREAM_CALL = /\bprocess\s*\.\s*(?:stdout|stderr)\s*\.\s*write\s*\(/g;
// Логгеры, которые lib/ получает параметром (log = console.log, report = logError):
// имя вызова не доказывает, что это лог, но в этих файлах так и есть.
const LOGGER_CALL = /(?<![.\w$])(?<!function\s)(?<!async\s)(log|warn|report|error|logError)\s*\(/g;

function lineOf(src, index) {
    let line = 1;
    for (let k = 0; k < index; k++) if (src.charCodeAt(k) === 10) line++;
    return line;
}

// Аргументы верхнего уровня вызова, чья «(» стоит на openIndex. В маске скобки
// только кодовые, поэтому достаточно считать глубину.
function readArgs(masked, openIndex) {
    const args = [];
    let depth = 0;
    let cur = '';
    for (let k = openIndex; k < masked.length; k++) {
        const ch = masked[k];
        if (ch === '(' || ch === '[' || ch === '{') {
            depth++;
            if (depth === 1) continue;
        } else if (ch === ')' || ch === ']' || ch === '}') {
            depth--;
            if (depth === 0) { args.push(cur); return { args, end: k + 1 }; }
        } else if (ch === ',' && depth === 1) {
            args.push(cur);
            cur = '';
            continue;
        }
        cur += ch;
    }
    return { args, end: masked.length };
}

// ---------- Что считается данными ----------

// Имена, которым нечего делать в логе ни голыми, ни как свойство чего угодно.
// Не вошли общие слова (name, path, id отдельно, rows): иначе под подозрением
// каждое «rows.length» и «job.name». Поле id запрещено как .id — это чужая строка.
const BARE_BAD = [
    'ip', 'clientIp', 'realIp', 'userId', 'user_id', 'roomId', 'room_id', 'chatId', 'chat_id',
    'messageId', 'message_id', 'requestId', 'sessionID', 'sid', 'filename', 'fileName', 'originalname',
    'username', 'uniqueCode', 'unique_code', 'inviteCode', 'invite_code', 'code', 'req', 'res',
    'socket', 'headers', 'body',
];
const PROP_BAD = [
    'ip', 'realIp', 'clientIp', 'userId', 'user_id', 'roomId', 'room_id', 'chatId', 'chat_id',
    'messageId', 'message_id', 'sessionID', 'sid', 'filename', 'originalname', 'username',
    'unique_code', 'invite_code', 'remoteAddress', 'handshake', 'headers', 'body', 'params',
    'query', 'originalUrl', 'id',
];
// Объект ошибки целиком (или его message) в console.*: у ошибок Postgres в
// detail лежат значения строк; безопасно только logError.
const ERROR_NAMES = ['err', 'error', 'e', 'reason', 'cause', 'failure', 'magicErr'];
const BARE_BAD_RE = new RegExp(`(?<![.\\w$])(${BARE_BAD.join('|')})(?![\\w$])`);
const PROP_BAD_RE = new RegExp(`\\.\\s*(${PROP_BAD.join('|')})(?![\\w$])`);
const ERROR_NAME_RE = new RegExp(`(?<![.\\w$])(${ERROR_NAMES.join('|')})(?![\\w$])`);
const CODE_PROP_RE = /([\w$]+)\s*\.\s*code(?![\w$])/g;
const ERROR_NAME_SET = new Set(ERROR_NAMES);

// Нарушения в одном аргументе. console — аргументы console.* (в них нельзя
// даже объект ошибки); иначе проверяются только имена данных.
function badInArg(arg, { isConsole }) {
    const found = [];
    const bare = BARE_BAD_RE.exec(arg);
    if (bare) found.push(`«${bare[1]}»`);
    const prop = PROP_BAD_RE.exec(arg);
    if (prop) found.push(`«.${prop[1]}»`);
    for (const m of arg.matchAll(CODE_PROP_RE)) {
        if (!ERROR_NAME_SET.has(m[1])) found.push(`«${m[1]}.code» (код допустим только у объекта ошибки)`);
    }
    if (isConsole) {
        const errName = ERROR_NAME_RE.exec(arg);
        if (errName) found.push(`ошибка «${errName[1]}» в console.* (используйте logError)`);
    }
    return found;
}

// Возвращает нарушения файла: { line, call, problems[] }. call — текст вызова
// одной строкой (по нему сверяются разрешения).
function scanSource(src) {
    const { masked, ok } = maskSource(src);
    const violations = [];
    const squeeze = (text) => text.replace(/\s+/g, ' ').trim();
    const take = (start, end) => squeeze(src.slice(start, end));

    for (const [re, isConsole] of [[CONSOLE_CALL, true], [STREAM_CALL, true], [LOGGER_CALL, false]]) {
        re.lastIndex = 0;
        for (let m; (m = re.exec(masked));) {
            const open = m.index + m[0].length - 1;
            const { args, end } = readArgs(masked, open);
            // logError(context, error) и report(context, error): второй
            // аргумент — ошибка, которую logError чистит сам.
            const callee = m[1];
            const checked = (callee === 'logError' || callee === 'report') ? args.slice(0, 1) : args;
            const problems = checked.flatMap(arg => badInArg(arg, { isConsole }));
            if (problems.length > 0) {
                violations.push({ line: lineOf(src, m.index), call: take(m.index, end), problems });
            }
        }
    }

    CONSOLE_REF.lastIndex = 0;
    for (let m; (m = CONSOLE_REF.exec(masked));) {
        const lineStart = masked.lastIndexOf('\n', m.index) + 1;
        const lineEnd = masked.indexOf('\n', m.index);
        violations.push({
            line: lineOf(src, m.index),
            call: squeeze(src.slice(lineStart, lineEnd === -1 ? undefined : lineEnd)),
            problems: ['ссылка на console без вызова: логгер уходит в код, который проверка не видит'],
        });
    }
    return { violations, ok };
}

// ---------- Файлы ----------

function listFiles() {
    const files = ['server.js'];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
            const rel = `${dir}/${entry.name}`;
            if (entry.isDirectory()) walk(rel);
            else if (entry.name.endsWith('.js')) files.push(rel);
        }
    };
    walk('lib');
    for (const entry of fs.readdirSync(path.join(ROOT, 'scripts'), { withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith('.js')) files.push(`scripts/${entry.name}`);
    }
    return files.sort();
}

// ---------- Разрешения ----------

// { file, call, why }: call — узкое регулярное выражение по тексту вызова
// (пробелы сжаты). Изменившийся вызов перестанет подходить и станет нарушением.
const ALLOW = [
    { file: 'server.js', call: /^\(envReport\.errors\.length > 0 \? console\.error : console\.log\)/,
      why: 'отчёт проверки настроек (lib/env-check.js): имена переменных и тексты замечаний, значений нет' },
    { file: 'lib/log-error.js', call: /^function logError\(context, err, \{ log = console\.error \} = \{\}\)/,
      why: 'это и есть единственный приёмник: logError пишет в console.error строку «контекст: описание» без деталей ошибки' },
    { file: 'lib/advisory-locks.js', call: /^log = console\.log/,
      why: 'значение по умолчанию параметра log; сообщения фиксированные, без данных (вызовы log(…) проверяет этот же тест)' },
    { file: 'lib/jobs/index.js', call: /^log = console\.log/,
      why: 'значение по умолчанию параметра log; сообщения фиксированные, без данных' },
    { file: 'lib/migrations/index.js', call: /^async function migrateSchema\(\{ pool, client, migrations, initialSteps, log = console\.log/,
      why: 'значение по умолчанию параметра log; пишутся номера версий схемы' },
    { file: 'lib/legacy-reset.js', call: /[ {]log = console\.log/,
      why: 'значения по умолчанию log и error; пишутся только числа и коды системных ошибок, имена файлов нет (комментарий у deleteLegacyUploads)' },
    { file: 'lib/e2ee-keys.js', call: /logError\('\[E2EE\] Не удалось удалить ключи удалённого пользователя', error, \{ log: console\.warn \}\)/,
      why: 'logError с уровнем предупреждения вместо ошибки: чистку делает тот же logError, id в контексте нет' },
    { file: 'lib/sw-kill-switch.js', call: /warn = console\.warn/,
      why: 'значение по умолчанию параметра warn; сообщение фиксированное' },
    { file: 'lib/message-retag.js', call: /^log\(`комната \$\{roomId\}: пачка/,
      why: 'log передаёт только scripts/retag-messages.js и только с --verbose: ручной инструмент оператора, вывод в его терминал, не в журнал сервиса' },
    { file: 'scripts/retag-messages.js', call: /\{ \.\.\.opts, log: opts\.verbose \? console\.log : undefined \}/,
      why: 'ручной инструмент оператора; построчный вывод только с --verbose и только в его терминал' },
    { file: 'scripts/retag-messages.js', call: /^console\.log\(` ?комната \$\{p\.roomId\}, сообщение \$\{p\.id\}/,
      why: 'ручной инструмент оператора: id проблемных строк печатаются только по --verbose (без него: «id не печатаются»), чтобы найти и починить битую запись; вывод идёт в терминал оператора' },
    { file: 'scripts/audit-check.js', call: /^console\.error\(error && error\.stack \? error\.stack : error\)/,
      why: 'проверка зависимостей в CI (npm audit): внутренний сбой самого скрипта, стек нужен для разбора; данных пользователей в этом процессе нет' },
    { file: 'scripts/verify-deployment.js', call: /^console\.error\('Ошибка: ' \+ \(err && err\.message \? err\.message : err\)\)/,
      why: 'сверка клиента на устройстве проверяющего и в сторожевом workflow: скрипт нарочно самодостаточен (подключает только public/lib/client-verify.js), поэтому без lib/log-error.js; в сообщении сетевая ошибка и адрес проверяемого сайта' },
];

function isAllowed(file, call) {
    return ALLOW.findIndex(rule => rule.file === file && rule.call.test(call));
}

// ---------- Тесты самого сканера ----------

function scan(src) { return scanSource(src).violations; }

function selfTests() {
    test('сканер: идентификаторы в аргументах console.* находятся, в текстах строк — нет', () => {
        assert.strictEqual(scan("console.log('userId roomId chatId code ip');").length, 0, 'слова внутри строки');
        assert.strictEqual(scan('console.log(`чат ${chatId} открыт`);').length, 1);
        assert.strictEqual(scan('console.warn("x", req.ip);').length, 1);
        assert.strictEqual(scan('console.log(socket.handshake.address);').length, 1);
        assert.strictEqual(scan('console.log("ok", user.username);').length, 1);
        assert.strictEqual(scan('console.log(sessionID);').length, 1);
        assert.strictEqual(scan('console.log(file.filename);').length, 1);
        assert.strictEqual(scan('console.log(row.id);').length, 1);
        assert.strictEqual(scan('console.log(code);').length, 1);
    });

    test('сканер: счётчики и фиксированные тексты проходят', () => {
        assert.strictEqual(scan('console.log(`Удалено: ${rows.length - failed}`);').length, 0);
        assert.strictEqual(scan("console.log('[Anon] Удалено', count);").length, 0);
        assert.strictEqual(scan('console.log(`порт ${PORT}`);').length, 0);
    });

    test('сканер: объект ошибки в console.* — нарушение, в logError — нет', () => {
        assert.strictEqual(scan("console.error('Get chats error:', error);").length, 1);
        assert.strictEqual(scan("console.error('x', err.message);").length, 1);
        assert.strictEqual(scan("console.error('x', e);").length, 1);
        assert.strictEqual(scan("console.warn('x', reason);").length, 1);
        assert.strictEqual(scan("logError('Get chats error', error);").length, 0);
        assert.strictEqual(scan("report('[Jobs] x', err);").length, 0);
    });

    test('сканер: logError(контекст с id, …) — нарушение', () => {
        assert.strictEqual(scan('logError(`Комната ${roomId}`, err);').length, 1);
        assert.strictEqual(scan('logError(`Пользователь ${user.user_id}`, err);').length, 1);
    });

    test('сканер: код ошибки err.code допустим, чужое .code — нет', () => {
        assert.strictEqual(scan("log(`ошибка ${err.code || 'unknown'}`);").length, 0);
        assert.strictEqual(scan('log(`код ${invite.code}`);').length, 1);
        assert.strictEqual(scan('log(`код ${code}`);').length, 1);
    });

    test('сканер: аргументы на нескольких строках и вложенные вызовы', () => {
        const src = [
            'console.error(',
            "    '[X] текст',",
            '    formatThing(a, b),',
            '    { n: roomId },',
            ');',
        ].join('\n');
        const v = scan(src);
        assert.strictEqual(v.length, 1);
        assert.strictEqual(v[0].line, 1);
    });

    test('сканер: вызовы в комментариях и строках не считаются, шаблон с вложенным шаблоном разбирается', () => {
        assert.strictEqual(scan("// console.log(userId)\n/* console.log(roomId) */\nconst s = 'console.log(chatId)';").length, 0);
        assert.strictEqual(scan('const t = `a ${`b ${1}`} c`;\nconsole.log(`x ${rooms.length}`);').length, 0);
        assert.strictEqual(scan('console.log(`a ${`b ${userId}`} c`);').length, 1);
    });

    test('сканер: регулярное выражение с кавычкой не сбивает разбор', () => {
        const src = "const re = /['\"]/;\nconsole.log(roomId);\n";
        const { violations, ok } = scanSource(src);
        assert.ok(ok);
        assert.strictEqual(violations.length, 1);
        assert.strictEqual(violations[0].line, 2);
    });

    test('сканер: ссылка на console без вызова и запись в поток — нарушения', () => {
        assert.strictEqual(scan('const log = console.log;').length, 1);
        assert.strictEqual(scan("function f({ warn = console.warn } = {}) { warn('x'); }").length, 1);
        assert.strictEqual(scan('process.stderr.write(`id ${userId}\\n`);').length, 1);
        assert.strictEqual(scan("process.stdout.write('готово\\n');").length, 0);
    });

    test('сканер: определение функции log(…) вызовом не считается', () => {
        assert.strictEqual(scan('function log(roomId) { return 1; }').length, 0);
        assert.strictEqual(scan('async function report(userId) { return 1; }').length, 0);
    });

    test('сканер: разметка не ломает разбор — маска сохраняет длину и строки', () => {
        const src = "const a = 'x\\'y'; // c\nconst b = `q ${a} w`; /* m\nn */ console.log(1);\n";
        const { masked, ok } = maskSource(src);
        assert.ok(ok);
        assert.strictEqual(masked.length, src.length);
        assert.strictEqual(masked.split('\n').length, src.split('\n').length);
    });
}

// ---------- Проверка репозитория ----------

function repoTest() {
    const files = listFiles();
    const used = new Set();
    const bad = [];
    const brokenMask = [];
    let calls = 0;

    for (const file of files) {
        const src = fs.readFileSync(path.join(ROOT, file), 'utf8').replace(/\r\n/g, '\n');
        const { violations, ok } = scanSource(src);
        if (!ok) brokenMask.push(file);
        calls += (src.match(CONSOLE_CALL) || []).length;
        for (const v of violations) {
            const rule = isAllowed(file, v.call);
            if (rule >= 0) { used.add(rule); continue; }
            bad.push(`${file}:${v.line}: ${v.problems.join('; ')}\n        ${v.call.slice(0, 160)}`);
        }
    }

    test('разбор исходников не сбился (строки, шаблоны, комментарии закрыты)', () => {
        assert.deepStrictEqual(brokenMask, [], `токенайзер сбился на файлах: ${brokenMask.join(', ')}`);
    });

    test('сканер видит вызовы (проверка не пуста)', () => {
        assert.ok(files.length > 30, `файлов: ${files.length}`);
        assert.ok(calls > 10, `вызовов console.*: ${calls}`);
    });

    test('в server.js, lib/** и scripts/* лог не принимает id, IP, sid, имена и коды; ошибки идут через logError', () => {
        assert.deepStrictEqual(bad, [],
            `нарушений: ${bad.length}. Перепишите вызов (счётчик вместо id, logError вместо объекта ошибки)\n` +
            'или добавьте разрешение в ALLOW с обоснованием.\n    ' + bad.join('\n    '));
    });

    test('каждое разрешение ещё нужно и имеет обоснование', () => {
        const stale = ALLOW.map((rule, index) => ({ rule, index })).filter(({ index }) => !used.has(index));
        assert.deepStrictEqual(stale.map(({ rule }) => `${rule.file}: ${rule.call}`), [], 'устаревшие разрешения');
        for (const rule of ALLOW) assert.ok(rule.why.length >= 20, `нет обоснования у ${rule.file}: ${rule.call}`);
    });
}

function main() {
    console.log('Log guard tests\n');
    selfTests();
    repoTest();
    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main();
