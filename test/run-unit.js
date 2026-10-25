'use strict';
// Раннер юнит-тестов: сам находит test/*.test.js и запускает каждый файл
// отдельным процессом Node (как раньше делала цепочка через && в
// package.json). Раньше каждый новый тестовый файл приходилось дописывать
// в одну строку scripts.test — при параллельной работе это была гарантия
// конфликта слияния. Сквозные тесты (test/e2e/, им нужен Postgres) сюда не
// попадают: они во вложенной папке и запускаются отдельно.
//
// Запуск: npm test                       — все файлы, пул процессов
//         node test/run-unit.js pow lib  — только файлы, в имени которых
//                                          есть одна из подстрок
//         node test/run-unit.js --serial — по одному, вывод идёт сразу
//                                          (отладка: видно, где завис файл)
//         --jobs=N                       — размер пула (по умолчанию
//                                          min(os.availableParallelism(), 4))
//         --timeout=СЕК                  — тайм-аут на файл (по умолчанию 300)
//         --dir=ПАПКА                    — искать *.test.js в другой папке
//                                          (для самопроверки раннера)
//
// Почему можно параллельно: юнит-тесты не делят порты, базы и файлы (серверные
// берут порт 0 и временные папки), а процесс на файл и раньше был изолирован.
// В пуле вывод каждого файла собирается и печатается целиком, когда файл
// закончил, — строки разных файлов не перемешиваются; упавший файл помечен
// строкой «ПАДЕНИЕ». Зависший файл убивается по тайм-ауту вместе с дочерними
// процессами и считается упавшим, а не держит весь прогон до лимита CI.
//
// В отличие от цепочки через &&, упавший файл не останавливает остальные:
// в конце печатается сводка, код выхода — 1, если упал хотя бы один.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const DEFAULT_TIMEOUT_SEC = 300;
const MAX_DEFAULT_JOBS = 4;
const REPO_ROOT = path.join(__dirname, '..');

function parseArgs(argv) {
    const opts = { serial: false, jobs: null, timeoutSec: DEFAULT_TIMEOUT_SEC, dir: __dirname, filters: [] };
    const positive = (name, value) => {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 1) throw new Error(`${name}: нужно целое число не меньше 1, получено «${value}»`);
        return number;
    };
    for (const arg of argv) {
        if (arg === '--serial') opts.serial = true;
        else if (arg.startsWith('--jobs=')) opts.jobs = positive('--jobs', arg.slice('--jobs='.length));
        else if (arg.startsWith('--timeout=')) opts.timeoutSec = positive('--timeout', arg.slice('--timeout='.length));
        else if (arg.startsWith('--dir=')) opts.dir = path.resolve(arg.slice('--dir='.length));
        else if (arg.startsWith('--')) throw new Error(`неизвестный параметр ${arg}`);
        else opts.filters.push(arg);
    }
    return opts;
}

// Размер пула: не больше четырёх — юнит-тесты частью упираются в процессор (KT-журнал, PDF, PoW), и
// на машине с десятками ядер, занятой чем-то ещё, больше процессов дают только разброс времени.
function poolSize(opts) {
    if (opts.serial) return 1;
    if (opts.jobs) return opts.jobs;
    const cpus = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
    return Math.max(1, Math.min(cpus, MAX_DEFAULT_JOBS));
}

// Запущенные сейчас файлы: при Ctrl+C / SIGTERM раннера их надо убить, ведь на POSIX они в своих группах процессов.
const running = new Set();

// POSIX: каждый файл — лидер своей группы процессов (detached), чтобы по тайм-ауту убить всю группу сразу; без этого
// потомок зависшего файла держал бы канал вывода открытым, и раннер ждал бы его вечно. Windows: дерево
// убивает taskkill /T (а Node-потомки умирают ещё и с родителем - job-объект libuv).
const DETACH = process.platform !== 'win32';

// Убить процесс вместе с потомками.
function killTree(child) {
    if (!child.pid) return;
    if (!DETACH) {
        spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
        return;
    }
    try {
        process.kill(-child.pid, 'SIGKILL');
    } catch {
        try { child.kill('SIGKILL'); } catch { /* уже завершился */ }
    }
}

for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
        for (const child of running) killTree(child);
        process.exit(130);
    });
}

// Один файл отдельным процессом. capture: true — вывод копится и отдаётся в результате, false — идёт сразу.
function runFile(dir, name, { cwd, timeoutMs, capture }) {
    return new Promise((resolve) => {
        const started = Date.now();
        const chunks = [];
        let timedOut = false;
        let spawnError = null;
        const child = spawn(process.execPath, [path.join(dir, name)], {
            stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
            cwd,
            detached: DETACH,
            windowsHide: true,
        });
        running.add(child);
        if (capture) {
            child.stdout.on('data', chunk => chunks.push(chunk));
            child.stderr.on('data', chunk => chunks.push(chunk));
        }
        const timer = setTimeout(() => {
            timedOut = true;
            killTree(child);
        }, timeoutMs);
        child.on('error', (err) => { spawnError = err; });
        child.on('close', (code, signal) => {
            clearTimeout(timer);
            running.delete(child);
            let detail = null;
            if (timedOut) detail = `тайм-аут ${Math.round(timeoutMs / 1000)} с, процесс убит`;
            else if (spawnError) detail = spawnError.message;
            else if (signal) detail = `убит сигналом ${signal}`;
            else if (code !== 0) detail = `код выхода ${code}`;
            const ok = code === 0 && !timedOut && !spawnError;
            resolve({ name, ok, ms: Date.now() - started, detail, output: Buffer.concat(chunks).toString('utf8') });
        });
    });
}

function report(result, { capture }) {
    if (capture) {
        // Один вызов: вывод файла не перемешается с выводом соседних процессов пула.
        const tail = result.output === '' || result.output.endsWith('\n') ? '' : '\n';
        process.stdout.write(`\n=== ${result.name} ===\n${result.output}${tail}`);
    }
    if (!result.ok) {
        console.log(`ПАДЕНИЕ ${result.name}: ${result.detail} (${(result.ms / 1000).toFixed(1)} с)`);
        // Аннотация в интерфейсе GitHub Actions: упавший файл виден без чтения всего лога.
        if (process.env.GITHUB_ACTIONS) console.log(`::error file=test/${result.name}::${result.detail}`);
    }
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const files = fs.readdirSync(opts.dir)
        .filter(name => name.endsWith('.test.js'))
        .filter(name => opts.filters.length === 0 || opts.filters.some(f => name.includes(f)))
        .sort();

    if (files.length === 0) {
        console.error(opts.filters.length > 0
            ? `Нет тестовых файлов, подходящих под: ${opts.filters.join(', ')}`
            : `В ${opts.dir} нет файлов *.test.js`);
        return 1;
    }

    const jobs = Math.min(poolSize(opts), files.length);
    const capture = jobs > 1;
    const cwd = opts.dir === __dirname ? REPO_ROOT : opts.dir;
    const timeoutMs = opts.timeoutSec * 1000;
    const startedAt = Date.now();
    const results = [];
    const queue = [...files];

    async function worker() {
        for (let name = queue.shift(); name !== undefined; name = queue.shift()) {
            if (!capture) console.log(`\n=== ${name} ===`);
            const result = await runFile(opts.dir, name, { cwd, timeoutMs, capture });
            results.push(result);
            report(result, { capture });
        }
    }
    await Promise.all(Array.from({ length: jobs }, worker));

    results.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    console.log('\n=== Итог ===');
    for (const r of results) {
        const extra = r.detail ? ` (${r.detail})` : '';
        console.log(`  ${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}  ${(r.ms / 1000).toFixed(1)} с${extra}`);
    }
    const failed = results.filter(r => !r.ok);
    const mode = jobs > 1 ? `параллельно, процессов: ${jobs}` : 'по очереди';
    console.log(`\nФайлов: ${results.length}, упало: ${failed.length}, время: ${((Date.now() - startedAt) / 1000).toFixed(1)} с (${mode})`);
    if (failed.length > 0) {
        console.log(`Упавшие: ${failed.map(r => r.name).join(', ')}. Повтор по одному: node test/run-unit.js --serial ${failed.map(r => r.name.replace(/\.test\.js$/, '')).join(' ')}`);
    }
    return failed.length > 0 ? 1 : 0;
}

main().then(
    (code) => { process.exitCode = code; },
    (err) => { console.error(`[unit] ${err.message}`); process.exitCode = 2; }
);
