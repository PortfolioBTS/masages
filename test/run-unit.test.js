'use strict';
// Самопроверка раннера юнит-тестов test/run-unit.js (ревью W7 R5, З-9): пул процессов, тайм-аут на файл,
// понятный вывод упавшего файла и режим --serial. Раннер запускается на временной папке с файлами-пустышками
// (параметр --dir), настоящие тесты проекта не трогаются.
//
// Параллельность доказана рукопожатием, а не временем: два файла-пустышки пишут каждый свой флаг-файл и ждут
// флаг соседа; пройти оба могут только запущенные одновременно.
// Запуск: node test/run-unit.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const RUNNER = path.join(__dirname, 'run-unit.js');
// Запас на загруженную машину: раннер с пустышками обычно укладывается в секунды.
const RUN_TIMEOUT_MS = 60000;

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const dirs = [];
function fixtureDir(files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-run-unit-'));
    dirs.push(dir);
    for (const [name, source] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), source);
    return dir;
}

function run(dir, args = [], extraEnv = {}) {
    const started = Date.now();
    const result = spawnSync(process.execPath, [RUNNER, `--dir=${dir}`, ...args], {
        encoding: 'utf8',
        timeout: RUN_TIMEOUT_MS,
        env: { ...process.env, GITHUB_ACTIONS: '', ...extraEnv },
    });
    return { code: result.status, signal: result.signal, out: `${result.stdout}${result.stderr}`, ms: Date.now() - started };
}

const OK = "console.log('ok-fixture'); process.exitCode = 0;";
const FAIL = "console.error('причина-падения'); process.exitCode = 1;";

// Файл ждёт флаг соседа до waitMs и падает, если не дождался: пройдёт только при одновременном запуске.
function handshake(mine, theirs, waitMs) {
    return `
const fs = require('fs'); const path = require('path');
fs.writeFileSync(path.join(__dirname, ${JSON.stringify(mine)}), '1');
const other = path.join(__dirname, ${JSON.stringify(theirs)});
const deadline = Date.now() + ${waitMs};
const timer = setInterval(() => {
    if (fs.existsSync(other)) { clearInterval(timer); console.log('сосед виден'); }
    else if (Date.now() > deadline) { clearInterval(timer); console.error('соседа нет'); process.exitCode = 1; }
}, 10);
`;
}

function summaryOf(out, name) {
    const line = out.split('\n').find(l => /^\s+(ok|FAIL)\s/.test(l) && l.includes(` ${name} `));
    return line ? line.trim().split(/\s+/)[0] : null;
}

test('все файлы зелёные: код 0, в сводке каждый файл отмечен ok', () => {
    const dir = fixtureDir({ 'a.test.js': OK, 'b.test.js': OK, 'c.test.js': OK });
    const r = run(dir);
    assert.strictEqual(r.code, 0, r.out);
    for (const name of ['a.test.js', 'b.test.js', 'c.test.js']) assert.strictEqual(summaryOf(r.out, name), 'ok', name);
    assert.match(r.out, /Файлов: 3, упало: 0/);
});

test('упавший файл: код 1, строка ПАДЕНИЕ с именем и причиной, вывод файла сохранён, остальные всё равно выполнены', () => {
    const dir = fixtureDir({ 'a.test.js': OK, 'b.test.js': FAIL, 'c.test.js': OK });
    const r = run(dir);
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.out, /ПАДЕНИЕ b\.test\.js: код выхода 1/);
    assert.match(r.out, /причина-падения/, 'вывод упавшего файла не потерян');
    assert.strictEqual(summaryOf(r.out, 'b.test.js'), 'FAIL');
    assert.strictEqual(summaryOf(r.out, 'a.test.js'), 'ok');
    assert.strictEqual(summaryOf(r.out, 'c.test.js'), 'ok', 'файл после упавшего выполнен');
    assert.match(r.out, /Файлов: 3, упало: 1/);
    assert.match(r.out, /Упавшие: b\.test\.js/);
});

test('необработанное исключение и process.exit(3) тоже падение; в GitHub Actions есть аннотация ::error', () => {
    const dir = fixtureDir({ 'a.test.js': "throw new Error('boom');", 'b.test.js': 'process.exit(3);' });
    const r = run(dir, [], { GITHUB_ACTIONS: 'true' });
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.out, /ПАДЕНИЕ a\.test\.js: код выхода 1/);
    assert.match(r.out, /ПАДЕНИЕ b\.test\.js: код выхода 3/);
    assert.match(r.out, /::error file=test\/a\.test\.js::/);
});

test('зависший файл убивается по тайм-ауту: прогон кончается, причина названа, остальные файлы выполнены', () => {
    const dir = fixtureDir({ 'hang.test.js': 'setInterval(() => {}, 1000);', 'ok.test.js': OK });
    const r = run(dir, ['--timeout=1']);
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.out, /ПАДЕНИЕ hang\.test\.js: тайм-аут 1 с, процесс убит/);
    assert.strictEqual(summaryOf(r.out, 'ok.test.js'), 'ok');
    assert.ok(r.ms < RUN_TIMEOUT_MS - 10000, `прогон не должен ждать сам себя: ${r.ms} мс`);
});

test('тайм-аут убивает и дочерние процессы файла: сосед по пулу видит, что потомок мёртв, пока раннер ещё работает', () => {
    // Потомок, переживший убитый файл, мог бы держать канал вывода (раннер завис бы) или тихо доживать до конца
    // прогона (на Windows его добивает только закрытие job-объекта раннера, то есть уже после прогона). Поэтому
    // смотрим не после, а изнутри: третий файл пула дожидается гибели родителя и через 0,5 с требует мёртвого потомка.
    // Пул из двух процессов: spawner (убит на 4-й секунде) и filler (2 с) идут сразу, checker стартует вслед за filler.
    const spawner = `
const { spawn } = require('child_process'); const fs = require('fs'); const path = require('path');
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'inherit' });
fs.writeFileSync(path.join(__dirname, 'grandchild.pid'), String(child.pid));
fs.writeFileSync(path.join(__dirname, 'parent.pid'), String(process.pid));
setInterval(() => {}, 1000);
`;
    const filler = 'setTimeout(() => {}, 2000);';
    const checker = `
const fs = require('fs'); const path = require('path');
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const read = (name) => { try { return Number(fs.readFileSync(path.join(__dirname, name), 'utf8')); } catch { return 0; } };
const started = Date.now();
const timer = setInterval(() => {
    if (Date.now() - started > 3500) { clearInterval(timer); console.error('родитель не был убит вовремя'); process.exitCode = 1; return; }
    const parent = read('parent.pid'); const child = read('grandchild.pid');
    if (!parent || !child || alive(parent)) return;
    clearInterval(timer);
    setTimeout(() => {
        if (alive(child)) { console.error('потомок ' + child + ' жив через 0,5 с после гибели родителя'); try { process.kill(child, 'SIGKILL'); } catch { /* уже нет */ } process.exitCode = 1; }
        else console.log('потомок убит вместе с родителем');
    }, 500);
}, 25);
`;
    const dir = fixtureDir({ 'a-spawner.test.js': spawner, 'b-filler.test.js': filler, 'c-checker.test.js': checker });
    const r = run(dir, ['--timeout=4', '--jobs=2']);
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.out, /ПАДЕНИЕ a-spawner\.test\.js: тайм-аут 4 с/);
    assert.match(r.out, /потомок убит вместе с родителем/, r.out);
    assert.strictEqual(summaryOf(r.out, 'c-checker.test.js'), 'ok', r.out);
    assert.strictEqual(summaryOf(r.out, 'b-filler.test.js'), 'ok', r.out);
});

test('пул: два файла, которым нужен одновременный запуск, проходят (--jobs=2)', () => {
    const dir = fixtureDir({ 'a.test.js': handshake('a.flag', 'b.flag', 20000), 'b.test.js': handshake('b.flag', 'a.flag', 20000) });
    const r = run(dir, ['--jobs=2']);
    assert.strictEqual(r.code, 0, r.out);
    assert.match(r.out, /параллельно, процессов: 2/);
});

test('размер пула по умолчанию - min(availableParallelism, 4, число файлов)', () => {
    const dir = fixtureDir({ 'a.test.js': OK, 'b.test.js': OK, 'c.test.js': OK, 'd.test.js': OK, 'e.test.js': OK, 'f.test.js': OK });
    const r = run(dir);
    assert.strictEqual(r.code, 0, r.out);
    const expected = Math.min(os.availableParallelism(), 4, 6);
    if (expected > 1) assert.match(r.out, new RegExp(`параллельно, процессов: ${expected}\\)`));
    else assert.match(r.out, /по очереди/);
});

test('--serial: файлы идут по одному (то же рукопожатие не проходит), вывод по алфавиту и сразу', () => {
    const dir = fixtureDir({ 'a.test.js': handshake('a.flag', 'b.flag', 800), 'b.test.js': handshake('b.flag', 'a.flag', 800) });
    const r = run(dir, ['--serial']);
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.out, /\(по очереди\)/);
    assert.strictEqual(summaryOf(r.out, 'a.test.js'), 'FAIL', 'первый не дождался соседа, которого ещё нет');
    assert.strictEqual(summaryOf(r.out, 'b.test.js'), 'ok', 'второй пошёл после первого и увидел его флаг');
    assert.ok(r.out.indexOf('=== a.test.js ===') < r.out.indexOf('=== b.test.js ==='));
});

test('в пуле вывод файла печатается целиком: строки разных файлов не перемешиваются', () => {
    const chatty = (tag) => `
let n = 0;
const timer = setInterval(() => {
    console.log('${tag}-' + (n++));
    if (n === 40) { clearInterval(timer); }
}, 5);
`;
    const dir = fixtureDir({ 'a.test.js': chatty('AAA'), 'b.test.js': chatty('BBB') });
    const r = run(dir, ['--jobs=2']);
    assert.strictEqual(r.code, 0, r.out);
    const blocks = r.out.split(/^=== (.+?) ===$/m); // ['', имя, текст, имя, текст, ...]
    const byName = {};
    for (let i = 1; i < blocks.length; i += 2) byName[blocks[i]] = blocks[i + 1];
    const own = (name, tag, other) => {
        const text = byName[name] || '';
        assert.strictEqual((text.match(new RegExp(`${tag}-\\d+`, 'g')) || []).length, 40, `${name}: все 40 строк на месте`);
        assert.ok(!text.includes(other), `${name}: чужие строки внутри блока`);
    };
    own('a.test.js', 'AAA', 'BBB-');
    own('b.test.js', 'BBB', 'AAA-');
});

test('фильтр по подстроке имени выбирает файлы; без совпадений - код 1', () => {
    const dir = fixtureDir({ 'alpha.test.js': OK, 'beta.test.js': OK });
    const only = run(dir, ['alp']);
    assert.strictEqual(only.code, 0, only.out);
    assert.match(only.out, /Файлов: 1, упало: 0/);
    assert.ok(!only.out.includes('beta.test.js'));
    const none = run(dir, ['zzz']);
    assert.strictEqual(none.code, 1);
    assert.match(none.out, /Нет тестовых файлов, подходящих под: zzz/);
});

test('неверные параметры: код 2 и понятное сообщение', () => {
    const dir = fixtureDir({ 'a.test.js': OK });
    for (const [args, pattern] of [
        [['--bogus'], /неизвестный параметр --bogus/],
        [['--jobs=0'], /--jobs: нужно целое число не меньше 1/],
        [['--timeout=abc'], /--timeout: нужно целое число не меньше 1/],
    ]) {
        const r = run(dir, args);
        assert.strictEqual(r.code, 2, `${args}: ${r.out}`);
        assert.match(r.out, pattern);
    }
});

for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
