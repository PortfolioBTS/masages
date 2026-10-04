'use strict';
// Харнесс сквозных тестов сам: упавший набор не остаётся без следов.
//
// Раньше при падении не теста, а файла-набора целиком (исключение в хуке,
// необработанное исключение после конца теста) runner показывал «tests N+1,
// fail 1» с названием файла, а в test/e2e/.logs не появлялось ничего.
// Здесь вложенные прогоны `node --test` (с теми же флагами, что у runner)
// гоняют маленькие наборы, которые ломаются разными способами, и проверяют,
// что осталось в папке логов: причина сбоя (suite.log) и лог сервера.
// Вложенные наборы пишутся во временную папку, логи — в свою
// NYXO_E2E_LOGS_DIR, настоящая test/e2e/.logs не засоряется.

const { test } = require('node:test');
const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { REPO_ROOT } = require('./helpers/env');
const { dropDatabase } = require('./helpers/pg');

const INNER_TIMEOUT_MS = 50000;
const SCENARIOS = path.join(__dirname, 'helpers', 'scenarios');

// Код вложенного набора. Заголовок общий: node:test, помощники харнесса и
// запись имени базы в файл — чтобы утёкшую базу можно было удалить снаружи.
function innerSource(dir, body) {
    return `'use strict';
const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createSuite } = require(${JSON.stringify(SCENARIOS)});
const rememberDatabase = (suite) => fs.writeFileSync(path.join(${JSON.stringify(dir)}, 'db-name.txt'), suite.dbName);
${body}
`;
}

// Запуск вложенного прогона одного набора; результат — код выхода, весь вывод
// и файлы из папки логов.
async function runInner(t, name, body) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `nyxo-harness-${name}-`));
    const logsDir = path.join(dir, 'logs');
    const file = path.join(dir, `${name}.inner.test.js`);
    fs.writeFileSync(file, innerSource(dir, body));
    t.after(async () => {
        // База, которую вложенный набор оставил нарочно (его уборка сломана
        // или процесс убит до неё), удаляется здесь — по имени из файла.
        const dbNameFile = path.join(dir, 'db-name.txt');
        if (fs.existsSync(dbNameFile)) await dropDatabase(fs.readFileSync(dbNameFile, 'utf8')).catch(() => {});
        fs.rmSync(dir, { recursive: true, force: true });
    });

    // Вложенный runner не должен считать себя дочерним процессом внешнего.
    const env = { ...process.env, NYXO_E2E_LOGS_DIR: logsDir };
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, ['--test', '--test-timeout=60000', '--test-force-exit', '--test-reporter=spec', file], {
        cwd: REPO_ROOT,
        env,
        windowsHide: true,
    });
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    const timer = setTimeout(() => child.kill(), INNER_TIMEOUT_MS);
    const code = await new Promise((resolve) => child.once('close', (exitCode) => resolve(exitCode)));
    clearTimeout(timer);

    const files = fs.existsSync(logsDir) ? fs.readdirSync(logsDir).sort() : [];
    const read = (pattern) => {
        const found = files.find(f => pattern.test(f));
        return found ? fs.readFileSync(path.join(logsDir, found), 'utf8') : null;
    };
    return { code, output, files, read };
}

test('сбой старта сервера: причина и лог сервера сохранены', async (t) => {
    const run = await runInner(t, 'start', `
const suite = createSuite('inner-start', { env: { SESSION_SECRET: null } });
test('не должен выполниться', async () => { await suite.client().auth(); });
`);
    assert.notStrictEqual(run.code, 0, run.output);
    const report = run.read(/-inner-start-suite\.log$/);
    assert.ok(report, `нет suite.log среди ${run.files.join(', ') || 'пусто'}\n${run.output}`);
    assert.match(report, /\[before: подготовка набора/);
    assert.match(report, /SESSION_SECRET/);
    const serverLog = run.read(/-inner-start-inner-start-1\.log$/);
    assert.ok(serverLog, `нет лога сервера среди ${run.files.join(', ')}`);
    assert.match(serverLog, /SESSION_SECRET/);
});

test('необработанное исключение после конца теста: файл упал, причина и лог сохранены', async (t) => {
    const run = await runInner(t, 'late', `
const suite = createSuite('inner-late');
test('проходит и оставляет таймер с исключением', async () => {
    await suite.client().auth();
    setTimeout(() => { throw new Error('БУМ из таймера'); }, 150);
});
test('проходит, но дольше таймера', async () => { await new Promise(resolve => setTimeout(resolve, 500)); });
`);
    assert.notStrictEqual(run.code, 0, `файл должен считаться упавшим\n${run.output}`);
    const report = run.read(/-inner-late-suite\.log$/);
    assert.ok(report, `нет suite.log среди ${run.files.join(', ') || 'пусто'}\n${run.output}`);
    assert.match(report, /\[uncaughtException\]/);
    assert.match(report, /БУМ из таймера/);
    const serverLog = run.read(/-inner-late-inner-late-1\.log$/);
    assert.ok(serverLog, `нет лога сервера среди ${run.files.join(', ')}`);
    assert.match(serverLog, /База данных инициализирована/);
});

test('упавший тест: в suite.log имя теста и сообщение ассерта, лог сервера на месте', async (t) => {
    const run = await runInner(t, 'failing', `
const suite = createSuite('inner-failing');
test('проходит', async () => { await suite.client().auth(); });
test('падает ассертом', async () => { assert.strictEqual(1, 2, 'ожидали один, получили два'); });
`);
    assert.notStrictEqual(run.code, 0, run.output);
    const report = run.read(/-inner-failing-suite\.log$/);
    assert.ok(report, `нет suite.log среди ${run.files.join(', ') || 'пусто'}\n${run.output}`);
    assert.match(report, /\[тест «падает ассертом»\]/);
    assert.match(report, /ожидали один, получили два/);
    assert.ok(run.read(/-inner-failing-inner-failing-1\.log$/), `нет лога сервера среди ${run.files.join(', ')}`);
});

test('процесс набора завершён посреди теста: причина с кодом выхода и лог сохранены', async (t) => {
    const run = await runInner(t, 'exit', `
const suite = createSuite('inner-exit');
test('убивает процесс набора', async () => {
    await suite.client().auth();
    rememberDatabase(suite);
    process.exit(3);
});
`);
    assert.notStrictEqual(run.code, 0, run.output);
    const report = run.read(/-inner-exit-suite\.log$/);
    assert.ok(report, `нет suite.log среди ${run.files.join(', ') || 'пусто'}\n${run.output}`);
    assert.match(report, /\[exit\]/);
    assert.match(report, /кодом 3/);
    assert.ok(run.read(/-inner-exit-inner-exit-1\.log$/), `нет лога сервера среди ${run.files.join(', ')}`);
});

test('сбой уборки при зелёных тестах — предупреждение, а не «fail 1», и без падения при выходе', async (t) => {
    const run = await runInner(t, 'cleanup', `
const suite = createSuite('inner-cleanup');
test('проходит и ломает имя базы: удаление в уборке упадёт', async () => {
    await suite.client().auth();
    rememberDatabase(suite);
    suite.dbName = 'плохое имя';
});
test('проходит', async () => {});
`);
    // Все тесты зелёные, а уборка сломана: набор не падает (утёкшую базу
    // раннер удалит через 2 часа), след остаётся в выводе и в suite.log.
    assert.strictEqual(run.code, 0, run.output);
    assert.ok(!/Assertion failed/.test(run.output), `процесс упал при выходе:\n${run.output}`);
    assert.match(run.output, /# ВНИМАНИЕ, уборка набора inner-cleanup/);
    const report = run.read(/-inner-cleanup-suite\.log$/);
    assert.ok(report, `нет suite.log среди ${run.files.join(', ') || 'пусто'}\n${run.output}`);
    assert.match(report, /Сбои уборки/);
    assert.ok(!/Причины сбоя/.test(report), 'тесты зелёные — причин сбоя нет');
});
