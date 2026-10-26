'use strict';
// Жизненный цикл процесса (src/lifecycle.js; ревью W7 R5, З-11 г) - ОТДЕЛЬНЫМИ процессами, потому что
// проверяется то, что происходит с самим процессом: код выхода и что попало в лог.
//   * uncaughtException: запись в лог без стека и detail (поля ошибок Postgres - значения строк) и выход 1;
//   * unhandledRejection: запись в лог, процесс живёт;
//   * сбой миграций: сообщение, выход 1, порт не открывается; порт открывается только ПОСЛЕ миграций;
//   * SIGTERM и SIGINT: настоящая остановка (задачи, сервер, сокеты, пул) и выход 0 - слушатели подключены
//     к createShutdown (само поведение остановки - в shutdown.test.js);
//   * настоящий server.js при сбое старта (недоступная база, нет секретов) завершается с кодом не 0.
// Сценарии с заглушками - в test/lifecycle-child.js.
// Запуск: node test/lifecycle.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const CHILD = path.join(__dirname, 'lifecycle-child.js');
const SERVER = path.join(__dirname, '..', 'server.js');
const TIMEOUT_MS = 20000;

// Запускает процесс и ждёт его конца: { code, signal, out, events, timedOut }. Зависший процесс убивается.
function run(args, { cwd, env = process.env } = {}) {
    return new Promise((resolve) => {
        const child = spawn(process.execPath, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        let out = '';
        child.stdout.on('data', (chunk) => { out += chunk; });
        child.stderr.on('data', (chunk) => { out += chunk; });
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, TIMEOUT_MS);
        child.on('close', (code, signal) => {
            clearTimeout(timer);
            const events = out.split('\n').filter(line => line.startsWith('EV ')).map(line => JSON.parse(line.slice(3)));
            resolve({ code, signal, out, events, timedOut });
        });
    });
}

const runChild = (scenario, action) => run([CHILD, scenario, ...(action ? [action] : [])]);
const names = (result) => result.events.map(e => e.ev);

async function main() {
    await test('запуск: порт открывается только после миграций, задачи стартуют после открытия порта', async () => {
        const r = await runChild('ok', 'SIGTERM');
        assert.deepStrictEqual(names(r).slice(0, 3), ['migrated', 'listen', 'jobs.start'], r.out);
        const listen = r.events.find(e => e.ev === 'listen');
        assert.deepStrictEqual([listen.port, listen.host, listen.migrated], [3999, '127.0.0.1', true], 'readiness.migrated выставлен до listen');
    });

    for (const signal of ['SIGTERM', 'SIGINT']) {
        await test(`${signal}: задачи останавливаются, сервер и сокеты закрываются, пул - последним, выход 0`, async () => {
            const r = await runChild('ok', signal);
            assert.strictEqual(r.timedOut, false, r.out);
            assert.strictEqual(r.code, 0, r.out);
            const order = names(r);
            for (const step of ['jobs.stop', 'server.close', 'io.close', 'pool.end']) assert.ok(order.includes(step), `нет шага ${step}: ${order}`);
            assert.ok(order.indexOf('jobs.start') < order.indexOf('jobs.stop'));
            assert.ok(order.indexOf('server.close') < order.indexOf('pool.end'), 'пул закрывается после HTTP');
            assert.match(r.out, new RegExp(`\\[Process\\] ${signal}: остановка`));
            assert.match(r.out, /\[Process\] Остановлен/);
        });
    }

    await test('uncaughtException: запись в лог без стека и detail и выход с кодом 1', async () => {
        const r = await runChild('ok', 'uncaught');
        assert.strictEqual(r.timedOut, false, r.out);
        assert.strictEqual(r.code, 1, r.out);
        assert.match(r.out, /\[Process\] Необработанное исключение: boom/);
        assert.ok(!r.out.includes('SECRET-DETAIL'), 'detail ошибки попал в лог');
        assert.ok(!/\n\s+at .*\(.*\)/.test(r.out), 'стек попал в лог');
    });

    await test('unhandledRejection: запись в лог без detail, процесс продолжает работать', async () => {
        const r = await runChild('ok', 'rejection');
        assert.strictEqual(r.timedOut, false, r.out);
        assert.ok(names(r).includes('alive'), `процесс не пережил необработанный reject:\n${r.out}`);
        assert.strictEqual(r.code, 0, r.out);
        assert.match(r.out, /\[Process\] Необработанный reject промиса: rej/);
        assert.ok(!r.out.includes('SECRET-DETAIL'), 'detail ошибки попал в лог');
    });

    await test('сбой миграций: сообщение в лог, выход 1, порт не открывается и задачи не стартуют', async () => {
        const r = await runChild('init-fail');
        assert.strictEqual(r.timedOut, false, r.out);
        assert.strictEqual(r.code, 1, r.out);
        assert.match(r.out, /Ошибка инициализации БД: Postgres недоступен \(code=ECONNREFUSED\)/);
        assert.deepStrictEqual(names(r), [], `порт или задачи запущены после сбоя миграций: ${names(r)}`);
    });

    await test('миграция не дождалась блокировки таблицы: отдельное сообщение для оператора и выход 1', async () => {
        const r = await runChild('init-locked');
        assert.strictEqual(r.code, 1, r.out);
        assert.match(r.out, /миграция не дождалась блокировки таблицы/);
        assert.deepStrictEqual(names(r), []);
    });

    // ---- Настоящий server.js ----

    function serverEnv(overrides = {}) {
        const env = {
            PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TEMP: process.env.TEMP, TMP: process.env.TMP,
            NODE_ENV: 'test', HOST: '127.0.0.1', PORT: '39871',
            SESSION_SECRET: crypto.randomBytes(32).toString('base64url'),
            MESSAGE_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
            ...overrides,
        };
        for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
        return env;
    }

    await test('настоящий server.js: база недоступна - «Ошибка инициализации БД», выход 1, секрет из адреса базы в лог не попадает', async () => {
        const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-lifecycle-'));
        try {
            const dbSecret = crypto.randomBytes(12).toString('hex');
            const r = await run([SERVER], {
                cwd,
                env: serverEnv({ DATABASE_URL: `postgresql://nyxo:${dbSecret}@127.0.0.1:1/nope`, UPLOADS_DIR: path.join(cwd, 'uploads') }),
            });
            assert.strictEqual(r.timedOut, false, r.out);
            assert.strictEqual(r.code, 1, r.out);
            assert.match(r.out, /Ошибка инициализации БД: .*ECONNREFUSED/);
            assert.ok(!r.out.includes(dbSecret), 'секрет подключения к базе попал в лог');
            assert.ok(!/Nyxo Messenger запущен/.test(r.out), 'сервер объявил запуск при сбое миграций');
        } finally {
            fs.rmSync(cwd, { recursive: true, force: true });
        }
    });

    await test('настоящий server.js: нет ключа шифрования сообщений - процесс не стартует, выход не 0', async () => {
        const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-lifecycle-'));
        try {
            const r = await run([SERVER], {
                cwd,
                env: serverEnv({
                    MESSAGE_ENCRYPTION_KEY: undefined, DATABASE_URL: 'postgresql://nyxo:pw@127.0.0.1:1/nope', UPLOADS_DIR: path.join(cwd, 'uploads'),
                }),
            });
            assert.strictEqual(r.timedOut, false, r.out);
            assert.notStrictEqual(r.code, 0, r.out);
            assert.match(r.out, /MESSAGE_ENCRYPTION_KEY не задан/);
            assert.ok(!/Nyxo Messenger запущен/.test(r.out));
        } finally {
            fs.rmSync(cwd, { recursive: true, force: true });
        }
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
