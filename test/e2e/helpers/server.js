'use strict';
// Сервер сквозного теста: настоящий server.js отдельным процессом.
//
// Почему не в процессе теста: server.js при загрузке читает .env, открывает
// пул, ставит таймеры и вызывает process.exit при ошибках, а тестам нужны
// рестарты (идемпотентность миграций), две реплики на одну базу, чистые
// логи и изоляция падений.
//
// * cwd — временная папка: dotenv не найдёт .env разработчика, а
//   localhost+1*.pem не подхватятся — сервер идёт по HTTP;
// * окружение — явное (helpers/env.js#serverEnv);
// * порт — свободный (listen(0) → close); если его успели занять
//   (EADDRINUSE) — повтор с другим;
// * готовность — GET /api/auth отвечает 200 (до 30 с); процесс умер раньше —
//   ошибка с хвостом лога;
// * restart({ env }) сохраняет базу, UPLOADS_DIR и по возможности порт;
// * логи — в памяти (server.logs, helpers/logs.js), переживают рестарты.

const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { setTimeout: delay } = require('timers/promises');
const { SERVER_ENTRY, serverEnv, randomSecrets } = require('./env');
const { LogBuffer } = require('./logs');
const { TestClient } = require('./client');

const CHILD_GUARD = path.join(__dirname, 'child-guard.js');
const READY_TIMEOUT_MS = 30000;
const READY_POLL_MS = 100;
const STOP_TIMEOUT_MS = 5000;
const TICK_RE = /\[Test\] maintenance tick (\d+)/;
const DB_BUSY_RE = /too many clients already|remaining connection slots are reserved/i;

// Тишина перед выходом процесса набора.
//
// Если процесс набора завершается сразу после остановки серверов, а runner
// делает это без паузы после последнего хука (--test-force-exit), на Windows
// libuv падает: «Assertion failed: !(handle->flags & UV_HANDLE_CLOSING),
// src\win\async.c». Файл-набор тогда помечается упавшим при ВСЕХ зелёных
// тестах («tests N+1, fail 1», в выводе одна строка 'test failed', логов
// нет). Воспроизводится стабильно: любой fetch к серверу, затем kill сервера и
// немедленный выход (с keep-alive-соединениями, которые убитый сервер рвёт);
// пауза в 50 мс после kill — и падения нет. Обычно спасало удаление базы после
// остановки серверов (десятки мс), но не всегда.
//
// Поэтому в конце хука ждём: дескрипторов дочерних процессов (ProcessWrap) в
// процессе больше нет и с момента завершения последнего сервера прошло
// quietMs. Время здесь неизбежно — закрытие сокетов libuv снаружи не
// наблюдается (getActiveResourcesInfo их уже не показывает) — но ждём только
// остаток: обычно удаление базы после остановки серверов съедает его почти
// целиком.
let lastServerExitAt = 0;

async function settleBeforeExit({ quietMs = 150, timeoutMs = 3000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const hasChildHandles = typeof process.getActiveResourcesInfo === 'function'
            && process.getActiveResourcesInfo().includes('ProcessWrap');
        const quiet = Date.now() - lastServerExitAt >= quietMs;
        if ((!hasChildHandles && quiet) || Date.now() >= deadline) return;
        await delay(5);
    }
}

function freePort() {
    return new Promise((resolve, reject) => {
        const probe = net.createServer();
        probe.unref();
        probe.on('error', reject);
        probe.listen(0, '127.0.0.1', () => {
            const { port } = probe.address();
            probe.close(() => resolve(port));
        });
    });
}

class ServerHandle {
    constructor({ databaseUrl, env = {}, name = 'server', secrets = randomSecrets(), workDir } = {}) {
        if (!databaseUrl) throw new Error('startServer: нужен databaseUrl');
        this.databaseUrl = databaseUrl;
        this.env = { ...env };
        this.name = name;
        this.secrets = secrets;
        this.ownWorkDir = !workDir;
        this.workDir = workDir || fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-e2e-'));
        this.uploadsDir = path.join(this.workDir, 'uploads');
        this.logs = new LogBuffer();
        this.port = null;
        this.child = null;
        this.exitInfo = null;
        this.exitPromise = Promise.resolve(null);
    }

    get baseUrl() { return `http://127.0.0.1:${this.port}`; }
    get alive() { return Boolean(this.child) && !this.exitInfo; }

    spawnProcess() {
        const env = serverEnv({
            databaseUrl: this.databaseUrl,
            port: this.port,
            uploadsDir: this.uploadsDir,
            secrets: this.secrets,
            extra: this.env,
        });
        this.logs.note(`старт ${this.name}, порт ${this.port}`);
        this.logs.processStarted();
        this.exitInfo = null;
        const child = spawn(process.execPath, ['--require', CHILD_GUARD, SERVER_ENTRY], {
            cwd: this.workDir,
            env,
            stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
            windowsHide: true,
        });
        this.child = child;
        this.logs.attach(child.stdout, 'stdout');
        this.logs.attach(child.stderr, 'stderr');
        child.on('error', (err) => this.logs.note(`ошибка процесса: ${err.message}`));
        this.exitPromise = new Promise((resolve) => {
            child.once('close', (code, signal) => {
                lastServerExitAt = Date.now();
                this.exitInfo = { code, signal };
                this.logs.processExited(this.exitInfo);
                resolve(this.exitInfo);
            });
        });
    }

    async waitReady() {
        const deadline = Date.now() + READY_TIMEOUT_MS;
        for (;;) {
            if (this.exitInfo) {
                throw new Error(`сервер ${this.name} завершился при старте (${JSON.stringify(this.exitInfo)}):\n${this.logs.tail(100)}`);
            }
            try {
                const res = await fetch(`${this.baseUrl}/api/auth`, { signal: AbortSignal.timeout(2000) });
                await res.arrayBuffer();
                if (res.status === 200) return;
            } catch {
                // ещё не слушает порт
            }
            if (Date.now() > deadline) {
                throw new Error(`сервер ${this.name} не ответил на GET /api/auth за ${READY_TIMEOUT_MS} мс:\n${this.logs.tail(100)}`);
            }
            await Promise.race([delay(READY_POLL_MS), this.exitPromise]);
        }
    }

    async start() {
        for (let attempt = 1; ; attempt++) {
            if (!this.port) this.port = await freePort();
            const mark = this.logs.mark();
            this.spawnProcess();
            try {
                await this.waitReady();
                return this;
            } catch (err) {
                await this.stop();
                if (attempt < 3 && this.logs.find('EADDRINUSE', { from: mark })) {
                    this.port = null;
                    continue;
                }
                // Общий контейнер Postgres делят несколько прогонов: на пике
                // кончаются слоты соединений, и сервер падает при старте. Это
                // сбой окружения, а не кода — повтор с паузой.
                if (attempt < 3 && this.logs.find(DB_BUSY_RE, { from: mark })) {
                    this.logs.note(`Postgres перегружен (нет слотов соединений), повтор старта ${this.name}`);
                    await delay(500 * attempt);
                    continue;
                }
                throw err;
            }
        }
    }

    async stop() {
        if (!this.child || this.exitInfo) return this.exitInfo;
        this.logs.note(`остановка ${this.name}`);
        const child = this.child;
        child.kill();
        const timer = setTimeout(() => child.kill('SIGKILL'), STOP_TIMEOUT_MS);
        const info = await this.exitPromise;
        clearTimeout(timer);
        return info;
    }

    // Рестарт на той же базе и с теми же UPLOADS_DIR и портом; env
    // дополняет окружение (null — убрать переменную).
    async restart({ env } = {}) {
        await this.stop();
        if (env) this.env = { ...this.env, ...env };
        this.logs.note(`рестарт ${this.name}`);
        return this.start();
    }

    // Ждёт count НОВЫХ строк «[Test] maintenance tick <n>» (проходов чистки
    // анонимов) и возвращает номер последнего. Гарантированно полный проход,
    // начатый ПОСЛЕ вызова, — count = 2: первый мог начаться раньше.
    async waitForTick(count = 1, { timeoutMs = 10000 } = {}) {
        let from = this.logs.mark();
        let last = null;
        for (let i = 0; i < count; i++) {
            last = await this.logs.waitFor(TICK_RE, { from, timeoutMs });
            from = last.n + 1;
        }
        return Number(last.match[1]);
    }

    // Ждёт завершения процесса (для проверок «сервер не стартует»).
    async waitForExit({ timeoutMs = READY_TIMEOUT_MS } = {}) {
        let timer;
        const timeout = new Promise((resolve, reject) => {
            timer = setTimeout(() => reject(new Error(`сервер ${this.name} не завершился за ${timeoutMs} мс:\n${this.logs.tail(40)}`)), timeoutMs);
        });
        try {
            return await Promise.race([this.exitPromise, timeout]);
        } finally {
            clearTimeout(timer);
        }
    }

    client(opts) { return new TestClient(this, opts); }

    async dispose() {
        await this.stop();
        if (this.ownWorkDir) fs.rmSync(this.workDir, { recursive: true, force: true });
    }
}

// Запустить и дождаться готовности.
async function startServer(opts) {
    return new ServerHandle(opts).start();
}

// Запустить процесс без ожидания готовности: для проверок, что сервер НЕ
// стартует (ждать — waitForExit()).
async function spawnServer(opts) {
    const handle = new ServerHandle(opts);
    handle.port = await freePort();
    handle.spawnProcess();
    return handle;
}

module.exports = { ServerHandle, startServer, spawnServer, freePort, settleBeforeExit, TICK_RE };
