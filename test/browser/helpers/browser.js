'use strict';
// Запуск настоящего Chrome/Chromium с временным профилем и управление им по CDP.
//
// * Профиль — новая папка user-data-dir во временной директории ОС: личные
//   профили человека не открываются и не меняются, а после набора папка
//   удаляется. Каждый профиль — отдельный процесс браузера со своими куками,
//   localStorage и IndexedDB: так получаются «два разных устройства».
// * Порт отладки выбирает сам браузер (--remote-debugging-port=0) и записывает
//   в файл DevToolsActivePort внутри профиля — гонки за свободный порт нет.
// * Отладочный порт слушает только 127.0.0.1 (так ведёт себя сам Chrome).
// * Закрытие: Browser.close, ожидание выхода, затем принудительное завершение
//   дерева процессов; профиль удаляется с повторами (Windows отпускает файлы
//   не сразу).

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { setTimeout: delay } = require('timers/promises');
const { CdpConnection } = require('./cdp');
const { BrowserPage } = require('./page');
const { isCi } = require('./find-browser');

const START_TIMEOUT_MS = 30000;
const EXIT_TIMEOUT_MS = 8000;

// Флаги, без которых профиль «шумит»: окна приветствия, проверки обновлений,
// фоновые запросы к серверам Google (они были бы лишней сетью и лишним шумом
// в консоли). Сетевые запросы страницы приложения этим не меняются.
const BASE_FLAGS = [
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-sync',
    '--disable-component-update',
    '--disable-background-networking',
    '--disable-default-apps',
    '--disable-search-engine-choice-screen',
    '--disable-features=Translate,MediaRouter,OptimizationHints',
    '--password-store=basic',
    '--use-mock-keychain',
    '--metrics-recording-only',
];

function launchFlags({ userDataDir, headed, env }) {
    const flags = [`--user-data-dir=${userDataDir}`, '--remote-debugging-port=0', ...BASE_FLAGS];
    if (!headed) flags.push('--headless=new', '--hide-scrollbars', '--mute-audio');
    // На Linux-раннерах CI (особенно с AppArmor-ограничениями пользовательских
    // пространств имён) песочница Chrome не стартует, а изолирован там уже сам
    // раннер. Локально песочница остаётся включённой.
    if (isCi(env) || env.NYXO_BROWSER_NO_SANDBOX) {
        flags.push('--no-sandbox', '--disable-dev-shm-usage');
    }
    flags.push('about:blank');
    return flags;
}

function removeDir(dir) {
    // maxRetries: сразу после выхода Chrome Windows ещё держит файлы профиля.
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
}

class BrowserProfile {
    constructor({ name, executable, headed = false, env = process.env }) {
        this.name = name;
        this.executable = executable;
        this.headed = headed;
        this.env = env;
        this.userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), `nyxo-browser-${name}-`));
        this.child = null;
        this.exit = null;
        this.exitPromise = null;
        this.stderrTail = '';
        this.connection = null;
        this.pages = [];
        this.workerProblems = [];   // ошибки из воркеров (service worker, PoW), не привязанные к вкладке
    }

    static async launch(opts) {
        const profile = new BrowserProfile(opts);
        try {
            await profile.start();
        } catch (err) {
            await profile.close().catch(() => {});
            throw err;
        }
        return profile;
    }

    async start() {
        const args = launchFlags({ userDataDir: this.userDataDir, headed: this.headed, env: this.env });
        const child = spawn(this.executable, args, {
            stdio: ['ignore', 'ignore', 'pipe'],
            windowsHide: true,
            // На Linux — своя группа процессов, чтобы завершить всё дерево разом.
            detached: process.platform !== 'win32',
        });
        this.child = child;
        child.stderr.on('data', (chunk) => {
            this.stderrTail = (this.stderrTail + chunk.toString('utf8')).slice(-4000);
        });
        this.exitPromise = new Promise((resolve) => {
            child.once('error', (err) => { this.exit = { error: err.message }; resolve(this.exit); });
            child.once('close', (code, signal) => { this.exit = { code, signal }; resolve(this.exit); });
        });

        const wsUrl = await this.waitForDebugUrl();
        this.connection = new CdpConnection(wsUrl);
        await this.connection.open();
        await this.watchWorkers();
    }

    // Chrome пишет в профиль DevToolsActivePort: первая строка — порт, вторая —
    // путь вебсокета браузера.
    async waitForDebugUrl() {
        const file = path.join(this.userDataDir, 'DevToolsActivePort');
        const deadline = Date.now() + START_TIMEOUT_MS;
        for (;;) {
            if (this.exit) {
                throw new Error(`браузер ${this.name} завершился при запуске (${JSON.stringify(this.exit)}):\n${this.stderrTail}`);
            }
            try {
                const [port, wsPath] = fs.readFileSync(file, 'utf8').split('\n');
                if (port && wsPath) return `ws://127.0.0.1:${port.trim()}${wsPath.trim()}`;
            } catch {
                // файла ещё нет
            }
            if (Date.now() > deadline) {
                throw new Error(`браузер ${this.name} не открыл порт отладки за ${START_TIMEOUT_MS} мс:\n${this.stderrTail}`);
            }
            await Promise.race([delay(50), this.exitPromise]);
        }
    }

    // Воркеры (service worker, PoW-воркер) живут вне вкладки: их консоль не
    // попала бы в вкладку. Подключаемся к ним сами и собираем ошибки.
    async watchWorkers() {
        const conn = this.connection;
        conn.on(null, 'Target.attachedToTarget', ({ sessionId, targetInfo }) => {
            if (!['service_worker', 'worker', 'shared_worker'].includes(targetInfo.type)) return;
            const label = `${targetInfo.type} ${targetInfo.url}`;
            conn.on(sessionId, 'Runtime.exceptionThrown', ({ exceptionDetails }) => {
                this.workerProblems.push(`${label}: исключение: ${exceptionDetails.exception ? exceptionDetails.exception.description || exceptionDetails.text : exceptionDetails.text}`);
            });
            conn.on(sessionId, 'Runtime.consoleAPICalled', ({ type, args }) => {
                if (type !== 'error') return;
                this.workerProblems.push(`${label}: console.error: ${args.map(a => a.value !== undefined ? a.value : a.description).join(' ')}`);
            });
            conn.on(sessionId, 'Log.entryAdded', ({ entry }) => {
                if (entry.level === 'error') this.workerProblems.push(`${label}: ${entry.source}: ${entry.text}`);
            });
            conn.send('Runtime.enable', {}, sessionId).catch(() => {});
            conn.send('Log.enable', {}, sessionId).catch(() => {});
            conn.send('Runtime.runIfWaitingForDebugger', {}, sessionId).catch(() => {});
        });
        await conn.send('Target.setAutoAttach', {
            autoAttach: true,
            waitForDebuggerOnStart: false,
            flatten: true,
            filter: [{ type: 'service_worker' }, { type: 'worker' }, { type: 'shared_worker' }, { exclude: true }],
        });
    }

    async version() {
        return this.connection.send('Browser.getVersion');
    }

    async newPage({ width = 1280, height = 800 } = {}) {
        const page = await BrowserPage.create(this, { width, height });
        this.pages.push(page);
        return page;
    }

    // Все замечания консоли по всем вкладкам профиля и воркерам.
    consoleProblems() {
        return [...this.pages.flatMap(page => page.problems), ...this.workerProblems];
    }

    async close() {
        if (this.connection && !this.connection.closed && !this.exit) {
            await this.connection.send('Browser.close').catch(() => {});
        }
        if (this.child && !this.exit) {
            const exited = await Promise.race([this.exitPromise, delay(EXIT_TIMEOUT_MS).then(() => null)]);
            if (!exited) this.killTree();
            await Promise.race([this.exitPromise, delay(EXIT_TIMEOUT_MS)]);
        }
        if (this.connection) this.connection.close();
        removeDir(this.userDataDir);
    }

    killTree() {
        const pid = this.child && this.child.pid;
        if (!pid) return;
        if (process.platform === 'win32') {
            spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
        } else {
            try { process.kill(-pid, 'SIGKILL'); } catch { try { process.kill(pid, 'SIGKILL'); } catch { /* уже вышел */ } }
        }
    }
}

module.exports = { BrowserProfile, launchFlags };
