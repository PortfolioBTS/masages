'use strict';
// Вкладка настоящего браузера: действия «как человек» (клик мышью в точку
// элемента, ввод текста, нажатия клавиш, выбор файла в input) и наблюдение за
// всем, что браузер считает проблемой, — ошибки консоли, исключения страницы,
// нарушения CSP, отказавшие сетевые запросы.
//
// Принцип: страница не подправляется скриптами из теста. Клик идёт через
// Input.dispatchMouseEvent, поэтому элемент, перекрытый другим (модальным
// окном, баннером), нельзя «нажать» — тест упадёт с названием перекрывающего
// элемента, как не смог бы нажать человек. Чтение состояния (текст, число
// элементов) — через Runtime.evaluate.

const fs = require('fs');
const path = require('path');
const { setTimeout: delay } = require('timers/promises');

const SCREENS_DIR = process.env.NYXO_BROWSER_SCREENS_DIR
    ? path.resolve(process.env.NYXO_BROWSER_SCREENS_DIR)
    : path.join(__dirname, '..', '.screens');

const DEFAULT_TIMEOUT_MS = 15000;
const POLL_MS = 50;
// Транспорт socket.io (опрос, пинги) идёт сам по себе и к действиям человека не относится.
const SOCKET_IO_RE = /\/socket\.io\//;

// Ошибки вида «страница ушла на другой документ, пока шёл запрос» — при
// ожидании это просто повод повторить.
const NAVIGATION_ERROR_RE = /Execution context was destroyed|Cannot find context|Inspected target navigated|Target closed|context with specified id/i;

const KEYS = {
    Enter: { code: 'Enter', vk: 13, text: '\r' },
    Escape: { code: 'Escape', vk: 27 },
    Tab: { code: 'Tab', vk: 9 },
    Backspace: { code: 'Backspace', vk: 8 },
    ArrowDown: { code: 'ArrowDown', vk: 40 },
    ArrowUp: { code: 'ArrowUp', vk: 38 },
    Home: { code: 'Home', vk: 36 },
    End: { code: 'End', vk: 35 },
    F10: { code: 'F10', vk: 121 },
    ContextMenu: { code: 'ContextMenu', vk: 93 },
};

function remoteValue(arg) {
    if (arg.value !== undefined) return typeof arg.value === 'string' ? arg.value : JSON.stringify(arg.value);
    return arg.description || arg.unserializableValue || arg.type;
}

function exceptionText(details) {
    const ex = details.exception;
    const where = details.url ? ` (${details.url}:${details.lineNumber}:${details.columnNumber})` : '';
    return `${(ex && (ex.description || ex.value)) || details.text}${where}`;
}

class BrowserPage {
    constructor(profile, targetId, sessionId) {
        this.profile = profile;
        this.conn = profile.connection;
        this.targetId = targetId;
        this.sessionId = sessionId;
        this.problems = [];       // то, что считается сбоем набора
        this.warnings = [];       // предупреждения консоли: для диагностики, не сбой
        this.dialogs = [];        // [{ type, message, accepted }]
        this.requests = [];       // [{ url, method, type }] — все запросы вкладки по порядку
        this.lastRequestAt = Date.now();   // последний запрос не из socket.io (для waitForNetworkQuiet)
        this.allowed = [];        // шаблоны известных безвредных сообщений
        this.dialogHandler = () => true;   // true — OK, false — отмена
        this.closed = false;
    }

    static async create(profile, { width, height }) {
        const conn = profile.connection;
        const { targetId } = await conn.send('Target.createTarget', { url: 'about:blank' });
        const { sessionId } = await conn.send('Target.attachToTarget', { targetId, flatten: true });
        const page = new BrowserPage(profile, targetId, sessionId);
        await page.init({ width, height });
        return page;
    }

    send(method, params) {
        return this.conn.send(method, params, this.sessionId);
    }

    on(event, handler) {
        return this.conn.on(this.sessionId, event, handler);
    }

    addProblem(text) {
        if (this.allowed.some(re => re.test(text))) return;
        this.problems.push(text);
    }

    // Известное безвредное сообщение: не считается сбоем. Каждое такое
    // исключение должно быть описано в тесте — почему оно допустимо.
    allow(re) {
        this.allowed.push(re);
    }

    async init({ width, height }) {
        this.on('Runtime.consoleAPICalled', ({ type, args }) => {
            const text = args.map(remoteValue).join(' ');
            if (type === 'error' || type === 'assert') this.addProblem(`console.${type}: ${text}`);
            else if (type === 'warning') this.warnings.push(text);
        });
        this.on('Runtime.exceptionThrown', ({ exceptionDetails }) => {
            this.addProblem(`исключение страницы: ${exceptionText(exceptionDetails)}`);
        });
        this.on('Log.entryAdded', ({ entry }) => {
            if (entry.level === 'error') this.addProblem(`${entry.source}: ${entry.text}${entry.url ? ` (${entry.url})` : ''}`);
            else if (entry.level === 'warning') this.warnings.push(`${entry.source}: ${entry.text}`);
        });
        // Нарушения CSP: браузер сообщает о них и в консоль, и отдельной
        // «проблемой» — ловим оба пути, чтобы не пропустить тихое.
        this.on('Audits.issueAdded', ({ issue }) => {
            if (issue.code !== 'ContentSecurityPolicyIssue') return;
            const d = issue.details.contentSecurityPolicyIssueDetails || {};
            this.addProblem(`CSP: ${d.violatedDirective || '?'} заблокировал ${d.blockedURL || d.contentSecurityPolicyViolationType || '?'}`);
        });
        this.on('Network.requestWillBeSent', ({ request, type }) => {
            this.requests.push({ url: request.url, method: request.method, type: type || '' });
            if (!SOCKET_IO_RE.test(request.url)) this.lastRequestAt = Date.now();
        });
        this.on('Network.webSocketCreated', ({ url }) => {
            this.requests.push({ url, method: 'GET', type: 'WebSocket' });
        });
        this.on('Network.loadingFailed', ({ errorText, canceled, blockedReason, type }) => {
            if (canceled && !blockedReason) return;
            this.addProblem(`сеть: запрос (${type || '?'}) не выполнен: ${blockedReason || errorText}`);
        });
        this.on('Page.javascriptDialogOpening', async ({ type, message }) => {
            const accept = Boolean(this.dialogHandler({ type, message }));
            this.dialogs.push({ type, message, accepted: accept });
            await this.send('Page.handleJavaScriptDialog', { accept }).catch(() => {});
        });
        // Dedicated worker (PoW) — часть вкладки: его ошибки тоже ошибки вкладки.
        this.on('Target.attachedToTarget', ({ sessionId, targetInfo }) => {
            if (targetInfo.type !== 'worker') return;
            const label = `worker ${path.posix.basename(targetInfo.url)}`;
            this.conn.on(sessionId, 'Runtime.exceptionThrown', ({ exceptionDetails }) => this.addProblem(`${label}: исключение: ${exceptionText(exceptionDetails)}`));
            this.conn.on(sessionId, 'Runtime.consoleAPICalled', ({ type, args }) => {
                if (type === 'error') this.addProblem(`${label}: console.error: ${args.map(remoteValue).join(' ')}`);
            });
            this.conn.send('Runtime.enable', {}, sessionId).catch(() => {});
            this.conn.send('Runtime.runIfWaitingForDebugger', {}, sessionId).catch(() => {});
        });

        await Promise.all([
            this.send('Page.enable'),
            this.send('Runtime.enable'),
            this.send('Log.enable'),
            this.send('Network.enable'),
            this.send('DOM.enable'),
            this.send('Audits.enable'),
            this.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false }),
            this.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }),
        ]);
    }

    // Размер окна страницы: у интерфейса есть узкая раскладка, её тоже снимаем.
    setViewport(width, height) {
        return this.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
    }

    // ---- Навигация ----

    async goto(url, { timeoutMs = 30000 } = {}) {
        const loaded = this.conn.waitForEvent(this.sessionId, 'Page.loadEventFired', () => true, { timeoutMs, what: `загрузка ${url}` });
        const { errorText } = await this.send('Page.navigate', { url });
        if (errorText) {
            loaded.catch(() => {});
            throw new Error(`переход на ${url} не удался: ${errorText}`);
        }
        await loaded;
    }

    async reload({ timeoutMs = 30000 } = {}) {
        const loaded = this.conn.waitForEvent(this.sessionId, 'Page.loadEventFired', () => true, { timeoutMs, what: 'перезагрузка' });
        await this.send('Page.reload', { ignoreCache: false });
        await loaded;
    }

    // ---- Чтение состояния ----

    async evaluate(fn, ...args) {
        const expression = typeof fn === 'function' ? `(${fn.toString()})(...${JSON.stringify(args)})` : String(fn);
        const res = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
        if (res.exceptionDetails) throw new Error(`в странице: ${exceptionText(res.exceptionDetails)}`);
        return res.result.value;
    }

    // Ждёт, пока fn (выполняется в странице) вернёт истинное значение.
    async waitFor(fn, { args = [], timeoutMs = DEFAULT_TIMEOUT_MS, what = 'условие' } = {}) {
        const deadline = Date.now() + timeoutMs;
        for (;;) {
            try {
                const value = await this.evaluate(fn, ...args);
                if (value) return value;
            } catch (err) {
                if (!NAVIGATION_ERROR_RE.test(err.message)) throw err;
            }
            if (Date.now() > deadline) {
                throw new Error(`не дождались за ${timeoutMs} мс: ${what}\n${await this.describe()}`);
            }
            await delay(POLL_MS);
        }
    }

    waitForSelector(selector, opts = {}) {
        return this.waitFor((sel) => {
            const el = document.querySelector(sel);
            if (!el) return false;
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
        }, { args: [selector], what: `виден элемент ${selector}`, ...opts });
    }

    waitForGone(selector, opts = {}) {
        return this.waitFor((sel) => {
            const el = document.querySelector(sel);
            if (!el) return true;
            const r = el.getBoundingClientRect();
            return r.width === 0 || r.height === 0 || getComputedStyle(el).visibility === 'hidden';
        }, { args: [selector], what: `скрыт элемент ${selector}`, ...opts });
    }

    waitForText(selector, pattern, opts = {}) {
        const source = pattern instanceof RegExp ? pattern.source : String(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const flags = pattern instanceof RegExp ? pattern.flags : '';
        return this.waitFor((sel, src, fl) => {
            const el = document.querySelector(sel);
            return Boolean(el) && new RegExp(src, fl).test(el.textContent || '');
        }, { args: [selector, source, flags], what: `текст в ${selector}: ${pattern}`, ...opts });
    }

    text(selector) {
        return this.evaluate((sel) => {
            const el = document.querySelector(sel);
            return el ? el.textContent : null;
        }, selector);
    }

    texts(selector) {
        return this.evaluate((sel) => Array.from(document.querySelectorAll(sel), el => el.textContent), selector);
    }

    count(selector) {
        return this.evaluate((sel) => document.querySelectorAll(sel).length, selector);
    }

    // Элемент есть и занимает место на экране (не hidden и не display:none).
    isVisible(selector) {
        return this.evaluate((sel) => {
            const el = document.querySelector(sel);
            if (!el) return false;
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
        }, selector);
    }

    // Короткое описание состояния для сообщений об ошибках.
    async describe() {
        let state = '';
        try {
            state = await this.evaluate(() => {
                const pick = (sel) => {
                    const el = document.querySelector(sel);
                    return el ? (el.textContent || '').trim().slice(0, 200) : null;
                };
                const modals = Array.from(document.querySelectorAll('.modal:not(.hidden)'), el => el.id);
                return JSON.stringify({ url: location.pathname + (location.hash ? '#…' : ''), toast: pick('#toast:not(.hidden)'), authProgress: pick('#auth-progress'), authNotice: pick('#auth-notice:not(.hidden)'), modals });
            });
        } catch (err) {
            state = `страница недоступна: ${err.message}`;
        }
        const problems = this.problems.length > 0 ? `\nпроблемы консоли:\n  ${this.problems.slice(-5).join('\n  ')}` : '';
        return `состояние страницы: ${state}${problems}`;
    }

    // ---- Действия ----

    // Положение элемента для клика: ждёт, пока он появится, включится и перестанет двигаться
    // (модальные окна и баннеры выезжают с анимацией).
    async locate(selector, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
        const probe = (sel) => {
            const el = document.querySelector(sel);
            if (!el) return { state: 'absent' };
            if (el.disabled || el.getAttribute('aria-disabled') === 'true') return { state: 'disabled' };
            el.scrollIntoView({ block: 'center', inline: 'center' });
            const r = el.getBoundingClientRect();
            if (r.width === 0 || r.height === 0 || getComputedStyle(el).visibility === 'hidden') return { state: 'hidden' };
            const x = r.left + r.width / 2;
            const y = r.top + r.height / 2;
            const hit = document.elementFromPoint(x, y);
            const label = hit && hit.closest('label');
            const reachable = hit && (el === hit || el.contains(hit) || (label && label.contains(el)));
            if (reachable) return { state: 'ok', x, y };
            const name = hit ? `${hit.tagName.toLowerCase()}${hit.id ? '#' + hit.id : ''}${hit.className && typeof hit.className === 'string' ? '.' + hit.className.trim().split(/\s+/).join('.') : ''}` : 'ничего';
            return { state: 'covered', by: name };
        };
        const deadline = Date.now() + timeoutMs;
        let previous = null;
        let last = { state: 'absent' };
        for (;;) {
            try {
                last = await this.evaluate(probe, selector);
            } catch (err) {
                if (!NAVIGATION_ERROR_RE.test(err.message)) throw err;
            }
            if (last.state === 'ok') {
                if (previous && Math.abs(previous.x - last.x) < 0.5 && Math.abs(previous.y - last.y) < 0.5) return last;
                previous = last;
            } else {
                previous = null;
            }
            if (Date.now() > deadline) {
                const why = { absent: 'элемента нет в странице', disabled: 'элемент выключен', hidden: 'элемент скрыт', covered: `элемент перекрыт: ${last.by}`, ok: 'элемент всё время двигался' }[last.state];
                throw new Error(`нельзя нажать ${selector}: ${why}\n${await this.describe()}`);
            }
            await delay(POLL_MS);
        }
    }

    async click(selector, opts = {}) {
        const { x, y } = await this.locate(selector, opts);
        await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
        await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 });
        await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 });
    }

    // Клик в поле, выделение прежнего содержимого и вставка текста: как «выделил всё и набрал».
    async type(selector, text, { replace = true, ...opts } = {}) {
        await this.click(selector, opts);
        if (replace) {
            await this.evaluate((sel) => {
                const el = document.querySelector(sel);
                if (el && typeof el.select === 'function') el.select();
            }, selector);
        }
        await this.send('Input.insertText', { text });
    }

    // Очистить поле: клик, «выделить всё», Backspace.
    async clear(selector, opts = {}) {
        await this.click(selector, opts);
        await this.evaluate((sel) => {
            const el = document.querySelector(sel);
            if (el && typeof el.select === 'function') el.select();
        }, selector);
        await this.press('Backspace');
    }

    // shift: true — с зажатым Shift (Shift+Enter — перенос строки, Shift+F10 — контекстное меню).
    async press(key, { shift = false } = {}) {
        const k = KEYS[key];
        if (!k) throw new Error(`неизвестная клавиша ${key}`);
        const modifiers = shift ? 8 : 0;
        await this.send('Input.dispatchKeyEvent', { type: k.text ? 'keyDown' : 'rawKeyDown', key, code: k.code, windowsVirtualKeyCode: k.vk, text: k.text, modifiers });
        await this.send('Input.dispatchKeyEvent', { type: 'keyUp', key, code: k.code, windowsVirtualKeyCode: k.vk, modifiers });
    }

    // Файлы в <input type="file">: как выбор в системном диалоге (события input и change приходят сами).
    async setFiles(selector, files) {
        const { root } = await this.send('DOM.getDocument', { depth: 0 });
        const { nodeId } = await this.send('DOM.querySelector', { nodeId: root.nodeId, selector });
        if (!nodeId) throw new Error(`нет элемента ${selector}`);
        await this.send('DOM.setFileInputFiles', { files: files.map(f => path.resolve(f)), nodeId });
    }

    // ---- Сеть ----

    networkMark() {
        return this.requests.length;
    }

    // Запросы после метки. Транспорт socket.io отфильтрован, остальное считается.
    requestsSince(mark, { ignore = SOCKET_IO_RE } = {}) {
        return this.requests.slice(mark).filter(r => !ignore.test(r.url));
    }

    // Ждёт, пока страница перестанет что-то запрашивать (отметки о прочтении,
    // догрузка ключей идут «по следам» действий): после этого можно ставить метку
    // и проверять, что следующее действие сети не трогает.
    async waitForNetworkQuiet({ quietMs = 1500, timeoutMs = 20000 } = {}) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() - this.lastRequestAt < quietMs) {
            if (Date.now() > deadline) throw new Error(`сеть не затихла за ${timeoutMs} мс: последние запросы ${JSON.stringify(this.requests.slice(-3).map(r => `${r.method} ${r.url}`))}`);
            await delay(POLL_MS);
        }
    }

    // ---- Итоги ----

    assertConsoleClean(label = '') {
        if (this.conn.handlerError) throw this.conn.handlerError;
        if (this.problems.length === 0) return;
        throw new Error(`в консоли браузера есть ошибки${label ? ` (${label})` : ''}:\n  ${this.problems.join('\n  ')}`);
    }

    async screenshot(name) {
        fs.mkdirSync(SCREENS_DIR, { recursive: true });
        const { data } = await this.send('Page.captureScreenshot', { format: 'png' });
        const file = path.join(SCREENS_DIR, `${name}.png`);
        fs.writeFileSync(file, Buffer.from(data, 'base64'));
        return file;
    }

    async close() {
        if (this.closed) return;
        this.closed = true;
        await this.conn.send('Target.closeTarget', { targetId: this.targetId }).catch(() => {});
    }
}

module.exports = { BrowserPage, SCREENS_DIR };
