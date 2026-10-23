'use strict';
// Запуск отдельных функций клиента (public/js/*.js) в vm с заглушками DOM — без браузера.
//
// Клиент — классические скрипты с общей глобальной областью, поэтому «модулем» его
// не загрузить. Здесь из склеенного исходника (readClientScript) вырезаются нужные
// функции верхнего уровня по имени и выполняются в изолированном контексте вместе с
// переменными, которые тест объявляет сам (let/const состояния). Всё остальное —
// заглушки: `elements` — прокси, который сам создаёт FakeEl на любое обращение,
// `document`, `window`, `showToast` и прочее передаёт тест.
//
// Это проверка ЛОГИКИ (какой режим включился, что очистилось, какой запрос ушёл);
// вёрстка, фокус и настоящие события проверяются сценариями test/browser.

const vm = require('vm');
const { readClientScript } = require('./client-script-source');

// Исходник функции верхнего уровня по имени: от `function name(` / `async function name(` до
// закрывающей `}` в первом столбце.
function extractFunction(source, name) {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    if (!match) throw new Error(`функция ${name} не найдена в клиенте`);
    const end = source.indexOf('\n}\n', match.index);
    if (end < 0) throw new Error(`у функции ${name} нет конца`);
    return source.slice(match.index, end + 2);
}

// Объявление верхнего уровня const/let в одну строку (константы с тайм-аутами и т. п.).
function extractConst(source, name) {
    const match = new RegExp(`^(?:const|let) ${name} = [^\\n]*;$`, 'm').exec(source);
    if (!match) throw new Error(`константа ${name} не найдена (или занимает несколько строк)`);
    return match[0];
}

// Элемент-заглушка: ровно то, что нужно логике композера и меню. Дерево детей и классы
// настоящие (className ↔ classList, querySelector по .классу и тегу, contains), стили и
// раскладка — нет: offsetParent === null, если сам элемент или предок скрыт классом hidden.
class FakeEl {
    constructor(tag = 'div') {
        this.tagName = tag.toUpperCase();
        this.classes = new Set();
        this.attrs = new Map();
        this.listeners = new Map();
        this.children = [];
        this.parent = null;
        this.dataset = {};
        this.style = {};
        this.value = '';
        this.textContent = '';
        this.disabled = false;
        this.isConnected = true;
        this.selection = null;
        const el = this;
        this.classList = {
            add: (...c) => c.forEach((x) => el.classes.add(x)),
            remove: (...c) => c.forEach((x) => el.classes.delete(x)),
            contains: (c) => el.classes.has(c),
            toggle: (c, force) => {
                const on = force === undefined ? !el.classes.has(c) : Boolean(force);
                if (on) el.classes.add(c); else el.classes.delete(c);
                return on;
            },
        };
    }
    get className() { return [...this.classes].join(' '); }
    set className(value) { this.classes = new Set(String(value).split(/\s+/).filter(Boolean)); }
    get hidden() { return this.classes.has('hidden'); }
    get offsetParent() {
        for (let el = this; el; el = el.parent) if (el.classes.has('hidden')) return null;
        return this.parent || {};
    }
    setAttribute(name, value) { this.attrs.set(name, String(value)); }
    getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
    removeAttribute(name) { this.attrs.delete(name); }
    hasAttribute(name) { return this.attrs.has(name); }
    set tabIndex(value) { this.attrs.set('tabindex', String(value)); }
    get tabIndex() { return this.attrs.has('tabindex') ? Number(this.attrs.get('tabindex')) : -1; }
    addEventListener(type, fn) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(fn);
    }
    focus() { FakeEl.active = this; }
    setSelectionRange(a, b) { this.selection = [a, b]; }
    appendChild(node) { if (node instanceof FakeEl) node.parent = this; this.children.push(node); return node; }
    append(...nodes) { nodes.forEach((n) => this.appendChild(n)); }
    replaceChildren(...nodes) { this.children = []; nodes.forEach((n) => this.appendChild(n)); }
    contains(node) {
        for (let el = node; el; el = el.parent) if (el === this) return true;
        return false;
    }
    descendants() { return this.children.filter((c) => c instanceof FakeEl).flatMap((c) => [c, ...c.descendants()]); }
    // Селекторы: «.класс», «тег», «тег.класс», через запятую.
    querySelectorAll(selector) {
        const parts = selector.split(',').map((p) => p.trim());
        return this.descendants().filter((el) => parts.some((part) => {
            const m = /^([a-z0-9]*)((?:\.[\w-]+)*)$/i.exec(part);
            if (!m) return false;
            if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
            return m[2].split('.').filter(Boolean).every((c) => el.classes.has(c));
        }));
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    getBoundingClientRect() { return { left: 10, top: 10, right: 210, bottom: 60, width: 200, height: 50 }; }
    // Вызвать подписчиков события; возвращает объект события (e.defaultPrevented видно тесту).
    fire(type, init = {}) {
        const event = { type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {}, ...init };
        for (const fn of this.listeners.get(type) || []) fn(event);
        return event;
    }
}
FakeEl.active = null;

// Таблица elements: любой ключ — свой FakeEl (создаётся при первом обращении).
function fakeElements(preset = {}) {
    const store = new Map(Object.entries(preset));
    return new Proxy({}, {
        get(_t, key) {
            if (typeof key !== 'string') return undefined;
            if (!store.has(key)) store.set(key, new FakeEl());
            return store.get(key);
        },
        set(_t, key, value) { store.set(key, value); return true; },
    });
}

// createClient({ functions: ['startReply', ...], prelude: 'let x = null;', sandbox: { ... } })
//   → { context, run(code), el(name) }
// prelude выполняется до функций (объявления состояния), sandbox — глобальные заглушки.
function createClient({ functions = [], consts = [], prelude = '', sandbox = {}, source = readClientScript() } = {}) {
    const elements = sandbox.elements || fakeElements();
    const context = vm.createContext({
        console,
        setTimeout,
        clearTimeout,
        Promise,
        Map,
        Set,
        Number,
        String,
        Boolean,
        Array,
        Object,
        JSON,
        Math,
        Error,
        ...sandbox,
        elements,
    });
    const code = [prelude, ...consts.map((name) => extractConst(source, name)), ...functions.map((name) => extractFunction(source, name))].join('\n');
    vm.runInContext(code, context, { filename: 'client-under-test.js' });
    return {
        context,
        elements,
        run: (snippet) => vm.runInContext(snippet, context, { filename: 'client-probe.js' }),
    };
}

// Мини-харнесс, как у остальных тестов: test(name, fn) считает ok/FAIL, итог — process.exitCode.
function createHarness() {
    let passed = 0, failed = 0;
    const queue = [];
    function test(name, fn) {
        queue.push({ name, fn });
    }
    // Тесты идут по очереди, в порядке объявления: асинхронные не перемешивают вывод.
    async function done() {
        for (const { name, fn } of queue) {
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
        console.log(`\n${passed} passed, ${failed} failed`);
        if (failed > 0) process.exitCode = 1;
    }
    return { test, done };
}

module.exports = { extractFunction, extractConst, FakeEl, fakeElements, createClient, createHarness };
