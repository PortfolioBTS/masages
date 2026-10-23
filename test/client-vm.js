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

// Элемент-заглушка: ровно то, что нужно логике композера и меню.
class FakeEl {
    constructor(tag = 'div') {
        this.tagName = tag.toUpperCase();
        this.classes = new Set();
        this.attrs = new Map();
        this.listeners = new Map();
        this.children = [];
        this.dataset = {};
        this.style = {};
        this.value = '';
        this.textContent = '';
        this.disabled = false;
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
    get hidden() { return this.classes.has('hidden'); }
    setAttribute(name, value) { this.attrs.set(name, String(value)); }
    getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
    removeAttribute(name) { this.attrs.delete(name); }
    hasAttribute(name) { return this.attrs.has(name); }
    addEventListener(type, fn) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(fn);
    }
    focus() { FakeEl.active = this; }
    setSelectionRange(a, b) { this.selection = [a, b]; }
    append(...nodes) { this.children.push(...nodes); }
    appendChild(node) { this.children.push(node); return node; }
    replaceChildren(...nodes) { this.children = nodes; }
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
function createClient({ functions = [], prelude = '', sandbox = {}, source = readClientScript() } = {}) {
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
    const code = [prelude, ...functions.map((name) => extractFunction(source, name))].join('\n');
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

module.exports = { extractFunction, FakeEl, fakeElements, createClient, createHarness };
