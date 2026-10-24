'use strict';
// Многострочное поле сообщения (T7.3, п.10 ревью W7 R3): вместо <input type="text"> —
// <textarea rows="1"> с автовысотой до шести строк; Enter отправляет, Shift+Enter переносит
// строку; перенос строк при вставке больше не пропадает; всё, что клиент делает с полем
// (value, focus, setSelectionRange, placeholder, disabled), есть и у textarea.
// Логика в vm с заглушками (test/client-vm.js); живой набор и вставка — test/browser.
// Запуск: node test/client-message-textarea.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');
const { readClientCss } = require('./client-css');

const { test, done } = createHarness();
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
const script = readClientScript();

test('в разметке поле сообщения — textarea на одну строку с лимитом, подписью и enterkeyhint=send', () => {
    const tag = /<textarea id="message-input"[^>]*>/.exec(html);
    assert.ok(tag, 'нет <textarea id="message-input">');
    for (const attr of ['rows="1"', 'maxlength="4000"', 'aria-label="Текст сообщения"', 'enterkeyhint="send"']) {
        assert.ok(tag[0].includes(attr), `у поля нет ${attr}`);
    }
    assert.ok(!/<input[^>]*id="message-input"/.test(html), 'осталось и однострочное поле с тем же id');
});

test('CSS: поле растёт до шести строк (140 px = 6 × 20 + отступы + рамка), без ручного изменения размера', () => {
    const css = readClientCss();
    const rules = [...css.matchAll(/\.input-wrapper textarea \{([^}]*)\}/g)].map((m) => m[1]).join('\n');
    assert.ok(rules, 'нет правила для поля сообщения');
    assert.match(rules, /max-height:\s*140px/);
    assert.match(rules, /line-height:\s*20px/);
    assert.match(rules, /resize:\s*none/);
});

// ---- клавиши ----

function composerClient() {
    const log = { sent: 0 };
    const elements = fakeElements();
    const client = createClient({
        functions: ['setupComposerListeners', 'setMessageInputValue', 'autoResizeMessageInput'],
        prelude: 'let editingMessageId = null; let replyToMessageId = null; let uploadQueue = null;',
        sandbox: {
            elements,
            window: { addEventListener() {} },
            getComputedStyle: () => ({ maxHeight: '140px' }),
            sendMessage: () => { log.sent++; },
            cancelEditing() {},
            clearReply() {},
            showToast() {},
            onFilesChosen() {},
            sendChosenFiles() {},
            cancelUploadQueue() {},
            setupDragAndDrop() {},
            onBotSuggestionClick() {},
        },
    });
    client.run('setupComposerListeners()');
    return { ...client, log, elements };
}

test('Enter отправляет, Shift+Enter переносит строку, Enter при вводе через IME не отправляет', () => {
    const c = composerClient();
    const input = c.elements.messageInput;
    const enter = input.fire('keydown', { key: 'Enter', shiftKey: false, isComposing: false });
    assert.strictEqual(enter.defaultPrevented, true);
    assert.strictEqual(c.log.sent, 1);
    const shiftEnter = input.fire('keydown', { key: 'Enter', shiftKey: true, isComposing: false });
    assert.strictEqual(shiftEnter.defaultPrevented, false, 'Shift+Enter должен вставить перенос браузером');
    assert.strictEqual(c.log.sent, 1);
    const composing = input.fire('keydown', { key: 'Enter', shiftKey: false, isComposing: true });
    assert.strictEqual(composing.defaultPrevented, false);
    assert.strictEqual(c.log.sent, 1);
});

// ---- автовысота ----

function sizedInput({ scrollHeight, offsetHeight = 40, clientHeight = 38, visible = true }) {
    const input = new FakeEl('textarea');
    input.scrollHeight = scrollHeight;
    input.offsetHeight = offsetHeight;
    input.clientHeight = clientHeight;
    if (!visible) input.classList.add('hidden');
    return input;
}

function resizeWith(input, maxHeight = '140px') {
    const elements = fakeElements({ messageInput: input });
    const c = createClient({
        functions: ['autoResizeMessageInput', 'setMessageInputValue'],
        sandbox: { elements, getComputedStyle: () => ({ maxHeight }) },
    });
    return c;
}

test('автовысота: короткий текст — по содержимому, длинный — не выше шести строк и с прокруткой', () => {
    const short = sizedInput({ scrollHeight: 58 });            // две строки
    resizeWith(short).run('autoResizeMessageInput()');
    assert.strictEqual(short.style.height, '60px', 'scrollHeight + рамка');
    assert.strictEqual(short.style.overflowY, 'hidden');
    const long = sizedInput({ scrollHeight: 400 });
    resizeWith(long).run('autoResizeMessageInput()');
    assert.strictEqual(long.style.height, '140px');
    assert.strictEqual(long.style.overflowY, 'auto');
});

test('автовысота: после очистки поля высота снова одна строка (замер идёт от auto)', () => {
    const input = sizedInput({ scrollHeight: 400 });
    const c = resizeWith(input);
    c.run('autoResizeMessageInput()');
    assert.strictEqual(input.style.height, '140px');
    input.scrollHeight = 20 + 18;                               // пустое поле: одна строка + отступы
    c.context.__input = input;
    c.run("setMessageInputValue('')");
    assert.strictEqual(input.value, '');
    assert.strictEqual(input.style.height, '40px');
});

test('автовысота: скрытое поле (чат не открыт) высоту не фиксирует', () => {
    const input = sizedInput({ scrollHeight: 400, visible: false });
    resizeWith(input).run('autoResizeMessageInput()');
    assert.strictEqual(input.style.height, '');
});

test('ввод в поле и изменение размера окна пересчитывают высоту', () => {
    const resized = [];
    const elements = fakeElements();
    const windowListeners = {};
    const c = createClient({
        functions: ['setupComposerListeners'],
        prelude: 'let editingMessageId = null; let replyToMessageId = null; let uploadQueue = null;',
        sandbox: {
            elements,
            window: { addEventListener: (type, fn) => { windowListeners[type] = fn; } },
            autoResizeMessageInput: () => resized.push('resize'),
            cancelEditing() {}, clearReply() {}, sendMessage() {}, showToast() {}, onFilesChosen() {},
            sendChosenFiles() {}, cancelUploadQueue() {}, setupDragAndDrop() {}, onBotSuggestionClick() {},
        },
    });
    c.run('setupComposerListeners()');
    elements.messageInput.fire('input');
    assert.deepStrictEqual(resized, ['resize']);
    assert.strictEqual(windowListeners.resize.name === '' || typeof windowListeners.resize === 'function', true);
    windowListeners.resize();
    assert.strictEqual(resized.length, 2);
});

test('код: значение поля меняется только через setMessageInputValue (иначе высота застрянет)', () => {
    const writes = script.match(/messageInput\.value = [^;]*;/g) || [];
    assert.deepStrictEqual(writes, ['messageInput.value = text;'], 'прямые присваивания value вне setMessageInputValue: ' + writes.join(' | '));
});

done();
