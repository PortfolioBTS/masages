'use strict';
// Меню сообщения с клавиатуры (T7.3, п.3 ревью W7 R3): сообщение берёт фокус (tabindex=0,
// role=article), клавиши ContextMenu и Shift+F10 открывают меню и ставят фокус на первый
// пункт, стрелки/Home/End ходят по пунктам, Esc и Tab закрывают меню и возвращают фокус на
// сообщение. Логика — в vm с заглушками DOM (test/client-vm.js); живые клавиши в Chrome —
// test/browser/composer.browser.test.js.
// Запуск: node test/client-menu-keyboard.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');

const { test, done } = createHarness();

function menuWithButtons(...names) {
    const menu = new FakeEl();
    const buttons = names.map((name) => {
        const btn = new FakeEl('button');
        btn.name = name;
        menu.appendChild(btn);
        return btn;
    });
    return { menu, buttons };
}

function makeClient(extra = {}) {
    const elements = fakeElements();
    const document = {
        createElement: (tag) => new FakeEl(tag),
        get activeElement() { return FakeEl.active; },
    };
    const client = createClient({
        functions: ['popupMenuItems', 'onPopupMenuKeydown', 'showMessageMenu', 'hideMessageMenu', 'createMessageElement'],
        prelude: 'let menuMessage = null;',
        sandbox: {
            elements,
            document,
            window: { innerWidth: 1000, innerHeight: 800 },
            hideChatItemMenu() {},
            updateReactionPicker() {},
            isOwnMessage: () => false,
            roomAuthorLabel: () => 'Автор',
            iconText: () => new FakeEl(),
            icon: () => new FakeEl('svg'),
            formatReplyQuote: () => '',
            createAttachmentElement: () => null,
            setMessageText() {},
            renderReactions() {},
            formatMessageTime: () => '12:00',
            formatMessageTimeTitle: () => '',
            renderMessageStatus() {},
            attachLongPress() {},
            ...extra,
        },
    });
    return { ...client, elements, document };
}

const key = (name, init = {}) => ({ key: name, ...init });

test('popupMenuItems: только видимые и включённые кнопки', () => {
    const { menu, buttons } = menuWithButtons('a', 'b', 'c');
    buttons[1].classList.add('hidden');
    buttons[2].disabled = true;
    const c = makeClient();
    c.context.__menu = menu;
    assert.deepStrictEqual(c.run('popupMenuItems(__menu)').map((b) => b.name), ['a']);
});

test('стрелки двигают фокус по кругу; Home и End — в начало и в конец; событие гасится', () => {
    const { menu, buttons } = menuWithButtons('a', 'b', 'c');
    const c = makeClient();
    Object.assign(c.context, { __menu: menu, __hide: () => { throw new Error('меню не должно закрываться'); } });
    const press = (name) => {
        const e = { ...key(name), defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
        c.context.__e = e;
        c.run('onPopupMenuKeydown(__e, __menu, __hide)');
        return e;
    };
    FakeEl.active = buttons[0];
    assert.strictEqual(press('ArrowDown').defaultPrevented, true);
    assert.strictEqual(FakeEl.active, buttons[1]);
    press('ArrowDown'); press('ArrowDown');
    assert.strictEqual(FakeEl.active, buttons[0], 'после последнего — снова первый');
    press('ArrowUp');
    assert.strictEqual(FakeEl.active, buttons[2], 'вверх от первого — последний');
    press('Home');
    assert.strictEqual(FakeEl.active, buttons[0]);
    press('End');
    assert.strictEqual(FakeEl.active, buttons[2]);
    FakeEl.active = null;
    press('ArrowUp');
    assert.strictEqual(FakeEl.active, buttons[2], 'без фокуса в меню стрелка вверх идёт к последнему');
    assert.strictEqual(press('x').defaultPrevented, false, 'чужие клавиши не перехватываются');
});

test('Esc и Tab закрывают меню', () => {
    const { menu } = menuWithButtons('a');
    const c = makeClient();
    let closed = 0;
    Object.assign(c.context, { __menu: menu, __hide: () => { closed++; } });
    for (const name of ['Escape', 'Tab']) {
        c.context.__e = { ...key(name), preventDefault() {} };
        c.run('onPopupMenuKeydown(__e, __menu, __hide)');
    }
    assert.strictEqual(closed, 2);
});

test('сообщение фокусируется с клавиатуры и называется article', () => {
    const c = makeClient();
    c.context.__m = { id: 1, text: 'привет', reactions: [] };
    const el = c.run('createMessageElement(__m, false)');
    assert.strictEqual(el.tabIndex, 0);
    assert.strictEqual(el.getAttribute('role'), 'article');
});

function openFromKeyboard(c, messageEl, init) {
    FakeEl.active = messageEl;
    const event = messageEl.fire('keydown', init);
    return event;
}

test('ContextMenu и Shift+F10 открывают меню, фокус — на первом пункте; обычные клавиши — нет', () => {
    for (const init of [key('ContextMenu'), key('F10', { shiftKey: true })]) {
        const c = makeClient();
        const { menu, buttons } = menuWithButtons('reaction', 'reply');
        c.elements.messageMenu = menu;
        c.context.__m = { id: 1, text: 'привет', reactions: [] };
        const el = c.run('createMessageElement(__m, false)');
        const event = openFromKeyboard(c, el, init);
        assert.strictEqual(event.defaultPrevented, true);
        assert.strictEqual(menu.hidden, false, `меню по ${init.key} не открылось`);
        assert.strictEqual(FakeEl.active, buttons[0], 'фокус на первом пункте');
    }
    const c = makeClient();
    const { menu } = menuWithButtons('reaction');
    menu.classList.add('hidden');
    c.elements.messageMenu = menu;
    c.context.__m = { id: 1, text: 'привет', reactions: [] };
    const el = c.run('createMessageElement(__m, false)');
    for (const init of [key('Enter'), key('F10'), key('a'), key('ArrowDown')]) {
        openFromKeyboard(c, el, init);
        assert.strictEqual(menu.hidden, true, `${init.key} не должен открывать меню`);
    }
});

test('закрытие меню возвращает фокус на сообщение, если фокус был в меню', () => {
    const c = makeClient();
    const { menu, buttons } = menuWithButtons('reaction', 'reply');
    c.elements.messageMenu = menu;
    c.context.__m = { id: 1, text: 'привет', reactions: [] };
    const el = c.run('createMessageElement(__m, false)');
    openFromKeyboard(c, el, key('ContextMenu'));
    assert.strictEqual(FakeEl.active, buttons[0]);
    c.run('hideMessageMenu()');
    assert.strictEqual(menu.hidden, true);
    assert.strictEqual(FakeEl.active, el, 'фокус вернулся на сообщение');
});

test('меню, открытое с клавиатуры, но потерявшее фокус (клик в другое место), фокус не отбирает', () => {
    const c = makeClient();
    const { menu } = menuWithButtons('reaction');
    c.elements.messageMenu = menu;
    c.context.__m = { id: 1, text: 'привет', reactions: [] };
    const el = c.run('createMessageElement(__m, false)');
    openFromKeyboard(c, el, key('ContextMenu'));
    const input = new FakeEl('textarea');
    input.focus();                 // пользователь кликнул в поле ввода
    c.run('hideMessageMenu()');
    assert.strictEqual(FakeEl.active, input);
});

test('меню, открытое мышью (showMessageMenu без keyboard), фокус не двигает и не возвращает', () => {
    const c = makeClient();
    const { menu } = menuWithButtons('reaction');
    c.elements.messageMenu = menu;
    const before = new FakeEl();
    before.focus();
    c.context.__m = { id: 1, text: 'привет', reactions: [] };
    c.run('showMessageMenu(100, 100, __m)');
    assert.strictEqual(menu.hidden, false);
    assert.strictEqual(FakeEl.active, before, 'открытие мышью фокус не трогает');
    c.run('hideMessageMenu()');
    assert.strictEqual(FakeEl.active, before);
});

test('contextmenu сразу после клавиши ContextMenu не открывает меню повторно', () => {
    const c = makeClient();
    const { menu, buttons } = menuWithButtons('reaction');
    c.elements.messageMenu = menu;
    c.context.__m = { id: 1, text: 'привет', reactions: [] };
    const el = c.run('createMessageElement(__m, false)');
    openFromKeyboard(c, el, key('ContextMenu'));
    const second = el.fire('contextmenu', { clientX: 0, clientY: 0 });
    assert.strictEqual(second.defaultPrevented, true);
    assert.strictEqual(FakeEl.active, buttons[0], 'фокус остался на пункте меню');
    // Через некоторое время правый клик мышью снова работает.
    c.run('keyboardMenuAt = 0');
    c.run('hideMessageMenu()');
    el.fire('contextmenu', { clientX: 50, clientY: 60 });
    assert.strictEqual(menu.hidden, false);
});

test('обработчик клавиш навешен на меню сообщения', () => {
    const { readClientScript } = require('./client-script-source');
    const script = readClientScript();
    assert.ok(script.includes("elements.messageMenu.addEventListener('keydown', (e) => onPopupMenuKeydown(e, elements.messageMenu, hideMessageMenu))"));
});

done();
