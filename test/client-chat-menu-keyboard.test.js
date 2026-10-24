'use strict';
// Контекстное меню строки чата с клавиатуры (T7.3, п.9 ревью W7 R3): после Escape фокус
// уходил на body, стрелок не было. Теперь Esc и Tab закрывают меню и возвращают фокус на
// строку чата, стрелки/Home/End ходят по пунктам (общий onPopupMenuKeydown с меню сообщения).
// Логика в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-chat-menu-keyboard.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();

function makeClient() {
    const elements = fakeElements();
    const menu = elements.chatItemMenu;
    menu.classList.add('hidden');
    for (const name of ['ctxPinBtn', 'ctxMuteBtn', 'ctxArchiveBtn']) {
        const btn = new FakeEl('button');
        btn.id = name;
        elements[name] = btn;
        menu.appendChild(btn);
    }
    const list = [];
    elements.chatsList.querySelectorAll = () => list;
    const document = { get activeElement() { return FakeEl.active; } };
    const client = createClient({
        functions: ['popupMenuItems', 'onPopupMenuKeydown', 'showChatItemMenu', 'hideChatItemMenu', 'findChatItem', 'onChatItemMenuAction'],
        prelude: 'let chatItemMenuChat = null; let chatItemMenuReturnFocus = null;',
        sandbox: {
            elements,
            document,
            window: { innerWidth: 1000, innerHeight: 800 },
            hideMessageMenu() {},
            setIconLabel() {},
            toggleChatPref: (id, key) => { client.toggled.push([id, key]); },
        },
    });
    client.toggled = [];
    // Проводка из setupChatMenuListeners (что она есть в клиенте, проверяет последний тест).
    client.run("elements.chatItemMenu.addEventListener('keydown', (e) => onPopupMenuKeydown(e, elements.chatItemMenu, hideChatItemMenu))");
    // Строки чата: findChatItem сравнивает dataset.roomId/dataset.id.
    const row = (id, roomId) => {
        const el = new FakeEl();
        el.dataset.id = String(id);
        el.dataset.roomId = roomId == null ? '' : String(roomId);
        list.push(el);
        return el;
    };
    return { ...client, elements, menu, row, list };
}

const CHAT = { id: 5, room_id: 50, pinned: false, muted: false, archived: false };

test('меню открывается с фокусом на первом пункте; Esc закрывает и возвращает фокус на строку чата', () => {
    const c = makeClient();
    const row = c.row(5, 50);
    row.focus();
    c.context.__chat = CHAT;
    c.context.__row = row;
    c.run('showChatItemMenu(10, 10, __chat, __row)');
    assert.strictEqual(c.menu.hidden, false);
    assert.strictEqual(FakeEl.active, c.elements.ctxPinBtn);
    const esc = c.menu.fire('keydown', { key: 'Escape' });
    assert.strictEqual(esc.defaultPrevented, true);
    assert.strictEqual(c.menu.hidden, true);
    assert.strictEqual(FakeEl.active, row, 'после Escape фокус не должен уходить на body');
});

test('стрелки, Home и End двигают фокус по пунктам', () => {
    const c = makeClient();
    const row = c.row(5, 50);
    c.context.__chat = CHAT;
    c.context.__row = row;
    c.run('showChatItemMenu(10, 10, __chat, __row)');
    // Слушатель клавиш навешивает setupChatMenuListeners; здесь вызываем тот же обработчик напрямую.
    const press = (key) => {
        c.context.__e = { key, preventDefault() {} };
        c.context.__menu = c.menu;
        c.run('onPopupMenuKeydown(__e, __menu, hideChatItemMenu)');
    };
    press('ArrowDown');
    assert.strictEqual(FakeEl.active, c.elements.ctxMuteBtn);
    press('ArrowDown');
    assert.strictEqual(FakeEl.active, c.elements.ctxArchiveBtn);
    press('ArrowDown');
    assert.strictEqual(FakeEl.active, c.elements.ctxPinBtn, 'по кругу');
    press('ArrowUp');
    assert.strictEqual(FakeEl.active, c.elements.ctxArchiveBtn);
    press('Home');
    assert.strictEqual(FakeEl.active, c.elements.ctxPinBtn);
    press('End');
    assert.strictEqual(FakeEl.active, c.elements.ctxArchiveBtn);
    press('Tab');
    assert.strictEqual(c.menu.hidden, true, 'Tab закрывает меню');
    assert.strictEqual(FakeEl.active, row);
});

test('выбор пункта закрывает меню, возвращает фокус и применяет настройку', () => {
    const c = makeClient();
    const row = c.row(5, 50);
    c.context.__chat = CHAT;
    c.context.__row = row;
    c.run('showChatItemMenu(10, 10, __chat, __row)');
    c.run("onChatItemMenuAction('muted')");
    assert.strictEqual(c.menu.hidden, true);
    assert.deepStrictEqual(c.toggled, [[5, 'muted']]);
    assert.strictEqual(FakeEl.active, row);
});

test('список чатов перерисовался, пока меню было открыто: фокус возвращается на новую строку того же чата', () => {
    const c = makeClient();
    const old = c.row(5, 50);
    c.context.__chat = CHAT;
    c.context.__row = old;
    c.run('showChatItemMenu(10, 10, __chat, __row)');
    old.isConnected = false;                       // строку пересоздали
    c.list.splice(0, c.list.length);
    const fresh = c.row(5, 50);
    c.run('hideChatItemMenu()');
    assert.strictEqual(FakeEl.active, fresh);
});

test('клик в другое место: меню закрывается, но фокус не отбирается', () => {
    const c = makeClient();
    const row = c.row(5, 50);
    c.context.__chat = CHAT;
    c.context.__row = row;
    c.run('showChatItemMenu(10, 10, __chat, __row)');
    const input = new FakeEl('textarea');
    input.focus();
    c.run('hideChatItemMenu()');
    assert.strictEqual(c.menu.hidden, true);
    assert.strictEqual(FakeEl.active, input);
});

test('код: строки чата передают себя в showChatItemMenu, а меню слушает клавиши', () => {
    const script = readClientScript();
    assert.ok(script.includes('showChatItemMenu(rect.left + 24, rect.bottom - 8, meta, div)'));
    assert.ok(script.includes('showChatItemMenu(e.clientX, e.clientY, meta, div)'));
    assert.ok(script.includes("elements.chatItemMenu.addEventListener('keydown', (e) => onPopupMenuKeydown(e, elements.chatItemMenu, hideChatItemMenu))"));
});

done();
