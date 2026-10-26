'use strict';
// Двойной клик по кнопке с запросом (T7.3, п.5 ревью W7 R3): «Создать группу» дважды
// создавала две группы. Теперь кнопка занята (disabled + aria-busy) на время запроса —
// это общий withBusyButton; им же пользуются «Новый код» и «Отключить приглашение».
// Логика клиента в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-busy-button.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();
const plain = (value) => JSON.parse(JSON.stringify(value));

function busyClient(sandbox = {}) {
    return createClient({
        functions: ['withBusyButton', 'setIconLabel'],
        sandbox: {
            document: { createElement: (tag) => new FakeEl(tag) },
            icon: (name, options = {}) => Object.assign(new FakeEl('svg'), { iconName: name, className: options.className || '' }),
            ...sandbox,
        },
    });
}

// Внешний «ручной» промис: запрос, завершением которого управляет тест.
function deferred() {
    let resolve;
    const promise = new Promise((r) => { resolve = r; });
    return { promise, resolve };
}

test('withBusyButton: на время задачи кнопка disabled + aria-busy, потом возвращается как была', async () => {
    const c = busyClient();
    const btn = new FakeEl('button');
    const label = new FakeEl('span');
    btn.appendChild(label);
    const gate = deferred();
    c.context.__btn = btn;
    c.context.__task = () => gate.promise;
    const run = c.run('withBusyButton(__btn, __task, "Создаём…")');
    assert.strictEqual(btn.disabled, true);
    assert.strictEqual(btn.getAttribute('aria-busy'), 'true');
    assert.strictEqual(btn.children[0].iconName, 'loader', 'на время запроса — значок загрузки');
    gate.resolve('готово');
    assert.strictEqual(await run, 'готово', 'результат задачи возвращается');
    assert.strictEqual(btn.disabled, false);
    assert.strictEqual(btn.getAttribute('aria-busy'), null);
    assert.deepStrictEqual(btn.children, [label], 'прежнее содержимое кнопки на месте');
});

test('withBusyButton: второй вызов, пока кнопка занята, задачу не запускает', async () => {
    const c = busyClient();
    const btn = new FakeEl('button');
    const gate = deferred();
    let started = 0;
    c.context.__btn = btn;
    c.context.__task = () => { started++; return gate.promise; };
    const first = c.run('withBusyButton(__btn, __task)');
    const second = await c.run('withBusyButton(__btn, __task)');
    assert.strictEqual(second, undefined);
    assert.strictEqual(started, 1);
    gate.resolve();
    await first;
    assert.strictEqual(btn.disabled, false);
});

test('withBusyButton: ошибка в задаче тоже снимает «занято» и пробрасывается', async () => {
    const c = busyClient();
    const btn = new FakeEl('button');
    c.context.__btn = btn;
    c.context.__task = async () => { throw new Error('сбой'); };
    await assert.rejects(c.run('withBusyButton(__btn, __task)'), /сбой/);
    assert.strictEqual(btn.disabled, false);
    assert.strictEqual(btn.getAttribute('aria-busy'), null);
});

function createChatClient(apiImpl) {
    const calls = [];
    const input = new FakeEl('input');
    input.value = '  Моя группа ';
    const elements = fakeElements();
    const client = createClient({
        functions: ['createChat', 'withBusyButton', 'setIconLabel'],
        sandbox: {
            elements,
            document: {
                getElementById: (id) => (id === 'new-chat-name' ? input : new FakeEl()),
                createElement: (tag) => new FakeEl(tag),
            },
            icon: (name) => Object.assign(new FakeEl('svg'), { iconName: name }),
            api: (url, init) => { calls.push({ url, init }); return apiImpl(); },
            showToast() {},
            getReadyE2eeClient: async () => null,
            closeModal() {},
            loadChats() {},
            openChat() {},
            currentUser: { username: 'u' },
        },
    });
    return { ...client, calls, input };
}

test('«Создать группу»: двойной клик и Enter во время запроса создают одну группу', async () => {
    const gate = deferred();
    const c = createChatClient(() => gate.promise);
    const first = c.run('createChat()');
    const second = c.run('createChat()');   // второй клик / Enter в поле названия
    const third = c.run('createChat()');
    assert.strictEqual(c.calls.length, 1, 'запрос на создание ушёл больше одного раза');
    assert.deepStrictEqual(plain(JSON.parse(c.calls[0].init.body)), { name: 'Моя группа' });
    assert.strictEqual(c.elements.createChatBtn.disabled, true);
    assert.strictEqual(c.elements.createChatBtn.getAttribute('aria-busy'), 'true');
    gate.resolve({ success: true, chat: { id: 1, room_id: null, name: 'Моя группа' } });
    await Promise.all([first, second, third]);
    assert.strictEqual(c.calls.length, 1);
    assert.strictEqual(c.elements.createChatBtn.disabled, false, 'кнопка снова доступна');
    assert.strictEqual(c.input.value, '', 'поле названия очищено после успеха');
});

test('«Создать группу»: после отказа сервера кнопка свободна, название остаётся для повтора', async () => {
    const c = createChatClient(async () => ({ success: false, message: 'Слишком много групп' }));
    await c.run('createChat()');
    assert.strictEqual(c.elements.createChatBtn.disabled, false);
    assert.strictEqual(c.input.value, '  Моя группа ');
    await c.run('createChat()');
    assert.strictEqual(c.calls.length, 2, 'повторная попытка после отказа возможна');
});

test('«Создать группу»: пустое название запрос не отправляет и кнопку не занимает', async () => {
    const c = createChatClient(async () => ({ success: true }));
    c.input.value = '   ';
    await c.run('createChat()');
    assert.strictEqual(c.calls.length, 0);
    assert.strictEqual(c.elements.createChatBtn.disabled, false);
});

test('код: «Новый код» и «Отключить приглашение» идут через withBusyButton, а не через ручной disabled', () => {
    const script = readClientScript();
    assert.match(script, /withBusyButton\(elements\.rotateInviteBtn,/);
    assert.match(script, /withBusyButton\(elements\.disableInviteBtn,/);
    assert.doesNotMatch(script, /rotateInviteBtn\.disabled = (true|false)/);
    assert.doesNotMatch(script, /disableInviteBtn\.disabled = (true|false);\s*\n\s*const data/);
});

done();
