'use strict';
// Черновик, набранный во время отправки (T7.3, п.6 ревью W7 R3): раньше после успешной
// отправки поле стиралось безусловно, и всё, что человек успел набрать за время ответа
// сервера (при плохой связи — десятки секунд), пропадало. Теперь поле очищается, только
// если в нём всё ещё отправленный текст; ответ — если он тот же.
// Логика sendMessage в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-draft-during-send.test.js

const assert = require('assert');
const { createClient, createHarness, fakeElements } = require('./client-vm');

const { test, done } = createHarness();

function makeClient({ sendResult = true } = {}) {
    const log = { sent: [], cleared: 0, toasts: [] };
    const gate = {};
    gate.promise = new Promise((resolve) => { gate.release = resolve; });
    const elements = fakeElements();
    const client = createClient({
        functions: ['sendMessage', 'clearReply', 'setMessageInputValue'],
        prelude: 'let sending = false; let currentChatId = 1; let currentRoomId = 10; let replyToMessageId = null; let editingMessageId = null;',
        sandbox: {
            elements,
            autoResizeMessageInput() {},
            showToast: (text) => log.toasts.push(text),
            setSending: (value) => { client.run(`sending = ${value}`); },
            sendText: async (text, opts) => {
                log.sent.push({ text, ...opts });
                await gate.promise;
                return sendResult;
            },
        },
    });
    return { ...client, log, gate, elements };
}

test('в поле всё ещё отправленный текст — оно очищается, ответ снимается', async () => {
    const c = makeClient();
    c.elements.messageInput.value = '  привет  ';
    c.run('replyToMessageId = 42');
    const pending = c.run('sendMessage()');
    c.gate.release();
    await pending;
    assert.strictEqual(c.elements.messageInput.value, '');
    assert.strictEqual(c.run('replyToMessageId'), null);
    assert.deepStrictEqual(c.log.sent.map((s) => [s.text, s.replyToId]), [['привет', 42]]);
});

test('за время отправки набран другой текст — черновик не стирается', async () => {
    const c = makeClient();
    c.elements.messageInput.value = 'первое';
    const pending = c.run('sendMessage()');
    c.elements.messageInput.value = 'второе, уже набираю';   // человек печатает, пока ждём ответ сервера
    c.gate.release();
    await pending;
    assert.strictEqual(c.elements.messageInput.value, 'второе, уже набираю');
});

test('человек дописал к отправленному тексту — тоже не стирается', async () => {
    const c = makeClient();
    c.elements.messageInput.value = 'первое';
    const pending = c.run('sendMessage()');
    c.elements.messageInput.value = 'первое и ещё';
    c.gate.release();
    await pending;
    assert.strictEqual(c.elements.messageInput.value, 'первое и ещё');
});

test('за время отправки выбран другой ответ — выбор остаётся; тот же — снимается', async () => {
    const other = makeClient();
    other.elements.messageInput.value = 'первое';
    other.run('replyToMessageId = 1');
    const pendingOther = other.run('sendMessage()');
    other.run('replyToMessageId = 2');            // «Ответить» на другое сообщение
    other.gate.release();
    await pendingOther;
    assert.strictEqual(other.run('replyToMessageId'), 2, 'новый выбор ответа стёрт отправкой старого');
    assert.strictEqual(other.log.sent[0].replyToId, 1, 'ушло с тем ответом, что был при нажатии');
});

test('отправка не удалась — поле и ответ остаются как были', async () => {
    const c = makeClient({ sendResult: false });
    c.elements.messageInput.value = 'не дошло';
    c.run('replyToMessageId = 7');
    const pending = c.run('sendMessage()');
    c.gate.release();
    await pending;
    assert.strictEqual(c.elements.messageInput.value, 'не дошло');
    assert.strictEqual(c.run('replyToMessageId'), 7);
});

test('пока идёт отправка, повторный вызов ничего не делает', async () => {
    const c = makeClient();
    c.elements.messageInput.value = 'один раз';
    const first = c.run('sendMessage()');
    await c.run('sendMessage()');
    c.gate.release();
    await first;
    assert.strictEqual(c.log.sent.length, 1);
});

done();
