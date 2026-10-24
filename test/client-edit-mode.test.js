'use strict';
// Режим правки сообщения в поле ввода (T7.3, п.1 ревью W7 R3): у правки есть плашка
// «Редактирование» с отменой, правка сбрасывается очисткой поля и началом ответа,
// «правка + ответ» не превращается тихо в одну правку.
// Логика клиента запускается в vm с заглушками DOM (test/client-vm.js).
// Запуск: node test/client-edit-mode.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createClient, createHarness, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

const FUNCTIONS = ['messageSummary', 'clearReply', 'startReply', 'startEditing', 'finishEditing', 'cancelEditing', 'setMessageInputValue', 'setupComposerListeners'];

function makeClient() {
    const elements = fakeElements();
    const client = createClient({
        functions: FUNCTIONS,
        prelude: 'let replyToMessageId = null; let editingMessageId = null; let uploadQueue = null;',
        sandbox: {
            elements,
            showToast() {},
            sendMessage() {},
            onFilesChosen() {},
            sendChosenFiles() {},
            cancelUploadQueue() {},
            setupDragAndDrop() {},
            autoResizeMessageInput() {},
            window: { addEventListener() {} },
            onBotSuggestionClick() {},
        },
    });
    client.run('setupComposerListeners()');
    return client;
}

const MSG = { id: 7, text: 'старый текст' };
const OTHER = { id: 9, text: 'чужая реплика' };

test('в разметке есть плашка правки с кнопкой отмены, как у ответа', () => {
    assert.match(html, /<div id="edit-preview" class="reply-preview edit-preview hidden">/);
    assert.match(html, /<span id="edit-preview-text"><\/span>/);
    assert.match(html, /<button id="cancel-edit-btn"[^>]*aria-label="Отменить правку"/);
    assert.ok(html.indexOf('id="edit-preview"') > html.indexOf('id="reply-preview"'), 'плашка правки стоит рядом с плашкой ответа');
    assert.ok(html.indexOf('id="edit-preview"') < html.indexOf('id="message-input"'), 'плашка правки стоит над полем ввода');
});

test('«Изменить»: плашка видна, в поле текст сообщения, режим включён', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    assert.strictEqual(c.run('editingMessageId'), 7);
    assert.strictEqual(c.elements.editPreview.hidden, false);
    assert.match(c.elements.editPreviewText.textContent, /^Редактирование: старый текст$/);
    assert.strictEqual(c.elements.messageInput.value, 'старый текст');
    assert.strictEqual(c.elements.messageInput.getAttribute('aria-describedby'), 'edit-preview-text');
});

test('отмена правки (крестик): плашка скрыта, режим сброшен, поле очищено', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.elements.cancelEditBtn.fire('click');
    assert.strictEqual(c.run('editingMessageId'), null);
    assert.strictEqual(c.elements.editPreview.hidden, true);
    assert.strictEqual(c.elements.messageInput.value, '');
    assert.strictEqual(c.elements.messageInput.getAttribute('aria-describedby'), null);
});

test('Esc в поле отменяет правку', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.elements.messageInput.fire('keydown', { key: 'Escape' });
    assert.strictEqual(c.run('editingMessageId'), null);
    assert.strictEqual(c.elements.editPreview.hidden, true);
    assert.strictEqual(c.elements.messageInput.value, '');
});

test('очистка поля вручную сбрасывает правку: следующий текст уйдёт новым сообщением', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.elements.messageInput.value = '';
    c.elements.messageInput.fire('input');
    assert.strictEqual(c.run('editingMessageId'), null, 'режим правки остался после очистки поля');
    assert.strictEqual(c.elements.editPreview.hidden, true);
    // Поле, где остались только пробелы, — тоже пустое.
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.elements.messageInput.value = '   ';
    c.elements.messageInput.fire('input');
    assert.strictEqual(c.run('editingMessageId'), null);
});

test('правка текста (поле не пустое) режим не сбрасывает', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.elements.messageInput.value = 'новый текст';
    c.elements.messageInput.fire('input');
    assert.strictEqual(c.run('editingMessageId'), 7);
    assert.strictEqual(c.elements.editPreview.hidden, false);
});

test('«Ответить» во время правки отменяет правку: уходит ответ, а не правка', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.run('startReply(' + JSON.stringify(OTHER) + ')');
    assert.strictEqual(c.run('editingMessageId'), null, 'правка пережила начало ответа');
    assert.strictEqual(c.elements.editPreview.hidden, true);
    assert.strictEqual(c.elements.messageInput.value, '', 'текст старого сообщения остался в поле ответа');
    assert.strictEqual(c.run('replyToMessageId'), 9);
    assert.strictEqual(c.elements.replyPreview.hidden, false);
    assert.strictEqual(c.elements.replyPreviewText.textContent, 'чужая реплика');
});

test('«Изменить» во время ответа отменяет ответ: плашки не висят вместе', () => {
    const c = makeClient();
    c.run('startReply(' + JSON.stringify(OTHER) + ')');
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    assert.strictEqual(c.run('replyToMessageId'), null);
    assert.strictEqual(c.elements.replyPreview.hidden, true);
    assert.strictEqual(c.run('editingMessageId'), 7);
    assert.strictEqual(c.elements.editPreview.hidden, false);
});

test('finishEditing (правка сохранена): плашка скрыта, поле не трогается', () => {
    const c = makeClient();
    c.run('startEditing(' + JSON.stringify(MSG) + ')');
    c.elements.messageInput.value = 'черновик следующего сообщения';
    c.run('finishEditing()');
    assert.strictEqual(c.run('editingMessageId'), null);
    assert.strictEqual(c.elements.editPreview.hidden, true);
    assert.strictEqual(c.elements.messageInput.value, 'черновик следующего сообщения');
});

test('код: сохранение правки и сброс вида чата прячут плашку (finishEditing), а не только обнуляют id', () => {
    const script = readClientScript();
    const assignments = script.match(/^.*\beditingMessageId = [^;]*;.*$/gm) || [];
    // Присваивания допустимы только в объявлении состояния, startEditing (= message.id) и finishEditing (= null).
    for (const line of assignments) {
        assert.match(line, /let editingMessageId = null|editingMessageId = message\.id|editingMessageId = null/, `неожиданное присваивание: ${line}`);
    }
    const resets = assignments.filter((line) => /editingMessageId = null/.test(line) && !/let /.test(line));
    assert.strictEqual(resets.length, 1, 'сбрасывать editingMessageId напрямую можно только в finishEditing: ' + resets.join(' | '));
});

done();
