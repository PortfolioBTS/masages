'use strict';
// Собственное окно подтверждения вместо window.confirm и выход из группы (T7.3, п.7 ревью
// W7 R3): раньше «Отмена» во втором confirm всё равно выводила из группы, вопрос про
// сообщения задавался и без сообщений, последнему участнику не говорили, что группа
// удалится, а при отключённых диалогах confirm() молча давал false.
// Логика клиента в vm с заглушками (test/client-vm.js); живое окно — test/browser.
// Запуск: node test/client-confirm-dialog.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
const script = readClientScript();
const plain = (value) => JSON.parse(JSON.stringify(value));

// ---- разметка и отсутствие родных диалогов ----

test('в разметке есть alertdialog подтверждения: подписан, описан, стоит после остальных окон', () => {
    assert.match(html, /<div id="confirm-modal" class="modal hidden" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-body">/);
    for (const id of ['confirm-title', 'confirm-body', 'confirm-actions', 'confirm-close-btn']) assert.ok(html.includes(`id="${id}"`), id);
    const lastModal = html.lastIndexOf('class="modal hidden"');
    assert.strictEqual(lastModal, html.indexOf('<div id="confirm-modal" class="modal hidden"') + '<div id="confirm-modal" '.length,
        'окно подтверждения должно быть последним .modal в разметке: onModalKeydown считает верхним последнее открытое');
    assert.ok(html.indexOf('id="confirm-modal"') < html.indexOf('id="overlay"'));
    // Крестик закрывает только это окно, а не все: у него нет класса close-modal.
    assert.doesNotMatch(html.slice(html.indexOf('id="confirm-modal"'), html.indexOf('id="overlay"')), /close-modal/);
});

test('window.confirm в клиенте не вызывается нигде', () => {
    const { clientScriptFiles } = require('./client-script-source');
    const found = [];
    for (const file of clientScriptFiles()) {
        const text = fs.readFileSync(path.join(__dirname, '..', 'public', ...file.split('/')), 'utf8');
        text.split('\n').forEach((line, i) => {
            if (/^\s*\/\//.test(line)) return;                      // комментарии не в счёт
            if (/(^|[^\w.])confirm\(/.test(line)) found.push(`${file}:${i + 1}`);
        });
    }
    assert.deepStrictEqual(found, [], 'родной confirm() при отключённых диалогах молча даёт false: нужен confirmAction/confirmDialog');
});

test('вопросы про ключи участников идут через окно и сохраняют смысл: «принять ключ» — подтверждённым остаётся только прежде подтверждённый', () => {
    const members = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', '11-key-log-members.js'), 'utf8');
    const accept = members.slice(members.indexOf('async function acceptIdentityChange'), members.indexOf('// Подтверждение участника вручную'));
    assert.match(accept, /await confirmAction\(/);
    assert.match(accept, /Участник останется подтверждённым в группах, где вы его уже подтверждали; в группах, где он был не подтверждён, он таким и останется\./);
    assert.match(accept, /Принять новый ключ\?/);
    for (const name of ['overrideLogMismatch', 'trustUnconfirmedMember', 'vouchForMember']) {
        const body = members.slice(members.indexOf(`async function ${name}`), members.indexOf(`async function ${name}`) + 600);
        assert.match(body, /await confirmAction\(/, name);
    }
});

// ---- окно подтверждения в vm ----

function dialogClient() {
    const modals = [];
    const elements = fakeElements();
    elements.confirmModal.classList.add('hidden');
    elements.confirmModal.appendChild(elements.confirmActions);
    modals.push(elements.confirmModal);
    const document = {
        createElement: (tag) => new FakeEl(tag),
        querySelector: () => modals.find((m) => !m.hidden) || null,
        querySelectorAll: () => modals.filter((m) => !m.hidden),
        get activeElement() { return FakeEl.active; },
    };
    const client = createClient({
        functions: ['confirmDialog', 'onConfirmClosed', 'confirmAction', 'openModal', 'closeModal', 'closeAllModals', 'isFocusable', 'initialFocusTarget'],
        prelude: 'let modalReturnFocus = null; let confirmResolve = null; let confirmChoice = null; let confirmReturnFocus = null;',
        sandbox: { elements, document },
    });
    return { ...client, modals, elements };
}

test('confirmDialog: кнопки с подписями, абзацы текстом, фокус на «Отмене»', async () => {
    const c = dialogClient();
    c.context.__spec = {
        title: 'Выйти из группы?',
        paragraphs: ['Первый <b>абзац</b>', 'Второй'],
        actions: [{ id: 'leave-keep', label: 'Выйти и оставить сообщения', style: 'secondary' }, { id: 'leave-delete', label: 'Выйти и удалить сообщения', style: 'danger' }],
    };
    const trigger = new FakeEl('button');
    trigger.focus();
    const pending = c.run('confirmDialog(__spec)');
    assert.strictEqual(c.elements.confirmModal.hidden, false);
    assert.strictEqual(c.elements.confirmTitle.textContent, 'Выйти из группы?');
    assert.deepStrictEqual(c.elements.confirmBody.children.map((p) => p.textContent), ['Первый <b>абзац</b>', 'Второй'], 'текст не разбирается как HTML');
    const buttons = c.elements.confirmActions.children;
    assert.deepStrictEqual(buttons.map((b) => b.textContent), ['Отмена', 'Выйти и оставить сообщения', 'Выйти и удалить сообщения']);
    assert.ok(buttons[2].className.includes('btn-danger') && buttons[1].className.includes('btn-secondary'));
    assert.strictEqual(FakeEl.active, buttons[0], 'фокус сначала на «Отмене»');
    buttons[1].fire('click');
    assert.strictEqual(await pending, 'leave-keep');
    assert.strictEqual(c.elements.confirmModal.hidden, true);
    assert.strictEqual(FakeEl.active, trigger, 'фокус вернулся туда, откуда открыли');
});

test('«Отмена», крестик, Escape (closeModal) и закрытие всех окон дают null — обещание не повисает', async () => {
    for (const how of ['cancel', 'closeModal', 'closeAllModals']) {
        const c = dialogClient();
        c.context.__spec = { title: 'T', paragraphs: ['x'], actions: [{ id: 'ok', label: 'Да' }] };
        const pending = c.run('confirmDialog(__spec)');
        if (how === 'cancel') c.elements.confirmActions.children[0].fire('click');
        else if (how === 'closeModal') c.run('closeModal(elements.confirmModal)');
        else c.run('closeAllModals()');
        assert.strictEqual(await pending, null, how);
    }
});

test('второй вопрос поверх первого отменяет первый', async () => {
    const c = dialogClient();
    c.context.__spec = { title: 'T', paragraphs: ['x'], actions: [{ id: 'ok', label: 'Да' }] };
    const first = c.run('confirmDialog(__spec)');
    const second = c.run('confirmDialog(__spec)');
    assert.strictEqual(await first, null);
    c.elements.confirmActions.children[1].fire('click');
    assert.strictEqual(await second, 'ok');
});

test('confirmAction: true только по кнопке подтверждения; абзацы делятся по пустой строке', async () => {
    const c = dialogClient();
    const yes = c.run('confirmAction("Один.\\n\\nДва.", { title: "Заголовок", confirmLabel: "Да, продолжить", danger: true })');
    assert.deepStrictEqual(c.elements.confirmBody.children.map((p) => p.textContent), ['Один.', 'Два.']);
    assert.strictEqual(c.elements.confirmActions.children[1].textContent, 'Да, продолжить');
    assert.ok(c.elements.confirmActions.children[1].className.includes('btn-danger'));
    c.elements.confirmActions.children[1].fire('click');
    assert.strictEqual(await yes, true);
    const no = c.run('confirmAction("Текст")');
    c.elements.confirmActions.children[0].fire('click');
    assert.strictEqual(await no, false);
});

// ---- выход из группы ----

const fn = (c, call) => plain(c.run(call));

test('leaveChatDialog: чат с ботом — одно действие «Удалить чат»', () => {
    const c = createClient({ functions: ['leaveChatDialog'] });
    const d = fn(c, 'leaveChatDialog({ isRoom: false })');
    assert.strictEqual(d.title, 'Удалить чат?');
    assert.deepStrictEqual(d.actions.map((a) => a.id), ['delete']);
});

test('leaveChatDialog: последний участник — сказано, что группа удалится; про сообщения не спрашивают', () => {
    const c = createClient({ functions: ['leaveChatDialog'] });
    const d = fn(c, 'leaveChatDialog({ isRoom: true, memberCount: 1, mayHaveOwnMessages: true })');
    assert.strictEqual(d.title, 'Удалить группу?');
    assert.match(d.paragraphs.join(' '), /последний участник.*группа и все её сообщения будут удалены безвозвратно/);
    assert.deepStrictEqual(d.actions.map((a) => a.id), ['leave']);
});

test('leaveChatDialog: своих сообщений нет — про сообщения не спрашивают', () => {
    const c = createClient({ functions: ['leaveChatDialog'] });
    const d = fn(c, 'leaveChatDialog({ isRoom: true, memberCount: 3, mayHaveOwnMessages: false })');
    assert.deepStrictEqual(d.actions.map((a) => a.id), ['leave']);
    assert.ok(!d.paragraphs.join(' ').includes('сообщени'), 'вопрос про сообщения без сообщений');
});

test('leaveChatDialog: есть свои сообщения — «Выйти и оставить» / «Выйти и удалить»', () => {
    const c = createClient({ functions: ['leaveChatDialog'] });
    const d = fn(c, 'leaveChatDialog({ isRoom: true, memberCount: 3, mayHaveOwnMessages: true })');
    assert.deepStrictEqual(d.actions.map((a) => [a.id, a.label]), [
        ['leave-keep', 'Выйти и оставить сообщения'],
        ['leave-delete', 'Выйти и удалить сообщения'],
    ]);
    assert.match(d.paragraphs.join(' '), /удалятся вместе с аккаунтом, но не раньше/);
    // Число участников неизвестно (чат не в списке) — как обычная группа, не «последний».
    assert.deepStrictEqual(fn(c, 'leaveChatDialog({ isRoom: true, memberCount: NaN, mayHaveOwnMessages: true })').actions.map((a) => a.id), ['leave-keep', 'leave-delete']);
});

function deleteChatClient({ choice, memberCount = 3, hasMore = false, sentInFeed = true }) {
    const log = { dialogs: [], api: [], toasts: [], left: [] };
    const elements = fakeElements();
    if (sentInFeed) elements.chatMessages.appendChild(Object.assign(new FakeEl(), { className: 'message sent' }));
    const client = createClient({
        functions: ['leaveChatDialog', 'deleteChat', 'withBusyButton'],
        prelude: `let currentChatId = 5; let currentRoomId = 50; let hasMoreHistory = ${hasMore}; const chatsById = new Map([[5, { member_count: ${memberCount} }]]);`,
        sandbox: {
            elements,
            confirmDialog: async (spec) => { log.dialogs.push(plain(spec)); return choice; },
            api: async (url, init) => { log.api.push({ url, method: init.method }); return { success: true }; },
            forgetLeftRoom: async (roomId) => log.left.push(roomId),
            showToast: (text) => log.toasts.push(text),
            closeModal() {},
            resetChatView() {},
            loadChats() {},
        },
    });
    return { ...client, log, elements };
}

test('deleteChat: «Отмена» (null) ничего не делает — не выводит из группы', async () => {
    const c = deleteChatClient({ choice: null });
    await c.run('deleteChat()');
    assert.strictEqual(c.log.api.length, 0, 'запрос на выход ушёл после отмены');
    assert.deepStrictEqual(c.log.toasts, []);
});

test('deleteChat: «Выйти и оставить» — DELETE без deleteMessages; «Выйти и удалить» — с deleteMessages=1', async () => {
    const keep = deleteChatClient({ choice: 'leave-keep' });
    await keep.run('deleteChat()');
    assert.deepStrictEqual(keep.log.api, [{ url: '/api/chats/5', method: 'DELETE' }]);
    assert.deepStrictEqual(keep.log.left, [50]);
    assert.deepStrictEqual(keep.log.toasts, ['Вы вышли из группы']);
    const del = deleteChatClient({ choice: 'leave-delete' });
    await del.run('deleteChat()');
    assert.deepStrictEqual(del.log.api, [{ url: '/api/chats/5?deleteMessages=1', method: 'DELETE' }]);
});

test('deleteChat: спрашивает по ситуации — одиночка, без сообщений, есть ещё история', async () => {
    const last = deleteChatClient({ choice: 'leave', memberCount: 1 });
    await last.run('deleteChat()');
    assert.strictEqual(last.log.dialogs[0].title, 'Удалить группу?');
    const empty = deleteChatClient({ choice: 'leave', sentInFeed: false });
    await empty.run('deleteChat()');
    assert.deepStrictEqual(empty.log.dialogs[0].actions.map((a) => a.id), ['leave']);
    // Своих сообщений в ленте нет, но история подгружена не вся — они могут быть выше.
    const more = deleteChatClient({ choice: 'leave-keep', sentInFeed: false, hasMore: true });
    await more.run('deleteChat()');
    assert.deepStrictEqual(more.log.dialogs[0].actions.map((a) => a.id), ['leave-keep', 'leave-delete']);
    // 'leave' без выбора про сообщения — это «оставить»: параметра удаления нет.
    assert.deepStrictEqual(empty.log.api, [{ url: '/api/chats/5', method: 'DELETE' }]);
});

done();
