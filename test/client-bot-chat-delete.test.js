'use strict';
// Удаление чата с ботом (T7.3, п.14 ревью W7 R3): раньше чат с ботом удалялся без предупреждения
// и без возврата. Чат с ботом создаётся один раз, вместе с аккаунтом (src/services/accounts.js),
// поэтому перед удалением спрашиваем и прямо говорим, что бота вернуть нельзя; кнопка в меню
// чата подписана «Удалить чат с ботом»; «Отмена» ничего не удаляет.
// Логика в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-bot-chat-delete.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createClient, createHarness, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();
const plain = (value) => JSON.parse(JSON.stringify(value));

function botClient({ choice }) {
    const log = { dialogs: [], api: [], toasts: [], reset: 0 };
    const elements = fakeElements();
    const client = createClient({
        functions: ['leaveChatDialog', 'deleteChat', 'withBusyButton', 'feedMayHaveOwnMessages'],
        prelude: 'let currentChatId = 3; let currentRoomId = null; let hasMoreHistory = false; const chatsById = new Map([[3, { is_bot: 1 }]]);',
        sandbox: {
            elements,
            confirmDialog: async (spec) => { log.dialogs.push(plain(spec)); return choice; },
            api: async (url, init) => { log.api.push({ url, method: init.method }); return { success: true }; },
            forgetLeftRoom: async () => { throw new Error('у чата с ботом нет комнаты'); },
            showToast: (text) => log.toasts.push(text),
            closeModal() {},
            resetChatView: () => { log.reset++; },
            loadChats() {},
        },
    });
    return { ...client, log };
}

test('удаление чата с ботом: перед запросом диалог с предупреждением «Бота вернуть нельзя»', async () => {
    const c = botClient({ choice: 'delete' });
    await c.run('deleteChat()');
    assert.strictEqual(c.log.dialogs.length, 1, 'без диалога чат удалять нельзя');
    const [dialog] = c.log.dialogs;
    assert.strictEqual(dialog.title, 'Удалить чат с ботом?');
    const text = dialog.paragraphs.join(' ');
    assert.match(text, /Переписка с ботом удалится безвозвратно/);
    assert.match(text, /Бота вернуть нельзя/);
    assert.deepStrictEqual(dialog.actions.map((a) => [a.id, a.label, a.style]), [['delete', 'Удалить чат с ботом', 'danger']]);
    assert.deepStrictEqual(c.log.api, [{ url: '/api/chats/3', method: 'DELETE' }]);
    assert.deepStrictEqual(c.log.toasts, ['Чат с ботом удалён']);
    assert.strictEqual(c.log.reset, 1);
});

test('«Отмена» чат с ботом не удаляет', async () => {
    const c = botClient({ choice: null });
    await c.run('deleteChat()');
    assert.deepStrictEqual(c.log.api, []);
    assert.deepStrictEqual(c.log.toasts, []);
    assert.strictEqual(c.log.reset, 0);
});

test('кнопка в меню чата с ботом подписана честно; для группы — «Выйти из группы»', () => {
    const script = readClientScript();
    assert.ok(script.includes("currentRoomId ? 'Выйти из группы' : 'Удалить чат с ботом'"));
    assert.doesNotMatch(script, /currentRoomId \? 'Выйти из группы' : 'Удалить чат'\)/);
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    assert.match(html, /id="delete-chat-btn"[^>]*>.*<span>Удалить чат<\/span>/, 'исходная подпись в разметке — запасная, JS её переписывает');
});

test('сервер: чат с ботом создаётся только при создании аккаунта, поэтому «вернуть» его нечем', () => {
    const accounts = fs.readFileSync(path.join(__dirname, '..', 'src', 'services', 'accounts.js'), 'utf8');
    assert.match(accounts, /INSERT INTO chats \(user_id, name, avatar, online, is_bot,/);
    const insertsOfBot = [];
    const root = path.join(__dirname, '..', 'src');
    // Чат с ботом заводится строкой с его именем; другие вставки в chats (комнаты) is_bot = 0.
    (function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js') && /INSERT INTO chats[\s\S]*'Бот Помощник'/.test(fs.readFileSync(full, 'utf8'))) insertsOfBot.push(path.relative(root, full).replace(/\\/g, '/'));
        }
    })(root);
    assert.deepStrictEqual(insertsOfBot, ['services/accounts.js'], 'чат с ботом создаётся и где-то ещё: текст про «вернуть нельзя» надо пересмотреть');
});

done();
