'use strict';
// Вход и чат с ботом в настоящем Chrome: экран входа, «Начать анонимно» (PoW
// считает воркер в браузере), чат с ботом, кнопка-подсказка и ответ бота по
// сокету; service worker, закрепляющий код; снимки экрана для сверки до/после
// правок разметки и стилей. Консоль после каждого теста — без ошибок и без
// нарушений CSP (suite.withProfiles).

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');

const suite = createBrowserSuite('login-bot');
const UNREADABLE = '[Не удалось расшифровать]';

suite.test('экран входа: «Как это работает», срок хранения, светлая тема', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage();
        await page.goto(`${suite.baseUrl}/`);
        await page.waitForSelector('#anon-start-btn');
        await page.screenshot('login-01-auth-screen');

        const before = await page.text('#auth-lifetime-detail');
        await page.click('label.segmented-option:has(input[name="auth-lifetime"][value="week"])');
        const after = await page.text('#auth-lifetime-detail');
        assert.notStrictEqual(after, before, 'пояснение к сроку хранения не изменилось при выборе «7 дней»');

        await page.click('#auth-theme-btn');
        await page.waitFor(() => document.documentElement.getAttribute('data-theme') === 'light', { what: 'светлая тема на экране входа' });
        await page.screenshot('login-02-auth-screen-light');
        await page.click('#auth-theme-btn');
        await page.waitFor(() => document.documentElement.getAttribute('data-theme') === 'dark', { what: 'возврат тёмной темы' });

        await page.click('#about-open-btn');
        await page.waitForSelector('#about-modal:not(.hidden)');
        await page.screenshot('login-03-about');
        await app.closeModal(page, 'about-modal');
    });
});

suite.test('«Начать анонимно» → чат с ботом → подсказка → ответ', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage();
        await app.startAnonymously(page, `${suite.baseUrl}/`);

        // Чат с ботом создан вместе с аккаунтом; у него нет комнаты (data-room-id пуст).
        assert.strictEqual(await page.count('#chats-list .chat-item'), 1);
        await page.click('#chats-list .chat-item[data-room-id=""]');
        await page.waitForSelector('#message-input-container');
        await page.waitFor(() => document.querySelectorAll('#chat-messages .message').length > 0, { what: 'приветствие бота в ленте' });
        const welcome = await app.readChat(page);
        assert.strictEqual(welcome.length, 1, 'в чате с ботом одно приветствие');
        assert.strictEqual(welcome[0].sent, false);
        assert.ok(welcome[0].text.length > 0 && welcome[0].text !== UNREADABLE, `приветствие бота не читается: ${welcome[0].text}`);

        // Кнопка-подсказка отправляет своё название обычным сообщением, бот отвечает.
        await page.waitForSelector('#bot-suggestions:not(.hidden) button.suggestion');
        const label = (await page.texts('#bot-suggestions button.suggestion'))[0];
        await page.click('#bot-suggestions button.suggestion');
        await app.waitForMessage(page, label, { sent: true });
        await page.waitFor(() => document.querySelectorAll('#chat-messages .message.received').length >= 2, { what: 'ответ бота на подсказку', timeoutMs: 30000 });
        const chat = await app.readChat(page);
        const reply = chat[chat.length - 1];
        assert.strictEqual(reply.sent, false);
        assert.ok(reply.text.length > 0 && reply.text !== UNREADABLE, `ответ бота не читается: ${reply.text}`);
        await page.screenshot('login-04-bot-chat');

        // Имя аккаунта показывается в профиле.
        assert.ok((await app.username(page)).length > 0);

        // Светлая тема и узкая раскладка — те же экраны, другие правила стилей.
        await page.click('#theme-toggle-btn');
        await page.waitFor(() => document.documentElement.getAttribute('data-theme') === 'light', { what: 'светлая тема в приложении' });
        await page.screenshot('login-05-bot-chat-light');
        await page.click('#theme-toggle-btn');
        await page.setViewport(390, 844);
        await page.screenshot('login-06-bot-chat-narrow');
        await page.click('#back-btn');
        await page.waitForSelector('#chats-list .chat-item');
        await page.screenshot('login-07-chat-list-narrow');
        await page.setViewport(1280, 800);
    });
});

suite.test('service worker закрепляет код: регистрация, кэш оболочки, управление после перезагрузки', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage();
        await page.goto(`${suite.baseUrl}/`);
        await page.waitForSelector('#anon-start-btn');
        // Регистрация стартует через ~1,5 с после загрузки страницы (public/lib/sw-client.js).
        const sw = await page.waitFor(async () => {
            const registrations = await navigator.serviceWorker.getRegistrations();
            const names = await caches.keys();
            const active = registrations.length === 1 && registrations[0].active && registrations[0].active.state === 'activated';
            const shell = names.find(name => name.startsWith('nyxo-shell-'));
            return active && shell ? { scope: registrations[0].scope, shell } : false;
        }, { what: 'активный service worker и кэш оболочки', timeoutMs: 30000 });
        assert.strictEqual(sw.scope, `${suite.baseUrl}/`);

        // После перезагрузки страница уже под управлением SW и по-прежнему работает целиком.
        await page.reload();
        await page.waitFor(() => Boolean(navigator.serviceWorker.controller), { what: 'страница под управлением service worker', timeoutMs: 30000 });
        await app.startAnonymously(page, `${suite.baseUrl}/`);
        assert.strictEqual(await page.isVisible('#code-banner'), false, 'баннер о коде не должен появляться на свежей установке');
    });
});
