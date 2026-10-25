'use strict';
// Мелкие действия и наблюдения над интерфейсом, общие для сценариев с утверждениями (messages,
// settings, keyboard, layout). Как и helpers/app.js, работают через настоящие клавиши и клики;
// фокус на сообщение ставится так же, как после Tab (element.focus()).

const APP_TIMEOUT_MS = 30000;

// Элемент, у которого сейчас фокус: тег, id и первые классы.
const focused = (page) => page.evaluate(() => {
    const el = document.activeElement;
    return { tag: el.tagName.toLowerCase(), id: el.id, cls: String(el.className || ''), text: (el.textContent || '').trim().slice(0, 40) };
});

const isHidden = (page, selector) => page.evaluate((sel) => document.querySelector(sel).classList.contains('hidden'), selector);

// Тексты сообщений ленты по порядку.
const messageTexts = (page) => page.evaluate(() => Array.from(document.querySelectorAll('#chat-messages .message .message-text'), (el) => el.textContent));

// Поставить фокус на сообщение по тексту.
const focusMessage = (page, text) => page.evaluate((wanted) => {
    const el = Array.from(document.querySelectorAll('#chat-messages .message')).find((m) => m.querySelector('.message-text').textContent === wanted);
    if (!el) throw new Error(`нет сообщения «${wanted}»`);
    el.focus();
    return true;
}, text);

// Меню сообщения, открытое с клавиатуры (ContextMenu на сообщении в фокусе).
async function openMessageMenu(page, text) {
    await focusMessage(page, text);
    await page.press('ContextMenu');
    await page.waitForSelector('#message-menu:not(.hidden)');
}

// Правка своего сообщения через меню; ждёт, пока в ленте появится новый текст.
async function editMessage(page, oldText, newText) {
    await openMessageMenu(page, oldText);
    await page.click('#edit-message-btn');
    await page.waitForSelector('#edit-preview:not(.hidden)');
    await page.type('#message-input', newText);
    await page.press('Enter');
    await page.waitFor((wanted) => Array.from(document.querySelectorAll('#chat-messages .message .message-text')).some((el) => el.textContent === wanted),
        { args: [newText], what: `в ленте текст правки «${newText}»`, timeoutMs: APP_TIMEOUT_MS });
}

// Удаление своего сообщения через меню (подтверждения нет: удаление сразу).
async function deleteMessage(page, text) {
    await openMessageMenu(page, text);
    await page.click('#delete-message-btn');
    await waitForNoMessage(page, text);
}

function waitForNoMessage(page, text, { timeoutMs = APP_TIMEOUT_MS } = {}) {
    return page.waitFor((wanted) => !Array.from(document.querySelectorAll('#chat-messages .message .message-text')).some((el) => el.textContent === wanted),
        { args: [text], what: `сообщение «${text}» исчезло из ленты`, timeoutMs });
}

// Клик в точку окна страницы (по затемнению вокруг окна).
async function clickAt(page, x, y) {
    await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
    await page.send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1, pointerType: 'mouse' });
    await page.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1, pointerType: 'mouse' });
}

// Состояние сообщения у человека: тексты, пометка «изменено», сбой расшифровки.
const messageViews = (page) => page.evaluate(() => Array.from(document.querySelectorAll('#chat-messages .message'), (el) => ({
    text: (el.querySelector('.message-text') || {}).textContent || '',
    edited: Boolean(el.querySelector('.edited-label')),
    failed: Boolean(el.querySelector('.message-text.e2ee-failed')),
    quote: (el.querySelector('.reply-to small') || {}).textContent || null,
    sent: el.classList.contains('sent'),
})));

// Номер комнаты по её названию (в базе набора).
async function roomIdByName(suite, name) {
    const { rows } = await suite.query('SELECT id FROM rooms WHERE name = $1', [name]);
    if (rows.length !== 1) throw new Error(`комнат с названием «${name}»: ${rows.length}`);
    return rows[0].id;
}

module.exports = {
    focused,
    isHidden,
    messageTexts,
    focusMessage,
    openMessageMenu,
    editMessage,
    deleteMessage,
    waitForNoMessage,
    clickAt,
    messageViews,
    roomIdByName,
};
