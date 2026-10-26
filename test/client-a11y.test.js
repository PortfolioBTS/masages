'use strict';
// Доступность (T7.3, п.17 ревью W7 R3): лента — role="log" без aria-live на весь контейнер и с
// отдельным статусом новых сообщений; ориентиры aside/nav/main; aria-current у выбранного чата;
// счётчик непрочитанного читается словами; картинки в ленте открываются с клавиатуры.
// Логика в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-a11y.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');

const { test, done } = createHarness();
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

// ---- разметка ----

test('лента сообщений — role="log" с названием, без aria-live на весь контейнер; рядом отдельный статус новых', () => {
    const feed = /<div id="chat-messages"[^>]*>/.exec(html)[0];
    assert.ok(feed.includes('role="log"'));
    assert.ok(feed.includes('aria-label="Сообщения чата"'));
    assert.ok(feed.includes('aria-live="off"'), 'без aria-live=off role=log озвучивал бы каждое изменение ленты');
    assert.ok(feed.includes('aria-relevant="additions"'));
    const status = /<div id="new-message-status"[^>]*>/.exec(html)[0];
    assert.ok(status.includes('role="status"') && status.includes('aria-live="polite"') && status.includes('visually-hidden'));
});

test('ориентиры: боковая панель — aside, список чатов — navigation, содержимое чата — main', () => {
    assert.match(html, /<aside class="sidebar" aria-label="Чаты и профиль">/);
    assert.match(html, /<div id="chats-list" class="chats-list" role="navigation" aria-label="Список чатов">/);
    assert.match(html, /<main class="main-content" hidden>/);
    // Теги закрыты теми же именами (не осталось div-закрытия у aside/main).
    assert.strictEqual((html.match(/<aside\b/g) || []).length, (html.match(/<\/aside>/g) || []).length);
    assert.strictEqual((html.match(/<main\b/g) || []).length, (html.match(/<\/main>/g) || []).length);
});

// ---- счётчик непрочитанного ----

function badgeClient() {
    return createClient({
        functions: ['setChatBadge', 'plural'],
        sandbox: { document: { createElement: (tag) => new FakeEl(tag) } },
    });
}

test('счётчик непрочитанного: число для глаз, фраза словами для скринридера (со склонением)', () => {
    const c = badgeClient();
    const item = new FakeEl();
    c.context.__item = item;
    const spoken = (n) => {
        c.run(`setChatBadge(__item, ${n})`);
        const badge = item.children.find((el) => el.classes.has('chat-badge'));
        return { shown: badge.children[0], spoken: badge.children[1] };
    };
    let { shown, spoken: said } = spoken(1);
    assert.strictEqual(shown.textContent, '1');
    assert.strictEqual(shown.getAttribute('aria-hidden'), 'true', 'цифру скринридер не читает');
    assert.ok(said.classes.has('visually-hidden'));
    assert.strictEqual(said.textContent, '1 непрочитанное сообщение');
    assert.strictEqual(spoken(3).spoken.textContent, '3 непрочитанных сообщения');
    assert.strictEqual(spoken(5).spoken.textContent, '5 непрочитанных сообщений');
    assert.strictEqual(spoken(21).spoken.textContent, '21 непрочитанное сообщение');
    ({ shown, spoken: said } = spoken(150));
    assert.strictEqual(shown.textContent, '99+');
    assert.strictEqual(said.textContent, '150 непрочитанных сообщений', 'словами — точное число');
    c.run('setChatBadge(__item, 0)');
    assert.ok(!item.children.some((el) => el.classes.has('chat-badge')), 'нулевой счётчик убран');
});

// ---- aria-current ----

test('выбранный чат помечен aria-current="true", у прежнего отметка снимается', () => {
    const elements = fakeElements();
    const rows = [5, 6].map((id) => {
        const el = new FakeEl();
        el.className = 'chat-item';
        el.dataset.id = String(id);
        el.dataset.roomId = '';
        elements.chatsList.appendChild(el);
        return el;
    });
    const c = createClient({
        functions: ['setActiveChatItem', 'findChatItem', 'setChatBadge', 'plural'],
        prelude: 'const chatsById = new Map([[5, { unread: 2 }], [6, { unread: 0 }]]);',
        sandbox: { elements, document: { createElement: (tag) => new FakeEl(tag) } },
    });
    c.run('setActiveChatItem(5, null)');
    assert.strictEqual(rows[0].getAttribute('aria-current'), 'true');
    assert.ok(rows[0].classes.has('active'));
    assert.strictEqual(rows[1].getAttribute('aria-current'), null);
    c.run('setActiveChatItem(6, null)');
    assert.strictEqual(rows[0].getAttribute('aria-current'), null, 'отметка у прежнего снята');
    assert.strictEqual(rows[1].getAttribute('aria-current'), 'true');
    c.run('setActiveChatItem(null, null)');
    assert.strictEqual(rows[1].getAttribute('aria-current'), null);
});

// ---- статус новых ----

function announceClient() {
    const frames = [];
    const timers = [];
    const elements = fakeElements();
    const client = createClient({
        functions: ['announceNewMessage', 'messageSummary'],
        prelude: 'let newMessageStatusTimer = null;',
        sandbox: {
            elements,
            roomAuthorLabel: (roomId, senderId) => `Автор${senderId}`,
            requestAnimationFrame: (fn) => frames.push(fn),
            setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
            clearTimeout() {},
        },
    });
    const flush = () => frames.splice(0).forEach((fn) => fn());
    return { ...client, elements, flush, timers };
}

test('новое сообщение озвучивается в #new-message-status: автор и текст; сначала очистка, текст — на следующем кадре', () => {
    const c = announceClient();
    c.elements.newMessageStatus.textContent = 'старое';
    c.context.__m = { room_id: 10, _senderId: 7, text: 'Привет,\n  как дела?' };
    c.run('announceNewMessage(__m)');
    assert.strictEqual(c.elements.newMessageStatus.textContent, '', 'прежняя фраза стёрта: одинаковая подряд прозвучит снова');
    c.flush();
    assert.strictEqual(c.elements.newMessageStatus.textContent, 'Новое сообщение от Автор7: Привет, как дела?');
    c.timers[0].fn();
    assert.strictEqual(c.elements.newMessageStatus.textContent, '', 'через 10 с область очищается');
});

test('длинный текст обрезается; файл и бот называются по-человечески', () => {
    const c = announceClient();
    c.context.__long = { room_id: 10, _senderId: 1, text: 'я'.repeat(300) };
    c.run('announceNewMessage(__long)');
    c.flush();
    const said = c.elements.newMessageStatus.textContent;
    assert.ok(said.endsWith('…') && said.length < 160, said.length);
    c.context.__file = { room_id: 10, _senderId: 2, file_url: '/uploads/x', text: '' };
    c.run('announceNewMessage(__file)');
    c.flush();
    assert.strictEqual(c.elements.newMessageStatus.textContent, 'Новое сообщение от Автор2: Файл');
    c.context.__bot = { room_id: null, sender_username: 'Бот Помощник', text: 'Здравствуйте' };
    c.run('announceNewMessage(__bot)');
    c.flush();
    assert.strictEqual(c.elements.newMessageStatus.textContent, 'Новое сообщение от Бот Помощник: Здравствуйте');
});

// ---- картинки ----

test('картинка в ленте: tabindex, role=button, подпись; Enter и пробел открывают, другие клавиши — нет', () => {
    const opened = [];
    const c = createClient({
        functions: ['makeImageOpenable'],
        sandbox: { window: { open: (...args) => opened.push(args) } },
    });
    const img = new FakeEl('img');
    img.alt = 'кот.png';
    c.context.__img = img;
    c.run("makeImageOpenable(__img, 'blob:abc')");
    assert.strictEqual(img.tabIndex, 0);
    assert.strictEqual(img.getAttribute('role'), 'button');
    assert.strictEqual(img.getAttribute('aria-label'), 'Открыть изображение: кот.png');
    const enter = img.fire('keydown', { key: 'Enter' });
    img.fire('keydown', { key: ' ' });
    img.fire('keydown', { key: 'a' });
    img.fire('click');
    assert.strictEqual(enter.defaultPrevented, true);
    assert.deepStrictEqual(opened, [['blob:abc', '_blank', 'noopener'], ['blob:abc', '_blank', 'noopener'], ['blob:abc', '_blank', 'noopener']]);
});

test('оба места, где рисуются картинки ленты, используют makeImageOpenable', () => {
    const { readClientScript } = require('./client-script-source');
    const script = readClientScript();
    assert.strictEqual((script.match(/^\s+makeImageOpenable\(img,/gm) || []).length, 2);
    assert.ok(!script.includes("img.addEventListener('click', () => window.open("), 'остался открывающий только мышью обработчик');
    assert.ok(script.includes('if (!mine) announceNewMessage(message);'));
});

done();
