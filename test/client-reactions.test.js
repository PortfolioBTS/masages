'use strict';
// Реакции в клиенте (T7.3, п.2 ревью W7 R3): признак «моя» приходит с сервера
// ({emoji, count, mine}), поэтому после перезагрузки реакцию можно снять; событие
// reactionChanged обновляет ленту без перезагрузки. Логика — в vm с заглушками DOM
// (test/client-vm.js); серверная часть — test/e2e/reactions.e2e.test.js.
// Запуск: node test/client-reactions.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();

const LIKE = '\u{1F44D}';
const HEART = '❤️';
const REACTIONS = [
    { emoji: LIKE, icon: 'thumbs-up', label: 'Нравится' },
    { emoji: HEART, icon: 'heart', label: 'Сердце' },
];

function makeClient({ api } = {}) {
    const calls = [];
    const toasts = [];
    const bubbles = new Map();
    const elements = fakeElements();
    const client = createClient({
        functions: [
            'normalizeReaction', 'messageReactions', 'myReaction', 'setReactionState', 'applyReactionChange',
            'renderReactions', 'updateReactionPicker', 'toggleReaction', 'findMessageEl',
        ],
        prelude: 'let menuMessage = null; const REACTIONS = __REACTIONS;',
        sandbox: {
            elements,
            __REACTIONS: REACTIONS,
            CSS: { escape: (x) => x },
            document: { createElement: (tag) => new FakeEl(tag) },
            icon: (name) => Object.assign(new FakeEl('svg'), { iconName: name }),
            showToast: (text, kind) => toasts.push({ text, kind }),
            api: async (url, init) => {
                calls.push({ url, init });
                return api(url, init);
            },
        },
    });
    // Лента: findMessageEl ищет по селектору, в заглушке — по таблице.
    elements.chatMessages.querySelector = (selector) => {
        const id = /data-message-id="([^"]*)"/.exec(selector)[1];
        return bubbles.get(id) || null;
    };
    // Пузырь сообщения с контейнером реакций.
    function bubbleFor(message) {
        const bubble = new FakeEl();
        const container = new FakeEl();
        bubble._message = message;
        bubble.querySelector = (selector) => (selector === '.reactions' ? container : null);
        bubbles.set(String(message.id), bubble);
        return { bubble, container };
    }
    return { ...client, calls, toasts, bubbleFor };
}

const shown = (container) => container.children.map((el) => ({ icon: el.children[0].iconName, count: el.children[1] ? el.children[1].textContent : null, active: el.className.split(' ').includes('is-active') }));

test('история с mine: реакция отображается как своя и распознаётся как снимаемая', () => {
    const c = makeClient();
    const message = { id: 5, reactions: [{ emoji: LIKE, count: 2, mine: true }, { emoji: HEART, count: 1, mine: false }] };
    c.context.__m = message;
    assert.strictEqual(c.run('myReaction(__m, ' + JSON.stringify(LIKE) + ')'), true);
    assert.strictEqual(c.run('myReaction(__m, ' + JSON.stringify(HEART) + ')'), false);
    const { container } = c.bubbleFor(message);
    c.context.__c = container;
    c.run('renderReactions(__c, __m)');
    assert.deepStrictEqual(shown(container), [
        { icon: 'thumbs-up', count: '2', active: true },
        { icon: 'heart', count: null, active: false },
    ]);
});

test('старые элементы-строки (newMessage, прежние клиенты) читаются как чужие реакции', () => {
    const c = makeClient();
    c.context.__m = { id: 1, reactions: [LIKE] };
    assert.strictEqual(c.run('myReaction(__m, ' + JSON.stringify(LIKE) + ')'), false);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(c.run('messageReactions(__m)'))), [{ emoji: LIKE, count: 1, mine: false }]);
});

test('toggleReaction на свою реакцию из истории шлёт DELETE и применяет итог сервера', async () => {
    const c = makeClient({ api: async () => ({ success: true, count: 1, mine: false }) });
    const message = { id: 5, reactions: [{ emoji: LIKE, count: 2, mine: true }] };
    const { container } = c.bubbleFor(message);
    c.context.__m = message;
    await c.run('toggleReaction(__m, ' + JSON.stringify(LIKE) + ')');
    assert.strictEqual(c.calls.length, 1);
    assert.strictEqual(c.calls[0].init.method, 'DELETE', 'своя реакция из истории снимается, а не ставится заново');
    assert.match(c.calls[0].url, /^\/api\/reactions\/5\//);
    assert.deepStrictEqual(shown(container), [{ icon: 'thumbs-up', count: null, active: false }], 'осталась чужая реакция, отметки «моя» нет');
});

test('toggleReaction на чужую реакцию шлёт POST и отмечает её своей; число — из ответа сервера', async () => {
    const c = makeClient({ api: async () => ({ success: true, count: 3, mine: true }) });
    const message = { id: 8, reactions: [{ emoji: LIKE, count: 1, mine: false }] };
    const { container } = c.bubbleFor(message);
    c.context.__m = message;
    await c.run('toggleReaction(__m, ' + JSON.stringify(LIKE) + ')');
    assert.strictEqual(c.calls[0].init.method, 'POST');
    assert.deepStrictEqual(JSON.parse(c.calls[0].init.body), { messageId: 8, emoji: LIKE });
    assert.deepStrictEqual(shown(container), [{ icon: 'thumbs-up', count: '3', active: true }]);
});

test('отказ сервера: тост, реакции не меняются', async () => {
    const c = makeClient({ api: async () => ({ success: false, message: 'Сообщение недоступно' }) });
    const message = { id: 8, reactions: [] };
    c.bubbleFor(message);
    c.context.__m = message;
    await c.run('toggleReaction(__m, ' + JSON.stringify(LIKE) + ')');
    assert.deepStrictEqual(c.toasts, [{ text: 'Сообщение недоступно', kind: 'error' }]);
    assert.deepStrictEqual(message.reactions, []);
});

test('reactionChanged другого участника: число обновляется, отметка «моя» не трогается; ноль убирает реакцию', () => {
    const c = makeClient();
    const message = { id: 11, reactions: [{ emoji: LIKE, count: 1, mine: true }] };
    const { container } = c.bubbleFor(message);
    c.run('applyReactionChange(11, ' + JSON.stringify(LIKE) + ', 2, undefined)');
    assert.deepStrictEqual(shown(container), [{ icon: 'thumbs-up', count: '2', active: true }]);
    c.run('applyReactionChange(11, ' + JSON.stringify(HEART) + ', 1, undefined)');
    assert.deepStrictEqual(shown(container), [
        { icon: 'thumbs-up', count: '2', active: true },
        { icon: 'heart', count: null, active: false },
    ]);
    c.run('applyReactionChange(11, ' + JSON.stringify(LIKE) + ', 0, undefined)');
    assert.deepStrictEqual(shown(container), [{ icon: 'heart', count: null, active: false }]);
    c.run('applyReactionChange(11, ' + JSON.stringify(HEART) + ', 0, undefined)');
    assert.strictEqual(container.classes.has('hidden'), true, 'контейнер без реакций скрыт');
});

test('reactionChanged вкладки автора (mine) выставляет отметку; события о сообщении вне ленты игнорируются', () => {
    const c = makeClient();
    const message = { id: 12, reactions: [] };
    const { container } = c.bubbleFor(message);
    c.run('applyReactionChange(12, ' + JSON.stringify(LIKE) + ', 1, true)');
    assert.deepStrictEqual(shown(container), [{ icon: 'thumbs-up', count: null, active: true }]);
    c.run('applyReactionChange(12, ' + JSON.stringify(LIKE) + ', 0, false)');
    assert.deepStrictEqual(shown(container), []);
    c.run('applyReactionChange(999, ' + JSON.stringify(LIKE) + ', 1, true)'); // сообщения нет в ленте — без ошибок
});

test('в picker отметка нажатости берётся из mine', () => {
    const c = makeClient();
    const buttons = REACTIONS.map((_, i) => Object.assign(new FakeEl('button'), { dataset: { index: String(i) } }));
    c.elements.reactionPicker.querySelectorAll = () => buttons;
    c.context.__m = { id: 1, reactions: [{ emoji: HEART, count: 1, mine: true }] };
    c.run('updateReactionPicker(__m)');
    assert.deepStrictEqual(buttons.map((b) => b.getAttribute('aria-pressed')), ['false', 'true']);
});

test('код: подписка на reactionChanged есть, локальной таблицы myReactions больше нет', () => {
    const script = readClientScript();
    assert.match(script, /socket\.on\('reactionChanged'/);
    assert.doesNotMatch(script, /myReactions|_serverReactions/);
});

done();
