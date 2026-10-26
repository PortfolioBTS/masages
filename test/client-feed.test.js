'use strict';
// Лента сообщений и отправка правки на клиенте (ревью W7 R5, В-6): клиентская половина контракта
// docs/security/message-ordering.md, разделы 6, 9, 12 и 13. Раньше эти ветки держались на регэкспах по
// исходнику и браузерном «счастливом пути»; здесь настоящий код public/js/*.js запускается в vm
// (test/client-vm.js) с заглушками DOM:
//   - placeMessageElement / appendMessage (13): вставка по seq, а не в конец; один id — одна строка;
//   - refreshCurrentChat (13): догрузка после обрыва — только новое, без повторной расшифровки показанного;
//   - обработчик socket.io 'reconnect' (06): после переподключения догружает ленту;
//   - newMessage / messageEdited (07): перепутанный порядок по сокету, ответ сокета раньше ответа POST;
//   - setChatExpiry (12): запрос уходит с выбранным сроком;
//   - меню сообщения (07): «Удалить» шлёт DELETE и убирает сообщение, «Изменить»/«Ответить» передают выбранное;
//   - sendMessage в режиме правки (14): конверт правки несёт edit: true и mid правляемого сообщения.
// Вёрстка, настоящие события и сеть — в test/browser (messages.browser.test.js).
// Запуск: node test/client-feed.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');
const NyxoMessageOrder = require('../public/lib/message-order.js');

const { test, done } = createHarness();
// Объекты из vm имеют чужой Object.prototype: для deepStrictEqual приводим к обычным.
const plain = (value) => JSON.parse(JSON.stringify(value));

// ---- Заглушки DOM ----

// FakeEl умеет не всё, что нужно ленте: вставку перед элементом и выбор по [data-…="…"].
class FeedEl extends FakeEl {
    insertBefore(node, ref) {
        if (node.parent) node.remove();
        const index = this.children.indexOf(ref);
        node.parent = this;
        if (index < 0) this.children.push(node);
        else this.children.splice(index, 0, node);
        return node;
    }
    querySelectorAll(selector) {
        const m = /^((?:\.[\w-]+)*)((?:\[data-[\w-]+(?:="[^"]*")?\])*)$/.exec(selector);
        if (!m) return super.querySelectorAll(selector);
        const classes = m[1].split('.').filter(Boolean);
        const attrs = [...m[2].matchAll(/\[data-([\w-]+)(?:="([^"]*)")?\]/g)]
            .map((a) => [a[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase()), a[2]]);
        return this.descendants().filter((el) => classes.every((c) => el.classes.has(c))
            && attrs.every(([key, value]) => Object.prototype.hasOwnProperty.call(el.dataset, key) && (value === undefined || el.dataset[key] === value)));
    }
}

function messageEl(id, seq, message = {}) {
    const el = new FeedEl('div');
    el.className = 'message';
    el.dataset.messageId = String(id);
    el.dataset.seq = String(seq);
    el._message = { id, seq, ...message };
    return el;
}

function noticeEl() {
    const el = new FeedEl('div');
    el.className = 'system-notice';
    return el;
}

const order = (container) => container.children.map((el) => (el.dataset.messageId === undefined ? 'notice' : el.dataset.messageId));
const msg = (id, seq, extra = {}) => ({ id, seq, room_id: 9, chat_id: 5, ...extra });

// ---- Вставка по seq и один id — одна строка (13-chat-messages.js) ----

function placementClient(shown = []) {
    const container = new FeedEl('div');
    for (const [id, seq] of shown) container.appendChild(messageEl(id, seq));
    const log = { searchStale: 0 };
    const client = createClient({
        functions: ['placeMessageElement', 'appendMessage', 'findMessageEl'],
        prelude: 'let oldestSeq = null;',
        sandbox: {
            elements: fakeElements({ chatMessages: container }),
            CSS: { escape: (s) => s },
            NyxoMessageOrder,
            createMessageElement: (message) => messageEl(message.id, message.seq, message),
            markChatSearchStale: () => { log.searchStale++; },
        },
    });
    return { ...client, container, log };
}

test('appendMessage: сообщения, пришедшие в перепутанном порядке, встают по seq, а не в конец', () => {
    const c = placementClient();
    // Разное число цифр в seq: сравнение строками поставило бы 100 перед 9.
    for (const [id, seq] of [[7, 70], [3, 300], [9, 9], [1, 100], [5, 50], [2, 1000]]) {
        c.context.__m = { id, seq };
        assert.strictEqual(c.run('appendMessage(__m, false)'), true);
    }
    assert.deepStrictEqual(order(c.container), ['9', '5', '7', '1', '3', '2']);
});

test('appendMessage: служебные строки без seq остаются на месте, сообщение встаёт между сообщениями', () => {
    const c = placementClient([[1, 10], [3, 30]]);
    c.container.insertBefore(noticeEl(), c.container.children[1]);
    c.context.__m = { id: 2, seq: 20 };
    c.run('appendMessage(__m, false)');
    assert.deepStrictEqual(order(c.container), ['1', 'notice', '2', '3']);
    c.context.__m = { id: 4, seq: 40 };
    c.run('appendMessage(__m, false)');
    assert.deepStrictEqual(order(c.container), ['1', 'notice', '2', '3', '4']);
});

test('appendMessage: при равном seq новое сообщение идёт после уже показанного', () => {
    const c = placementClient([[1, 10], [2, 20]]);
    c.context.__m = { id: 3, seq: 20 };
    c.run('appendMessage(__m, false)');
    assert.deepStrictEqual(order(c.container), ['1', '2', '3']);
});

test('appendMessage: сообщение с тем же id (в том числе числом вместо строки) второй раз не добавляется', () => {
    const c = placementClient();
    c.context.__m = { id: 5, seq: 50 };
    assert.strictEqual(c.run('appendMessage(__m, true)'), true);
    c.context.__same = { id: '5', seq: 50 };
    assert.strictEqual(c.run('appendMessage(__same, true)'), false);
    assert.strictEqual(c.container.children.length, 1);
    assert.strictEqual(c.log.searchStale, 1, 'поиск по ленте помечен устаревшим только после настоящего добавления');
});

test('appendMessage: oldestSeq — курсор «выше» — опускается до самого раннего показанного seq', () => {
    const c = placementClient();
    for (const seq of [50, 30, 40]) {
        c.context.__m = { id: seq, seq };
        c.run('appendMessage(__m, false)');
    }
    assert.strictEqual(c.run('oldestSeq'), 30);
});

// ---- Догрузка после обрыва (refreshCurrentChat, 13-chat-messages.js) ----

function refreshClient({ shown = [], page, roomId = 9, chatId = 5, near = true, mine = () => false, inApi = null }) {
    const container = new FeedEl('div');
    for (const [id, seq] of shown) container.appendChild(messageEl(id, seq));
    const log = { calls: [], decrypted: [], removed: [], bumps: 0, scrolls: 0, warns: [], ensure: 0 };
    const client = createClient({
        functions: ['placeMessageElement', 'appendMessage', 'findMessageEl', 'refreshCurrentChat'],
        prelude: `let oldestSeq = null; let lastSeenSeq = 0; let openChatSeq = 1; let currentChatId = ${chatId}; let currentRoomId = ${roomId};`,
        sandbox: {
            elements: fakeElements({ chatMessages: container }),
            CSS: { escape: (s) => s },
            NyxoMessageOrder,
            console: { ...console, warn: (...args) => log.warns.push(args.join(' ')) },
            syncE2eeKeyShares: async (chat, room) => { log.calls.push(`sync:${chat}:${room}`); },
            ensureE2eeRoomSession: () => { log.ensure++; },
            api: async (url) => {
                log.calls.push(`api:${url}`);
                if (inApi) inApi(client);
                return page;
            },
            removeMessageElement: (id) => {
                log.removed.push(String(id));
                const el = container.descendants().find((child) => child.dataset.messageId === String(id));
                if (el) el.remove();
            },
            decryptMessagesInPlace: async (messages) => { log.decrypted.push(messages.map((m) => String(m.id))); },
            createMessageElement: (message) => messageEl(message.id, message.seq, message),
            markChatSearchStale() {},
            isNearBottom: () => near,
            scrollToBottom: () => { log.scrolls++; },
            bumpJumpDown: () => { log.bumps++; },
            isOwnMessage: mine,
        },
    });
    return { ...client, container, log };
}

const pageOf = (messages, hasMore = false) => ({ success: true, messages, hasMore });

test('refreshCurrentChat: в ленту попадают только новые сообщения страницы, показанные не расшифровываются повторно', async () => {
    const c = refreshClient({
        shown: [[1, 10], [2, 20]],
        page: pageOf([msg(1, 10), msg(2, 20), msg(3, 30), msg(4, 40)]),
    });
    await c.run('refreshCurrentChat()');
    assert.deepStrictEqual(c.log.decrypted, [['3', '4']], 'расшифровываются только новые id');
    assert.deepStrictEqual(order(c.container), ['1', '2', '3', '4'], 'каждое сообщение один раз, по seq');
    assert.strictEqual(c.run('lastSeenSeq'), 40);
    assert.ok(c.log.calls.includes('api:/api/messages/5'));
});

test('refreshCurrentChat: чужие новые сообщения при прокрутке вверх считает кнопка «вниз», свои — нет; внизу лента прокручивается', async () => {
    const mine = (m) => m.id === 4;
    const up = refreshClient({ shown: [[1, 10]], page: pageOf([msg(1, 10), msg(2, 20), msg(3, 30), msg(4, 40)]), near: false, mine });
    await up.run('refreshCurrentChat()');
    assert.strictEqual(up.log.bumps, 2, 'два чужих новых; показанное и своё не считаются');
    assert.strictEqual(up.log.scrolls, 0);
    const down = refreshClient({ shown: [[1, 10]], page: pageOf([msg(1, 10), msg(2, 20)]), near: true });
    await down.run('refreshCurrentChat()');
    assert.strictEqual(down.log.scrolls, 1);
    assert.strictEqual(down.log.bumps, 0);
});

test('refreshCurrentChat: удалённое за время обрыва пропадает из ленты — в границах страницы', async () => {
    const c = refreshClient({
        shown: [[1, 10], [2, 20], [3, 30], [4, 40], [5, 50]],
        page: pageOf([msg(1, 10), msg(3, 30), msg(5, 50), msg(6, 60)]),
    });
    await c.run('refreshCurrentChat()');
    assert.deepStrictEqual(c.log.removed.sort(), ['2', '4']);
    assert.deepStrictEqual(order(c.container), ['1', '3', '5', '6']);
});

test('refreshCurrentChat: более старые, чем страница (есть hasMore), не трогаются, пустая страница ничего не стирает', async () => {
    const c = refreshClient({
        shown: [[1, 10], [2, 20], [3, 30], [4, 40]],
        page: pageOf([msg(3, 30), msg(4, 40), msg(5, 50)], true),
    });
    await c.run('refreshCurrentChat()');
    assert.deepStrictEqual(c.log.removed, [], 'сообщения 1 и 2 старше страницы: их отсутствие в ней ничего не значит');
    assert.deepStrictEqual(order(c.container), ['1', '2', '3', '4', '5']);
    const empty = refreshClient({ shown: [[1, 10], [2, 20]], page: pageOf([]) });
    await empty.run('refreshCurrentChat()');
    assert.deepStrictEqual(empty.log.removed, []);
    assert.deepStrictEqual(order(empty.container), ['1', '2']);
});

test('refreshCurrentChat: ответ для уже закрытого чата игнорируется', async () => {
    const c = refreshClient({
        shown: [[1, 10]],
        page: pageOf([msg(1, 10), msg(2, 20)]),
        inApi: (client) => client.run('openChatSeq++'),
    });
    await c.run('refreshCurrentChat()');
    assert.deepStrictEqual(order(c.container), ['1']);
    assert.deepStrictEqual(c.log.decrypted, []);
    assert.strictEqual(c.log.ensure, 0);
});

test('refreshCurrentChat: в комнате сначала забираются ключи, потом лента; в чате с ботом ключей нет', async () => {
    const room = refreshClient({ page: pageOf([msg(1, 10)]) });
    await room.run('refreshCurrentChat()');
    assert.deepStrictEqual(room.log.calls, ['sync:5:9', 'api:/api/messages/5']);
    assert.strictEqual(room.log.ensure, 1);
    const bot = refreshClient({ page: pageOf([msg(1, 10, { room_id: null })]), roomId: 'null' });
    await bot.run('refreshCurrentChat()');
    assert.deepStrictEqual(bot.log.calls, ['api:/api/messages/5']);
    assert.strictEqual(bot.log.ensure, 0);
});

test('refreshCurrentChat: неудачный ответ сервера ленту не меняет', async () => {
    const c = refreshClient({ shown: [[1, 10]], page: { success: false, message: 'Нет соединения' } });
    await c.run('refreshCurrentChat()');
    assert.deepStrictEqual(order(c.container), ['1']);
    assert.deepStrictEqual(c.log.removed, []);
});

test('refreshCurrentChat: seq известного id изменился — сообщение не дублируется, расхождение пишется в консоль (12, строка 18)', async () => {
    const c = refreshClient({ shown: [[1, 10]], page: pageOf([msg(1, 99)]) });
    await c.run('refreshCurrentChat()');
    assert.deepStrictEqual(order(c.container), ['1']);
    assert.strictEqual(c.log.warns.length, 1);
    assert.match(c.log.warns[0], /seq известного сообщения изменился/);
});

// ---- После переподключения сокета (06-session-socket.js) ----

function reconnectClient({ user = true, chatId = 5, roomId = 9 } = {}) {
    const source = readClientScript();
    const start = source.indexOf("socket.io.on('reconnect', () => {");
    assert.notStrictEqual(start, -1, "в клиенте нет socket.io.on('reconnect', …)");
    const snippet = source.slice(start, source.indexOf('\n});\n', start) + 4);
    const handlers = {};
    const log = [];
    const client = createClient({
        prelude: `let currentUser = ${user ? '{ id: 1 }' : 'null'}; let currentChatId = ${chatId}; let currentRoomId = ${roomId};`,
        sandbox: {
            socket: { io: { on: (name, fn) => { handlers[name] = fn; } } },
            loadChats: () => log.push('loadChats'),
            refreshCurrentChat: () => log.push('refreshCurrentChat'),
            loadJoinRequestsCount: () => log.push('loadJoinRequestsCount'),
            pingSession: () => log.push('pingSession'),
        },
    });
    client.run(snippet);
    assert.strictEqual(typeof handlers.reconnect, 'function', 'обработчик reconnect не зарегистрирован');
    return { handler: handlers.reconnect, log };
}

test('reconnect: открытая комната — список чатов, догрузка ленты, заявки и продление сессии', () => {
    const c = reconnectClient();
    c.handler();
    assert.deepStrictEqual([...c.log].sort(), ['loadChats', 'loadJoinRequestsCount', 'pingSession', 'refreshCurrentChat']);
});

test('reconnect: чат с ботом — без счётчика заявок; чат не открыт — без догрузки ленты; без входа — ничего', () => {
    const bot = reconnectClient({ roomId: 'null' });
    bot.handler();
    assert.deepStrictEqual([...bot.log].sort(), ['loadChats', 'pingSession', 'refreshCurrentChat']);
    const none = reconnectClient({ chatId: 'null', roomId: 'null' });
    none.handler();
    assert.deepStrictEqual([...none.log].sort(), ['loadChats', 'pingSession']);
    const anonymous = reconnectClient({ user: false });
    anonymous.handler();
    assert.deepStrictEqual(anonymous.log, []);
});

// ---- События сокета: newMessage и messageEdited (07-api-listeners.js) ----

function socketClient({ shown = [], near = true } = {}) {
    const container = new FeedEl('div');
    for (const [id, seq] of shown) container.appendChild(messageEl(id, seq));
    const handlers = {};
    const log = { announced: [], bumps: 0, scrolls: 0, listUpdates: [], notified: [], edits: [], envelopes: [], decrypted: 0, toLoad: 0 };
    const client = createClient({
        functions: ['placeMessageElement', 'appendMessage', 'findMessageEl', 'belongsToCurrentChat', 'isOwnMessage', 'setupSocketListeners'],
        prelude: 'let currentUser = { id: 1 }; let currentChatId = 5; let currentRoomId = 9; let openChatSeq = 1; let oldestSeq = null;',
        sandbox: {
            elements: fakeElements({ chatMessages: container }),
            CSS: { escape: (s) => s },
            NyxoMessageOrder,
            socket: { on: (name, fn) => { handlers[name] = fn; } },
            createMessageElement: (message) => messageEl(message.id, message.seq, message),
            markChatSearchStale() {},
            maybeNotify: (m) => log.notified.push(m.id),
            decryptMessageInPlace: async () => { log.decrypted++; if (log.hook) log.hook(); },
            isNearBottom: () => near,
            scrollToBottom: () => { log.scrolls++; },
            bumpJumpDown: () => { log.bumps++; },
            announceNewMessage: (m) => log.announced.push(m.id),
            updateChatListOnMessage: (m, open) => log.listUpdates.push([m.id, open]),
            markVisibleMessagesRead() {},
            scheduleLoadChats: () => { log.toLoad++; },
            decryptEnvelope: async (...args) => { log.envelopes.push(args); if (log.hook) log.hook(); return { ok: true, text: 'расшифровано' }; },
            decryptedSummary: (res) => res.text,
            e2eeFailureText: (code) => `[${code}]`,
            applyMessageEdit: (...args) => log.edits.push(args),
        },
    });
    client.run('setupSocketListeners()');
    return { ...client, handlers, container, log };
}

test('newMessage: сообщения, пришедшие по сокету в перепутанном порядке, встают в ленту по seq', async () => {
    const c = socketClient();
    for (const [id, seq] of [[3, 30], [1, 10], [2, 20]]) await c.handlers.newMessage(msg(id, seq));
    assert.deepStrictEqual(order(c.container), ['1', '2', '3']);
    assert.deepStrictEqual(c.log.announced, [3, 1, 2], 'каждое чужое объявлено один раз');
});

test('newMessage: ответ сокета раньше ответа POST — в ленте одно сообщение, прокрутка и объявление не дублируются', async () => {
    const c = socketClient();
    const own = msg(7, 70, { mine: true });
    await c.handlers.newMessage(own);
    assert.strictEqual(c.log.scrolls, 1);
    // sendText показывает сообщение из ответа POST тем же appendMessage.
    c.context.__fromPost = { ...own };
    assert.strictEqual(c.run('appendMessage(__fromPost, true)'), false, 'дубликат отсечён по id');
    assert.deepStrictEqual(order(c.container), ['7']);
});

test('newMessage: ответ POST раньше сокета — событие сокета не создаёт второе сообщение и не прокручивает ленту', async () => {
    const c = socketClient();
    const foreign = msg(8, 80);
    c.context.__fromPost = { ...foreign };
    assert.strictEqual(c.run('appendMessage(__fromPost, true)'), true);
    await c.handlers.newMessage(foreign);
    assert.deepStrictEqual(order(c.container), ['8']);
    assert.strictEqual(c.log.scrolls, 0);
    assert.strictEqual(c.log.bumps, 0);
    assert.deepStrictEqual(c.log.announced, [], 'повторно показанное не объявляется');
    assert.deepStrictEqual(c.log.listUpdates, [[8, true]], 'список чатов при этом обновляется');
});

test('newMessage: чужое новое при прокрутке вверх увеличивает кнопку «вниз»; сообщение другого чата в ленту не попадает', async () => {
    const c = socketClient({ near: false });
    await c.handlers.newMessage(msg(1, 10));
    assert.strictEqual(c.log.bumps, 1);
    assert.strictEqual(c.log.scrolls, 0);
    await c.handlers.newMessage(msg(2, 20, { room_id: 10, chat_id: 6 }));
    assert.deepStrictEqual(order(c.container), ['1']);
    assert.deepStrictEqual(c.log.listUpdates, [[1, true], [2, false]]);
});

test('newMessage: пока сообщение расшифровывалось, открыли другой чат — в ленту оно не попадает', async () => {
    const c = socketClient();
    c.log.hook = () => c.run('openChatSeq++');
    await c.handlers.newMessage(msg(1, 10));
    assert.deepStrictEqual(order(c.container), []);
    assert.deepStrictEqual(c.log.listUpdates, []);
});

test('messageEdited: правка расшифровывается с id сообщения (привязка mid) и применяется к показанному', async () => {
    const c = socketClient({ shown: [[41, 410]] });
    await c.handlers.messageEdited({ id: 41, text: 'ENV-правка', chat_id: 5, room_id: 9, encrypted: true });
    assert.deepStrictEqual(c.log.envelopes, [[9, null, 'ENV-правка', 41]], 'id правляемого сообщения передан в проверку mid');
    assert.deepStrictEqual(c.log.edits, [[41, 'расшифровано', false]]);
    assert.strictEqual(c.log.toLoad, 1);
});

test('messageEdited: нешифрованная правка в комнате не показывается текстом; правка другого чата и устаревшая игнорируются', async () => {
    const c = socketClient({ shown: [[41, 410]] });
    await c.handlers.messageEdited({ id: 41, text: 'открытый текст', chat_id: 5, room_id: 9, encrypted: false });
    assert.deepStrictEqual(c.log.envelopes, []);
    assert.deepStrictEqual(c.log.edits, [[41, '[not-encrypted]', true]]);
    await c.handlers.messageEdited({ id: 41, text: 'ENV', chat_id: 6, room_id: 10, encrypted: true });
    assert.strictEqual(c.log.edits.length, 1, 'правка в чужой комнате ленту не меняет');
    const stale = socketClient({ shown: [[41, 410]] });
    stale.log.hook = () => stale.run('openChatSeq++');
    await stale.handlers.messageEdited({ id: 41, text: 'ENV', chat_id: 5, room_id: 9, encrypted: true });
    assert.deepStrictEqual(stale.log.edits, [], 'пока расшифровывали, открыли другой чат');
});

// ---- Таймер исчезновения (12-chat-list.js) ----

function expiryClient({ meta = { expiry_seconds: 0 }, response = { success: true }, roomId = 'null' } = {}) {
    const log = { requests: [], radios: [], toasts: [], synced: 0, policy: [], rendered: 0, indicators: 0 };
    const client = createClient({
        functions: ['normalizeExpiry', 'expiryLabel', 'setChatExpiry'],
        consts: ['EXPIRY_OPTIONS', 'EXPIRY_LABELS'],
        prelude: `let currentChatId = 5; let currentRoomId = ${roomId};`,
        sandbox: {
            getCurrentChatMeta: () => meta,
            setExpiryRadiosDisabled: (disabled) => log.radios.push(disabled),
            api: async (url, init) => {
                log.requests.push({ url, method: init.method, body: JSON.parse(init.body) });
                return response;
            },
            showToast: (text, kind) => log.toasts.push([text, kind]),
            syncExpiryRadios: () => { log.synced++; },
            syncRoomKeyPolicy: (room, value) => log.policy.push([room, value]),
            renderChatList: () => { log.rendered++; },
            updateChatIndicators: () => { log.indicators++; },
        },
    });
    return { ...client, meta, log };
}

for (const seconds of [0, 300, 3600, 86400, 604800]) {
    test(`таймер исчезновения ${seconds} с: запрос уходит с выбранным сроком, срок запоминается, окно разблокируется`, async () => {
        const c = expiryClient({ meta: { expiry_seconds: seconds === 3600 ? 300 : 3600 } });
        await c.run(`setChatExpiry(${seconds})`);
        assert.deepStrictEqual(c.log.requests, [{ url: '/api/chats/5/expiry', method: 'POST', body: { seconds } }]);
        assert.strictEqual(c.meta.expiry_seconds, seconds);
        assert.deepStrictEqual(c.log.radios, [true, false], 'переключатели блокируются на время запроса');
        assert.strictEqual(c.log.toasts.length, 1);
        assert.strictEqual(c.log.toasts[0][1], 'success');
        if (seconds > 0) assert.ok(c.log.toasts[0][0].includes(c.run(`expiryLabel(${seconds})`)), c.log.toasts[0][0]);
        assert.strictEqual(c.log.rendered, 1);
        assert.strictEqual(c.log.indicators, 1);
    });
}

test('таймер исчезновения: тот же срок и недопустимые значения запроса не вызывают', async () => {
    const c = expiryClient({ meta: { expiry_seconds: 3600 } });
    for (const bad of ['3600', '123', 'NaN', '-300', 'undefined']) await c.run(`setChatExpiry(${bad})`);
    assert.deepStrictEqual(c.log.requests, []);
    assert.strictEqual(c.meta.expiry_seconds, 3600);
});

test('таймер исчезновения: отказ сервера — срок прежний, переключатели возвращаются, пользователь видит причину', async () => {
    const c = expiryClient({ meta: { expiry_seconds: 0 }, response: { success: false, message: 'Недостаточно прав' } });
    await c.run('setChatExpiry(300)');
    assert.strictEqual(c.meta.expiry_seconds, 0);
    assert.deepStrictEqual(c.log.toasts, [['Недостаточно прав', 'error']]);
    assert.strictEqual(c.log.synced, 1, 'выбранный радиокнопкой срок откатывается к прежнему');
    assert.deepStrictEqual(c.log.radios, [true, false]);
    assert.strictEqual(c.log.rendered, 0);
});

test('таймер исчезновения: срок из ответа сервера важнее запрошенного; в комнате обновляется политика ключей', async () => {
    const c = expiryClient({ meta: { expiry_seconds: 0 }, response: { success: true, seconds: 86400 }, roomId: '9' });
    await c.run('setChatExpiry(300)');
    assert.strictEqual(c.meta.expiry_seconds, 86400);
    assert.deepStrictEqual(c.log.policy, [[9, 86400]]);
});

// ---- Меню сообщения: удаление, правка, ответ (setupMessageMenuListeners, 07-api-listeners.js) ----

function menuClient({ message = { id: 41, text: 'текст' }, response = { success: true } } = {}) {
    const log = { requests: [], toasts: [], removed: [], hidden: 0, editing: [], replying: [] };
    const elements = fakeElements();
    const client = createClient({
        functions: ['setupMessageMenuListeners'],
        prelude: 'let menuMessage = null;',
        sandbox: {
            elements,
            buildReactionPicker() {},
            onPopupMenuKeydown() {},
            hideMessageMenu: () => { log.hidden++; },
            startReply: (m) => log.replying.push(m.id),
            startEditing: (m) => log.editing.push(m.id),
            copyText() {},
            api: async (url, init) => { log.requests.push([url, init && init.method]); return response; },
            showToast: (text, kind) => log.toasts.push([text, kind]),
            removeMessageElement: (id) => log.removed.push(id),
        },
    });
    client.run('setupMessageMenuListeners()');
    if (message) client.context.__message = message;
    client.run(message ? 'menuMessage = __message' : 'menuMessage = null');
    const click = (name) => elements[name].listeners.get('click')[0]();
    return { ...client, log, click };
}

test('меню сообщения «Удалить»: DELETE, при успехе тост и сообщение сразу убирается из ленты', async () => {
    const c = menuClient();
    await c.click('deleteMessageBtn');
    assert.deepStrictEqual(c.log.requests, [['/api/messages/41', 'DELETE']]);
    assert.deepStrictEqual(c.log.removed, [41]);
    assert.deepStrictEqual(c.log.toasts, [['Сообщение удалено', 'success']]);
    assert.strictEqual(c.log.hidden, 1, 'меню закрывается');
});

test('меню сообщения «Удалить»: отказ сервера — сообщение остаётся, пользователь видит причину; без выбранного сообщения ничего не уходит', async () => {
    const c = menuClient({ response: { success: false, message: 'Нельзя удалить чужое' } });
    await c.click('deleteMessageBtn');
    assert.deepStrictEqual(c.log.removed, []);
    assert.deepStrictEqual(c.log.toasts, [['Нельзя удалить чужое', 'error']]);
    const none = menuClient({ message: null });
    await none.click('deleteMessageBtn');
    assert.deepStrictEqual(none.log.requests, []);
});

test('меню сообщения «Изменить» и «Ответить» передают выбранное сообщение в режим правки и ответа', async () => {
    const c = menuClient();
    await c.click('editMessageBtn');
    await c.click('replyMessageBtn');
    assert.deepStrictEqual(c.log.editing, [41]);
    assert.deepStrictEqual(c.log.replying, [41]);
    assert.strictEqual(c.log.hidden, 2);
});

// ---- Правка своего сообщения (sendMessage, 14-send.js) ----

function editClient({ roomId = 9, original = null, response = { success: true, text: 'от сервера' }, plaintextAllowed = true, text = 'новый текст' } = {}) {
    const input = new FakeEl('textarea');
    input.value = text;
    const log = { encrypt: [], requests: [], applied: [], finished: 0, toasts: [], cleared: [], sentNew: 0 };
    const client = createClient({
        functions: ['sendMessage'],
        prelude: `let currentChatId = 5; let currentRoomId = ${roomId}; let replyToMessageId = null; let editingMessageId = 77; let sending = false; let draftBeforeEdit = ''; const PROTO_VERSION = 4;`,
        sandbox: {
            elements: fakeElements({ messageInput: input }),
            setSending() {},
            showToast: (message, kind) => log.toasts.push([message, kind]),
            plaintextAllowedForChat: () => plaintextAllowed,
            getReadyE2eeClient: async () => ({ fake: 'client' }),
            findMessageEl: () => (original ? { _message: original } : null),
            encryptForRoom: async (_client, chatId, room, plain, options) => { log.encrypt.push({ chatId, room, plain, options }); return 'ENVELOPE'; },
            api: async (url, init) => {
                log.requests.push({ url, method: init.method, body: JSON.parse(init.body) });
                return response;
            },
            sendFailureText: (data, fallback) => data.message || fallback,
            applyMessageEdit: (...args) => log.applied.push(args),
            finishEditing: () => { log.finished++; },
            setMessageInputValue: (value) => log.cleared.push(value),
            clearReply() {},
            sendText: async () => { log.sentNew++; return true; },
        },
    });
    return { ...client, log };
}

test('правка в комнате: конверт несёт edit: true и mid правляемого сообщения; уходит PUT, а не новое сообщение', async () => {
    const c = editClient();
    await c.run('sendMessage()');
    assert.deepStrictEqual(plain(c.log.encrypt), [{ chatId: 5, room: 9, plain: 'новый текст', options: { messageId: '77', edit: true, replyTo: null } }]);
    assert.deepStrictEqual(c.log.requests, [{ url: '/api/messages/77', method: 'PUT', body: { text: 'ENVELOPE', proto: 4 } }]);
    assert.strictEqual(c.log.sentNew, 0, 'правка не должна уходить как второй оригинал');
    assert.deepStrictEqual(c.log.applied, [[77, 'новый текст']], 'в ленте — набранный текст, а не шифротекст');
    assert.strictEqual(c.log.finished, 1);
    assert.deepStrictEqual(c.log.cleared, ['']);
});

test('правка ответа: цитата того же сообщения едет внутри конверта правки (replyTo)', async () => {
    const c = editClient({ original: { reply_to: { id: 12 } } });
    await c.run('sendMessage()');
    assert.strictEqual(c.log.encrypt[0].options.replyTo, '12');
    assert.strictEqual(c.log.encrypt[0].options.edit, true);
});

test('правка в чате с ботом: открытый текст без конверта; без разрешения на открытый текст — отказ без запроса', async () => {
    const bot = editClient({ roomId: 'null' });
    await bot.run('sendMessage()');
    assert.deepStrictEqual(bot.log.encrypt, []);
    assert.deepStrictEqual(bot.log.requests, [{ url: '/api/messages/77', method: 'PUT', body: { text: 'новый текст', proto: 4 } }]);
    assert.deepStrictEqual(bot.log.applied, [[77, 'от сервера']], 'в чате с ботом показывается текст из ответа сервера');
    const denied = editClient({ roomId: 'null', plaintextAllowed: false });
    await denied.run('sendMessage()');
    assert.deepStrictEqual(denied.log.requests, []);
    assert.strictEqual(denied.log.toasts[0][1], 'error');
});

test('правка отклонена сервером: режим правки и набранный текст остаются', async () => {
    const c = editClient({ response: { success: false, httpStatus: 400, message: 'Нельзя изменить' } });
    await c.run('sendMessage()');
    assert.deepStrictEqual(c.log.toasts, [['Нельзя изменить', 'error']]);
    assert.deepStrictEqual(c.log.applied, []);
    assert.strictEqual(c.log.finished, 0);
    assert.deepStrictEqual(c.log.cleared, [], 'поле не очищается — человек не теряет текст');
});

done();
