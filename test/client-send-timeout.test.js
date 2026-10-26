'use strict';
// Зависшая отправка (T7.3, п.4 ревью W7 R3): запрос без ответа обрывается по таймауту
// (AbortController), замок «идёт отправка» снимается, кнопка показывает aria-busy, а
// повторное «Отправить» с тем же текстом шлёт тот же запрос — с тем же clientMessageId
// (идемпотентность, message-ordering.md 6.5), а не новое сообщение.
// Логика клиента запускается в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-send-timeout.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();
// Объекты из vm имеют чужой Object.prototype: для deepStrictEqual приводим к обычным.
const plain = (value) => JSON.parse(JSON.stringify(value));

// ---- api() ----

function apiClient(fetchImpl) {
    return createClient({
        functions: ['api', 'getCsrfToken'],
        consts: ['API_TIMEOUT_MS', 'TIMED_OUT_MESSAGE'],
        sandbox: {
            AbortController,
            fetch: fetchImpl,
            document: { cookie: 'csrf_token=abc' },
            onUnauthorizedResponse() {},
        },
    });
}

// fetch, который не отвечает, пока его не оборвут.
const hangingFetch = (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
});

test('api(): запрос без ответа обрывается по таймауту — timedOut, а не networkError', async () => {
    const c = apiClient(hangingFetch);
    const started = Date.now();
    const result = await c.run("api('/api/x', { method: 'POST', timeoutMs: 40 })");
    assert.deepStrictEqual(plain(result), { success: false, timedOut: true, message: 'Сервер не отвечает' });
    assert.ok(Date.now() - started < 2000, 'таймаут не сработал вовремя');
});

test('api(): тело ответа, оборвавшееся на середине, тоже таймаут', async () => {
    const c = apiClient(async (_url, init) => ({
        status: 200,
        json: () => new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted')))),
    }));
    const result = await c.run("api('/api/x', { timeoutMs: 40 })");
    assert.strictEqual(result.timedOut, true);
    assert.notStrictEqual(result.networkError, true);
});

test('api(): быстрый ответ проходит без изменений, таймер снят; обрыв сети остаётся networkError', async () => {
    const ok = apiClient(async () => ({ status: 200, json: async () => ({ success: true, id: 7 }) }));
    const result = await ok.run("api('/api/x', { timeoutMs: 40 })");
    assert.deepStrictEqual(plain(result), { success: true, id: 7, httpStatus: 200 });
    const down = apiClient(async () => { throw new TypeError('Failed to fetch'); });
    const failed = await down.run("api('/api/x', { timeoutMs: 40 })");
    assert.deepStrictEqual(plain(failed), { success: false, networkError: true, message: 'Нет соединения с сервером' });
});

test('api(): таймаут по умолчанию задан константой и заметно больше таймаута отправки', () => {
    const script = readClientScript();
    const api = /const API_TIMEOUT_MS = (\d+) \* 1000;/.exec(script);
    const send = /const SEND_TIMEOUT_MS = (\d+) \* 1000;/.exec(script);
    assert.ok(api && send, 'константы таймаутов не найдены');
    assert.ok(Number(api[1]) > Number(send[1]));
    assert.match(script, /signal: controller\.signal/);
});

// ---- загрузка файла (XHR) ----

class FakeXhr {
    constructor() {
        this.upload = {};
        this.headers = {};
        this.aborted = false;
    }
    open() {}
    setRequestHeader(name, value) { this.headers[name] = value; }
    send() { FakeXhr.last = this; }
    abort() { this.aborted = true; if (this.onabort) this.onabort(); }
}

function uploadClient() {
    return createClient({
        functions: ['postFormDataWithProgress', 'getCsrfToken'],
        consts: ['UPLOAD_STALL_MS', 'TIMED_OUT_MESSAGE'],
        sandbox: {
            XMLHttpRequest: FakeXhr,
            document: { cookie: '' },
            onUnauthorizedResponse() {},
            fetch: async () => ({}),
        },
    });
}

test('загрузка: «тишина» дольше stallMs обрывает запрос как timedOut', async () => {
    const c = uploadClient();
    const result = await c.run("postFormDataWithProgress('/api/messages/file', {}, { stallMs: 40 })");
    assert.deepStrictEqual(plain(result), { success: false, timedOut: true, message: 'Сервер не отвечает' });
    assert.strictEqual(FakeXhr.last.aborted, true);
});

test('загрузка: прогресс продлевает ожидание — медленная, но идущая загрузка не обрывается', async () => {
    const c = uploadClient();
    c.context.__opts = { stallMs: 80 };
    const pending = c.run("postFormDataWithProgress('/api/messages/file', {}, __opts)");
    const xhr = FakeXhr.last;
    for (let i = 0; i < 4; i++) {
        await new Promise((resolve) => setTimeout(resolve, 40));
        xhr.upload.onprogress({ lengthComputable: true, loaded: i, total: 10 });
    }
    assert.strictEqual(xhr.aborted, false, 'загрузка с прогрессом оборвана');
    xhr.status = 200;
    xhr.responseText = JSON.stringify({ success: true });
    await xhr.onload();
    assert.deepStrictEqual(plain(await pending), { success: true, httpStatus: 200 });
});

test('загрузка: отмена пользователем остаётся aborted, а не timedOut', async () => {
    const c = uploadClient();
    c.context.__opts = { stallMs: 5000, onXhr: (xhr) => { c.context.__xhr = xhr; } };
    const pending = c.run("postFormDataWithProgress('/api/messages/file', {}, __opts)");
    c.context.__xhr.abort();
    const result = await pending;
    assert.strictEqual(result.aborted, true);
    assert.notStrictEqual(result.timedOut, true);
});

// ---- отправка сообщения ----

// keys — { current }: текущий Sender Key отправителя в комнате (RR-9); без него клиент E2EE-заглушка о ключе не знает.
function sendClient({ responses, keys = null }) {
    const log = { posts: [], encrypts: 0, toasts: [], appended: [], delays: 0 };
    let clock = 1_000_000;
    let idCounter = 0;
    class E2eeBlockedError extends Error {}
    const client = createClient({
        functions: ['isUnknownSendOutcome', 'sendWithOutcomes', 'unknownSendKey', 'requestSenderKeyId', 'sendFailureText', 'sendText'],
        consts: ['SEND_RETRY_DELAYS_MS', 'MAX_ID_CONFLICTS', 'SEND_TIMEOUT_MS', 'SEND_TOTAL_MS', 'UNKNOWN_SEND_TTL_MS'],
        prelude: 'let unknownSend = null; let currentChatId = 1; const PROTO_VERSION = 4;',
        sandbox: {
            elements: fakeElements(),
            Date: { now: () => clock },
            E2eeBlockedError,
            NyxoMessageOrder: { newClientMessageId: () => `id-${++idCounter}` },
            delay: async () => { log.delays++; },
            prepareOutgoing: async () => (keys ? { currentSenderKeyId: async () => keys.current } : { fake: 'client' }),
            reportBlockedSend() {},
            encryptForRoom: async (_client, _chatId, _roomId, text, { messageId }) => {
                log.encrypts++;
                return keys ? JSON.stringify({ senderKeyId: keys.current, mid: messageId, t: text }) : `ENV[${messageId}:${text}]`;
            },
            api: async (url, init) => {
                log.posts.push({ url, body: JSON.parse(init.body), timeoutMs: init.timeoutMs });
                const next = responses.shift();
                const response = typeof next === 'function' ? next(clock) : next;
                if (response.advance) clock += response.advance;
                return response.data;
            },
            showToast: (text, kind) => log.toasts.push({ text, kind }),
            clearRoomBlock() {},
            checkRoomKeyRotation() {},
            appendMessage: (m) => { log.appended.push(m); return true; },
            scrollToBottom() {},
            updateChatListOnMessage() {},
            decryptEnvelope: async () => ({ ok: true }),
            decryptedSummary: () => '',
            roomAuthorLabel: () => '',
        },
    });
    return { ...client, log };
}

const TIMED_OUT = { advance: 25_000, data: { success: false, timedOut: true, message: 'Сервер не отвечает' } };
const OK = { data: { success: true, message: { id: 5, text: 'x' }, httpStatus: 200 } };

test('все попытки отправки таймаутятся: ровно один запрос повторяется с тем же id, тост понятный, запрос запомнен', async () => {
    const c = sendClient({ responses: [{ ...TIMED_OUT, advance: 1000 }, { ...TIMED_OUT, advance: 1000 }, { ...TIMED_OUT, advance: 1000 }, { ...TIMED_OUT, advance: 1000 }] });
    const sent = await c.run("sendText('привет', { chatId: 1, roomId: 10, replyToId: null })");
    assert.strictEqual(sent, false);
    assert.strictEqual(c.log.posts.length, 4, 'первая попытка и три повтора');
    assert.deepStrictEqual([...new Set(c.log.posts.map((p) => p.body.clientMessageId))], ['id-1'], 'повторы идут с одним clientMessageId');
    assert.deepStrictEqual([...new Set(c.log.posts.map((p) => p.body.text))], ['ENV[id-1:привет]'], 'и с одним и тем же конвертом');
    assert.strictEqual(c.log.encrypts, 1, 'шифруется один раз');
    assert.ok(c.log.posts.every((p) => p.timeoutMs === 20_000), 'каждая попытка ограничена SEND_TIMEOUT_MS');
    assert.match(c.log.toasts[0].text, /^Сервер не отвечает/);
    assert.strictEqual(c.log.toasts[0].kind, 'error');
    assert.notStrictEqual(c.run('unknownSend'), null, 'запрос с неизвестным исходом запомнен');
});

test('общий потолок: попытки не тянутся дольше SEND_TOTAL_MS, а таймаут последней ужимается', async () => {
    const c = sendClient({ responses: [TIMED_OUT, TIMED_OUT, TIMED_OUT, TIMED_OUT] });
    await c.run("sendText('медленно', { chatId: 1, roomId: 10 })");
    assert.strictEqual(c.log.posts.length, 3, 'после 75 с повторов нет (потолок 60 с)');
    assert.deepStrictEqual(c.log.posts.map((p) => p.timeoutMs), [20_000, 20_000, 10_000]);
});

test('повторное «Отправить» с тем же текстом шлёт тот же запрос (id и конверт), без нового шифрования', async () => {
    const c = sendClient({ responses: [{ ...TIMED_OUT, advance: 1000 }, { ...TIMED_OUT, advance: 1000 }, { ...TIMED_OUT, advance: 1000 }, { ...TIMED_OUT, advance: 1000 }, OK] });
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    const first = c.log.posts[0].body;
    const again = await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    assert.strictEqual(again, true);
    assert.strictEqual(c.log.posts.length, 5);
    assert.deepStrictEqual(c.log.posts[4].body, first, 'ушёл тот же запрос с тем же clientMessageId');
    assert.strictEqual(c.log.encrypts, 1, 'повторного шифрования не было');
    assert.strictEqual(c.run('unknownSend'), null, 'после успеха память очищена');
});

test('другой текст, чат или ответ — новое сообщение с новым id', async () => {
    const timeouts = () => Array.from({ length: 4 }, () => ({ ...TIMED_OUT, advance: 1000 }));
    const c = sendClient({ responses: [...timeouts(), OK] });
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    await c.run("sendText('привет!', { chatId: 1, roomId: 10 })");
    assert.strictEqual(c.log.posts[4].body.clientMessageId, 'id-2');
    assert.strictEqual(c.log.encrypts, 2);
    assert.strictEqual(c.log.posts[4].body.text, 'ENV[id-2:привет!]');
});

test('запомненный запрос устаревает через UNKNOWN_SEND_TTL_MS', async () => {
    const c = sendClient({ responses: [...Array.from({ length: 4 }, () => ({ ...TIMED_OUT, advance: 1000 })), OK] });
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    c.run('unknownSend.at -= 6 * 60 * 1000');
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    assert.strictEqual(c.log.posts[4].body.clientMessageId, 'id-2', 'старый запрос не используется');
});

// Повторное ревью клиента W7, RR-9: unknownSend повторял конверт, зашифрованный до ротации ключа комнаты. Если первая
// попытка не дошла, а ключ сменился из-за исключения участника, старый конверт под прежним ключом может прочитать
// исключённый (сервер по модели угроз может отдать его ему). Конфиденциальность важнее возможного дубликата.
test('RR-9: свой ключ комнаты сменился после неизвестного исхода — старый конверт не повторяется: заново, новый id, предупреждение', async () => {
    const keys = { current: 'k1' };
    const c = sendClient({ responses: [...Array.from({ length: 4 }, () => ({ ...TIMED_OUT, advance: 1000 })), OK], keys });
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    assert.strictEqual(c.run('unknownSend.senderKeyId'), 'k1', 'ключ конверта запомнен');
    keys.current = 'k2';
    const again = await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    assert.strictEqual(again, true);
    assert.strictEqual(c.log.encrypts, 2, 'зашифровано заново');
    const last = c.log.posts[4].body;
    assert.notStrictEqual(last.clientMessageId, c.log.posts[0].body.clientMessageId, 'новый id');
    assert.strictEqual(JSON.parse(last.text).senderKeyId, 'k2', 'под новым ключом');
    assert.ok(c.log.toasts.some((t) => /Ключ группы сменился/.test(t.text) && /дважды/.test(t.text)), JSON.stringify(c.log.toasts));
});

test('RR-9: ключ комнаты тот же — повторяется тот же запрос, как раньше', async () => {
    const keys = { current: 'k1' };
    const c = sendClient({ responses: [...Array.from({ length: 4 }, () => ({ ...TIMED_OUT, advance: 1000 })), OK], keys });
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    assert.strictEqual(c.log.encrypts, 1);
    assert.deepStrictEqual(c.log.posts[4].body, c.log.posts[0].body);
});

test('отказ сервера (не «неизвестный исход») запрос не запоминает', async () => {
    const c = sendClient({ responses: [{ data: { success: false, httpStatus: 400, message: 'Нельзя' } }] });
    await c.run("sendText('привет', { chatId: 1, roomId: 10 })");
    assert.strictEqual(c.run('unknownSend'), null);
    assert.strictEqual(c.log.toasts[0].text, 'Нельзя');
});

test('sendFailureText: таймаут отличается от обрыва сети', () => {
    const c = sendClient({ responses: [] });
    c.context.__t = { timedOut: true };
    c.context.__n = { networkError: true };
    assert.match(c.run("sendFailureText(__t, 'x')"), /Сервер не отвечает/);
    assert.match(c.run("sendFailureText(__n, 'x')"), /Нет соединения/);
});

// ---- кнопка ----

test('кнопка отправки: aria-busy и крутящийся значок, пока стоит замок; потом возвращается', () => {
    const btn = new FakeEl('button');
    const svg = new FakeEl('svg');
    const use = new FakeEl('use');
    use.setAttribute('href', '#i-send');
    svg.appendChild(use);
    btn.appendChild(svg);
    const elements = fakeElements({ sendBtn: btn });
    const c = createClient({
        functions: ['setSending', 'syncSendButtonBusy', 'syncBotSuggestionsBusy'],
        prelude: 'let sending = false;',
        sandbox: { elements },
    });
    c.run('setSending(true)');
    assert.strictEqual(btn.getAttribute('aria-busy'), 'true');
    assert.strictEqual(use.getAttribute('href'), '#i-loader');
    assert.ok(svg.classes.has('spin'));
    assert.strictEqual(btn.title, 'Отправляем…');
    c.run('setSending(false)');
    assert.strictEqual(btn.getAttribute('aria-busy'), null);
    assert.strictEqual(use.getAttribute('href'), '#i-send');
    assert.ok(!svg.classes.has('spin'));
    assert.strictEqual(btn.title, 'Отправить');
});

done();
