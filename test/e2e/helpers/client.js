'use strict';
// HTTP-клиент сквозных тестов: один экземпляр — один «браузер».
//
// * fetch + хранилище кук (helpers/cookies.js), redirect: 'manual';
// * по умолчанию заголовки Origin: <адрес сервера> и уникальный
//   X-Forwarded-For на клиента: лимиты регистрации и сокетов считаются по IP
//   (trust proxy = 1 — IP берётся из X-Forwarded-For), и клиенты одного
//   набора не должны упираться в общий лимит;
// * перед первым небезопасным запросом — GET за кукой csrf_token, дальше
//   заголовок X-CSRF-Token (csrfToken() — единственное место, которое
//   поменяется, если токен станет привязан к сессии);
// * методы API бросают ошибку с телом ответа, если success !== true;
//   для негативных проверок — сырые get/post/put/del.

const path = require('path');
const crypto = require('crypto');
const { CookieJar } = require('./cookies');
const { connectSocket } = require('./socket');
const { REPO_ROOT } = require('./env');
const { solve } = require(path.join(REPO_ROOT, 'public', 'pow-worker.js'));
const { fakeEnvelope } = require('./envelope');

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
// Общий признак версии клиента волны 4 (message-ordering.md, 14.1): изменяющие
// запросы сообщений несут proto: 4. `proto: undefined` в тесте - «поле не присылать».
const PROTO = 4;
let clientCounter = 0;

// Случайный id сообщения в допустимом формате (31 бит, не меньше 1 000 000).
function newClientMessageId() {
    for (;;) {
        const value = crypto.randomInt(0, 0x80000000);
        if (value >= 1000000) return String(value);
    }
}

// 10.<процесс>.<n>.<n>: уникально в пределах файла-набора (у каждого файла
// свой сервер, лимиты в памяти его процесса).
function nextXff() {
    clientCounter++;
    return `10.${(process.pid % 200) + 20}.${(clientCounter >> 8) & 255}.${clientCounter & 255}`;
}

class ApiError extends Error {
    constructor(what, res) {
        super(`${what}: HTTP ${res.status} ${typeof res.body === 'string' ? res.body.slice(0, 300) : JSON.stringify(res.body)}`);
        this.status = res.status;
        this.body = res.body;
    }
}

class TestClient {
    // server — объект с baseUrl (ServerHandle): адрес берётся при каждом
    // запросе, поэтому клиент переживает рестарт сервера на другом порту.
    constructor(server, { xff = nextXff(), origin, secureContext = false, name = null } = {}) {
        this.server = server;
        this.xff = xff;
        this.originOverride = origin;
        this.name = name || `клиент ${xff}`;
        this.jar = new CookieJar({ secureContext });
        this.user = null;
        this.roomChats = new Map();   // id чата -> Promise<boolean>: комната ли это (см. isRoomChat)
    }

    get baseUrl() { return this.server.baseUrl; }
    get origin() { return this.originOverride === undefined ? this.baseUrl : this.originOverride; }

    // Сырой запрос: { status, headers, body, text, response }. body — JSON,
    // если ответ JSON, иначе текст; binary: true — Buffer.
    async request(method, urlPath, { json, body, headers = {}, origin, csrf = 'auto', binary = false } = {}) {
        const upper = method.toUpperCase();
        const all = { 'X-Forwarded-For': this.xff, ...headers };
        const effectiveOrigin = origin === undefined ? this.origin : origin;
        if (effectiveOrigin !== null) all.Origin = effectiveOrigin;
        if (csrf === 'auto' && UNSAFE.has(upper)) all['X-CSRF-Token'] = await this.csrfToken();
        else if (typeof csrf === 'string') all['X-CSRF-Token'] = csrf;
        let payload = body;
        if (json !== undefined) {
            all['Content-Type'] = 'application/json';
            payload = JSON.stringify(json);
        }
        const cookie = this.jar.header(urlPath);
        if (cookie) all.Cookie = cookie;
        const response = await fetch(this.baseUrl + urlPath, { method: upper, headers: all, body: payload, redirect: 'manual' });
        this.jar.setFromResponse(response, urlPath);
        let parsed;
        let text = null;
        if (binary) {
            parsed = Buffer.from(await response.arrayBuffer());
        } else {
            text = await response.text();
            parsed = text;
            if ((response.headers.get('content-type') || '').includes('application/json')) {
                try { parsed = JSON.parse(text); } catch { /* оставляем текст */ }
            }
        }
        return { status: response.status, headers: response.headers, body: parsed, text, response };
    }

    get(urlPath, opts) { return this.request('GET', urlPath, opts); }
    post(urlPath, json, opts = {}) { return this.request('POST', urlPath, { ...opts, json }); }
    put(urlPath, json, opts = {}) { return this.request('PUT', urlPath, { ...opts, json }); }
    del(urlPath, opts) { return this.request('DELETE', urlPath, opts); }

    async csrfToken() {
        if (!this.jar.get('csrf_token')) await this.request('GET', '/api/auth', { csrf: false });
        const token = this.jar.get('csrf_token');
        if (!token) throw new Error('сервер не выдал куку csrf_token');
        return token;
    }

    withCookie(name, value, attrs) {
        this.jar.set(name, value, attrs);
        return this;
    }

    async ok(promise, what) {
        const res = await promise;
        if (!res.body || res.body.success !== true) throw new ApiError(what, res);
        return res.body;
    }

    // ---- Вход и аккаунт ----

    async solvePow(purpose) {
        const challenge = await this.get(`/api/pow/challenge?purpose=${encodeURIComponent(purpose)}`);
        if (!challenge.body || !challenge.body.success) throw new ApiError('PoW challenge', challenge);
        const { token, difficulty } = challenge.body;
        return { token, nonce: String(solve(token, difficulty)) };
    }

    async registerAnon({ lifetime = 'tab' } = {}) {
        const pow = await this.solvePow('register-anon');
        const body = await this.ok(this.post('/api/register/anonymous', { lifetime, pow }), 'регистрация анонима');
        this.user = body.user;
        return body.user;
    }

    async auth() {
        const res = await this.get('/api/auth');
        return res.body;
    }

    async logout() { return this.ok(this.post('/api/logout', {}), 'выход'); }

    async deleteAccount(password) {
        return this.ok(this.post('/api/account/delete', password === undefined ? {} : { password }), 'удаление аккаунта');
    }

    // ---- Чаты и комнаты ----

    async chats() { return (await this.ok(this.get('/api/chats'), 'список чатов')).chats; }

    async botChat() {
        const chat = (await this.chats()).find(c => Number(c.is_bot) === 1);
        if (!chat) throw new Error('у пользователя нет чата с ботом');
        return chat;
    }

    async createRoom(name) { return (await this.ok(this.post('/api/chats', { name }), 'создание комнаты')).chat; }

    async invite(chatId) { return this.ok(this.get(`/api/chats/invite/${chatId}`), 'код приглашения'); }

    async rotateInvite(chatId, settings = {}) {
        return this.ok(this.post(`/api/chats/${chatId}/invite/rotate`, settings), 'новый код приглашения');
    }

    async joinPreview(code) { return this.ok(this.post('/api/chats/join/preview', { code }), 'предпросмотр комнаты'); }

    // { pending: true, requestId } — заявка; { chat } — вход без одобрения.
    async join(code) { return this.ok(this.post('/api/chats/join', { code }), 'вход по коду'); }

    async joinRequests(chatId) { return (await this.ok(this.get(`/api/chats/${chatId}/join-requests`), 'заявки комнаты')).requests; }

    async approve(requestId) { return this.ok(this.post(`/api/join-requests/${requestId}/approve`, {}), 'одобрение заявки'); }

    async deny(requestId) { return this.ok(this.post(`/api/join-requests/${requestId}/deny`, {}), 'отклонение заявки'); }

    // deleteMessages: true - выйти и сразу удалить свои сообщения (?deleteMessages=1).
    async leave(chatId, { deleteMessages = false } = {}) {
        return this.ok(this.del(`/api/chats/${chatId}${deleteMessages ? '?deleteMessages=1' : ''}`), 'выход из чата');
    }

    // ---- Сообщения и файлы ----

    // Комната ли чат (у чата с ботом room_id нет). Список чатов запрашивается один
    // раз на чат; чужой или неизвестный id считается обычным чатом: сервер ответит
    // «Чат не найден».
    isRoomChat(chatId) {
        const key = String(chatId);
        if (!this.roomChats.has(key)) {
            this.roomChats.set(key, this.chats().then(list => list.some(c => String(c.id) === key && Boolean(c.room_id))));
        }
        return this.roomChats.get(key);
    }

    // Тело POST /api/messages. Id сообщения комнаты выбирает клиент
    // (message-ordering.md, раздел 6): helper подставляет случайный clientMessageId,
    // если тест не задал свой (в том числе `clientMessageId: undefined` — «поле не
    // присылать»). Для чата с ботом поле сервер игнорирует.
    //
    // В комнате сервер принимает только E2EE-конверт правильной формы (R7), поэтому
    // текст теста превращается в fakeEnvelope(текст) и уходит с encrypted: true.
    // extra.raw: true — отправить text и поля как есть (негативные проверки).
    async messageBody(chatId, text, extra) {
        const { raw, ...rest } = extra;
        const body = { chatId, text, clientMessageId: newClientMessageId(), proto: PROTO, ...rest };
        if (!raw && body.encrypted === undefined && await this.isRoomChat(chatId)) {
            body.text = fakeEnvelope(text);
            body.encrypted = true;
        }
        if (body.clientMessageId === undefined) delete body.clientMessageId;
        if (body.proto === undefined) delete body.proto;
        return body;
    }

    async send(chatId, text, extra = {}) {
        return (await this.ok(this.post('/api/messages', await this.messageBody(chatId, text, extra)), 'отправка сообщения')).message;
    }

    // Сырой ответ: негативные проверки кодов 400/409.
    async sendRaw(chatId, text, extra = {}) {
        return this.post('/api/messages', await this.messageBody(chatId, text, extra));
    }

    // Правка сообщения: PUT /api/messages/:id (тело - конверт; proto: 4 по умолчанию).
    async editRaw(messageId, text, extra = {}) {
        const body = { text: fakeEnvelope(text), proto: PROTO, ...extra };
        if (body.proto === undefined) delete body.proto;
        return this.put(`/api/messages/${messageId}`, body);
    }

    async edit(messageId, text, extra) { return this.ok(this.editRaw(messageId, text, extra), 'правка сообщения'); }

    async messages(chatId, query = '') {
        return this.ok(this.get(`/api/messages/${chatId}${query ? `?${query}` : ''}`), 'сообщения чата');
    }

    // Сырой ответ: квота и отказы проверяются по статусу.
    // Порядок полей FormData важен (раздел 6.3 контракта): proto, chatId, encrypted,
    // clientMessageId, envelope — ДО файла, иначе fileFilter сервера их не увидит.
    // clientMessageId: undefined — не присылать поле; ключа нет — случайный id.
    async uploadRaw(chatId, bytes, mime, opts = {}) {
        const { filename = 'file.bin', text, encrypted, envelope } = opts;
        const clientMessageId = 'clientMessageId' in opts ? opts.clientMessageId : newClientMessageId();
        const proto = 'proto' in opts ? opts.proto : PROTO;
        const form = new FormData();
        // proto - первым: как clientMessageId, он обязан стоять ДО файла (14.1).
        if (proto !== undefined) form.append('proto', String(proto));
        form.append('chatId', String(chatId));
        if (text !== undefined) form.append('text', text);
        if (encrypted !== undefined) form.append('encrypted', String(encrypted));
        if (clientMessageId !== undefined) form.append('clientMessageId', String(clientMessageId));
        if (envelope !== undefined) form.append('envelope', envelope);
        form.append('file', new Blob([bytes], { type: mime }), filename);
        return this.request('POST', '/api/messages/file', { body: form });
    }

    // Вложение в комнату: шифротекст (случайные байты) и конверт-метка. Открытых
    // вложений в комнатах нет (R7). label — что положить в конверт (по умолчанию имя файла).
    uploadCipherRaw(chatId, { bytes = crypto.randomBytes(300), label = 'file', ...opts } = {}) {
        return this.uploadRaw(chatId, bytes, 'application/octet-stream', {
            encrypted: true, envelope: fakeEnvelope(label), ...opts,
        });
    }

    async uploadCipher(chatId, opts) {
        return (await this.ok(this.uploadCipherRaw(chatId, opts), 'загрузка шифротекста')).message;
    }

    async upload(chatId, bytes, mime, opts) {
        return (await this.ok(this.uploadRaw(chatId, bytes, mime, opts), 'загрузка файла')).message;
    }

    async download(fileUrl) { return this.request('GET', fileUrl, { binary: true }); }

    // ---- Сокет с куками, Origin и X-Forwarded-For этого клиента ----

    socket({ origin, cookie, xff, ...opts } = {}) {
        return connectSocket({
            baseUrl: this.baseUrl,
            cookie: cookie === undefined ? this.jar.header('/socket.io/') : cookie,
            origin: origin === undefined ? this.origin : origin,
            xff: xff === undefined ? this.xff : xff,
            ...opts,
        });
    }
}

module.exports = { TestClient, ApiError, nextXff, newClientMessageId, PROTO };
