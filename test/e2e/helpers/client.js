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
const { CookieJar } = require('./cookies');
const { connectSocket } = require('./socket');
const { REPO_ROOT } = require('./env');
const { solve } = require(path.join(REPO_ROOT, 'public', 'pow-worker.js'));

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
let clientCounter = 0;

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

    async leave(chatId) { return this.ok(this.del(`/api/chats/${chatId}`), 'выход из чата'); }

    // ---- Сообщения и файлы ----

    async send(chatId, text, extra = {}) {
        return (await this.ok(this.post('/api/messages', { chatId, text, ...extra }), 'отправка сообщения')).message;
    }

    async messages(chatId, query = '') {
        return this.ok(this.get(`/api/messages/${chatId}${query ? `?${query}` : ''}`), 'сообщения чата');
    }

    // Сырой ответ: квота и отказы проверяются по статусу.
    async uploadRaw(chatId, bytes, mime, { filename = 'file.bin', text, encrypted, envelope } = {}) {
        const form = new FormData();
        form.append('chatId', String(chatId));
        if (text !== undefined) form.append('text', text);
        if (encrypted !== undefined) form.append('encrypted', String(encrypted));
        if (envelope !== undefined) form.append('envelope', envelope);
        form.append('file', new Blob([bytes], { type: mime }), filename);
        return this.request('POST', '/api/messages/file', { body: form });
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

module.exports = { TestClient, ApiError, nextXff };
