'use strict';
// Минимальный клиент Socket.IO (протокол Socket.IO v5 поверх Engine.IO v4)
// на глобальном WebSocket Node 24 — без пакета socket.io-client.
//
// Почему свой: пакета в зависимостях нет; у официального клиента
// автоматические переподключения и буферизация прячут ошибки; а заголовки
// рукопожатия (Cookie, Origin, X-Forwarded-For) нужны под полным контролем —
// для проверки Cross-Site WebSocket Hijacking и лимитов по IP.
//
// Протокол (только то, что нужно тестам):
//   Engine.IO: 0{…} — open, 2 — ping (ответ 3 — pong), 1 — close, 4 — сообщение;
//   Socket.IO: 40 — CONNECT (ответ 40{sid} или 44{message} — CONNECT_ERROR),
//              42[…] — событие, 42<id>[…] — с подтверждением, 43<id>[…] —
//              подтверждение, 41 — отключение. Бинарные пакеты (45/46) не
//              поддерживаются: приложению они не нужны.
//
// Все полученные события пишутся в историю. waitFor смотрит и в неё, поэтому
// порядок «действие → waitFor» безопасен (событие могло прийти раньше, чем
// тест начал ждать); чтобы не поймать старое событие — предикат или mark().
// Служебные записи истории: 'connect', 'disconnect' ({ reason }) и
// 'engine:ping' (каждый ping сервера).

const DEFAULT_TIMEOUT_MS = 5000;

function socketError(kind, reason, extra = {}) {
    const titles = {
        handshake: 'рукопожатие отклонено',
        connect_error: 'подключение отклонено сервером',
        timeout: 'тайм-аут',
        closed: 'соединение закрыто',
    };
    const err = new Error(`Socket.IO: ${titles[kind] || kind}: ${reason}`);
    return Object.assign(err, { kind, reason }, extra);
}

// Пакет Socket.IO (без префикса Engine.IO «4»).
function parseSioPacket(text) {
    const type = text[0];
    if (type === '5' || type === '6') throw new Error('бинарные пакеты Socket.IO не поддерживаются');
    let i = 1;
    let nsp = '/';
    if (text[i] === '/') {
        const comma = text.indexOf(',', i);
        nsp = comma === -1 ? text.slice(i) : text.slice(i, comma);
        i = comma === -1 ? text.length : comma + 1;
    }
    let j = i;
    while (j < text.length && text[j] >= '0' && text[j] <= '9') j++;
    const id = j > i ? Number(text.slice(i, j)) : null;
    const payload = j < text.length ? JSON.parse(text.slice(j)) : undefined;
    return { type, nsp, id, payload };
}

class TestSocket {
    constructor({ baseUrl, headers, namespace = '/', auth, timeoutMs = 10000 }) {
        this.baseUrl = baseUrl;
        this.headers = headers;
        this.namespace = namespace;
        this.auth = auth;
        this.timeoutMs = timeoutMs;
        this.history = [];          // { n, event, args }
        this.waiters = new Set();
        this.acks = new Map();      // id -> { resolve, reject, timer }
        this.nextAckId = 0;
        this.connected = false;
        this.closed = false;
        this.sid = null;
        this.engine = null;         // { sid, pingInterval, pingTimeout }
        this.ws = null;
        this.closedPromise = null;
    }

    get nspPrefix() { return this.namespace === '/' ? '' : `${this.namespace},`; }

    open() {
        return new Promise((resolve, reject) => {
            let settled = false;
            const settle = (err) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                if (err) {
                    this.closeTransport();
                    reject(err);
                } else {
                    resolve(this);
                }
            };
            const timer = setTimeout(() => settle(socketError('timeout', `нет ответа за ${this.timeoutMs} мс`)), this.timeoutMs);
            this.pending = { settle };

            const wsUrl = `${this.baseUrl.replace(/^http/, 'ws')}/socket.io/?EIO=4&transport=websocket`;
            const ws = new WebSocket(wsUrl, { headers: this.headers });
            this.ws = ws;
            this.closedPromise = new Promise((done) => {
                ws.addEventListener('close', (event) => {
                    this.onTransportClose(event);
                    done();
                    if (settled) return;
                    if (!this.engine) {
                        // Апгрейд отклонён до Engine.IO open: WebSocket не отдаёт ни
                        // статус, ни тело — причину узнаём тем же запросом по polling.
                        this.diagnose().then(
                            (info) => settle(socketError('handshake', info.reason, { status: info.status })),
                            (err) => settle(socketError('handshake', `сервер недоступен (${err.message})`))
                        );
                    } else {
                        settle(socketError('closed', `до CONNECT, код ${event.code}`));
                    }
                });
            });
            ws.addEventListener('error', () => {}); // подробности — в 'close'
            ws.addEventListener('message', (event) => this.onFrame(event.data));
        });
    }

    // Причина отказа рукопожатия: тот же запрос транспортом polling
    // (engine.io отвечает JSON { code, message }, например «Origin not allowed»).
    async diagnose() {
        const res = await fetch(`${this.baseUrl}/socket.io/?EIO=4&transport=polling`, {
            headers: this.headers,
            signal: AbortSignal.timeout(5000),
        });
        const text = await res.text();
        let reason = `HTTP ${res.status}`;
        try {
            const body = JSON.parse(text);
            if (body && body.message) reason = body.message;
        } catch {
            if (res.ok && text.startsWith('0')) reason = 'polling-рукопожатие прошло, WebSocket — нет';
        }
        return { status: res.status, reason };
    }

    send(text) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw socketError('closed', 'сокет не подключён');
        this.ws.send(text);
    }

    onFrame(data) {
        if (typeof data !== 'string') return this.push('error', [{ message: 'бинарный кадр не поддерживается' }]);
        const kind = data[0];
        if (kind === '0') {
            this.engine = JSON.parse(data.slice(1));
            const auth = this.auth === undefined ? '' : JSON.stringify(this.auth);
            this.send(`40${this.nspPrefix}${auth}`);
        } else if (kind === '2') {
            this.send(`3${data.slice(1)}`);
            this.push('engine:ping', []);
        } else if (kind === '1') {
            this.closeTransport();
        } else if (kind === '4') {
            this.onPacket(parseSioPacket(data.slice(1)));
        }
    }

    onPacket(packet) {
        if (packet.nsp !== this.namespace) return;
        if (packet.type === '0') {
            this.connected = true;
            this.sid = packet.payload && packet.payload.sid;
            this.push('connect', [packet.payload]);
            if (this.pending) this.pending.settle(null);
        } else if (packet.type === '4') {
            const reason = packet.payload && packet.payload.message ? packet.payload.message : 'CONNECT_ERROR';
            this.push('connect_error', [packet.payload]);
            if (this.pending) this.pending.settle(socketError('connect_error', reason, { data: packet.payload && packet.payload.data }));
        } else if (packet.type === '2') {
            const [event, ...args] = Array.isArray(packet.payload) ? packet.payload : [];
            // Сервер ждёт подтверждения — пустое (приложению это не нужно).
            if (packet.id !== null) this.send(`43${this.nspPrefix}${packet.id}[]`);
            this.push(event, args);
        } else if (packet.type === '3') {
            const ack = this.acks.get(packet.id);
            if (ack) {
                this.acks.delete(packet.id);
                clearTimeout(ack.timer);
                ack.resolve(Array.isArray(packet.payload) ? packet.payload[0] : undefined);
            }
        } else if (packet.type === '1') {
            this.markDisconnected('io server disconnect');
            this.closeTransport();
        }
    }

    onTransportClose(event) {
        this.markDisconnected(this.closingByClient ? 'io client disconnect' : `transport close (${event.code})`);
    }

    markDisconnected(reason) {
        if (this.closed) return;
        this.closed = true;
        this.connected = false;
        this.push('disconnect', [{ reason }]);
        for (const [id, ack] of this.acks) {
            clearTimeout(ack.timer);
            ack.reject(socketError('closed', reason));
            this.acks.delete(id);
        }
        for (const waiter of [...this.waiters]) waiter.onDisconnect(reason);
    }

    closeTransport() {
        if (this.ws && this.ws.readyState <= WebSocket.OPEN) {
            try { this.ws.close(1000); } catch { /* уже закрывается */ }
        }
    }

    push(event, args) {
        this.history.push({ n: this.history.length, event, args });
        for (const waiter of [...this.waiters]) waiter.check();
    }

    // ---- API тестов ----

    mark() { return this.history.length; }

    emit(event, ...args) {
        this.send(`42${this.nspPrefix}${JSON.stringify([event, ...args])}`);
    }

    // Событие с подтверждением: результат — первый аргумент ответа сервера.
    emitWithAck(event, ...args) {
        const id = this.nextAckId++;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.acks.delete(id);
                reject(socketError('timeout', `нет подтверждения ${event} за ${DEFAULT_TIMEOUT_MS} мс`));
            }, DEFAULT_TIMEOUT_MS);
            this.acks.set(id, { resolve, reject, timer });
            try {
                this.send(`42${this.nspPrefix}${id}${JSON.stringify([event, ...args])}`);
            } catch (err) {
                clearTimeout(timer);
                this.acks.delete(id);
                reject(err);
            }
        });
    }

    // Первое событие event (начиная с since), для которого predicate(payload,
    // args) истинен; результат — payload (первый аргумент события). Если
    // сокет закрылся раньше — ошибка сразу (кроме ожидания 'disconnect').
    waitFor(event, predicate = () => true, { timeoutMs = DEFAULT_TIMEOUT_MS, since = 0 } = {}) {
        let scanned = since;
        return new Promise((resolve, reject) => {
            const finish = (err, value) => {
                clearTimeout(timer);
                this.waiters.delete(waiter);
                if (err) reject(err); else resolve(value);
                return true;
            };
            const waiter = {
                check: () => {
                    for (; scanned < this.history.length; scanned++) {
                        const entry = this.history[scanned];
                        if (entry.event === event && predicate(entry.args[0], entry.args)) {
                            scanned++;
                            return finish(null, entry.args[0]);
                        }
                    }
                    return false;
                },
                onDisconnect: (reason) => {
                    if (event !== 'disconnect') finish(socketError('closed', `${reason}, а события ${event} не было`));
                },
            };
            const timer = setTimeout(() => {
                const seen = this.history.slice(since).map(e => e.event).filter(e => e !== 'engine:ping');
                finish(socketError('timeout', `события ${event} нет за ${timeoutMs} мс (пришли: ${seen.join(', ') || 'ничего'})`));
            }, timeoutMs);
            this.waiters.add(waiter);
            if (!waiter.check() && this.closed && event !== 'disconnect') waiter.onDisconnect('сокет уже закрыт');
        });
    }

    // Полезные нагрузки всех уже полученных событий event (начиная с since).
    collect(event, { since = 0 } = {}) {
        return this.history.slice(since).filter(e => e.event === event).map(e => e.args[0]);
    }

    async close() {
        if (!this.ws) return;
        this.closingByClient = true;
        if (this.ws.readyState === WebSocket.OPEN && this.connected) {
            try { this.send(`41${this.nspPrefix}`); } catch { /* уже закрыт */ }
        }
        this.closeTransport();
        await this.closedPromise;
    }
}

// Подключение: { baseUrl, cookie, origin, xff, headers, namespace, auth, timeoutMs }.
// origin: null — без заголовка Origin.
async function connectSocket({ baseUrl, cookie, origin, xff, headers = {}, namespace = '/', auth, timeoutMs } = {}) {
    const all = { ...headers };
    if (origin !== null && origin !== undefined) all.Origin = origin;
    if (cookie) all.Cookie = cookie;
    if (xff) all['X-Forwarded-For'] = xff;
    const socket = new TestSocket({ baseUrl, headers: all, namespace, auth, timeoutMs });
    return socket.open();
}

module.exports = { connectSocket, TestSocket, parseSioPacket, socketError };
