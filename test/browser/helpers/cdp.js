'use strict';
// Минимальный клиент Chrome DevTools Protocol поверх встроенного в Node
// WebSocket (новых зависимостей нет).
//
// Одно соединение — с браузером целиком (ws://…/devtools/browser/<id>); вкладки
// подключаются как «плоские» сессии (Target.attachToTarget, flatten: true) и
// различаются полем sessionId. Так одно соединение обслуживает все вкладки
// профиля, а закрытая вкладка не рвёт остальные.

class CdpError extends Error {
    constructor(method, error) {
        super(`CDP ${method}: ${error.message}${error.data ? ` (${error.data})` : ''}`);
        this.code = error.code;
    }
}

class CdpConnection {
    constructor(url) {
        this.url = url;
        this.nextId = 1;
        this.pending = new Map();      // id -> { resolve, reject, method }
        this.listeners = [];           // { sessionId, event, handler }
        this.closed = false;
        this.ws = null;
    }

    open({ timeoutMs = 10000 } = {}) {
        return new Promise((resolve, reject) => {
            const ws = new WebSocket(this.url);
            this.ws = ws;
            const timer = setTimeout(() => {
                reject(new Error(`CDP: не удалось подключиться к ${this.url} за ${timeoutMs} мс`));
                try { ws.close(); } catch { /* уже закрыт */ }
            }, timeoutMs);
            ws.addEventListener('open', () => { clearTimeout(timer); resolve(this); }, { once: true });
            ws.addEventListener('error', () => { clearTimeout(timer); reject(new Error(`CDP: ошибка соединения с ${this.url}`)); }, { once: true });
            ws.addEventListener('message', event => this.onMessage(event.data));
            ws.addEventListener('close', () => this.onClose());
        });
    }

    onMessage(raw) {
        let message;
        try {
            message = JSON.parse(typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8'));
        } catch {
            return;
        }
        if (message.id !== undefined) {
            const call = this.pending.get(message.id);
            if (!call) return;
            this.pending.delete(message.id);
            if (message.error) call.reject(new CdpError(call.method, message.error));
            else call.resolve(message.result || {});
            return;
        }
        // Обработчик может бросить исключение — оно не должно ломать разбор
        // следующих сообщений.
        for (const listener of [...this.listeners]) {
            if (listener.event !== message.method) continue;
            if ((listener.sessionId || null) !== (message.sessionId || null)) continue;
            try { listener.handler(message.params || {}); } catch (err) { this.onHandlerError(err); }
        }
    }

    onHandlerError(err) {
        // Ошибка обработчика события — ошибка самого теста: всплывёт при ближайшей проверке.
        this.handlerError = this.handlerError || err;
    }

    onClose() {
        this.closed = true;
        for (const call of this.pending.values()) call.reject(new Error(`CDP: соединение закрыто до ответа на ${call.method}`));
        this.pending.clear();
    }

    send(method, params = {}, sessionId = null) {
        if (this.closed || !this.ws || this.ws.readyState !== 1) return Promise.reject(new Error(`CDP: соединение закрыто (${method})`));
        const id = this.nextId++;
        const message = { id, method, params };
        if (sessionId) message.sessionId = sessionId;
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject, method });
            this.ws.send(JSON.stringify(message));
        });
    }

    // Подписка на событие сессии (sessionId = null — события самого браузера).
    // Возвращает функцию отписки.
    on(sessionId, event, handler) {
        const listener = { sessionId: sessionId || null, event, handler };
        this.listeners.push(listener);
        return () => {
            const index = this.listeners.indexOf(listener);
            if (index >= 0) this.listeners.splice(index, 1);
        };
    }

    // Одно событие с условием; без совпадения за timeoutMs — ошибка.
    waitForEvent(sessionId, event, predicate = () => true, { timeoutMs = 15000, what = event } = {}) {
        return new Promise((resolve, reject) => {
            const off = this.on(sessionId, event, (params) => {
                if (!predicate(params)) return;
                clearTimeout(timer);
                off();
                resolve(params);
            });
            const timer = setTimeout(() => {
                off();
                reject(new Error(`CDP: не дождались события ${what} за ${timeoutMs} мс`));
            }, timeoutMs);
        });
    }

    close() {
        this.closed = true;
        if (this.ws && this.ws.readyState <= 1) {
            try { this.ws.close(); } catch { /* уже закрыт */ }
        }
    }
}

module.exports = { CdpConnection, CdpError };
