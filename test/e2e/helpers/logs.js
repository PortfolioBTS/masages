'use strict';
// Логи процесса сервера — в памяти теста (stdout и stderr построчно).
//
// Буфер один на сервер и переживает его рестарты: перед действием, после
// которого ждём строку, берут метку mark(), а потом waitFor(re, { from }).
// Так же ждут маркеры фоновых задач, которые идут уже после listen
// (например, будущая разовая очистка легаси после старта):
//
//     const mark = server.logs.mark();
//     await server.restart();
//     await server.logs.waitFor(/\[Legacy\] .../, { from: mark });
//
// waitFor ничего не опрашивает: проверяет уже пришедшие строки и ждёт
// новых; если процесс сервера завершился раньше, сразу падает с хвостом лога.

const DEFAULT_TIMEOUT_MS = 10000;

function toMatcher(pattern) {
    if (pattern instanceof RegExp) {
        const re = new RegExp(pattern.source, pattern.flags.replace('g', '').replace('y', ''));
        return (text) => re.exec(text);
    }
    const needle = String(pattern);
    return (text) => (text.includes(needle) ? [needle] : null);
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

class LogBuffer {
    constructor({ limit = 50000 } = {}) {
        this.limit = limit;
        this.lines = [];          // { n, stream, text }
        this.offset = 0;          // номер первой хранимой строки
        this.partial = new Map(); // недописанный хвост по потокам
        this.waiters = new Set();
        this.exitInfo = null;     // процесс завершился (до следующего старта)
    }

    get size() { return this.offset + this.lines.length; }

    // Метка «отсюда»: номер следующей строки.
    mark() { return this.size; }

    attach(stream, name) {
        stream.setEncoding('utf8');
        stream.on('data', (chunk) => this.write(name, chunk));
    }

    write(name, chunk) {
        const parts = ((this.partial.get(name) || '') + chunk).split(/\r?\n/);
        this.partial.set(name, parts.pop());
        for (const text of parts) this.add(name, text);
    }

    flush() {
        for (const [name, rest] of this.partial) if (rest) this.add(name, rest);
        this.partial.clear();
    }

    add(stream, text) {
        this.lines.push({ n: this.size, stream, text });
        if (this.lines.length > this.limit) {
            const drop = this.lines.length - this.limit;
            this.lines.splice(0, drop);
            this.offset += drop;
        }
        for (const waiter of [...this.waiters]) waiter.check();
    }

    // Служебная строка харнесса (старт, рестарт, остановка) — видна в
    // сохранённом логе упавшего теста.
    note(text) { this.add('harness', `--- ${text}`); }

    processStarted() { this.exitInfo = null; }

    processExited(info) {
        this.flush();
        this.exitInfo = info;
        for (const waiter of [...this.waiters]) waiter.onExit();
    }

    entries({ from = 0 } = {}) { return this.lines.filter(l => l.n >= from); }

    text({ from = 0 } = {}) {
        return this.entries({ from }).map(l => (l.stream === 'stdout' ? l.text : `[${l.stream}] ${l.text}`)).join('\n');
    }

    tail(count = 100) {
        return this.lines.slice(-count).map(l => (l.stream === 'stdout' ? l.text : `[${l.stream}] ${l.text}`)).join('\n');
    }

    find(pattern, { from = 0 } = {}) {
        const match = toMatcher(pattern);
        for (const line of this.entries({ from })) {
            const m = match(line.text);
            if (m) return { n: line.n, text: line.text, match: m };
        }
        return null;
    }

    count(pattern, { from = 0 } = {}) {
        const match = toMatcher(pattern);
        return this.entries({ from }).filter(l => match(l.text)).length;
    }

    // Первая строка (начиная с from), подходящая под pattern: { n, text, match }.
    waitFor(pattern, { from = 0, timeoutMs = DEFAULT_TIMEOUT_MS, failOnExit = true } = {}) {
        const match = toMatcher(pattern);
        let scanned = from;
        return new Promise((resolve, reject) => {
            const waiter = {
                check: () => {
                    for (let i = Math.max(0, scanned - this.offset); i < this.lines.length; i++) {
                        const line = this.lines[i];
                        scanned = line.n + 1;
                        const m = match(line.text);
                        if (m) return finish(null, { n: line.n, text: line.text, match: m });
                    }
                    return false;
                },
                onExit: () => {
                    if (failOnExit) finish(new Error(`сервер завершился (${JSON.stringify(this.exitInfo)}), а строки ${pattern} в логе нет.\n${this.tail(40)}`));
                },
            };
            const timer = setTimeout(() => finish(new Error(`за ${timeoutMs} мс в логе не появилось ${pattern}.\nХвост лога:\n${this.tail(40)}`)), timeoutMs);
            const finish = (err, value) => {
                clearTimeout(timer);
                this.waiters.delete(waiter);
                if (err) reject(err); else resolve(value);
                return true;
            };
            this.waiters.add(waiter);
            if (!waiter.check() && failOnExit && this.exitInfo) waiter.onExit();
        });
    }

    // В логах не должно быть идентифицирующих данных: id, имён, кодов,
    // кодов приглашений, email, IP, id сессий. Числа ищутся целиком (123 не
    // находится внутри 51234), строки — как есть.
    assertNoSensitive(values = {}, { from = 0 } = {}) {
        const checks = [];
        for (const [kind, list] of Object.entries(values)) {
            for (const value of [].concat(list || [])) {
                if (value === undefined || value === null || value === '') continue;
                const text = String(value);
                const re = /^\d+$/.test(text) ? new RegExp(`(?<!\\d)${text}(?!\\d)`) : new RegExp(escapeRe(text));
                checks.push({ kind, text, re });
            }
        }
        const found = [];
        for (const line of this.entries({ from })) {
            for (const check of checks) {
                if (check.re.test(line.text)) found.push(`${check.kind} «${check.text}» в строке ${line.n}: ${line.text}`);
            }
        }
        if (found.length > 0) {
            throw new Error(`в логах сервера найдены идентифицирующие данные (${found.length}):\n${found.slice(0, 20).join('\n')}`);
        }
    }
}

module.exports = { LogBuffer, DEFAULT_TIMEOUT_MS };
