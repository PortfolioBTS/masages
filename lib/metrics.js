'use strict';
// Метрики в формате Prometheus (text exposition 0.0.4) без зависимостей (7.6).
//
// Принцип: метрики — агрегаты, а не журнал. В них нет id пользователей,
// комнат и сообщений, IP-адресов и путей с параметрами: HTTP считается по
// ШАБЛОНУ маршрута (/api/messages/:messageId), а не по адресу запроса. Значение
// метки задаёт код, не клиент; на случай ошибки в коде число серий каждой
// метрики ограничено (MAX_SERIES) — лишние сливаются в серию «other», и
// память не растёт от подставленных клиентом значений.
//
// /metrics отдаёт lib/routes/health.js и только по токену METRICS_TOKEN.

const { monitorEventLoopDelay } = require('perf_hooks');

const MAX_SERIES = 500;
const MAX_LABEL_VALUE_LENGTH = 80;
const METRIC_NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const HTTP_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
const KNOWN_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const NS_PER_SECOND = 1e9;

function escapeLabelValue(value) {
    return String(value).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}
function escapeHelp(text) {
    return String(text).replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}
function formatNumber(value) {
    if (Number.isNaN(value)) return 'NaN';
    if (value === Infinity) return '+Inf';
    if (value === -Infinity) return '-Inf';
    return String(value);
}

// Семейство метрик с общим именем и набором меток.
class Family {
    constructor({ name, help, type, labelNames }) {
        if (!METRIC_NAME_RE.test(name)) throw new TypeError(`некорректное имя метрики: ${name}`);
        for (const label of labelNames) {
            if (!LABEL_NAME_RE.test(label) || label === 'le') throw new TypeError(`некорректное имя метки: ${label}`);
        }
        this.name = name;
        this.help = help;
        this.type = type;
        this.labelNames = labelNames;
        this.series = new Map();
    }

    // Серия для значений меток; переполнение — серия «other».
    slot(labels) {
        let values = this.labelNames.map((label) => {
            const value = String(labels && labels[label] !== undefined ? labels[label] : '');
            return value.length > MAX_LABEL_VALUE_LENGTH ? value.slice(0, MAX_LABEL_VALUE_LENGTH) : value;
        });
        let key = values.join('\u0001');
        let slot = this.series.get(key);
        if (!slot && this.series.size >= MAX_SERIES) {
            values = this.labelNames.map(() => 'other');
            key = values.join('\u0001');
            slot = this.series.get(key);
        }
        if (!slot) {
            slot = this.create(values);
            this.series.set(key, slot);
        }
        return slot;
    }

    labelText(values, extra) {
        const pairs = this.labelNames.map((label, i) => `${label}="${escapeLabelValue(values[i])}"`);
        if (extra) pairs.push(extra);
        return pairs.length > 0 ? `{${pairs.join(',')}}` : '';
    }

    render() {
        const lines = [`# HELP ${this.name} ${escapeHelp(this.help)}`, `# TYPE ${this.name} ${this.type}`];
        for (const slot of this.series.values()) this.renderSlot(slot, lines);
        return lines;
    }
}

class CounterFamily extends Family {
    constructor(opts) { super({ ...opts, type: 'counter' }); }
    create(values) { return { values, value: 0 }; }
    renderSlot(slot, lines) { lines.push(`${this.name}${this.labelText(slot.values)} ${formatNumber(slot.value)}`); }
}

class GaugeFamily extends Family {
    constructor(opts) { super({ ...opts, type: 'gauge' }); }
    create(values) { return { values, value: 0 }; }
    renderSlot(slot, lines) { lines.push(`${this.name}${this.labelText(slot.values)} ${formatNumber(slot.value)}`); }
}

class HistogramFamily extends Family {
    constructor({ buckets, ...opts }) {
        super({ ...opts, type: 'histogram' });
        this.buckets = buckets;
    }
    create(values) { return { values, counts: this.buckets.map(() => 0), sum: 0, count: 0 }; }
    renderSlot(slot, lines) {
        let cumulative = 0;
        this.buckets.forEach((bound, i) => {
            cumulative += slot.counts[i];
            lines.push(`${this.name}_bucket${this.labelText(slot.values, `le="${formatNumber(bound)}"`)} ${cumulative}`);
        });
        lines.push(`${this.name}_bucket${this.labelText(slot.values, 'le="+Inf"')} ${slot.count}`);
        lines.push(`${this.name}_sum${this.labelText(slot.values)} ${formatNumber(slot.sum)}`);
        lines.push(`${this.name}_count${this.labelText(slot.values)} ${slot.count}`);
    }
}

// Шаблон маршрута для запроса. Маршрут Express знает свой шаблон
// (req.route.path), а для остального (статика, неизвестные адреса, сокет)
// берётся класс пути, но не сам путь.
function routeLabel(req) {
    if (req.route && req.route.path !== undefined && req.route.path !== null) {
        return `${req.baseUrl || ''}${typeof req.route.path === 'string' ? req.route.path : String(req.route.path)}`;
    }
    const pathname = String(req.originalUrl || req.url || '').split('?', 1)[0];
    if (pathname.startsWith('/socket.io')) return '/socket.io/';
    if (pathname === '/api' || pathname.startsWith('/api/')) return '/api/(unmatched)';
    return '(static)';
}

function createMetrics({ now = Date.now, startedAt = now() } = {}) {
    const families = [];
    const collectors = [];
    const loopDelay = monitorEventLoopDelay({ resolution: 20 });
    loopDelay.enable();

    function add(family) {
        if (families.some(f => f.name === family.name)) throw new Error(`метрика ${family.name} уже есть`);
        families.push(family);
        return family;
    }
    function counter(name, help, labelNames = []) {
        const family = add(new CounterFamily({ name, help, labelNames }));
        return {
            inc: (labels, n = 1) => { family.slot(labels).value += n; },
            // Для значений, накопленных снаружи (процессорное время процесса).
            set: (labels, value) => { family.slot(labels).value = value; },
        };
    }
    function gauge(name, help, labelNames = []) {
        const family = add(new GaugeFamily({ name, help, labelNames }));
        return { set: (labels, value) => { family.slot(labels).value = value; } };
    }
    function histogram(name, help, labelNames = [], buckets = HTTP_BUCKETS) {
        const family = add(new HistogramFamily({ name, help, labelNames, buckets }));
        return {
            observe: (labels, value) => {
                const slot = family.slot(labels);
                slot.sum += value;
                slot.count++;
                const i = family.buckets.findIndex(bound => value <= bound);
                if (i !== -1) slot.counts[i]++;
            },
        };
    }

    // ---- Процесс ----
    const uptime = gauge('nyxo_uptime_seconds', 'Время работы процесса, секунды');
    const memory = gauge('nyxo_process_memory_bytes', 'Память процесса, байты', ['kind']);
    const cpu = counter('nyxo_process_cpu_seconds_total', 'Использованное процессорное время, секунды', ['mode']);
    const loopLag = gauge('nyxo_eventloop_lag_seconds', 'Задержка цикла событий за период между опросами, секунды', ['quantile']);
    collectors.push(() => {
        uptime.set({}, Math.round((now() - startedAt) / 1000));
        const mem = process.memoryUsage();
        memory.set({ kind: 'rss' }, mem.rss);
        memory.set({ kind: 'heap_used' }, mem.heapUsed);
        memory.set({ kind: 'heap_total' }, mem.heapTotal);
        const usage = process.cpuUsage();
        cpu.set({ mode: 'user' }, usage.user / 1e6);
        cpu.set({ mode: 'system' }, usage.system / 1e6);
        if (loopDelay.count > 0) {
            loopLag.set({ quantile: '0.5' }, loopDelay.percentile(50) / NS_PER_SECOND);
            loopLag.set({ quantile: '0.99' }, loopDelay.percentile(99) / NS_PER_SECOND);
            loopLag.set({ quantile: '1' }, loopDelay.max / NS_PER_SECOND);
        }
        loopDelay.reset();
    });

    // ---- HTTP ----
    const httpRequests = counter('nyxo_http_requests_total',
        'HTTP-запросы по шаблону маршрута; outcome — поле success в JSON-ответе API (none — не JSON API)',
        ['method', 'route', 'status', 'outcome']);
    const httpDuration = histogram('nyxo_http_request_duration_seconds', 'Время обработки HTTP-запроса по шаблону маршрута, секунды', ['route']);

    function httpMiddleware() {
        return function metricsMiddleware(req, res, next) {
            const started = process.hrtime.bigint();
            let outcome = 'none';
            const json = res.json;
            res.json = function patchedJson(body) {
                if (body && typeof body === 'object' && typeof body.success === 'boolean') outcome = body.success ? 'ok' : 'fail';
                return json.call(this, body);
            };
            // close срабатывает один раз и после нормального ответа, и при
            // обрыве соединения клиентом.
            res.once('close', () => {
                const route = routeLabel(req);
                const finished = res.writableFinished;
                httpRequests.inc({
                    method: KNOWN_METHODS.has(req.method) ? req.method : 'OTHER',
                    route,
                    status: finished ? `${Math.floor(res.statusCode / 100)}xx` : 'aborted',
                    outcome,
                });
                httpDuration.observe({ route }, Number(process.hrtime.bigint() - started) / NS_PER_SECOND);
            });
            next();
        };
    }

    // ---- События приложения ----
    const rateLimited = counter('nyxo_rate_limited_total', 'Запросы, отклонённые лимитером (429)', ['limiter']);
    const limitStoreErrors = counter('nyxo_limits_store_errors_total', 'Сбои хранилища лимитов (503 busy)', ['limiter']);
    const powRejected = counter('nyxo_pow_rejected_total', 'Отклонённые решения proof-of-work', ['reason']);
    const csrfRejected = counter('nyxo_csrf_rejected_total', 'Запросы, отклонённые проверкой CSRF-токена');
    const originRejected = counter('nyxo_origin_rejected_total', 'Запросы, отклонённые проверкой Origin');
    const registrations = counter('nyxo_registrations_total', 'Созданные аккаунты');
    const deletions = counter('nyxo_account_deletions_total', 'Удалённые аккаунты по причине', ['reason']);
    const jobRuns = counter('nyxo_job_runs_total', 'Проходы фоновых задач', ['job', 'result']);

    // ---- Внешние источники чисел: пул Postgres и сокеты ----
    const poolGauge = gauge('nyxo_pg_pool_connections', 'Соединения пула Postgres', ['state']);
    const socketsGauge = gauge('nyxo_sockets_connected', 'Подключённые сокеты этого процесса');
    function attachRuntime({ pool, io } = {}) {
        collectors.push(() => {
            if (pool) {
                poolGauge.set({ state: 'total' }, pool.totalCount);
                poolGauge.set({ state: 'idle' }, pool.idleCount);
                poolGauge.set({ state: 'waiting' }, pool.waitingCount);
            }
            if (io && io.engine) socketsGauge.set({}, io.engine.clientsCount);
        });
    }

    function render() {
        for (const collect of collectors) collect();
        return `${families.flatMap(family => family.render()).join('\n')}\n`;
    }

    return {
        counter, gauge, histogram, render, attachRuntime, httpMiddleware,
        stop: () => loopDelay.disable(),
        // Именованные события — чтобы server.js не знал имён метрик.
        rateLimited: (limiter) => rateLimited.inc({ limiter }),
        limitStoreError: (limiter) => limitStoreErrors.inc({ limiter }),
        powRejected: (reason) => powRejected.inc({ reason }),
        csrfRejected: () => csrfRejected.inc(),
        originRejected: () => originRejected.inc(),
        registered: () => registrations.inc(),
        accountsDeleted: (reason, n = 1) => { if (n > 0) deletions.inc({ reason }, n); },
        jobRan: (job, ran) => jobRuns.inc({ job, result: ran ? 'ok' : 'skipped' }),
    };
}

module.exports = { createMetrics, routeLabel, MAX_SERIES, HTTP_BUCKETS };
