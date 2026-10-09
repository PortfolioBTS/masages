'use strict';
// Реестр фоновых задач сервера (чистки просроченного, продление
// активности, уборка временных файлов).
//
// Задача — { name, run, firstDelayMs, intervalMs, exclusive, maintenance, testTick }:
//   * firstDelayMs — первый запуск через столько мс после start() (0 — сразу,
//     в следующем витке цикла событий); не задан — отдельного первого
//     запуска нет;
//   * intervalMs — запуски каждые столько мс, отсчёт от start() (как у
//     setInterval, независимо от первого запуска); не задан — задача разовая;
//   * exclusive (по умолчанию true) — через runExclusive (lib/advisory-locks.js):
//     в каждый момент задачу выполняет один экземпляр сервера на базу, у
//     остальных запуск пропускается. false — для задач про состояние САМОГО
//     процесса (его сокеты, его временные файлы): их выполняет каждый;
//   * maintenance — тестовая ручка NYXO_TEST_MAINTENANCE_MS (сервер передаёт
//     её только при NODE_ENV=test) заменяет firstDelayMs и intervalMs на N мс:
//     сквозные тесты не ждут минутами;
//   * testTick — после каждого выполненного (не пропущенного из-за
//     блокировки) прохода в тестовом режиме в лог пишется
//     «[Test] maintenance tick <n>»: по нему тест знает, что проход был.
//
// Новые задачи: из server.js — jobs.register({...}) в блоке задач; из
// lib-модуля — файл с функцией jobs(ctx) → [описания задач] и одна строка
// `require('./<имя>'),` в JOB_MODULES ниже.

const { logError } = require('../log-error');

const JOB_MODULES = [
    // Уборка просроченных строк лимитов и PoW (7.4).
    require('../pg-limits'),
];

const DEFAULT_TIMERS = { setTimeout, setInterval, setImmediate, clearTimeout, clearInterval, clearImmediate };

function checkDelay(job, field) {
    const value = job[field];
    if (value === undefined || value === null) return;
    if (!Number.isInteger(value) || value < 0) throw new RangeError(`задача ${job.name}: ${field} должен быть целым числом мс ≥ 0`);
}

function createJobScheduler({
    runExclusive,
    maintenanceMs = null,
    log = console.log,
    report = logError,
    timers = DEFAULT_TIMERS,
    onRun = null,
} = {}) {
    if (maintenanceMs !== null && !(Number.isInteger(maintenanceMs) && maintenanceMs > 0)) {
        throw new RangeError('maintenanceMs — целое число мс > 0 или null');
    }
    const jobs = new Map();
    const handles = [];
    let started = false;
    let ticks = 0;

    function register(job) {
        if (!job || typeof job.name !== 'string' || job.name === '') throw new TypeError('у задачи нет имени');
        if (typeof job.run !== 'function') throw new TypeError(`задача ${job.name}: нет функции run`);
        if (jobs.has(job.name)) throw new Error(`задача ${job.name} уже зарегистрирована`);
        if (started) throw new Error(`задача ${job.name}: регистрация после start()`);
        checkDelay(job, 'firstDelayMs');
        checkDelay(job, 'intervalMs');
        if (job.exclusive !== false && typeof runExclusive !== 'function') {
            throw new TypeError(`задача ${job.name}: для exclusive-задачи нужен runExclusive`);
        }
        jobs.set(job.name, { exclusive: true, maintenance: false, testTick: false, ...job });
    }

    // true — проход выполнен полностью; false — пропущен или упал (ошибка в логе).
    async function runJob(name) {
        const job = jobs.get(name);
        if (!job) throw new Error(`нет задачи ${name}`);
        let ran;
        if (job.exclusive) {
            ran = await runExclusive(job.name, job.run);
        } else {
            try {
                await job.run();
                ran = true;
            } catch (err) {
                report(`[Jobs] ${job.name}`, err);
                ran = false;
            }
        }
        if (ran && job.testTick && maintenanceMs) log(`[Test] maintenance tick ${++ticks}`);
        // Для метрик: проход выполнен (true) или пропущен/упал (false). Сбой хука
        // не должен влиять на саму задачу.
        if (onRun) {
            try { onRun(name, ran); } catch (err) { report('[Jobs] onRun', err); }
        }
        return ran;
    }

    // Действующие задержки задачи (с учётом тестовой ручки).
    function schedule(job) {
        const knob = job.maintenance && maintenanceMs ? maintenanceMs : null;
        const first = job.firstDelayMs === undefined || job.firstDelayMs === null ? null : (knob || job.firstDelayMs);
        const every = job.intervalMs === undefined || job.intervalMs === null ? null : (knob || job.intervalMs);
        return { first, every };
    }

    function start() {
        if (started) throw new Error('планировщик задач уже запущен');
        started = true;
        // Запуск из таймера: ошибки run уже перехвачены (runExclusive и
        // runJob), этот catch — на случай ошибки в самом планировщике.
        const fire = (name) => () => { runJob(name).catch(err => report(`[Jobs] ${name}`, err)); };
        for (const job of jobs.values()) {
            const { first, every } = schedule(job);
            if (first === 0) handles.push(['immediate', timers.setImmediate(fire(job.name))]);
            else if (first !== null) handles.push(['timeout', timers.setTimeout(fire(job.name), first)]);
            if (every !== null) handles.push(['interval', timers.setInterval(fire(job.name), every)]);
        }
        if (maintenanceMs) log(`[Test] NYXO_TEST_MAINTENANCE_MS=${maintenanceMs}: задачи обслуживания каждые ${maintenanceMs} мс`);
    }

    function stop() {
        for (const [kind, handle] of handles.splice(0)) {
            if (kind === 'immediate') timers.clearImmediate(handle);
            else if (kind === 'timeout') timers.clearTimeout(handle);
            else timers.clearInterval(handle);
        }
    }

    return { register, start, stop, runJob, schedule: (name) => schedule(jobs.get(name)), names: () => [...jobs.keys()] };
}

// Задачи lib-модулей из JOB_MODULES: каждый экспортирует jobs(ctx) → [описания].
function registerJobModules(scheduler, ctx, modules = JOB_MODULES) {
    for (const mod of modules) {
        for (const job of mod.jobs(ctx)) scheduler.register(job);
    }
}

module.exports = { createJobScheduler, registerJobModules, JOB_MODULES };
