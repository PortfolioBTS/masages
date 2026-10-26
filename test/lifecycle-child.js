'use strict';
// Помощник test/lifecycle.test.js: отдельный процесс с настоящим src/lifecycle.js и заглушками вместо
// сервера, сокетов, пула и задач. Процесс выполняет сценарий и сам печатает события строками «EV {json}»:
// родитель по ним проверяет порядок запуска и остановки и по коду выхода - поведение страховочных обработчиков.
// Запуск: node test/lifecycle-child.js <ok|init-fail|init-locked> [uncaught|rejection|SIGTERM|SIGINT]

const { createLifecycle } = require('../src/lifecycle');
const { LOCK_NOT_AVAILABLE } = require('../lib/advisory-locks');

const [scenario, action] = process.argv.slice(2);
const ev = (name, extra = {}) => console.log('EV ' + JSON.stringify({ ev: name, ...extra }));

const readiness = { migrated: false };
const server = {
    listen(port, host, onListening) {
        ev('listen', { port, host, migrated: readiness.migrated });
        setImmediate(onListening);
    },
    close(onClosed) {
        ev('server.close');
        setImmediate(onClosed);
    },
    closeIdleConnections() {},
    closeAllConnections() {},
};
const io = { close() { ev('io.close'); } };
const pool = { end: async () => ev('pool.end') };

// Поле detail у ошибки - как у ошибок Postgres: значения строк, в лог попадать не должны.
const secretError = (message) => Object.assign(new Error(message), { detail: 'SECRET-DETAIL' });

function afterStart() {
    if (action === 'uncaught') {
        // Исключение из таймера: никто его не ловит.
        setTimeout(() => { throw secretError('boom'); }, 10);
    } else if (action === 'rejection') {
        Promise.reject(secretError('rej'));
        // Процесс должен пережить необработанный reject: сам выходит с кодом 0.
        setTimeout(() => { ev('alive'); process.exit(0); }, 300);
    } else if (action === 'SIGTERM' || action === 'SIGINT') {
        // Тот же вызов слушателей, что и при настоящем сигнале (на Windows child.kill() SIGTERM не доставляет).
        setImmediate(() => process.emit(action));
    }
}

const jobs = {
    start() { ev('jobs.start'); afterStart(); },
    stop() { ev('jobs.stop'); },
};

const initDatabaseExclusive = async () => {
    if (scenario === 'init-fail') throw Object.assign(new Error('Postgres недоступен'), { code: 'ECONNREFUSED' });
    if (scenario === 'init-locked') throw Object.assign(new Error('таблица занята'), { code: LOCK_NOT_AVAILABLE });
    ev('migrated');
};

createLifecycle({
    IS_PRODUCTION: false, PORT: 3999, HOST: '127.0.0.1', readiness, server, io, pool, initDatabaseExclusive, jobs,
}).start();
