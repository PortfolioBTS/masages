'use strict';
// Штатная остановка по SIGTERM и SIGINT (ревью W7 R2.5). Хостинг при деплое и перезапуске
// шлёт SIGTERM и ждёт ограниченное время; раньше обработчика не было, и процесс умирал
// посреди запросов и транзакций: клиенты получали обрыв, Postgres — оборванные сессии.
//
// Порядок: фоновые задачи останавливаются; новые соединения не принимаются (HTTP и
// onion-порт), простаивающие keep-alive закрываются; сокеты Socket.IO отключаются
// (клиент переподключится к новому экземпляру); идущие запросы дорабатывают; затем пул
// Postgres закрывается и процесс выходит с кодом 0. Не уложились в timeoutMs — оставшиеся
// соединения рвутся и выход с кодом 1. Повторный сигнал — выход сразу.

const { logError } = require('../lib/log-error');

const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10 * 1000;

function closeServer(server) {
    return new Promise((resolve) => {
        if (!server || typeof server.close !== 'function') return resolve();
        server.close(() => resolve());
        // Простаивающие keep-alive иначе держали бы close() до своего тайм-аута.
        if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
    });
}

function createShutdown({
    server, io, pool, jobs, getOnionListener = () => null, timeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
    exit = (code) => process.exit(code), log = (line) => console.log(line), report = logError,
    timers = { setTimeout, clearTimeout },
} = {}) {
    let stopping = null;

    async function stopEverything() {
        if (jobs && typeof jobs.stop === 'function') jobs.stop();
        const onion = getOnionListener();
        const closing = [closeServer(server), closeServer(onion)];
        // io.close() отключает сокеты и закрывает и сам HTTP-сервер — поэтому он после
        // server.close(): ожидание идущих запросов уже начато.
        if (io && typeof io.close === 'function') io.close();
        await Promise.all(closing);
        if (pool && typeof pool.end === 'function') await pool.end();
    }

    function shutdown(signal) {
        if (stopping) {
            log(`[Process] Повторный ${signal} — выход без ожидания`);
            exit(1);
            return stopping;
        }
        log(`[Process] ${signal}: остановка — новые соединения не принимаются, идущие запросы дорабатывают`);
        const timer = timers.setTimeout(() => {
            log(`[Process] Остановка не уложилась в ${timeoutMs} мс — оставшиеся соединения закрываются`);
            if (server && typeof server.closeAllConnections === 'function') server.closeAllConnections();
            exit(1);
        }, timeoutMs);
        if (timer && typeof timer.unref === 'function') timer.unref();
        stopping = stopEverything().then(() => {
            timers.clearTimeout(timer);
            log('[Process] Остановлен');
            exit(0);
        }, (err) => {
            timers.clearTimeout(timer);
            report('[Process] Ошибка при остановке', err);
            exit(1);
        });
        return stopping;
    }

    return shutdown;
}

module.exports = { createShutdown, DEFAULT_SHUTDOWN_TIMEOUT_MS };
