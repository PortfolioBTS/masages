'use strict';
// Потоки очистки метаданных не-изображений (повторное ревью W7, Н0).
//
// MediaSanitizer — синхронный JS. В главном потоке PDF в 100 КБ, распаковывающийся в 100 МБ, держал цикл событий
// ~2 с: всё это время сервер не отвечал никому, а одного анонимного аккаунта хватало, чтобы держать его занятым почти
// постоянно. Ограничитель (lib/work-limiter.js) от этого не спасал: работа не уходила из главного потока.
//
// Теперь разбор идёт в lib/sanitizer-worker.js:
//   * потоки постоянные: свободный поток ждёт следующую задачу, новый создаётся, только если свободных нет (сколько
//     задач идёт одновременно, решает ограничитель вызывающего — lib/metadata-stripper.js);
//   * буфер уходит в поток копией через transfer (у вызывающего он остаётся целым);
//   * тайм-аут: поток, не закончивший разбор за timeoutMs, завершается (terminate), файл отклоняется понятным текстом,
//     следующей задаче достаётся новый поток. Отсчёт идёт с начала разбора (поток сообщает started): запуск нового
//     потока и загрузка санитайзера под нагрузкой занимают сотни миллисекунд и в тайм-аут не входят — на них свой
//     предел STARTUP_MS;
//   * предел памяти потока (resourceLimits.maxOldGenerationSizeMb): поток, упавший от нехватки памяти или по любой
//     другой причине, тоже отклоняет файл и заменяется.
// Свободный поток не держит процесс (unref): штатной остановке он не мешает.

const path = require('path');
const { Worker } = require('worker_threads');
const { logError } = require('./log-error');

const WORKER_FILE = path.join(__dirname, 'sanitizer-worker.js');
const DEFAULT_TIMEOUT_MS = 10 * 1000;
const DEFAULT_MEMORY_MB = 256;
const STARTUP_MS = 10 * 1000;

const FAILED_MESSAGE = 'Не удалось обработать файл: он слишком сложный или повреждён. Сохраните его заново и отправьте снова.';

function refusal(message) {
    const err = new Error(message);
    err.userFacing = true;
    return err;
}

// Ошибка санитайзера из потока: тот же текст и тот же признак userFacing, что и при вызове на месте.
function fromWorkerError({ name, message, userFacing }) {
    const err = new Error(message);
    err.name = name;
    if (userFacing) err.userFacing = true;
    return err;
}

function createSanitizerPool({ timeoutMs = DEFAULT_TIMEOUT_MS, memoryMb = DEFAULT_MEMORY_MB, workerFile = WORKER_FILE } = {}) {
    const idle = [];
    let seq = 0;
    let closed = false;

    function spawn() {
        return new Worker(workerFile, { resourceLimits: { maxOldGenerationSizeMb: memoryMb } });
    }

    // bytes — Uint8Array (Buffer тоже). Результат — Uint8Array очищенного файла.
    function sanitize(bytes, mime, options) {
        if (closed) return Promise.reject(new Error('Пул потоков очистки закрыт'));
        return new Promise((resolve, reject) => {
            const worker = idle.pop() || spawn();
            const id = ++seq;
            let settled = false;

            function finish(err, result, reusable) {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                worker.off('message', onMessage);
                worker.off('error', onError);
                worker.off('exit', onExit);
                if (reusable && !closed) {
                    worker.unref();
                    idle.push(worker);
                } else {
                    worker.terminate().catch(() => {});
                }
                if (err) reject(err); else resolve(result);
            }
            function onMessage(msg) {
                if (!msg || msg.id !== id) return;
                if (msg.started) {
                    clearTimeout(timer);
                    timer = setTimeout(onTimeout, timeoutMs);
                    return;
                }
                if (msg.ok) finish(null, new Uint8Array(msg.bytes), true);
                else finish(fromWorkerError(msg.error || {}), null, true);
            }
            function onError(err) {
                // В лог — только причина падения потока (нехватка памяти и т.п.), данных файла в ней нет.
                logError('[MetadataStripper] Поток очистки упал', err);
                finish(refusal(FAILED_MESSAGE), null, false);
            }
            function onExit() {
                finish(refusal(FAILED_MESSAGE), null, false);
            }
            function onTimeout() {
                console.warn('[MetadataStripper] Очистка файла не уложилась в отведённое время: поток остановлен');
                finish(refusal(FAILED_MESSAGE), null, false);
            }
            // До сообщения started — предел на запуск потока, после — на сам разбор.
            let timer = setTimeout(onTimeout, Math.max(STARTUP_MS, timeoutMs));

            worker.ref();
            worker.on('message', onMessage);
            worker.once('error', onError);
            worker.once('exit', onExit);
            const copy = new Uint8Array(bytes);
            worker.postMessage({ id, mime, options, bytes: copy.buffer }, [copy.buffer]);
        });
    }

    async function close() {
        closed = true;
        await Promise.all(idle.splice(0).map((worker) => worker.terminate()));
    }

    return { sanitize, close, stats: () => ({ idle: idle.length }) };
}

module.exports = { createSanitizerPool, DEFAULT_TIMEOUT_MS, DEFAULT_MEMORY_MB };
