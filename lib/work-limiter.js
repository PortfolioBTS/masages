'use strict';
// Ограничитель одновременной тяжёлой работы (обработка вложений, R1 п.1).
//
// Санитайзер изображений держит в памяти сотни мегабайт на файл; без потолка
// несколько параллельных загрузок исчерпывают память контейнера (OOM = отказ
// сервиса для всех). Ограничитель пускает в работу не больше `concurrency`
// задач, ещё `maxQueue` ждут в очереди, остальные получают BusyError сразу —
// HTTP-слой отвечает 503 с Retry-After, а не держит запрос и память.

class BusyError extends Error {
    constructor(message = 'Сервер занят обработкой файлов, повторите через несколько секунд') {
        super(message);
        this.name = 'BusyError';
        // busy — признак для HTTP-слоя (503); userFacing — текст можно показать как есть.
        this.busy = true;
        this.userFacing = true;
    }
}

function createLimiter({ concurrency = 1, maxQueue = 4 } = {}) {
    const limit = Math.max(1, Math.floor(concurrency));
    const queueLimit = Math.max(0, Math.floor(maxQueue));
    const waiting = [];
    let active = 0;

    function pump() {
        while (active < limit && waiting.length > 0) {
            const job = waiting.shift();
            active++;
            job();
        }
    }

    // task выполняется, когда освободится место. Ошибка задачи пробрасывается
    // вызывающему и место освобождает так же, как успех.
    function run(task) {
        if (active >= limit && waiting.length >= queueLimit) return Promise.reject(new BusyError());
        return new Promise((resolve, reject) => {
            waiting.push(() => {
                Promise.resolve().then(task).then(resolve, reject).finally(() => {
                    active--;
                    pump();
                });
            });
            pump();
        });
    }

    return { run, stats: () => ({ active, queued: waiting.length, concurrency: limit, maxQueue: queueLimit }) };
}

module.exports = { createLimiter, BusyError };
