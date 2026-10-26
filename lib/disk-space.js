'use strict';
// Свободное место папки вложений (W7 R1 п.3): без контроля один поток загрузок мог
// заполнить volume, и тогда падали бы запись сессий, временных файлов и т.п. рядом.
// Порог - UPLOAD_MIN_FREE_MB; ниже него новые загрузки отклоняются понятным ответом.
// Результат statfs кэшируется на несколько секунд: проверка стоит на каждой загрузке.
// Не удалось узнать (платформа, права) - загрузку не блокируем и один раз пишем в лог.
// Загрузки, которые пишутся прямо сейчас, держат резерв (tryReserve): иначе несколько одновременных загрузок
// проходили проверку разом и вместе уходили ниже порога (повторное ревью W7, Н8). Снятый резерв сбрасывает кэш:
// записанный файл виден следующей проверке.

const fs = require('fs');
const { logError } = require('./log-error');

function createDiskGuard({ dir, minFreeBytes, ttlMs = 5000, statfs = fs.promises.statfs, now = Date.now }) {
    let cached = null; // { at, freeBytes }
    let reportedUnknown = false;
    let reserved = 0;

    async function freeBytes() {
        if (cached && now() - cached.at < ttlMs) return cached.freeBytes;
        try {
            const stats = await statfs(dir);
            const free = Number(stats.bavail) * Number(stats.bsize);
            cached = { at: now(), freeBytes: free };
            return free;
        } catch (err) {
            if (!reportedUnknown) {
                reportedUnknown = true;
                logError('[Uploads] Не удалось узнать свободное место папки вложений, проверка порога отключена', err);
            }
            return null;
        }
    }

    const noReservation = () => {};

    return {
        // true - можно принимать файл (места хватает или оно неизвестно).
        async hasRoom(extraBytes = 0) {
            if (!(minFreeBytes > 0)) return true;
            const free = await freeBytes();
            return free === null || free - reserved - extraBytes >= minFreeBytes;
        },
        // Резерв bytes на время записи файла: функция-освобождение (вызывать один раз, повтор безвреден) или null —
        // места не хватает с учётом идущих загрузок. Проверка и учёт резерва идут без await между ними, поэтому
        // одновременные загрузки не проходят по одному и тому же остатку.
        async tryReserve(bytes) {
            if (!(minFreeBytes > 0)) return noReservation;
            const free = await freeBytes();
            if (free === null) return noReservation;
            if (free - reserved - bytes < minFreeBytes) return null;
            reserved += bytes;
            let released = false;
            return () => {
                if (released) return;
                released = true;
                reserved -= bytes;
                cached = null;
            };
        },
        freeBytes,
    };
}

module.exports = { createDiskGuard };
