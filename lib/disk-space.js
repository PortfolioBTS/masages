'use strict';
// Свободное место папки вложений (W7 R1 п.3): без контроля один поток загрузок мог
// заполнить volume, и тогда падали бы запись сессий, временных файлов и т.п. рядом.
// Порог - UPLOAD_MIN_FREE_MB; ниже него новые загрузки отклоняются понятным ответом.
// Результат statfs кэшируется на несколько секунд: проверка стоит на каждой загрузке.
// Не удалось узнать (платформа, права) - загрузку не блокируем и один раз пишем в лог.

const fs = require('fs');
const { logError } = require('./log-error');

function createDiskGuard({ dir, minFreeBytes, ttlMs = 5000, statfs = fs.promises.statfs, now = Date.now }) {
    let cached = null; // { at, freeBytes }
    let reportedUnknown = false;

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

    return {
        // true - можно принимать файл (места хватает или оно неизвестно).
        async hasRoom(extraBytes = 0) {
            if (!(minFreeBytes > 0)) return true;
            const free = await freeBytes();
            return free === null || free - extraBytes >= minFreeBytes;
        },
        freeBytes,
    };
}

module.exports = { createDiskGuard };
