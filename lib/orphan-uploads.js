'use strict';
// Уборщик файлов-сирот в папке вложений (ревью W7 R2.5; обещан в roadmap, threat-model,
// message-ordering.md §5.2 и §11, sealed-sender.md раздел 14, docs/ops/backups.md).
//
// Сирота — файл вложения, на который не ссылается ни одна строка messages.file_url:
//   * файлы строк, удалённых каскадом (удаление аккаунта, пересоздание чата с ботом,
//     снос комнаты): код удаления их не трогает, это работа уборщика;
//   * файл не удалился после COMMIT удаления или процесс упал между записью файла и
//     вставкой строки;
//   * база и volume восстановлены из неатомарных снимков.
//
// Что удаляется — только обычные файлы, у которых одновременно:
//   * имя по шаблону загрузок этой версии: 32 hex-символа (16 случайных байт,
//     src/http/middleware/upload.js) и расширение из MIME_EXTENSIONS, .bin или без него.
//     Чужие файлы и папки на volume (lost+found, временные копии очистки метаданных —
//     их убирает cleanupStaleTempFiles) не трогаются;
//   * mtime старше ORPHAN_MIN_AGE_MS (2 ч, lib/coarse-time.js): mtime файла огрублён вниз
//     до часа, а свежая загрузка живёт без строки, пока идут обработка и вставка;
//   * нет строки messages с этим file_url — проверка пачками прямо перед удалением.
// В лог — только числа: имя файла указывает на сообщение.

const fs = require('fs');
const path = require('path');
const { MIME_EXTENSIONS, ENCRYPTED_FILE_EXTENSION } = require('./security-utils');
const { ORPHAN_MIN_AGE_MS, orphanAgeThresholdMs } = require('./coarse-time');
const { logError } = require('./log-error');

const UPLOAD_NAME_RE = /^[0-9a-f]{32}(\.[a-z0-9]+)?$/;
const UPLOAD_EXTENSIONS = new Set(['', ENCRYPTED_FILE_EXTENSION, ...Object.values(MIME_EXTENSIONS)]);
const DEFAULT_BATCH = 500;

function isUploadFileName(name) {
    const match = UPLOAD_NAME_RE.exec(name);
    return Boolean(match) && UPLOAD_EXTENSIONS.has(match[1] || '');
}

function defaultLog(line) {
    console.log(line);
}

// query(sql, params) → rows (dbAll сервера). Возвращает { candidates, removed, failed }.
async function sweepOrphanUploads({
    uploadsDir, query, minAgeMs = ORPHAN_MIN_AGE_MS, now = Date.now(), batchSize = DEFAULT_BATCH,
    fsApi = fs.promises, log = defaultLog, report = logError,
}) {
    const ageMs = orphanAgeThresholdMs(minAgeMs);
    let entries;
    try {
        entries = await fsApi.readdir(uploadsDir, { withFileTypes: true });
    } catch (err) {
        if (err && err.code === 'ENOENT') return { candidates: 0, removed: 0, failed: 0 };
        throw err;
    }
    const candidates = [];
    for (const entry of entries) {
        if (!entry.isFile() || !isUploadFileName(entry.name)) continue;
        try {
            const stats = await fsApi.stat(path.join(uploadsDir, entry.name));
            if (now - stats.mtimeMs >= ageMs) candidates.push(entry.name);
        } catch {
            // Файл удалён параллельно — уже не сирота.
        }
    }
    let removed = 0;
    let failed = 0;
    for (let i = 0; i < candidates.length; i += batchSize) {
        const names = candidates.slice(i, i + batchSize);
        const rows = await query('SELECT file_url FROM messages WHERE file_url = ANY($1::text[])', [names.map(name => `/uploads/${name}`)]);
        const referenced = new Set(rows.map(row => row.file_url));
        for (const name of names) {
            if (referenced.has(`/uploads/${name}`)) continue;
            try {
                await fsApi.unlink(path.join(uploadsDir, name));
                removed++;
            } catch (err) {
                if (err && err.code === 'ENOENT') continue;
                failed++;
                report('[Uploads] Не удалось удалить файл-сироту', err);
            }
        }
    }
    if (removed > 0 || failed > 0) {
        log(`[Uploads] Уборка файлов-сирот: удалено ${removed}${failed > 0 ? `, не удалось ${failed}` : ''}`);
    }
    return { candidates: candidates.length, removed, failed };
}

// Задача для планировщика: проход не начинается, пока не кончился предыдущий (каталог
// большой, а в тестовом режиме проходы идут каждые несколько сотен мс).
function createOrphanSweeper(options) {
    let running = null;
    return function runSweep() {
        if (running) return running;
        running = sweepOrphanUploads(options).finally(() => { running = null; });
        return running;
    };
}

module.exports = { isUploadFileName, sweepOrphanUploads, createOrphanSweeper, UPLOAD_NAME_RE };
