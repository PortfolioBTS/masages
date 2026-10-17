'use strict';
// Файлы вложений на диске: папка загрузок (создаётся и проверяется на запись при старте),
// удаление файлов по file_url, временные файлы обработки и огрубление времени файла.
// Вынесено из server.js; приём multipart (multer) — в http/middleware/upload.js.

const path = require('path');
const fs = require('fs');
const { logError } = require('../../lib/log-error');
// Огрубление времени сообщений и файлов (раздел 11 контракта).
const { floorToHour } = require('../../lib/coarse-time');

// Итоговое имя файла на диске должно состоять только из "безопасных" для
// файловой системы символов — доп. страховка на случай, если MIME_EXTENSIONS
// когда-нибудь получит некорректное значение (п.2 аудита, "валидировать
// итоговое имя файла регуляркой").
const SAFE_FILENAME_RE = /^[\w.-]+$/;

async function readFileHead(filePath, length) {
    const handle = await fs.promises.open(filePath, 'r');
    try {
        const buffer = Buffer.alloc(length);
        const { bytesRead } = await handle.read(buffer, 0, length, 0);
        return buffer.subarray(0, bytesRead);
    } finally {
        await handle.close();
    }
}

// mtime и atime файла вложения — с точностью до часа, вниз: по времени
// изменения файла иначе восстанавливалось бы время сообщения до секунды
// (раздел 11 контракта). Уборщик файлов-сирот учитывает округление: его порог
// возраста не меньше двух часов (lib/coarse-time.js). Сбой не фатален.
async function coarsenFileTimes(filePath) {
    try {
        const hour = floorToHour();
        await fs.promises.utimes(filePath, hour, hour);
    } catch (err) {
        logError('[Uploads] Не удалось округлить время файла', err);
    }
}

function createUploads(ctx) {
    const { UPLOADS_DIR } = ctx;

    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    try {
        const probe = path.join(UPLOADS_DIR, `.write-test-${process.pid}`);
        fs.writeFileSync(probe, '');
        fs.unlinkSync(probe);
        console.log(`[Uploads] Папка вложений: ${UPLOADS_DIR}`);
    } catch (err) {
        logError(`[Uploads] Нет доступа на запись в ${UPLOADS_DIR}, загрузка файлов работать не будет`, err);
    }

    // Удаляет файлы вложений с диска по их file_url ("/uploads/<name>").
    // Вызывается после того, как ссылающиеся на них сообщения удалены из БД.
    function removeUploadedFiles(fileUrls) {
        for (const url of fileUrls) {
            if (typeof url !== 'string' || !url.startsWith('/uploads/')) continue;
            const filename = path.basename(url);
            if (!SAFE_FILENAME_RE.test(filename)) continue;
            fs.promises.unlink(path.join(UPLOADS_DIR, filename)).catch(err => {
                // Имя файла в лог не идёт (по нему находят сообщение): logError убирает
                // путь и из текста системной ошибки.
                if (err.code !== 'ENOENT') logError('[Uploads] Не удалось удалить файл вложения', err);
            });
        }
    }

    // multer(upload.single('file')) уже записал файл на диск ДО этого хендлера —
    // значит, ранние return (401/400/404) должны сами убирать за собой, иначе
    // каждая неудачная/подделанная попытка загрузки будет накапливать файлы-сироты.
    function cleanupUploadedFile(file) {
        if (!file) return;
        fs.promises.unlink(path.join(UPLOADS_DIR, file.filename)).catch(() => {});
    }

    function rejectUpload(res, file, status, message) {
        cleanupUploadedFile(file);
        return res.status(status).json({ success: false, message });
    }

    // То же с готовым телом ответа (коды ошибок контракта порядка сообщений).
    function rejectUploadWith(res, file, status, body) {
        cleanupUploadedFile(file);
        return res.status(status).json(body);
    }

    return { removeUploadedFiles, cleanupUploadedFile, rejectUpload, rejectUploadWith };
}

module.exports = { createUploads, SAFE_FILENAME_RE, readFileHead, coarsenFileTimes };
