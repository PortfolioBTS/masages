'use strict';
// GET /uploads/:filename — выдача вложения участнику сообщения. Вынесено из server.js.

const path = require('path');
const { isInlineUpload } = require('../../../lib/security-utils');
const { SAFE_FILENAME_RE } = require('../../services/uploads');

function register(app, ctx) {
    const { UPLOADS_DIR, userCanAccessFile } = ctx;

    app.get('/uploads/:filename', async (req, res) => {
        if (!req.session.userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
        const filename = path.basename(req.params.filename);
        if (!SAFE_FILENAME_RE.test(filename)) return res.status(404).json({ success: false, message: 'Файл не найден' });
        const allowed = await userCanAccessFile(req.session.userId, filename);
        if (!allowed) return res.status(403).json({ success: false, message: 'Доступ запрещён' });
        // Вложения переписки не должны оседать в дисковом кэше браузера: после
        // выхода (и после удаления сообщения) их нельзя было бы достать из кэша
        // устройства. no-store сам по себе запрещает хранение — Pragma/Expires
        // от глобального middleware тут лишние. Last-Modified/ETag не отдаём:
        // без кэша они не нужны, а время изменения файла — лишняя метка.
        res.set('Cache-Control', 'no-store, private');
        res.removeHeader('Pragma');
        res.removeHeader('Expires');
        // Прямо на странице показываются только фото и видео. PDF, TXT и
        // шифротекст скачиваются (attachment), а не открываются внутри нашего
        // origin; неизвестное расширение тоже считается скачиваемым.
        if (!isInlineUpload(filename)) res.set('Content-Disposition', 'attachment');
        res.sendFile(path.join(UPLOADS_DIR, filename), { lastModified: false, etag: false, cacheControl: false }, (err) => {
            if (err && !res.headersSent) {
                // JSON с ошибкой не должен уходить как «скачиваемый файл».
                res.removeHeader('Content-Disposition');
                res.status(err.status === 404 ? 404 : 500).json({ success: false, message: 'Файл не найден' });
            }
        });
    });
}

module.exports = { register };
