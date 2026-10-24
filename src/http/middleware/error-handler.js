'use strict';
// Обработчик ошибок Express (после всех маршрутов): ответы из multer и разбора JSON, остальное —
// 500 без деталей. Вынесено из server.js.

const multer = require('multer');
const { logError } = require('../../../lib/log-error');
const { EarlyResponse } = require('../early-response');

function installErrorHandler(app) {
    app.use((err, req, res, next) => {
        if (res.headersSent) return next(err);
        // Ответ из fileFilter multer: 400/409 с кодом контракта порядка сообщений
        // или 200 с уже сохранённым сообщением (повтор отправки).
        if (err instanceof EarlyResponse) return res.status(err.status).json(err.body);
        if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({ success: false, message: 'Файл слишком большой (макс. 50 МБ)' });
            }
            return res.status(400).json({ success: false, message: `Ошибка загрузки: ${err.message}` });
        }
        if (err.message === 'Неподдерживаемый тип файла') {
            return res.status(400).json({ success: false, message: 'Разрешены только фото, видео, PDF и TXT' });
        }
        if (err.type === 'entity.parse.failed') {
            return res.status(400).json({ success: false, message: 'Некорректный JSON в запросе' });
        }
        if (err.type === 'entity.too.large') {
            return res.status(413).json({ success: false, message: 'Слишком большой запрос' });
        }
        // Ошибки запроса с кодом 4xx от самого Express и middleware (битое %-кодирование в пути:
        // URIError со status 400, невалидный заголовок и т.п.) - вина клиента, а не сервера: отвечаем этим
        // кодом и не пишем в лог как необработанную ошибку (R1 п.7). Текст ошибки в ответ не попадает.
        const status = err.status || err.statusCode;
        if (Number.isInteger(status) && status >= 400 && status <= 499) {
            const message = status === 400 ? 'Некорректный запрос' : status === 404 ? 'Не найдено' : 'Запрос отклонён';
            return res.status(status).json({ success: false, message });
        }
        logError('Unhandled error', err);
        res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
    });
}

module.exports = { installErrorHandler };
