'use strict';
// Ответ, который обработчик ошибок Express отдаёт вместо ошибки (http/middleware/error-handler.js).
// Вынесено из server.js.

// Ответ, который отдаёт обработчик ошибок Express вместо ошибки: так из
// fileFilter multer уходят 400/409 с телом { success, code, message } и даже 200
// с уже сохранённым сообщением (повтор отправки), не принимая файл на диск.
class EarlyResponse extends Error {
    constructor(status, body) {
        super(body && body.message ? body.message : 'early response');
        this.status = status;
        this.body = body;
    }
}

module.exports = { EarlyResponse };
