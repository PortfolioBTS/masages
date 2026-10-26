'use strict';
// Поток очистки метаданных не-изображений (PDF, MP4/MOV, WebM): его держит lib/sanitizer-pool.js (повторное ревью W7,
// Н0). Здесь работает тот же public/media-sanitizer.js, что и в браузере, но вне главного потока сервера: тяжёлый
// файл занимает этот поток, а HTTP-запросы и сокеты остальных обслуживаются как обычно.
//
// Протокол: { id, mime, options, bytes: ArrayBuffer } → { id, started: true } (разбор начат: тайм-аут разбора считается
// отсюда, а не с запуска потока), затем { id, ok: true, bytes } или { id, ok: false, error: { name, message, userFacing } }.
// Буферы передаются (transfer), а не копируются.

const { parentPort } = require('worker_threads');
const MediaSanitizer = require('../public/media-sanitizer.js');

// Результат передаётся целиком своим ArrayBuffer: представление на часть чужого буфера сначала копируется.
function ownBuffer(view) {
    const own = view.byteOffset === 0 && view.byteLength === view.buffer.byteLength ? view : view.slice();
    return own.buffer;
}

parentPort.on('message', ({ id, mime, options, bytes }) => {
    parentPort.postMessage({ id, started: true });
    let out;
    try {
        out = ownBuffer(MediaSanitizer.sanitize(new Uint8Array(bytes), mime, options));
    } catch (err) {
        const error = {
            name: err && err.name ? String(err.name) : 'Error',
            message: err && err.message ? String(err.message) : 'ошибка очистки',
            userFacing: Boolean(err && err.userFacing),
        };
        parentPort.postMessage({ id, ok: false, error });
        return;
    }
    parentPort.postMessage({ id, ok: true, bytes: out }, [out]);
});
