'use strict';
// Огрубление времени (docs/security/message-ordering.md, раздел 11): точность не
// больше нужной для работы функции, округление «в безопасную сторону».
//
//   * created_at и edited_at сообщений — до минуты вниз (floorToMinute);
//   * mtime и atime файлов вложений — до часа вниз (floorToHour): по времени
//     изменения файла иначе восстанавливалось бы время сообщения с точностью до
//     секунды. Уборщик файлов-сирот учитывает округление: порог возраста у него
//     не меньше двух часов (ORPHAN_MIN_AGE_MS).

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;

// Не меньше двух часов: файл, чей mtime округлён вниз до часа, выглядит старше
// настоящего возраста максимум на час.
const ORPHAN_MIN_AGE_MS = 2 * HOUR_MS;

function floorTo(stepMs, value) {
    const ms = value instanceof Date ? value.getTime() : Number(value);
    return new Date(Math.floor(ms / stepMs) * stepMs);
}

// Date (или миллисекунды) → Date на начало минуты.
function floorToMinute(value = Date.now()) {
    return floorTo(MINUTE_MS, value);
}

// Date (или миллисекунды) → Date на начало часа.
function floorToHour(value = Date.now()) {
    return floorTo(HOUR_MS, value);
}

// Порог возраста для уборки брошенных файлов: не меньше ORPHAN_MIN_AGE_MS.
function orphanAgeThresholdMs(requestedMs) {
    return Math.max(ORPHAN_MIN_AGE_MS, Number(requestedMs) || 0);
}

module.exports = { MINUTE_MS, HOUR_MS, ORPHAN_MIN_AGE_MS, floorToMinute, floorToHour, orphanAgeThresholdMs };
