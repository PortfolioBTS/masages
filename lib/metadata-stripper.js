const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const MediaSanitizer = require('../public/media-sanitizer.js');

// Суффикс временного файла, в который пишется очищенная копия. По нему
// же cleanupStaleTempFiles находит "осиротевшие" временные файлы (процесс
// упал посреди обработки) и не трогает настоящие вложения.
const TEMP_MARKER = '-cleaned-';

// Удаление EXIF/XMP/IPTC из изображений.
//
// Раньше здесь вызывался .withMetadata({...}) — в sharp это "СОХРАНИТЬ
// метаданные" (keepMetadata + ICC), то есть EXIF вместе с GPS-координатами
// и моделью камеры уезжал в чат как есть. По умолчанию (без withMetadata/
// keepMetadata) sharp сам выбрасывает все метаданные и приводит цвет к sRGB.
//
// Ошибка обработки больше не приводит к копированию оригинала (fail open):
// файл, который sharp не смог разобрать, отклоняется целиком.
async function stripImageMetadata(inputPath, outputPath, mimeType = '') {
    // Анимированные GIF/WebP без { animated: true } превращались в
    // статичную картинку из первого кадра.
    const animated = mimeType === 'image/gif' || mimeType === 'image/webp';
    // Буфер, а не путь: libvips кэширует открытые файлы, и на Windows
    // последующий rename поверх исходника падал бы с EPERM.
    let pipeline = sharp(await fs.promises.readFile(inputPath), { animated });
    // Поворот по EXIF Orientation "вшивается" в пиксели до того, как сам
    // тег будет выброшен — иначе фото с телефона ложились бы на бок.
    if (!animated) pipeline = pipeline.rotate();
    await pipeline.toFile(outputPath);
    return outputPath;
}

// ---- Видео, аудио, PDF ----
//
// Всё, что не изображение, чистит public/media-sanitizer.js — тот же модуль,
// что работает в браузере перед E2EE-шифрованием вложений (зашифрованный
// файл сервер уже не видит). Одна реализация на обе стороны: GPS из MP4/MOV,
// теги WebM/MP3/OGG, LIST/bext у WAV, Info/XMP у PDF. Модуль бросает
// исключение на файле, который не смог разобрать целиком (fail closed).
async function stripWithSanitizer(inputPath, outputPath, mimeType) {
    const input = await fs.promises.readFile(inputPath);
    await fs.promises.writeFile(outputPath, MediaSanitizer.sanitize(input, mimeType));
    return outputPath;
}

// Универсальная функция: обрабатывает файл во временную копию и заменяет
// ею оригинал. Любая ошибка пробрасывается — вызывающий код отклоняет
// загрузку (fail closed). Неподдерживаемый тип — тоже ошибка: раньше такие
// файлы (видео, аудио) молча уходили в чат вместе с GPS и моделью телефона.
async function stripMetadataFromFile(filePath, mimeType) {
    const mime = MediaSanitizer._internal.normalizeMimeType(mimeType);
    if (!MediaSanitizer.isSupported(mime)) {
        throw new Error(`Неподдерживаемый тип файла для очистки метаданных: ${String(mimeType).slice(0, 100)}`);
    }
    if (mime === 'text/plain') return filePath; // метаданных нет — копировать незачем

    const ext = path.extname(filePath);
    const basename = path.basename(filePath, ext);
    const dirname = path.dirname(filePath);
    const tempPath = path.join(dirname, `${basename}${TEMP_MARKER}${crypto.randomBytes(4).toString('hex')}${ext}`);

    try {
        if (mime.startsWith('image/')) {
            await stripImageMetadata(filePath, tempPath, mime);
        } else {
            await stripWithSanitizer(filePath, tempPath, mime);
        }
        await fs.promises.rename(tempPath, filePath); // атомарно заменяет оригинал
        return filePath;
    } catch (error) {
        console.error('[MetadataStripper] Error processing file:', error.message);
        await fs.promises.unlink(tempPath).catch(() => {});
        throw error;
    }
}

// Удаляет только брошенные временные файлы обработки (*-cleaned-*), а не
// все файлы старше maxAgeMs. Раньше сюда передавалась вся папка uploads,
// и через сутки у всех сообщений пропадали вложения.
async function cleanupStaleTempFiles(directory, maxAgeMs = 60 * 60 * 1000) {
    try {
        const files = await fs.promises.readdir(directory);
        const now = Date.now();
        for (const file of files) {
            if (!file.includes(TEMP_MARKER)) continue;
            const filePath = path.join(directory, file);
            try {
                const stats = await fs.promises.stat(filePath);
                if (now - stats.mtimeMs > maxAgeMs) {
                    await fs.promises.unlink(filePath);
                    console.log('[MetadataStripper] Cleaned up stale temp file:', file);
                }
            } catch (_) { /* файл уже удалён параллельно */ }
        }
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error('[MetadataStripper] Error cleaning up temp files:', error.message);
        }
    }
}

module.exports = {
    stripImageMetadata,
    stripMetadataFromFile,
    cleanupStaleTempFiles,
    // Затирание Info/XMP на месте (Buffer тоже Uint8Array) — для тестов.
    _internal: { blankPdfMetadata: MediaSanitizer._internal.blankPdfMetadata },
};
