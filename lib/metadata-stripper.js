const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');

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

// ---- PDF ----
//
// Прежняя версия вырезала "/Info N N R" и XMP-пакет из файла, сдвигая все
// последующие байты: таблица xref (байтовые смещения объектов) после
// этого указывала мимо, и многие просмотрщики считали PDF повреждённым.
// При этом сам словарь Info (Author/Creator/Producer...) оставался в файле
// нетронутым. Теперь метаданные затираются пробелами той же длины — ни
// одно смещение не меняется, а значения исчезают.
//
// Ограничение: объекты внутри сжатых object streams (PDF 1.5+) без полного
// разбора PDF не видны — такие метаданные остаются.

// Затирает содержимое всех строк PDF ((...) и <hex>) в диапазоне [start, end).
function blankPdfStrings(buf, start, end) {
    let i = start;
    while (i < end) {
        const c = buf[i];
        if (c === 0x28) { // '(' — литеральная строка, скобки внутри могут быть вложенными
            let depth = 1;
            i++;
            while (i < end && depth > 0) {
                const ch = buf[i];
                if (ch === 0x5C) { // '\' — экранирование, следующий байт не может закрыть строку
                    buf[i] = 0x20;
                    if (i + 1 < end) buf[i + 1] = 0x20;
                    i += 2;
                    continue;
                }
                if (ch === 0x28) depth++;
                else if (ch === 0x29 && --depth === 0) break;
                buf[i] = 0x20;
                i++;
            }
            i++;
        } else if (c === 0x3C && buf[i + 1] === 0x3C) { // '<<' — начало словаря, не строка
            i += 2;
        } else if (c === 0x3C) { // '<' — hex-строка
            i++;
            while (i < end && buf[i] !== 0x3E) { buf[i] = 0x20; i++; }
            i++;
        } else {
            i++;
        }
    }
}

function blankPdfMetadata(buf) {
    const text = buf.toString('latin1'); // 1 символ == 1 байт, смещения совпадают

    // Словарь(и) Info — по ссылкам из trailer'ов (их несколько при
    // инкрементальных обновлениях).
    const refs = new Set();
    for (const m of text.matchAll(/\/Info\s+(\d+)\s+(\d+)\s+R/g)) refs.add(`${m[1]} ${m[2]}`);
    for (const ref of refs) {
        const [num, gen] = ref.split(' ');
        const objRe = new RegExp(`(?:^|[^0-9])${num}\\s+${gen}\\s+obj\\b`, 'g');
        for (const m of text.matchAll(objRe)) {
            const start = m.index + m[0].length;
            const end = text.indexOf('endobj', start);
            if (end !== -1) blankPdfStrings(buf, start, end);
        }
    }

    // XMP-пакеты: содержимое <x:xmpmeta>...</x:xmpmeta> заменяется
    // пробелами, длина потока (и /Length) не меняется.
    for (const m of text.matchAll(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/g)) {
        buf.fill(0x20, m.index, m.index + m[0].length);
    }
    return buf;
}

async function stripPdfMetadata(inputPath, outputPath) {
    const buffer = await fs.promises.readFile(inputPath);
    await fs.promises.writeFile(outputPath, blankPdfMetadata(buffer));
    return outputPath;
}

// Универсальная функция: обрабатывает файл во временную копию и заменяет
// ею оригинал. Любая ошибка пробрасывается — вызывающий код отклоняет
// загрузку (fail closed).
async function stripMetadataFromFile(filePath, mimeType) {
    const ext = path.extname(filePath);
    const basename = path.basename(filePath, ext);
    const dirname = path.dirname(filePath);
    const tempPath = path.join(dirname, `${basename}${TEMP_MARKER}${crypto.randomBytes(4).toString('hex')}${ext}`);

    try {
        if (mimeType.startsWith('image/')) {
            await stripImageMetadata(filePath, tempPath, mimeType);
        } else if (mimeType === 'application/pdf') {
            await stripPdfMetadata(filePath, tempPath);
        } else {
            return filePath; // для остальных типов обработки нет — копировать незачем
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
    stripPdfMetadata,
    stripMetadataFromFile,
    cleanupStaleTempFiles,
    _internal: { blankPdfMetadata },
};
