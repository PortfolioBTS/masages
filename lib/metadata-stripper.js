const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const MediaSanitizer = require('../public/media-sanitizer.js');
const { logError } = require('./log-error');
const { createLimiter } = require('./work-limiter');
const { createSanitizerPool } = require('./sanitizer-pool');

// libvips по умолчанию кэширует операции и берёт потоки по числу ядер: при
// нескольких загрузках это лишние сотни мегабайт сверх самой картинки.
// Кэш выключен, потоки — один на операцию (параллелизм задаёт ограничитель ниже).
sharp.cache(false);
sharp.concurrency(1);

// Суффикс временного файла, в который пишется очищенная копия. По нему
// же cleanupStaleTempFiles находит "осиротевшие" временные файлы (процесс
// упал посреди обработки) и не трогает настоящие вложения.
const TEMP_MARKER = '-cleaned-';

// ---- Потолки обработки изображений (R1 п.1) ----
//
// Файл в 800 КБ может раскрыться в 16383x16383 пикселей: sharp по умолчанию
// пропускает до 268 Мпикс, и одна такая загрузка поднимала RSS сервера с
// 81 до 2393 МБ (две параллельные — до 4,5 ГБ, то есть OOM контейнера).
// Размеры берутся из заголовка и проверяются ДО декодирования.
//   IMAGE_MAX_PIXELS — предел пикселей (у анимации — суммарно по всем кадрам);
//   IMAGE_MAX_FRAMES — предел кадров GIF/WebP;
//   UPLOAD_PROCESS_CONCURRENCY / UPLOAD_PROCESS_QUEUE — сколько файлов
//   обрабатывается одновременно и сколько ждёт в очереди (дальше — 503 busy).
const DEFAULT_MAX_PIXELS = 24 * 1000 * 1000;
const DEFAULT_MAX_FRAMES = 500;
const DEFAULT_PROCESS_CONCURRENCY = 1;
const DEFAULT_PROCESS_QUEUE = 4;
// Предел времени конвейера sharp (повторное ревью W7, Н3): изображение в пределах IMAGE_MAX_PIXELS, но дорогое в
// обработке (шум без сжатия, предельный размер), иначе держало бы слот ограничителя сколько угодно долго. Обычная
// фотография на 24 Мпикс обрабатывается за 1–3 с.
const DEFAULT_IMAGE_TIMEOUT_S = 20;

// Только десятичные цифры (как в lib/env-check.js): Number() принял бы и '1e1', и '0x10'.
function intFromEnv(value, fallback, min) {
    const n = typeof value === 'string' && /^\d{1,9}$/.test(value.trim()) ? Number(value) : NaN;
    return Number.isInteger(n) && n >= min ? n : fallback;
}

function resolveImageLimits(env = process.env) {
    return {
        maxPixels: intFromEnv(env.IMAGE_MAX_PIXELS, DEFAULT_MAX_PIXELS, 1),
        maxFrames: intFromEnv(env.IMAGE_MAX_FRAMES, DEFAULT_MAX_FRAMES, 1),
    };
}

// Ограничитель создаётся при первом обращении: окружение к этому моменту уже
// прочитано (dotenv), а тесты подставляют свой через options.limiter.
let sharedLimiter = null;
function processingLimiter(env = process.env) {
    if (!sharedLimiter) {
        sharedLimiter = createLimiter({
            concurrency: intFromEnv(env.UPLOAD_PROCESS_CONCURRENCY, DEFAULT_PROCESS_CONCURRENCY, 1),
            maxQueue: intFromEnv(env.UPLOAD_PROCESS_QUEUE, DEFAULT_PROCESS_QUEUE, 0),
        });
    }
    return sharedLimiter;
}

function describePixels(count) {
    return count >= 1e6 ? `${Math.round(count / 1e6)} мегапикселей` : `${count} пикселей`;
}

// Отказ с понятным пользователю текстом (userFacing): в нём нет данных файла.
function imageRefusal(message) {
    const err = new Error(message);
    err.userFacing = true;
    return err;
}

// Удаление EXIF/XMP/IPTC из изображений.
//
// Раньше здесь вызывался .withMetadata({...}) — в sharp это "СОХРАНИТЬ
// метаданные" (keepMetadata + ICC), то есть EXIF вместе с GPS-координатами
// и моделью камеры уезжал в чат как есть. По умолчанию (без withMetadata/
// keepMetadata) sharp сам выбрасывает все метаданные и приводит цвет к sRGB.
//
// Ошибка обработки больше не приводит к копированию оригинала (fail open):
// файл, который sharp не смог разобрать, отклоняется целиком.
async function stripImageMetadata(inputPath, outputPath, mimeType = '', options = {}) {
    const limits = options.limits || resolveImageLimits();
    // Анимированные GIF/WebP без { animated: true } превращались в
    // статичную картинку из первого кадра.
    const animated = mimeType === 'image/gif' || mimeType === 'image/webp';
    // Буфер, а не путь: libvips кэширует открытые файлы, и на Windows
    // последующий rename поверх исходника падал бы с EPERM.
    const input = await fs.promises.readFile(inputPath);
    // limitInputPixels: sharp сам откажет по размерам из заголовка, не декодируя
    // (failOn оставлен по умолчанию — самый строгий: битый файл отклоняется).
    const sharpOptions = { animated, limitInputPixels: limits.maxPixels };
    // Заголовок читается отдельно и заранее: разбор метаданных почти ничего не
    // стоит, а отказ получает человекочитаемую причину. У анимации height
    // суммарный (кадры уложены столбцом), так что предел относится ко всем кадрам.
    // Предел для самого metadata() снят: он читает только заголовок, а sharp на нём бросил
    // бы свою англоязычную ошибку вместо нашего текста. Декодирует уже конвейер ниже,
    // и у него предел включён (вторая линия обороны, если размеры в заголовке лгут).
    const meta = await sharp(input, { animated, limitInputPixels: false }).metadata();
    if (!(meta.width > 0 && meta.height > 0)) throw imageRefusal('Не удалось определить размеры изображения');
    if (meta.width * meta.height > limits.maxPixels) {
        throw imageRefusal(`Изображение слишком большое: не больше ${describePixels(limits.maxPixels)}${animated ? ' на все кадры вместе' : ''}. Уменьшите его и отправьте снова.`);
    }
    if (animated && meta.pages > limits.maxFrames) {
        throw imageRefusal(`В анимации слишком много кадров: не больше ${limits.maxFrames}.`);
    }
    let pipeline = sharp(input, sharpOptions).timeout({ seconds: limits.timeoutSeconds || DEFAULT_IMAGE_TIMEOUT_S });
    // Поворот по EXIF Orientation "вшивается" в пиксели до того, как сам
    // тег будет выброшен — иначе фото с телефона ложились бы на бок.
    if (!animated) pipeline = pipeline.rotate();
    try {
        await pipeline.toFile(outputPath);
    } catch (err) {
        // sharp прерывает конвейер по тайм-ауту ошибкой «timeout: N% complete».
        if (/^timeout\b/i.test(String(err && err.message))) {
            throw imageRefusal('Изображение обрабатывается слишком долго. Уменьшите его или сохраните в другом формате и отправьте снова.');
        }
        throw err;
    }
    return outputPath;
}

// ---- Видео и PDF ----
//
// Всё, что не изображение, чистит public/media-sanitizer.js — тот же модуль,
// что работает в браузере перед E2EE-шифрованием вложений (зашифрованный
// файл сервер уже не видит). Одна реализация на обе стороны: GPS из MP4/MOV,
// теги WebM, Info/XMP у PDF. Модуль бросает исключение на файле, который
// не смог разобрать целиком (fail closed).
//
// На сервере модуль работает в отдельном потоке (lib/sanitizer-pool.js) с тайм-аутом и пределом памяти, а бюджет
// распаковки PDF меньше клиентского: специально собранный PDF в 100 КБ распаковывался в 100 МБ и держал главный поток
// ~2 с (повторное ревью W7, Н0). Сжатые потоки PDF, которые санитайзер распаковывает (object streams и XMP), у
// обычных документов занимают килобайты, так что 16 МБ хватает с большим запасом.
const SERVER_PDF_INFLATE_TOTAL = 16 * 1024 * 1024;

let sharedPool = null;
function sanitizerPool() {
    if (!sharedPool) sharedPool = createSanitizerPool();
    return sharedPool;
}

async function stripWithSanitizer(inputPath, outputPath, mimeType, options = {}) {
    const input = await fs.promises.readFile(inputPath);
    const output = await (options.pool || sanitizerPool()).sanitize(input, mimeType, { maxInflateTotal: SERVER_PDF_INFLATE_TOTAL });
    await fs.promises.writeFile(outputPath, output);
    return outputPath;
}

// Универсальная функция: обрабатывает файл во временную копию и заменяет
// ею оригинал. Любая ошибка пробрасывается — вызывающий код отклоняет
// загрузку (fail closed). Неподдерживаемый тип — тоже ошибка: раньше такие
// файлы (например, видео) молча уходили в чат вместе с GPS и моделью телефона.
async function stripMetadataFromFile(filePath, mimeType, options = {}) {
    const mime = MediaSanitizer._internal.normalizeMimeType(mimeType);
    if (!MediaSanitizer.isSupported(mime)) {
        // Заявленный тип в сообщение не входит: его присылает клиент, а текст
        // ошибки попадает в лог.
        throw new Error('Неподдерживаемый тип файла для очистки метаданных');
    }
    if (mime === 'text/plain') return filePath; // метаданных нет — копировать незачем

    // Обработка идёт через ограничитель: не больше N файлов одновременно, лишние
    // получают BusyError (503), а не копят память.
    return (options.limiter || processingLimiter()).run(() => stripLocked(filePath, mime, options));
}

async function stripLocked(filePath, mime, options) {
    const ext = path.extname(filePath);
    const basename = path.basename(filePath, ext);
    const dirname = path.dirname(filePath);
    const tempPath = path.join(dirname, `${basename}${TEMP_MARKER}${crypto.randomBytes(4).toString('hex')}${ext}`);

    try {
        if (mime.startsWith('image/')) {
            await stripImageMetadata(filePath, tempPath, mime, options);
        } else {
            await stripWithSanitizer(filePath, tempPath, mime, options);
        }
        await fs.promises.rename(tempPath, filePath); // атомарно заменяет оригинал
        return filePath;
    } catch (error) {
        logError('[MetadataStripper] Error processing file', error);
        await fs.promises.unlink(tempPath).catch(() => {});
        throw error;
    }
}

// Удаляет только брошенные временные файлы обработки (*-cleaned-*), а не
// все файлы старше maxAgeMs. Раньше сюда передавалась вся папка uploads,
// и через сутки у всех сообщений пропадали вложения.
async function cleanupStaleTempFiles(directory, maxAgeMs = 60 * 60 * 1000) {
    let removedTemp = 0;
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
                    removedTemp++;
                }
            } catch (_) { /* файл уже удалён параллельно */ }
        }
        // В лог — только число: имя файла указывает на вложение.
        if (removedTemp > 0) console.log(`[MetadataStripper] Удалено брошенных временных файлов: ${removedTemp}`);
    } catch (error) {
        if (error.code !== 'ENOENT') {
            logError('[MetadataStripper] Error cleaning up temp files', error);
        }
    }
}

module.exports = {
    stripImageMetadata,
    stripMetadataFromFile,
    cleanupStaleTempFiles,
    // Затирание Info/XMP на месте (Buffer тоже Uint8Array) — для тестов.
    _internal: {
        blankPdfMetadata: MediaSanitizer._internal.blankPdfMetadata,
        resolveImageLimits, processingLimiter, DEFAULT_MAX_PIXELS, DEFAULT_MAX_FRAMES, DEFAULT_IMAGE_TIMEOUT_S, SERVER_PDF_INFLATE_TOTAL,
    },
};
