const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Функция для удаления EXIF метаданных из изображений
// Будет работать с sharp после его установки
async function stripImageMetadata(inputPath, outputPath) {
    try {
        // Проверяем доступность sharp
        let sharp;
        try {
            sharp = require('sharp');
        } catch (e) {
            console.warn('[MetadataStripper] Sharp not available, copying file without metadata stripping');
            await fs.promises.copyFile(inputPath, outputPath);
            return outputPath;
        }

        // Обрабатываем изображение и удаляем все метаданные
        await sharp(inputPath)
            .rotate() // Автоповорот по EXIF, затем метаданные удаляются
            .withMetadata({
                // Удаляем все метаданные
                exif: {},
                icc: undefined,
                xmp: undefined,
                iptc: undefined
            })
            .toFile(outputPath);

        return outputPath;
    } catch (error) {
        console.error('[MetadataStripper] Error stripping metadata:', error.message);
        // В случае ошибки копируем оригинал
        await fs.promises.copyFile(inputPath, outputPath);
        return outputPath;
    }
}

// Удаление метаданных из PDF (базовая версия)
async function stripPdfMetadata(inputPath, outputPath) {
    try {
        const buffer = await fs.promises.readFile(inputPath);

        // Простое удаление стандартных PDF метаданных
        let content = buffer.toString('binary');

        // Удаляем Info dictionary
        content = content.replace(/\/Info\s+\d+\s+\d+\s+R/g, '');

        // Удаляем XMP метаданные
        content = content.replace(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/g, '');

        // Записываем очищенный файл
        await fs.promises.writeFile(outputPath, Buffer.from(content, 'binary'));

        return outputPath;
    } catch (error) {
        console.error('[MetadataStripper] Error stripping PDF metadata:', error.message);
        await fs.promises.copyFile(inputPath, outputPath);
        return outputPath;
    }
}

// Универсальная функция для обработки файлов
async function stripMetadataFromFile(filePath, mimeType) {
    const ext = path.extname(filePath);
    const basename = path.basename(filePath, ext);
    const dirname = path.dirname(filePath);

    // Создаем временное имя для обработанного файла
    const tempName = `${basename}-cleaned-${crypto.randomBytes(4).toString('hex')}${ext}`;
    const tempPath = path.join(dirname, tempName);

    try {
        if (mimeType.startsWith('image/')) {
            await stripImageMetadata(filePath, tempPath);
        } else if (mimeType === 'application/pdf') {
            await stripPdfMetadata(filePath, tempPath);
        } else {
            // Для других типов файлов просто копируем
            await fs.promises.copyFile(filePath, tempPath);
        }

        // Заменяем оригинальный файл очищенной версией
        await fs.promises.unlink(filePath);
        await fs.promises.rename(tempPath, filePath);

        return filePath;
    } catch (error) {
        console.error('[MetadataStripper] Error processing file:', error.message);

        // Очищаем временный файл если он существует
        try {
            if (fs.existsSync(tempPath)) {
                await fs.promises.unlink(tempPath);
            }
        } catch (cleanupError) {
            // Игнорируем ошибки очистки
        }

        throw error;
    }
}

// Удаление временных файлов старше определенного времени
async function cleanupOldFiles(directory, maxAgeMs = 3600000) {
    try {
        const files = await fs.promises.readdir(directory);
        const now = Date.now();

        for (const file of files) {
            const filePath = path.join(directory, file);
            const stats = await fs.promises.stat(filePath);

            if (now - stats.mtimeMs > maxAgeMs) {
                await fs.promises.unlink(filePath);
                console.log('[MetadataStripper] Cleaned up old file:', file);
            }
        }
    } catch (error) {
        console.error('[MetadataStripper] Error cleaning up old files:', error.message);
    }
}

module.exports = {
    stripImageMetadata,
    stripPdfMetadata,
    stripMetadataFromFile,
    cleanupOldFiles
};
