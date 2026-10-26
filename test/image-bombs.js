'use strict';
// «Бомбы» для проверок санитайзера изображений: маленький файл, заявляющий
// огромное число пикселей (R1 п.1). Помощник, не тест: раннер берёт только *.test.js.

const zlib = require('zlib');
const sharp = require('sharp');

function pngChunk(type, data) {
    const head = Buffer.alloc(8);
    head.writeUInt32BE(data.length, 0);
    head.write(type, 4, 'latin1');
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(Buffer.concat([head.subarray(4), data])), 0);
    return Buffer.concat([head, data, crc]);
}

function pngIhdr(width, height) {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8; // 8 бит
    ihdr[9] = 0; // оттенки серого
    return ihdr;
}

// eXIf с Orientation=6: заставляет .rotate() держать в памяти всю картинку
// (без поворота PNG обрабатывается построчно и почти не ест память).
const EXIF_ORIENTATION_6 = Buffer.from('4d4d002a0000000800010112000300000001000600000000' + '00000000', 'hex');

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// PNG, у которого заголовок заявляет width x height, а данных почти нет.
function forgedPng(width, height) {
    const idat = zlib.deflateSync(Buffer.alloc(width + 1));
    return Buffer.concat([PNG_SIGNATURE, pngChunk('IHDR', pngIhdr(width, height)), pngChunk('IDAT', idat), pngChunk('IEND', Buffer.alloc(0))]);
}

// Настоящий PNG width x height из нулей с поворотом по EXIF: сжатие ~1000:1,
// при декодировании раскрывается целиком (16383x16383 = 268 Мпикс — предел sharp по умолчанию).
// Строки потоком через zlib: сама сборка почти не занимает памяти.
async function realBombPng(width, height) {
    const deflate = zlib.createDeflate({ level: 1 });
    const parts = [];
    deflate.on('data', (chunk) => parts.push(chunk));
    const finished = new Promise((resolve, reject) => { deflate.on('end', resolve); deflate.on('error', reject); });
    const row = Buffer.alloc(width + 1);
    for (let y = 0; y < height; y++) {
        if (!deflate.write(row)) await new Promise((resolve) => deflate.once('drain', resolve));
    }
    deflate.end();
    await finished;
    return Buffer.concat([
        PNG_SIGNATURE, pngChunk('IHDR', pngIhdr(width, height)), pngChunk('eXIf', EXIF_ORIENTATION_6),
        pngChunk('IDAT', Buffer.concat(parts)), pngChunk('IEND', Buffer.alloc(0)),
    ]);
}

// Настоящий маленький JPEG с EXIF Orientation=6, в заголовке (SOF) которого
// подменены размеры: «бомба» ревью (JPEG 16383x16383 с поворотом), но без данных.
async function forgedJpeg(width, height) {
    const small = await sharp({ create: { width: 16, height: 16, channels: 3, background: { r: 9, g: 9, b: 9 } } })
        .jpeg().withMetadata({ orientation: 6 }).toBuffer();
    for (let i = 2; i + 9 < small.length; i++) {
        if (small[i] === 0xff && (small[i + 1] === 0xc0 || small[i + 1] === 0xc2)) {
            small.writeUInt16BE(height, i + 5);
            small.writeUInt16BE(width, i + 7);
            return small;
        }
    }
    throw new Error('в JPEG нет маркера SOF');
}

module.exports = { forgedPng, realBombPng, forgedJpeg };
