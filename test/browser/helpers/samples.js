'use strict';
// Образцы файлов для выбора через <input type="file">. Личные файлы человека не
// используются: PNG собирается здесь же, звук — «голова» mp3 из образцов
// сквозных тестов (отказ идёт по типу, содержимое не важно).

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { MP3_ID3 } = require('../../e2e/helpers/samples');

function chunk(type, data) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(body));
    return Buffer.concat([length, body, crc]);
}

// Настоящий PNG (RGB, градиент с рамкой) с текстовым блоком «автор» — тем, что
// клиент должен вычистить перед отправкой.
function makePng(width = 64, height = 48) {
    const header = Buffer.alloc(13);
    header.writeUInt32BE(width, 0);
    header.writeUInt32BE(height, 4);
    header[8] = 8;   // глубина цвета
    header[9] = 2;   // RGB
    const rows = [];
    for (let y = 0; y < height; y++) {
        const row = Buffer.alloc(1 + width * 3);   // первый байт — фильтр 0
        for (let x = 0; x < width; x++) {
            const edge = x === 0 || y === 0 || x === width - 1 || y === height - 1;
            row[1 + x * 3] = edge ? 255 : Math.round((x / width) * 255);
            row[2 + x * 3] = edge ? 255 : Math.round((y / height) * 255);
            row[3 + x * 3] = edge ? 255 : 128;
        }
        rows.push(row);
    }
    return Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        chunk('IHDR', header),
        chunk('tEXt', Buffer.from('Author\0Secret Author', 'latin1')),
        chunk('IDAT', zlib.deflateSync(Buffer.concat(rows))),
        chunk('IEND', Buffer.alloc(0)),
    ]);
}

// Временная папка с образцами; удаляется после fn. Имена файлов нарочно «личные»:
// интерфейс не должен показывать собеседнику исходное имя фото.
async function withSampleFiles(fn) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-browser-files-'));
    try {
        const files = {
            photo: path.join(dir, 'holiday-photo.png'),
            audio: path.join(dir, 'voice-note.mp3'),
        };
        fs.writeFileSync(files.photo, makePng());
        fs.writeFileSync(files.audio, MP3_ID3);
        return await fn({ ...files, png: { width: 64, height: 48 } });
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

module.exports = { makePng, withSampleFiles };
