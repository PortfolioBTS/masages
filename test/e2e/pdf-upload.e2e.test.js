'use strict';
// Загрузка PDF (открытое вложение, сервер чистит сам тем же public/media-sanitizer.js):
// сжатые метаданные в object stream — отказ, сжатый XMP затирается на месте,
// /ID заменяется, зашифрованный PDF отклоняется. Отказ не оставляет ни сообщения
// в базе, ни файла на диске.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { createSuite, waitUntil } = require('./helpers/scenarios');
const { XMP, assertOffsetsValid, streamData, sample } = require('../pdf-fixtures');

const suite = createSuite('pdf-upload');

const REJECT = { success: false, message: 'Не удалось проверить содержимое файла' };

async function uploadsCount() { return fs.readdirSync(suite.server.uploadsDir).length; }

test('PDF с Info внутри сжатого object stream отклоняется: 400, в базе и на диске ничего не остаётся', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const before = await uploadsCount();

    const res = await a.uploadRaw(bot.id, sample({ info: 'compressed' }), 'application/pdf', { filename: 'report.pdf' });
    assert.strictEqual(res.status, 400);
    assert.deepStrictEqual(res.body, REJECT);
    const rows = await suite.query('SELECT count(*)::int AS n FROM messages WHERE user_id = $1 AND file_url IS NOT NULL', [a.user.id]);
    assert.strictEqual(rows.rows[0].n, 0);
    await waitUntil(async () => (await uploadsCount()) === before, { what: 'отклонённый PDF удалён с диска' });
});

test('зашифрованный PDF отклоняется', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const res = await a.uploadRaw(bot.id, sample({ info: 'none', extra: '/Encrypt 9 0 R' }), 'application/pdf', { filename: 'locked.pdf' });
    assert.strictEqual(res.status, 400);
    assert.deepStrictEqual(res.body, REJECT);
});

test('PDF со сжатым XMP и object stream без метаданных принимается: XMP затёрт, длина и смещения xref те же, /ID новый', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const original = sample({ info: 'none', xmp: { filter: 'flate', text: XMP } });
    const idRe = /\/ID \[<([0-9A-Fa-f]+)><([0-9A-Fa-f]+)>\]/;
    assert.ok(zlib.inflateSync(streamData(original, 5).data).toString('latin1').includes('Ivan Petrov'), 'в исходном файле XMP на месте');

    const message = await a.upload(bot.id, original, 'application/pdf', { filename: 'Ivanov-CV.pdf' });
    assert.strictEqual(message.message_type, 'file');
    assert.strictEqual(message.file_name, 'document.pdf');

    const download = await a.download(message.file_url);
    assert.strictEqual(download.status, 200);
    const out = download.body;
    assert.strictEqual(out.length, original.length, 'длина файла не изменилась');
    assertOffsetsValid(out);
    assert.strictEqual(zlib.inflateSync(streamData(out, 5).data).length, 0, 'XMP стал пустым потоком');
    const text = out.toString('latin1');
    assert.ok(!text.includes('Ivan Petrov') && !text.includes('Secret Writer'));
    const before = original.toString('latin1').match(idRe);
    const after = text.match(idRe);
    assert.ok(after && after[1] !== before[1] && after[2] !== before[2] && after[1].length === before[1].length, '/ID заменён случайным той же длины');

    const row = (await suite.query('SELECT file_size FROM messages WHERE id = $1', [message.id])).rows[0];
    assert.strictEqual(Number(row.file_size), out.length);
    const onDisk = fs.readFileSync(path.join(suite.server.uploadsDir, path.basename(message.file_url)));
    assert.ok(onDisk.equals(out));
    assert.deepStrictEqual(fs.readdirSync(suite.server.uploadsDir).filter(f => f.includes('-cleaned-')), [], 'временных файлов нет');
});

test('обычный PDF с несжатым Info принимается, метаданные затёрты на месте', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const original = sample({ info: 'plain' });
    const message = await a.upload(bot.id, original, 'application/pdf', { filename: 'plain.pdf' });
    const out = (await a.download(message.file_url)).body;
    const text = out.toString('latin1');
    assert.strictEqual(out.length, original.length);
    assert.ok(!text.includes('Secret Producer') && !text.includes('Ivan Petrov') && !text.includes('D:2024'));
    assertOffsetsValid(out);
});
