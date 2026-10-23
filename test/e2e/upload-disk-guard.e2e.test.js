'use strict';
// Порог свободного места на томе вложений (W7 R1 п.3): ниже UPLOAD_MIN_FREE_MB новые
// загрузки отклоняются понятным ответом 507 storage-full ДО записи файла на диск, а
// текстовые сообщения продолжают работать. Тот же сервер с разумным порогом файлы принимает.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const sharp = require('sharp');
const { createSuite } = require('./helpers/scenarios');

// Порог недостижимо большой (~95 ТБ): места «всегда мало».
const suite = createSuite('upload-disk-guard', { env: { UPLOAD_MIN_FREE_MB: '99999999' } });

const uploadsOnDisk = () => fs.readdirSync(suite.server.uploadsDir).filter(name => !name.startsWith('.'));

test('мало места: загрузка файла - 507 storage-full, на диск ничего не пишется, текст отправляется', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const image = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#336699' } }).jpeg().toBuffer();
    const res = await a.uploadRaw(bot.id, image, 'image/jpeg');
    assert.strictEqual(res.status, 507, JSON.stringify(res.body));
    assert.strictEqual(res.body.code, 'storage-full');
    assert.match(res.body.message, /Хранилище вложений почти заполнено/);
    assert.deepStrictEqual(uploadsOnDisk(), []);
    const cipher = await a.uploadCipherRaw(bot.id);
    assert.strictEqual(cipher.status, 507, 'шифротекст в общей очереди: порог один для всех загрузок');

    const message = await a.send(bot.id, 'текст проходит');
    assert.strictEqual(message.text, 'текст проходит');
});

test('места достаточно (порог 1 МБ): тот же файл принимается', async () => {
    const roomy = await suite.startServer({ name: 'roomy', env: { UPLOAD_MIN_FREE_MB: '1' } });
    const b = roomy.client();
    await b.registerAnon();
    const bot = await b.botChat();
    const image = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#336699' } }).jpeg().toBuffer();
    const res = await b.uploadRaw(bot.id, image, 'image/jpeg');
    assert.strictEqual(res.status, 200, JSON.stringify(res.body));
});
