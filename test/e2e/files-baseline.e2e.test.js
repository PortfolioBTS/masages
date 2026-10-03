'use strict';
// Вложения: метаданные (EXIF) сняты, имя обезличено; /uploads отдаётся только
// участникам; квота на пользователя (UPLOAD_QUOTA_MB).

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

const EXIF_MARKER = 'NyxoExifMarker-Ivanov';
// Квота ~30 КБ: маленькая картинка проходит, шумная PNG 128×128 — нет.
const suite = createSuite('files-baseline', { env: { UPLOAD_QUOTA_MB: '0.03' } });

async function jpegWithExif() {
    return sharp({ create: { width: 16, height: 16, channels: 3, background: { r: 200, g: 40, b: 40 } } })
        .jpeg()
        .withExif({ IFD0: { Artist: EXIF_MARKER, ImageDescription: 'GPS 55.75 37.61' } })
        .toBuffer();
}

test('EXIF снимается, имя файла обезличено — в ответе, в базе и на диске', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const original = await jpegWithExif();
    assert.ok(original.includes(Buffer.from(EXIF_MARKER)), 'исходный файл должен содержать EXIF');
    assert.ok((await sharp(original).metadata()).exif, 'у исходного файла есть EXIF');

    const message = await a.upload(bot.id, original, 'image/jpeg', { filename: 'IMG_20260914_Ivanov.jpg' });
    assert.strictEqual(message.file_name, 'photo.jpg');
    assert.strictEqual(message.text, 'photo.jpg');
    assert.strictEqual(message.message_type, 'image');
    assert.match(message.file_url, /^\/uploads\/\d+-[0-9a-f]{24}\.jpg$/);
    assert.ok(!message.file_url.includes('Ivanov'));

    const row = (await suite.query('SELECT file_name, file_size FROM messages WHERE id = $1', [message.id])).rows[0];
    assert.strictEqual(row.file_name, 'photo.jpg');

    const download = await a.download(message.file_url);
    assert.strictEqual(download.status, 200);
    assert.match(download.headers.get('cache-control'), /no-store/);
    assert.ok(!download.body.includes(Buffer.from(EXIF_MARKER)), 'в отданном файле нет EXIF-метки');
    assert.ok(!(await sharp(download.body).metadata()).exif, 'в отданном файле нет EXIF');
    assert.strictEqual(Number(row.file_size), download.body.length);

    const onDisk = fs.readFileSync(path.join(suite.server.uploadsDir, path.basename(message.file_url)));
    assert.ok(!onDisk.includes(Buffer.from(EXIF_MARKER)), 'на диске файл уже без EXIF');
});

test('/uploads — только участникам комнаты: чужому 403, без входа 401', async () => {
    const owner = suite.client();
    const member = suite.client();
    const stranger = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    await stranger.registerAnon();
    const { ownerChat, memberChat } = await roomWithMember(owner, member);

    const message = await owner.upload(ownerChat.id, await jpegWithExif(), 'image/jpeg', { filename: 'room.jpg' });
    assert.strictEqual((await owner.download(message.file_url)).status, 200);
    assert.strictEqual((await member.download(message.file_url)).status, 200);
    assert.ok((await member.messages(memberChat.id)).messages.some(m => m.file_url === message.file_url));

    const foreign = await stranger.download(message.file_url);
    assert.strictEqual(foreign.status, 403);
    const anonymous = suite.client();
    assert.strictEqual((await anonymous.download(message.file_url)).status, 401);
    // Несуществующий файл и попытка выйти из папки — тот же отказ, без содержимого;
    // имя с недопустимыми символами — 404.
    assert.strictEqual((await member.download('/uploads/123-deadbeef.jpg')).status, 403);
    const traversal = await member.download('/uploads/..%2Fserver.js');
    assert.strictEqual(traversal.status, 403);
    assert.ok(!traversal.body.includes(Buffer.from('require(')));
    assert.strictEqual((await member.download('/uploads/bad%20name.jpg')).status, 404);
});

test('квота вложений: сверх лимита — 413, файл не сохраняется', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    // Случайный шум почти не сжимается: PNG ~48 КБ.
    const noise = await sharp(crypto.randomBytes(128 * 128 * 3), {
        raw: { width: 128, height: 128, channels: 3 },
    }).png().toBuffer();
    assert.ok(noise.length > 0.03 * 1024 * 1024, `тестовая PNG должна быть больше квоты (${noise.length} байт)`);

    const filesBefore = fs.readdirSync(suite.server.uploadsDir).length;
    const res = await a.uploadRaw(bot.id, noise, 'image/png', { filename: 'big.png' });
    assert.strictEqual(res.status, 413);
    assert.deepStrictEqual(res.body, { success: false, message: 'Превышена квота хранилища вложений' });
    const rows = await suite.query('SELECT count(*)::int AS n FROM messages WHERE user_id = $1 AND file_url IS NOT NULL', [a.user.id]);
    assert.strictEqual(rows.rows[0].n, 0);
    // Отклонённый файл удаляется с диска асинхронно — ждём условия.
    await waitUntil(() => fs.readdirSync(suite.server.uploadsDir).length === filesBefore, { what: 'отклонённый по квоте файл удалён с диска' });
    // Маленький файл в пределах квоты проходит.
    const small = await a.upload(bot.id, await jpegWithExif(), 'image/jpeg', { filename: 'small.jpg' });
    assert.strictEqual(small.file_name, 'photo.jpg');
});
