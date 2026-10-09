'use strict';
// Звук в приложении не поддерживается (контракт волны 1, §7, T1.3a; roadmap R2):
// сервер отклоняет любые звуковые типы, а подмена типа ловится по сигнатуре.
//
// * audio/mpeg, audio/ogg, audio/wav, audio/webm (и родственные) -> 400 с
//   текстом «Разрешены только фото, видео, PDF и TXT», сообщения и файла нет;
// * video/webm с сигнатурой OggS (и другие подмены) -> 400 «Содержимое файла
//   не соответствует его типу»; image/webp требует 'WEBP' после 'RIFF', иначе
//   под видом картинки прошёл бы WAV;
// * фото, видео, PDF и TXT по-прежнему принимаются (отказ не «на всё подряд»),
//   а /uploads отдаёт attachment для всего, кроме image/* и video/*.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const { createSuite, waitUntil } = require('./helpers/scenarios');
const samples = require('./helpers/samples');

const suite = createSuite('files-audio');

const TYPE_ERROR = 'Разрешены только фото, видео, PDF и TXT';
const SIGNATURE_ERROR = 'Содержимое файла не соответствует его типу';

const listUploads = () => (fs.existsSync(suite.server.uploadsDir) ? fs.readdirSync(suite.server.uploadsDir).sort() : []);
const fileMessages = async (userId) => Number((await suite.query(
    'SELECT count(*) AS n FROM messages WHERE user_id = $1 AND file_url IS NOT NULL', [userId]
)).rows[0].n);

// Аккаунт и чат с ботом (в нём разрешены вложения), отказ -> { status, body }.
async function fixture() {
    const client = suite.client();
    await client.registerAnon();
    const bot = await client.botChat();
    return { client, chatId: bot.id };
}

test('звуковые типы отклоняются по типу: 400, ни сообщения, ни файла', async () => {
    const { client, chatId } = await fixture();
    const before = listUploads();
    const cases = [
        ['audio/mpeg (ID3)', 'audio/mpeg', samples.MP3_ID3, 'song.mp3'],
        ['audio/mpeg (кадр MPEG)', 'audio/mpeg', samples.MP3_FRAME, 'song.mp3'],
        ['audio/mp3', 'audio/mp3', samples.MP3_ID3, 'song.mp3'],
        ['audio/ogg', 'audio/ogg', samples.OGG, 'voice.ogg'],
        ['audio/opus', 'audio/opus', samples.OGG, 'voice.opus'],
        ['audio/wav', 'audio/wav', samples.WAV, 'sound.wav'],
        ['audio/x-wav', 'audio/x-wav', samples.WAV, 'sound.wav'],
        ['audio/webm', 'audio/webm', samples.EBML_STUB, 'voice.weba'],
        ['audio/webm;codecs=opus (запись с микрофона)', 'audio/webm;codecs=opus', samples.EBML_STUB, 'voice.webm'],
        ['audio/mp4', 'audio/mp4', samples.M4A, 'voice.m4a'],
        ['audio/aac', 'audio/aac', samples.MP3_ID3, 'x.aac'],
        ['audio/flac', 'audio/flac', samples.MP3_ID3, 'x.flac'],
    ];
    for (const [label, mime, bytes, filename] of cases) {
        const res = await client.uploadRaw(chatId, bytes, mime, { filename });
        assert.strictEqual(res.status, 400, `${label}: ${res.text}`);
        assert.deepStrictEqual(res.body, { success: false, message: TYPE_ERROR }, label);
    }
    assert.strictEqual(await fileMessages(client.user.id), 0, 'сообщений с файлом нет');
    assert.deepStrictEqual(listUploads(), before, 'в папке вложений ничего не осталось');
});

test('звук нельзя пронести ни как «шифротекст», ни под безобидным именем, ни под типом, не входящим в список', async () => {
    const { client, chatId } = await fixture();
    const before = listUploads();
    // Шифротекст принимается только в комнатах и с флагом encrypted; обычный чат и звуковой тип с флагом — отказ.
    const flagged = await client.uploadRaw(chatId, samples.MP3_ID3, 'audio/mpeg', { filename: 'song.mp3', encrypted: true, envelope: 'x' });
    assert.strictEqual(flagged.status, 400);
    assert.strictEqual(flagged.body.message, TYPE_ERROR);
    // Тип «любой бинарный» без флага encrypted.
    const octet = await client.uploadRaw(chatId, samples.MP3_ID3, 'application/octet-stream', { filename: 'song.mp3' });
    assert.strictEqual(octet.status, 400);
    assert.strictEqual(octet.body.message, TYPE_ERROR);
    // Звук под безобидным именем: решает заявленный тип, а не имя файла.
    const renamed = await client.uploadRaw(chatId, samples.MP3_ID3, 'audio/mpeg', { filename: 'photo.png' });
    assert.strictEqual(renamed.status, 400);
    assert.strictEqual(renamed.body.message, TYPE_ERROR);
    assert.strictEqual(await fileMessages(client.user.id), 0);
    assert.deepStrictEqual(listUploads(), before);
});

test('подмена типа: заявленный тип не совпадает с содержимым -> 400', async () => {
    const { client, chatId } = await fixture();
    const spoofs = [
        ['video/webm с сигнатурой OggS', 'video/webm', samples.OGG, 'clip.webm'],
        ['video/webm с сигнатурой MP3 (ID3)', 'video/webm', samples.MP3_ID3, 'clip.webm'],
        ['video/webm с сигнатурой WAV', 'video/webm', samples.WAV, 'clip.webm'],
        ['video/mp4 с байтами OggS', 'video/mp4', samples.OGG, 'clip.mp4'],
        ['video/mp4 с байтами WAV', 'video/mp4', samples.WAV, 'clip.mp4'],
        ['video/quicktime с байтами OggS', 'video/quicktime', samples.OGG, 'clip.mov'],
        ['image/png с байтами MP3', 'image/png', samples.MP3_ID3, 'photo.png'],
        ['image/jpeg с байтами OggS', 'image/jpeg', samples.OGG, 'photo.jpg'],
        // RIFF-контейнер общий для WebP и WAV: одной сигнатуры 'RIFF' недостаточно.
        ['image/webp с байтами WAV (RIFF…WAVE)', 'image/webp', samples.WAV, 'photo.webp'],
        ['application/pdf с байтами WAV', 'application/pdf', samples.WAV, 'doc.pdf'],
    ];
    for (const [label, mime, bytes, filename] of spoofs) {
        const before = listUploads();
        const res = await client.uploadRaw(chatId, bytes, mime, { filename });
        assert.strictEqual(res.status, 400, `${label}: ${res.text}`);
        assert.deepStrictEqual(res.body, { success: false, message: SIGNATURE_ERROR }, label);
        // Принятый multer'ом файл удаляется асинхронно — ждём условия, а не паузы.
        await waitUntil(() => JSON.stringify(listUploads()) === JSON.stringify(before), { what: `${label}: отклонённый файл удалён с диска` });
    }
    assert.strictEqual(await fileMessages(client.user.id), 0);
});

test('обычные вложения по-прежнему принимаются; PDF и TXT скачиваются (attachment), фото и видео показываются', async () => {
    const { client, chatId } = await fixture();
    const png = await sharp({ create: { width: 8, height: 8, channels: 3, background: { r: 10, g: 120, b: 200 } } }).png().toBuffer();
    const webp = await sharp({ create: { width: 8, height: 8, channels: 3, background: { r: 10, g: 120, b: 200 } } }).webp().toBuffer();
    assert.strictEqual(webp.subarray(8, 12).toString('latin1'), 'WEBP', 'образец WebP настоящий');
    const accepted = [
        ['image/png', png, 'photo.png', 'image', false],
        ['image/webp', webp, 'photo.webp', 'image', false],
        ['video/mp4', samples.makeMp4(), 'trip.mp4', 'video', false],
        ['video/webm', samples.makeWebm(), 'clip.webm', 'video', false],
        ['application/pdf', samples.makePdf(), 'Отчёт Иванов.pdf', 'file', true],
        ['text/plain', Buffer.from('просто текст\n', 'utf8'), 'notes.txt', 'file', true],
    ];
    for (const [mime, bytes, filename, kind, attachment] of accepted) {
        const message = await client.upload(chatId, bytes, mime, { filename });
        assert.strictEqual(message.message_type, kind, mime);
        assert.strictEqual(message.file_type, mime, mime);

        const download = await client.download(message.file_url);
        assert.strictEqual(download.status, 200, mime);
        const disposition = download.headers.get('content-disposition');
        if (attachment) assert.strictEqual(disposition, 'attachment', `${mime}: PDF и TXT только скачиваются`);
        else assert.strictEqual(disposition, null, `${mime}: фото и видео показываются на странице`);
        assert.match(download.headers.get('cache-control'), /no-store/, mime);

        // Метаданные вычищены, содержимое осталось файлом нужного типа.
        if (mime === 'application/pdf') {
            assert.strictEqual(download.body.subarray(0, 4).toString('latin1'), '%PDF');
            assert.ok(!download.body.includes('Petrov') && !download.body.includes('Ivan'), 'автор PDF вычищен');
        }
        if (mime === 'video/mp4') assert.ok(!download.body.includes(samples.GPS), 'координаты MP4 вычищены');
        if (mime === 'video/webm') {
            assert.strictEqual(download.body.subarray(0, 4).toString('hex'), '1a45dfa3');
            assert.ok(!download.body.includes('Secret Title') && !download.body.includes('SecretWriter'), 'теги WebM вычищены');
        }
    }
    assert.strictEqual(await fileMessages(client.user.id), accepted.length);
    // На диске — ровно принятые файлы: ни остатков очистки метаданных, ни отклонённых загрузок.
    const files = listUploads();
    assert.strictEqual(files.length, accepted.length, files.join(', '));
    assert.ok(files.every(name => !name.includes('-cleaned-')), files.join(', '));
    assert.ok(files.every(name => /^\d{13}-[0-9a-f]{24}\.[a-z0-9]{3,4}$/.test(name)), files.join(', '));
});

test('файл пропал с диска: /uploads отвечает JSON-404, а не «скачиваемым файлом»', async () => {
    const { client, chatId } = await fixture();
    const message = await client.upload(chatId, Buffer.from('текст\n', 'utf8'), 'text/plain', { filename: 'a.txt' });
    fs.rmSync(path.join(suite.server.uploadsDir, path.basename(message.file_url)));
    const res = await client.request('GET', message.file_url);
    assert.strictEqual(res.status, 404);
    assert.strictEqual(res.headers.get('content-disposition'), null);
    assert.deepStrictEqual(res.body, { success: false, message: 'Файл не найден' });
});
