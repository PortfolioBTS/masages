'use strict';
// Вложения в чат с ботом: потолки обработки изображений (W7 R1 п.1).
//   * «бомба» (малый файл с заголовком 16383x16383) отклоняется быстро и с понятным текстом;
//   * обработка идёт через ограничитель: при переполнении очереди - 503 с Retry-After,
//     сервер остаётся живым и принимает следующую загрузку.
// Квота до санитайзера - в upload-quota-early.e2e.test.js.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const sharp = require('sharp');
const { createSuite } = require('./helpers/scenarios');
const { forgedPng, forgedJpeg, realBombPng } = require('../image-bombs');

// Одновременно обрабатывается один файл, очереди нет: переполнение детерминировано.
const suite = createSuite('upload-limits', {
    env: { UPLOAD_PROCESS_CONCURRENCY: '1', UPLOAD_PROCESS_QUEUE: '0' },
});

function uploadsOnDisk() {
    return fs.readdirSync(suite.server.uploadsDir).filter(name => !name.startsWith('.'));
}

async function smallJpeg() {
    return sharp({ create: { width: 16, height: 16, channels: 3, background: '#336699' } }).jpeg().toBuffer();
}

test('бомба 16383x16383 (PNG и JPEG с поворотом) - 400 с понятным текстом, быстро, файлов на диске не остаётся', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const before = uploadsOnDisk().length;
    for (const [bytes, mime] of [[forgedPng(16383, 16383), 'image/png'], [await forgedJpeg(16383, 16383), 'image/jpeg']]) {
        const started = Date.now();
        const res = await a.uploadRaw(bot.id, bytes, mime, { filename: 'bomb' });
        assert.strictEqual(res.status, 400, JSON.stringify(res.body));
        assert.match(res.body.message, /слишком большое/);
        assert.ok(Date.now() - started < 3000, 'отказ быстрый');
    }
    assert.strictEqual(uploadsOnDisk().length, before, 'отклонённые файлы удалены');
    // Сервер жив и принимает обычную картинку.
    const message = await a.upload(bot.id, await smallJpeg(), 'image/jpeg');
    assert.strictEqual(message.message_type, 'image');
});

test('настоящая бомба-PNG с поворотом (268 Мпикс, ~1 МБ) отклоняется, сервер отвечает', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const bytes = await realBombPng(16383, 16383);
    const started = Date.now();
    const res = await a.uploadRaw(bot.id, bytes, 'image/png', { filename: 'bomb.png' });
    assert.strictEqual(res.status, 400, JSON.stringify(res.body));
    assert.match(res.body.message, /слишком большое/);
    assert.ok(Date.now() - started < 5000, 'отказ быстрый');
    assert.strictEqual((await a.get('/api/auth')).status, 200, 'сервер отвечает');
});

test('очередь обработки переполнена: 503 с Retry-After, остальные загрузки проходят, сервер жив', async () => {
    // Картинка в 20 Мпикс с поворотом: обработка заметно дольше передачи по loopback.
    const big = await sharp({ create: { width: 5000, height: 4000, channels: 3, background: '#445566' } })
        .jpeg({ quality: 40 }).withMetadata({ orientation: 6 }).toBuffer();
    const clients = [];
    for (let i = 0; i < 6; i++) {
        const c = suite.client();
        await c.registerAnon();
        clients.push({ c, bot: await c.botChat() });
    }
    const results = await Promise.all(clients.map(({ c, bot }) => c.uploadRaw(bot.id, big, 'image/jpeg')));
    const statuses = results.map(r => r.status);
    assert.ok(statuses.includes(200), `хотя бы одна загрузка прошла: ${statuses}`);
    const busy = results.filter(r => r.status === 503);
    assert.ok(busy.length > 0, `лишние получили 503: ${statuses}`);
    for (const r of busy) {
        assert.ok(Number(r.headers.get('retry-after')) > 0, 'Retry-After');
        assert.match(r.body.message, /занят/);
    }
    assert.ok(statuses.every(s => s === 200 || s === 503), `других статусов нет: ${statuses}`);
    // После разгрузки очередь свободна, а отклонённые файлы с диска убраны.
    const { c, bot } = clients[0];
    assert.strictEqual((await c.uploadRaw(bot.id, await smallJpeg(), 'image/jpeg')).status, 200);
    const accepted = statuses.filter(s => s === 200).length;
    assert.strictEqual(uploadsOnDisk().length >= accepted, true);
});
