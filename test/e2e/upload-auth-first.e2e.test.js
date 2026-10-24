'use strict';
// Загрузка вложения (W7 R1 п.8): сессия проверяется ДО разбора multipart. Раньше multer разбирал
// тело (поля до 10 МБ и файл на диск), и только потом обработчик отвечал 401. Плюс fieldSize
// 64 КБ: текстовые поля формы не бывают длиннее конверта E2EE (~11 КБ) и подписи (4000 символов).

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const net = require('net');
const sharp = require('sharp');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('upload-auth-first');

// Сырой запрос: заголовки и начало тела, остальное не отправляется. Ответ приходит, только если сервер
// не ждёт конца тела. Возвращает { status, closed, ms }.
async function rawUnauthenticatedUpload(client, contentLength) {
    const csrf = await client.csrfToken();
    const { hostname, port } = new URL(suite.server.baseUrl);
    const boundary = 'nyxoBoundary7731';
    const head = [
        'POST /api/messages/file HTTP/1.1',
        `Host: ${hostname}:${port}`,
        `Origin: ${suite.server.baseUrl}`,
        `Cookie: ${client.jar.header('/api/messages/file')}`,
        `X-CSRF-Token: ${csrf}`,
        `X-Forwarded-For: ${client.xff}`,
        `Content-Type: multipart/form-data; boundary=${boundary}`,
        `Content-Length: ${contentLength}`,
        '', '',
    ].join('\r\n');
    const started = Date.now();
    return new Promise((resolve, reject) => {
        const socket = net.connect({ host: hostname, port: Number(port) });
        let received = '';
        let closed = false;
        const timer = setTimeout(() => { socket.destroy(); reject(new Error(`ответа нет за 3 с; получено: ${JSON.stringify(received)}`)); }, 3000);
        socket.on('connect', () => {
            socket.write(head);
            socket.write(`--${boundary}\r\nContent-Disposition: form-data; name="text"\r\n\r\n${'x'.repeat(2000)}`);
        });
        socket.on('data', (chunk) => {
            received += chunk.toString('utf8');
            const match = /^HTTP\/1\.1 (\d{3})/.exec(received);
            if (match && /\r\n\r\n[\s\S]*\}/.test(received)) {
                clearTimeout(timer);
                const result = { status: Number(match[1]), head: received, ms: Date.now() - started };
                // Сервер закрывает соединение после ответа (Connection: close), не ожидая остатка тела.
                socket.once('close', () => { closed = true; });
                setTimeout(() => { socket.destroy(); resolve({ ...result, closed }); }, 300);
            }
        });
        socket.on('error', (err) => { if (!closed) { clearTimeout(timer); reject(err); } });
    });
}

test('неавторизованная загрузка получает 401 сразу, не дожидаясь тела запроса', async () => {
    const stranger = suite.client();
    const result = await rawUnauthenticatedUpload(stranger, 5000000);
    assert.strictEqual(result.status, 401, result.head);
    assert.match(result.head, /"message":"Не авторизован"/);
    assert.doesNotMatch(result.head, /connection: close/i, 'тело разумного размера дочитывается, соединение не рвётся');
    assert.ok(result.ms < 2000, `ответ быстрый: ${result.ms} мс`);
});

test('неавторизованная загрузка с телом больше предела файла: 401 и закрытие соединения без дочитывания', async () => {
    const stranger = suite.client();
    const result = await rawUnauthenticatedUpload(stranger, 500000000);
    assert.strictEqual(result.status, 401, result.head);
    assert.match(result.head, /connection: close/i, 'сервер просит закрыть соединение');
    assert.strictEqual(result.closed, true, 'и закрывает его');
    assert.ok(result.ms < 2000, `ответ быстрый: ${result.ms} мс`);
});

test('обычный запрос без входа и с входом работает как раньше: 401 / 200', async () => {
    const a = suite.client();
    const image = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#336699' } }).jpeg().toBuffer();
    const anonymous = await a.uploadRaw(1, image, 'image/jpeg');
    assert.strictEqual(anonymous.status, 401);
    assert.deepStrictEqual(anonymous.body, { success: false, message: 'Не авторизован' });

    await a.registerAnon();
    const bot = await a.botChat();
    const caption = 'п'.repeat(3000); // подпись допустимой длины проходит через fieldSize
    const ok = await a.uploadRaw(bot.id, image, 'image/jpeg', { text: caption });
    assert.strictEqual(ok.status, 200, JSON.stringify(ok.body));
});

test('текстовое поле формы больше 64 КБ: 400 «Ошибка загрузки», на диск ничего не пишется', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const image = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#336699' } }).jpeg().toBuffer();
    const files = () => fs.readdirSync(suite.server.uploadsDir).filter(name => !name.startsWith('.')).sort();
    const before = files();
    const res = await a.uploadRaw(bot.id, image, 'image/jpeg', { text: 'x'.repeat(70 * 1024) });
    assert.strictEqual(res.status, 400, JSON.stringify(res.body));
    assert.match(res.body.message, /Ошибка загрузки/);
    assert.deepStrictEqual(files(), before, 'новых файлов нет');
});
