'use strict';
// POST /api/messages/file после COMMIT (ревью W7 R2.12): общий catch маршрута удалял файл
// с диска при любой ошибке — и после COMMIT вставки тоже, и в чате оставалось сообщение
// без файла. Теперь файл удаляется только при сбое до COMMIT. Маршрут
// (src/http/routes/file-upload.js) запускается на подставном контексте без базы.
// Запуск: node test/file-upload-committed.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

// lib/message-crypto читает ключ при загрузке.
process.env.MESSAGE_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
const { register } = require('../src/http/routes/file-upload');
const { fakeEnvelope } = require('./e2e/helpers/envelope');
const { newClientMessageId, PROTO } = require('./e2e/helpers/client');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

function fakeRes() {
    return {
        statusCode: 200, body: null, headers: {}, headersSent: false,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; this.headersSent = true; return this; },
        set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    };
}

// Маршрут с подставными зависимостями; overrides заменяют отдельные функции контекста.
function setup(overrides = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-upload-committed-'));
    const cleaned = [];
    let handler = null;
    const app = { post: (route, middleware, fn) => { if (route === '/api/messages/file') handler = fn; } };
    const ctx = {
        UPLOAD_QUOTA_BYTES: 10 * 1024 * 1024, UPLOADS_DIR: dir,
        cleanupUploadedFile: (file) => { cleaned.push(file.filename); fs.rmSync(path.join(dir, file.filename), { force: true }); },
        rejectUpload: (res, file, status, message) => res.status(status).json({ success: false, message }),
        rejectUploadWith: (res, file, status, body) => res.status(status).json(body),
        io: { to: () => ({ emit() {} }) },
        emitVisibleRoomMessage: async () => {},
        newMessageExpirySeconds: async () => null,
        getOwnChat: async () => ({ id: 11, room_id: 22, user_id: 1, last_read_seq: 0 }),
        unarchiveForRecipients: () => {},
        insertChatMessage: async () => assert.fail('чат с ботом не ожидался'),
        insertRoomMessage: async () => ({ row: { id: 3000001, seq: 7, created_at: new Date() } }),
        describeMessageIdUse: async () => ({ status: 'free' }),
        advanceSenderMarker: async () => {},
        upload: { single: () => (req, res, next) => next() },
        uploadQuotaLeft: async () => 10 * 1024 * 1024,
        ...overrides,
    };
    register(app, ctx);
    const filename = `${crypto.randomBytes(16).toString('hex')}.bin`;
    fs.writeFileSync(path.join(dir, filename), crypto.randomBytes(300));
    const req = {
        session: { userId: 1 },
        file: { filename, mimetype: 'application/octet-stream', size: 300 },
        body: { proto: String(PROTO), chatId: '11', encrypted: 'true', clientMessageId: newClientMessageId(), envelope: fakeEnvelope('file') },
    };
    return { dir, filename, cleaned, run: async () => { const res = fakeRes(); await handler(req, res); return res; } };
}

async function quietly(fn) {
    const original = console.error;
    console.error = () => {};
    try { return await fn(); } finally { console.error = original; }
}

async function main() {
    await test('сбой после COMMIT (рассылка): файл остаётся у сохранённого сообщения', async () => {
        const t = setup({ emitVisibleRoomMessage: async () => { throw new Error('сбой рассылки'); } });
        try {
            const res = await quietly(t.run);
            assert.strictEqual(res.statusCode, 500);
            assert.deepStrictEqual(t.cleaned, [], 'cleanupUploadedFile не вызывался');
            assert.ok(fs.existsSync(path.join(t.dir, t.filename)), 'файл на диске');
        } finally {
            fs.rmSync(t.dir, { recursive: true, force: true });
        }
    });

    await test('сбой до COMMIT (вставка): файл удаляется', async () => {
        const t = setup({ insertRoomMessage: async () => { throw new Error('сбой вставки'); } });
        try {
            const res = await quietly(t.run);
            assert.strictEqual(res.statusCode, 500);
            assert.deepStrictEqual(t.cleaned, [t.filename]);
            assert.ok(!fs.existsSync(path.join(t.dir, t.filename)));
        } finally {
            fs.rmSync(t.dir, { recursive: true, force: true });
        }
    });

    await test('обычная отправка: 200, файл на месте', async () => {
        const t = setup();
        try {
            const res = await t.run();
            assert.strictEqual(res.statusCode, 200, JSON.stringify(res.body));
            assert.strictEqual(res.body.success, true);
            assert.deepStrictEqual(t.cleaned, []);
            assert.ok(fs.existsSync(path.join(t.dir, t.filename)));
        } finally {
            fs.rmSync(t.dir, { recursive: true, force: true });
        }
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
