'use strict';
// Квота вложений проверяется ДО санитайзера (W7 R1 п.1): аккаунт с исчерпанной
// квотой не гоняет тяжёлую обработку впустую - ответ 413 приходит сразу.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const sharp = require('sharp');
const { createSuite } = require('./helpers/scenarios');

// Квота ~31 КБ: один шумный PNG помещается, второй файл - нет.
const suite = createSuite('upload-quota-early', { env: { UPLOAD_QUOTA_MB: '0.03' } });

test('квота исчерпана: 413 приходит ДО санитайзера (а не 400 «не удалось проверить»)', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const noise = crypto.randomBytes(100 * 100 * 3); // не сжимается: PNG после очистки тоже ~30 КБ
    const first = await sharp(noise, { raw: { width: 100, height: 100, channels: 3 } }).png({ compressionLevel: 0 }).toBuffer();
    assert.ok(first.length > 16000 && first.length < 31000, `размер PNG ${first.length}`);
    await a.upload(bot.id, first, 'image/png');
    // Второй файл: подпись PNG есть (проверка типа проходит), но содержимое - мусор, и
    // санитайзер отказал бы 400. При исчерпанной квоте до него дело не доходит.
    const garbage = Buffer.concat([first.subarray(0, 8), Buffer.alloc(16000, 7)]);
    const res = await a.uploadRaw(bot.id, garbage, 'image/png');
    assert.strictEqual(res.status, 413, JSON.stringify(res.body));
    assert.match(res.body.message, /квот/);
    // Тот же файл у аккаунта со свежей квотой доходит до санитайзера и получает 400.
    const b = suite.client();
    await b.registerAnon();
    const res2 = await b.uploadRaw((await b.botChat()).id, garbage, 'image/png');
    assert.strictEqual(res2.status, 400, JSON.stringify(res2.body));
});
