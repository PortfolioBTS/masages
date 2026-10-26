'use strict';
// Открытые вложения (чат с ботом) после повторного ревью W7, Н0.
//   * PDF в 100 КБ, распаковывающийся в 100 МБ, раньше чистился в главном потоке ~2 с: всё это время сервер не
//     отвечал никому. Теперь санитайзер работает в потоке, а серверный бюджет распаковки меньше клиентского:
//     файл отклоняется быстро, запросы постороннего аккаунта обслуживаются без задержки;
//   * частота открытых вложений на аккаунт ограничена (OPEN_UPLOADS_PER_10MIN) до записи файла на диск;
//     зашифрованные вложения групп лимит не расходуют.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { createSuite } = require('./helpers/scenarios');
const { objStmBomb, sample } = require('../pdf-fixtures');

const LIMIT = 4;
const suite = createSuite('open-uploads', { env: { OPEN_UPLOADS_PER_10MIN: String(LIMIT) } });

function uploadsOnDisk() {
    return fs.readdirSync(suite.server.uploadsDir).filter((name) => !name.startsWith('.'));
}

test('PDF-«бомба»: файл отклонён быстро, посторонний аккаунт всё это время обслуживается без задержки', async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    const b = suite.client();
    await b.registerAnon();
    const bomb = objStmBomb();
    const before = uploadsOnDisk().length;

    let uploading = true;
    const waits = [];
    const poll = (async () => {
        while (uploading) {
            const started = Date.now();
            const res = await b.get('/api/auth');
            waits.push(Date.now() - started);
            assert.strictEqual(res.status, 200);
        }
    })();
    const results = [];
    try {
        for (let i = 0; i < 3; i++) {
            const started = Date.now();
            const res = await a.uploadRaw(bot.id, bomb, 'application/pdf', { filename: 'objstm.pdf' });
            results.push({ res, ms: Date.now() - started });
        }
    } finally {
        uploading = false;
        await poll;
    }
    for (const { res, ms } of results) {
        assert.strictEqual(res.status, 400, JSON.stringify(res.body));
        assert.match(res.body.message, /Сохранить как PDF/);
        assert.ok(ms < 3000, `отказ за ${ms} мс`);
    }
    const worst = Math.max(...waits);
    assert.ok(waits.length >= 3, `посторонний успел сделать запросы: ${waits.length}`);
    assert.ok(worst < 300, `самый долгий ответ постороннему: ${worst} мс (запросов ${waits.length})`);
    assert.strictEqual(uploadsOnDisk().length, before, 'отклонённые файлы удалены');
});

test(`частота открытых вложений: ${LIMIT} за 10 минут, дальше 429 с Retry-After и файл не пишется на диск; группы не считаются`, async () => {
    const a = suite.client();
    await a.registerAnon();
    const bot = await a.botChat();
    for (let i = 0; i < LIMIT; i++) {
        const res = await a.uploadRaw(bot.id, sample({ info: 'plain' }), 'application/pdf', { filename: 'doc.pdf' });
        assert.strictEqual(res.status, 200, `загрузка ${i + 1}: ${JSON.stringify(res.body)}`);
    }
    const onDisk = uploadsOnDisk().length;
    const res = await a.uploadRaw(bot.id, sample({ info: 'plain' }), 'application/pdf', { filename: 'doc.pdf' });
    assert.strictEqual(res.status, 429, JSON.stringify(res.body));
    assert.strictEqual(res.body.code, 'open-uploads-limit');
    assert.match(res.body.message, new RegExp(`не больше ${LIMIT} за 10 минут`));
    const retryAfter = Number(res.headers.get('retry-after'));
    assert.ok(retryAfter > 0 && retryAfter <= 600, `Retry-After: ${retryAfter}`);
    assert.strictEqual(uploadsOnDisk().length, onDisk, 'файл сверх лимита на диск не попал');

    // Лимит — на аккаунт: у другого свои LIMIT загрузок.
    const c = suite.client();
    await c.registerAnon();
    const cBot = await c.botChat();
    assert.strictEqual((await c.uploadRaw(cBot.id, sample({ info: 'plain' }), 'application/pdf')).status, 200);

    // Зашифрованные вложения групп сервер не разбирает — лимит открытых вложений их не трогает.
    const room = await a.createRoom('Файлы');
    for (let i = 0; i < 2; i++) await a.uploadCipher(room.id);
});
