'use strict';
// Уборщик файлов-сирот на настоящем сервере и базе (ревью W7 R2.5, lib/orphan-uploads.js):
// старый файл по шаблону загрузок без строки messages удаляется; файл со ссылкой, свежий
// файл и чужой файл остаются. Задача обслуживания в тестах идёт каждые 300 мс
// (NYXO_TEST_MAINTENANCE_MS), поэтому «раз в сутки» не ждём.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

const suite = createSuite('orphan-uploads');

const HOUR = 60 * 60 * 1000;

function age(file, ms) {
    const when = new Date(Date.now() - ms);
    fs.utimesSync(file, when, when);
}

test('старый файл без строки messages удаляется; со ссылкой, свежий и чужой остаются', async () => {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    const { ownerChat } = await roomWithMember(owner, member);
    await owner.isRoomChat(ownerChat.id);
    const message = await owner.uploadCipher(ownerChat.id);
    const dir = suite.server.uploadsDir;
    const referenced = path.join(dir, path.basename(message.file_url));
    assert.ok(fs.existsSync(referenced));
    age(referenced, 5 * HOUR);

    const orphan = path.join(dir, `${crypto.randomBytes(16).toString('hex')}.bin`);
    const fresh = path.join(dir, `${crypto.randomBytes(16).toString('hex')}.jpg`);
    const foreign = path.join(dir, 'operator-notes.txt');
    for (const file of [orphan, fresh, foreign]) fs.writeFileSync(file, 'x');
    age(orphan, 3 * HOUR);
    age(foreign, 50 * HOUR);
    const mark = suite.server.logs.mark();

    await waitUntil(() => !fs.existsSync(orphan), { timeoutMs: 15000, what: 'уборщик удалил файл-сироту' });
    await suite.server.logs.waitFor(/\[Uploads\] Уборка файлов-сирот: удалено 1/, { from: mark });
    // Ещё пара проходов — остальные файлы на месте.
    await suite.server.waitForTick(2);
    for (const file of [referenced, fresh, foreign]) assert.ok(fs.existsSync(file), `${path.basename(file)} остался`);
    assert.ok(!suite.server.logs.text({ from: mark }).includes(path.basename(orphan)), 'имени файла нет в логе');
    // Вложение по-прежнему скачивается.
    const download = await owner.download(message.file_url);
    assert.strictEqual(download.status, 200);
});
