'use strict';
// Файлы в настоящем Chrome: PNG выбирается через input[type=file]
// (DOM.setFileInputFiles — как выбор в системном диалоге), шифруется на
// устройстве и показывается получателю картинкой; звук (.mp3) приложение
// отклоняет до отправки. Исходное имя фото собеседнику не показывается.

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');
const { withSampleFiles } = require('./helpers/samples');

const suite = createBrowserSuite('files');
const GROUP = 'Группа с файлами';

// Строки окна «Отправить файлы»: отклонённые помечены классом muted.
const sendRows = (page) => page.evaluate(() => Array.from(document.querySelectorAll('#send-files-list .send-file-row'), row => ({
    muted: row.classList.contains('muted'),
    text: row.textContent.trim(),
})));

suite.test('PNG уходит и показывается получателю картинкой; .mp3 отклоняется до отправки', async () => {
    await withSampleFiles(async (samples) => {
        await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
            const pa = await alice.newPage();
            const pb = await bob.newPage();
            await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });

            // Выбор двух файлов сразу: фото годится, звук — нет, и это видно до отправки.
            await pa.setFiles('#file-input', [samples.photo, samples.audio]);
            await pa.waitForSelector('#send-files-modal:not(.hidden)');
            const rows = await sendRows(pa);
            assert.strictEqual(rows.length, 2);
            assert.strictEqual(rows[0].muted, false, `фото не должно быть отклонено: ${rows[0].text}`);
            assert.strictEqual(rows[1].muted, true, `звук должен быть отклонён: ${rows[1].text}`);
            assert.ok(!rows[0].text.includes('holiday-photo'), `исходное имя фото попало в список отправки: ${rows[0].text}`);
            assert.strictEqual(await pa.evaluate(() => document.getElementById('send-files-btn').disabled), false);
            await pa.screenshot('files-01-choose');

            const mark = pa.networkMark();
            await pa.click('#send-files-btn');
            await pa.waitForGone('#send-files-modal:not(.hidden)');
            await pa.waitFor(() => document.querySelector('#chat-messages .message.sent img.message-image'), { what: 'своя картинка в ленте', timeoutMs: 30000 });
            assert.ok(pa.requestsSince(mark).every(r => !/\.mp3/i.test(r.url)), 'на сервер ушёл звуковой файл');

            // Получатель: картинка расшифрована и декодирована в исходный размер.
            const image = await pb.waitFor(() => {
                const img = document.querySelector('#chat-messages .message.received img.message-image');
                return img && img.complete && img.naturalWidth > 0 ? { width: img.naturalWidth, height: img.naturalHeight, src: img.src.split(':')[0] } : false;
            }, { what: 'картинка у получателя', timeoutMs: 30000 });
            assert.deepStrictEqual({ width: image.width, height: image.height }, samples.png);
            assert.strictEqual(image.src, 'blob', 'зашифрованное вложение показывается из расшифрованных данных, а не по прямой ссылке');
            assert.strictEqual(await pb.count('#chat-messages .message'), 1, 'у получателя должно быть ровно одно сообщение — картинка');
            assert.strictEqual(await pb.count('#chat-messages .file-attachment'), 0, 'звук не должен дойти как вложение');
            await pb.screenshot('files-02-image-received');

            // Только звук: список показывает отказ, отправить нечего; чат после этого работает как раньше.
            await pa.setFiles('#file-input', [samples.audio]);
            await pa.waitForSelector('#send-files-modal:not(.hidden)');
            const only = await sendRows(pa);
            assert.strictEqual(only.length, 1);
            assert.strictEqual(only[0].muted, true);
            assert.strictEqual(await pa.evaluate(() => document.getElementById('send-files-btn').disabled), true, 'кнопка отправки должна быть выключена');
            await pa.screenshot('files-03-audio-rejected');
            await app.closeModal(pa, 'send-files-modal');
            await app.sendMessage(pa, 'после отказа');
            await app.waitForMessage(pb, 'после отказа', { sent: false });
            assert.strictEqual(await pb.count('#chat-messages .message'), 2);
        });
    });
});
