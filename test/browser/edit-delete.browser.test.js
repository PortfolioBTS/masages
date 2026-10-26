'use strict';
// Удаление сообщений в настоящем Chrome, с утверждениями по ленте обоих участников и по базе (ревью W7 R5, З-12;
// правка с получателем — в messages.browser.test.js):
//  - в меню чужого сообщения нет «Изменить» и «Удалить»;
//  - своё сообщение удаляется из ленты автора и, без перезагрузки, собеседника; из БД строка исчезает физически;
//  - цитата удалённого в ответе собеседника становится «Сообщение удалено», после перезагрузки текст удалённого
//    не возвращается, порядок остальных сообщений прежний.

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');
const ui = require('./helpers/ui');

const suite = createBrowserSuite('edit-delete');
const GROUP = 'Удаление сообщений';

suite.test('удаление: у чужого сообщения нет «Изменить»/«Удалить»; своё пропадает у обоих, цитата становится «удалено», история после перезагрузки без него', async () => {
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        const roomId = await ui.roomIdByName(suite, GROUP);
        const rowsInRoom = async () => Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1', [roomId])).rows[0].n);

        for (const text of ['первое', 'второе', 'третье']) await app.sendMessage(pa, text);
        for (const text of ['первое', 'второе', 'третье']) await app.waitForMessage(pb, text, { sent: false });

        // Боб отвечает на «второе».
        await ui.openMessageMenu(pb, 'второе');
        await pb.click('#reply-message-btn');
        await pb.waitForSelector('#reply-preview:not(.hidden)');
        await pb.type('#message-input', 'ответ на второе');
        await pb.press('Enter');
        await app.waitForMessage(pb, 'ответ на второе', { sent: true });
        await app.waitForMessage(pa, 'ответ на второе', { sent: false });
        const quoteBefore = (await ui.messageViews(pa)).find((view) => view.text === 'ответ на второе').quote;
        assert.match(quoteBefore, /второе/, 'цитата показывает отвеченное сообщение');
        assert.strictEqual(await rowsInRoom(), 4);

        // Чужое сообщение: ни правки, ни удаления; свои — есть (меню показывает только допустимое).
        await ui.openMessageMenu(pb, 'первое');
        assert.strictEqual(await ui.isHidden(pb, '#delete-message-btn'), true, 'Боб не может удалить сообщение Алисы');
        assert.strictEqual(await ui.isHidden(pb, '#edit-message-btn'), true, 'Боб не может изменить сообщение Алисы');
        await pb.press('Escape');
        await pb.waitForGone('#message-menu:not(.hidden)');
        await ui.openMessageMenu(pa, 'ответ на второе');
        assert.strictEqual(await ui.isHidden(pa, '#delete-message-btn'), true, 'Алиса не может удалить ответ Боба');
        await pa.press('Escape');
        await pa.waitForGone('#message-menu:not(.hidden)');
        await ui.openMessageMenu(pa, 'второе');
        assert.strictEqual(await ui.isHidden(pa, '#delete-message-btn'), false);
        assert.strictEqual(await ui.isHidden(pa, '#edit-message-btn'), false);
        await pa.press('Escape');
        await pa.waitForGone('#message-menu:not(.hidden)');

        // Алиса удаляет «второе»: пропадает у неё и у Боба, строка уходит из БД, цитата помечается удалённой.
        await ui.deleteMessage(pa, 'второе');
        await pa.waitForText('#toast', /Сообщение удалено/);
        await ui.waitForNoMessage(pb, 'второе');
        assert.strictEqual(await rowsInRoom(), 3, 'в БД осталось три сообщения');
        for (const [label, page] of [['Алиса', pa], ['Боб', pb]]) {
            const reply = (await ui.messageViews(page)).find((view) => view.text === 'ответ на второе');
            assert.match(reply.quote, /Сообщение удалено/, `${label}: цитата удалённого сообщения`);
            assert.deepStrictEqual(await ui.messageTexts(page), ['первое', 'третье', 'ответ на второе'], `${label}: порядок остальных не нарушен`);
        }

        // Перезагрузка обоих: история с сервера без удалённого, текст удалённого не возвращается ни в ленте, ни в цитате.
        for (const [page, sentOwn] of [[pa, false], [pb, true]]) {
            await page.reload();
            await app.waitForApp(page);
            await app.openChat(page, GROUP);
            await app.waitForMessage(page, 'ответ на второе', { sent: sentOwn });
            assert.deepStrictEqual(await ui.messageTexts(page), ['первое', 'третье', 'ответ на второе']);
            const reply = (await ui.messageViews(page)).find((view) => view.text === 'ответ на второе');
            assert.doesNotMatch(reply.quote || '', /второе/, 'удалённое сообщение не воскресает в цитате');
        }
        await pb.screenshot('edit-delete-01-after-reload');
    });
});
