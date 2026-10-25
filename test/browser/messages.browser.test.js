'use strict';
// Отправка и правка сообщений в настоящем Chrome (ревью W7 R5, В-6): клиентская половина контракта
// docs/security/message-ordering.md (разделы 6.5, 9, 12) на настоящей странице, сокете и сервере.
//  1) потерянный ответ на первый POST /api/messages: страница повторяет ТОТ ЖЕ запрос (тот же
//     clientMessageId и конверт), в ленте у отправителя и получателя одно сообщение, в БД одна строка;
//     то же, когда запрос вообще не дошёл до сервера;
//  2) ответ сокета раньше ответа POST: сообщение в ленте одно, запись в БД одна;
//  3) правка своего сообщения доходит до получателя без ошибки привязки (id-mismatch): конверт правки
//     несёт edit: true и mid правляемого сообщения; то же для правки ответа (цитата остаётся) и после
//     перезагрузки получателя.
// Обрыв делается средствами браузера (CDP Fetch, helpers/intercept.js), страница не подправляется.

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');
const ui = require('./helpers/ui');
const { interceptRequests } = require('./helpers/intercept');
const { waitUntil } = require('../e2e/helpers/scenarios');

const suite = createBrowserSuite('messages');

const inputEmpty = (page) => page.waitFor(() => document.getElementById('message-input').value === '', { what: 'поле ввода очищено: отправка завершена', timeoutMs: app.APP_TIMEOUT_MS });
const roomMessages = async (roomId) => (await suite.query('SELECT id FROM messages WHERE room_id = $1 ORDER BY seq', [roomId])).rows.map((row) => Number(row.id));
const countOf = async (page, text) => (await ui.messageViews(page)).filter((view) => view.text === text).length;
const sendFromInput = async (page, text) => {
    await page.type('#message-input', text);
    await page.click('#send-btn');
};

suite.test('потерян ответ на первый POST: тот же запрос уходит повторно, в ленте и в БД одно сообщение', async () => {
    const GROUP = 'Потерянный ответ';
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        const roomId = await ui.roomIdByName(suite, GROUP);
        // Оборванный запрос — то, что моделирует тест; браузер сообщает о нём как о сетевой ошибке.
        pa.allow(/ERR_CONNECTION_(RESET|REFUSED)/);

        // 1. Сервер получил запрос и сохранил сообщение, а ответ до страницы не дошёл.
        const lostResponse = await interceptRequests(pa, { pattern: '*/api/messages', stage: 'Response', decide: (entry) => (entry.index === 0 ? 'fail' : 'pass') });
        await sendFromInput(pa, 'ответ потерян');
        await waitUntil(() => lostResponse.seen.length >= 2, { timeoutMs: 20000, what: 'повторный POST /api/messages после обрыва' });
        await inputEmpty(pa);
        await lostResponse.stop();

        assert.strictEqual(lostResponse.seen.length, 2, 'ровно один повтор');
        const [first, retry] = lostResponse.seen.map((entry) => JSON.parse(entry.body));
        assert.ok(first.clientMessageId, 'у сообщения комнаты есть clientMessageId');
        assert.deepStrictEqual(retry, first, 'повтор — тот же запрос: тот же clientMessageId и тот же конверт');
        assert.deepStrictEqual(lostResponse.seen.map((entry) => entry.status), [200, 200], 'сервер ответил на оба запроса: первое сообщение он принял');
        await app.waitForMessage(pb, 'ответ потерян', { sent: false });
        assert.strictEqual(await countOf(pa, 'ответ потерян'), 1, 'у отправителя одно сообщение');
        assert.strictEqual(await countOf(pb, 'ответ потерян'), 1, 'у получателя одно сообщение');
        assert.deepStrictEqual(await roomMessages(roomId), [Number(first.clientMessageId)], 'в БД одна строка с id, выбранным клиентом');
        assert.doesNotMatch(await pa.text('#toast'), /Нет соединения|Не удалось/, 'пользователю об ошибке не сообщается');

        // 2. Запрос не дошёл до сервера вообще: повтор тоже тем же запросом, строка появляется один раз.
        const lostRequest = await interceptRequests(pa, { pattern: '*/api/messages', stage: 'Request', reason: 'ConnectionRefused', decide: (entry) => (entry.index === 0 ? 'fail' : 'pass') });
        await sendFromInput(pa, 'запрос потерян');
        await waitUntil(() => lostRequest.seen.length >= 2, { timeoutMs: 20000, what: 'повторный POST /api/messages после обрыва запроса' });
        await inputEmpty(pa);
        await lostRequest.stop();
        const [again, againRetry] = lostRequest.seen.map((entry) => JSON.parse(entry.body));
        assert.deepStrictEqual(againRetry, again);
        assert.notStrictEqual(again.clientMessageId, first.clientMessageId, 'новое сообщение — новый id');
        await app.waitForMessage(pb, 'запрос потерян', { sent: false });
        assert.strictEqual(await countOf(pa, 'запрос потерян'), 1);
        assert.strictEqual(await countOf(pb, 'запрос потерян'), 1);
        assert.deepStrictEqual(await roomMessages(roomId), [Number(first.clientMessageId), Number(again.clientMessageId)]);
        await pa.screenshot('messages-01-lost-response');
    });
});

suite.test('ответ сокета раньше ответа POST: в ленте одно сообщение, в БД одна строка', async () => {
    const GROUP = 'Сокет раньше POST';
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        const roomId = await ui.roomIdByName(suite, GROUP);

        let release;
        const gate = new Promise((resolve) => { release = resolve; });
        const hold = await interceptRequests(pa, { pattern: '*/api/messages', stage: 'Response', decide: async () => { await gate; return 'pass'; } });
        await sendFromInput(pa, 'сокет быстрее');
        // Ответ POST придержан, поэтому сообщение в ленте появилось по событию сокета.
        await app.waitForMessage(pa, 'сокет быстрее', { sent: true });
        assert.strictEqual(hold.seen.length, 1);
        assert.strictEqual(await pa.evaluate(() => document.getElementById('message-input').value), 'сокет быстрее', 'отправка ещё не завершена: ответ POST не получен');
        assert.strictEqual(await countOf(pa, 'сокет быстрее'), 1);

        release();
        await inputEmpty(pa);
        await hold.stop();
        assert.strictEqual(await countOf(pa, 'сокет быстрее'), 1, 'ответ POST не добавил второй экземпляр');
        await app.waitForMessage(pb, 'сокет быстрее', { sent: false });
        assert.strictEqual(await countOf(pb, 'сокет быстрее'), 1);
        assert.strictEqual((await roomMessages(roomId)).length, 1);
        // Порядок «сначала ответ POST» проверяют юнит-тесты (test/client-feed.test.js): сокет придержать нельзя.
        await pa.screenshot('messages-02-socket-first');
    });
});

suite.test('правка своего сообщения доходит до получателя без id-mismatch; правка ответа сохраняет цитату; после перезагрузки так же', async () => {
    const GROUP = 'Правка у получателя';
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        const roomId = await ui.roomIdByName(suite, GROUP);

        await app.sendMessage(pa, 'до правки');
        await app.waitForMessage(pb, 'до правки', { sent: false });
        const originalId = (await roomMessages(roomId))[0];

        await ui.editMessage(pa, 'до правки', 'после правки');
        await app.waitForMessage(pb, 'после правки', { sent: false });
        const received = await ui.messageViews(pb);
        assert.deepStrictEqual(received.map((view) => [view.text, view.edited, view.failed]), [['после правки', true, false]],
            'у получателя новый текст с пометкой «изменено», без ошибки расшифровки');
        assert.deepStrictEqual(await roomMessages(roomId), [originalId], 'правка не создала новое сообщение');
        const { rows } = await suite.query('SELECT edited_at FROM messages WHERE id = $1', [originalId]);
        assert.notStrictEqual(rows[0].edited_at, null, 'сервер отметил правку');
        const own = await ui.messageViews(pa);
        assert.deepStrictEqual(own.map((view) => [view.text, view.edited, view.failed]), [['после правки', true, false]]);

        // Правка на стороне получателя: Боб отвечает и правит свой ответ — цитата остаётся.
        await ui.openMessageMenu(pb, 'после правки');
        await pb.click('#reply-message-btn');
        await pb.waitForSelector('#reply-preview:not(.hidden)');
        await pb.type('#message-input', 'ответ Боба');
        await pb.press('Enter');
        await app.waitForMessage(pb, 'ответ Боба', { sent: true });
        await app.waitForMessage(pa, 'ответ Боба', { sent: false });
        await ui.editMessage(pb, 'ответ Боба', 'ответ Боба, исправлено');
        await app.waitForMessage(pa, 'ответ Боба, исправлено', { sent: false });
        const aliceView = (await ui.messageViews(pa)).find((view) => view.text === 'ответ Боба, исправлено');
        assert.deepStrictEqual({ edited: aliceView.edited, failed: aliceView.failed }, { edited: true, failed: false });
        assert.match(aliceView.quote, /после правки/, 'цитата отредактированного сообщения сохранилась в правке ответа');

        // История с сервера: обе правки читаются у получателя и после перезагрузки.
        await pb.reload();
        await app.waitForApp(pb);
        await app.openChat(pb, GROUP);
        await app.waitForMessage(pb, 'после правки', { sent: false });
        await app.waitForMessage(pb, 'ответ Боба, исправлено', { sent: true });
        const history = await ui.messageViews(pb);
        assert.deepStrictEqual(history.map((view) => [view.text, view.edited, view.failed]),
            [['после правки', true, false], ['ответ Боба, исправлено', true, false]]);
        assert.match(history[1].quote, /после правки/);
        await pb.screenshot('messages-03-edited-history');
    });
});
