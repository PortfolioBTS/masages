'use strict';
// Поиск в настоящем Chrome: по сообщениям открытого чата (подсветка через CSS
// Custom Highlight API, счётчик, переход между совпадениями, «е» и «ё» не
// различаются, регистр не важен) и по списку чатов. Всё считается на устройстве:
// между первым вводом и закрытием поиска страница не делает ни одного сетевого
// запроса (события Network протокола CDP; транспорт socket.io не в счёт).

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');

const suite = createBrowserSuite('search');
const GROUP = 'Рабочая группа';
const MESSAGES = ['яблоко красное', 'Груша жёлтая', 'Яблоко зелёное и яблоко сладкое'];

// Сколько диапазонов сейчас подсвечено (все совпадения / текущее).
const highlighted = (page) => page.evaluate(() => {
    const size = (name) => (CSS.highlights.get(name) ? CSS.highlights.get(name).size : 0);
    return { all: size('nyxo-search'), current: size('nyxo-search-current') };
});

const currentMessage = (page) => page.evaluate(() => {
    const el = document.querySelector('#chat-messages .message.is-search-current .message-text');
    return el ? el.textContent : null;
});

suite.test('поиск по сообщениям и по чатам считается на устройстве, без сетевых запросов', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage();
        await app.startAnonymously(page, `${suite.baseUrl}/`);
        await app.createGroup(page, GROUP);
        for (const text of MESSAGES) await app.sendMessage(page, text);

        // Отметки о прочтении и подобное идут «по следам» отправки — ждём тишины и только потом считаем запросы.
        await page.waitForNetworkQuiet();
        const mark = page.networkMark();

        // Регистр не важен: «ЯБЛОКО» находит «яблоко» и «Яблоко» — три вхождения в двух сообщениях.
        await page.click('#chat-search-btn');
        await page.waitForSelector('#chat-search:not(.hidden)');
        await page.type('#chat-search-input', 'ЯБЛОКО');
        await page.waitForText('#chat-search-counter', /3\D+3/);
        assert.deepStrictEqual(await highlighted(page), { all: 3, current: 1 });
        assert.strictEqual(await currentMessage(page), MESSAGES[2], 'сначала выбрано самое новое совпадение');
        await page.screenshot('search-01-chat-search');

        await page.click('#chat-search-prev');
        await page.click('#chat-search-prev');
        await page.waitForText('#chat-search-counter', /1\D+3/);
        assert.strictEqual(await currentMessage(page), MESSAGES[0]);
        await page.click('#chat-search-next');
        await page.waitForText('#chat-search-counter', /2\D+3/);
        // Enter в поле — следующее совпадение.
        await page.click('#chat-search-input');
        await page.press('Enter');
        await page.waitForText('#chat-search-counter', /3\D+3/);

        // «е» вместо «ё»: «желтая» находит «жёлтая».
        await page.type('#chat-search-input', 'желтая');
        await page.waitForText('#chat-search-counter', /1\D+1/);
        assert.strictEqual(await currentMessage(page), MESSAGES[1]);

        // Ничего не найдено: переходы выключены, подсветки нет.
        await page.type('#chat-search-input', 'нетакогослова');
        await page.waitFor(() => document.getElementById('chat-search-next').disabled, { what: 'выключенные кнопки перехода при пустом результате' });
        assert.strictEqual(await page.evaluate(() => document.getElementById('chat-search-prev').disabled), true);
        assert.deepStrictEqual(await highlighted(page), { all: 0, current: 0 });
        assert.ok((await page.text('#chat-search-counter')).trim().length > 0, 'нет сообщения о том, что ничего не найдено');

        // Escape закрывает поиск и снимает подсветку.
        await page.press('Escape');
        await page.waitForGone('#chat-search:not(.hidden)');
        assert.deepStrictEqual(await highlighted(page), { all: 0, current: 0 });

        // Список чатов: фильтр по названию.
        await page.type('#search-input', 'рабоч');
        await page.waitFor(() => document.querySelectorAll('#chats-list .chat-item').length === 1, { what: 'в списке остался один чат' });
        assert.strictEqual((await page.text('#chats-list .chat-item .chat-name')).trim(), GROUP);
        await page.screenshot('search-02-chats-filter');
        await page.type('#search-input', 'нетакогочата');
        await page.waitFor(() => document.querySelectorAll('#chats-list .chat-item').length === 0, { what: 'пустой список чатов при фильтре без совпадений' });
        assert.strictEqual(await page.isVisible('#chats-empty'), true);
        await page.clear('#search-input');
        await page.waitFor(() => document.querySelectorAll('#chats-list .chat-item').length === 2, { what: 'список чатов вернулся после очистки фильтра' });
        assert.strictEqual(await page.isVisible('#chats-empty'), false);

        const requests = page.requestsSince(mark);
        assert.deepStrictEqual(requests, [], `поиск обращался к сети: ${JSON.stringify(requests)}`);

        // Контроль самой проверки: настоящий запрос страницы журнал сети видит (иначе «ни одного запроса» ничего не значило бы).
        const control = page.networkMark();
        await page.evaluate(() => fetch('/api/auth', { cache: 'no-store' }).then(res => res.status));
        const seen = page.requestsSince(control);
        assert.strictEqual(seen.length, 1, `журнал сети не увидел контрольный запрос: ${JSON.stringify(seen)}`);
        assert.ok(seen[0].url.endsWith('/api/auth'));
    });
});
