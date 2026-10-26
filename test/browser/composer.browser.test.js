'use strict';
// Исправления клиента по ревью W7 R3 (T7.3) в настоящем Chrome:
//  1) правка, ответ, плашки, Esc; многострочное поле (Shift+Enter, вставка, автовысота до шести строк);
//     меню сообщения и меню чата с клавиатуры (ContextMenu, Shift+F10, стрелки, Esc возвращает фокус);
//  2) реакции между двумя профилями: событие reactionChanged без перезагрузки, снятие после перезагрузки;
//  3) окно подтверждения: «Отмена» не выводит из группы, Escape и затемнение, «Выйти и удалить сообщения»;
//     клик по затемнению закрывает обычное окно;
//  4) 320×640: «Начать анонимно» в первом экране; сенсорный экран: цели нажатия ≥ 44 px; изоляция bidi.
// Логика отдельных функций проверена юнит-тестами test/client-*.test.js; здесь — то, что без браузера не увидеть
// (фокус, раскладка, настоящие клавиши и события).

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');

const suite = createBrowserSuite('composer');
const GROUP = 'Группа композера';

// ---- вспомогательное ----

const isHidden = (page, selector) => page.evaluate((sel) => document.querySelector(sel).classList.contains('hidden'), selector);

// Элемент, у которого сейчас фокус: тег, id и первые классы.
const focused = (page) => page.evaluate(() => {
    const el = document.activeElement;
    return { tag: el.tagName.toLowerCase(), id: el.id, cls: String(el.className || ''), text: (el.textContent || '').trim().slice(0, 40) };
});

// Поставить фокус на сообщение по тексту (как после Tab).
const focusMessage = (page, text) => page.evaluate((wanted) => {
    const el = Array.from(document.querySelectorAll('#chat-messages .message')).find(m => m.querySelector('.message-text').textContent === wanted);
    if (!el) throw new Error(`нет сообщения «${wanted}»`);
    el.focus();
    return true;
}, text);

// Клик в точку окна страницы (по затемнению вокруг окна, где нет элементов с нужным id).
async function clickAt(page, x, y) {
    await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
    await page.send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1, pointerType: 'mouse' });
    await page.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1, pointerType: 'mouse' });
}

const messageTexts = (page) => page.evaluate(() => Array.from(document.querySelectorAll('#chat-messages .message .message-text'), el => el.textContent));

// ---- 1. правка, ответ, многострочное поле, меню с клавиатуры ----

suite.test('правка и ответ: плашки, Esc, очистка поля; меню сообщения с клавиатуры; многострочное поле', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage();
        await app.startAnonymously(page, `${suite.baseUrl}/`);
        await app.createGroup(page, GROUP);
        await app.sendMessage(page, 'первое');
        await app.sendMessage(page, 'второе');

        // Сообщения берут фокус с клавиатуры.
        assert.deepStrictEqual(await page.evaluate(() => {
            const el = document.querySelector('#chat-messages .message');
            return { tabindex: el.getAttribute('tabindex'), role: el.getAttribute('role') };
        }), { tabindex: '0', role: 'article' });

        // ContextMenu открывает меню, фокус на первом пункте; стрелки и Home/End; Escape возвращает фокус.
        await focusMessage(page, 'первое');
        await page.press('ContextMenu');
        await page.waitForSelector('#message-menu:not(.hidden)');
        assert.strictEqual((await focused(page)).cls.includes('reaction-option'), true, 'фокус должен быть на первом пункте (реакция)');
        await page.press('End');
        assert.strictEqual((await focused(page)).id, 'delete-message-btn', 'End — последний видимый пункт');
        await page.press('Home');
        assert.strictEqual((await focused(page)).cls.includes('reaction-option'), true);
        await page.press('ArrowDown');
        assert.strictEqual(await page.evaluate(() => Array.from(document.querySelectorAll('#reaction-picker .reaction-option')).indexOf(document.activeElement)), 1, 'стрелка вниз переводит фокус на следующий пункт');
        await page.press('Escape');
        assert.strictEqual(await isHidden(page, '#message-menu'), true);
        const back = await focused(page);
        assert.ok(back.cls.includes('message'), `после Escape фокус должен вернуться на сообщение, а не на ${back.tag}`);
        // Shift+F10 — то же.
        await page.press('F10', { shift: true });
        await page.waitForSelector('#message-menu:not(.hidden)');
        await page.press('Escape');

        // Правка: плашка «Редактирование», поле заполнено, очистка поля отменяет правку.
        await focusMessage(page, 'первое');
        await page.press('ContextMenu');
        await page.click('#edit-message-btn');
        await page.waitForSelector('#edit-preview:not(.hidden)');
        assert.match(await page.text('#edit-preview-text'), /^Редактирование: первое$/);
        assert.strictEqual(await page.evaluate(() => document.getElementById('message-input').value), 'первое');
        await page.clear('#message-input');
        await page.waitForGone('#edit-preview:not(.hidden)');

        // Esc в поле тоже отменяет правку и стирает подставленный текст.
        await focusMessage(page, 'первое');
        await page.press('ContextMenu');
        await page.click('#edit-message-btn');
        await page.waitForSelector('#edit-preview:not(.hidden)');
        await page.press('Escape');
        await page.waitForGone('#edit-preview:not(.hidden)');
        assert.strictEqual(await page.evaluate(() => document.getElementById('message-input').value), '');

        // «Ответить» во время правки отменяет правку (иначе ответ тихо ушёл бы правкой).
        await focusMessage(page, 'первое');
        await page.press('ContextMenu');
        await page.click('#edit-message-btn');
        await page.waitForSelector('#edit-preview:not(.hidden)');
        await focusMessage(page, 'второе');
        await page.press('ContextMenu');
        await page.click('#reply-message-btn');
        await page.waitForSelector('#reply-preview:not(.hidden)');
        assert.strictEqual(await isHidden(page, '#edit-preview'), true, 'плашка правки осталась после «Ответить»');
        assert.strictEqual(await page.evaluate(() => document.getElementById('message-input').value), '', 'текст правки остался в поле ответа');
        await page.click('#cancel-reply-btn');
        await page.waitForGone('#reply-preview:not(.hidden)');

        // Правка доводится до конца: Enter сохраняет, плашка исчезает, в ленте новый текст.
        await focusMessage(page, 'первое');
        await page.press('ContextMenu');
        await page.click('#edit-message-btn');
        await page.waitForSelector('#edit-preview:not(.hidden)');
        await page.type('#message-input', 'первое, исправлено');
        await page.press('Enter');
        await app.waitForMessage(page, 'первое, исправлено', { sent: true });
        assert.strictEqual(await isHidden(page, '#edit-preview'), true);
        assert.deepStrictEqual(await messageTexts(page), ['первое, исправлено', 'второе'], 'правка не создала новое сообщение');

        // Многострочное поле: Shift+Enter — перенос, высота растёт, Enter отправляет все строки.
        const oneLine = await page.evaluate(() => document.getElementById('message-input').offsetHeight);
        // Первый ввод — с кликом в поле; дальше текст идёт в то же место (повторный клик переставил бы курсор).
        await page.type('#message-input', 'строка 1');
        await page.press('Enter', { shift: true });
        await page.send('Input.insertText', { text: 'строка 2' });
        await page.press('Enter', { shift: true });
        await page.send('Input.insertText', { text: 'строка 3' });
        assert.strictEqual(await page.evaluate(() => document.getElementById('message-input').value), 'строка 1\nстрока 2\nстрока 3');
        assert.ok((await page.evaluate(() => document.getElementById('message-input').offsetHeight)) > oneLine, 'поле не выросло на трёх строках');
        assert.strictEqual((await messageTexts(page)).length, 2, 'Shift+Enter не должен отправлять');
        await page.press('Enter');
        await app.waitForMessage(page, 'строка 1\nстрока 2\nстрока 3', { sent: true });
        assert.strictEqual(await page.evaluate(() => document.getElementById('message-input').offsetHeight), oneLine, 'после отправки поле снова в одну строку');

        // Вставка текста с переносами сохраняет их; больше шести строк — поле не растёт дальше и прокручивается.
        await page.type('#message-input', Array.from({ length: 10 }, (_, i) => `стр ${i + 1}`).join('\n'));
        const big = await page.evaluate(() => {
            const el = document.getElementById('message-input');
            return { lines: el.value.split('\n').length, height: el.offsetHeight, scrolls: el.scrollHeight > el.clientHeight, overflowY: getComputedStyle(el).overflowY };
        });
        assert.strictEqual(big.lines, 10);
        assert.ok(big.height <= 142, `поле выше шести строк: ${big.height}px`);
        assert.ok(big.scrolls && big.overflowY === 'auto', 'длинный текст должен прокручиваться');
        await page.screenshot('composer-01-multiline');
    });
});

// ---- 2. реакции между двумя профилями ----

suite.test('реакции: собеседник видит без перезагрузки, свою реакцию можно снять после перезагрузки', async () => {
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        await app.sendMessage(pa, 'поставь реакцию');
        await app.waitForMessage(pb, 'поставь реакцию', { sent: false });

        const reactionsOf = (page) => page.evaluate(() => Array.from(document.querySelectorAll('#chat-messages .message .reactions .reaction'), el => ({ active: el.classList.contains('is-active'), title: el.title })));

        // Боб ставит реакцию из меню, открытого с клавиатуры.
        await focusMessage(pb, 'поставь реакцию');
        await pb.press('ContextMenu');
        await pb.waitForSelector('#message-menu:not(.hidden)');
        await pb.click('#reaction-picker .reaction-option');
        await pb.waitFor(() => document.querySelectorAll('#chat-messages .message .reactions .reaction').length === 1, { what: 'своя реакция у Боба' });
        assert.deepStrictEqual((await reactionsOf(pb)).map(r => r.active), [true]);
        // Алиса видит её сразу, без перезагрузки, и она не «её».
        await pa.waitFor(() => document.querySelectorAll('#chat-messages .message .reactions .reaction').length === 1, { what: 'реакция Боба у Алисы без перезагрузки', timeoutMs: 15000 });
        assert.deepStrictEqual((await reactionsOf(pa)).map(r => r.active), [false]);

        // Боб перезагружает страницу: реакция на месте и отмечена как его; повторный выбор снимает её.
        await pb.reload();
        await app.waitForApp(pb);
        await app.openChat(pb, GROUP);
        await app.waitForMessage(pb, 'поставь реакцию', { sent: false });
        await pb.waitFor(() => document.querySelectorAll('#chat-messages .message .reactions .reaction.is-active').length === 1, { what: 'своя реакция после перезагрузки' });
        await focusMessage(pb, 'поставь реакцию');
        await pb.press('ContextMenu');
        await pb.waitForSelector('#message-menu:not(.hidden)');
        assert.strictEqual(await pb.evaluate(() => document.querySelector('#reaction-picker .reaction-option').getAttribute('aria-pressed')), 'true');
        await pb.click('#reaction-picker .reaction-option');
        await pb.waitFor(() => document.querySelectorAll('#chat-messages .message .reactions .reaction').length === 0, { what: 'реакция снята после перезагрузки' });
        await pa.waitFor(() => document.querySelectorAll('#chat-messages .message .reactions .reaction').length === 0, { what: 'снятая реакция исчезла у Алисы', timeoutMs: 15000 });
        await pb.screenshot('composer-02-reactions');
    });
});

// ---- 3. окно подтверждения, выход из группы, затемнение ----

suite.test('выход из группы: «Отмена» не выводит; Escape и затемнение; «Выйти и удалить сообщения»; клик по затемнению закрывает обычное окно', async () => {
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });

        const openLeave = async () => {
            await pb.click('#chat-menu-btn');
            await pb.waitForSelector('#chat-menu-modal:not(.hidden)');
            await pb.click('#delete-chat-btn');
            await pb.waitForSelector('#confirm-modal:not(.hidden)');
        };
        const confirmActions = () => pb.evaluate(() => Array.from(document.querySelectorAll('#confirm-actions button'), b => b.textContent));

        // Своих сообщений у Боба нет: про сообщения не спрашивают, «Отмена» оставляет его в группе.
        await openLeave();
        assert.deepStrictEqual(await confirmActions(), ['Отмена', 'Выйти']);
        assert.ok((await focused(pb)).text === 'Отмена', 'фокус сначала на «Отмене»');
        await pb.click('#confirm-actions [data-cancel]');
        await pb.waitForGone('#confirm-modal:not(.hidden)');
        assert.strictEqual(await pb.evaluate(() => document.getElementById('chat-name').textContent), GROUP, 'после «Отмены» Боб всё ещё в группе');
        await pb.press('Escape');
        await pb.waitForGone('#chat-menu-modal:not(.hidden)');

        // Теперь есть своё сообщение: три исхода.
        await app.sendMessage(pb, 'моё сообщение');
        await openLeave();
        // Три кнопки — столбец, «Отмена» последней и в DOM: порядок Tab совпадает с видимым (RR-8); фокус — на «Отмене».
        assert.deepStrictEqual(await confirmActions(), ['Выйти и оставить сообщения', 'Выйти и удалить сообщения', 'Отмена']);
        assert.strictEqual(await pb.evaluate(() => document.activeElement && document.activeElement.hasAttribute('data-cancel')), true);
        // Затемнение alertdialog не закрывает; Escape закрывает только его — окно меню чата под ним остаётся.
        await clickAt(pb, 4, 4);
        assert.strictEqual(await isHidden(pb, '#confirm-modal'), false, 'alertdialog закрылся кликом по затемнению');
        await pb.press('Escape');
        await pb.waitForGone('#confirm-modal:not(.hidden)');
        assert.strictEqual(await isHidden(pb, '#chat-menu-modal'), false, 'Escape закрыл и окно под подтверждением');
        assert.strictEqual((await focused(pb)).id, 'delete-chat-btn', 'фокус вернулся на кнопку, вызвавшую вопрос');
        // Обычное окно закрывается кликом по затемнению вокруг него.
        await clickAt(pb, 4, 4);
        await pb.waitForGone('#chat-menu-modal:not(.hidden)');
        await pb.screenshot('composer-03-confirm');

        // Светлая тема: то же окно подтверждения читается и в ней (снимок для просмотра человеком).
        await pb.click('#theme-toggle-btn');
        assert.strictEqual(await pb.evaluate(() => document.documentElement.dataset.theme), 'light');
        await openLeave();
        await pb.screenshot('composer-03-confirm-light');
        await pb.press('Escape');
        await pb.waitForGone('#confirm-modal:not(.hidden)');
        await pb.press('Escape');
        await pb.waitForGone('#chat-menu-modal:not(.hidden)');
        await pb.click('#theme-toggle-btn');

        // «Выйти и удалить сообщения»: Боб выходит, сообщение исчезает у Алисы.
        await openLeave();
        await pb.click('#confirm-actions [data-action="leave-delete"]');
        await pb.waitFor((name) => !Array.from(document.querySelectorAll('#chats-list .chat-item .chat-name')).some(el => el.textContent.trim() === name), { args: [GROUP], what: 'группа пропала из списка Боба' });
        await pa.waitFor(() => !Array.from(document.querySelectorAll('#chat-messages .message .message-text')).some(el => el.textContent === 'моё сообщение'), { what: 'сообщение Боба удалено у Алисы', timeoutMs: 15000 });
    });
});

// ---- 4. узкий экран, сенсорный экран, bidi ----

suite.test('320×640: «Начать анонимно» и «У меня есть приглашение» в первом экране, без горизонтальной прокрутки', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage({ width: 320, height: 640 });
        await page.goto(`${suite.baseUrl}/`);
        await page.waitForSelector('#anon-start-btn');
        const m = await page.evaluate(() => ({
            vh: innerHeight,
            start: document.getElementById('anon-start-btn').getBoundingClientRect().bottom,
            invite: document.getElementById('invite-toggle-btn').getBoundingClientRect().bottom,
            wide: document.documentElement.scrollWidth > innerWidth,
            options: Array.from(document.querySelectorAll('#auth-lifetime .segmented-option'), (el) => {
                const span = el.querySelector('span');
                const box = el.getBoundingClientRect();
                const text = span.getBoundingClientRect();
                const clipped = span.scrollWidth > span.clientWidth || text.left < box.left || text.right > box.right;
                return { text: span.textContent, height: box.height, clipped };
            }),
        }));
        assert.ok(m.start <= m.vh, `«Начать анонимно» ниже первого экрана: ${m.start} > ${m.vh}`);
        assert.ok(m.invite <= m.vh, `«У меня есть приглашение» ниже первого экрана: ${m.invite} > ${m.vh}`);
        assert.strictEqual(m.wide, false, 'горизонтальная прокрутка');
        // Варианты срока в две строки (controls.css): текст целиком, цель нажатия не меньше 44 px.
        assert.strictEqual(m.options.length, 3);
        for (const option of m.options) {
            assert.strictEqual(option.clipped, false, `текст варианта «${option.text}» обрезан`);
            assert.ok(option.height >= 44, `вариант «${option.text}» ниже 44 px: ${option.height}`);
        }
        await page.screenshot('composer-04-auth-320');
    });
});

suite.test('сенсорный экран 375×812: цели нажатия не меньше 44 px; bidi-названия изолированы', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage({ width: 375, height: 812 });
        // Сенсорный экран: (pointer: coarse) включается эмуляцией касаний в мобильном режиме.
        await page.send('Emulation.setDeviceMetricsOverride', { width: 375, height: 812, deviceScaleFactor: 1, mobile: true });
        await page.send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
        await page.goto(`${suite.baseUrl}/`);
        await page.waitForSelector('#anon-start-btn');
        assert.strictEqual(await page.evaluate(() => matchMedia('(pointer: coarse)').matches), true, 'эмуляция не включила pointer: coarse');
        await page.click('#anon-start-btn');
        await app.waitForApp(page);

        const size = (selector) => page.evaluate((sel) => {
            const r = document.querySelector(sel).getBoundingClientRect();
            return { w: Math.round(r.width), h: Math.round(r.height) };
        }, selector);
        for (const selector of ['#new-chat-btn', '#theme-toggle-btn']) {
            const s = await size(selector);
            assert.ok(s.w >= 44 && s.h >= 44, `${selector}: ${s.w}×${s.h}`);
        }
        // «Профиль» и «Удалить и выйти» — широкие кнопки: важна высота.
        for (const selector of ['#profile-btn', '#logout-btn']) {
            const s = await size(selector);
            assert.ok(s.h >= 44, `${selector}: ${s.w}×${s.h}`);
        }

        // Группа с названием на арабском и иврите: названия изолированы, кнопки шапки — не меньше 44×44.
        const RTL = 'مرحبا שלום';
        await app.createGroup(page, RTL);
        for (const selector of ['#back-btn', '#chat-search-btn', '#chat-menu-btn']) {
            const s = await size(selector);
            assert.ok(s.w >= 44 && s.h >= 44, `${selector}: ${s.w}×${s.h}`);
        }
        for (const selector of ['#e2ee-indicator']) {
            if (await page.isVisible(selector)) {
                const s = await size(selector);
                assert.ok(s.w >= 32 && s.h >= 32, `${selector}: ${s.w}×${s.h}`);
            }
        }
        const bidi = await page.evaluate(() => ({
            header: getComputedStyle(document.getElementById('chat-name')).unicodeBidi,
            list: getComputedStyle(document.querySelector('#chats-list .chat-item .chat-name')).unicodeBidi,
        }));
        assert.deepStrictEqual(bidi, { header: 'isolate', list: 'isolate' });
        // Лента и ориентиры.
        assert.deepStrictEqual(await page.evaluate(() => ({
            log: document.getElementById('chat-messages').getAttribute('role'),
            live: document.getElementById('chat-messages').getAttribute('aria-live'),
            main: Boolean(document.querySelector('main.main-content')),
            aside: Boolean(document.querySelector('aside.sidebar')),
        })), { log: 'log', live: 'off', main: true, aside: true });
        await page.screenshot('composer-05-touch');
    });
});
