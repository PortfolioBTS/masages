'use strict';
// Настройки чата и аккаунта в настоящем Chrome, с утверждениями по интерфейсу И по базе (ревью W7 R5, З-12):
//  1) таймер исчезающих сообщений: выбранный срок уходит на сервер (room_settings), виден собеседнику без
//     перезагрузки и после неё, у сообщения появляется срок в message_expiry, по истечении оно пропадает
//     у обоих; выключение возвращает обычные сообщения;
//  2) срок хранения аккаунта (tab/day/week): смена в профиле меняет users.anon_lifetime, подписи в профиле и
//     боковой панели, вторая вкладка профиля узнаёт об этом сама, чат после смены работает (сокет
//     переподключён к новой сессии), после перезагрузки выбор на месте.
// Чистка просроченных сообщений ускорена CLEANUP_INTERVAL_MS: ждать минуту не нужно.

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');
const ui = require('./helpers/ui');

const suite = createBrowserSuite('settings', { env: { CLEANUP_INTERVAL_MS: '300' } });

const expirySetting = async (roomId) => {
    const { rows } = await suite.query('SELECT default_message_expiry FROM room_settings WHERE room_id = $1', [roomId]);
    return rows.length === 0 ? 0 : Number(rows[0].default_message_expiry);
};
const expiryRows = async (roomId) => (await suite.query(
    `SELECT me.message_id, EXTRACT(EPOCH FROM (me.expires_at - LOCALTIMESTAMP))::float8 AS left_s
       FROM message_expiry me JOIN messages m ON m.id = me.message_id WHERE m.room_id = $1`, [roomId])).rows;
const roomMessageCount = async (roomId) => Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1', [roomId])).rows[0].n);

async function chooseExpiry(page, seconds) {
    await page.click('#chat-menu-btn');
    await page.waitForSelector('#chat-menu-modal:not(.hidden)');
    await page.click(`label.radio-row:has(input[name="chat-expiry"][value="${seconds}"])`);
}

const checkedExpiry = (page) => page.evaluate(() => {
    const radio = document.querySelector('input[name="chat-expiry"]:checked');
    return radio ? Number(radio.value) : null;
});

const indicator = (page) => page.evaluate(() => {
    const el = document.getElementById('expiry-indicator');
    return { visible: !el.classList.contains('hidden'), text: document.getElementById('expiry-indicator-text').textContent, title: el.title };
});

suite.test('таймер исчезновения: срок уходит на сервер, виден собеседнику, сообщение исчезает у обоих, выключение возвращает обычные', async () => {
    const GROUP = 'Исчезающие';
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        const roomId = await ui.roomIdByName(suite, GROUP);
        assert.strictEqual(await expirySetting(roomId), 0, 'по умолчанию таймера нет');
        assert.deepStrictEqual((await indicator(pa)).visible, false);

        // Алиса выбирает 5 минут: запрос уходит с этим сроком, интерфейс и база согласны.
        await chooseExpiry(pa, 300);
        await pa.waitForText('#toast', /Исчезающие сообщения: 5 минут/);
        assert.strictEqual(await expirySetting(roomId), 300, 'на сервере сохранён выбранный срок, а не 0');
        assert.strictEqual(await checkedExpiry(pa), 300);
        assert.deepStrictEqual(await indicator(pa), { visible: true, text: '5 мин', title: 'Исчезающие сообщения: 5 минут' });
        await pa.press('Escape');
        await pa.waitForGone('#chat-menu-modal:not(.hidden)');

        // Боб видит смену без перезагрузки (служебная строка и значок), и после перезагрузки срок на месте.
        await ui.waitForNoticeText(pb, /Исчезающие сообщения: 5 минут/);
        assert.deepStrictEqual((await indicator(pb)).text, '5 мин');
        await pb.reload();
        await app.waitForApp(pb);
        await app.openChat(pb, GROUP);
        await pb.waitFor(() => !document.getElementById('expiry-indicator').classList.contains('hidden'), { what: 'значок таймера у Боба после перезагрузки' });
        assert.strictEqual((await indicator(pb)).text, '5 мин');
        await pb.click('#chat-menu-btn');
        await pb.waitForSelector('#chat-menu-modal:not(.hidden)');
        assert.strictEqual(await checkedExpiry(pb), 300, 'в окне чата у Боба отмечен тот же срок');
        await pb.press('Escape');
        await pb.waitForGone('#chat-menu-modal:not(.hidden)');

        // Новое сообщение получает срок жизни ≈ выбранному (время огрубляется вверх до минуты).
        await app.sendMessage(pa, 'исчезнет');
        await app.waitForMessage(pb, 'исчезнет', { sent: false });
        const rows = await expiryRows(roomId);
        assert.strictEqual(rows.length, 1, 'срок записан ровно для одного сообщения');
        assert.ok(rows[0].left_s > 295 && rows[0].left_s <= 365, `срок сообщения ${rows[0].left_s} с вместо ≈300`);

        // Срок вышел (перемотка данных в БД): чистка удаляет сообщение, оно пропадает у обоих без перезагрузки.
        await suite.query(`UPDATE message_expiry SET expires_at = LOCALTIMESTAMP - INTERVAL '1 minute' WHERE message_id = $1`, [rows[0].message_id]);
        await ui.waitForNoMessage(pa, 'исчезнет');
        await ui.waitForNoMessage(pb, 'исчезнет');
        assert.strictEqual(await roomMessageCount(roomId), 0, 'строка сообщения удалена из БД');

        // Выключение: значок скрыт у обоих, новое сообщение живёт без срока.
        await chooseExpiry(pa, 0);
        await pa.waitForText('#toast', /Исчезающие сообщения выключены/);
        assert.strictEqual(await expirySetting(roomId), 0);
        assert.strictEqual((await indicator(pa)).visible, false);
        await pa.press('Escape');
        await pb.waitFor(() => document.getElementById('expiry-indicator').classList.contains('hidden'), { what: 'значок таймера скрыт у Боба' });
        await ui.waitForNoticeText(pb, /Исчезающие сообщения выключены/);
        await app.sendMessage(pa, 'останется');
        await app.waitForMessage(pb, 'останется', { sent: false });
        assert.deepStrictEqual(await expiryRows(roomId), [], 'у сообщения без таймера нет срока');
        await pa.screenshot('settings-01-expiry');
    });
});

suite.test('срок хранения аккаунта: смена в профиле меняет базу и подписи, вторая вкладка узнаёт сама, чат работает, после перезагрузки на месте', async () => {
    const GROUP = 'Срок аккаунта';
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();
        await app.groupWithMember({ baseUrl: suite.baseUrl, name: GROUP, owner: alice, ownerPage: pa, memberPage: pb });
        const userId = await pa.evaluate(async () => (await (await fetch('/api/auth', { cache: 'no-store' })).json()).user.id);
        const lifetimeInDb = async () => (await suite.query('SELECT anon_lifetime FROM users WHERE id = $1', [userId])).rows[0].anon_lifetime;
        const second = await alice.newPage();
        await second.goto(`${suite.baseUrl}/`);
        await app.waitForApp(second);

        assert.strictEqual(await lifetimeInDb(), 'tab', 'по умолчанию — пока открыта вкладка');
        const profile = async (page) => {
            await page.click('#profile-btn');
            await page.waitForSelector('#profile-modal:not(.hidden)');
            return page.evaluate(() => ({
                checked: (document.querySelector('input[name="profile-lifetime"]:checked') || {}).value || null,
                status: document.getElementById('profile-lifetime-status').textContent,
            }));
        };
        const before = await profile(pa);
        assert.strictEqual(before.checked, 'tab');
        assert.match(before.status, /Удалится через 30 минут после закрытия последней вкладки/);

        await pa.click('label.segmented-option:has(input[name="profile-lifetime"][value="week"])');
        await pa.waitForText('#toast', /Срок хранения: 7 дней/);
        assert.strictEqual(await lifetimeInDb(), 'week', 'на сервере сохранён выбранный срок');
        const after = await pa.evaluate(() => ({
            checked: document.querySelector('input[name="profile-lifetime"]:checked').value,
            status: document.getElementById('profile-lifetime-status').textContent,
            note: document.getElementById('anon-note-text').textContent,
        }));
        assert.strictEqual(after.checked, 'week');
        assert.match(after.status, /^Удалится(, если не заходить до | после 7 дней без входа)/);
        assert.strictEqual(after.note, 'Удалится, если не заходить 7 дней');
        await app.closeModal(pa, 'profile-modal');

        // Вторая вкладка того же аккаунта узнаёт о смене сама (BroadcastChannel), без перезагрузки.
        const other = await profile(second);
        assert.strictEqual(other.checked, 'week');
        assert.strictEqual(await second.text('#anon-note-text'), 'Удалится, если не заходить 7 дней');
        await app.closeModal(second, 'profile-modal');

        // Сессия пересоздана, сокет переподключён: сообщения идут в обе стороны.
        await app.sendMessage(pa, 'после смены срока');
        await app.waitForMessage(pb, 'после смены срока', { sent: false });
        await app.sendMessage(pb, 'ответ после смены');
        await app.waitForMessage(pa, 'ответ после смены', { sent: false });

        // Перезагрузка: аккаунт тот же, срок тот же.
        await pa.reload();
        await app.waitForApp(pa);
        const reloaded = await profile(pa);
        assert.strictEqual(reloaded.checked, 'week');
        assert.strictEqual(await lifetimeInDb(), 'week');
        await pa.screenshot('settings-02-lifetime');
        await app.closeModal(pa, 'profile-modal');
    });
});
