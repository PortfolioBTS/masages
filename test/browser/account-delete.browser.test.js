'use strict';
// Удаление аккаунта в настоящем Chrome: две вкладки одного профиля (общие куки,
// localStorage, IndexedDB и BroadcastChannel — как у человека с двумя вкладками).
// В первой аккаунт удаляется кнопкой «Удалить и выйти»; после этого:
//  - у первой вкладки экран входа с уведомлением об удалении;
//  - вторая вкладка сама узнаёт об удалении: «Аккаунт удалён в другой вкладке»;
//  - на устройстве не осталось ни ключей шифрования (IndexedDB), ни записей
//    localStorage об аккаунте; сервер аккаунта не знает.

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');

const suite = createBrowserSuite('account-delete');
const GROUP = 'Группа перед удалением';

// Состояние входа с точки зрения сервера, как его видит страница.
const authState = (page) => page.evaluate(async () => {
    const res = await fetch('/api/auth', { cache: 'no-store' });
    return res.json();
});

suite.test('удаление аккаунта стирает данные устройства; вторая вкладка видит «удалён в другой вкладке»', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const first = await alice.newPage();
        await app.startAnonymously(first, `${suite.baseUrl}/`);
        await app.createGroup(first, GROUP);
        await app.sendMessage(first, 'сообщение перед удалением');
        const before = await authState(first);
        assert.strictEqual(before.authenticated, true);
        const userId = before.user.id;

        // Данные на устройстве есть (иначе проверка «пусто» после удаления ничего бы не значила).
        const filled = await app.readLocalData(first);
        assert.ok(filled.indexedDb.some(name => name.endsWith(`-${userId}`)), `нет базы ключей аккаунта: ${JSON.stringify(filled)}`);
        assert.ok(filled.local.length > 0, 'в localStorage нет записей аккаунта');
        assert.strictEqual((await suite.query('SELECT 1 FROM users WHERE id = $1', [userId])).rowCount, 1);

        // Вторая вкладка того же аккаунта.
        const second = await alice.newPage();
        await second.goto(`${suite.baseUrl}/`);
        await app.waitForApp(second);
        await second.screenshot('account-01-second-tab-before');

        await app.deleteAccount(first);
        await first.waitForText('#auth-notice', app.TEXT.deleted, { timeoutMs: app.APP_TIMEOUT_MS });
        await first.screenshot('account-02-deleted');

        // Вторая вкладка узнаёт сама: уведомление «в другой вкладке» на экране входа.
        await second.waitForSelector('#auth-screen:not(.hidden)', { timeoutMs: app.APP_TIMEOUT_MS });
        await second.waitForText('#auth-notice', app.TEXT.deletedElsewhere, { timeoutMs: app.APP_TIMEOUT_MS });
        assert.strictEqual(await second.isVisible('#app'), false);
        await second.screenshot('account-03-deleted-elsewhere');

        // Устройство: ни баз IndexedDB, ни ключей localStorage, ни следов в sessionStorage.
        for (const [label, page] of [['первая вкладка', first], ['вторая вкладка', second]]) {
            // Удаление базы ждёт закрытия соединений, поэтому не мгновенно.
            await page.waitFor(async () => (await indexedDB.databases()).length === 0, { what: `IndexedDB пуста (${label})`, timeoutMs: 15000 });
            assert.deepStrictEqual(await app.readLocalData(page), { local: [], session: [], indexedDb: [] }, `на устройстве остались данные (${label})`);
        }

        // Сервер: сессии нет, аккаунта нет.
        assert.strictEqual((await authState(first)).authenticated, false);
        assert.strictEqual((await suite.query('SELECT 1 FROM users WHERE id = $1', [userId])).rowCount, 0);
    });
});
