'use strict';
// Межсайтовая навигация к API (W7 R1 п.5): GET с побочными эффектами - GET /api/messages/:chatId
// отмечает сообщения прочитанными, GET /api/keys/key-shares/:chatId удаляет доставленные ключи -
// проходил по ссылке с чужого сайта (кука SameSite=Lax уходит при переходе). Теперь запрос с
// Sec-Fetch-Site: cross-site к /api/* отклоняется, а свои запросы работают как раньше.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('cross-site-api');
const CROSS_SITE = { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' };

const unreadOf = async (client, chatId) => (await client.chats()).find(c => c.id === chatId).unread;

test('переход с чужого сайта на GET /api/messages/:chatId - 403 и сообщения остаются непрочитанными', async () => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const { ownerChat, memberChat } = await roomWithMember(owner, member);
    await owner.send(ownerChat.id, 'непрочитанное');
    assert.strictEqual(Number(await unreadOf(member, memberChat.id)), 1);

    const crossSite = await member.get(`/api/messages/${memberChat.id}`, { headers: CROSS_SITE });
    assert.strictEqual(crossSite.status, 403);
    assert.deepStrictEqual(crossSite.body, { success: false, message: 'Запрещено: запрос с чужого сайта' });
    assert.strictEqual(Number(await unreadOf(member, memberChat.id)), 1, 'побочный эффект не выполнился');

    // Свой клиент (same-origin) и запрос из адресной строки (none) - как раньше.
    const own = await member.get(`/api/messages/${memberChat.id}`, { headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors' } });
    assert.strictEqual(own.status, 200);
    assert.strictEqual(Number(await unreadOf(member, memberChat.id)), 0, 'свой запрос отметил прочитанным');
});

test('cross-site блокируется при любом методе и любом пути /api (в том числе выдача и удаление ключей)', async () => {
    const a = suite.client();
    await a.registerAnon();
    for (const [method, path] of [
        ['GET', '/api/auth'], ['GET', '/api/chats'], ['GET', '/api/keys/key-shares/1'], ['GET', '/api/keys/key-requests/1'],
        ['POST', '/api/chats'], ['DELETE', '/api/chats/1'], ['GET', '/api/nope'],
    ]) {
        const res = await a.request(method, path, { headers: CROSS_SITE, json: method === 'POST' ? { name: 'x' } : undefined });
        assert.strictEqual(res.status, 403, `${method} ${path}`);
        assert.strictEqual(res.body.success, false);
    }
    // Не API: страница и статика отдаются (для них заголовок значения не имеет).
    const page = await a.get('/', { headers: CROSS_SITE });
    assert.strictEqual(page.status, 200);
    // Без Sec-Fetch-Site (curl, старые браузеры) API работает.
    assert.strictEqual((await a.get('/api/chats')).status, 200);
});
