'use strict';
// Лимиты на аккаунт (W7 R1 п.3): суточный объём текста сообщений и потолок числа комнат.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

// Суточный объём текста ~2 КБ (0,002 МБ = 2097 байт); комнат на аккаунт - 3.
const suite = createSuite('account-quotas', { env: { TEXT_QUOTA_MB_PER_DAY: '0.002', ROOMS_PER_USER_MAX: '3' } });

test('суточный объём текста: сверх него - 429 text-quota, сообщение не сохраняется, у других аккаунтов свой счёт', async () => {
    const a = suite.client();
    const b = suite.client();
    await a.registerAnon();
    await b.registerAnon();
    const botA = await a.botChat();
    const botB = await b.botChat();
    const chunk = 'а'.repeat(250); // кириллица: 500 байт в UTF-8 - лимит считается в байтах, а не в символах
    for (let i = 0; i < 4; i++) await a.send(botA.id, chunk);
    const before = (await suite.query('SELECT count(*)::int AS n FROM messages WHERE chat_id = $1 AND sent = 1', [botA.id])).rows[0].n;

    const over = await a.sendRaw(botA.id, chunk);
    assert.strictEqual(over.status, 429, JSON.stringify(over.body));
    assert.strictEqual(over.body.code, 'text-quota');
    assert.match(over.body.message, /Суточный объём сообщений исчерпан/);
    const after = (await suite.query('SELECT count(*)::int AS n FROM messages WHERE chat_id = $1 AND sent = 1', [botA.id])).rows[0].n;
    assert.strictEqual(after, before, 'отказанное сообщение не сохранено');

    // Короткое сообщение, влезающее в остаток, проходит: счёт идёт по байтам.
    await a.send(botA.id, 'ок');
    // Другой аккаунт не затронут.
    await b.send(botB.id, chunk);

    // Счётчик лежит под HMAC-ключом без id и сам истекает в течение суток.
    const rows = (await suite.query("SELECT k, reset_at - now() AS left FROM rl_counters WHERE k LIKE 'text-quota:%'")).rows;
    assert.strictEqual(rows.length, 2);
    for (const row of rows) {
        assert.match(row.k, /^text-quota:[A-Za-z0-9_-]{43}$/);
        assert.ok(row.left.hours >= 23 || row.left.days >= 1, 'окно - сутки');
    }
});

test('потолок комнат: четвёртая создаваемая комната - 403 rooms-limit, выход освобождает место', async () => {
    const owner = suite.client();
    await owner.registerAnon();
    const rooms = [];
    for (let i = 0; i < 3; i++) rooms.push(await owner.createRoom(`Комната ${i}`));
    const refused = await owner.post('/api/chats', { name: 'Лишняя' });
    assert.strictEqual(refused.status, 403, JSON.stringify(refused.body));
    assert.strictEqual(refused.body.code, 'rooms-limit');
    assert.match(refused.body.message, /предел числа групп/);
    assert.strictEqual((await owner.chats()).filter(c => c.room_id).length, 3, 'лишняя комната не создана');
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM rooms')).rows[0].n >= 3, true);

    await owner.leave(rooms[0].id);
    const again = await owner.createRoom('Освободилось место');
    assert.ok(again.room_id);
});

test('потолок комнат действует и на вступление: по подписанному приглашению - 403, по заявке - одобрить нельзя, после выхода можно', async () => {
    const owner = suite.client();
    const guest = suite.client();
    await owner.registerAnon();
    await guest.registerAnon();
    for (let i = 0; i < 3; i++) await guest.createRoom(`Своя ${i}`);

    // Вход по приглашению без одобрения.
    const open = await owner.createRoom('Открытая');
    const { code } = await owner.invite(open.id);
    await owner.rotateInvite(open.id, { requireApproval: false });
    const rotated = await owner.invite(open.id);
    const direct = await guest.joinRaw(rotated.code);
    assert.strictEqual(direct.status, 403, JSON.stringify(direct.body));
    assert.strictEqual(direct.body.code, 'rooms-limit');
    assert.ok(code);

    // Вступление по заявке: заявка создаётся, а одобрение упирается в потолок заявителя.
    const closed = await owner.createRoom('С одобрением');
    const closedInvite = await owner.invite(closed.id);
    const pending = await guest.join(closedInvite.code);
    assert.strictEqual(pending.pending, true);
    await assert.rejects(owner.approve(pending.requestId), (err) => {
        assert.strictEqual(err.status, 409);
        assert.strictEqual(err.body.code, 'rooms-limit');
        return true;
    });
    assert.strictEqual((await guest.chats()).filter(c => c.room_id).length, 3);

    // Гость выходит из одной своей комнаты - и заявка одобряется.
    const own = (await guest.chats()).find(c => c.room_id && c.name === 'Своя 0');
    await guest.leave(own.id);
    await owner.approve(pending.requestId);
    assert.ok((await guest.chats()).some(c => c.name === 'С одобрением'));
});

test('уже состоящему в комнате потолок не мешает повторить вход', async () => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const { ownerChat } = await roomWithMember(owner, member, { name: 'Общая' });
    await member.createRoom('Вторая');
    await member.createRoom('Третья');
    assert.strictEqual((await member.chats()).filter(c => c.room_id).length, 3);
    await owner.rotateInvite(ownerChat.id, { requireApproval: false });
    const { code } = await owner.invite(ownerChat.id);
    const again = await member.joinRaw(code);
    assert.notStrictEqual(again.body && again.body.code, 'rooms-limit', JSON.stringify(again.body));
});
