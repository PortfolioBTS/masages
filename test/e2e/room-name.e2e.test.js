'use strict';
// Название комнаты и аватар (W7 R1 п.11): управляющие и двунаправленные символы удаляются на
// сервере, аватар - первая графема (эмодзи не рвётся), предел длины считается по очищенному названию.
// Невидимые символы задаются кодовыми точками (cp), а не записываются в исходнике.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('room-name');
const cp = (...codes) => String.fromCodePoint(...codes);

test('название очищается от bidi, нулевой ширины и управляющих; в ответе, списке чатов и базе - очищенное', async () => {
    const a = suite.client();
    await a.registerAnon();
    const hostile = `${cp(0x202E)}Ad${cp(0x200B)}min${cp(0x2066)}${cp(0x0007)}\tчат${cp(0x202C)}\n`;
    const res = await a.post('/api/chats', { name: hostile });
    assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
    assert.strictEqual(res.body.chat.name, 'Admin чат');
    assert.strictEqual(res.body.chat.avatar, 'A');
    const listed = (await a.chats()).find(c => c.id === res.body.chat.id);
    assert.strictEqual(listed.name, 'Admin чат');
    const row = (await suite.query('SELECT name FROM rooms WHERE id = $1', [res.body.chat.room_id])).rows[0];
    assert.strictEqual(row.name, 'Admin чат');
    const chatRow = (await suite.query('SELECT name, avatar FROM chats WHERE id = $1', [res.body.chat.id])).rows[0];
    assert.deepStrictEqual({ ...chatRow }, { name: 'Admin чат', avatar: 'A' });
});

test('название только из невидимых символов - «Введите имя чата»; предел 64 символа считается после очистки', async () => {
    const a = suite.client();
    await a.registerAnon();
    const empty = await a.post('/api/chats', { name: `${cp(0x202E, 0x200B)}  ${cp(0x2066, 0x2069)}` });
    assert.deepStrictEqual(empty.body, { success: false, message: 'Введите имя чата' });
    const long = await a.post('/api/chats', { name: 'я'.repeat(65) });
    assert.strictEqual(long.body.success, false);
    assert.match(long.body.message, /не может быть длиннее 64/);
    const padded = await a.post('/api/chats', { name: `${cp(0x200B).repeat(200)}${'я'.repeat(64)}` });
    assert.strictEqual(padded.body.success, true, 'невидимые символы в длину не засчитываются');
    assert.strictEqual(padded.body.chat.name.length, 64);
});

test('аватар - первая графема: эмодзи, флаг и символ вне BMP не превращаются в одиночный суррогат', async () => {
    const a = suite.client();
    await a.registerAnon();
    for (const [name, avatar] of [['🚀 Запуск', '🚀'], ['🇷🇺 Россия', '🇷🇺'], ['👍🏽 Класс', '👍🏽'], [`${cp(0x1D49C)} математика`, cp(0x1D49C)], ['друзья', 'Д']]) {
        const res = await a.post('/api/chats', { name });
        assert.strictEqual(res.body.success, true, `${name}: ${JSON.stringify(res.body)}`);
        assert.strictEqual(res.body.chat.avatar, avatar, name);
        assert.ok(res.body.chat.avatar.isWellFormed(), `${name}: в аватаре нет одиночного суррогата`);
        const row = (await suite.query('SELECT avatar FROM chats WHERE id = $1', [res.body.chat.id])).rows[0];
        assert.strictEqual(row.avatar, avatar, `${name}: и в базе`);
    }
});

test('вступивший видит очищенное название и аватар-эмодзи целиком', async () => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const { memberChat, ownerChat } = await roomWithMember(owner, member, { name: `${cp(0x202E)}🚀${cp(0x200B)} Старт` });
    assert.strictEqual(ownerChat.name, '🚀 Старт');
    assert.strictEqual(memberChat.name, '🚀 Старт');
    assert.strictEqual(memberChat.avatar, '🚀');
    const preview = await member.joinPreview((await owner.invite(ownerChat.id)).code);
    assert.strictEqual(preview.roomName || preview.name, '🚀 Старт');
});
