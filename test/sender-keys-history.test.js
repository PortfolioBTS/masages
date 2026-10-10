'use strict';
// «Не хранить историю на устройстве» (план криптографии, раздел 6): личная настройка
// комнаты на этом устройстве, забывание ключей, архивов, таблиц повторов и записей о
// версиях сообщений; причина отказа 'history-not-kept'.
// Запуск: node test/sender-keys-history.test.js

const {
    assert, E2EE,
    test, finish, makeClock, makeUser, reload, makeRoom, chatOf, participantsOf,
    send, read, stored,
} = require('./sender-keys-helpers');

const ROOM = 100;
const OTHER = 200;
const keyName = (id, room = ROOM) => 'senderKey:' + room + ':' + id;

async function pair(opts = {}) {
    const server = makeRoom(ROOM, [1, 2]);
    server.addParticipant(OTHER, 1, chatOf(1) + 1000);
    server.addParticipant(OTHER, 2, chatOf(2) + 1000);
    const clock = opts.clock || makeClock();
    const alice = makeUser(server, 1, { now: clock.now });
    const bob = makeUser(server, 2, { now: clock.now });
    await alice.init();
    await bob.init();
    const ctx = { server, clock, alice, bob };
    await connect(ctx, ROOM);
    return ctx;
}

// Alice раздаёт ключ комнаты room, Bob забирает.
async function connect(ctx, room) {
    const chat = (id) => (room === ROOM ? chatOf(id) : chatOf(id) + 1000);
    await ctx.alice.ensureRoomSession(chat(1), room, participantsOf(ctx.server, room));
    await ctx.bob.syncKeyShares(chat(2), room);
}

// Все значения всех записей хранилища одной строкой: ищем в ней остатки забытых ключей.
function dump(client) {
    return JSON.stringify(Array.from(client._storage.map.entries()).map(([name, value]) => [name, value && typeof value === 'object' ? Object.assign({}, value, {
        priv: undefined, dhPriv: undefined, signPriv: undefined, signingPrivateKey: undefined,
    }) : value]));
}

(async () => {
    console.log('Не хранить историю на устройстве\n');

    await test('режим none: прочитанное нечитаемо (history-not-kept), новые сообщения читаются, свои отправленные — нет', async () => {
        const ctx = await pair();
        const old = await send(ctx.alice, ROOM, 'старое');
        assert.strictEqual((await read(ctx.bob, ROOM, old)).text, 'старое');
        assert.strictEqual(await ctx.bob.getRoomHistoryMode(ROOM), 'keep');
        assert.strictEqual(await ctx.bob.setRoomHistoryMode(ROOM, 'none'), 'none');
        assert.strictEqual(await ctx.bob.getRoomHistoryMode(ROOM), 'none');
        assert.deepStrictEqual(await read(ctx.bob, ROOM, old), { ok: false, reason: 'history-not-kept' });
        const fresh = await send(ctx.alice, ROOM, 'новое');
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'новое', 'будущие сообщения читаются');

        await ctx.alice.setRoomHistoryMode(ROOM, 'none');
        assert.deepStrictEqual(await read(ctx.alice, ROOM, old), { ok: false, reason: 'history-not-kept' }, 'свои отправленные не расшифровываются');
        const afterForget = await send(ctx.alice, ROOM, 'после забывания');
        assert.strictEqual((await read(ctx.alice, ROOM, afterForget)).text, 'после забывания', 'ключи новых своих сообщений есть, пока комната открыта');
    });

    await test('после забывания ни одно значение прежних ключей не встречается ни в одной записи хранилища', async () => {
        const ctx = await pair();
        const messages = [];
        for (let i = 0; i < 5; i++) messages.push(await send(ctx.alice, ROOM, 'm' + i));
        for (const m of messages) await read(ctx.bob, ROOM, m);
        // Ротация даёт архив у обоих.
        await ctx.alice.rotateRoomKey(ROOM);
        await ctx.alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(ctx.server, ROOM));
        await ctx.bob.syncKeyShares(chatOf(2), ROOM);
        messages.push(await send(ctx.alice, ROOM, 'после ротации'));
        await read(ctx.bob, ROOM, messages.at(-1));

        const secrets = {};
        for (const [who, client] of [['alice', ctx.alice], ['bob', ctx.bob]]) {
            const state = await stored(client, keyName(1));
            const keys = Object.values(state.cachedKeys);
            for (const name of await client._storage.keys('skArchive:' + ROOM + ':')) keys.push(...Object.values((await stored(client, name)).cachedKeys));
            assert.ok(keys.length >= 6, who + ': ключей для проверки достаточно');
            secrets[who] = { keys, chainKey0: state.origin && state.origin.chainKey0 };
        }
        assert.ok(secrets.alice.chainKey0, 'у владельца есть chainKey0 эпохи');

        await ctx.alice.forgetRoomHistory(ROOM);
        await ctx.bob.forgetRoomHistory(ROOM);
        for (const [who, client] of [['alice', ctx.alice], ['bob', ctx.bob]]) {
            const text = dump(client);
            for (const key of secrets[who].keys) assert.ok(!text.includes(key), who + ': ключ сообщения остался в хранилище');
            if (secrets[who].chainKey0) assert.ok(!text.includes(secrets[who].chainKey0), who + ': chainKey0 остался в хранилище');
            assert.deepStrictEqual(await client._storage.keys('skArchive:'), [], who + ': записей архива нет');
            assert.deepStrictEqual(await client._storage.keys('seen:'), [], who + ': таблиц повторов нет');
            assert.deepStrictEqual(await client._storage.keys('edit:'), [], who + ': записей о версиях нет');
            const state = await stored(client, keyName(1));
            assert.deepStrictEqual(state.cachedKeys, {});
            assert.ok(state.archive.every(entry => typeof entry === 'string'), who + ': в индексе архива только id');
            assert.strictEqual(state.archive.length, 1);
            assert.ok(!('origin' in state));
        }
        // Читаются только новые сообщения; старые, включая архивные, — history-not-kept.
        for (const m of messages) assert.strictEqual((await read(ctx.bob, ROOM, m)).reason, 'history-not-kept', m.text);
        const fresh = await send(ctx.alice, ROOM, 'после забывания');
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'после забывания');
    });

    await test('забывание не трогает ни другие комнаты, ни рабочие данные (цепочки, ключи подписи, состав, закрепления)', async () => {
        const ctx = await pair();
        await connect(ctx, OTHER);
        const inRoom = await send(ctx.alice, ROOM, 'комната 100');
        const inOther = await send(ctx.alice, OTHER, 'комната 200');
        await read(ctx.bob, ROOM, inRoom);
        await read(ctx.bob, OTHER, inOther);
        const before = await stored(ctx.bob, keyName(1));
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        assert.strictEqual((await read(ctx.bob, OTHER, inOther)).text, 'комната 200', 'другая комната читается');
        assert.strictEqual(await ctx.bob.getRoomHistoryMode(OTHER), 'keep');
        const after = await stored(ctx.bob, keyName(1));
        assert.strictEqual(after.chainKey, before.chainKey);
        assert.strictEqual(after.nextIteration, before.nextIteration);
        assert.strictEqual(after.signingPublicKey, before.signingPublicKey);
        assert.strictEqual(after.forgottenBelow, before.nextIteration);
        assert.ok(await stored(ctx.bob, 'peer:1'), 'закрепление identity осталось');
        assert.ok(await stored(ctx.bob, 'pw2Recv:1'), 'попарная сессия осталась');
        assert.strictEqual(Object.keys((await stored(ctx.bob, keyName(1, OTHER))).cachedKeys).length, 1, 'ключи другой комнаты на месте');
        const ownBefore = await stored(ctx.alice, keyName(1));
        await ctx.alice.forgetRoomHistory(ROOM);
        const ownAfter = await stored(ctx.alice, keyName(1));
        assert.strictEqual(ownAfter.chainKey, ownBefore.chainKey);
        assert.ok(ownAfter.signingPrivateKey, 'ключ подписи свой остался');
        assert.deepStrictEqual(ownAfter.entitled, ownBefore.entitled);
    });

    await test('сообщения, пропущенные до забывания и ещё не показанные, теряются', async () => {
        const ctx = await pair();
        const messages = [];
        for (let i = 0; i < 5; i++) messages.push(await send(ctx.alice, ROOM, 'm' + i));
        assert.strictEqual((await read(ctx.bob, ROOM, messages[4])).text, 'm4'); // m0..m3 выведены, но не показаны
        await ctx.bob.forgetRoomHistory(ROOM);
        for (const m of messages.slice(0, 4)) assert.strictEqual((await read(ctx.bob, ROOM, m)).reason, 'history-not-kept');
    });

    await test('возврат в keep удалённое не воскрешает; настройка живёт только в хранилище ключей устройства', async () => {
        const ctx = await pair();
        const old = await send(ctx.alice, ROOM, 'старое');
        await read(ctx.bob, ROOM, old);
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        await ctx.bob.setRoomHistoryMode(ROOM, 'keep');
        assert.strictEqual(await ctx.bob.getRoomHistoryMode(ROOM), 'keep');
        assert.strictEqual((await read(ctx.bob, ROOM, old)).reason, 'history-not-kept');
        assert.strictEqual(await stored(ctx.bob, 'roomPolicy:' + ROOM), null, 'значение по умолчанию записи не оставляет');
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        assert.strictEqual((await stored(ctx.bob, 'roomPolicy:' + ROOM)).historyMode, 'none');
        // Ничего о настройке не ушло на сервер: у Alice и сервера её нет.
        assert.strictEqual(await stored(ctx.alice, 'roomPolicy:' + ROOM), null);
        await assert.rejects(ctx.bob.setRoomHistoryMode(ROOM, 'maybe'), TypeError);
        await assert.rejects(ctx.bob.setRoomPolicy(ROOM, { historyMode: 'всё' }), TypeError);
        // Тот же ключ после forget в режиме keep снова копит историю.
        await ctx.bob.setRoomHistoryMode(ROOM, 'keep');
        const next = await send(ctx.alice, ROOM, 'снова хранится');
        await read(ctx.bob, ROOM, next);
        assert.strictEqual((await read(ctx.bob, ROOM, next)).text, 'снова хранится');
        assert.strictEqual(Object.keys((await stored(ctx.bob, keyName(1))).cachedKeys).length, 1);
    });

    await test('init() забывает комнаты в режиме none (закрытая или упавшая вкладка), плановый init() — нет', async () => {
        const ctx = await pair();
        const m1 = await send(ctx.alice, ROOM, 'прошлая сессия');
        await read(ctx.bob, ROOM, m1);
        // Вкладка упала: настройка записана, а забывание не состоялось.
        await ctx.bob._storage.set('roomPolicy:' + ROOM, { historyMode: 'none', expirySeconds: null, updatedAt: 1 });
        const bob2 = reload(ctx.server, ctx.bob, { now: ctx.clock.now });
        await bob2.init();
        assert.strictEqual((await read(bob2, ROOM, m1)).reason, 'history-not-kept', 'init() забыл историю');
        const m2 = await send(ctx.alice, ROOM, 'эта сессия');
        assert.strictEqual((await read(bob2, ROOM, m2)).text, 'эта сессия');
        // Плановый init() (раз в 6 часов) историю открытой комнаты не стирает.
        await bob2.init();
        assert.strictEqual((await read(bob2, ROOM, m2)).text, 'эта сессия');
        assert.ok(Object.keys((await stored(bob2, keyName(1))).cachedKeys).length >= 1);
        // Новая загрузка страницы — снова забывает.
        const bob3 = reload(ctx.server, ctx.bob, { now: ctx.clock.now });
        await bob3.init();
        assert.strictEqual((await read(bob3, ROOM, m2)).reason, 'history-not-kept');
    });

    await test('forgetAllNoHistoryRooms: только комнаты в режиме none, список возвращается', async () => {
        const ctx = await pair();
        await connect(ctx, OTHER);
        const a = await send(ctx.alice, ROOM, 'a');
        const b = await send(ctx.alice, OTHER, 'b');
        await read(ctx.bob, ROOM, a);
        await read(ctx.bob, OTHER, b);
        await ctx.bob._storage.set('roomPolicy:' + OTHER, { historyMode: 'none', expirySeconds: null, updatedAt: 1 });
        assert.deepStrictEqual(await ctx.bob.forgetAllNoHistoryRooms(), [String(OTHER)]);
        assert.strictEqual((await read(ctx.bob, ROOM, a)).text, 'a');
        assert.strictEqual((await read(ctx.bob, OTHER, b)).reason, 'history-not-kept');
    });

    await test('ключ, присланный с начала эпохи, забытое не воскрешает; владелец в режиме none не хранит chainKey0', async () => {
        const ctx = await pair();
        const old = await send(ctx.alice, ROOM, 'эпоха');
        await read(ctx.bob, ROOM, old);
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        // Alice (entitled Bob) снимает отметку и переотправляет ключ с начала эпохи.
        const keyId = (await stored(ctx.alice, keyName(1))).senderKeyId;
        await ctx.alice.answerKeyRequests(chatOf(1), ROOM, [{ fromUserId: 2, senderKeyIds: [keyId] }]);
        await ctx.alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(ctx.server, ROOM));
        assert.strictEqual((await ctx.bob.syncKeyShares(chatOf(2), ROOM)).applied, 1);
        assert.strictEqual((await read(ctx.bob, ROOM, old)).reason, 'history-not-kept', 'забытое не воскресло');
        // Владелец, забывший историю, выдаёт ключ с текущей позиции (chainKey0 стёрт).
        await ctx.alice.setRoomHistoryMode(ROOM, 'none');
        await ctx.alice._storage.delete('sharedWith2:' + ROOM + ':' + keyId + ':2');
        const aliceState = await stored(ctx.alice, keyName(1));
        assert.ok(!('origin' in aliceState));
        await ctx.alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(ctx.server, ROOM));
        assert.strictEqual((await ctx.bob.syncKeyShares(chatOf(2), ROOM)).applied, 1);
        const fresh = await send(ctx.alice, ROOM, 'дальше');
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'дальше');
    });

    await test('режим none вместе со сроком комнаты: оба работают, смена срока режим не сбрасывает', async () => {
        const ctx = await pair();
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        await ctx.bob.setRoomPolicy(ROOM, { expirySeconds: 3600 });
        const policy = await stored(ctx.bob, 'roomPolicy:' + ROOM);
        assert.deepStrictEqual({ h: policy.historyMode, e: policy.expirySeconds }, { h: 'none', e: 3600 });
        await ctx.bob.setRoomPolicy(ROOM, { expirySeconds: 0 });
        assert.strictEqual((await stored(ctx.bob, 'roomPolicy:' + ROOM)).historyMode, 'none', 'запись осталась из-за режима');
        assert.strictEqual(await ctx.bob.getRoomHistoryMode(ROOM), 'none');
    });

    await test('ротация отправителя в режиме none: новый ключ читает дальше, архив старого после забывания — надгробие', async () => {
        const ctx = await pair();
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        // Ротация Alice, Боб забирает новый ключ и читает дальше; архив старого ключа у него — надгробие.
        const old = await send(ctx.alice, ROOM, 'до ротации');
        await ctx.alice.rotateRoomKey(ROOM);
        await ctx.alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(ctx.server, ROOM));
        await ctx.bob.syncKeyShares(chatOf(2), ROOM);
        const fresh = await send(ctx.alice, ROOM, 'после ротации');
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'после ротации');
        // Пока комната открыта, архив старого ключа читается; после забывания — нет.
        assert.strictEqual((await read(ctx.bob, ROOM, old)).text, 'до ротации');
        await ctx.bob.forgetRoomHistory(ROOM);
        assert.strictEqual((await read(ctx.bob, ROOM, old)).reason, 'history-not-kept');
    });

    finish();
})();
