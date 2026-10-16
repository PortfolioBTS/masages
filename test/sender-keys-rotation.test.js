'use strict';
// Sender Key, фаза 2 (план криптографии, раздел 5): ротация раз в 100 сообщений
// или 7 дней, жёсткая граница, prev/final в ext SKDM, выдача ключа «с начала
// эпохи» (поздняя настройка, потерянный share), запрос ключа.
// Запуск: node test/sender-keys-rotation.test.js

const {
    assert, E2EE, HOUR, DAY,
    test, finish, makeClock, makeUser, makeRoom, chatOf, participantsOf,
    send, read, stored,
} = require('./sender-keys-helpers');

const I = E2EE._internal;
const ROOM = 100;
const stateName = (id) => 'senderKey:' + ROOM + ':' + id;

async function trio(opts = {}) {
    const ids = opts.ids || [1, 2, 3];
    const server = makeRoom(ROOM, ids);
    const clock = opts.clock || makeClock();
    const users = {};
    for (const id of ids) users[id] = makeUser(server, id, { now: clock.now });
    for (const id of opts.initIds || ids) await users[id].init();
    return { server, clock, users, alice: users[1], bob: users[2], carol: users[3] };
}

const parts = (ctx) => participantsOf(ctx.server, ROOM);
const ensure = (ctx, id) => ctx.users[id].ensureRoomSession(chatOf(id), ROOM, parts(ctx));
const sync = (ctx, id) => ctx.users[id].syncKeyShares(chatOf(id), ROOM);
const ownKeyId = async (ctx, id) => (await stored(ctx.users[id], stateName(id))).senderKeyId;

async function connect(ctx, ids = [2, 3]) {
    await ensure(ctx, 1);
    for (const id of ids) await sync(ctx, id);
}

(async () => {
    console.log('Sender Key: ротация, prev/final, выдача с начала эпохи, запрос ключа (фаза 2)\n');

    // ===================== Политика ротации =====================

    await test('100 сообщений: roomKeyDue, плановая ротация (reason scheduled), читают все, отправитель тоже', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const first = await ownKeyId(ctx, 1);
        const messages = [];
        for (let i = 0; i < 99; i++) messages.push(await send(ctx.alice, ROOM, 'm' + i));
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), false, 'на 99-м сообщении ещё рано');
        messages.push(await send(ctx.alice, ROOM, 'm99'));
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), true, 'после 100-го пора');
        assert.strictEqual(await ctx.bob.roomKeyDue(ROOM), false, 'у Боба своего ключа нет');

        const result = await ensure(ctx, 1);
        assert.strictEqual(result.rotated, true);
        assert.strictEqual(result.rotationReason, 'scheduled');
        assert.notStrictEqual(await ownKeyId(ctx, 1), first);
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), false);
        assert.strictEqual((await ensure(ctx, 1)).rotated, false, 'повторный вызов не ротирует');

        await sync(ctx, 2);
        const fresh = await send(ctx.alice, ROOM, 'после ротации');
        for (const m of [...messages, fresh]) {
            assert.strictEqual((await read(ctx.bob, ROOM, m)).text, m.text);
            assert.strictEqual((await read(ctx.alice, ROOM, m)).text, m.text, 'отправитель читает свои');
        }
    });

    await test('7 суток: ключ просрочен (подставные часы), ротация плановая', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        await send(ctx.alice, ROOM, 'раз');
        ctx.clock.advance(7 * DAY - HOUR);
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), false);
        ctx.clock.advance(2 * HOUR);
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), true);
        const result = await ensure(ctx, 1);
        assert.deepStrictEqual({ rotated: result.rotated, reason: result.rotationReason }, { rotated: true, reason: 'scheduled' });
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), false);
    });

    await test('уход участника: ротация с причиной member-left, у остальных история читается', async () => {
        const ctx = await trio();
        await connect(ctx);
        const early = await send(ctx.alice, ROOM, 'до ухода');
        ctx.server.removeParticipant(ROOM, 3);
        const result = await ensure(ctx, 1);
        assert.deepStrictEqual({ rotated: result.rotated, reason: result.rotationReason }, { rotated: true, reason: 'member-left' });
        await sync(ctx, 2);
        const late = await send(ctx.alice, ROOM, 'после ухода');
        assert.strictEqual((await read(ctx.bob, ROOM, early)).text, 'до ухода');
        assert.strictEqual((await read(ctx.bob, ROOM, late)).text, 'после ухода');
        assert.strictEqual((await read(ctx.carol, ROOM, late)).reason, 'no-sender-key', 'ушедший нового ключа не получил: в его индексе отправителей этого keyId нет');
    });

    await test('жёсткая граница: на 200-м сообщении без ensureRoomSession — needs-room-session, после ensureRoomSession шифрует', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        for (let i = 0; i < I.FORCE_ROTATE_AFTER_MESSAGES; i++) await send(ctx.alice, ROOM, 'm' + i);
        await assert.rejects(send(ctx.alice, ROOM, 'лишнее'), (err) => {
            assert.ok(err instanceof E2EE.E2eeError);
            assert.strictEqual(err.code, 'needs-room-session');
            return true;
        });
        assert.strictEqual((await stored(ctx.alice, stateName(1))).nextIteration, I.FORCE_ROTATE_AFTER_MESSAGES, 'цепочка не сдвинута');
        await ensure(ctx, 1);
        await sync(ctx, 2);
        const ok = await send(ctx.alice, ROOM, 'после ротации');
        assert.strictEqual((await read(ctx.bob, ROOM, ok)).text, 'после ротации');
    });

    await test('жёсткая граница по времени: 8 суток без ensureRoomSession — needs-room-session', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        await send(ctx.alice, ROOM, 'раз');
        ctx.clock.advance(8 * DAY - HOUR);
        await send(ctx.alice, ROOM, 'ещё можно');
        ctx.clock.advance(2 * HOUR);
        await assert.rejects(send(ctx.alice, ROOM, 'нельзя'), (err) => err.code === 'needs-room-session');
    });

    await test('свой ключ прежней версии без createdAt считается просроченным: ротация при первом использовании комнаты', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const name = stateName(1);
        const own = await stored(ctx.alice, name);
        const oldId = own.senderKeyId;
        delete own.createdAt;
        await ctx.alice._storage.set(name, own);
        assert.strictEqual(await ctx.alice.roomKeyDue(ROOM), true);
        await assert.rejects(send(ctx.alice, ROOM, 'без ротации'), (err) => err.code === 'needs-room-session');
        const result = await ensure(ctx, 1);
        assert.strictEqual(result.rotationReason, 'scheduled');
        assert.notStrictEqual(await ownKeyId(ctx, 1), oldId);
    });

    // ===================== prev / final =====================

    await test('prev.final: цепочка архивного ключа закрыта, непрочитанное до ротации читается, дальше final — нет', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const pending = [];
        for (let i = 0; i < 5; i++) pending.push(await send(ctx.alice, ROOM, 'в пути ' + i));
        const oldId = await ownKeyId(ctx, 1);
        await ctx.alice.rotateRoomKey(ROOM);
        await ensure(ctx, 1);
        await sync(ctx, 2);

        const archiveName = 'skArchive:' + ROOM + ':1:' + oldId;
        const rec = await stored(ctx.bob, archiveName);
        assert.ok(!('chainKey' in rec), 'chainKey старой цепочки стёрт');
        assert.strictEqual(rec.final, 4);
        assert.strictEqual(Object.keys(rec.cachedKeys).length, 5, 'оставшиеся ключи выведены и кэшированы');
        const entry = (await stored(ctx.bob, stateName(1))).archive[0];
        assert.deepStrictEqual({ id: entry.id, final: entry.final }, { id: oldId, final: 4 });
        for (const m of pending) assert.strictEqual((await read(ctx.bob, ROOM, m)).text, m.text);

        // Конверт старого ключа за пределом final — не от Alice: отвергается.
        const extra = await ctx.alice.encryptOutgoing(ROOM, 'шестое', { messageId: '6900001' });
        const forged = JSON.parse(extra);
        assert.strictEqual(forged.senderKeyId, await ownKeyId(ctx, 1));
        // Тот же ключ подписи не поможет: подделка итерации 5 под старым id ломает подпись.
        const asOld = JSON.stringify(Object.assign({}, forged, { senderKeyId: oldId, iteration: 5 }));
        const res = await ctx.bob.decryptIncoming(ROOM, 1, asOld, '6900001');
        assert.strictEqual(res.ok, false);
        assert.ok(['bad-signature', 'stale-sender-key'].includes(res.reason), res.reason);
    });

    await test('prev: ключ без отправленных сообщений prev не несёт (закрывать нечего)', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        await ctx.alice.rotateRoomKey(ROOM);
        assert.ok(!('prev' in (await stored(ctx.alice, stateName(1)))));
        await ctx.alice.rotateRoomKey(ROOM);
        await send(ctx.alice, ROOM, 'теперь есть');
        await ctx.alice.rotateRoomKey(ROOM);
        const prev = (await stored(ctx.alice, stateName(1))).prev;
        assert.strictEqual(prev.final, 0);
    });

    await test('prev.final: абсурдное значение ограничено MAX_SKIP, получатель не зависает', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const first = await send(ctx.alice, ROOM, 'первое');
        const oldId = await ownKeyId(ctx, 1);
        await ctx.alice.rotateRoomKey(ROOM);
        const name = stateName(1);
        const own = await stored(ctx.alice, name);
        own.prev.final = 4000000000;
        await ctx.alice._storage.set(name, own);
        await ensure(ctx, 1);
        const started = Date.now();
        await sync(ctx, 2);
        assert.ok(Date.now() - started < 20000, 'без перебора миллиардов шагов');
        const rec = await stored(ctx.bob, 'skArchive:' + ROOM + ':1:' + oldId);
        assert.ok(!('chainKey' in rec));
        assert.strictEqual(rec.final, I.MAX_SKIP - 1, 'final обрезан: nextIteration (0) + MAX_SKIP - 1');
        assert.strictEqual((await read(ctx.bob, ROOM, first)).text, 'первое');
    });

    await test('prev.final меньше уже прочитанного — противоречие, цепочка остаётся как была', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const messages = [];
        for (let i = 0; i < 6; i++) messages.push(await send(ctx.alice, ROOM, 'm' + i));
        for (const m of messages) await read(ctx.bob, ROOM, m); // Боб дошёл до итерации 5
        const oldId = await ownKeyId(ctx, 1);
        await ctx.alice.rotateRoomKey(ROOM);
        const name = stateName(1);
        const own = await stored(ctx.alice, name);
        own.prev.final = 2;
        await ctx.alice._storage.set(name, own);
        await ensure(ctx, 1);
        await sync(ctx, 2);
        const rec = await stored(ctx.bob, 'skArchive:' + ROOM + ':1:' + oldId);
        assert.ok(rec.chainKey, 'цепочка не закрыта по противоречивому final');
        assert.strictEqual(rec.final, null);
        for (const m of messages) assert.strictEqual((await read(ctx.bob, ROOM, m)).text, m.text);
    });

    await test('prev давнего архивного ключа (не предыдущего) тоже закрывает его цепочку', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const old = [];
        for (let i = 0; i < 3; i++) old.push(await send(ctx.alice, ROOM, 'ключ 1 / ' + i));
        const id1 = await ownKeyId(ctx, 1);
        // Ключ 2 доходит без prev (отправитель прежней версии): цепочка ключа 1 у Боба открыта.
        await ctx.alice.rotateRoomKey(ROOM);
        const name = stateName(1);
        let own = await stored(ctx.alice, name);
        delete own.prev;
        await ctx.alice._storage.set(name, own);
        await ensure(ctx, 1);
        await sync(ctx, 2);
        assert.ok((await stored(ctx.bob, 'skArchive:' + ROOM + ':1:' + id1)).chainKey, 'цепочка ключа 1 открыта');
        // Ключ 3 несёт prev, указывающий на ключ 1: закрывается именно он, а не вытесняемый ключ 2.
        await ctx.alice.rotateRoomKey(ROOM);
        own = await stored(ctx.alice, name);
        own.prev = { id: id1, final: 2 };
        await ctx.alice._storage.set(name, own);
        await ensure(ctx, 1);
        await sync(ctx, 2);
        const rec = await stored(ctx.bob, 'skArchive:' + ROOM + ':1:' + id1);
        assert.ok(!('chainKey' in rec) && rec.final === 2, 'цепочка ключа 1 закрыта по final');
        assert.strictEqual((await stored(ctx.bob, name)).archive.find(e => e.id === id1).final, 2);
        for (const m of old) assert.strictEqual((await read(ctx.bob, ROOM, m)).text, m.text);
    });

    await test('prev неизвестного ключа игнорируется: архив ключа 1 остаётся с открытой цепочкой', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const m1 = await send(ctx.alice, ROOM, 'ключ 1');
        const id1 = await ownKeyId(ctx, 1);
        // Ключ 2: Боб его не получает (share теряется), а ключ 3 доходит.
        await ctx.alice.rotateRoomKey(ROOM);
        await ensure(ctx, 1);
        ctx.server._keyShares.splice(0);
        const m2 = await send(ctx.alice, ROOM, 'ключ 2');
        await ctx.alice.rotateRoomKey(ROOM);
        await ensure(ctx, 1);
        await sync(ctx, 2);
        // prev ключа 3 указывает на ключ 2 (Бобу неизвестный): архив ключа 1 остаётся с открытой цепочкой.
        assert.ok((await stored(ctx.bob, 'skArchive:' + ROOM + ':1:' + id1)).chainKey);
        assert.strictEqual((await read(ctx.bob, ROOM, m1)).text, 'ключ 1');
        assert.strictEqual((await read(ctx.bob, ROOM, m2)).reason, 'no-sender-key', 'ключ 2 устройство никогда не видело: его нет в индексе отправителей');
    });

    // ===================== Выдача «с начала эпохи» =====================

    await test('с начала эпохи: участник без identity при создании ключа получает ключ как новичок (не получатель на момент создания), прежнего не читает', async () => {
        const ctx = await trio({ ids: [1, 2, 3, 4], initIds: [1, 2, 4] }); // Carol (3) ещё не настроила E2EE
        // Dave (4) пока не в комнате.
        ctx.server.removeParticipant(ROOM, 4);
        const first = await ensure(ctx, 1);
        assert.ok(first.warnings.some(w => w.userId === 3), 'Carol не готова: предупреждение');
        await sync(ctx, 2);
        const early = [await send(ctx.alice, ROOM, 'эпоха 1'), await send(ctx.alice, ROOM, 'эпоха 2')];
        assert.strictEqual((await read(ctx.bob, ROOM, early[0])).text, 'эпоха 1');

        // Carol настраивает E2EE; Alice заново рассылает ключ.
        await ctx.carol.init();
        await ensure(ctx, 1);
        const carolSync = await sync(ctx, 3);
        assert.strictEqual(carolSync.applied, 1);
        // Право на ключ с начала эпохи - у recipients на момент создания ключа (signed-membership.md, 9.4, entitled = пары
        // { id, memkey }): у Carol тогда не было ключей на сервере, значит, её не было среди получателей. Поздняя настройка
        // шифрования больше не открывает прежних сообщений эпохи; те, что отправлены дальше, она читает.
        for (const m of early) assert.strictEqual((await read(ctx.carol, ROOM, m)).reason, 'no-message-key', 'Carol не читает то, что отправлено до её настройки');
        const afterSetup = await send(ctx.alice, ROOM, 'после настройки Carol');
        assert.strictEqual((await read(ctx.carol, ROOM, afterSetup)).text, 'после настройки Carol');

        // Dave вступает позже: ключ ему — с текущей позиции.
        ctx.server.addParticipant(ROOM, 4, chatOf(4));
        const joined = await ensure(ctx, 1);
        assert.deepStrictEqual(joined.newMembers.map(m => m.id), [4]);
        await sync(ctx, 4);
        const later = await send(ctx.alice, ROOM, 'после вступления Dave');
        assert.strictEqual((await read(ctx.users[4], ROOM, later)).text, 'после вступления Dave');
        for (const m of early) {
            assert.strictEqual((await read(ctx.users[4], ROOM, m)).reason, 'no-message-key', 'новичок прошлое не читает');
        }
        const daveState = await stored(ctx.users[4], stateName(1));
        assert.strictEqual(daveState.startIteration, 3, 'ключ Dave - с текущей позиции: две ранние итерации и сообщение после настройки Carol');
    });

    await test('с начала эпохи: достройка цепочки назад не трогает текущую позицию и уже имеющиеся ключи', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const messages = [];
        for (let i = 0; i < 4; i++) messages.push(await send(ctx.alice, ROOM, 'm' + i));
        for (const m of messages.slice(0, 2)) await read(ctx.bob, ROOM, m);
        // Боб «потерял» часть истории: сносим его ключи 0..1, стартовая позиция сдвинута вперёд.
        const name = stateName(1);
        const bobState = await stored(ctx.bob, name);
        const keep = { 2: bobState.cachedKeys[2] };
        bobState.cachedKeys = keep;
        bobState.keyTimes = { 2: bobState.keyTimes[2] };
        bobState.startIteration = 2;
        await ctx.bob._storage.set(name, bobState);
        const before = (await stored(ctx.bob, name)).chainKey;
        // Alice по запросу переотправляет ключ с начала эпохи (Боб — entitled).
        await ctx.alice._storage.delete('sharedWith2:' + ROOM + ':' + await ownKeyId(ctx, 1) + ':2');
        await ensure(ctx, 1);
        await sync(ctx, 2);
        const after = await stored(ctx.bob, name);
        assert.strictEqual(after.startIteration, 0);
        assert.strictEqual(after.chainKey, before, 'текущая позиция цепочки не изменилась');
        assert.strictEqual(after.cachedKeys[2], keep[2]);
        for (const m of messages) assert.strictEqual((await read(ctx.bob, ROOM, m)).text, m.text);
    });

    // ===================== Запрос ключа =====================

    await test('запрос ключа: потерянный key-share лечится — запрос, повторная выдача, расшифровка', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await ensure(ctx, 1);
        ctx.server._keyShares.splice(0); // share потерян по дороге
        const m1 = await send(ctx.alice, ROOM, 'первое');
        const m2 = await send(ctx.alice, ROOM, 'второе');
        assert.strictEqual((await read(ctx.bob, ROOM, m1)).reason, 'no-sender-key');

        const asked = await ctx.bob.requestRoomKeys(chatOf(2), ROOM, [m1.env, m2.env]);
        assert.deepStrictEqual(asked, { requested: 1 }, 'оба конверта одного ключа — один запрос');
        assert.strictEqual(ctx.server._keyRequests.length, 1);
        assert.strictEqual(ctx.server._keyRequestPosts[0].senderKeyIds[0], JSON.parse(m1.env).senderKeyId);

        // Alice (владелец) узнаёт о запросе и переотправляет ключ.
        const answer = await ctx.alice.answerKeyRequests(chatOf(1), ROOM);
        assert.deepStrictEqual(answer, { resend: [2] });
        await ensure(ctx, 1);
        assert.strictEqual((await sync(ctx, 2)).applied, 1);
        assert.strictEqual((await read(ctx.bob, ROOM, m1)).text, 'первое', 'ключ выдан с начала эпохи');
        assert.strictEqual((await read(ctx.bob, ROOM, m2)).text, 'второе');
        // Запрос снят: на сервере и у Боба.
        assert.strictEqual(ctx.server._keyRequests.length, 0);
        assert.deepStrictEqual(await ctx.bob._storage.keys('keyReq:'), []);
    });

    await test('запрос ключа через событие сокета: requests передаются прямо, без обращения к серверу', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await ensure(ctx, 1);
        ctx.server._keyShares.splice(0);
        const m = await send(ctx.alice, ROOM, 'письмо');
        const keyId = JSON.parse(m.env).senderKeyId;
        const answer = await ctx.alice.answerKeyRequests(chatOf(1), ROOM, [{ fromUserId: 2, senderKeyIds: [keyId] }]);
        assert.deepStrictEqual(answer, { resend: [2] });
    });

    await test('запрос ключа: чужой ключ, не участник и архивный ключ игнорируются', async () => {
        const ctx = await trio();
        await connect(ctx);
        const oldId = await ownKeyId(ctx, 1);
        await ctx.alice.rotateRoomKey(ROOM);
        await ensure(ctx, 1);
        await sync(ctx, 2);
        await sync(ctx, 3);
        const currentId = await ownKeyId(ctx, 1);
        const strangerKey = 'AAAAAAAAAAAAAAAAAAAAAA==';
        const answer = (requests) => ctx.alice.answerKeyRequests(chatOf(1), ROOM, requests);
        assert.deepStrictEqual(await answer([{ fromUserId: 2, senderKeyIds: [oldId] }]), { resend: [] }, 'архивный ключ не переотправляется');
        assert.deepStrictEqual(await answer([{ fromUserId: 2, senderKeyIds: [strangerKey] }]), { resend: [] }, 'ключ другого участника — не мой');
        assert.deepStrictEqual(await answer([{ fromUserId: 77, senderKeyIds: [currentId] }]), { resend: [] }, 'запросил не участник комнаты');
        assert.deepStrictEqual(await answer([{ fromUserId: 1, senderKeyIds: [currentId] }]), { resend: [] }, 'сам у себя');
        assert.deepStrictEqual(await answer([{ fromUserId: 'abc', senderKeyIds: [currentId] }, null, { fromUserId: 3 }]), { resend: [] }, 'мусор');
        assert.deepStrictEqual(await answer([{ fromUserId: 3, senderKeyIds: [currentId] }]), { resend: [3] }, 'мой текущий ключ, запросил участник');
    });

    await test('запрос ключа: повторно не чаще раза в час, неудачный запрос не блокирует следующий', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await ensure(ctx, 1);
        ctx.server._keyShares.splice(0);
        const m = await send(ctx.alice, ROOM, 'письмо');
        assert.deepStrictEqual(await ctx.bob.requestRoomKeys(chatOf(2), ROOM, [m.env]), { requested: 1 });
        assert.deepStrictEqual(await ctx.bob.requestRoomKeys(chatOf(2), ROOM, [m.env]), { requested: 0 }, 'в течение часа не повторяется');
        ctx.clock.advance(HOUR + 1000);
        assert.deepStrictEqual(await ctx.bob.requestRoomKeys(chatOf(2), ROOM, [m.env]), { requested: 1 }, 'через час можно снова');
        // Сбой сети: отметка снимается, повторить можно сразу.
        const failing = makeUser(ctx.server, 2, {
            storage: ctx.bob._storage, now: ctx.clock.now,
            transport: Object.assign({}, ctx.server.transportFor(2), { postKeyRequests: async () => { throw new TypeError('fetch failed'); } }),
        });
        ctx.clock.advance(HOUR + 1000);
        assert.deepStrictEqual(await failing.requestRoomKeys(chatOf(2), ROOM, [m.env]), { requested: 0 });
        assert.deepStrictEqual(await ctx.bob.requestRoomKeys(chatOf(2), ROOM, [m.env]), { requested: 1 }, 'отметка после сбоя снята');
        // Конверт без своего ключа или мусор запроса не порождают.
        assert.deepStrictEqual(await ctx.bob.requestRoomKeys(chatOf(2), ROOM, ['мусор', '{}', JSON.stringify({ senderKeyId: 'x' })]), { requested: 0 });
        assert.deepStrictEqual(await ctx.bob.requestRoomKeys(chatOf(2), ROOM, null), { requested: 0 });
    });

    await test('выдача по запросу не чаще раза в 10 минут на ключ и участника', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await connect(ctx, [2]);
        const keyId = await ownKeyId(ctx, 1);
        const request = [{ fromUserId: 2, senderKeyIds: [keyId] }];
        assert.deepStrictEqual(await ctx.alice.answerKeyRequests(chatOf(1), ROOM, request), { resend: [2] });
        assert.deepStrictEqual(await ctx.alice.answerKeyRequests(chatOf(1), ROOM, request), { resend: [] });
        ctx.clock.advance(11 * 60 * 1000);
        assert.deepStrictEqual(await ctx.alice.answerKeyRequests(chatOf(1), ROOM, request), { resend: [2] });
    });

    await test('сожжённые одноразовые prekey и потерянный share (T3.2): запрос ключа восстанавливает обмен', async () => {
        const ctx = await trio({ ids: [1, 2] });
        const poolBefore = ctx.server._pqOneTimePrekeys.get(2).size;
        await ensure(ctx, 1);
        assert.strictEqual(ctx.server._pqOneTimePrekeys.get(2).size, poolBefore - 1, 'одноразовый PQ-prekey выдан Alice');
        ctx.server._keyShares.splice(0); // share, собранный по этому bundle, не дошёл
        const m = await send(ctx.alice, ROOM, 'после потери');
        assert.strictEqual((await read(ctx.bob, ROOM, m)).reason, 'no-sender-key');
        await ctx.bob.requestRoomKeys(chatOf(2), ROOM, [m.env]);
        await ctx.alice.answerKeyRequests(chatOf(1), ROOM);
        await ensure(ctx, 1); // сессия уже есть: заголовок PQXDH повторяется в каждой передаче
        assert.strictEqual((await sync(ctx, 2)).applied, 1);
        assert.strictEqual((await read(ctx.bob, ROOM, m)).text, 'после потери');
    });

    // ===================== Очередь key-share на сервере =====================

    await test('вытеснение очереди: давно отсутствующий получатель видит новейшие ключи, рассылка остальным не срывается', async () => {
        const ctx = await trio();
        await connect(ctx);
        const rotations = 230; // больше потолка в 200 строк от одного отправителя
        const sent = [];
        for (let i = 0; i < rotations; i++) {
            await ctx.alice.rotateRoomKey(ROOM);
            const result = await ensure(ctx, 1);
            assert.strictEqual(result.ok, true, 'рассылка не срывается на ротации ' + (i + 1));
            if (i % 50 === 0) { await sync(ctx, 2); sent.push(await send(ctx.alice, ROOM, 'ключ ' + i)); } // Bob заходит, Carol — нет
        }
        const last = await send(ctx.alice, ROOM, 'последнее');
        const queue = ctx.server._keyShares.filter(s => s.recipientId === 3);
        assert.ok(queue.length <= 200, 'очередь Carol ограничена: ' + queue.length);
        const carolSync = await sync(ctx, 3);
        assert.ok(carolSync.applied > 0);
        assert.strictEqual((await read(ctx.carol, ROOM, last)).text, 'последнее', 'новейший ключ дошёл');
        await sync(ctx, 2);
        assert.strictEqual((await read(ctx.bob, ROOM, last)).text, 'последнее');
    });

    finish();
})();
