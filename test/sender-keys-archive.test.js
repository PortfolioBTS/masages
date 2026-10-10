'use strict';
// Sender Key, фаза 1 (план криптографии, раздел 5): хранение. Архив старых
// ключей отдельными записями вместо MAX_ARCHIVED_KEYS = 3, индекс и «надгробия»,
// время вывода ключей (keyTimes), политика комнаты, таймер и бюджет ключей,
// поле ext в SKDM, ленивая миграция встроенного archived.
// Запуск: node test/sender-keys-archive.test.js

const nodeCrypto = require('crypto');
const {
    assert, E2EE, makeFakeServer, HOUR, DAY,
    test, finish, makeClock, makeUser, reload, makeRoom, chatOf, participantsOf,
    send, read, stored, sizeOf, shuffled,
} = require('./sender-keys-helpers');

const I = E2EE._internal;
const { b64encode: b64 } = I;
const ROOM = 100;

// Alice (1) и Bob (2) в комнате; Alice раздала ключ, Bob его забрал.
async function pair(opts = {}) {
    const server = makeRoom(ROOM, [1, 2]);
    const clock = opts.clock || null;
    const alice = makeUser(server, 1, { now: clock && clock.now });
    const bob = makeUser(server, 2, { now: clock && clock.now });
    await alice.init();
    await bob.init();
    const parts = participantsOf(server, ROOM);
    await alice.ensureRoomSession(chatOf(1), ROOM, parts);
    await bob.syncKeyShares(chatOf(2), ROOM);
    return { server, alice, bob, parts, clock };
}

// Alice меняет ключ и рассылает новый; Bob забирает его (если sync = true).
// withoutPrev: отправитель прежней версии не сообщает prev.final, и цепочка
// старого ключа у получателя остаётся открытой.
async function rotate(ctx, sync = true, { withoutPrev = false } = {}) {
    await ctx.alice.rotateRoomKey(ROOM);
    if (withoutPrev) {
        const name = 'senderKey:' + ROOM + ':1';
        const own = await ctx.alice._storage.get(name);
        delete own.prev;
        await ctx.alice._storage.set(name, own);
    }
    await ctx.alice.ensureRoomSession(chatOf(1), ROOM, ctx.parts);
    if (sync) await ctx.bob.syncKeyShares(chatOf(2), ROOM);
}

const aliceKey = async (ctx) => (await stored(ctx.alice, 'senderKey:' + ROOM + ':1')).senderKeyId;

function rawSkdm(extra = {}, overrides = {}) {
    const base = {
        v: 2, type: 'skdm', roomId: ROOM,
        senderKeyId: b64(nodeCrypto.randomBytes(16)),
        chainKey: b64(nodeCrypto.randomBytes(32)),
        iteration: 3,
        signingPublicKey: b64(nodeCrypto.randomBytes(32)),
    };
    return new TextEncoder().encode(JSON.stringify(Object.assign(base, overrides, extra)));
}

(async () => {
    console.log('Sender Key: архив, ключи, поле ext (фаза 1)\n');

    // ===================== ext в SKDM =====================

    await test('ext: SKDM без ext разбирается как раньше, ext пуст', () => {
        const skdm = I.parseSkdm(rawSkdm(), ROOM);
        assert.ok(skdm);
        assert.deepStrictEqual(skdm.ext, {});
        assert.strictEqual(skdm.iteration, 3);
    });

    await test('ext: prev (id и final) проходит разбор без изменений', () => {
        const prevId = b64(nodeCrypto.randomBytes(16));
        const skdm = I.parseSkdm(rawSkdm({ ext: { prev: { id: prevId, final: 41 } } }), ROOM);
        assert.deepStrictEqual(skdm.ext, { prev: { id: prevId, final: 41 } });
    });

    await test('ext: неизвестные поля игнорируются и наружу не отдаются, известные проверяются', () => {
        const prevId = b64(nodeCrypto.randomBytes(16));
        const skdm = I.parseSkdm(rawSkdm({ ext: { prev: { id: prevId, final: 0, junk: 1 }, view: 'abc', future: { a: [1, 2] } } }), ROOM);
        assert.deepStrictEqual(skdm.ext, { prev: { id: prevId, final: 0 } });
        assert.deepStrictEqual(I.parseSkdm(rawSkdm({ ext: { view: 'abc' } }), ROOM).ext, {});
        assert.deepStrictEqual(I.parseSkdm(rawSkdm({ ext: {} }), ROOM).ext, {});
    });

    await test('ext: испорченный ext отвергает весь SKDM', () => {
        const okId = b64(nodeCrypto.randomBytes(16));
        const bad = [
            ['ext не объект', 'строка'],
            ['ext массив', []],
            ['ext null', null],
            ['ext число', 7],
            ['prev не объект', { prev: 'x' }],
            ['prev null', { prev: null }],
            ['prev массив', { prev: [okId, 1] }],
            ['id не строка', { prev: { id: 5, final: 1 } }],
            ['id короткий', { prev: { id: b64(nodeCrypto.randomBytes(8)), final: 1 } }],
            ['id с мусором', { prev: { id: okId + '!!', final: 1 } }],
            ['id без паддинга', { prev: { id: okId.replace(/=+$/, ''), final: 1 } }],
            ['final отрицательный', { prev: { id: okId, final: -1 } }],
            ['final дробный', { prev: { id: okId, final: 1.5 } }],
            ['final строкой', { prev: { id: okId, final: '7' } }],
            ['final больше 2^32-1', { prev: { id: okId, final: 0x100000000 } }],
            ['final нет', { prev: { id: okId } }],
            ['ext слишком велик', { prev: { id: okId, final: 1 }, pad: 'x'.repeat(I.MAX_EXT_CHARS || 4000) }],
        ];
        for (const [label, ext] of bad) {
            assert.strictEqual(I.parseSkdm(rawSkdm({ ext }), ROOM), null, label);
        }
    });

    await test('SKDM: senderKeyId обязан быть каноническим base64 ровно 16 байт', () => {
        const id = b64(nodeCrypto.randomBytes(16));
        assert.ok(I.parseSkdm(rawSkdm({}, { senderKeyId: id }), ROOM));
        for (const bad of [id + 'A', id.slice(0, -2), id.replace('=', '') + '@', 'AAAA', 5, null]) {
            assert.strictEqual(I.parseSkdm(rawSkdm({}, { senderKeyId: bad }), ROOM), null, String(bad));
        }
    });

    await test('buildSkdm: ext пишется только когда в нём есть поля; круг build → parse', () => {
        const key = {
            senderKeyId: b64(nodeCrypto.randomBytes(16)), chainKey: b64(nodeCrypto.randomBytes(32)),
            iteration: 9, signingPublicKey: b64(nodeCrypto.randomBytes(32)),
        };
        assert.ok(!('ext' in I.buildSkdm(ROOM, key)));
        assert.ok(!('ext' in I.buildSkdm(ROOM, key, {})));
        const prev = { id: b64(nodeCrypto.randomBytes(16)), final: 12 };
        const built = I.buildSkdm(ROOM, key, { prev });
        const parsed = I.parseSkdm(new TextEncoder().encode(JSON.stringify(built)), ROOM);
        assert.deepStrictEqual(parsed.ext, { prev });
        assert.strictEqual(parsed.iteration, 9);
        assert.strictEqual(parsed.senderKeyId, key.senderKeyId);
    });

    // ===================== Архив без предела MAX_ARCHIVED_KEYS =====================

    await test('архив: 1000 сообщений и 10 ротаций; доставка вразнобой; после перезагрузки читается всё', async () => {
        const ctx = await pair();
        const messages = [];
        const keyIds = [];
        for (let k = 0; k < 10; k++) {
            keyIds.push(await aliceKey(ctx));
            for (let i = 0; i < 100; i++) messages.push(await send(ctx.alice, ROOM, `k${k}-m${i}`));
            if (k < 9) await rotate(ctx, false); // Bob забирает ключи только в конце
        }
        assert.strictEqual(new Set(keyIds).size, 10);
        const synced = await ctx.bob.syncKeyShares(chatOf(2), ROOM);
        assert.strictEqual(synced.applied, 9, 'девять доставленных key-share новых ключей');

        // Сообщения ключа №2 читаются уже после установки ключа №10; порядок смешан.
        for (const m of shuffled(messages)) {
            const res = await read(ctx.bob, ROOM, m);
            assert.strictEqual(res.ok, true, `${m.text}: ${JSON.stringify(res)}`);
            assert.strictEqual(res.text, m.text);
        }
        // Основная запись получателя хранит только текущий ключ; остальные — отдельные записи.
        const bobState = await stored(ctx.bob, 'senderKey:' + ROOM + ':1');
        assert.strictEqual(bobState.senderKeyId, keyIds[9]);
        assert.ok(!('archived' in bobState), 'встроенного архива нет');
        assert.strictEqual(bobState.archive.length, 9);
        assert.strictEqual((await ctx.bob._storage.keys('skArchive:' + ROOM + ':1:')).length, 9);
        const aliceState = await stored(ctx.alice, 'senderKey:' + ROOM + ':1');
        assert.strictEqual(aliceState.archive.length, 9);
        assert.strictEqual((await ctx.alice._storage.keys('skArchive:' + ROOM + ':1:')).length, 9);

        // «Перезагрузка»: новые клиенты на тех же хранилищах.
        const alice2 = reload(ctx.server, ctx.alice);
        const bob2 = reload(ctx.server, ctx.bob);
        await alice2.init();
        await bob2.init();
        for (const m of shuffled(messages, 777)) {
            const forBob = await read(bob2, ROOM, m);
            assert.strictEqual(forBob.text, m.text, 'Bob после перезагрузки: ' + m.text);
            const forAlice = await read(alice2, ROOM, m);
            assert.strictEqual(forAlice.text, m.text, 'Alice после перезагрузки: ' + m.text);
        }
    });

    await test('архив: основная запись не растёт от содержимого архивов', async () => {
        const ctx = await pair();
        for (let i = 0; i < 20; i++) await send(ctx.alice, ROOM, 'старый ключ ' + i);
        await rotate(ctx);
        const afterOne = sizeOf(await stored(ctx.alice, 'senderKey:' + ROOM + ':1'));
        for (let k = 0; k < 9; k++) {
            for (let i = 0; i < 20; i++) await send(ctx.alice, ROOM, 'ключ ' + k + ' сообщение ' + i);
            await rotate(ctx);
        }
        const afterTen = sizeOf(await stored(ctx.alice, 'senderKey:' + ROOM + ':1'));
        const state = await stored(ctx.alice, 'senderKey:' + ROOM + ':1');
        assert.strictEqual(state.archive.length, 10);
        // Каждый архив добавляет в основную запись только строчку индекса (~100 байт),
        // а не 20 ключей сообщений (~1,5 КБ).
        assert.ok(afterTen - afterOne < 9 * 200, `основная запись выросла на ${afterTen - afterOne} байт`);
        const archiveSize = sizeOf(await stored(ctx.alice, 'skArchive:' + ROOM + ':1:' + state.archive[0].id));
        assert.ok(archiveSize > 1000, 'ключи сообщений лежат в записи архива');
    });

    await test('архив: индекс держит 500 подробных записей, остальные — надгробия; удалённое нечитаемо (key-expired)', async () => {
        const ctx = await pair();
        const oldest = await send(ctx.alice, ROOM, 'самое старое');
        const total = I.MAX_ARCHIVE_INDEX + 3;
        for (let i = 0; i < total; i++) await ctx.alice.rotateRoomKey(ROOM);
        const state = await stored(ctx.alice, 'senderKey:' + ROOM + ':1');
        assert.strictEqual(state.archive.length, total);
        assert.strictEqual(state.archive.filter(e => typeof e === 'object').length, I.MAX_ARCHIVE_INDEX);
        assert.strictEqual(state.archive.filter(e => typeof e === 'string').length, 3);
        assert.strictEqual((await ctx.alice._storage.keys('skArchive:' + ROOM + ':1:')).length, I.MAX_ARCHIVE_INDEX);
        const res = await read(ctx.alice, ROOM, oldest);
        assert.deepStrictEqual(res, { ok: false, reason: 'key-expired' });
        assert.ok(state.archive.every((e, i) => (i < I.MAX_ARCHIVE_INDEX ? typeof e === 'object' : typeof e === 'string')), 'подробные записи — первыми, надгробия — в хвосте');
    });

    await test('архив: опоздавший key-share старого ключа уходит в архив и не заменяет текущий', async () => {
        const ctx = await pair();
        const first = await send(ctx.alice, ROOM, 'ключ 1');
        await rotate(ctx, false);
        const second = await send(ctx.alice, ROOM, 'ключ 2');
        await rotate(ctx, false);
        const third = await send(ctx.alice, ROOM, 'ключ 3');
        // Доставляем key-share третьего ключа раньше второго.
        const [share2, share3] = ctx.server._keyShares.splice(0, 2);
        ctx.server._keyShares.push(share3);
        assert.strictEqual((await ctx.bob.syncKeyShares(chatOf(2), ROOM)).applied, 1);
        ctx.server._keyShares.push(share2);
        assert.strictEqual((await ctx.bob.syncKeyShares(chatOf(2), ROOM)).applied, 1);
        const state = await stored(ctx.bob, 'senderKey:' + ROOM + ':1');
        assert.strictEqual(state.senderKeyId, JSON.parse(third.env).senderKeyId, 'текущий ключ — третий');
        assert.strictEqual(state.archive.length, 2);
        for (const m of [first, second, third]) assert.strictEqual((await read(ctx.bob, ROOM, m)).text, m.text);
    });

    // ===================== Миграция встроенного archived =====================

    await test('миграция: встроенный archived раскладывается по записям skArchive, история читается', async () => {
        const ctx = await pair();
        const msgs = [await send(ctx.alice, ROOM, 'прошлый ключ')];
        await rotate(ctx, true, { withoutPrev: true });
        msgs.push(await send(ctx.alice, ROOM, 'текущий ключ'));
        // Боб ещё не читал ни одно сообщение: цепочка старого ключа в архиве открыта.
        const name = 'senderKey:' + ROOM + ':1';
        const state = await stored(ctx.bob, name);
        const oldId = state.archive[0].id;
        const archiveRec = await stored(ctx.bob, 'skArchive:' + ROOM + ':1:' + oldId);
        assert.ok(archiveRec.chainKey, 'цепочка старого ключа ещё открыта');

        // Состояние Боба в формате прежней версии: archived внутри, ни keyTimes, ни archive.
        const legacy = {
            senderKeyId: state.senderKeyId, signingPublicKey: state.signingPublicKey, chainKey: state.chainKey,
            nextIteration: state.nextIteration, cachedKeys: state.cachedKeys,
            archived: [{
                senderKeyId: oldId, signingPublicKey: archiveRec.signingPublicKey,
                cachedKeys: archiveRec.cachedKeys, chainKey: archiveRec.chainKey, nextIteration: archiveRec.nextIteration,
            }],
            installedBy: state.installedBy,
        };
        await ctx.bob._storage.set(name, legacy);
        await ctx.bob._storage.delete('skArchive:' + ROOM + ':1:' + oldId);

        const bob2 = reload(ctx.server, ctx.bob);
        await bob2.init();
        assert.strictEqual((await read(bob2, ROOM, msgs[0])).text, 'прошлый ключ', 'читается по ключу из прежнего archived');
        assert.strictEqual((await read(bob2, ROOM, msgs[1])).text, 'текущий ключ');
        const migrated = await stored(bob2, name);
        assert.ok(!('archived' in migrated), 'встроенный archived убран');
        assert.deepStrictEqual(migrated.archive.map(e => e.id), [oldId]);
        assert.ok(migrated.keyTimes && Number.isInteger(migrated.startIteration), 'добавлены keyTimes и startIteration');
        const rec = await stored(bob2, 'skArchive:' + ROOM + ':1:' + oldId);
        assert.ok(rec && rec.archivedAt > 0 && rec.final === null, 'запись архива создана');
    });

    // ===================== Политика комнаты и срок ключей =====================

    await test('roomPolicy: срок хранится, значение по умолчанию записи не оставляет, мусор отвергается', async () => {
        const ctx = await pair();
        assert.strictEqual(await stored(ctx.bob, 'roomPolicy:' + ROOM), null);
        const set = await ctx.bob.setRoomPolicy(ROOM, { expirySeconds: 3600 });
        assert.deepStrictEqual({ h: set.historyMode, e: set.expirySeconds }, { h: 'keep', e: 3600 });
        assert.strictEqual((await stored(ctx.bob, 'roomPolicy:' + ROOM)).expirySeconds, 3600);
        await ctx.bob.setRoomPolicy(ROOM, { expirySeconds: 0 });
        assert.strictEqual(await stored(ctx.bob, 'roomPolicy:' + ROOM), null, 'срок снят — записи нет');
        for (const bad of [-5, 1.5, '3600', NaN, Infinity]) {
            await assert.rejects(ctx.bob.setRoomPolicy(ROOM, { expirySeconds: bad }), TypeError, String(bad));
        }
        await assert.rejects(ctx.bob.setRoomPolicy(ROOM, null), TypeError);
    });

    await test('таймер комнаты 1 ч: через T + 1 ч ключи и seen удалены (key-expired), свежие сообщения читаются', async () => {
        const clock = makeClock();
        const ctx = await pair({ clock });
        const old = await send(ctx.alice, ROOM, 'старое');
        assert.strictEqual((await read(ctx.bob, ROOM, old)).text, 'старое');
        await rotate(ctx);
        const oldArchived = await send(ctx.alice, ROOM, 'старое под вторым ключом');
        assert.strictEqual((await read(ctx.bob, ROOM, oldArchived)).text, 'старое под вторым ключом');
        await ctx.bob.setRoomPolicy(ROOM, { expirySeconds: 3600 });

        clock.advance(30 * 60 * 1000);
        await ctx.bob.maintainRoomKeys(ROOM);
        assert.strictEqual((await read(ctx.bob, ROOM, old)).text, 'старое', 'срок не вышел');

        clock.advance(2 * HOUR + 40 * 60 * 1000); // ключи выведены в начале часа t0: к t0 + 3 ч 10 мин их час целиком старше T + 1 ч
        const fresh = await send(ctx.alice, ROOM, 'свежее');
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'свежее');
        const stats = await ctx.bob.maintainRoomKeys(ROOM);
        assert.ok(stats.expiredKeys >= 1 && stats.removedArchives >= 1, JSON.stringify(stats));
        assert.deepStrictEqual(await read(ctx.bob, ROOM, old), { ok: false, reason: 'key-expired' });
        assert.deepStrictEqual(await read(ctx.bob, ROOM, oldArchived), { ok: false, reason: 'key-expired' });
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'свежее', 'свежее читается');
        // Таблицы повторов удалённых ключей убраны.
        const state = await stored(ctx.bob, 'senderKey:' + ROOM + ':1');
        const keys = await ctx.bob._storage.keys('seen:' + ROOM + ':1:');
        assert.deepStrictEqual(keys, ['seen:' + ROOM + ':1:' + state.senderKeyId], 'остался seen только текущего ключа');
        assert.ok(Object.keys(await stored(ctx.bob, keys[0])).length >= 1);
        assert.strictEqual(Object.keys(state.cachedKeys).length, 1, 'в текущем ключе остались только свежие');
        assert.ok(state.expiredBelow >= 1);
    });

    await test('таймер комнаты: свои архивы подчиняются тем же правилам', async () => {
        const clock = makeClock();
        const ctx = await pair({ clock });
        const mine = await send(ctx.alice, ROOM, 'моё старое');
        await ctx.alice.rotateRoomKey(ROOM);
        await ctx.alice.setRoomPolicy(ROOM, { expirySeconds: 7200 });
        assert.strictEqual((await read(ctx.alice, ROOM, mine)).text, 'моё старое');
        clock.advance(4 * HOUR);
        await ctx.alice.maintainRoomKeys(ROOM);
        assert.deepStrictEqual(await read(ctx.alice, ROOM, mine), { ok: false, reason: 'key-expired' });
        assert.deepStrictEqual(await ctx.alice._storage.keys('skArchive:' + ROOM + ':1:'), []);
    });

    await test('без таймера ключи не удаляются по времени', async () => {
        const clock = makeClock();
        const ctx = await pair({ clock });
        const m = await send(ctx.alice, ROOM, 'навсегда');
        await read(ctx.bob, ROOM, m);
        clock.advance(400 * DAY);
        const stats = await ctx.bob.maintainRoomKeys(ROOM);
        assert.deepStrictEqual(stats, { expiredKeys: 0, removedArchives: 0 });
        assert.strictEqual((await read(ctx.bob, ROOM, m)).text, 'навсегда');
    });

    await test('цепочка архивного чужого ключа без prev.final стирается через 7 дней', async () => {
        const clock = makeClock();
        const ctx = await pair({ clock });
        const unread = await send(ctx.alice, ROOM, 'не прочитано до ротации');
        await rotate(ctx, true, { withoutPrev: true });
        const oldId = (await stored(ctx.bob, 'senderKey:' + ROOM + ':1')).archive[0].id;
        const name = 'skArchive:' + ROOM + ':1:' + oldId;
        assert.ok((await stored(ctx.bob, name)).chainKey, 'цепочка открыта');
        clock.advance(6 * DAY);
        await ctx.bob.maintainRoomKeys(ROOM);
        assert.ok((await stored(ctx.bob, name)).chainKey, 'через 6 дней цепочка ещё есть');
        clock.advance(2 * DAY);
        await ctx.bob.maintainRoomKeys(ROOM);
        const rec = await stored(ctx.bob, name);
        assert.ok(!('chainKey' in rec), 'chainKey удалён');
        assert.strictEqual(rec.final, -1, 'закрыта по прочитанному: ничего не читали');
        assert.deepStrictEqual(await read(ctx.bob, ROOM, unread), { ok: false, reason: 'stale-sender-key' });
    });

    await test('бюджет: сверх MAX_KEYS_PER_ROOM удаляются самые старые архивы, расшифровка — key-expired', async () => {
        const ctx = await pair();
        const a1 = await send(ctx.alice, ROOM, 'первый ключ');
        await rotate(ctx);
        const a2 = await send(ctx.alice, ROOM, 'второй ключ');
        await rotate(ctx);
        const a3 = await send(ctx.alice, ROOM, 'третий ключ');
        for (const m of [a1, a2, a3]) assert.strictEqual((await read(ctx.bob, ROOM, m)).ok, true);
        // Раздуваем записи Боба заведомо лишними ключами: бюджет превышен.
        const state = await stored(ctx.bob, 'senderKey:' + ROOM + ':1');
        const [newest, oldest] = state.archive; // индекс: новые первыми
        const fillTo = (rec, from, count) => { for (let i = 0; i < count; i++) { rec.cachedKeys[from + i] = 'AAAA'; rec.keyTimes[from + i] = 0; } };
        for (const entry of [oldest, newest]) {
            const name = 'skArchive:' + ROOM + ':1:' + entry.id;
            const rec = await stored(ctx.bob, name);
            fillTo(rec, 1000, 11000);
            await ctx.bob._storage.set(name, rec);
        }
        const stats = await ctx.bob.maintainRoomKeys(ROOM);
        assert.strictEqual(stats.removedArchives, 1, JSON.stringify(stats));
        assert.deepStrictEqual(await read(ctx.bob, ROOM, a1), { ok: false, reason: 'key-expired' }, 'самый старый архив удалён');
        assert.strictEqual((await read(ctx.bob, ROOM, a2)).text, 'второй ключ');
        assert.strictEqual((await read(ctx.bob, ROOM, a3)).text, 'третий ключ');
        const after = await stored(ctx.bob, 'senderKey:' + ROOM + ':1');
        assert.strictEqual(typeof after.archive[1], 'string', 'в индексе осталось надгробие');
    });

    await test('бюджет: одни текущие цепочки режутся с начала, граница запоминается', async () => {
        const ctx = await pair();
        const m = await send(ctx.alice, ROOM, 'читается');
        await read(ctx.bob, ROOM, m);
        const name = 'senderKey:' + ROOM + ':1';
        const state = await stored(ctx.bob, name);
        for (let i = 0; i < I.MAX_KEYS_PER_ROOM + 500; i++) { state.cachedKeys[100000 + i] = 'AAAA'; state.keyTimes[100000 + i] = 0; }
        await ctx.bob._storage.set(name, state);
        const stats = await ctx.bob.maintainRoomKeys(ROOM);
        assert.ok(stats.expiredKeys >= 500, JSON.stringify(stats));
        const after = await stored(ctx.bob, name);
        assert.strictEqual(Object.keys(after.cachedKeys).length, I.MAX_KEYS_PER_ROOM);
        assert.ok(after.expiredBelow > 0);
        assert.deepStrictEqual(await read(ctx.bob, ROOM, m), { ok: false, reason: 'key-expired' }, 'самый старый ключ цепочки срезан');
    });

    await test('предел цепочки MAX_KEYS_PER_CHAIN: старые ключи уходят с явной границей, а не молча', async () => {
        const ctx = await pair();
        const first = await send(ctx.alice, ROOM, 'самое первое');
        assert.strictEqual((await read(ctx.bob, ROOM, first)).text, 'самое первое');
        // Alice «ушла вперёд»: честно продвигаем её цепочку на MAX_SKIP - 1 шагов без сообщений.
        const name = 'senderKey:' + ROOM + ':1';
        const aliceState = await stored(ctx.alice, name);
        const subtle = globalThis.crypto.subtle;
        let chain = I.b64decode(aliceState.chainKey);
        for (let i = 1; i < I.MAX_SKIP; i++) {
            const key = await subtle.importKey('raw', chain, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
            chain = new Uint8Array(await subtle.sign('HMAC', key, new Uint8Array([2])));
        }
        aliceState.chainKey = I.b64encode(chain);
        aliceState.nextIteration = I.MAX_SKIP;
        aliceState.startIteration = I.MAX_SKIP; // иначе жёсткий порог числа сообщений не даст шифровать
        await ctx.alice._storage.set(name, aliceState);
        const far = await send(ctx.alice, ROOM, 'далеко');
        assert.strictEqual((await read(ctx.bob, ROOM, far)).text, 'далеко');
        const bobState = await stored(ctx.bob, name);
        assert.strictEqual(Object.keys(bobState.cachedKeys).length, I.MAX_KEYS_PER_CHAIN);
        assert.strictEqual(bobState.expiredBelow, 1);
        assert.deepStrictEqual(await read(ctx.bob, ROOM, first), { ok: false, reason: 'key-expired' });
    });

    finish();
})();
