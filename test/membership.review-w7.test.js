'use strict';
// Повторное ревью криптографии, волна 7 (R4), часть про подписанный состав группы (signed-membership.md):
//   F1  принятие нового ключа собеседника не делает «призрака» подтверждённым в чужих комнатах (9.7, П1);
//   F4  отправка блокируется, если ключ комнаты не получил ни один участник (9.4);
//   З1  кратковременная подмена ключа не выбивает подтверждённых из V навсегда (9.7);
//   З2  аккаунт, добавленный сервером без намерения входа, не считает себя создателем (9.1).
// Запуск: node test/membership.review-w7.test.js

const { assert, E2EE, mlkem, makeWorld, test, finish, ROOM, DAY, chatOf } = require('./membership-world');
const Policy = require('../public/lib/e2ee-policy.js');

const at = (user, room) => ({ ...user, room, chatId: chatOf(user.id, room) });
const memberOf = (result, id) => result.members.find(m => m.id === id);
const sharesTo = (w, room, recipientId, senderId) =>
    w.server._keyShares.filter(s => s.roomId === room && s.recipientId === recipientId && s.senderId === senderId).length;

(async () => {
    console.log('Ревью W7 R4: подписанный состав\n');

    // ===================== F1: принятие нового ключа и призраки в других комнатах =====================

    await test('F1: принятие нового ключа в R1 не подтверждает «призрака» R2 и не отдаёт ему ключ R2', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        const carol = await w.addUser(3);
        const R2 = 200;
        // R1: Алиса создала, Боб принят по одобрению.
        await w.createRoom(alice);
        await w.approve(alice, bob);
        await w.ensure(alice); await w.sync(bob); await w.ensure(bob); await w.sync(alice);
        // R2: Кэрол создала, Алиса принята; Боба там никто не подписывал, сервер добавил его молча.
        const carol2 = at(carol, R2);
        const alice2 = at(alice, R2);
        await w.createRoom(carol2);
        await w.approve(carol2, alice2);
        await w.ensure(carol2); await w.sync(alice2); await w.ensure(alice2); await w.sync(carol2);
        w.server.evil.addGhost(R2, bob.id, chatOf(bob.id, R2));
        let r = await w.ensure(alice2);
        assert.strictEqual(memberOf(r, bob.id).status, 'unconfirmed');

        // Боб переустановил клиент (новые ключи); Алиса видит смену в R1 и принимает.
        await w.addUser(2);
        r = await w.ensure(alice);
        assert.ok(r.identityChanges.some(c => c.userId === bob.id));
        assert.strictEqual(await alice.client.acceptPeerIdentityChange(bob.id), true);

        // R1: Боб был в V - решение человека подтверждает его вручную.
        const inR1 = memberOf(await w.ensure(alice), bob.id);
        assert.deepStrictEqual([inR1.status, inR1.how], ['confirmed', 'manual']);
        // R2: Боба никто не подписывал - остаётся неподтверждённым, записи V нет, ключ ему не уходит.
        r = await w.ensure(alice2);
        assert.strictEqual(memberOf(r, bob.id).status, 'unconfirmed', 'призрак R2 не должен стать подтверждённым');
        assert.ok(!(await w.stored(alice2, 'trusted:' + R2)).list.some(e => e.id === bob.id), 'в V комнаты R2 Боба нет');
        assert.strictEqual(sharesTo(w, R2, bob.id, alice.id), 0, 'key-share Алиса -> Боб в R2 не отправляется');
        const id = String(w.server.newMessageId());
        const env = await alice2.client.encryptOutgoing(R2, 'секрет комнаты R2', { messageId: id });
        w.server.postMessage(R2, alice.id, env, id);
        const bobNew2 = at(w.users.get(2), R2);
        await w.sync(bobNew2);
        const out = await bobNew2.client.decryptIncoming(R2, null, env, id);
        assert.notStrictEqual(out.ok && out.text, 'секрет комнаты R2', 'призрак R2 не должен прочитать сообщение');
        w.noViolations();
    });

    await test('F1: сервер подменил ключ собеседника и добавил «его» призраком в другие комнаты - одно «Принять» не открывает их', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        const carol = await w.addUser(3);
        const dave = await w.addUser(4);
        const mallory = await w.addUser(9);
        await w.createRoom(alice); await w.approve(alice, bob);
        await w.ensure(alice); await w.sync(bob); await w.ensure(bob); await w.sync(alice);
        for (const [room, owner] of [[200, carol], [300, dave]]) {
            const o = at(owner, room);
            const a = at(alice, room);
            await w.createRoom(o); await w.approve(o, a);
            await w.ensure(o); await w.sync(a); await w.ensure(a); await w.sync(o);
            w.server.evil.addGhost(room, bob.id, chatOf(bob.id, room));
            assert.strictEqual(memberOf(await w.ensure(a), bob.id).status, 'unconfirmed');
        }
        // MITM: сервер выдаёт ключи Мэллори за ключи Боба; Алиса принимает «смену ключа».
        w.server.evil.impersonate(bob.id, mallory.id);
        await w.ensure(alice);
        assert.strictEqual(await alice.client.acceptPeerIdentityChange(bob.id), true);
        // Атакующий: клиент на хранилище Мэллори, представляется как Боб.
        const evil = E2EE.createClient({ userId: bob.id, storage: mallory.storage, kem: mlkem, now: w.clock.now, transport: w.server.shadowTransportFor(bob.id) });
        for (const room of [200, 300]) {
            const a = at(alice, room);
            await w.ensure(a);
            const id = String(w.server.newMessageId());
            const env = await a.client.encryptOutgoing(room, 'секрет комнаты R' + room / 100, { messageId: id });
            w.server.postMessage(room, alice.id, env, id);
            await evil.syncKeyShares(chatOf(bob.id, room), room);
            const out = await evil.decryptIncoming(room, null, env, id);
            assert.ok(!out.ok, 'сервер не должен читать комнату R' + room / 100 + ': ' + JSON.stringify(out));
            assert.strictEqual(sharesTo(w, room, bob.id, alice.id), 0);
        }
        w.noViolations();
    });

    await test('F1: комната, где участник был в V, но проверка состава после смены ключа в ней ещё не прошла, подтверждает его вручную', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        const carol = await w.addUser(3);
        const R2 = 200;
        await w.createRoom(alice); await w.approve(alice, bob);
        await w.ensure(alice); await w.sync(bob); await w.ensure(bob); await w.sync(alice);
        // R2: Боб допущен Кэрол, у Алисы он в V по цепочке сертификатов.
        const carol2 = at(carol, R2);
        const alice2 = at(alice, R2);
        const bob2 = at(bob, R2);
        await w.createRoom(carol2);
        await w.approve(carol2, alice2);
        await w.approve(carol2, bob2);
        await w.ensure(carol2); await w.sync(alice2); await w.ensure(alice2);
        assert.strictEqual(memberOf(await w.ensure(alice2), bob.id).status, 'confirmed');
        // Смена ключа замечена в R1 (R2 Алиса ещё не открывала): запись V в R2 держит старый memkey.
        await w.addUser(2);
        await w.ensure(alice);
        assert.strictEqual(await alice.client.acceptPeerIdentityChange(bob.id), true);
        const inR2 = memberOf(await w.ensure(alice2), bob.id);
        assert.deepStrictEqual([inR2.status, inR2.how], ['confirmed', 'manual']);
        w.noViolations();
    });

    await test('F1: проход по комнате во время «ключ изменился» откладывает запись V (suspended), принятие ключа возвращает подтверждение, ушедший забывается', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        const carol = await w.addUser(3);
        const R2 = 200;
        await w.createRoom(alice); await w.approve(alice, bob); await w.ensure(alice);
        const carol2 = at(carol, R2);
        const alice2 = at(alice, R2);
        const bob2 = at(bob, R2);
        await w.createRoom(carol2); await w.approve(carol2, alice2); await w.approve(carol2, bob2);
        await w.ensure(carol2); await w.sync(alice2); await w.ensure(alice2);
        w.server.evil.addGhost(R2, 9, chatOf(9, R2));   // «призрак» без записи V: в suspended не попадает
        await w.addUser(9);
        await w.ensure(alice2);
        await w.addUser(2);                              // Боб сменил ключи; сервер показывает новые
        const during = await w.ensure(alice2);
        assert.strictEqual(memberOf(during, bob.id).status, 'unconfirmed');
        assert.deepStrictEqual((await w.stored(alice2, 'suspended:' + R2)).map(e => e.id), [bob.id], 'в suspended - только выпавший из V');
        assert.ok(!(await w.stored(alice2, 'trusted:' + R2)).list.some(e => e.id === bob.id));
        assert.strictEqual(await alice.client.acceptPeerIdentityChange(bob.id), true);
        const after = memberOf(await w.ensure(alice2), bob.id);
        assert.deepStrictEqual([after.status, after.how], ['confirmed', 'manual']);
        assert.strictEqual(await w.stored(alice2, 'suspended:' + R2), null, 'после подтверждения запись suspended снята');
        // Выпавший и ушедший: запись забывается, при возвращении нужно новое подтверждение.
        await w.addUser(2);
        await w.ensure(alice2);
        assert.ok(await w.stored(alice2, 'suspended:' + R2), 'снова выпал из V: запись отложена');
        w.server.removeParticipant(R2, bob.id);
        await w.ensure(alice2);
        assert.strictEqual(await w.stored(alice2, 'suspended:' + R2), null, 'ушёл из комнаты - отложенная запись забыта');
        w.noViolations();
    });

    // ===================== F4: отправка, когда ключ комнаты некому передать =====================

    await test('F4: в комнате все остальные неподтверждены (ключ никому не ушёл) - отправка блокируется, после подтверждения снимается', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        await w.createRoom(alice);
        w.server.evil.addGhost(ROOM, bob.id, bob.chatId);       // Боб в комнате без сертификата
        const session = await w.ensure(alice);
        assert.strictEqual(session.ok, true, 'рассылка не падала: адресатов просто нет');
        assert.strictEqual(session.peers, 1);
        assert.strictEqual(session.keyHolders, 0);
        assert.strictEqual(session.withheldPeers, 1, 'сессия сообщает, сколько участников остались без ключа из-за статуса');
        const block = Policy.sessionBlock(session);
        assert.ok(block, 'отправка должна быть заблокирована');
        assert.strictEqual(block.code, 'keys-withheld');
        assert.match(block.text, /не подтверждены/);
        // Подтвердили Боба вручную - ключ ушёл, блокировки нет.
        await alice.client.checkPeerIdentities([bob.id]);
        assert.deepStrictEqual(await alice.client.trustMember(ROOM, bob.id), { ok: true, cancelledIntent: false });
        const after = await w.ensure(alice);
        assert.strictEqual(after.keyHolders, 1);
        assert.strictEqual(Policy.sessionBlock(after), null);
        w.noViolations();
    });

    await test('F4: часть участников получила ключ - отправка идёт (неподтверждённый остаётся предупреждением)', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        const ghost = await w.addUser(3);
        await w.createRoom(alice);
        await w.approve(alice, bob);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        const session = await w.ensure(alice);
        assert.strictEqual(session.keyHolders, 1);
        assert.strictEqual(session.withheldPeers, 1);
        assert.strictEqual(Policy.sessionBlock(session), null);
    });

    await test('F4: участник без настроенного шифрования по-прежнему не блокирует отправку (решение e2ee-policy)', async () => {
        const w = makeWorld();
        const alice = await w.addUser(1);
        await w.addUser(3, { init: false });                    // у Кэрол нет ключей на сервере
        await w.createRoom(alice);
        w.server.addParticipant(ROOM, 3, chatOf(3));
        const notReady = await w.ensure(alice);
        assert.strictEqual(notReady.withheldPeers, 0, 'нет ключей на сервере - это не отказ из-за подтверждения');
        assert.strictEqual(Policy.sessionBlock(notReady), null);
    });

    await test('policy.sessionBlock: ключ получил кто-то - не блокирует; никто, но есть удержанные - блок; старые результаты без счётчика - как раньше', () => {
        assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 2, keyHolders: 0, withheldPeers: 2 }).code, 'keys-withheld');
        assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 2, keyHolders: 1, withheldPeers: 1 }), null);
        assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 2, keyHolders: 0, withheldPeers: 0 }), null, 'остальные без шифрования');
        assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 0, keyHolders: 0, withheldPeers: 0 }), null);
        assert.strictEqual(Policy.sessionBlock({ ok: false, peers: 2, keyHolders: 0, withheldPeers: 2 }).code, 'keys-not-delivered', 'сбой рассылки - прежний код');
        assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 2, keyHolders: 0 }), null, 'без withheldPeers - как раньше');
    });

    finish();
})().catch((err) => { console.error(err); process.exitCode = 1; });
