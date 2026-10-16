'use strict';
// Допуск в группу (signed-membership.md, разделы 5, 9.1, 9.2, 12): призрак без подписи не получает ключ,
// допуск подтверждает участника, якорная проверка новичка (только при joinIntent и по способу входа),
// снимок состава, дубликаты ключей. Настоящие клиенты E2EE против fake-server с сертификатами.
// Запуск: node test/membership.admission.test.js

const { assert, M, makeWorld, test, finish, ids, ROOM, MINUTE } = require('./membership-world');

const b64 = M.toB64;

(async () => {
    console.log('Подписанный состав: допуск, призраки, якорная проверка\n');

    // ===================== Призрак =====================

    await test('призрак без сертификата: не подтверждён, ключ ему не отправлен, его сообщения помечены unverifiedSender, он чужого не читает', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);

        const result = await w.ensure(a);
        assert.deepStrictEqual(ids(result.unconfirmed), [ghost.id]);
        assert.ok(result.warnings.some(x => x.userId === ghost.id && x.reason === 'unconfirmed-member'));
        assert.deepStrictEqual(ids(result.members.filter(m => m.status === 'confirmed')), [b.id]);
        assert.ok(!w.server._keyShares.some(s => s.recipientId === ghost.id), 'призрак ключа не получил');
        assert.ok(w.server._keyShares.some(s => s.recipientId === b.id));
        assert.strictEqual(result.members.find(m => m.id === ghost.id).status, 'unconfirmed');

        // Призрак сам подтверждает Алису вручную и присылает ей свой ключ: SKDM принимается, сообщения помечены.
        await w.trustAll(ghost, [a.id]);
        await w.ensure(ghost);
        assert.strictEqual((await w.sync(a)).applied, 1);
        const sent = await ghost.client.encryptOutgoing(ROOM, 'привет от призрака', { messageId: '3000001' });
        const read = await a.client.decryptIncoming(ROOM, ghost.id, sent, '3000001');
        assert.strictEqual(read.ok, true);
        assert.strictEqual(read.unverifiedSender, true);
        // Сообщение самой Алисы призрак прочитать не может: ключа у него нет.
        await w.sync(b);
        const mine = await a.client.encryptOutgoing(ROOM, 'секрет группы', { messageId: '3000002' });
        assert.strictEqual((await w.sync(ghost)).applied, 0);
        assert.strictEqual((await ghost.client.decryptIncoming(ROOM, a.id, mine, '3000002')).reason, 'no-sender-key');
        assert.strictEqual((await b.client.decryptIncoming(ROOM, a.id, mine, '3000002')).text, 'секрет группы');
        w.noViolations();
    });

    await test('unverifiedSender вычисляется при расшифровке по текущему V: после подтверждения пометка исчезает без перешифровки', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        await w.ensure(a);
        await w.trustAll(ghost, [a.id]);
        await w.ensure(ghost);
        await w.sync(a);
        const sent = await ghost.client.encryptOutgoing(ROOM, 'раз', { messageId: '3000010' });
        assert.strictEqual((await a.client.decryptIncoming(ROOM, ghost.id, sent, '3000010')).unverifiedSender, true);
        assert.deepStrictEqual(await a.client.trustMember(ROOM, ghost.id), { ok: true, cancelledIntent: false });
        const again = await a.client.decryptIncoming(ROOM, ghost.id, sent, '3000010');
        assert.strictEqual(again.ok, true);
        assert.strictEqual(again.unverifiedSender, undefined, 'после подтверждения пометки нет');
        // Свои сообщения не помечаются никогда.
        const mine = await a.client.encryptOutgoing(ROOM, 'моё', { messageId: '3000011' });
        assert.strictEqual((await a.client.decryptIncoming(ROOM, a.id, mine, '3000011')).unverifiedSender, undefined);
    });

    // ===================== Допуск участником =====================

    await test('vouch от доверенного подтверждает участника и открывает ему ключ; vouch от недоверенного - нет', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const c = await w.addUser(1003);
        const x = await w.addUser(1004);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.approve(b, c);                       // допуск от участника, подтверждённого Алисой
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        await w.trustAll(ghost, []);
        const fromGhost = await ghost.client.signApproval(ROOM, w.keysOf(x.id));
        w.server.admit(ROOM, x.id, x.chatId, { actorId: ghost.id, kind: 1, cert: fromGhost.cert, snap: fromGhost.snap });

        const result = await w.ensure(a);
        const byId = new Map(result.members.map(m => [m.id, m]));
        assert.deepStrictEqual([byId.get(c.id).status, byId.get(c.id).how, byId.get(c.id).by], ['confirmed', 'vouched', b.id]);
        assert.strictEqual(byId.get(x.id).status, 'unconfirmed', 'допуск от недоверенного не годится');
        assert.strictEqual(byId.get(ghost.id).status, 'unconfirmed');
        assert.ok(w.server._keyShares.some(s => s.recipientId === c.id));
        assert.ok(!w.server._keyShares.some(s => s.recipientId === x.id || s.recipientId === ghost.id));
        w.noViolations();
    });

    await test('участник из заявки получает ключ и читает; одобрение подписано: статусы у одобренного и у остальных', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, j);
        const jr = await w.ensure(j);
        const byId = new Map(jr.members.map(m => [m.id, m]));
        assert.deepStrictEqual([byId.get(j.id).status, byId.get(j.id).how, byId.get(j.id).by], ['self', 'approved', a.id]);
        assert.deepStrictEqual([byId.get(a.id).status, byId.get(a.id).how, byId.get(a.id).by], ['confirmed', 'approved', a.id]);
        assert.deepStrictEqual(jr.anchor, { ok: true, via: 'request', by: a.id });
        assert.strictEqual(await w.stored(j, 'joinIntent:' + ROOM), null, 'намерение расходуется');
        assert.strictEqual((await w.stored(j, 'trusted:' + ROOM)).bootstrapDone, true);
        const ar = await w.ensure(a);
        assert.deepStrictEqual(ar.members.find(m => m.id === j.id), { id: j.id, username: 'user' + j.id, status: 'confirmed', how: 'vouched', by: a.id });
        assert.strictEqual((await w.sync(j)).applied, 1);
        const sent = await a.client.encryptOutgoing(ROOM, 'добро пожаловать', { messageId: '3000020' });
        const read = await j.client.decryptIncoming(ROOM, a.id, sent, '3000020');
        assert.strictEqual(read.text, 'добро пожаловать');
        assert.strictEqual(read.unverifiedSender, undefined);
    });

    // ===================== Якорная проверка (М1) =====================

    await test('якорь (а): создатель комнаты - сертификат "для него" от призрака со снимком не подтверждает никого', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const x = await w.addUser(1002);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        w.server.evil.addGhost(ROOM, x.id, x.chatId);
        // Призрак подписывает допуск создателю; в снимок призрака входят он сам и участник x (ключи x призраку известны).
        await ghost.client.trustMember(ROOM, a.id).catch(() => null);
        const forged = await ghost.client.signApproval(ROOM, w.keysOf(a.id));
        w.server.evil.injectCert(ROOM, { subjectId: a.id, actorId: ghost.id, kind: 1, cert: forged.cert, snap: forged.snap });
        const before = await w.stored(a, 'trusted:' + ROOM);
        const result = await w.ensure(a);
        assert.strictEqual(result.anchor, null, 'якорной проверки у создателя нет');
        assert.deepStrictEqual(ids(result.unconfirmed), [x.id, ghost.id].sort((p, q) => p - q));
        assert.deepStrictEqual((await w.stored(a, 'trusted:' + ROOM)).list.map(e => e.id), [a.id], 'V = {я}');
        assert.strictEqual(before.bootstrapDone, true);
    });

    await test('якорь (б): участник с записанным V - подсунутый сертификат "для него" якорем не становится', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(b);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        const forged = await ghost.client.signApproval(ROOM, w.keysOf(b.id));
        w.server.evil.injectCert(ROOM, { subjectId: b.id, actorId: ghost.id, kind: 1, cert: forged.cert, snap: forged.snap });
        const result = await w.ensure(b);
        assert.strictEqual(result.anchor, null);
        assert.strictEqual(result.members.find(m => m.id === ghost.id).status, 'unconfirmed');
        assert.deepStrictEqual(ids(result.members.filter(m => m.status === 'confirmed')), [a.id]);
    });

    await test('якорь (в): без joinIntent при V = {я} сертификат "для меня" якорем не служит (потеря данных)', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const p = await w.addUser(1002);
        await w.createRoom(a);
        // Допуск p есть на сервере, но намерения входа на устройстве p нет (оно не создавалось или данные потеряны).
        const signed = await a.client.signApproval(ROOM, w.keysOf(p.id));
        w.server.admit(ROOM, p.id, p.chatId, { actorId: a.id, kind: 1, cert: signed.cert, snap: signed.snap });
        const result = await w.ensure(p);
        assert.strictEqual(result.anchor, null);
        assert.deepStrictEqual(ids(result.unconfirmed), [a.id]);
        // Восстановление: ручное подтверждение либо повторный вход.
        assert.deepStrictEqual((await p.client.trustMember(ROOM, a.id)).ok, true);
        assert.strictEqual((await w.ensure(p)).unconfirmed.length, 0);
    });

    await test('якорь (г): с joinIntent и верным сертификатом (заявка, ссылка) намерение расходуется в той же секции, повтор безвреден', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        const k = await w.addUser(1003);
        await w.createRoom(a);
        await w.approve(a, j);
        await w.ensure(a);                       // V Алисы пополняется Джеем: он попадёт в снимок приглашения
        const invite = await w.makeInvite(a);
        await w.joinByLink(k, invite);
        assert.strictEqual((await w.stored(k, 'joinIntent:' + ROOM)).via, 'invite');
        assert.strictEqual(await w.stored(k, 'trusted:' + ROOM), null, 'до проверки V не записан');
        const first = await w.ensure(k);
        assert.deepStrictEqual(first.anchor, { ok: true, via: 'invite', by: a.id });
        assert.strictEqual(await w.stored(k, 'joinIntent:' + ROOM), null);
        const trusted = await w.stored(k, 'trusted:' + ROOM);
        assert.strictEqual(trusted.bootstrapDone, true);
        const entries = new Map(trusted.list.map(e => [e.id, e]));
        assert.deepStrictEqual([entries.get(k.id).how, entries.get(k.id).by], ['invite', a.id]);
        assert.deepStrictEqual([entries.get(a.id).how, entries.get(a.id).by], ['invite', a.id]);
        // j есть в снимке приглашения Алисы (она его подтвердила): подтверждён по якорю.
        assert.deepStrictEqual([entries.get(j.id).how, entries.get(j.id).by], ['invite', a.id]);
        const again = await w.ensure(k);
        assert.strictEqual(again.anchor, null, 'повтор безвреден: bootstrapDone запрещает якорь');
        assert.deepStrictEqual((await w.stored(k, 'trusted:' + ROOM)), trusted);
        w.noViolations();
    });

    await test('якорь (д): падение между записью V и расходом намерения - bootstrapDone запрещает повтор, намерение снимается', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, j);
        await w.ensure(j);
        // Состояние "V записан, намерение осталось" (процесс упал между шагами).
        await j.storage.set('joinIntent:' + ROOM, { via: 'request', at: Math.floor(w.clock.now() / 60000) });
        const result = await w.ensure(j);
        assert.strictEqual(result.anchor, null, 'якорь запрещён bootstrapDone');
        assert.strictEqual(await w.stored(j, 'joinIntent:' + ROOM), null, 'бесполезное намерение снято');
    });

    await test('якорь (е): вид сертификата определяется способом входа - при ссылке явный vouch и join с чужим ref не годятся, при заявке - join и revouch', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        const k = await w.addUser(1003);
        await w.createRoom(a);
        const one = await w.makeInvite(a);
        const oneStored = w.server.getInvite(ROOM);
        // Вход по ссылке, но сервер подсовывает явный vouch от Алисы (слабый якорь) вместо join.
        await j.client.prepareJoin(ROOM, { secret: one.secret, inviteCert: oneStored.cert });
        const vouch = await a.client.signApproval(ROOM, w.keysOf(j.id));
        w.server.admit(ROOM, j.id, j.chatId, { actorId: a.id, kind: 1, cert: vouch.cert, snap: vouch.snap });
        let result = await w.ensure(j);
        assert.strictEqual(result.anchor.ok, false, 'при ссылке vouch игнорируется');
        assert.strictEqual(result.anchor.reason, 'no-certificate');
        assert.strictEqual(await w.stored(j, 'trusted:' + ROOM), null, 'V не пишется');
        assert.ok(await w.stored(j, 'joinIntent:' + ROOM), 'намерение не расходуется');

        // join с ref другого приглашения: второе приглашение подписано Алисой, но намерение хранит хэш первого.
        w.server.removeParticipant(ROOM, j.id);
        const two = await w.makeInvite(a);
        const twoStored = w.server.getInvite(ROOM);
        const forged = await j.client.prepareJoin(ROOM, { secret: two.secret, inviteCert: twoStored.cert });
        await j.client.prepareJoin(ROOM, { secret: one.secret, inviteCert: oneStored.cert });   // намерение - приглашение one
        w.server.admit(ROOM, j.id, j.chatId, { actorId: 0, kind: 3, cert: forged.joinCert, aux: twoStored.cert });
        result = await w.ensure(j);
        assert.strictEqual(result.anchor.ok, false, 'join с ref, не равным inviteHash, отвергается');

        // Вход по заявке: join якорем не служит, даже действительный.
        const kInvite = await w.makeInvite(a);
        const kStored = w.server.getInvite(ROOM);
        const kJoin = await k.client.prepareJoin(ROOM, { secret: kInvite.secret, inviteCert: kStored.cert });
        await k.client.prepareJoin(ROOM, {});                                   // намерение - заявка
        w.server.admit(ROOM, k.id, k.chatId, { actorId: 0, kind: 3, cert: kJoin.joinCert, aux: kStored.cert });
        result = await w.ensure(k);
        assert.strictEqual(result.anchor.ok, false, 'при заявке join не годится');
        assert.strictEqual(result.anchor.reason, 'no-certificate');
    });

    await test('якорь (ж): перезагрузка между входом по ссылке и первой проверкой - материал в joinIntent, секрета не нужно; V не пишется, пока намерение живо', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        let j = await w.addUser(1002);
        await w.createRoom(a);
        const invite = await w.makeInvite(a);
        await w.joinByLink(j, invite);
        const intent = await w.stored(j, 'joinIntent:' + ROOM);
        assert.ok(intent.inviteHash && intent.inviteSnap && intent.joinCert);
        // Сервер скрывает сертификаты: якоря нет, обычная проверка V не пишет и bootstrapDone не ставит.
        w.server.evil.hideCerts(j.id);
        let result = await w.ensure(j);
        assert.strictEqual(result.anchor.ok, false);
        assert.strictEqual(await w.stored(j, 'trusted:' + ROOM), null);
        j = w.reload(j);
        w.server.evil.showCerts(j.id);
        result = await w.ensure(j);
        assert.deepStrictEqual(result.anchor, { ok: true, via: 'invite', by: a.id }, 'после перезагрузки якорь проходит без секрета');
        // Секрета ссылки у входящего в хранилище нет.
        const dump = JSON.stringify(Array.from(await j.storage.keys('')).map(String));
        assert.ok(!dump.includes(invite.secret));
    });

    await test('якорь: ручное подтверждение при живом намерении отменяет его, V пишется вместе с bootstrapDone', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        await j.client.prepareJoin(ROOM, {});
        w.server.admit(ROOM, j.id, j.chatId, null);
        await w.ensure(j);
        assert.ok(await w.stored(j, 'joinIntent:' + ROOM));
        const res = await j.client.trustMember(ROOM, a.id);
        assert.deepStrictEqual(res, { ok: true, cancelledIntent: true });
        assert.strictEqual(await w.stored(j, 'joinIntent:' + ROOM), null);
        assert.strictEqual((await w.stored(j, 'trusted:' + ROOM)).bootstrapDone, true);
    });

    await test('якорь (з): собственный выход стирает записи комнаты; повторный вход снова идёт с joinIntent и якорем', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, j);
        await w.ensure(j);
        await j.storage.set('removed:' + ROOM, { 5: 1 });
        await j.storage.set('revouch:' + ROOM, [{ x: 7, orig: '0'.repeat(64), due: 1 }]);
        await j.storage.set('inviteSecret:' + ROOM, { s: 'x', certHash: '0'.repeat(64) });
        await j.client.forgetRoom(ROOM);
        for (const name of ['trusted:', 'removed:', 'revouch:', 'joinIntent:', 'viewPending:', 'inviteSecret:', 'members:']) {
            assert.strictEqual(await w.stored(j, name + ROOM), null, name);
        }
        assert.deepStrictEqual(await j.storage.keys('delivered:' + ROOM + ':'), []);
        w.server.removeParticipant(ROOM, j.id);
        // Повторный вход: новая заявка - новое намерение - якорь.
        await w.approve(a, j);
        const result = await w.ensure(j);
        assert.strictEqual(result.anchor.ok, true);
    });

    // ===================== Снимок =====================

    await test('снимок: snapHash в сертификате совпадает с хэшем снимка, полученного отдельно; подменённый снимок отвергается якорем', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const j = await w.addUser(1003);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        const signed = await a.client.signApproval(ROOM, w.keysOf(j.id));
        const cert = M.parseCert(M.fromB64(signed.cert)).cert;
        const snap = M.fromB64(signed.snap);
        assert.strictEqual(cert.snapN, 2, 'Алиса и Боб');
        assert.strictEqual(await M.checkSnap(snap, cert.snapN, cert.snapHash), true);
        // Сервер подменяет снимок в ответе participants: якорь отказывает ("снимок повреждён"), V = {я}.
        await j.client.prepareJoin(ROOM, {});
        const tampered = snap.slice(); tampered[3] ^= 1;
        w.server.admit(ROOM, j.id, j.chatId, { actorId: a.id, kind: 1, cert: signed.cert, snap: b64(tampered) });
        const result = await w.ensure(j);
        assert.deepStrictEqual([result.anchor.ok, result.anchor.reason], [false, 'snap-bad']);
        assert.strictEqual(result.members.filter(m => m.status === 'confirmed').length, 0);
    });

    await test('снимок: новичок по якорю подтверждает участников снимка; участник с подменённым ключом не подтверждается; подмена ключа самого A невозможна', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const j = await w.addUser(1003);
        const attacker = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.approve(a, j);
        // Сервер показывает Джею ключи атакующего вместо Бобовых: memkey не входит в снимок.
        w.server.evil.impersonate(b.id, attacker.id);
        const result = await w.ensure(j);
        const byId = new Map(result.members.map(m => [m.id, m]));
        assert.strictEqual(byId.get(a.id).status, 'confirmed');
        assert.strictEqual(byId.get(b.id).status, 'unconfirmed', 'подменённый ключ Боба вне снимка');

        // Второй входящий: сервер подменяет ключи самого Алисы - подпись допуска не сходится с тем ключом, что показан.
        const w2 = makeWorld();
        const a2 = await w2.addUser(1001);
        const j2 = await w2.addUser(1003);
        const evil2 = await w2.addUser(1666);
        await w2.createRoom(a2);
        await w2.approve(a2, j2);
        w2.server.evil.impersonate(a2.id, evil2.id);
        const r2 = await w2.ensure(j2);
        assert.strictEqual(r2.anchor.ok, false, 'подмена A невозможна: допуск подписан настоящим ключом A');
        assert.strictEqual(r2.members.find(m => m.id === a2.id).status, 'unconfirmed');
    });

    await test('ручной участник не попадает в подписываемый снимок; после vouchForMember - попадает', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const g = await w.addUser(1010);
        await w.createRoom(a);
        w.server.addParticipant(ROOM, g.id, g.chatId);
        await w.ensure(a);
        assert.strictEqual((await a.client.trustMember(ROOM, g.id)).ok, true);
        const memG = M.toHex(await M.memkey(g.id, M.fromB64(w.keysOf(g.id).signingKey), M.fromB64(w.keysOf(g.id).dhKey)));
        const snapHex = async () => {
            const invite = await a.client.signInvite(ROOM, { ttlSeconds: 3600 });
            return M.toHex(M.fromB64(invite.snap));
        };
        assert.ok(!(await snapHex()).includes(memG), 'ручной участник вне снимка (П13)');
        const posted = w.server._certPosts.length;
        assert.strictEqual(w.server._certPosts.length, posted, 'ручное подтверждение сертификата не публикует');
        const res = await a.client.vouchForMember(a.chatId, ROOM, g.id);
        assert.deepStrictEqual(res, { ok: true, stored: true });
        assert.strictEqual(w.server._certPosts.length, posted + 1);
        assert.ok((await snapHex()).includes(memG), 'после явного поручительства участник входит в снимок');
        const trusted = await w.stored(a, 'trusted:' + ROOM);
        assert.strictEqual(trusted.list.find(e => e.id === g.id).vouchedByMe, true);
        const cert = M.parseCert(M.fromB64(w.server._certPosts[posted].body.cert)).cert;
        assert.strictEqual(cert.kind, M.KIND.vouch);
        assert.strictEqual(cert.subjectId, g.id);
    });

    await test('vouchForMember: нельзя поручиться за неподтверждённого; ручное подтверждение требует закреплённых ключей', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const g = await w.addUser(1010);
        const nokeys = await w.addUser(1011, { init: false });
        await w.createRoom(a);
        w.server.addParticipant(ROOM, g.id, g.chatId);
        w.server.addParticipant(ROOM, nokeys.id, nokeys.chatId);
        await w.ensure(a);
        assert.deepStrictEqual(await a.client.vouchForMember(a.chatId, ROOM, g.id), { ok: false, reason: 'not-trusted' });
        assert.deepStrictEqual(await a.client.trustMember(ROOM, nokeys.id), { ok: false, reason: 'no-keys' });
    });

    // ===================== Дубликаты ключей =====================

    await test('клон ключей под другим id: новичок с чужими ключами неподтверждён, кто уже в V - остаётся без ротации; если оба вне V - не подтверждён никто', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const x = await w.addUser(1002);
        const clone = await w.addUser(1666, { init: false });
        await w.createRoom(a);
        await w.approve(a, x);
        await w.ensure(a);
        await w.sync(x);
        // Сервер заводит учётную запись-клон с теми же identity-ключами, что у x.
        const keys = w.server.identityOf(x.id);
        await w.server.transportFor(clone.id).putIdentity({ identity_signing_key: keys.identity_signing_key, identity_dh_key: keys.identity_dh_key });
        w.server.addParticipant(ROOM, clone.id, clone.chatId);
        const keyBefore = (await w.stored(a, 'senderKey:' + ROOM + ':' + a.id)).senderKeyId;
        const result = await w.ensure(a);
        const byId = new Map(result.members.map(m => [m.id, m]));
        assert.strictEqual(byId.get(x.id).status, 'confirmed', 'кто уже в V по id, там и остаётся');
        assert.strictEqual(byId.get(x.id).duplicateKeys, true);
        assert.strictEqual(byId.get(clone.id).status, 'unconfirmed');
        assert.deepStrictEqual(result.duplicateKeys.map(g => g.ids.slice().sort((p, q) => p - q)), [[x.id, clone.id].sort((p, q) => p - q)]);
        assert.ok(result.warnings.some(m => m.reason === 'duplicate-keys'));
        assert.strictEqual(result.rotated, false, 'ротации нет');
        assert.strictEqual((await w.stored(a, 'senderKey:' + ROOM + ':' + a.id)).senderKeyId, keyBefore);
        assert.ok(result.unconfirmed.find(u => u.id === clone.id).duplicateKeys === true);
        assert.ok(!w.server._keyShares.some(s => s.recipientId === clone.id));

        // Клон не подтверждается и допуском (даже действительным), пока человек не решит сам.
        const forged = await a.client.signApproval(ROOM, w.keysOf(clone.id));
        w.server.evil.injectCert(ROOM, { subjectId: clone.id, actorId: a.id, kind: 1, cert: forged.cert, snap: forged.snap });
        assert.strictEqual((await w.ensure(a)).members.find(m => m.id === clone.id).status, 'unconfirmed');
        assert.strictEqual((await a.client.trustMember(ROOM, clone.id)).ok, true, 'ручное решение возможно (с предупреждением)');
    });

    await test('клон под другим id не подтверждается снимком (memkey v2 привязан к id): в снимке стоит memkey оригинала', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const x = await w.addUser(1002);
        const j = await w.addUser(1003);
        const clone = await w.addUser(1666, { init: false });
        await w.createRoom(a);
        await w.approve(a, x);
        const keys = w.server.identityOf(x.id);
        await w.server.transportFor(clone.id).putIdentity({ identity_signing_key: keys.identity_signing_key, identity_dh_key: keys.identity_dh_key });
        w.server.addParticipant(ROOM, clone.id, clone.chatId);
        await w.approve(a, j);
        const result = await w.ensure(j);
        const byId = new Map(result.members.map(m => [m.id, m]));
        assert.strictEqual(byId.get(clone.id).status, 'unconfirmed');
        assert.strictEqual(byId.get(x.id).status, 'unconfirmed', 'ключи x есть у двух участников: ни один не подтверждается снимком');
    });

    finish();
})().catch(err => { console.error(err); process.exitCode = 1; });
