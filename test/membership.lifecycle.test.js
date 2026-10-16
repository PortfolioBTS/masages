'use strict';
// Жизнь состава (signed-membership.md, разделы 5.5, 5.6, 6.4, 9.1, 9.4-9.6, 12): отзыв по субъекту, подделки
// сертификатов, повторный допуск после ухода подписавшего, ротация ключа по журналу доставок, entitled парами,
// ответы на запросы ключа только получателям, ext.view и сверка взглядов, секрет ссылки.
// Запуск: node test/membership.lifecycle.test.js

const { assert, E2EE, M, makeWorld, test, finish, ids, ROOM, MINUTE, DAY } = require('./membership-world');

const nowMin = (w) => M.minuteOf(w.clock.now());
const b64 = M.toB64;

// Подпись сертификата identity-ключом участника (как подписал бы его клиент) - для проверки границ времени и подделок.
async function signAs(user, fields) {
    const identity = await user.storage.get('identity');
    return M.signCert(fields, { sig: async (m) => new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', identity.signPriv, m)) });
}

function vouchFields(w, actor, subjectId, extra = {}) {
    const keys = w.keysOf(subjectId);
    return {
        kind: M.KIND.vouch, roomId: ROOM, issuedMin: nowMin(w), nonce: globalThis.crypto.getRandomValues(new Uint8Array(16)),
        subjectId, subjectSignPub: M.fromB64(keys.signingKey), subjectDhPub: M.fromB64(keys.dhKey),
        actorId: actor.id, actorKey: M.fromB64(w.keysOf(actor.id).signingKey), ...extra,
    };
}

// Допуск actor -> subject с настоящим снимком actor (как signApproval), но с изменённым телом.
async function customVouch(w, actor, subjectId, extra = {}) {
    const real = await actor.client.signApproval(ROOM, w.keysOf(subjectId));
    const parsed = M.parseCert(M.fromB64(real.cert)).cert;
    const fields = vouchFields(w, actor, subjectId, { snapN: parsed.snapN, snapHash: parsed.snapHash, ...extra });
    return { cert: b64(await signAs(actor, fields)), snap: real.snap };
}

function plant(w, roomId, subjectId, actorId, item) {
    w.server._memberCerts.splice(0, w.server._memberCerts.length, ...w.server._memberCerts.filter(c => c.subjectId !== subjectId));
    w.server.evil.injectCert(roomId, { subjectId, actorId, kind: 1, cert: item.cert, snap: item.snap });
}

const statusOf = (result, id) => result.members.find(m => m.id === id).status;

(async () => {
    console.log('Подписанный состав: отзыв, подделки, повторный допуск, ротация по журналу, взгляды\n');

    // ===================== Отзыв по субъекту (М3) =====================

    await test('removed ставится для КАЖДОГО ушедшего, в том числе неподтверждённого; записи старше 30 суток исчезают, предел 5000', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        await w.ensure(a);
        const minute = nowMin(w);
        w.server.removeParticipant(ROOM, ghost.id);
        const result = await w.ensure(a);
        assert.deepStrictEqual(result.removedMembers.map(m => m.id), [ghost.id]);
        const removed = await w.stored(a, 'removed:' + ROOM);
        assert.deepStrictEqual(removed, { [ghost.id]: minute }, 'неподтверждённый ушедший тоже может вернуться с повторённым сертификатом');
        // Старые и лишние записи.
        const big = {};
        for (let i = 0; i < 5100; i++) big[2000000 + i] = minute - 1 - (i % 100);
        big[9] = minute - 31 * 24 * 60;
        await a.storage.set('removed:' + ROOM, big);
        await w.ensure(a);
        const trimmed = await w.stored(a, 'removed:' + ROOM);
        assert.ok(Object.keys(trimmed).length <= 5000);
        assert.ok(!('9' in trimmed), 'запись старше 30 суток исчезла');
    });

    await test('сертификат субъекта после его выхода отвергается, даже новый с другим nonce; после возвращения с допуском позже выхода - принимается', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        const oldCert = w.server._memberCerts.find(c => c.subjectId === b.id);
        const kept = { cert: oldCert.cert, snap: oldCert.snap };
        w.server.removeParticipant(ROOM, b.id);
        await w.ensure(a);                                  // removed[b] = текущая минута
        w.server.addParticipant(ROOM, b.id, b.chatId);
        // Повтор старого допуска и новый допуск в ту же минуту (nonce другой, issuedMin не позже выхода).
        const sameMinute = await customVouch(w, a, b.id);
        for (const stale of [kept, sameMinute]) {
            plant(w, ROOM, b.id, a.id, stale);
            assert.strictEqual(statusOf(await w.ensure(a), b.id), 'unconfirmed');
        }
        w.clock.advance(2 * MINUTE);
        const fresh = await customVouch(w, a, b.id);
        plant(w, ROOM, b.id, a.id, fresh);
        assert.strictEqual(statusOf(await w.ensure(a), b.id), 'confirmed', 'допуск позже выхода принимается');
    });

    await test('сертификат, подписанный ушедшим, не заменяет ссылку: копия отвергается (actor-left), подтверждённый остаётся в V, допуск ему подписывает оставшийся', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const c = await w.addUser(1003);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.approve(b, c);
        await w.ensure(a);
        const bToC = w.server._memberCerts.find(x => x.subjectId === c.id && x.actorId === b.id);
        const copy = { ...bToC };
        w.server.removeParticipant(ROOM, b.id);            // сервер удаляет сертификаты ушедшего
        w.server.evil.injectCert(ROOM, copy);               // и подсовывает его копию обратно
        const result = await w.ensure(a);
        const entry = (await w.stored(a, 'trusted:' + ROOM)).list.find(e => e.id === c.id);
        assert.strictEqual(statusOf(result, c.id), 'confirmed', 'c уже подтверждён и не вылетает из V из-за ухода подписавшего');
        // Копия сертификата ушедшего b не принята; ссылка заменена только настоящим повторным допуском Алисы.
        assert.deepStrictEqual([entry.how, entry.by], ['revouched', a.id]);
        const posts = w.server._certPosts.filter(p => p.subjectId === c.id && p.actorId === a.id);
        assert.strictEqual(posts.length, 1);
    });

    // ===================== Подделки сертификатов =====================

    await test('подделки допуска не подтверждают: чужие ключи субъекта, чужая комната, обрезка, ненулевые поля, snapN, подпись, время', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        w.server.addParticipant(ROOM, j.id, j.chatId);
        const real = await a.client.signApproval(ROOM, w.keysOf(j.id));
        const raw = M.fromB64(real.cert);
        const mutate = (off, mask = 1) => { const c = raw.slice(); c[off] ^= mask; return b64(c); };
        const variants = {
            'ключи субъекта': mutate(40),
            'dh-ключ субъекта': mutate(80),
            'другая комната': mutate(12),
            'вид сертификата': (() => { const c = raw.slice(); c[8] = 3; return b64(c); })(),
            'обрезан': b64(raw.slice(0, 270)),
            'удлинён': b64(M.concat(raw, new Uint8Array(1))),
            'ненулевой ref': mutate(150),
            'ненулевой expiresMin': mutate(172),
            'snapN = 0': (() => { const c = raw.slice(); c[173] = 0; c[174] = 0; return b64(c); })(),
            'snapN = 1025': (() => { const c = raw.slice(); c[173] = 4; c[174] = 1; return b64(c); })(),
            'подпись': mutate(220),
            'ключ подписавшего': mutate(110),
            'мусор base64': 'не-base64',
        };
        for (const [name, cert] of Object.entries(variants)) {
            plant(w, ROOM, j.id, a.id, { cert, snap: real.snap });
            assert.strictEqual(statusOf(await w.ensure(a), j.id), 'unconfirmed', name);
        }
        // Подписанные правильно, но не подходящие по сроку: из будущего (> 10 минут) и старше 30 суток.
        const future = await customVouch(w, a, j.id, { issuedMin: nowMin(w) + 11 });
        plant(w, ROOM, j.id, a.id, future);
        assert.strictEqual(statusOf(await w.ensure(a), j.id), 'unconfirmed', 'из будущего');
        const stale = await customVouch(w, a, j.id, { issuedMin: nowMin(w) - 30 * 24 * 60 - 1 });
        plant(w, ROOM, j.id, a.id, stale);
        assert.strictEqual(statusOf(await w.ensure(a), j.id), 'unconfirmed', 'старше 30 суток');
        // Границы принимаются: +10 минут и ровно 30 суток.
        for (const issuedMin of [nowMin(w) + 10, nowMin(w) - 30 * 24 * 60]) {
            plant(w, ROOM, j.id, a.id, await customVouch(w, a, j.id, { issuedMin }));
            assert.strictEqual(statusOf(await w.ensure(a), j.id), 'confirmed', 'граница ' + issuedMin);
            const entry = (await w.stored(a, 'trusted:' + ROOM));
            await a.storage.set('trusted:' + ROOM, { ...entry, list: entry.list.filter(e => e.id !== j.id) });
        }
        // Настоящий допуск подтверждает.
        plant(w, ROOM, j.id, a.id, real);
        assert.strictEqual(statusOf(await w.ensure(a), j.id), 'confirmed');
        w.noViolations();
    });

    await test('смена identity-ключа участника: ключи в сертификате не совпадают - неподтверждён и "ключ изменился" до принятия; после принятия подтверждён вручную', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const attacker = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        assert.strictEqual((await w.sync(b)).applied, 1);
        w.server.evil.impersonate(b.id, attacker.id);
        const result = await w.ensure(a);
        assert.deepStrictEqual(result.identityChanges.map(c => c.userId), [b.id]);
        assert.strictEqual(statusOf(result, b.id), 'unconfirmed');
        assert.ok(!(await w.stored(a, 'trusted:' + ROOM)).list.some(e => e.id === b.id), 'выпал из V (отзыв)');
        assert.strictEqual(result.rotated, true, 'выпавший получатель текущего ключа - ротация до рассылки');
        assert.strictEqual(result.rotationReason, 'membership-revoked');
        assert.deepStrictEqual(await a.client.trustMember(ROOM, b.id), { ok: false, reason: 'changed' });
        assert.strictEqual(await a.client.acceptPeerIdentityChange(b.id), true);
        const after = await a.client.getMembers(ROOM);
        const entry = after.find(m => m.id === b.id);
        assert.deepStrictEqual([entry.status, entry.how], ['confirmed', 'manual']);
    });

    // ===================== Скрытый сертификат =====================

    await test('сервер скрывает сертификат: участник неподтверждён и ключа не получает; сертификат появился - подтверждается', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, j);
        w.server.evil.hideCerts(j.id);
        let result = await w.ensure(a);
        assert.strictEqual(statusOf(result, j.id), 'unconfirmed');
        assert.ok(!w.server._keyShares.some(s => s.recipientId === j.id));
        w.server.evil.showCerts(j.id);
        result = await w.ensure(a);
        assert.strictEqual(statusOf(result, j.id), 'confirmed');
        assert.ok(w.server._keyShares.some(s => s.recipientId === j.id), 'теперь ключ отправлен');
    });

    await test('участник, за которого поручился подтверждённый (vouchForMember), подтверждается у остальных и получает ключ', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const g = await w.addUser(1010);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.ensure(b);
        w.server.addParticipant(ROOM, g.id, g.chatId);
        assert.strictEqual(statusOf(await w.ensure(a), g.id), 'unconfirmed');
        await w.ensure(b);
        assert.strictEqual((await b.client.trustMember(ROOM, g.id)).ok, true);
        assert.deepStrictEqual(await b.client.vouchForMember(b.chatId, ROOM, g.id), { ok: true, stored: true });
        const result = await w.ensure(a);
        const entry = result.members.find(m => m.id === g.id);
        assert.deepStrictEqual([entry.status, entry.how, entry.by], ['confirmed', 'vouched', b.id]);
        assert.ok(w.server._keyShares.some(s => s.recipientId === g.id));
    });

    // ===================== Повторный допуск (М6) =====================

    await test('уход одобрившего: оставшиеся ставят задачу, публикуют revouch с ref = certHash исходного допуска; how = revouched; ручного нет', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const c = await w.addUser(1003);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.approve(a, c);
        await w.ensure(a);
        await w.ensure(b);
        await w.ensure(c);
        const origForC = (await w.stored(b, 'trusted:' + ROOM)).list.find(e => e.id === c.id);
        assert.deepStrictEqual([origForC.how, origForC.by], ['vouched', a.id]);
        w.server.removeParticipant(ROOM, a.id);              // сервер удалил сертификаты Алисы
        const result = await w.ensure(b);
        const posts = w.server._certPosts.filter(p => p.actorId === b.id);
        assert.strictEqual(posts.length, 1, 'задача исполнена сразу: в комнате двое, ранг 0');
        const cert = M.parseCert(M.fromB64(posts[0].body.cert)).cert;
        assert.deepStrictEqual([cert.kind, cert.subjectId, cert.actorId], [M.KIND.revouch, c.id, b.id]);
        assert.strictEqual(M.toHex(cert.ref), origForC.certHash, 'ref - certHash исходного допуска (из записи V)');
        assert.strictEqual(M.toHex(cert.snapHash), '00'.repeat(32), 'у revouch снимка нет');
        const entry = (await w.stored(b, 'trusted:' + ROOM)).list.find(e => e.id === c.id);
        assert.deepStrictEqual([entry.how, entry.by], ['revouched', b.id]);
        assert.strictEqual(await w.stored(b, 'revouch:' + ROOM), null, 'очередь пуста');
        assert.deepStrictEqual(result.revouchPublished, [c.id]);
        // Алисы больше нет: у Кэрол запись про Боба ссылалась на Алису - она тоже публикует допуск Бобу.
        await w.ensure(c);
        const cPosts = w.server._certPosts.filter(p => p.actorId === c.id);
        assert.strictEqual(cPosts.length, 1);
        // Участник, подтверждённый вручную, автоматического допуска не получает.
        assert.strictEqual(statusOf(await w.ensure(b), c.id), 'confirmed');
        w.noViolations();
    });

    await test('очередь с задержкой по рангу: второй не подписывает, а видит допуск первого, снимает задачу и обновляет how/by/certHash (повторных задач нет)', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const members = [await w.addUser(1002), await w.addUser(1003), await w.addUser(1004)];
        await w.createRoom(a);
        for (const m of members) { await w.approve(a, m); await w.ensure(a); }
        for (const m of members) await w.ensure(m);
        w.server.removeParticipant(ROOM, a.id);
        // Для субъекта d (последний) ранг считается среди остальных двух; один из них - с рангом 0, другой - 1.
        const [m1, m2, d] = members;
        const sortKeys = [];
        for (const who of [m1, m2]) sortKeys.push({ who, rank: await M.revouchRank(d.id, a.id, who.id, [m1.id, m2.id, d.id]) });
        sortKeys.sort((p, q) => p.rank - q.rank);
        const [first, second] = sortKeys.map(x => x.who);
        assert.deepStrictEqual(sortKeys.map(x => x.rank), [0, 1]);
        // Первый подписывает сразу.
        await w.ensure(first);
        const dCerts = () => w.server._certPosts.filter(p => p.subjectId === d.id);
        assert.strictEqual(dCerts().length, 1);
        assert.strictEqual(dCerts()[0].actorId, first.id);
        // Второй: задача есть, срок через 2 минуты; допуск первого он видит при перечитывании - подписывать не надо.
        await w.ensure(second);
        const queue = await w.stored(second, 'revouch:' + ROOM);
        assert.ok(queue === null || queue.every(t => t.x !== d.id), 'допуск первого найден: задача снята');
        const entry = (await w.stored(second, 'trusted:' + ROOM)).list.find(e => e.id === d.id);
        assert.deepStrictEqual([entry.how, entry.by], ['revouched', first.id], 'how/by/certHash обновлены из найденного допуска');
        w.clock.advance(3 * MINUTE);
        await w.ensure(second);
        assert.strictEqual(dCerts().length, 1, 'второй допуск не опубликован');
    });

    await test('задача повторного допуска переживает перезагрузку и исполняется по сроку; ручное подтверждение задач не ставит', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const ms = [await w.addUser(1002), await w.addUser(1003), await w.addUser(1004)];
        const g = await w.addUser(1010);
        await w.createRoom(a);
        for (const m of ms) { await w.approve(a, m); await w.ensure(a); }
        for (const m of ms) await w.ensure(m);
        w.server.addParticipant(ROOM, g.id, g.chatId);
        await w.ensure(ms[2]);
        await ms[2].client.trustMember(ROOM, g.id);                   // вручную
        w.server.removeParticipant(ROOM, a.id);
        // Тот из первых двух, чей ранг для последнего ненулевой, оставляет задачу в очереди.
        const [m1, m2, d] = ms;
        const ranks = [];
        for (const who of [m1, m2]) ranks.push({ who, rank: await M.revouchRank(d.id, a.id, who.id, [m1.id, m2.id, d.id, g.id]) });
        ranks.sort((p, q) => p.rank - q.rank);
        let late = ranks[ranks.length - 1].who;
        assert.ok(ranks[ranks.length - 1].rank > 0);
        await w.ensure(late);
        let queue = await w.stored(late, 'revouch:' + ROOM);
        const task = queue.find(t => t.x === d.id);
        assert.ok(task && task.due > nowMin(w), 'срок исполнения в будущем');
        assert.ok(M.toHex(M.fromHex(task.orig)) === task.orig && task.orig.length === 64);
        late = w.reload(late);                                          // перезагрузка вкладки
        assert.ok((await w.stored(late, 'revouch:' + ROOM)).some(t => t.x === d.id), 'очередь пережила перезагрузку');
        w.clock.advance(20 * MINUTE);
        // Если допуск первым опубликовал другой - задача снимется; иначе опубликует сам. В обоих случаях задачи не остаётся.
        await w.ensure(late);
        queue = await w.stored(late, 'revouch:' + ROOM);
        assert.ok(queue === null || !queue.some(t => t.x === d.id));
        assert.ok(w.server._certPosts.filter(p => p.subjectId === d.id).length >= 1);
        // Ручной g без задач у подтвердившего его вручную: допуск ему не публикуется.
        assert.strictEqual(w.server._certPosts.filter(p => p.subjectId === g.id).length, 0);
    });

    // ===================== Ротация по журналу доставок (повторное ревью 1) =====================

    await test('получатель текущего ключа вышел: ротация member-left по журналу; ключ незнавшему (призраку) ротации не требует', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const c = await w.addUser(1003);
        const ghost = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b); await w.ensure(a);
        await w.approve(a, c); await w.ensure(a);
        w.server.evil.addGhost(ROOM, ghost.id, ghost.chatId);
        await w.ensure(a);
        const keyBefore = (await w.stored(a, 'senderKey:' + ROOM + ':' + a.id)).senderKeyId;
        const journal = await w.stored(a, 'delivered:' + ROOM + ':' + keyBefore);
        assert.deepStrictEqual(journal.map(p => p.id).sort(), [b.id, c.id], 'призрака в журнале нет: ключ ему не отправлялся');
        // Призрак ушёл - ключ ему не отправляли, ротация не нужна.
        w.server.removeParticipant(ROOM, ghost.id);
        let result = await w.ensure(a);
        assert.strictEqual(result.rotated, false);
        // Ушёл получатель - ротация.
        w.server.removeParticipant(ROOM, c.id);
        result = await w.ensure(a);
        assert.deepStrictEqual([result.rotated, result.rotationReason], [true, 'member-left']);
        const own = await w.stored(a, 'senderKey:' + ROOM + ':' + a.id);
        assert.notStrictEqual(own.senderKeyId, keyBefore);
        assert.deepStrictEqual(own.entitled, [b.id]);
        assert.strictEqual(await w.stored(a, 'delivered:' + ROOM + ':' + keyBefore), null, 'журнал прежнего ключа удалён вместе с ротацией');
        assert.strictEqual(w.server._keyShares.filter(sh => sh.recipientId === c.id).length, 1, 'ушедшему ушёл только первый ключ: нового у него нет');
        assert.strictEqual((await w.sync(b)).applied, 2, 'b получил оба ключа');
        w.noViolations();
    });

    await test('стирание отметок рассылки (запрос ключа, принятие нового ключа) ротацию не отключает; запрос от постороннего ничего не стирает', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const c = await w.addUser(1003);
        const outsider = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b); await w.ensure(a);
        await w.approve(a, c); await w.ensure(a);
        w.server.evil.addGhost(ROOM, outsider.id, outsider.chatId);
        await w.ensure(a);
        const keyId = (await w.stored(a, 'senderKey:' + ROOM + ':' + a.id)).senderKeyId;
        // Запрос ключа от постороннего (неподтверждённого): отметка не снимается, кулдаун не расходуется.
        const ignored = await a.client.answerKeyRequests(a.chatId, ROOM, [{ fromUserId: outsider.id, senderKeyIds: [keyId] }]);
        assert.deepStrictEqual(ignored, { resend: [] });
        assert.deepStrictEqual(await a.storage.keys('keyServed:'), []);
        // Запрос от получателя: отметка снимается (переотправка), журнал остаётся.
        const served = await a.client.answerKeyRequests(a.chatId, ROOM, [{ fromUserId: c.id, senderKeyIds: [keyId] }]);
        assert.deepStrictEqual(served, { resend: [c.id] });
        assert.strictEqual(await a.storage.get('sharedWith2:' + ROOM + ':' + keyId + ':' + c.id), null);
        assert.ok((await w.stored(a, 'delivered:' + ROOM + ':' + keyId)).some(p => p.id === c.id));
        // Теперь c уходит: отметок нет, а ротация происходит - решает журнал.
        w.server.removeParticipant(ROOM, c.id);
        const result = await w.ensure(a);
        assert.deepStrictEqual([result.rotated, result.rotationReason], [true, 'member-left']);
    });

    await test('запись в журнале делается до сетевого вызова: сбой отправки key-share пару не теряет; журнал только растёт без дублей', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const c = await w.addUser(1003);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);                                      // подтверждает b, ключ ушёл
        await w.approve(a, c);
        w.failShares.add(a.id);                                 // сеть обрывается на отправке
        const result = await w.ensure(a);
        assert.strictEqual(result.ok, false);
        const keyId = (await w.stored(a, 'senderKey:' + ROOM + ':' + a.id)).senderKeyId;
        const journal = await w.stored(a, 'delivered:' + ROOM + ':' + keyId);
        assert.deepStrictEqual(journal.map(p => p.id).sort(), [b.id, c.id], 'ключ c мог дойти - пара в журнале, хотя запрос не удался');
        assert.ok(!w.server._keyShares.some(sh => sh.recipientId === c.id));
        w.failShares.delete(a.id);
        await w.ensure(a);
        await w.ensure(a);
        assert.strictEqual((await w.stored(a, 'delivered:' + ROOM + ':' + keyId)).length, 2, 'повторные проходы не плодят записи');
    });

    await test('смена ключей получателя (тот же id, другой memkey) ротирует ключ, новый ключ он получает как получатель с новыми ключами', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const attacker = await w.addUser(1666);
        await w.createRoom(a);
        await w.approve(a, b); await w.ensure(a);
        const keyBefore = (await w.stored(a, 'senderKey:' + ROOM + ':' + a.id)).senderKeyId;
        w.server.evil.impersonate(b.id, attacker.id);
        let result = await w.ensure(a);
        assert.strictEqual(result.rotationReason, 'membership-revoked', 'changed выводит из V');
        assert.strictEqual(await a.client.acceptPeerIdentityChange(b.id), true);
        result = await w.ensure(a);
        const own = await w.stored(a, 'senderKey:' + ROOM + ':' + a.id);
        assert.notStrictEqual(own.senderKeyId, keyBefore);
        const newMemkey = (await w.stored(a, 'trusted:' + ROOM)).list.find(e => e.id === b.id).memkey;
        assert.strictEqual(own.entitledKeys[b.id], newMemkey ? own.entitledKeys[b.id] : null);
        assert.ok(w.server._keyShares.some(s => s.recipientId === b.id), 'принявший новый ключ участник снова получатель');
    });

    await test('entitled - пары recipients на момент создания ключа: подтверждённый позже читает ключ с текущей позиции, а не с начала эпохи', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        const d = await w.addUser(1004);
        await w.createRoom(a);
        await w.approve(a, b); await w.ensure(a);
        await w.sync(b);
        const early = await a.client.encryptOutgoing(ROOM, 'до подтверждения d', { messageId: '3100001' });
        // d появился (призрак), позже его подтверждают вручную.
        w.server.addParticipant(ROOM, d.id, d.chatId);
        await w.ensure(a);
        assert.ok(!w.server._keyShares.some(s => s.recipientId === d.id));
        assert.strictEqual((await a.client.trustMember(ROOM, d.id)).ok, true);
        await w.ensure(a);
        assert.strictEqual((await w.sync(d)).applied, 1);
        assert.strictEqual((await d.client.decryptIncoming(ROOM, a.id, early, '3100001')).ok, false, 'прошлое эпохи он не читает');
        const later = await a.client.encryptOutgoing(ROOM, 'после', { messageId: '3100002' });
        assert.strictEqual((await d.client.decryptIncoming(ROOM, a.id, later, '3100002')).text, 'после');
        const own = await w.stored(a, 'senderKey:' + ROOM + ':' + a.id);
        assert.ok(!own.entitled.includes(d.id));
        assert.strictEqual((await b.client.decryptIncoming(ROOM, a.id, early, '3100001')).text, 'до подтверждения d');
    });

    // ===================== ext и view =====================

    await test('ext: испорченное view и kt отбрасываются с предупреждением, SKDM принят; испорченный prev отвергает SKDM; предел 2048 символов', async () => {
        const { parseSkdmExt, MAX_EXT_CHARS } = E2EE._internal;
        assert.strictEqual(MAX_EXT_CHARS, 2048);
        const warnings = [];
        const saved = console.warn;
        console.warn = (...args) => warnings.push(args.join(' '));
        try {
            const good = { ids: b64(new Uint8Array(16).fill(1)), keys: b64(new Uint8Array(16).fill(2)) };
            assert.deepStrictEqual(parseSkdmExt({ view: good }), { view: good });
            assert.deepStrictEqual(parseSkdmExt({ view: { ids: 'xx', keys: good.keys } }), {});
            assert.deepStrictEqual(parseSkdmExt({ view: 5 }), {});
            assert.deepStrictEqual(parseSkdmExt({ view: { ids: good.ids } }), {});
            assert.deepStrictEqual(parseSkdmExt({ view: good, kt: 'мусор' }), { view: good });
            assert.ok(warnings.length >= 4, 'предупреждения в консоль');
            assert.strictEqual(parseSkdmExt({ prev: { id: 'x', final: 1 }, view: good }), null, 'испорченный prev отвергает SKDM целиком');
            // Слишком большой ext: справочные поля отбрасываются, остальное принимается.
            const prev = { id: b64(new Uint8Array(16)), final: 3 };
            assert.deepStrictEqual(parseSkdmExt({ prev, view: { ...good, pad: 'x'.repeat(3000) } }), { prev });
            assert.strictEqual(parseSkdmExt({ prev: { ...prev, pad: 'x'.repeat(3000) } }), null);
        } finally {
            console.warn = saved;
        }
    });

    await test('view: SKDM несёт хэш взгляда; у честных сторон ids и keys совпадают - тревоги нет', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.ensure(b);
        const result = await w.sync(b);
        assert.strictEqual(result.applied, 1);
        assert.strictEqual(result.viewMismatch, undefined);
        assert.strictEqual(result.viewIdsDiverged, undefined);
        assert.strictEqual(await w.stored(b, 'viewPending:' + ROOM), null, 'очередь разобрана вне блокировки');
        w.noViolations();
    });

    async function mine(w, user) {
        const ids = [...w.server._rooms.get(ROOM)].sort((p, q) => p - q);
        const entries = [];
        for (const id of ids) {
            const k = w.keysOf(id);
            entries.push({ id, memkey: await M.memkey(id, M.fromB64(k.signingKey), M.fromB64(k.dhKey)) });
        }
        return M.viewHash(entries);
    }

    await test('view: ключи расходятся при равных ids - тревога view-mismatch не чаще раза в сутки; при смене ключа (changed) подавляется', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.ensure(b);
        const view = await mine(w, b);
        const wrong = { ids: b64(view.ids), keys: b64(new Uint8Array(16).fill(9)) };
        await b.storage.set('viewPending:' + ROOM, [{ sender: a.id, view: wrong, at: w.clock.now() }]);
        let res = await b.client.runViewChecks(ROOM);
        assert.strictEqual(res.viewMismatch, true);
        assert.strictEqual(await w.stored(b, 'viewPending:' + ROOM), null);
        // Не чаще раза в сутки на пару.
        await b.storage.set('viewPending:' + ROOM, [{ sender: a.id, view: wrong, at: w.clock.now() }]);
        res = await b.client.runViewChecks(ROOM);
        assert.strictEqual(res.viewMismatch, false);
        w.clock.advance(DAY + MINUTE);
        await b.storage.set('viewPending:' + ROOM, [{ sender: a.id, view: wrong, at: w.clock.now() }]);
        assert.strictEqual((await b.client.runViewChecks(ROOM)).viewMismatch, true);
        // Смена ключа участника объясняет расхождение: тревога подавляется.
        const attacker = await w.addUser(1666);
        w.server.evil.impersonate(a.id, attacker.id);
        w.clock.advance(2 * DAY);
        await b.storage.set('viewPending:' + ROOM, [{ sender: a.id, view: wrong, at: w.clock.now() }]);
        assert.strictEqual((await b.client.runViewChecks(ROOM)).viewMismatch, false);
        w.noViolations();
    });

    await test('view: расхождение ids - сверка ключей пропускается; три подряд или сутки дают мягкое уведомление view-ids-diverged; равные ids сбрасывают счётчик', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const b = await w.addUser(1002);
        await w.createRoom(a);
        await w.approve(a, b);
        await w.ensure(a);
        await w.ensure(b);
        const view = await mine(w, b);
        const other = { ids: b64(new Uint8Array(16).fill(5)), keys: b64(view.keys) };
        const queue = () => b.storage.set('viewPending:' + ROOM, [{ sender: a.id, view: other, at: w.clock.now() }]);
        for (let i = 0; i < 2; i++) {
            await queue();
            const res = await b.client.runViewChecks(ROOM);
            assert.deepStrictEqual([res.viewIdsDiverged, res.viewMismatch], [false, false], 'проход ' + (i + 1));
        }
        assert.strictEqual((await w.stored(b, 'viewDiv:' + ROOM + ':' + a.id)).count, 2);
        // Равные ids: счётчик сбрасывается.
        await b.storage.set('viewPending:' + ROOM, [{ sender: a.id, view: { ids: b64(view.ids), keys: b64(view.keys) }, at: w.clock.now() }]);
        await b.client.runViewChecks(ROOM);
        assert.strictEqual(await w.stored(b, 'viewDiv:' + ROOM + ':' + a.id), null);
        for (let i = 0; i < 2; i++) { await queue(); await b.client.runViewChecks(ROOM); }
        await queue();
        assert.strictEqual((await b.client.runViewChecks(ROOM)).viewIdsDiverged, true, 'третий подряд');
        // Сутки: одно расхождение через 25 часов.
        await b.storage.delete('viewNotice:' + ROOM + ':' + a.id + ':ids');
        await b.storage.set('viewDiv:' + ROOM + ':' + a.id, { count: 1, since: w.clock.now() - 25 * 60 * MINUTE });
        await queue();
        assert.strictEqual((await b.client.runViewChecks(ROOM)).viewIdsDiverged, true);
    });

    await test('viewPending: одна запись на отправителя (новая заменяет прежнюю), не больше 100 на комнату', async () => {
        const storage = new E2EE.MemoryStorage();
        const mc = require('../public/lib/membership-client.js').createMembershipClient({
            storage, transport: {}, withLock: (fn) => fn(), now: () => 1000, getUserId: () => 1,
            loadIdentityLocked: async () => null, sign: null, logExcluded: () => false,
        });
        const view = (n) => ({ ids: b64(new Uint8Array(16).fill(n)), keys: b64(new Uint8Array(16).fill(n)) });
        await mc.noteViewLocked(ROOM, 5, view(1));
        await mc.noteViewLocked(ROOM, 5, view(2));
        let list = await storage.get('viewPending:' + ROOM);
        assert.strictEqual(list.length, 1);
        assert.deepStrictEqual(list[0].view, view(2), 'новая запись заменяет прежнюю');
        for (let sender = 10; sender < 150; sender++) await mc.noteViewLocked(ROOM, sender, view(3));
        list = await storage.get('viewPending:' + ROOM);
        assert.strictEqual(list.length, 100, 'лишние отбрасываются: сверка справочная');
    });

    // ===================== Приглашение и секрет =====================

    await test('inviteSecret: ссылка показывается, только если сертификат на сервере тот же; иначе секрет удаляется; invite: null и ответ сервера стирают его', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        await w.createRoom(a);
        const invite = await w.makeInvite(a);
        const stored = await w.stored(a, 'inviteSecret:' + ROOM);
        assert.deepStrictEqual(Object.keys(stored).sort(), ['certHash', 's']);
        assert.strictEqual(await a.client.getInviteSecret(ROOM, w.server.getInvite(ROOM).cert), invite.secret);
        // Приглашение повернул другой участник: хэш не тот - секрет удаляется.
        const other = await a.client.signInvite(ROOM, { ttlSeconds: 3600 });
        await a.client.signInvite(ROOM, { ttlSeconds: 3600 });
        assert.strictEqual(await a.client.getInviteSecret(ROOM, other.cert), null);
        assert.strictEqual(await w.stored(a, 'inviteSecret:' + ROOM), null);
        // Сервер ответил invite: null (поворот, выключение, выход автора) - секрет стирается при ensureRoomSession.
        await w.makeInvite(a);
        assert.ok(await w.stored(a, 'inviteSecret:' + ROOM));
        w.server.setInvite(ROOM, null);
        await w.ensure(a);
        assert.strictEqual(await w.stored(a, 'inviteSecret:' + ROOM), null);
    });

    await test('вход по ссылке: подменённый ключ приглашения, приглашение другой комнаты, просроченное, неверный регистр секрета; срок больше 720 часов не подписывается', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        const invite = await w.makeInvite(a);
        const cert = w.server.getInvite(ROOM).cert;
        const fail = async (opts, room = ROOM) => {
            try { await j.client.prepareJoin(room, opts); } catch (err) { return err.code; }
            return 'ok';
        };
        assert.strictEqual(await fail({ secret: invite.secret, inviteCert: cert }), 'ok');
        // Регистр значим: меняется регистр первой буквы (последний символ секрета несёт неполные биты, его не трогаем).
        const recased = invite.secret.replace(/[A-Za-z]/, ch => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()));
        assert.notStrictEqual(recased, invite.secret);
        assert.strictEqual(await fail({ secret: recased, inviteCert: cert }), 'secret-mismatch', 'секрет не нормализуется');
        const swapped = invite.secret[0] === 'A' ? 'B' + invite.secret.slice(1) : 'A' + invite.secret.slice(1);
        assert.strictEqual(await fail({ secret: swapped, inviteCert: cert }), 'secret-mismatch');
        assert.strictEqual(await fail({ secret: 'коротко', inviteCert: cert }), 'invalid-secret');
        assert.strictEqual(await fail({ secret: invite.secret, inviteCert: null }), 'no-invite');
        assert.strictEqual(await fail({ secret: invite.secret, inviteCert: cert }, ROOM + 1), 'invalid-invite', 'приглашение другой комнаты');
        const tampered = M.fromB64(cert); tampered[120] ^= 1;
        assert.strictEqual(await fail({ secret: invite.secret, inviteCert: b64(tampered) }), 'invalid-invite');
        await assert.rejects(a.client.signInvite(ROOM, { ttlSeconds: 721 * 3600 }), RangeError);
        await assert.rejects(a.client.signInvite(ROOM, { ttlSeconds: 30 }), RangeError);
        w.clock.advance(8 * DAY);
        assert.strictEqual(await fail({ secret: invite.secret, inviteCert: cert }), 'expired');
    });

    await test('секрет ссылки не уходит ни в одном исходящем запросе клиентов: в запросе только сертификат и снимок', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        const invite = await w.makeInvite(a);
        await w.joinByLink(j, invite);
        await w.ensure(j);
        await w.ensure(a);
        await w.sync(j);
        assert.ok(w.requests.length > 10);
        for (const r of w.requests) assert.ok(!r.args.includes(invite.secret), 'секрет встретился в запросе ' + r.name);
        const dump = JSON.stringify(await j.storage.keys(''));
        assert.ok(!dump.includes(invite.secret));
        assert.deepStrictEqual(await j.storage.keys('inviteSecret:'), [], 'у входящего секрета нет');
    });

    await test('completeJoin: повреждённый снимок приглашения отвергается; getMembers отражает статусы', async () => {
        const w = makeWorld();
        const a = await w.addUser(1001);
        const j = await w.addUser(1002);
        await w.createRoom(a);
        const invite = await w.makeInvite(a);
        const stored = w.server.getInvite(ROOM);
        await j.client.prepareJoin(ROOM, { secret: invite.secret, inviteCert: stored.cert });
        const bad = M.fromB64(stored.snap); bad[0] ^= 1;
        assert.deepStrictEqual(await j.client.completeJoin(ROOM, b64(bad)), { ok: false, reason: 'snap-bad' });
        assert.deepStrictEqual(await j.client.completeJoin(ROOM, stored.snap), { ok: true });
        assert.strictEqual((await w.stored(j, 'joinIntent:' + ROOM)).inviteSnap, stored.snap);
        w.server.admit(ROOM, j.id, j.chatId, { actorId: 0, kind: 3, cert: (await w.stored(j, 'joinIntent:' + ROOM)).joinCert, aux: stored.cert });
        await w.ensure(j);
        const members = await j.client.getMembers(ROOM);
        assert.deepStrictEqual(members.map(m => [m.id, m.status, m.how]), [[a.id, 'confirmed', 'invite'], [j.id, 'self', 'invite']]);
    });

    finish();
})().catch(err => { console.error(err); process.exitCode = 1; });
