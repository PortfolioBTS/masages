'use strict';
// Подписанный состав группы на настоящем сервере и Postgres (docs/security/signed-membership.md, разделы 7, 12, 13):
// одобрение и вход проверяются по сертификатам (cert-required, snap-required, bad-cert, bad-cert-time), заявка при
// коде без секрета, приглашение с проверкой срока по длительности, повтор ответа join, потолок допусков, транзакция
// member-certs и гонки с выходом, удаление строк при выходе и удалении аккаунта, поворот приглашения при выходе
// участника (вопрос 17), размеры тел и ответов, общий признак версии клиента proto.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const M = require('../../public/lib/membership.js');
const { createSuite } = require('./helpers/scenarios');
const Membership = require('./helpers/membership');

const suite = createSuite('signed-membership');

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const nowMin = () => Math.floor(Date.now() / 60000);
const randomNonce = () => new Uint8Array(crypto.randomBytes(16));

// Пользователь с identity, зарегистрированной помощником (ключи для подписи доступны в tc.identity).
async function makeUser(name) {
    const tc = suite.client({ name });
    await tc.registerAnon();
    await Membership.ensureIdentity(tc);
    return tc;
}

const memkeyOf = (tc) => M.memkey(Number(tc.user.id), tc.identity.signPub, tc.identity.dhPub);

// Снимок из заданного числа случайных memkey плюс подписавший.
async function snapshotOf(tc, extra = 0) {
    const list = [await memkeyOf(tc)];
    for (let i = 0; i < extra; i++) list.push(new Uint8Array(crypto.randomBytes(16)));
    return M.buildSnap(list);
}

// Допуск actor -> subject; tweak меняет поля до подписи, mutate - байты после (подпись тогда не сойдётся).
async function vouch(actor, subject, roomId, { issuedMin = nowMin(), snap, tweak = {}, kind = M.KIND.vouch, ref } = {}) {
    const s = snap || await snapshotOf(actor);
    const fields = {
        kind, roomId, issuedMin, nonce: randomNonce(), subjectId: Number(subject.user.id), subjectSignPub: subject.identity.signPub,
        subjectDhPub: subject.identity.dhPub, actorId: Number(actor.user.id), actorKey: actor.identity.signPub, ...tweak,
    };
    if (kind === M.KIND.vouch) { fields.snapN = s.n; fields.snapHash = s.hash; } else { fields.ref = ref || new Uint8Array(crypto.randomBytes(32)); }
    const raw = await M.signCert(fields, { sig: actor.identity.sign });
    return { cert: b64(raw), snap: kind === M.KIND.vouch ? b64(s.snap) : undefined, raw };
}

async function room(owner, name = 'Группа') {
    const chat = await owner.createRoom(name);
    return { chat, roomId: Number(chat.room_id) };
}

// Заявка гостя в комнату владельца.
async function request(owner, guest, chat) {
    const { code } = await owner.invite(chat.id);
    const pending = await guest.join(code);
    assert.strictEqual(pending.pending, true);
    return { code, requestId: pending.requestId };
}

const certRows = (roomId) => suite.query('SELECT subject_id, actor_id, kind, octet_length(cert) AS len, aux IS NOT NULL AS has_aux, snap IS NOT NULL AS has_snap FROM room_member_certs WHERE room_id = $1 ORDER BY subject_id, kind, actor_id', [roomId]).then(r => r.rows);
const roomRow = (roomId) => suite.query('SELECT code, invite_cert IS NOT NULL AS signed, invite_snap IS NOT NULL AS has_snap, invite_actor_id, invite_require_approval FROM rooms WHERE id = $1', [roomId]).then(r => r.rows[0]);

// ===================== approve =====================

test('approve: без сертификата - cert-required, без снимка - snap-required; верный допуск сохраняется вместе со снимком', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const { chat, roomId } = await room(owner);
    const { requestId } = await request(owner, guest, chat);
    const post = (body) => owner.post(`/api/join-requests/${requestId}/approve`, body);
    let res = await post({});
    assert.deepStrictEqual([res.status, res.body.code], [400, 'cert-required']);
    const good = await vouch(owner, guest, roomId);
    res = await post({ cert: good.cert });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'snap-required']);
    assert.deepStrictEqual(await certRows(roomId), [], 'отказы ничего не пишут');
    res = await post({ cert: good.cert, snap: good.snap });
    assert.strictEqual(res.body.success, true);
    assert.deepStrictEqual(await certRows(roomId), [{ subject_id: guest.user.id, actor_id: owner.user.id, kind: 1, len: 271, has_aux: false, has_snap: true }]);
    assert.ok((await guest.chats()).some(c => c.room_id === roomId), 'заявитель вошёл вместе с сертификатом - одной транзакцией');
});

test('approve: сертификат не от сессии, не для заявителя, чужие ключи, чужая комната, время вне окна, неверный snapHash - отказ без побочных записей', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const third = await makeUser('третий');
    const { chat, roomId } = await room(owner);
    const { requestId } = await request(owner, guest, chat);
    const post = (body) => owner.post(`/api/join-requests/${requestId}/approve`, body);
    const bad = async (item, code, what) => {
        const res = await post({ cert: item.cert, snap: item.snap });
        assert.deepStrictEqual([res.status, res.body.code], [400, code], what);
        assert.deepStrictEqual(await certRows(roomId), [], what + ': ничего не записано');
        assert.ok(!(await guest.chats()).some(c => c.room_id === roomId), what + ': заявитель не вошёл');
    };
    await bad(await vouch(third, guest, roomId), 'bad-cert', 'подписан не сессией');
    await bad(await vouch(owner, third, roomId), 'bad-cert', 'выдан другому');
    await bad(await vouch(owner, guest, roomId, { tweak: { subjectDhPub: new Uint8Array(32).fill(7) } }), 'bad-cert', 'чужие ключи заявителя');
    await bad(await vouch(owner, guest, roomId + 1), 'bad-cert', 'другая комната');
    await bad(await vouch(owner, guest, roomId, { issuedMin: nowMin() + 11 }), 'bad-cert-time', 'из будущего');
    await bad(await vouch(owner, guest, roomId, { issuedMin: nowMin() - 11 }), 'bad-cert-time', 'из прошлого');
    const wrongSnap = await vouch(owner, guest, roomId);
    await bad({ cert: wrongSnap.cert, snap: b64(new Uint8Array(32).fill(1)) }, 'bad-cert', 'snapHash не сошёлся');
    const flipped = M.fromB64(wrongSnap.cert); flipped[230] ^= 1;
    await bad({ cert: b64(flipped), snap: wrongSnap.snap }, 'bad-cert', 'подпись');
    // Границы окна принимаются.
    const edge = await vouch(owner, guest, roomId, { issuedMin: nowMin() - 9 });
    const ok = await post({ cert: edge.cert, snap: edge.snap });
    assert.strictEqual(ok.body.success, true);
});

test('approve: заявитель без ключей - 409 applicant-no-keys; без proto - client-outdated', async () => {
    const owner = await makeUser('владелец');
    const guest = suite.client({ name: 'без ключей' });
    await guest.registerAnon();
    const { chat } = await room(owner);
    const { code } = await owner.invite(chat.id);
    const pending = await guest.post('/api/chats/join', { code });   // сырой запрос: помощник завёл бы заявителю ключи
    assert.strictEqual(pending.body.pending, true);
    const res = await owner.post(`/api/join-requests/${pending.body.requestId}/approve`, {});
    assert.deepStrictEqual([res.status, res.body.code], [409, 'applicant-no-keys']);
    const outdated = await owner.post(`/api/join-requests/${pending.body.requestId}/approve`, { proto: undefined });
    assert.deepStrictEqual([outdated.status, outdated.body.code], [400, 'client-outdated']);
});

test('approve против выхода подписавшего: таблица не содержит допусков с несуществующим подписавшим (в обоих порядках)', async () => {
    const owner = await makeUser('владелец');
    const { chat, roomId } = await room(owner);
    for (let i = 0; i < 6; i++) {
        const signer = await makeUser('подписавший' + i);
        const guest = await makeUser('гость' + i);
        const { code } = await owner.invite(chat.id);
        // Подписавшего впускает владелец, затем гость подаёт заявку, а подписавший одобряет её параллельно со своим выходом.
        const sp = await signer.join(code);
        await owner.approve(sp.requestId);
        const signerChat = (await signer.chats()).find(c => c.room_id === roomId);
        const gp = await guest.join(code);
        const cert = await vouch(signer, guest, roomId);
        const approve = signer.post(`/api/join-requests/${gp.requestId}/approve`, { cert: cert.cert, snap: cert.snap });
        const leave = signer.del(`/api/chats/${signerChat.id}`);
        if (i % 2) { await Promise.all([leave, approve]); } else { await Promise.all([approve, leave]); }
        const stale = await suite.query(
            `SELECT c.subject_id, c.actor_id FROM room_member_certs c WHERE c.room_id = $1
               AND (NOT EXISTS (SELECT 1 FROM room_participants p WHERE p.room_id = c.room_id AND p.user_id = c.subject_id)
                 OR (c.actor_id <> 0 AND NOT EXISTS (SELECT 1 FROM room_participants p WHERE p.room_id = c.room_id AND p.user_id = c.actor_id)))`,
            [roomId]
        );
        assert.deepStrictEqual(stale.rows, [], 'итерация ' + i);
    }
});

// ===================== invite/rotate, join =====================

async function signedInvite(owner, roomId, { ttlSeconds = 604800, issuedMin = nowMin(), expiresMin, snap } = {}) {
    const secret = new Uint8Array(crypto.randomBytes(16));
    const key = await M.inviteKeyFromSecret(secret);
    const s = snap || await snapshotOf(owner);
    const raw = await M.signCert({
        kind: M.KIND.invite, roomId, issuedMin, nonce: randomNonce(), actorId: Number(owner.user.id), actorKey: owner.identity.signPub,
        ref: key.invitePub, expiresMin: expiresMin === undefined ? issuedMin + ttlSeconds / 60 : expiresMin, snapN: s.n, snapHash: s.hash,
    }, { sig: owner.identity.sign, sig2: key.sign });
    return { cert: b64(raw), snap: b64(s.snap), secret, key, raw, issuedMin };
}

const rotate = (owner, chat, body) => owner.post(`/api/chats/${chat.id}/invite/rotate`, body);

test('rotate: без одобрения нужны сертификат и снимок; срок сверяется по длительности (часы +-3, +-9 минут допустимы), не абсолютное время', async () => {
    const owner = await makeUser('владелец');
    const { chat, roomId } = await room(owner);
    let res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'cert-required']);
    const inv = await signedInvite(owner, roomId);
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: inv.cert });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'snap-required']);
    res = await rotate(owner, chat, { requireApproval: false, inviteCert: inv.cert, inviteSnap: inv.snap });
    assert.strictEqual(res.status, 400, 'срок обязателен для подписанного приглашения');
    for (const shift of [-9, -3, 3, 9, 0]) {
        const shifted = await signedInvite(owner, roomId, { issuedMin: nowMin() + shift });
        res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: shifted.cert, inviteSnap: shifted.snap });
        assert.strictEqual(res.body.success, true, 'часы клиента сдвинуты на ' + shift);
    }
    const tooFar = await signedInvite(owner, roomId, { issuedMin: nowMin() + 11 });
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: tooFar.cert, inviteSnap: tooFar.snap });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'bad-cert-time']);
    const longer = await signedInvite(owner, roomId, { expiresMin: nowMin() + 10080 + 2 });
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: longer.cert, inviteSnap: longer.snap });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'bad-cert'], 'длительность отличается на 2 минуты');
    const within = await signedInvite(owner, roomId, { expiresMin: nowMin() + 10080 + 1 });
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: within.cert, inviteSnap: within.snap });
    assert.strictEqual(res.body.success, true, 'допуск +-1 минута');
    // Срок больше 720 часов не выбрать вовсе; 30 суток (720 часов) - предел.
    res = await rotate(owner, chat, { ttlSeconds: 2592001, requireApproval: false, inviteCert: inv.cert, inviteSnap: inv.snap });
    assert.strictEqual(res.body.success, false);
    const month = await signedInvite(owner, roomId, { ttlSeconds: 2592000 });
    res = await rotate(owner, chat, { ttlSeconds: 2592000, requireApproval: false, inviteCert: month.cert, inviteSnap: month.snap });
    assert.strictEqual(res.body.success, true);
    // Чужой автор и чужие ключи в приглашении.
    const other = await makeUser('чужой');
    const foreign = await signedInvite(other, roomId);
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: foreign.cert, inviteSnap: foreign.snap });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'bad-cert']);
    // С одобрением сертификата нет: invite_* обнуляются.
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: true });
    assert.strictEqual(res.body.success, true);
    assert.deepStrictEqual(await roomRow(roomId).then(r => [r.signed, r.has_snap, r.invite_actor_id]), [false, false, null]);
    // Без proto - client-outdated.
    res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: true, proto: undefined });
    assert.deepStrictEqual([res.status, res.body.code], [400, 'client-outdated']);
});

test('join: без joinCert - заявка даже при requireApproval=false; с joinCert - вход и inviteSnap; повтор того же joinCert; поворот - 409; в комнату с одобрением - заявка', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const second = await makeUser('второй');
    const { chat, roomId } = await room(owner);
    const rotated = await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
    assert.strictEqual((await roomRow(roomId)).signed, true);
    // Предпросмотр по коду: сертификат приглашения есть, снимка нет.
    const preview = await guest.joinPreview(rotated.code);
    assert.ok(preview.inviteCert);
    assert.strictEqual(preview.roomId, roomId);
    assert.ok(!('inviteSnap' in preview) && !('snap' in preview));
    // Код без секрета - заявка.
    const asRequest = await guest.joinRaw(rotated.code, { secret: null });
    assert.deepStrictEqual([asRequest.body.success, asRequest.body.pending], [true, true]);
    await guest.del(`/api/join-requests/${asRequest.body.requestId}`);
    // Ссылка с секретом - вход сразу, в ответе снимок приглашения.
    const joined = await guest.joinRaw(rotated.code);
    assert.strictEqual(joined.body.success, true);
    assert.ok(joined.body.inviteSnap, 'inviteSnap получает владелец join-сертификата');
    assert.strictEqual(joined.body.inviteSnap, b64((await suite.query('SELECT invite_snap FROM rooms WHERE id = $1', [roomId])).rows[0].invite_snap));
    const rows = await certRows(roomId);
    assert.deepStrictEqual(rows.map(r => [r.subject_id, r.actor_id, r.kind, r.len, r.has_aux]), [[guest.user.id, 0, 3, 335, true]]);
    // Повтор тем же joinCert от уже вошедшего: тот же ответ.
    const joinCert = (await suite.query('SELECT cert FROM room_member_certs WHERE room_id = $1 AND kind = 3', [roomId])).rows[0].cert;
    const again = await guest.post('/api/chats/join', { code: rotated.code, joinCert: b64(joinCert) });
    assert.strictEqual(again.body.success, true);
    assert.strictEqual(again.body.inviteSnap, joined.body.inviteSnap);
    // Чужой joinCert от другого вошедшего - 409, а после поворота приглашения и свой - 409.
    const code2 = await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
    const stale = await guest.post('/api/chats/join', { code: code2.code, joinCert: b64(joinCert) });
    assert.deepStrictEqual([stale.status, stale.body.code], [409, 'already-member']);
    // Ссылка в комнату с одобрением: заявка, секрет игнорируется.
    await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: true });
    const approvalCode = (await owner.invite(chat.id)).code;
    const withCert = await second.post('/api/chats/join', { code: approvalCode, joinCert: b64(joinCert) });
    assert.deepStrictEqual([withCert.body.success, withCert.body.pending], [true, true]);
});

test('join: неверная подпись, ref, чужой субъект, чужие ключи, чужая комната, время - bad-cert / bad-cert-time; join на границе I.issuedMin - 10 принимается', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const intruder = await makeUser('чужой');
    const { chat, roomId } = await room(owner);
    // Приглашение с часами владельца, убежавшими на +9 минут: нижняя граница join = nowMin - 1.
    const inv = await signedInvite(owner, roomId, { issuedMin: nowMin() + 9 });
    let res = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: inv.cert, inviteSnap: inv.snap });
    assert.strictEqual(res.body.success, true);
    const code = res.body.code;
    const build = async (subject, { issuedMin = nowMin(), tweak = {}, sign2 = subject.identity.sign, invite = inv } = {}) => M.signCert({
        kind: M.KIND.join, roomId, issuedMin, nonce: randomNonce(), subjectId: Number(subject.user.id), subjectSignPub: subject.identity.signPub,
        subjectDhPub: subject.identity.dhPub, actorId: 0, actorKey: invite.key.invitePub, ref: await M.certHash(invite.raw), ...tweak,
    }, { sig: invite.key.sign, sig2: sign2 });
    const attempt = async (raw) => guest.post('/api/chats/join', { code, joinCert: b64(raw) });
    const expectBad = async (raw, expected, what) => {
        const r = await attempt(raw);
        assert.deepStrictEqual([r.status, r.body.code], [400, expected], what);
        assert.deepStrictEqual(await certRows(roomId), [], what + ': сертификат не записан');
        assert.ok(!(await guest.chats()).some(c => c.room_id === roomId), what + ': не вошёл');
    };
    await expectBad(await build(intruder), 'bad-cert', 'выдан другому субъекту');
    await expectBad(await build(guest, { tweak: { subjectDhPub: new Uint8Array(32).fill(3) } }), 'bad-cert', 'чужие ключи');
    await expectBad(await build(guest, { tweak: { roomId: roomId + 1 } }), 'bad-cert', 'чужая комната');
    await expectBad(await build(guest, { tweak: { ref: new Uint8Array(32).fill(8) } }), 'bad-cert', 'ref другого приглашения');
    await expectBad(await build(guest, { sign2: intruder.identity.sign }), 'bad-cert', 'sig2 не ключом субъекта');
    const wrongKey = await M.inviteKeyFromSecret(new Uint8Array(16).fill(5));
    await expectBad(await M.signCert({
        kind: M.KIND.join, roomId, issuedMin: nowMin(), nonce: randomNonce(), subjectId: Number(guest.user.id), subjectSignPub: guest.identity.signPub,
        subjectDhPub: guest.identity.dhPub, actorId: 0, actorKey: wrongKey.invitePub, ref: await M.certHash(inv.raw),
    }, { sig: wrongKey.sign, sig2: guest.identity.sign }), 'bad-cert', 'не ключ приглашения');
    await expectBad(await build(guest, { issuedMin: inv.issuedMin - 11 }), 'bad-cert-time', 'раньше I.issuedMin - SKEW');
    await expectBad(await build(guest, { issuedMin: nowMin() + 11 }), 'bad-cert-time', 'вне окна сервера');
    const boundary = await attempt(await build(guest, { issuedMin: inv.issuedMin - 10 }));
    assert.strictEqual(boundary.body.success, true, 'граница I.issuedMin - 10 принимается');
});

test('гонка "поворот приглашения + join": join по уже повёрнутому сертификату не проходит, строка join без приглашения не остаётся', async () => {
    const owner = await makeUser('владелец');
    const { chat, roomId } = await room(owner);
    for (let i = 0; i < 5; i++) {
        const guest = await makeUser('гость' + i);
        const first = await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
        const joinCert = await (async () => {
            const preview = await guest.joinPreview(first.code);
            return Membership.joinCertFor(guest, roomId, preview.inviteCert, first.secret);
        })();
        const turn = owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
        const entry = guest.post('/api/chats/join', { code: first.code, joinCert });
        const [, res] = await Promise.all([turn, entry]);
        const member = (await guest.chats()).some(c => c.room_id === roomId);
        if (res.body.success) {
            assert.ok(member);
            assert.strictEqual((await certRows(roomId)).filter(r => r.subject_id === guest.user.id && r.kind === 3).length, 1);
        } else {
            assert.ok(!member, 'отказ: комнаты у гостя нет');
            assert.strictEqual((await certRows(roomId)).filter(r => r.subject_id === guest.user.id).length, 0, 'сертификата без вступления нет');
        }
    }
});

test('disable и rotate обнуляют invite_*; сохранённые join остаются (у них копия приглашения в aux)', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const { chat, roomId } = await room(owner);
    const inv = await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
    await guest.join(inv.code);
    assert.strictEqual((await roomRow(roomId)).signed, true);
    const res = await owner.post(`/api/chats/${chat.id}/invite/disable`, {});
    assert.strictEqual(res.body.success, true);
    assert.deepStrictEqual(await roomRow(roomId).then(r => [r.signed, r.has_snap, r.invite_actor_id]), [false, false, null]);
    const rows = await certRows(roomId);
    assert.deepStrictEqual(rows.map(r => [r.kind, r.has_aux]), [[3, true]], 'join остаётся с копией приглашения');
    const outdated = await owner.post(`/api/chats/${chat.id}/invite/disable`, { proto: undefined });
    assert.deepStrictEqual([outdated.status, outdated.body.code], [400, 'client-outdated']);
});

// ===================== member-certs =====================

test('member-certs: допуск и повторный допуск; не больше 4 на субъекта; субъект или подписавший вне комнаты - 404 и пустая таблица', async () => {
    const owner = await makeUser('владелец');
    const members = [];
    const { chat, roomId } = await room(owner);
    for (let i = 0; i < 3; i++) {
        const m = await makeUser('участник' + i);
        const { requestId } = await request(owner, m, chat);
        await owner.approve(requestId);
        members.push(m);
    }
    const subject = members[2];
    const [a, b] = [owner, members[0]];   // у субъекта уже есть допуск владельца (его одобрение): ещё три места
    const chatOf = async (tc) => (await tc.chats()).find(c => c.room_id === roomId).id;
    const post = async (actor, kindArgs) => {
        const item = await vouch(actor, subject, roomId, kindArgs);
        return actor.post(`/api/chats/${await chatOf(actor)}/member-certs`, { subjectId: subject.user.id, cert: item.cert, snap: item.snap });
    };
    assert.deepStrictEqual((await post(a, {})).body, { success: true, stored: false }, 'дубль той же пары: допуск владельца при одобрении уже есть');
    assert.deepStrictEqual((await post(b, {})).body, { success: true, stored: true });
    assert.deepStrictEqual((await post(b, { kind: M.KIND.revouch })).body, { success: true, stored: true });
    assert.deepStrictEqual((await post(members[1], {})).body, { success: true, stored: true });
    assert.deepStrictEqual((await post(members[1], { kind: M.KIND.revouch })).body, { success: true, stored: false }, 'пятый допуск отвергается без ошибки');
    assert.deepStrictEqual((await post(b, {})).body, { success: true, stored: false }, 'дубль той же пары');
    assert.strictEqual((await certRows(roomId)).filter(r => r.subject_id === subject.user.id && [1, 4].includes(r.kind)).length, 4);
    // Субъект вне комнаты.
    const outsider = await makeUser('посторонний');
    const forged = await vouch(owner, outsider, roomId);
    const gone = await owner.post(`/api/chats/${await chatOf(owner)}/member-certs`, { subjectId: outsider.user.id, cert: forged.cert, snap: forged.snap });
    assert.deepStrictEqual([gone.status, gone.body.code], [404, 'not-participant']);
    assert.strictEqual((await certRows(roomId)).filter(r => r.subject_id === outsider.user.id).length, 0);
    // Без proto.
    const outdated = await owner.post(`/api/chats/${await chatOf(owner)}/member-certs`, { subjectId: subject.user.id, cert: forged.cert, proto: undefined });
    assert.deepStrictEqual([outdated.status, outdated.body.code], [400, 'client-outdated']);
});

test('гонка "выход + member-certs": в обоих порядках не остаётся строк о ушедшем (субъекте и подписавшем)', async () => {
    const owner = await makeUser('владелец');
    const { chat, roomId } = await room(owner);
    const chatOfUser = async (tc) => (await tc.chats()).find(c => c.room_id === roomId);
    for (let i = 0; i < 6; i++) {
        const subject = await makeUser('субъект' + i);
        const { requestId } = await request(owner, subject, chat);
        await owner.approve(requestId);
        const subjectChat = await chatOfUser(subject);
        const item = await vouch(owner, subject, roomId);
        const post = owner.post(`/api/chats/${chat.id}/member-certs`, { subjectId: subject.user.id, cert: item.cert, snap: item.snap });
        const leave = subject.del(`/api/chats/${subjectChat.id}`);
        if (i % 2) await Promise.all([leave, post]); else await Promise.all([post, leave]);
        const stale = (await certRows(roomId)).filter(r => r.subject_id === subject.user.id);
        assert.deepStrictEqual(stale, [], 'итерация ' + i + ': строки ушедшего субъекта удалены');
    }
    // Подписавший уходит параллельно с публикацией.
    for (let i = 0; i < 4; i++) {
        const actor = await makeUser('подписавший' + i);
        const subject = await makeUser('цель' + i);
        for (const u of [actor, subject]) await owner.approve((await request(owner, u, chat)).requestId);
        const actorChat = await chatOfUser(actor);
        const item = await vouch(actor, subject, roomId);
        const post = actor.post(`/api/chats/${actorChat.id}/member-certs`, { subjectId: subject.user.id, cert: item.cert, snap: item.snap });
        const leave = actor.del(`/api/chats/${actorChat.id}`);
        if (i % 2) await Promise.all([leave, post]); else await Promise.all([post, leave]);
        assert.deepStrictEqual((await certRows(roomId)).filter(r => r.actor_id === actor.user.id), [], 'итерация ' + i + ': строк подписавшего нет');
    }
});

// ===================== Выход, удаление аккаунта, комната =====================

test('выход участника: сертификаты (субъект и подписавший) удалены, приглашение обнулено, код новый, событие inviteRotated; код принимает только заявки', async () => {
    const owner = await makeUser('владелец');
    const first = await makeUser('первый');
    const second = await makeUser('второй');
    const { chat, roomId } = await room(owner);
    const ownerSock = await owner.socket();
    try {
        const inv = await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
        await first.join(inv.code);
        await second.join(inv.code);
        assert.strictEqual((await certRows(roomId)).length, 2);
        const before = await roomRow(roomId);
        assert.strictEqual(before.signed, true);
        const mark = ownerSock.mark();
        const firstChat = (await first.chats()).find(c => c.room_id === roomId);
        await first.leave(firstChat.id);
        const event = await ownerSock.waitFor('roomMembersChanged', p => p.roomId === roomId && p.inviteRotated === true, { since: mark });
        assert.strictEqual(event.inviteRotated, true);
        const after = await roomRow(roomId);
        assert.deepStrictEqual([after.signed, after.has_snap, after.invite_actor_id], [false, false, null]);
        assert.notStrictEqual(after.code, before.code, 'новый код: старый перестал действовать');
        assert.deepStrictEqual((await certRows(roomId)).map(r => r.subject_id), [second.user.id], 'строки вышедшего удалены, чужие остались');
        // Старый код и старая ссылка не работают; новый код принимает только заявки, даже с joinCert.
        const stale = await owner.post('/api/chats/join/preview', { code: inv.code });
        assert.strictEqual(stale.body.success, false);
        const newCode = (await owner.invite(chat.id)).code;
        assert.notStrictEqual(newCode, inv.code);
        const newcomer = await makeUser('новый');
        const attempt = await newcomer.joinRaw(newCode);
        assert.deepStrictEqual([attempt.body.success, attempt.body.pending], [true, true]);
    } finally {
        await ownerSock.close();
    }
});

test('удаление аккаунта: строки сертификатов в обе стороны удалены, приглашение обнулено; удаление комнаты каскадом', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const { chat, roomId } = await room(owner);
    const { requestId } = await request(owner, guest, chat);
    await owner.approve(requestId);
    const inv = await owner.rotateInvite(chat.id, { ttlSeconds: 604800, requireApproval: false });
    assert.strictEqual((await certRows(roomId)).length, 1);
    await guest.deleteAccount();
    assert.deepStrictEqual(await certRows(roomId), [], 'гость был субъектом - строка удалена');
    const after = await roomRow(roomId);
    assert.strictEqual(after.signed, false, 'вышел любой участник - приглашение обнулено');
    assert.notStrictEqual(after.code, inv.code);
    // Подписавший удаляет аккаунт: допуск, который он выдал, исчезает.
    const second = await makeUser('второй');
    const third = await makeUser('третий');
    const r2 = await request(owner, second, chat);
    await owner.approve(r2.requestId);
    const r3 = await request(owner, third, chat);
    const secondChat = (await second.chats()).find(c => c.room_id === roomId);
    const item = await vouch(second, third, roomId);
    await second.post(`/api/join-requests/${r3.requestId}/approve`, { cert: item.cert, snap: item.snap });
    assert.ok((await certRows(roomId)).some(r => r.actor_id === second.user.id));
    await second.deleteAccount();
    assert.ok(!(await certRows(roomId)).some(r => r.actor_id === second.user.id || r.subject_id === second.user.id));
    assert.ok(secondChat);
    // Комната удаляется целиком (последний вышел): строки уходят каскадом.
    await third.leave((await third.chats()).find(c => c.room_id === roomId).id);
    await owner.leave(chat.id);
    assert.deepStrictEqual((await suite.query('SELECT count(*)::int AS n FROM room_member_certs WHERE room_id = $1', [roomId])).rows[0], { n: 0 });
});

test('параллельные одобрения и выход подписавшего: без взаимных блокировок (40P01) в ответах', async () => {
    const owner = await makeUser('владелец');
    const { chat, roomId } = await room(owner);
    const signer = await makeUser('подписавший');
    await owner.approve((await request(owner, signer, chat)).requestId);
    const guests = [];
    for (let i = 0; i < 5; i++) guests.push(await makeUser('гость' + i));
    const requests = [];
    for (const g of guests) requests.push(await request(owner, g, chat));
    const calls = [];
    for (let i = 0; i < guests.length; i++) {
        const item = await vouch(i % 2 ? signer : owner, guests[i], roomId);
        calls.push((i % 2 ? signer : owner).post(`/api/join-requests/${requests[i].requestId}/approve`, { cert: item.cert, snap: item.snap }));
    }
    calls.push(signer.del(`/api/chats/${(await signer.chats()).find(c => c.room_id === roomId).id}`));
    const results = await Promise.all(calls);
    for (const res of results) assert.notStrictEqual(res.status, 503, JSON.stringify(res.body));
    for (const res of results) assert.ok(res.body.code !== 'busy');
});

// ===================== Размеры =====================

test('размеры: approve, rotate и member-certs принимают снимок на 1000 и 1024 участников, больше 32 КБ - 413; participants без чужих сертификатов; member-certs до 200 id', async () => {
    const owner = await makeUser('владелец');
    const guest = await makeUser('гость');
    const guest2 = await makeUser('гость2');
    const { chat, roomId } = await room(owner);
    for (const [index, size] of [[0, 999], [1, 1023]]) {
        const target = [guest, guest2][index];
        const { requestId } = await request(owner, target, chat);
        const snap = await snapshotOf(owner, size);
        assert.strictEqual(snap.n, size + 1);
        const item = await vouch(owner, target, roomId, { snap });
        const res = await owner.post(`/api/join-requests/${requestId}/approve`, { cert: item.cert, snap: item.snap });
        assert.strictEqual(res.body.success, true, `approve со снимком на ${size + 1}`);
        const inv = await signedInvite(owner, roomId, { snap });
        const rot = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: false, inviteCert: inv.cert, inviteSnap: inv.snap });
        assert.strictEqual(rot.body.success, true, `rotate со снимком на ${size + 1}`);
        const certPost = await vouch(owner, target, roomId, { snap });
        const post = await owner.post(`/api/chats/${chat.id}/member-certs`, { subjectId: target.user.id, cert: certPost.cert, snap: certPost.snap });
        assert.strictEqual(post.body.success, true, `member-certs со снимком на ${size + 1}`);
    }
    const huge = await vouch(owner, guest, roomId);
    const tooBig = await owner.post(`/api/chats/${chat.id}/member-certs`, { subjectId: guest.user.id, cert: huge.cert, snap: huge.snap, pad: 'x'.repeat(33 * 1024) });
    assert.strictEqual(tooBig.status, 413);
    const tooBigRotate = await rotate(owner, chat, { ttlSeconds: 604800, requireApproval: true, pad: 'x'.repeat(33 * 1024) });
    assert.strictEqual(tooBigRotate.status, 413);
    // participants: только сертификаты самого запрашивающего, снимки к ним и приглашение.
    const asGuest = await guest.get(`/api/chats/${(await guest.chats()).find(c => c.room_id === roomId).id}/participants`);
    assert.ok(asGuest.body.certs.every(c => c.subjectId === guest.user.id));
    assert.ok(asGuest.body.certs.length >= 1 && asGuest.body.snaps.length >= 1);
    assert.ok(typeof asGuest.body.invite === 'string');
    assert.ok(JSON.stringify(asGuest.body).length < 100 * 1024, 'ответ participants - десятки килобайт, а не мегабайты');
    // member-certs: до 200 id; на 200 субъектов с четырьмя допусками и join - не больше ~0,5 МБ; снимков нет.
    const ids = [];
    const aux = Buffer.alloc(335, 7);
    for (let i = 0; i < 200; i++) {
        const subjectId = 900000000 + i;
        ids.push(subjectId);
        for (let k = 0; k < 4; k++) {
            await suite.query('INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, snap) VALUES ($1, $2, $3, $4, $5, $6)',
                [roomId, subjectId, 800000000 + k, k % 2 ? 4 : 1, Buffer.alloc(271, k + 1), k % 2 ? null : Buffer.alloc(16, 1)]);
        }
        await suite.query('INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, aux) VALUES ($1, $2, 0, 3, $3, $4)',
            [roomId, subjectId, Buffer.alloc(335, 9), aux]);
    }
    const chatId = (await owner.chats()).find(c => c.room_id === roomId).id;
    const big = await owner.get(`/api/chats/${chatId}/member-certs?subjects=${ids.join(',')}`);
    assert.strictEqual(big.body.success, true);
    assert.strictEqual(big.body.certs.length, 200 * 5);
    // Документ оценивает ответ в 0,47 МБ (сырые байты в base64); с именами полей JSON выходит около 0,53 МБ - порядок тот же.
    assert.ok(big.text.length <= 560 * 1024, 'ответ ' + big.text.length);
    assert.ok(big.body.certs.every(c => !('snap' in c)));
    const tooMany = await owner.get(`/api/chats/${chatId}/member-certs?subjects=${ids.concat([1]).join(',')}`);
    assert.strictEqual(tooMany.status, 400);
});

// ===================== Общий признак версии клиента =====================

test('proto: изменяющие запросы волны 4 без признака версии - 400 client-outdated (approve, join, member-certs, rotate, disable, identity, key-shares)', async () => {
    const owner = await makeUser('владелец');
    const { chat } = await room(owner);
    const noProto = { proto: undefined };
    const calls = {
        join: await owner.post('/api/chats/join', { code: 'A'.repeat(26), ...noProto }),
        approve: await owner.post('/api/join-requests/1/approve', { ...noProto }),
        memberCerts: await owner.post(`/api/chats/${chat.id}/member-certs`, { subjectId: 1, ...noProto }),
        rotate: await owner.post(`/api/chats/${chat.id}/invite/rotate`, { ttlSeconds: 604800, ...noProto }),
        disable: await owner.post(`/api/chats/${chat.id}/invite/disable`, { ...noProto }),
        identity: await owner.put('/api/keys/identity', { identity_signing_key: b64(owner.identity.signPub), identity_dh_key: b64(owner.identity.dhPub), ...noProto }),
        keyShares: await owner.post('/api/keys/key-shares', { chatId: chat.id, shares: [{ recipientUserId: 1, ciphertext: 'x' }], ...noProto }),
    };
    for (const [name, res] of Object.entries(calls)) {
        assert.deepStrictEqual([res.status, res.body.code], [400, 'client-outdated'], name);
    }
});
