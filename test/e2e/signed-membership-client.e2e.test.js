'use strict';
// Ворота G4 (подписанный состав группы) на настоящем сервере и Postgres с настоящими клиентами E2EE
// (docs/security/signed-membership.md, раздел 16):
//   * призрак, добавленный в комнату через базу, не получает ключ и виден как "не подтверждён";
//   * создатель комнаты и участник с готовым V не принимают подсунутого "подтверждённого" (допуск от призрака);
//   * вход по ссылке с секретом даёт подтверждение по якорю, чтение работает;
//   * поворот ссылки при выходе участника: старая ссылка и код не действуют, секрет на устройстве стирается.
// Клиент E2EE - public/e2ee.js целиком; транспорт - HTTP-клиент набора.

const { test } = require('node:test');
const assert = require('assert');
const E2EE = require('../../public/e2ee.js');
const MLKEM = require('../../public/mlkem.js');
const M = require('../../public/lib/membership.js');
const { createSuite } = require('./helpers/scenarios');

const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const suite = createSuite('signed-membership-client');

// Транспорт E2EE-клиента поверх HTTP-клиента набора (то же, что makeFetchTransport делает через fetch).
function transportFor(tc) {
    const call = async (method, url, body) => {
        const res = await tc.request(method, url, body === undefined ? {} : { json: body });
        return { status: res.status, data: res.body };
    };
    return {
        putIdentity: (body) => call('PUT', '/api/keys/identity', body),
        putSignedPrekey: (body) => call('PUT', '/api/keys/signed-prekey', body),
        putPqPrekey: (body) => call('PUT', '/api/keys/pq-prekey', body),
        postOneTimePrekeys: (body) => call('POST', '/api/keys/one-time-prekeys', body),
        postPqOneTimePrekeys: (body) => call('POST', '/api/keys/pq-one-time-prekeys', body),
        deletePqOneTimePrekeys: () => call('DELETE', '/api/keys/pq-one-time-prekeys'),
        getOneTimePrekeyCount: () => call('GET', '/api/keys/one-time-prekeys/count'),
        getBundle: (id) => call('GET', '/api/keys/bundle/' + id),
        getIdentities: (ids) => call('GET', '/api/keys/identities?ids=' + ids.join(',')),
        deleteKeys: () => call('DELETE', '/api/keys'),
        getParticipants: (chatId) => call('GET', `/api/chats/${chatId}/participants`),
        getMemberCerts: (chatId, ids) => call('GET', `/api/chats/${chatId}/member-certs?subjects=${ids.join(',')}`),
        postMemberCert: (chatId, body) => call('POST', `/api/chats/${chatId}/member-certs`, body),
        postKeyShares: (chatId, shares) => call('POST', '/api/keys/key-shares', { chatId, shares }),
        getKeyShares: (chatId) => call('GET', `/api/keys/key-shares/${chatId}`),
        postKeyRequests: (chatId, senderKeyIds) => call('POST', '/api/keys/key-requests', { chatId, senderKeyIds }),
        getKeyRequests: (chatId) => call('GET', `/api/keys/key-requests/${chatId}`),
        postKeyRequestsDone: (chatId, senderKeyIds) => call('POST', '/api/keys/key-requests/done', { chatId, senderKeyIds }),
        ktHead: () => call('GET', '/api/kt/head'),
        ktRoots: (gen, from, limit) => call('GET', `/api/kt/roots?gen=${gen}&from=${from}&limit=${limit}`),
        ktProof: (userId, gen, epoch) => call('GET', `/api/kt/proof?user=${userId}&gen=${gen}&epoch=${epoch}`),
        ktSelf: (gen, from, limit) => call('GET', `/api/kt/self?gen=${gen}&from=${from}&limit=${limit}`),
    };
}

// Пользователь с настоящим клиентом E2EE: клиент уже прошёл init() (ключи на сервере) и подписывает допуски сам (tc.e2ee).
async function makeUser(name) {
    const tc = suite.client({ name });
    await tc.registerAnon();
    const client = E2EE.createClient({ userId: tc.user.id, storage: new E2EE.MemoryStorage(), transport: transportFor(tc), kem: MLKEM });
    await client.init();
    tc.e2ee = client;
    return { tc, id: tc.user.id, client, chat: null, roomId: null };
}

async function session(user) {
    const part = (await user.tc.get(`/api/chats/${user.chat.id}/participants`)).body;
    return user.client.ensureRoomSession(user.chat.id, user.roomId, part.participants, part);
}
const sync = (user) => user.client.syncKeyShares(user.chat.id, user.roomId);

async function createRoom(owner, name = 'Состав') {
    owner.chat = await owner.tc.createRoom(name);
    owner.roomId = Number(owner.chat.room_id);
    await owner.client.noteRoomCreated(owner.roomId, owner.tc.user.username);
}

async function joinByApproval(owner, member) {
    const { code } = await owner.tc.invite(owner.chat.id);
    member.roomId = owner.roomId;
    await member.client.prepareJoin(member.roomId, {});
    const pending = await member.tc.join(code, { secret: null });
    assert.strictEqual(pending.pending, true);
    await session(owner);                                  // обновляет V владельца перед подписью
    await owner.tc.approve(pending.requestId);
    member.chat = (await member.tc.chats()).find(c => c.room_id === owner.roomId);
    assert.ok(member.chat, 'чат комнаты у участника');
}

const statusOf = (result, id) => result.members.find(m => m.id === id).status;
const keySharesTo = async (userId) => Number((await suite.query('SELECT count(*)::int AS n FROM e2ee_key_shares WHERE recipient_id = $1', [userId])).rows[0].n);

test('G4: призрак, добавленный через базу, не получает ключ и виден как "не подтверждён"; его сообщения помечены', async () => {
    const alice = await makeUser('алиса');
    const bob = await makeUser('боб');
    const ghost = await makeUser('призрак');
    await createRoom(alice);
    await joinByApproval(alice, bob);
    // Призрак добавлен прямо в базу: никто его не одобрял.
    await suite.query('INSERT INTO room_participants (room_id, user_id, visible_from_seq) VALUES ($1, $2, 0)', [alice.roomId, ghost.id]);
    ghost.roomId = alice.roomId;
    const before = await keySharesTo(ghost.id);
    const result = await session(alice);
    assert.strictEqual(statusOf(result, ghost.id), 'unconfirmed');
    assert.strictEqual(statusOf(result, bob.id), 'confirmed');
    assert.ok(result.warnings.some(w => w.userId === ghost.id && w.reason === 'unconfirmed-member'));
    assert.strictEqual(await keySharesTo(ghost.id), before, 'ключ призраку не отправлен');
    assert.ok(await keySharesTo(bob.id) >= 1);
    assert.strictEqual(statusOf(await session(bob), ghost.id), 'unconfirmed', 'у Боба призрак тоже не подтверждён');
    // Вручную подтверждённый призрак получает ключ (решение человека), но не как подтверждённый подписью.
    assert.strictEqual((await alice.client.trustMember(alice.roomId, ghost.id)).ok, true);
    const manual = await session(alice);
    assert.strictEqual(manual.members.find(m => m.id === ghost.id).how, 'manual');
    assert.ok(await keySharesTo(ghost.id) > before);
});

test('G4: создатель и участник с готовым V не принимают подсунутого "подтверждённого" - допуск от призрака ничего не даёт', async () => {
    const alice = await makeUser('алиса');
    const bob = await makeUser('боб');
    const ghost = await makeUser('призрак');
    await createRoom(alice);
    await joinByApproval(alice, bob);
    await suite.query('INSERT INTO room_participants (room_id, user_id, visible_from_seq) VALUES ($1, $2, 0)', [alice.roomId, ghost.id]);
    ghost.roomId = alice.roomId;
    await session(alice);
    await session(bob);
    // Призрак подписывает допуск создателю и Бобу (со снимком призрака) и сервер "находит" его в базе.
    for (const target of [alice, bob]) {
        const forged = await ghost.client.signApproval(alice.roomId, { userId: target.id, signingKey: (await keysOf(target.id)).signingKey, dhKey: (await keysOf(target.id)).dhKey });
        const cert = M.fromB64(forged.cert);
        await suite.query('INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, snap) VALUES ($1, $2, $3, 1, $4, $5)',
            [alice.roomId, target.id, ghost.id, Buffer.from(cert), Buffer.from(M.fromB64(forged.snap))]);
    }
    for (const user of [alice, bob]) {
        const result = await session(user);
        assert.strictEqual(result.anchor, null, 'якорной проверки нет: V уже записан');
        assert.strictEqual(statusOf(result, ghost.id), 'unconfirmed');
    }
    assert.deepStrictEqual((await alice.client.getMembers(alice.roomId)).filter(m => m.status === 'confirmed').map(m => m.id), [bob.id]);
});

async function keysOf(userId) {
    const row = (await suite.query('SELECT identity_signing_key, identity_dh_key FROM identity_keys WHERE user_id = $1', [userId])).rows[0];
    return { signingKey: row.identity_signing_key.toString('base64'), dhKey: row.identity_dh_key.toString('base64') };
}

test('G4: вход по ссылке с секретом даёт подтверждение по якорю; сообщения читаются; код без секрета - только заявка', async () => {
    const alice = await makeUser('алиса');
    const bob = await makeUser('боб');
    const carol = await makeUser('кэрол');
    const dave = await makeUser('дейв');
    await createRoom(alice);
    await joinByApproval(alice, bob);
    await session(alice);
    const invite = await alice.tc.rotateInvite(alice.chat.id, { ttlSeconds: 604800, requireApproval: false });
    assert.ok(invite.secret);
    // Кэрол: ссылка с секретом.
    carol.roomId = alice.roomId;
    const joined = await carol.tc.join(invite.code);
    assert.strictEqual(joined.success, true);
    assert.ok(joined.inviteSnap);
    assert.strictEqual((await carol.client.completeJoin(carol.roomId, joined.inviteSnap)).ok, true);
    carol.chat = (await carol.tc.chats()).find(c => c.room_id === alice.roomId);
    const first = await session(carol);
    assert.deepStrictEqual(first.anchor, { ok: true, via: 'invite', by: alice.id });
    assert.strictEqual(statusOf(first, alice.id), 'confirmed');
    assert.strictEqual(statusOf(first, bob.id), 'confirmed', 'Боб в снимке приглашения Алисы');
    // Алиса подтверждает Кэрол по её join-сертификату и отправляет ей ключ; Кэрол читает.
    const aliceView = await session(alice);
    assert.deepStrictEqual(aliceView.members.find(m => m.id === carol.id).how, 'invite');
    assert.strictEqual((await sync(carol)).applied >= 1, true);
    const sent = await alice.client.encryptOutgoing(alice.roomId, 'добро пожаловать', { messageId: '2000001' });
    const read = await carol.client.decryptIncoming(alice.roomId, alice.id, sent, '2000001');
    assert.strictEqual(read.text, 'добро пожаловать');
    assert.strictEqual(read.unverifiedSender, undefined);
    // Дейв пришёл кодом без секрета: заявка, комнаты у него нет.
    const request = await dave.tc.join(invite.code, { secret: null });
    assert.strictEqual(request.pending, true);
    assert.ok(!(await dave.tc.chats()).some(c => c.room_id === alice.roomId));
});

test('G4: поворот ссылки при выходе участника - старая ссылка и код не действуют, секрет автора стирается, о новой подписанной ссылке нужно позаботиться', async () => {
    const alice = await makeUser('алиса');
    const bob = await makeUser('боб');
    const carol = await makeUser('кэрол');
    await createRoom(alice);
    await joinByApproval(alice, bob);
    const invite = await alice.tc.rotateInvite(alice.chat.id, { ttlSeconds: 604800, requireApproval: false });
    assert.strictEqual(await alice.client.getInviteSecret(alice.roomId, (await alice.tc.get(`/api/chats/${alice.chat.id}/participants`)).body.invite), invite.secret);
    await session(alice);                                   // ключ разослан Бобу: он получатель, значит выход потребует ротации
    await bob.tc.leave(bob.chat.id);
    const part = (await alice.tc.get(`/api/chats/${alice.chat.id}/participants`)).body;
    assert.strictEqual(part.invite, null, 'подписанное приглашение обнулено');
    assert.strictEqual(await alice.client.getInviteSecret(alice.roomId, part.invite), null, 'секрет автора больше не показывается');
    const result = await session(alice);
    assert.strictEqual(result.rotated, true, 'ушёл получатель ключа: ротация');
    // Старая ссылка не работает: код сменился, joinCert не нужен.
    const stale = await carol.tc.joinRaw(invite.code);
    assert.strictEqual(stale.body.success, false);
    // Новый код принимает только заявки.
    const fresh = (await alice.tc.invite(alice.chat.id)).code;
    assert.notStrictEqual(fresh, invite.code);
    const attempt = await carol.tc.joinRaw(fresh);
    assert.strictEqual(attempt.body.pending, true);
});
