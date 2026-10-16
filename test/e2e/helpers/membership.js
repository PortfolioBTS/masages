'use strict';
// Подписанный состав группы для сквозных тестов (docs/security/signed-membership.md): вход по ссылке, одобрение
// заявки и приглашение без одобрения теперь требуют сертификатов, подписанных identity-ключом.
//
// Помощники HTTP-клиента набора (TestClient.join / approve / rotateInvite) подписывают сами: у клиента заводится
// identity (Ed25519 + X25519, регистрируется PUT /api/keys/identity), сертификат строится общим модулем
// public/lib/membership.js и подписывается node:crypto. Если у клиента подключён настоящий клиент E2EE
// (tc.e2ee = createClient(...) после init()), подписывает он: его ключи уже на сервере.
//
// Снимок состава в сертификате здесь - только подписавший (минимальный допустимый): настоящий состав проверяют
// протокольные тесты на клиенте; сквозным нужно, чтобы сервер принимал и отвергал сертификаты по правилам 7.2.

const crypto = require('crypto');
const M = require('../../../public/lib/membership.js');

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64 = (bytes) => Buffer.from(bytes).toString('base64');

// Секреты ссылок, созданных помощниками этого процесса: код -> { secret: Uint8Array(16), text }. Так join(code)
// ведёт себя как человек, у которого есть ссылка: найдя секрет, входит без одобрения; иначе - заявка.
const INVITE_SECRETS = new Map();

function newIdentity() {
    const seed = crypto.randomBytes(32);
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
    const signPub = new Uint8Array(crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32));
    const dh = crypto.generateKeyPairSync('x25519');
    const dhPub = new Uint8Array(dh.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32));
    return { signPub, dhPub, sign: async (message) => new Uint8Array(crypto.sign(null, message, privateKey)) };
}

// identity клиента набора: заведён раньше (tc.identity) или регистрируется сейчас. Если identity уже есть на сервере,
// а закрытой части у клиента нет, тест регистрировал ключи сам - ему нужно задать tc.identity или tc.e2ee.
async function ensureIdentity(tc) {
    if (tc.identity) return tc.identity;
    const known = await tc.get(`/api/keys/identities?ids=${tc.user.id}`);
    if (known.body && Array.isArray(known.body.identities) && known.body.identities.length > 0) {
        throw new Error('identity клиента уже зарегистрирован без закрытой части: задайте tc.identity или tc.e2ee');
    }
    const identity = newIdentity();
    await tc.ok(tc.put('/api/keys/identity', { identity_signing_key: b64(identity.signPub), identity_dh_key: b64(identity.dhPub) }), 'identity для подписи состава');
    tc.identity = identity;
    return identity;
}

async function roomIdOfChat(tc, chatId) {
    const chat = (await tc.chats()).find(c => String(c.id) === String(chatId));
    if (!chat || !chat.room_id) throw new Error('чат не комната: ' + chatId);
    return Number(chat.room_id);
}

const nowMin = () => Math.floor(Date.now() / 60000);
const nonce = () => new Uint8Array(crypto.randomBytes(16));

async function selfSnapshot(tc, identity) {
    return M.buildSnap([await M.memkey(Number(tc.user.id), identity.signPub, identity.dhPub)]);
}

// Приглашение (rotate): без одобрения - с подписанным сертификатом и снимком, секрет запоминается по коду.
async function rotateInvite(tc, chatId, settings = {}) {
    if (settings.requireApproval !== false) return tc.ok(tc.post(`/api/chats/${chatId}/invite/rotate`, settings), 'новый код приглашения');
    const ttlSeconds = settings.ttlSeconds || 604800;
    const roomId = await roomIdOfChat(tc, chatId);
    let body;
    let secretText;
    if (tc.e2ee) {
        const signed = await tc.e2ee.signInvite(roomId, { ttlSeconds });
        body = { ...settings, ttlSeconds, inviteCert: signed.cert, inviteSnap: signed.snap };
        secretText = signed.secret;
    } else {
        const identity = await ensureIdentity(tc);
        const secret = new Uint8Array(crypto.randomBytes(16));
        const key = await M.inviteKeyFromSecret(secret);
        const snap = await selfSnapshot(tc, identity);
        const issuedMin = nowMin();
        const raw = await M.signCert({
            kind: M.KIND.invite, roomId, issuedMin, nonce: nonce(), actorId: Number(tc.user.id), actorKey: identity.signPub,
            ref: key.invitePub, expiresMin: issuedMin + ttlSeconds / 60, snapN: snap.n, snapHash: snap.hash,
        }, { sig: identity.sign, sig2: key.sign });
        body = { ...settings, ttlSeconds, inviteCert: b64(raw), inviteSnap: b64(snap.snap) };
        secretText = M.secretToBase64Url(secret);
    }
    const res = await tc.ok(tc.post(`/api/chats/${chatId}/invite/rotate`, body), 'новый код приглашения');
    INVITE_SECRETS.set(res.code, { text: secretText });
    return { ...res, secret: secretText };
}

// Тело join для известной ссылки: joinCert по приглашению, которое отдал предпросмотр.
async function joinCertFor(tc, roomId, inviteCertB64, secretText) {
    if (tc.e2ee) return (await tc.e2ee.prepareJoin(roomId, { secret: secretText, inviteCert: inviteCertB64 })).joinCert;
    const identity = await ensureIdentity(tc);
    const secret = M.secretFromBase64Url(secretText);
    const key = await M.inviteKeyFromSecret(secret);
    const inviteRaw = M.fromB64(inviteCertB64);
    const issuedMin = nowMin();
    const raw = await M.signCert({
        kind: M.KIND.join, roomId, issuedMin, nonce: nonce(), subjectId: Number(tc.user.id), subjectSignPub: identity.signPub,
        subjectDhPub: identity.dhPub, actorId: 0, actorKey: key.invitePub, ref: await M.certHash(inviteRaw),
    }, { sig: key.sign, sig2: identity.sign });
    return b64(raw);
}

// Вход по коду. opts.secret: строка секрета ссылки; null - войти «кодом без секрета» (заявка); по умолчанию - секрет
// ссылки, созданной помощником rotateInvite в этом процессе, если он есть. Сырой ответ: rawJoin.
async function rawJoin(tc, code, opts = {}) {
    const body = { code };
    const secretText = opts.secret === null ? null : (opts.secret || (INVITE_SECRETS.get(code) || {}).text || null);
    // У каждого входящего есть ключи на сервере - иначе его нельзя одобрить. Тест, зарегистрировавший ключи сам, остаётся как есть.
    if (!tc.e2ee && !tc.identity) {
        try { await ensureIdentity(tc); } catch (err) { if (!/уже зарегистрирован/.test(err.message)) throw err; }
    }
    if (secretText) {
        const preview = await tc.post('/api/chats/join/preview', { code });
        if (preview.body && preview.body.success && preview.body.inviteCert) {
            body.joinCert = await joinCertFor(tc, Number(preview.body.roomId), preview.body.inviteCert, secretText);
        }
    }
    return tc.post('/api/chats/join', { ...body, ...(opts.extra || {}) });
}

async function join(tc, code, opts) {
    return tc.ok(rawJoin(tc, code, opts), 'вход по коду');
}

// Допуск заявки: подписанный vouch одобряющего заявителю и снимок. Заявка ищется среди заявок комнат одобряющего.
async function approve(tc, requestId, opts = {}) {
    let found = null;
    for (const chat of (await tc.chats()).filter(c => c.room_id)) {
        const list = await tc.joinRequests(chat.id);
        const hit = list.find(r => String(r.id) === String(requestId));
        if (hit) { found = { roomId: Number(chat.room_id), request: hit }; break; }
    }
    if (!found || !found.request.identity) {
        // Чужая, несуществующая заявка или заявитель без ключей: сервер ответит сам (404 / applicant-no-keys).
        return tc.ok(tc.post(`/api/join-requests/${requestId}/approve`, opts.body || {}), 'одобрение заявки');
    }
    const { roomId, request } = found;
    let body;
    if (tc.e2ee) {
        const signed = await tc.e2ee.signApproval(roomId, { userId: request.userId, signingKey: request.identity.signingKey, dhKey: request.identity.dhKey });
        body = { cert: signed.cert, snap: signed.snap };
    } else {
        const identity = await ensureIdentity(tc);
        const snap = await selfSnapshot(tc, identity);
        const raw = await M.signCert({
            kind: M.KIND.vouch, roomId, issuedMin: nowMin(), nonce: nonce(), subjectId: Number(request.userId),
            subjectSignPub: M.fromB64(request.identity.signingKey), subjectDhPub: M.fromB64(request.identity.dhKey),
            actorId: Number(tc.user.id), actorKey: identity.signPub, snapN: snap.n, snapHash: snap.hash,
        }, { sig: identity.sign });
        body = { cert: b64(raw), snap: b64(snap.snap) };
    }
    return tc.ok(tc.post(`/api/join-requests/${requestId}/approve`, { ...body, ...(opts.body || {}) }), 'одобрение заявки');
}

module.exports = { INVITE_SECRETS, ensureIdentity, newIdentity, rotateInvite, rawJoin, join, approve, joinCertFor, roomIdOfChat };
