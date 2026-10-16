'use strict';
// Проверки сертификатов состава на сервере (docs/security/signed-membership.md, 7.2).
//
// Разбор макетов, подписи и строгая проверка Ed25519 - те же функции, что исполняет клиент
// (public/lib/membership.js, public/lib/ed25519-strict.js): сервер и клиент не могут разойтись в
// том, что считать допустимым сертификатом. Проверки сервера - защита в глубину против ошибок
// клиента и случайного мусора; доверия серверу они не добавляют (раздел 3): состав группы
// клиенты проверяют сами. Здесь нет SQL: ключи участников, нужные для проверки, приходят
// аргументами, а строки БД пишет вызывающий в своей транзакции (7.1).
//
// Все функции возвращают { ok: true, ... } либо { ok: false, status, code, message }: статус и
// код - часть контракта с клиентом.

const M = require('../public/lib/membership.js');

const MAX_SNAP_BYTES = M.MAX_SNAP * M.MEMKEY_LENGTH;
// Лимит тела запросов со снимком (approve, invite/rotate, POST member-certs): 16 КБ снимка в base64 это
// около 21,8 тыс. символов, плюс сертификат и JSON; общих 20 КБ не хватает (повторное ревью 10).
const BODY_LIMIT_WITH_SNAP = '32kb';
// Сколько субъектов можно запросить за раз (GET member-certs).
const MAX_SUBJECTS_PER_REQUEST = 200;

function fail(status, code, message) {
    return { ok: false, status, code, message };
}

const BAD_CERT = (message = 'Сертификат недействителен') => fail(400, 'bad-cert', message);
const BAD_TIME = () => fail(400, 'bad-cert-time', 'Часы устройства отличаются от серверных больше чем на 10 минут: сертификат не принят');
const CERT_REQUIRED = () => fail(400, 'cert-required', 'Нужен подписанный сертификат: обновите страницу');
const SNAP_REQUIRED = () => fail(400, 'snap-required', 'Нужен снимок состава группы: обновите страницу');

// Минута сервера (Unix-эпоха).
const serverMinute = (now = Date.now()) => Math.floor(now / 60000);

// issuedMin присланного сертификата в окне сервера (SERVER_WINDOW): сертификат создаётся действием
// «сейчас», старый - это повтор.
function inServerWindow(cert, now = Date.now()) {
    const nowMin = serverMinute(now);
    return cert.issuedMin >= nowMin - M.SERVER_WINDOW_MIN && cert.issuedMin <= nowMin + M.SERVER_WINDOW_MIN;
}

// base64 из тела запроса в байты; null - не строка, не каноническая запись или длина вне границ.
function decodeField(value, { min, max }) {
    if (typeof value !== 'string' || value.length === 0) return null;
    const bytes = M.fromB64(value);
    if (!bytes || bytes.length < min || bytes.length > max) return null;
    return bytes;
}

// Ключи участника из хранилища ключей: { signingKey: Uint8Array(32), dhKey: Uint8Array(32) } либо null.
function normalizeKeys(row) {
    if (!row) return null;
    const signing = row.identity_signing_key || row.signingKey;
    const dh = row.identity_dh_key || row.dhKey;
    if (!signing || !dh) return null;
    const s = new Uint8Array(signing);
    const d = new Uint8Array(dh);
    return s.length === 32 && d.length === 32 ? { signingKey: s, dhKey: d } : null;
}

// Снимок в запросе: его длина 16·snapN и хэш равен snapHash сертификата.
async function checkSnapField(snapB64, cert) {
    if (snapB64 === undefined || snapB64 === null || snapB64 === '') return SNAP_REQUIRED();
    const snap = decodeField(snapB64, { min: M.MEMKEY_LENGTH, max: MAX_SNAP_BYTES });
    if (!snap) return BAD_CERT('Снимок состава повреждён');
    if (!(await M.checkSnap(snap, cert.snapN, cert.snapHash))) return BAD_CERT('Снимок состава не совпадает с сертификатом');
    return { ok: true, snap };
}

// Допуск (vouch, 1) или повторный допуск (revouch, 4) от участника actorId субъекту subjectId.
//   allowedKinds - какие виды допустимы маршруту (approve: [1]; member-certs: [1, 4]);
//   actorKeys, subjectKeys - ключи из key-store (identity_keys); roomId - комната запроса.
// vouch несёт снимок (его получает субъект), revouch - нет.
async function verifyVouch({ certB64, snapB64, allowedKinds, roomId, actorId, subjectId, actorKeys, subjectKeys, now = Date.now() }) {
    const raw = decodeField(certB64, { min: 1, max: 335 });
    if (certB64 === undefined || certB64 === null || certB64 === '') return CERT_REQUIRED();
    if (!raw) return BAD_CERT();
    const parsed = M.parseCert(raw);
    if (!parsed.ok) return BAD_CERT();
    const cert = parsed.cert;
    if (!allowedKinds.includes(cert.kind)) return BAD_CERT('Этот вид сертификата здесь не принимается');
    if (cert.roomId !== roomId) return BAD_CERT('Сертификат выдан для другой группы');
    if (cert.actorId !== actorId) return BAD_CERT('Сертификат подписан не вами');
    if (cert.subjectId !== subjectId) return BAD_CERT('Сертификат выдан другому участнику');
    const actor = normalizeKeys(actorKeys);
    const subject = normalizeKeys(subjectKeys);
    if (!actor || !M.bytesEqual(cert.actorKey, actor.signingKey)) return BAD_CERT('Ключ подписавшего не совпадает с зарегистрированным');
    if (!subject || !M.bytesEqual(cert.subjectSignPub, subject.signingKey) || !M.bytesEqual(cert.subjectDhPub, subject.dhKey)) {
        return BAD_CERT('Ключи участника в сертификате не совпадают с зарегистрированными');
    }
    const sigs = await M.verifyCertSignatures(cert);
    if (!sigs.ok) return BAD_CERT();
    if (!inServerWindow(cert, now)) return BAD_TIME();
    let snap = null;
    if (cert.kind === M.KIND.vouch) {
        const checked = await checkSnapField(snapB64, cert);
        if (!checked.ok) return checked;
        snap = checked.snap;
    } else if (snapB64 !== undefined && snapB64 !== null && snapB64 !== '') {
        return BAD_CERT('У повторного допуска снимка нет');
    }
    return { ok: true, cert, raw, snap, hash: await M.certHash(raw) };
}

// Приглашение (invite, 2) автора actorId. ttlSeconds - срок, выбранный в запросе: сервер сверяет
// ДЛИТЕЛЬНОСТЬ expiresMin - issuedMin с ним (точность 1 минута), а не абсолютное время: клиент с часами, сбитыми на
// 3-10 минут, не должен отвергаться (7.2).
async function verifyInvite({ certB64, snapB64, roomId, actorId, actorKeys, ttlSeconds, now = Date.now() }) {
    if (certB64 === undefined || certB64 === null || certB64 === '') return CERT_REQUIRED();
    const raw = decodeField(certB64, { min: 1, max: 335 });
    if (!raw) return BAD_CERT();
    const parsed = M.parseCert(raw);
    if (!parsed.ok || parsed.cert.kind !== M.KIND.invite) return BAD_CERT();
    const cert = parsed.cert;
    if (cert.roomId !== roomId) return BAD_CERT('Приглашение выдано для другой группы');
    if (cert.actorId !== actorId) return BAD_CERT('Приглашение подписано не вами');
    const actor = normalizeKeys(actorKeys);
    if (!actor || !M.bytesEqual(cert.actorKey, actor.signingKey)) return BAD_CERT('Ключ подписавшего не совпадает с зарегистрированным');
    const sigs = await M.verifyCertSignatures(cert);
    if (!sigs.ok) return BAD_CERT();
    if (!inServerWindow(cert, now)) return BAD_TIME();
    const duration = cert.expiresMin - cert.issuedMin;
    if (cert.expiresMin <= cert.issuedMin || duration > M.INVITE_MAX_MIN) return BAD_CERT('Срок приглашения больше 720 часов');
    if (Math.abs(duration - ttlSeconds / 60) > 1) return BAD_CERT('Срок приглашения не совпадает с выбранным');
    const checked = await checkSnapField(snapB64, cert);
    if (!checked.ok) return checked;
    return { ok: true, cert, raw, snap: checked.snap, hash: await M.certHash(raw) };
}

// Вход по приглашению (join, 3). inviteRaw - rooms.invite_cert (прочитан под блокировкой комнаты),
// userKeys - ключи входящего из key-store.
async function verifyJoin({ joinRaw, inviteRaw, roomId, userId, userKeys, now = Date.now() }) {
    if (!(joinRaw instanceof Uint8Array)) return BAD_CERT();
    const parsed = M.parseCert(joinRaw);
    if (!parsed.ok || parsed.cert.kind !== M.KIND.join) return BAD_CERT();
    const cert = parsed.cert;
    if (cert.roomId !== roomId) return BAD_CERT('Сертификат выдан для другой группы');
    if (cert.subjectId !== userId) return BAD_CERT('Сертификат выдан другому участнику');
    const keys = normalizeKeys(userKeys);
    if (!keys || !M.bytesEqual(cert.subjectSignPub, keys.signingKey) || !M.bytesEqual(cert.subjectDhPub, keys.dhKey)) {
        return BAD_CERT('Ключи в сертификате не совпадают с зарегистрированными');
    }
    if (!(inviteRaw instanceof Uint8Array)) return BAD_CERT('Приглашение недействительно');
    if (!M.bytesEqual(await M.certHash(inviteRaw), cert.ref)) return BAD_CERT('Сертификат выдан для другого приглашения');
    const inviteParsed = M.parseCert(inviteRaw);
    if (!inviteParsed.ok || inviteParsed.cert.kind !== M.KIND.invite) return BAD_CERT('Приглашение недействительно');
    const invite = inviteParsed.cert;
    // actorKey в join - открытый ключ приглашения (ref приглашения), sig проверена им.
    if (!M.bytesEqual(cert.actorKey, invite.ref)) return BAD_CERT('Ключ приглашения не совпадает');
    const sigs = await M.verifyCertSignatures(cert);
    if (!sigs.ok) return BAD_CERT();
    if (!inServerWindow(cert, now)) return BAD_TIME();
    // issuedMin(join) в [I.issuedMin - SKEW; I.expiresMin + SKEW]: те же границы, что у клиента (6.4).
    if (cert.issuedMin < invite.issuedMin - M.SKEW_MIN || cert.issuedMin > invite.expiresMin + M.SKEW_MIN) return BAD_TIME();
    return { ok: true, cert, raw: joinRaw, invite, hash: await M.certHash(joinRaw) };
}

// Строка таблицы -> элемент ответа API: { subjectId, actorId, kind, cert (base64), aux? (base64, у join) }.
function certRowToApi(row) {
    const item = {
        subjectId: Number(row.subject_id),
        actorId: Number(row.actor_id),
        kind: Number(row.kind),
        cert: M.toB64(new Uint8Array(row.cert)),
    };
    if (row.aux) item.aux = M.toB64(new Uint8Array(row.aux));
    return item;
}

// Разбор параметра subjects=<id>,<id>,...: целые 1..2^31-1 без повторов; null - ошибка формата или больше лимита.
function parseSubjects(raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_SUBJECTS_PER_REQUEST * 11) return null;
    const out = [];
    for (const part of raw.split(',')) {
        if (!/^\d{1,10}$/.test(part)) return null;
        const id = Number(part);
        if (id < 1 || id > 2147483647) return null;
        if (!out.includes(id)) out.push(id);
        if (out.length > MAX_SUBJECTS_PER_REQUEST) return null;
    }
    return out;
}

module.exports = {
    BODY_LIMIT_WITH_SNAP, MAX_SUBJECTS_PER_REQUEST, MAX_SNAP_BYTES,
    serverMinute, inServerWindow, decodeField, normalizeKeys,
    verifyVouch, verifyInvite, verifyJoin, certRowToApi, parseSubjects,
    BAD_CERT, BAD_TIME, CERT_REQUIRED, SNAP_REQUIRED,
};
