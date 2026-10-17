'use strict';
// Проверка сертификата клиентом (public/lib/membership.js, validateCert; signed-membership.md, 6.4): общие условия,
// вложенное приглашение I в join (все общие условия, кроме нижней границы свежести, плюс пп. 1-3 проверки invite),
// границы времени join (I.issuedMin - SKEW, I.expiresMin + SKEW), отзыв по субъекту, ключи малого порядка.
// Плюс статика: index.html подключает модули состава до e2ee.js, очередь повторных допусков ограничена.
// Запуск: node test/membership.validate.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { clientScriptFiles } = require('./client-script-source');
const M = require('../public/lib/membership.js');
const MC = require('../public/lib/membership-client.js');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function identity(id, seedByte) {
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, seedByte)]), format: 'der', type: 'pkcs8' });
    const signPub = new Uint8Array(crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32));
    return { id, signPub, dhPub: new Uint8Array(32).fill(seedByte + 1), sign: async (m) => new Uint8Array(crypto.sign(null, m, privateKey)) };
}
const A = identity(11, 0x21);
const J = identity(22, 0x31);
const ROOM = 77;
const NOW = 30_000_000;                 // минут
const DAY = 24 * 60;
const nonce = () => new Uint8Array(crypto.randomBytes(16));
const key = (seed) => M.inviteKeyFromSecret(new Uint8Array(16).fill(seed));
const LOW_ORDER_SIGNED = '0100000000000000000000000000000000000000000000000000000000000080';

async function snap() { return M.buildSnap([await M.memkey(A.id, A.signPub, A.dhPub)]); }

async function invite({ issuedMin = NOW - 10, expiresMin = NOW + 7 * DAY, actor = A, inviteKey } = {}) {
    const k = inviteKey || await key(5);
    const s = await snap();
    const raw = await M.signCert({
        kind: M.KIND.invite, roomId: ROOM, issuedMin, nonce: nonce(), actorId: actor.id, actorKey: actor.signPub,
        ref: k.invitePub, expiresMin, snapN: s.n, snapHash: s.hash,
    }, { sig: actor.sign, sig2: k.sign });
    return { raw, key: k };
}

async function join(inv, { issuedMin = NOW, subject = J } = {}) {
    return M.signCert({
        kind: M.KIND.join, roomId: ROOM, issuedMin, nonce: nonce(), subjectId: subject.id, subjectSignPub: subject.signPub,
        subjectDhPub: subject.dhPub, actorId: 0, actorKey: inv.key.invitePub, ref: await M.certHash(inv.raw),
    }, { sig: inv.key.sign, sig2: subject.sign });
}

function ctx(inviteRaw, patch = {}) {
    return {
        roomId: ROOM, nowMin: NOW, expectSubject: J.id, removedAt: () => undefined,
        actorOk: (id, k) => (id === A.id && M.bytesEqual(k, A.signPub) ? { ok: true } : { ok: false, reason: 'actor' }),
        subjectKeysOk: (id, sp, dp) => (id === J.id && M.bytesEqual(sp, J.signPub) && M.bytesEqual(dp, J.dhPub) ? { ok: true } : { ok: false, reason: 'subject-keys' }),
        invite: inviteRaw,
        ...patch,
    };
}

async function main() {
    await test('join: верный вход проходит; приглашение подтягивается из aux, actorKey равен ключу приглашения', async () => {
        const inv = await invite();
        const res = await M.validateCert(await join(inv), ctx(inv.raw));
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.cert.kind, M.KIND.join);
        assert.strictEqual(res.invite.actorId, A.id);
        assert.strictEqual(M.toHex(res.inviteHash), M.toHex(await M.certHash(inv.raw)));
    });

    await test('вложенное приглашение I: нижняя граница свежести не применяется (выдано 40 суток назад), для самого join - применяется', async () => {
        const old = await invite({ issuedMin: NOW - 20 * DAY, expiresMin: NOW + 10 * DAY });
        assert.strictEqual((await M.validateCert(await join(old), ctx(old.raw))).ok, true);
        // I выдано 40 суток назад на 29 суток; вход состоялся 12 суток назад, внутри срока приглашения.
        const veryOld = await invite({ issuedMin: NOW - 40 * DAY, expiresMin: NOW - 40 * DAY + 29 * DAY });
        const ok = await M.validateCert(await join(veryOld, { issuedMin: NOW - 12 * DAY }), ctx(veryOld.raw));
        assert.strictEqual(ok.ok, true, 'I старше 30 суток, но вход свежий и внутри срока приглашения: допустим');
        const stale = await M.validateCert(await join(old, { issuedMin: NOW - 31 * DAY }), ctx(old.raw));
        assert.deepStrictEqual([stale.ok, stale.reason], [false, 'time-stale']);
    });

    await test('вложенное приглашение I: ненулевое неиспользуемое поле, подпись, срок больше 720 часов, отзыв подписавшего, время из будущего, ключ малого порядка - отказ', async () => {
        const inv = await invite();
        const bad = async (raw, patch, reasonPart) => {
            const res = await M.validateCert(await join({ raw, key: inv.key }), ctx(raw, patch));
            assert.strictEqual(res.ok, false, reasonPart);
            assert.ok(res.reason.includes(reasonPart), res.reason + ' vs ' + reasonPart);
        };
        const nonZero = inv.raw.slice(); nonZero[40] = 1;          // subjectSignPub у приглашения - нули
        const nonZeroJoin = await M.validateCert(await join(inv), ctx(nonZero));
        assert.strictEqual(nonZeroJoin.ok, false);
        const forged = inv.raw.slice(); forged[220] ^= 1;
        await bad(forged, {}, 'invite');
        const tooLong = await invite({ expiresMin: NOW - 10 + 720 * 60 + 1 });
        await bad(tooLong.raw, {}, 'invite-term');
        await bad(inv.raw, { removedAt: (id) => (id === A.id ? NOW - 5 : undefined) }, 'invite-removed-actor');
        await bad(inv.raw, { actorOk: () => ({ ok: false, reason: 'actor-not-trusted' }) }, 'invite-actor-not-trusted');
        const future = await invite({ issuedMin: NOW + 11, expiresMin: NOW + 7 * DAY });
        await bad(future.raw, {}, 'invite-time-future');
        // Ключ приглашения малого порядка: приглашение и вход с ним не проходят даже с "нулевыми" подписями.
        const weakKey = M.fromHex(LOW_ORDER_SIGNED);
        const weak = await M.signCert({
            kind: M.KIND.invite, roomId: ROOM, issuedMin: NOW, nonce: nonce(), actorId: A.id, actorKey: A.signPub,
            ref: weakKey, expiresMin: NOW + 100, snapN: 1, snapHash: (await snap()).hash,
        }, { sig: A.sign, sig2: async () => new Uint8Array(64) });
        const weakJoin = await M.validateCert(await M.signCert({
            kind: M.KIND.join, roomId: ROOM, issuedMin: NOW, nonce: nonce(), subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub,
            actorId: 0, actorKey: weakKey, ref: await M.certHash(weak),
        }, { sig: async () => new Uint8Array(64), sig2: J.sign }), ctx(weak));
        assert.strictEqual(weakJoin.ok, false);
        assert.strictEqual(weakJoin.reason, 'key-strict');
    });

    await test('join: чужое приглашение (ref), приглашение не передано, отзыв субъекта по минуте выхода, inviteRef из намерения входа', async () => {
        const inv = await invite();
        const other = await invite({ inviteKey: await key(6) });
        const wrongRef = await M.validateCert(await join(inv), ctx(other.raw));
        assert.deepStrictEqual([wrongRef.ok, wrongRef.reason], [false, 'invite-ref']);
        const missing = await M.validateCert(await join(inv), ctx(null));
        assert.deepStrictEqual([missing.ok, missing.reason], [false, 'invite-missing']);
        const exited = await M.validateCert(await join(inv, { issuedMin: NOW - 5 }), ctx(inv.raw, { removedAt: (id) => (id === J.id ? NOW - 5 : undefined) }));
        assert.deepStrictEqual([exited.ok, exited.reason], [false, 'removed-subject'], 'issuedMin не позже выхода субъекта');
        const returned = await M.validateCert(await join(inv, { issuedMin: NOW - 4 }), ctx(inv.raw, { removedAt: (id) => (id === J.id ? NOW - 5 : undefined) }));
        assert.strictEqual(returned.ok, true, 'позже выхода принимается');
        const mismatch = await M.validateCert(await join(inv), ctx(inv.raw, { inviteRef: new Uint8Array(32).fill(1) }));
        assert.deepStrictEqual([mismatch.ok, mismatch.reason], [false, 'invite-ref']);
    });

    await test('join.issuedMin: границы I.issuedMin - 10 и I.expiresMin + 10 принимаются, за ними - join-time', async () => {
        const inv = await invite({ issuedMin: NOW - 100, expiresMin: NOW - 100 + 2 * 60 });          // приглашение живёт 2 часа
        const { issuedMin: I, expiresMin: E } = M.parseCert(inv.raw).cert;
        for (const [issuedMin, ok] of [[I - 10, true], [I - 11, false], [E + 10, true], [E + 11, false]]) {
            const nowMin = Math.max(issuedMin, NOW);
            const res = await M.validateCert(await join(inv, { issuedMin }), ctx(inv.raw, { nowMin }));
            assert.strictEqual(res.ok, ok, `issuedMin ${issuedMin - I} от I.issuedMin`);
            if (!ok) assert.strictEqual(res.reason, 'join-time');
        }
    });

    await test('общие условия: комната, из будущего (> SKEW), чужой субъект, ключ субъекта малого порядка - отказ; граница +SKEW принимается', async () => {
        const inv = await invite();
        const c = (patch) => ctx(inv.raw, patch);
        assert.strictEqual((await M.validateCert(await join(inv, { issuedMin: NOW + 10 }), c())).ok, true);
        assert.strictEqual((await M.validateCert(await join(inv, { issuedMin: NOW + 11 }), c())).reason, 'time-future');
        assert.strictEqual((await M.validateCert(await join(inv), c({ roomId: ROOM + 1 }))).reason, 'room');
        assert.strictEqual((await M.validateCert(await join(inv), c({ expectSubject: 999 }))).reason, 'subject');
        const weakSubject = { ...J, signPub: M.fromHex('0100000000000000000000000000000000000000000000000000000000000000') };
        const weak = await M.validateCert(await join(inv, { subject: weakSubject }), c({ subjectKeysOk: () => ({ ok: true }) }));
        assert.strictEqual(weak.ok, false);
        assert.strictEqual(weak.reason, 'key-strict');
    });

    await test('vouch и revouch: подписавший должен быть доверенным, ключи субъекта - закреплёнными; ref у revouch обязателен', async () => {
        const s = await snap();
        const vouch = await M.signCert({
            kind: M.KIND.vouch, roomId: ROOM, issuedMin: NOW, nonce: nonce(), subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub,
            actorId: A.id, actorKey: A.signPub, snapN: s.n, snapHash: s.hash,
        }, { sig: A.sign });
        assert.strictEqual((await M.validateCert(vouch, ctx(null))).ok, true);
        assert.strictEqual((await M.validateCert(vouch, ctx(null, { actorOk: () => ({ ok: false, reason: 'actor-not-trusted' }) }))).reason, 'actor-not-trusted');
        assert.strictEqual((await M.validateCert(vouch, ctx(null, { subjectKeysOk: () => ({ ok: false, reason: 'subject-keys' }) }))).reason, 'subject-keys');
        const revouch = await M.signCert({
            kind: M.KIND.revouch, roomId: ROOM, issuedMin: NOW, nonce: nonce(), subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub,
            actorId: A.id, actorKey: A.signPub, ref: new Uint8Array(32).fill(3),
        }, { sig: A.sign });
        assert.strictEqual((await M.validateCert(revouch, ctx(null))).ok, true);
        const zeroRef = revouch.slice(); zeroRef.fill(0, 137, 169);
        assert.strictEqual((await M.validateCert(zeroRef, ctx(null))).reason, 'unused-fields', 'ref = 0 у revouch отвергается ещё при разборе');
    });

    await test('очередь повторных допусков ограничена 50 задачами за проход; мусор отбрасывается', () => {
        const orig = '1'.repeat(64);
        const many = Array.from({ length: 80 }, (_, i) => ({ x: i + 1, orig, due: 5 }));
        assert.strictEqual(MC.normalizeRevouch(many).length, MC.MAX_REVOUCH_TASKS);
        assert.strictEqual(MC.MAX_REVOUCH_TASKS, 50);
        assert.deepStrictEqual(MC.normalizeRevouch([{ x: 1, orig, due: 1 }, { x: 1, orig, due: 2 }, { x: 0, orig, due: 1 }, { x: 2, orig: 'zz', due: 1 }, null, 7]), [{ x: 1, orig, due: 1 }]);
        assert.deepStrictEqual(MC.normalizeRevouch('мусор'), []);
    });

    await test('страница подключает модули состава до e2ee.js: ed25519-strict, membership, membership-client', () => {
        const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
        const at = (name) => html.indexOf(`<script src="${name}"`);
        const order = ['lib/ed25519-strict.js', 'lib/membership.js', 'lib/membership-client.js', 'e2ee.js', ...clientScriptFiles()].map(at);
        assert.ok(order.every(i => i >= 0), 'все скрипты подключены: ' + order.join());
        assert.deepStrictEqual(order.slice().sort((p, q) => p - q), order, 'порядок подключения');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error(err); process.exitCode = 1; });
