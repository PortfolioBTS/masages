'use strict';
// Вторая подпись сертификата приглашения (ревью W7 R5, З-3): sig2 ставит ключ приглашения (ref), то есть тот, кто
// знает секрет ссылки; без неё сертификат подписал бы один автор, и любой, кто видел сертификат, мог бы выдать
// чужой ключ за ключ приглашения. public/lib/membership.js, verifyCertSignatures, вид invite:
//   strictVerify(cert.ref, message, cert.sig2) -> иначе { ok: false, reason: 'sig2' }.
// Парная проверка для join (sig2 субъекта) уже убивается тестом «join: неверная подпись, ref, …»; здесь invite
// - напрямую и как вложенное приглашение внутри join ('invite-sig2').
// Запуск: node test/membership.invite-sig2.test.js

const assert = require('assert');
const crypto = require('crypto');
const M = require('../public/lib/membership.js');

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
const inviteKey = (seed) => M.inviteKeyFromSecret(new Uint8Array(16).fill(seed));

async function snap() { return M.buildSnap([await M.memkey(A.id, A.signPub, A.dhPub)]); }

// Сертификат приглашения; signers.sig/sig2 можно подменить (кто и чем подписал).
async function signInvite(k, signers = {}) {
    const s = await snap();
    return M.signCert({
        kind: M.KIND.invite, roomId: ROOM, issuedMin: NOW - 10, nonce: nonce(), actorId: A.id, actorKey: A.signPub,
        ref: k.invitePub, expiresMin: NOW + 7 * DAY, snapN: s.n, snapHash: s.hash,
    }, { sig: signers.sig || A.sign, sig2: signers.sig2 || k.sign });
}

async function joinFor(inviteRaw, k, { sig, sig2 } = {}) {
    return M.signCert({
        kind: M.KIND.join, roomId: ROOM, issuedMin: NOW, nonce: nonce(), subjectId: J.id, subjectSignPub: J.signPub,
        subjectDhPub: J.dhPub, actorId: 0, actorKey: k.invitePub, ref: await M.certHash(inviteRaw),
    }, { sig: sig || k.sign, sig2: sig2 || J.sign });
}

function ctx(patch = {}) {
    return {
        roomId: ROOM, nowMin: NOW, expectSubject: J.id, removedAt: () => undefined,
        actorOk: (id, key) => (id === A.id && M.bytesEqual(key, A.signPub) ? { ok: true } : { ok: false, reason: 'actor' }),
        subjectKeysOk: (id, sp, dp) => (id === J.id && M.bytesEqual(sp, J.signPub) && M.bytesEqual(dp, J.dhPub) ? { ok: true } : { ok: false, reason: 'subject-keys' }),
        ...patch,
    };
}

const flip = (raw, offset) => { const out = raw.slice(); out[offset] ^= 1; return out; };
const verdict = (res) => [res.ok, res.reason];

async function main() {
    const k = await inviteKey(5);
    const other = await inviteKey(6);

    await test('invite: верные sig (автор) и sig2 (ключ приглашения) - проходит', async () => {
        const raw = await signInvite(k);
        assert.deepStrictEqual(verdict(await M.validateCert(raw, ctx())), [true, undefined]);
    });

    await test('invite: верная sig, но sig2 испорчена одним битом - sig2', async () => {
        const raw = await signInvite(k);
        for (const offset of [M.OFF.sig2, M.OFF.sig2 + 17, M.OFF.sig2 + 63]) {
            assert.deepStrictEqual(verdict(await M.validateCert(flip(raw, offset), ctx())), [false, 'sig2'], `байт ${offset}`);
        }
    });

    await test('invite: sig2 поставлена не тем ключом (другим ключом приглашения или самим автором) - sig2', async () => {
        const byOther = await signInvite(k, { sig2: other.sign });
        assert.deepStrictEqual(verdict(await M.validateCert(byOther, ctx())), [false, 'sig2'], 'sig2 от другого ключа приглашения');
        const byActor = await signInvite(k, { sig2: A.sign });
        assert.deepStrictEqual(verdict(await M.validateCert(byActor, ctx())), [false, 'sig2'], 'sig2 от автора, а не от ref');
        const zero = await signInvite(k, { sig2: async () => new Uint8Array(64) });
        assert.deepStrictEqual(verdict(await M.validateCert(zero, ctx())), [false, 'sig2'], 'нулевая sig2');
    });

    await test('invite: порядок проверок - испорченная sig даёт sig, а не sig2; чужая sig при верной sig2 - тоже sig', async () => {
        const raw = await signInvite(k);
        assert.deepStrictEqual(verdict(await M.validateCert(flip(raw, M.OFF.sig + 5), ctx())), [false, 'sig']);
        const byStranger = await signInvite(k, { sig: J.sign });
        assert.deepStrictEqual(verdict(await M.validateCert(byStranger, ctx())), [false, 'sig']);
    });

    await test('join: вложенное приглашение с испорченной или чужой sig2 - invite-sig2, с верной - проходит', async () => {
        const good = await signInvite(k);
        const ok = await M.validateCert(await joinFor(good, k), ctx({ invite: good }));
        assert.strictEqual(ok.ok, true);
        for (const [what, raw] of [['бит sig2', flip(good, M.OFF.sig2 + 3)], ['sig2 от другого ключа', await signInvite(k, { sig2: other.sign })]]) {
            const res = await M.validateCert(await joinFor(raw, k), ctx({ invite: raw }));
            assert.deepStrictEqual(verdict(res), [false, 'invite-sig2'], what);
        }
    });

    await test('join: собственные подписи - sig ключом приглашения и sig2 ключом субъекта (контроль парной проверки)', async () => {
        const good = await signInvite(k);
        const wrongSig2 = await M.validateCert(await joinFor(good, k, { sig2: A.sign }), ctx({ invite: good }));
        assert.deepStrictEqual(verdict(wrongSig2), [false, 'sig2']);
        const wrongSig = await M.validateCert(await joinFor(good, k, { sig: other.sign }), ctx({ invite: good }));
        assert.deepStrictEqual(verdict(wrongSig), [false, 'sig']);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
