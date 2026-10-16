'use strict';
// Сертификаты состава группы (public/lib/membership.js, docs/security/signed-membership.md, раздел 6):
// фиксированные макеты 271/335 байт, memkey v2, хэш снимка, хэш взгляда, ключ приглашения из секрета,
// строгая проверка Ed25519 и контрольные векторы 6.6 (посчитаны в Node 24, дословно сверяются).
// Запуск: node test/membership.test.js

const assert = require('assert');
const crypto = require('crypto');
const M = require('../public/lib/membership.js');
const strict = require('../public/lib/ed25519-strict.js');

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

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const fill = (value, n) => new Uint8Array(n).fill(value);
const range = (from, n) => Uint8Array.from({ length: n }, (_, i) => from + i);

// ---- Вектор 6.6: ключи ----
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function identityFromSeed(seedByte, dhByte, id) {
    const seed = fill(seedByte, 32);
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
    const signPub = new Uint8Array(crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32));
    return { id, seed, privateKey, signPub, dhPub: fill(dhByte, 32), sign: async (m) => new Uint8Array(crypto.sign(null, m, privateKey)) };
}
const A = identityFromSeed(0xa1, 0xa2, 2345678);
const J = identityFromSeed(0xb1, 0xb2, 7654321);
const ROOM = 1234567;
const ISSUED = 29859120;

async function main() {
    // Источник правды для сборки — документ: сверяем hex сертификата дословно.
    const DOC_VOUCH_HEX = '4e59584f4d433031010012d68701c79d30101112131415161718191a1b1c1d1e1f0074cbb14721b5b632272e65a68dda7ac25b4185f8b01916db185c14287db92e2b770faeb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b20023cacebc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a50000000000000000000000000000000000000000000000000000000000000000000000000001931c7faa06435f5e287d62540382b8353d54b6dd323c7fb77ad7bb1786805ea7df8b936e37c62090e6d2048679655b50e348ae3add9e89296f9eb52ce05ade521c0f76292bb16a6d5fc101b46e2863a02f8f688800ab93b32282c874714e0c0f';

    await test('ключи A и J из 6.6: signPub совпадают с документом', () => {
        assert.strictEqual(hex(A.signPub), 'bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5');
        assert.strictEqual(hex(J.signPub), '4721b5b632272e65a68dda7ac25b4185f8b01916db185c14287db92e2b770fae');
    });

    await test('memkey v2: A, J и клон A под другим id (6.2)', async () => {
        assert.strictEqual(hex(await M.memkey(A.id, A.signPub, A.dhPub)), 'f3f6b4eb9f745b54bc1d639c66f3fc22');
        assert.strictEqual(hex(await M.memkey(J.id, J.signPub, J.dhPub)), '0e55cdbe407cf02ea80e104f1390052c');
        const clone = await M.memkey(2345679, A.signPub, A.dhPub);
        assert.strictEqual(hex(clone), '230451dc0bc3a39359f7c33ef32e1277');
        assert.notStrictEqual(hex(clone), 'f3f6b4eb9f745b54bc1d639c66f3fc22', 'id входит в memkey: клон не совпадает с оригиналом');
    });

    const memA = await M.memkey(A.id, A.signPub, A.dhPub);
    const memJ = await M.memkey(J.id, J.signPub, J.dhPub);

    await test('снимок [memkey(A)]: snapHash из 6.6; снимок проверяется до использования', async () => {
        const built = await M.buildSnap([memA]);
        assert.strictEqual(built.n, 1);
        assert.strictEqual(hex(built.hash), '931c7faa06435f5e287d62540382b8353d54b6dd323c7fb77ad7bb1786805ea7');
        assert.strictEqual(await M.checkSnap(built.snap, 1, built.hash), true);
        assert.strictEqual(await M.checkSnap(built.snap, 2, built.hash), false, 'snapN не равен длине');
        const tampered = built.snap.slice(); tampered[0] ^= 1;
        assert.strictEqual(await M.checkSnap(tampered, 1, built.hash), false, 'подменённый снимок');
        assert.strictEqual(await M.checkSnap(built.snap, 1, fill(0, 32)), false);
        assert.strictEqual(await M.checkSnap(new Uint8Array(0), 0, built.hash), false, 'пустой снимок не бывает');
    });

    await test('снимок: сортировка и повторы убираются; не отсортированный и с повторами чужой снимок отвергается; больше 1024 — отказ', async () => {
        const built = await M.buildSnap([memJ, memA, memJ]);
        assert.strictEqual(built.n, 2);
        const [lo, hi] = M.compareBytes(memA, memJ) < 0 ? [memA, memJ] : [memJ, memA];
        assert.deepStrictEqual(Array.from(built.snap), Array.from(M.concat(lo, hi)));
        const unsorted = M.concat(hi, lo);
        assert.strictEqual(await M.checkSnap(unsorted, 2, await M.snapHashOf(unsorted)), false, 'порядок обязателен: иначе один состав имел бы два хэша');
        const dup = M.concat(lo, lo);
        assert.strictEqual(await M.checkSnap(dup, 2, await M.snapHashOf(dup)), false);
        const many = Array.from({ length: 1025 }, (_, i) => M.u32be(i + 1)).map(b => M.concat(b, new Uint8Array(12)));
        await assert.rejects(M.buildSnap(many), RangeError);
        const max = await M.buildSnap(many.slice(0, 1024));
        assert.strictEqual(max.n, 1024);
        assert.strictEqual(max.snap.length, 16384);
    });

    // ---- Сертификат допуска ----
    const vouchFields = {
        kind: M.KIND.vouch, roomId: ROOM, issuedMin: ISSUED, nonce: range(0x10, 16),
        subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub,
        actorId: A.id, actorKey: A.signPub, snapN: 1,
        snapHash: unhex('931c7faa06435f5e287d62540382b8353d54b6dd323c7fb77ad7bb1786805ea7'),
    };

    await test('vouch 6.6: 271 байт, сборка и подпись дословно совпадают с документом; certHash', async () => {
        const raw = await M.signCert(vouchFields, { sig: A.sign });
        assert.strictEqual(raw.length, 271);
        assert.strictEqual(hex(raw), DOC_VOUCH_HEX);
        assert.strictEqual(hex(await M.certHash(raw)), '223d1c39a0fd74a64a86a6e4649fdd0df0ebddd44c09f08e79da336fcec49366');
        const parsed = M.parseCert(unhex(DOC_VOUCH_HEX));
        assert.strictEqual(parsed.ok, true);
        assert.strictEqual(parsed.cert.subjectId, J.id);
        assert.strictEqual(parsed.cert.actorId, A.id);
        assert.strictEqual(parsed.cert.snapN, 1);
        assert.deepStrictEqual(await M.verifyCertSignatures(parsed.cert), { ok: true });
    });

    await test('ключ приглашения из секрета (6.5): seed и invitePub; секрет не нормализуется', async () => {
        const secret = range(0, 16);
        assert.strictEqual(M.secretToBase64Url(secret), 'AAECAwQFBgcICQoLDA0ODw');
        const key = await M.inviteKeyFromSecret(secret);
        assert.strictEqual(hex(key.seed), '1e9ba1cb50667bc124a818354c89bf73a29ecf406409b9b1c18ce82344e9f6b4');
        assert.strictEqual(hex(key.invitePub), 'e5232aac92a5997fe3cb162de9975dae888e3f42c2d4b69004ad42ee91e093ec');
        assert.strictEqual(hex(M.secretFromBase64Url('AAECAwQFBgcICQoLDA0ODw')), hex(secret));
        // Регистр значим: «aaecawqfbgcicqolda0odw» — другие байты либо не секрет вовсе.
        const lower = M.secretFromBase64Url('aaecawqfbgcicqolda0odw');
        assert.ok(lower === null || hex(lower) !== hex(secret));
        // Неканоническая запись (лишние биты в последнем символе) и неверная длина.
        assert.strictEqual(M.secretFromBase64Url('AAECAwQFBgcICQoLDA0ODx'), null);
        assert.strictEqual(M.secretFromBase64Url('AAECAwQFBgcICQoLDA0OD'), null);
        assert.strictEqual(M.secretFromBase64Url('AAECAwQFBgcICQoLDA0ODw='), null);
        // Подпись ключом приглашения проверяется строгой проверкой.
        const msg = new Uint8Array([1, 2, 3]);
        assert.strictEqual(await M.strictVerify(key.invitePub, msg, await key.sign(msg)), true);
    });

    const inviteKey = await M.inviteKeyFromSecret(range(0, 16));
    const inviteFields = {
        kind: M.KIND.invite, roomId: ROOM, issuedMin: 29859060, nonce: range(0x20, 16),
        actorId: A.id, actorKey: A.signPub, ref: inviteKey.invitePub, expiresMin: 29869140, snapN: 1,
        snapHash: vouchFields.snapHash,
    };

    await test('invite 6.6: 335 байт, certHash; sig — identity A, sig2 — ключ приглашения', async () => {
        const raw = await M.signCert(inviteFields, { sig: A.sign, sig2: inviteKey.sign });
        assert.strictEqual(raw.length, 335);
        assert.strictEqual(hex(await M.certHash(raw)), '551d127b6380f8341ab3d4ed91e693525bd0d870b3c7236bb3388acd18d8e128');
        const parsed = M.parseCert(raw);
        assert.strictEqual(parsed.ok, true);
        assert.strictEqual(M.INVITE_MAX_MIN, 43200);
        assert.strictEqual(parsed.cert.expiresMin - parsed.cert.issuedMin, 10080, '+7 суток');
        assert.deepStrictEqual(await M.verifyCertSignatures(parsed.cert), { ok: true });
        // Подписи местами не годятся: sig должна быть от A, sig2 от ключа приглашения.
        const swapped = await M.signCert(inviteFields, { sig: inviteKey.sign, sig2: A.sign });
        assert.deepStrictEqual(await M.verifyCertSignatures(M.parseCert(swapped).cert), { ok: false, reason: 'sig' });
    });

    const inviteRaw = await M.signCert(inviteFields, { sig: A.sign, sig2: inviteKey.sign });
    const inviteHash = await M.certHash(inviteRaw);
    const joinFields = {
        kind: M.KIND.join, roomId: ROOM, issuedMin: ISSUED, nonce: range(0x30, 16),
        subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub,
        actorId: 0, actorKey: inviteKey.invitePub, ref: inviteHash,
    };

    await test('join 6.6: 335 байт, certHash; sig — ключ приглашения, sig2 — identity субъекта', async () => {
        const raw = await M.signCert(joinFields, { sig: inviteKey.sign, sig2: J.sign });
        assert.strictEqual(raw.length, 335);
        assert.strictEqual(hex(await M.certHash(raw)), 'c3ba2cfe8c68055ec00467f779ecb6035d3dade0a569077c947e908fe9971107');
        const parsed = M.parseCert(raw);
        assert.strictEqual(parsed.ok, true);
        assert.strictEqual(parsed.cert.actorId, 0);
        assert.strictEqual(parsed.cert.snapN, 0);
        assert.deepStrictEqual(await M.verifyCertSignatures(parsed.cert), { ok: true });
    });

    await test('revouch 6.6: 271 байт, ref — certHash исходного допуска', async () => {
        const vouchHash = unhex('223d1c39a0fd74a64a86a6e4649fdd0df0ebddd44c09f08e79da336fcec49366');
        const raw = await M.signCert({
            kind: M.KIND.revouch, roomId: ROOM, issuedMin: 29859123, nonce: range(0x40, 16),
            subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub, actorId: A.id, actorKey: A.signPub, ref: vouchHash,
        }, { sig: A.sign });
        assert.strictEqual(raw.length, 271);
        assert.strictEqual(hex(await M.certHash(raw)), 'dc839ea4627de0a283682eaf88fffdb3bd7cd3bd3f2f910fbe9a02eebcef260c');
        assert.deepStrictEqual(await M.verifyCertSignatures(M.parseCert(raw).cert), { ok: true });
    });

    await test('взгляд для {A, J} (6.3): ids и keys из 6.6; порядок по id; нулевой memkey у участника без ключей', async () => {
        const view = await M.viewHash([{ id: J.id, memkey: memJ }, { id: A.id, memkey: memA }]);
        assert.strictEqual(hex(view.ids), '0437270af5dc086352627bbc1681248f');
        assert.strictEqual(hex(view.keys), 'f24c74dafbd8636d26850a1e6e50e279');
        const noKeys = await M.viewHash([{ id: A.id, memkey: memA }, { id: J.id, memkey: null }]);
        const zeroed = await M.viewHash([{ id: A.id, memkey: memA }, { id: J.id, memkey: new Uint8Array(16) }]);
        assert.strictEqual(hex(noKeys.keys), hex(zeroed.keys));
        assert.strictEqual(hex(noKeys.ids), hex(view.ids), 'ids зависит только от состава');
        assert.notStrictEqual(hex(noKeys.keys), hex(view.keys));
    });

    // ---- Отрицательные векторы Ed25519 ----
    const ZERO_S_SIG = new Uint8Array(64); ZERO_S_SIG[0] = 1;
    const ONE = unhex('0100000000000000000000000000000000000000000000000000000000000000');
    const ONE_SIGN = unhex('0100000000000000000000000000000000000000000000000000000000000080');
    const platformVerify = async (pub, msg, sig) => {
        const key = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
        return crypto.subtle.verify({ name: 'Ed25519' }, key, sig, msg);
    };

    await test('отрицательные векторы 6.6: платформенный verify принимает оба, явная проверка membership отвергает оба', async () => {
        const msg = new TextEncoder().encode('любое сообщение');
        for (const key of [ONE, ONE_SIGN]) {
            assert.strictEqual(await platformVerify(key, msg, ZERO_S_SIG), true, 'платформа принимает ' + hex(key));
            assert.strictEqual(await M.strictVerify(key, msg, ZERO_S_SIG), false, 'membership отвергает ' + hex(key));
            assert.strictEqual(M.isStrictKey(key), false);
        }
    });

    await test('все восемь точек малого порядка, x = 0 при бите знака 1 и y ≥ p как ключ — отказ; S ≥ L — отказ; настоящие пары проходят', async () => {
        for (const e of strict.SMALL_ORDER_ENCODINGS) assert.strictEqual(M.isStrictKey(unhex(e)), false, e);
        for (const e of [hex(ONE_SIGN), 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f']) {
            assert.strictEqual(M.isStrictKey(unhex(e)), false, e);
        }
        const msg = new Uint8Array([9, 9, 9]);
        const good = await A.sign(msg);
        assert.strictEqual(await M.strictVerify(A.signPub, msg, good), true);
        const big = good.slice();
        // S + L > L: добавляем порядок группы к S (подпись остаётся математически верной, но неканонична).
        const L = (1n << 252n) + 27742317777372353535851937790883648493n;
        let s = 0n; for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(good[32 + i]);
        s += L;
        for (let i = 0; i < 32; i++) { big[32 + i] = Number(s & 0xffn); s >>= 8n; }
        assert.strictEqual(await M.strictVerify(A.signPub, msg, big), false, 'S ≥ L');
        for (let i = 0; i < 100; i++) {
            const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
            const pub = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32));
            const m = crypto.randomBytes(40);
            assert.strictEqual(await M.strictVerify(pub, m, new Uint8Array(crypto.sign(null, m, privateKey))), true);
        }
    });

    await test('сертификат с ключом малого порядка в подписывающей роли не проходит verifyCertSignatures (обе подписи «нулевые»)', async () => {
        for (const key of [ONE, ONE_SIGN]) {
            const body = M.encodeBody({ ...vouchFields, actorKey: key });
            const raw = M.concat(body, ZERO_S_SIG);
            const parsed = M.parseCert(raw);
            assert.strictEqual(parsed.ok, true);
            assert.deepStrictEqual(await M.verifyCertSignatures(parsed.cert), { ok: false, reason: 'key-strict' });
        }
        // Ключ субъекта малого порядка (подпись актора верна) — тоже отказ.
        const raw = await M.signCert({ ...vouchFields, subjectSignPub: ONE }, { sig: A.sign });
        assert.deepStrictEqual(await M.verifyCertSignatures(M.parseCert(raw).cert), { ok: false, reason: 'key-strict' });
        // Ключ приглашения малого порядка в invite.
        const inv = await M.signCert({ ...inviteFields, ref: ONE_SIGN }, { sig: A.sign, sig2: async () => ZERO_S_SIG });
        assert.deepStrictEqual(await M.verifyCertSignatures(M.parseCert(inv).cert), { ok: false, reason: 'key-strict' });
    });

    // ---- Форма сертификата ----
    await test('форма: длина вида, magic, вид; любая другая длина — отказ', async () => {
        const vouch = unhex(DOC_VOUCH_HEX);
        assert.strictEqual(M.parseCert(vouch.subarray(0, 270)).reason, 'length');
        assert.strictEqual(M.parseCert(M.concat(vouch, new Uint8Array(1))).reason, 'length');
        assert.strictEqual(M.parseCert(M.concat(vouch, new Uint8Array(64))).reason, 'length', 'vouch не бывает 335 байт');
        assert.strictEqual(M.parseCert(new Uint8Array(0)).reason, 'length');
        const badMagic = vouch.slice(); badMagic[0] ^= 1;
        assert.strictEqual(M.parseCert(badMagic).reason, 'magic');
        const badKind = vouch.slice(); badKind[8] = 9;
        assert.strictEqual(M.parseCert(badKind).reason, 'kind');
        // Вид invite с длиной vouch — длина не та.
        const asInvite = vouch.slice(); asInvite[8] = 2;
        assert.strictEqual(M.parseCert(asInvite).reason, 'length');
    });

    await test('форма: ненулевое неиспользуемое поле — отказ у каждого вида (М11)', async () => {
        const raws = {
            vouch: unhex(DOC_VOUCH_HEX),
            invite: inviteRaw,
            join: await M.signCert(joinFields, { sig: inviteKey.sign, sig2: J.sign }),
            revouch: await M.signCert({
                kind: M.KIND.revouch, roomId: ROOM, issuedMin: 1, nonce: range(0x40, 16),
                subjectId: J.id, subjectSignPub: J.signPub, subjectDhPub: J.dhPub, actorId: A.id, actorKey: A.signPub, ref: inviteHash,
            }, { sig: A.sign }),
        };
        for (const [name, raw] of Object.entries(raws)) assert.strictEqual(M.parseCert(raw).ok, true, name + ' исходный');
        const poke = (raw, off, v = 1) => { const c = raw.slice(); c[off] ^= v; return c; };
        // vouch: ref (137) и expiresMin (169)
        assert.strictEqual(M.parseCert(poke(raws.vouch, 140)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.vouch, 172)).reason, 'unused-fields');
        // invite: subjectId (33), subjectSignPub (37), subjectDhPub (69)
        assert.strictEqual(M.parseCert(poke(raws.invite, 36)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.invite, 40)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.invite, 90)).reason, 'unused-fields');
        // join: actorId (101), expiresMin (169), snapN (173), snapHash (175)
        assert.strictEqual(M.parseCert(poke(raws.join, 104)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.join, 172)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.join, 174)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.join, 180)).reason, 'unused-fields');
        // revouch: expiresMin, snapN, snapHash; ref нулевой — тоже отказ
        assert.strictEqual(M.parseCert(poke(raws.revouch, 170)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.revouch, 174)).reason, 'unused-fields');
        assert.strictEqual(M.parseCert(poke(raws.revouch, 200)).reason, 'unused-fields');
        const zeroRef = raws.revouch.slice(); zeroRef.fill(0, 137, 169);
        assert.strictEqual(M.parseCert(zeroRef).reason, 'unused-fields');
    });

    await test('форма: snapN = 0 у vouch/invite и snapN > 1024 — отказ; 1024 — можно', async () => {
        const make = async (kind, n) => M.parseCert(await M.signCert({ ...(kind === 1 ? vouchFields : inviteFields), snapN: n },
            kind === 1 ? { sig: A.sign } : { sig: A.sign, sig2: inviteKey.sign }));
        assert.strictEqual((await make(1, 0)).reason, 'snap-n');
        assert.strictEqual((await make(1, 1025)).reason, 'snap-n');
        assert.strictEqual((await make(1, 1024)).ok, true);
        assert.strictEqual((await make(2, 0)).reason, 'snap-n');
        assert.strictEqual((await make(2, 1025)).reason, 'snap-n');
    });

    await test('подпись одного вида не превращается в другой: kind входит в подписываемые байты', async () => {
        const raw = unhex(DOC_VOUCH_HEX);
        const asRevouch = raw.slice(); asRevouch[8] = 4;
        // revouch требует ref ≠ 0, поэтому форма отвергнет раньше; проверим подпись напрямую
        const forged = M.concat(M.encodeBody({ ...vouchFields, kind: 4, snapN: 0, snapHash: new Uint8Array(32), ref: fill(7, 32) }), raw.subarray(207, 271));
        const parsed = M.parseCert(forged);
        assert.strictEqual(parsed.ok, true);
        assert.deepStrictEqual(await M.verifyCertSignatures(parsed.cert), { ok: false, reason: 'sig' });
        // Другая комната — тоже другая подпись.
        const otherRoom = raw.slice(); otherRoom[12] ^= 1;
        assert.deepStrictEqual(await M.verifyCertSignatures(M.parseCert(otherRoom).cert), { ok: false, reason: 'sig' });
        // Подмена snapHash.
        const otherSnap = raw.slice(); otherSnap[180] ^= 1;
        assert.deepStrictEqual(await M.verifyCertSignatures(M.parseCert(otherSnap).cert), { ok: false, reason: 'sig' });
    });

    await test('base64: строгий разбор, мусор и неканоническая запись — null', () => {
        const raw = unhex(DOC_VOUCH_HEX);
        assert.deepStrictEqual(Array.from(M.fromB64(M.toB64(raw))), Array.from(raw));
        assert.strictEqual(M.fromB64('AAA'), null);
        assert.strictEqual(M.fromB64('AA=A'), null);
        assert.strictEqual(M.fromB64('AAB='), null, 'лишние биты перед заполнением');
        assert.strictEqual(M.fromB64(5), null);
        assert.deepStrictEqual(Array.from(M.fromB64('')), []);
    });

    await test('rank повторного допуска: определён списком сервера без X и A, не зависит от порядка списка, у разных X разный первый', async () => {
        const ids = [11, 22, 33, 44, 55, 66];
        const a = 66, x = 22;
        const ranks = [];
        for (const me of [11, 33, 44, 55]) ranks.push(await M.revouchRank(x, a, me, ids));
        assert.deepStrictEqual(ranks.slice().sort(), [0, 1, 2, 3]);
        const shuffled = ids.slice().reverse();
        for (const me of [11, 33, 44, 55]) assert.strictEqual(await M.revouchRank(x, a, me, shuffled), ranks[[11, 33, 44, 55].indexOf(me)]);
        assert.strictEqual(M.revouchDelayMin(0), 0);
        assert.strictEqual(M.revouchDelayMin(5), 10);
        assert.strictEqual(M.revouchDelayMin(900), 60, 'потолок: 30 рангов по 2 минуты');
        const firstFor = async (xx) => {
            const pool = ids.filter(id => id !== xx && id !== a);
            for (const me of pool) if ((await M.revouchRank(xx, a, me, ids)) === 0) return me;
        };
        const firsts = new Set();
        for (const xx of [11, 22, 33, 44, 55]) firsts.add(await firstFor(xx));
        assert.ok(firsts.size > 1, 'нагрузка по разным субъектам ложится на разных участников');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error(err); process.exitCode = 1; });
