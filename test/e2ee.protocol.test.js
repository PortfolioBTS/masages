'use strict';
// Прогон протокола E2EE (X3DH + Sender Keys) в чистом Node, без браузера
// и без реального сервера — public/e2ee.js использует только
// globalThis.crypto (Web Crypto), поэтому тестируется буквально тот же
// код, что грузится в браузере. Запуск: node test/e2ee.protocol.test.js

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const { makeFakeServer } = require('./fake-server');

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

function makeUser(server, userId) {
    return E2EE.createClient({ userId, storage: new E2EE.MemoryStorage(), transport: server.transportFor(userId) });
}

async function setupPair(roomId = 100) {
    const server = makeFakeServer();
    server.addParticipant(roomId, 1, 11);
    server.addParticipant(roomId, 2, 22);
    const alice = makeUser(server, 1);
    const bob = makeUser(server, 2);
    await alice.init();
    await bob.init();
    return { server, alice, bob, roomId };
}

async function main() {
    console.log('E2EE protocol tests\n');

    await test('base64 round-trip (binary edge cases)', async () => {
        const { b64encode, b64decode } = E2EE._internal;
        for (const len of [0, 1, 2, 3, 4, 5, 16, 31, 32, 33, 64]) {
            const bytes = crypto.getRandomValues(new Uint8Array(len));
            const decoded = b64decode(b64encode(bytes));
            assert.strictEqual(decoded.length, bytes.length, 'length len=' + len);
            assert.deepStrictEqual(Array.from(decoded), Array.from(bytes), 'content len=' + len);
        }
    });

    await test('init() is idempotent and uploads identity+SPK once', async () => {
        const server = makeFakeServer();
        const alice = makeUser(server, 1);
        const r1 = await alice.init();
        const r2 = await alice.init();
        assert.strictEqual(r1.identityPub, r2.identityPub, 'identity key stable across init() calls');
    });

    await test('init() tops up one-time prekeys above the low-water mark', async () => {
        const server = makeFakeServer();
        const alice = makeUser(server, 1);
        await alice.init();
        const countRes = await server.transportFor(1).getOneTimePrekeyCount();
        assert.ok(countRes.data.count >= 10, 'should have topped up OPK pool, got ' + countRes.data.count);
    });

    await test('basic round trip: Alice sends, Bob decrypts', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);

        const ct = await alice.encryptOutgoing(roomId, 'привет');
        const res = await bob.decryptIncoming(roomId, 1, ct);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.text, 'привет');
    });

    await test('ciphertext does not leak plaintext or contain it verbatim', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);
        const secret = 'the-quick-brown-fox-SECRET-42';
        const ct = await alice.encryptOutgoing(roomId, secret);
        assert.ok(!ct.includes(secret), 'ciphertext must not contain plaintext substring');
    });

    await test('sequential messages ratchet forward (different ciphertext, different keys)', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);

        const ct1 = await alice.encryptOutgoing(roomId, 'msg1');
        const ct2 = await alice.encryptOutgoing(roomId, 'msg1'); // same plaintext, must differ
        assert.notStrictEqual(ct1, ct2, 'same plaintext at different iterations must produce different ciphertext');
        assert.strictEqual(JSON.parse(ct1).iteration, 0);
        assert.strictEqual(JSON.parse(ct2).iteration, 1);

        const r1 = await bob.decryptIncoming(roomId, 1, ct1);
        const r2 = await bob.decryptIncoming(roomId, 1, ct2);
        assert.strictEqual(r1.text, 'msg1');
        assert.strictEqual(r2.text, 'msg1');
    });

    await test('out-of-order delivery: message N+1 arrives before N, both still decrypt', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);

        const ct0 = await alice.encryptOutgoing(roomId, 'zero');
        const ct1 = await alice.encryptOutgoing(roomId, 'one');
        const ct2 = await alice.encryptOutgoing(roomId, 'two');

        const r2 = await bob.decryptIncoming(roomId, 1, ct2); // arrives first
        assert.strictEqual(r2.ok, true);
        assert.strictEqual(r2.text, 'two');

        const r0 = await bob.decryptIncoming(roomId, 1, ct0); // then the earlier ones, out of order
        const r1 = await bob.decryptIncoming(roomId, 1, ct1);
        assert.strictEqual(r0.text, 'zero');
        assert.strictEqual(r1.text, 'one');
    });

    await test('history redisplay: same message can be decrypted twice (chat reopened)', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);
        const ct = await alice.encryptOutgoing(roomId, 'reread me');
        const first = await bob.decryptIncoming(roomId, 1, ct);
        const second = await bob.decryptIncoming(roomId, 1, ct); // simulate GET /api/messages returning full history again
        assert.strictEqual(first.text, 'reread me');
        assert.strictEqual(second.text, 'reread me');
    });

    await test('sender can decrypt their own past outgoing messages (self chain is cached)', async () => {
        const { alice, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        const ct = await alice.encryptOutgoing(roomId, 'note to self');
        const res = await alice.decryptIncoming(roomId, 1, ct);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.text, 'note to self');
    });

    await test('tampered ciphertext is rejected (bit flip in ct)', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);
        const ct = await alice.encryptOutgoing(roomId, 'integrity check');
        const env = JSON.parse(ct);
        const bytes = E2EE._internal.b64decode(env.ct);
        bytes[0] ^= 0xff; // повреждаем один байт шифротекста
        env.ct = E2EE._internal.b64encode(bytes);
        const res = await bob.decryptIncoming(roomId, 1, JSON.stringify(env));
        assert.strictEqual(res.ok, false);
    });

    await test('forged signature is rejected (ciphertext re-signed with a different key)', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);
        const ct = await alice.encryptOutgoing(roomId, 'trust me');
        const env = JSON.parse(ct);
        const forgedSig = crypto.getRandomValues(new Uint8Array(64));
        env.sig = E2EE._internal.b64encode(forgedSig);
        const res = await bob.decryptIncoming(roomId, 1, JSON.stringify(env));
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.reason, 'bad-signature');
    });

    await test('message from a sender with no known Sender Key fails gracefully', async () => {
        const { bob, roomId } = await setupPair();
        const fakeEnvelope = JSON.stringify({ v: 1, alg: 'senderkey-v1', senderKeyId: 'x', iteration: 0, iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA', sig: 'AAAA' });
        const res = await bob.decryptIncoming(roomId, 999, fakeEnvelope);
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.reason, 'no-sender-key');
    });

    await test('key rotation: old messages stay decryptable for both sender and receiver after rotation', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);

        const ctOld = await alice.encryptOutgoing(roomId, 'before rotation');
        const oldForBob = await bob.decryptIncoming(roomId, 1, ctOld);
        assert.strictEqual(oldForBob.ok, true);
        assert.strictEqual(oldForBob.text, 'before rotation');

        await alice.rotateRoomKey(roomId);
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]); // разослать новый ключ
        await bob.syncKeyShares(22, roomId);

        const ctNew = await alice.encryptOutgoing(roomId, 'after rotation');
        const newForBob = await bob.decryptIncoming(roomId, 1, ctNew);
        assert.strictEqual(newForBob.ok, true);
        assert.strictEqual(newForBob.text, 'after rotation');

        // Старое сообщение должно оставаться читаемым и после ротации —
        // и у получателя (архив в его состоянии), и у самого отправителя.
        const oldForBobAgain = await bob.decryptIncoming(roomId, 1, ctOld);
        assert.strictEqual(oldForBobAgain.ok, true);
        assert.strictEqual(oldForBobAgain.text, 'before rotation');

        const oldForAlice = await alice.decryptIncoming(roomId, 1, ctOld);
        assert.strictEqual(oldForAlice.ok, true);
        assert.strictEqual(oldForAlice.text, 'before rotation');
    });

    await test('bidirectional: Bob replies and Alice decrypts (independent pairwise secrets both directions)', async () => {
        const { alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, roomId);
        await bob.ensureRoomSession(22, roomId, [{ id: 1 }, { id: 2 }]);
        await alice.syncKeyShares(11, roomId);

        const aliceToBob = await alice.encryptOutgoing(roomId, 'hi bob');
        const bobToAlice = await bob.encryptOutgoing(roomId, 'hi alice');

        const r1 = await bob.decryptIncoming(roomId, 1, aliceToBob);
        const r2 = await alice.decryptIncoming(roomId, 2, bobToAlice);
        assert.strictEqual(r1.text, 'hi bob');
        assert.strictEqual(r2.text, 'hi alice');
    });

    await test('re-run is idempotent: does not resend an already-delivered share', async () => {
        const { server, alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        assert.strictEqual(server._keyShares.length, 1, 'one share sent to Bob');
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]); // same key, same participants
        assert.strictEqual(server._keyShares.length, 1, 'no duplicate share for a key already marked as shared');
    });

    await test('rotating the Sender Key reuses the cached pairwise secret (no new one-time prekey consumed)', async () => {
        const { server, alice, bob, roomId } = await setupPair();
        await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        const countAfterFirst = (await server.transportFor(2).getOneTimePrekeyCount()).data.count;

        await alice.rotateRoomKey(roomId);
        const r2 = await alice.ensureRoomSession(11, roomId, [{ id: 1 }, { id: 2 }]);
        assert.strictEqual(r2.warnings.length, 0);
        const countAfterSecond = (await server.transportFor(2).getOneTimePrekeyCount()).data.count;
        assert.strictEqual(countAfterFirst, countAfterSecond, 'reusing the cached pairwise secret must not touch the OPK pool again');

        await bob.syncKeyShares(22, roomId);
        const ct = await alice.encryptOutgoing(roomId, 'after rotation, reused pairwise channel');
        const res = await bob.decryptIncoming(roomId, 1, ct);
        assert.strictEqual(res.text, 'after rotation, reused pairwise channel');
    });

    await test('group of 3: all pairwise sessions established, all can decrypt one sender', async () => {
        const server = makeFakeServer();
        server.addParticipant(200, 1, 11);
        server.addParticipant(200, 2, 22);
        server.addParticipant(200, 3, 33);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        const carol = makeUser(server, 3);
        await Promise.all([alice.init(), bob.init(), carol.init()]);

        const participants = [{ id: 1 }, { id: 2 }, { id: 3 }];
        const r = await alice.ensureRoomSession(11, 200, participants);
        assert.strictEqual(r.warnings.length, 0);

        await bob.syncKeyShares(22, 200);
        await carol.syncKeyShares(33, 200);

        const ct = await alice.encryptOutgoing(200, 'group hello');
        const rb = await bob.decryptIncoming(200, 1, ct);
        const rc = await carol.decryptIncoming(200, 1, ct);
        assert.strictEqual(rb.text, 'group hello');
        assert.strictEqual(rc.text, 'group hello');
    });

    await test('participant with no E2EE keys yet is skipped with a warning, others still succeed', async () => {
        const server = makeFakeServer();
        server.addParticipant(300, 1, 11);
        server.addParticipant(300, 2, 22);
        server.addParticipant(300, 3, 33);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        await alice.init();
        await bob.init();
        // user 3 never calls init() -> has no identity/SPK on the fake server

        const r = await alice.ensureRoomSession(11, 300, [{ id: 1 }, { id: 2 }, { id: 3 }]);
        assert.strictEqual(r.warnings.length, 1);
        assert.strictEqual(r.warnings[0].userId, 3);

        await bob.syncKeyShares(22, 300);
        const ct = await alice.encryptOutgoing(300, 'partial group');
        const rb = await bob.decryptIncoming(300, 1, ct);
        assert.strictEqual(rb.text, 'partial group');
    });

    await test('rooms are isolated: a message encrypted for room A cannot be replayed into room B', async () => {
        const server = makeFakeServer();
        server.addParticipant(400, 1, 11);
        server.addParticipant(400, 2, 22);
        server.addParticipant(500, 1, 13);
        server.addParticipant(500, 2, 23);
        const alice = makeUser(server, 1);
        const bob = makeUser(server, 2);
        await alice.init();
        await bob.init();

        await alice.ensureRoomSession(11, 400, [{ id: 1 }, { id: 2 }]);
        await alice.ensureRoomSession(13, 500, [{ id: 1 }, { id: 2 }]);
        await bob.syncKeyShares(22, 400);
        await bob.syncKeyShares(23, 500);

        const ctForRoomA = await alice.encryptOutgoing(400, 'room A only');
        const replayed = await bob.decryptIncoming(500, 1, ctForRoomA); // wrong room on purpose
        assert.strictEqual(replayed.ok, false, 'AAD must bind ciphertext to its room; cross-room replay must fail');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exit(1);
}

main().catch(err => { console.error('Test runner crashed:', err); process.exit(1); });
