'use strict';
// Одноразовые PQ-prekey в протоколе E2EE (PQXDH): клиент public/e2ee.js против
// fake-server с настоящей проверкой подписей. Подписываемые байты здесь
// собираются независимо от клиента (BigInt, свой литерал метки).
// Запуск: node test/pq-prekeys.protocol.test.js

// ML-KEM в Node WebCrypto экспериментальный и шумит предупреждениями — глушим только их.
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const mlkem = require('../public/mlkem.js');
const { makeFakeServer } = require('./fake-server');

const subtle = globalThis.crypto.subtle;
const { b64encode: b64, b64decode: unb64, PREKEY_RETAIN_MS, PQ_OPK_REFRESH_MS, LOW_WATER_PQ_OPK, TOPUP_PQ_OPK, PQ_OPK_BATCH } = E2EE._internal;
const DAY = 24 * 60 * 60 * 1000;

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

// ===================== Хелперы =====================

// Подписываемые байты: 'nyxo-pqopk-v1' + NUL, u64be(key_id), ключ.
function labelled(keyId, publicKey) {
    const id = Buffer.alloc(8);
    id.writeBigUInt64BE(BigInt(keyId));
    return new Uint8Array(Buffer.concat([Buffer.from('nyxo-pqopk-v1\0', 'utf8'), id, Buffer.from(publicKey)]));
}

async function verifyEd25519(signPubB64, sigB64, data) {
    const key = await subtle.importKey('raw', unb64(signPubB64), { name: 'Ed25519' }, false, ['verify']);
    return subtle.verify('Ed25519', key, unb64(sigB64), data);
}

function makeUser(server, userId, opts = {}) {
    const storage = opts.storage || new E2EE.MemoryStorage();
    const client = E2EE.createClient({
        userId, storage,
        transport: opts.transport || server.transportFor(userId),
        kem: opts.kem || mlkem,
        now: opts.now,
    });
    client._storage = storage;
    return client;
}

// Комната 100: Alice (1), Bob (2), Carol (3); чаты 11, 22, 33.
async function trio(opts = {}) {
    const server = makeFakeServer();
    for (const [id, chat] of [[1, 11], [2, 22], [3, 33]]) server.addParticipant(100, id, chat);
    const clients = {};
    for (const id of [1, 2, 3]) clients[id] = makeUser(server, id, opts.byUser && opts.byUser[id] ? opts.byUser[id] : opts);
    if (!opts.skipInit) for (const id of [1, 2, 3]) await clients[id].init();
    return {
        server, alice: clients[1], bob: clients[2], carol: clients[3],
        withAlice: [{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }],
        withCarol: [{ id: 3, username: 'carol' }, { id: 2, username: 'bob' }],
    };
}

let messageCounter = 7000000;
async function assertMessage(sender, receiver, senderId, text) {
    const messageId = String(++messageCounter);
    const ct = await sender.encryptOutgoing(100, text, { messageId });
    const res = await receiver.decryptIncoming(100, senderId, ct, messageId);
    assert.strictEqual(res.ok, true, JSON.stringify(res));
    assert.strictEqual(res.text, text);
}

const initOf = (share) => JSON.parse(share.ciphertext).init;

// Числовые имена pqopk:<id> (без служебной pqopk:refreshedAt).
async function pqSeeds(client) {
    return (await client._storage.keys('pqopk:')).filter(n => /^pqopk:\d+$/.test(n));
}
const pqPoolIds = (server, userId) => Array.from((server._pqOneTimePrekeys.get(userId) || new Map()).keys());

// Перехват console.warn: предупреждение о пуле — штатное, тест проверяет его.
async function withWarnings(fn) {
    const original = console.warn;
    const seen = [];
    console.warn = (...args) => seen.push(args.join(' '));
    try { await fn(seen); } finally { console.warn = original; }
}

// Транспорт Alice, который правит bundle до того, как клиент его увидит.
function tamperingTransport(server, userId, mutate) {
    const t = server.transportFor(userId);
    const real = t.getBundle;
    t.getBundle = async (id) => {
        const res = await real(id);
        if (res.status === 200) mutate(res.data);
        return res;
    };
    return t;
}

// Тройка, где Alice видит bundle Bob после правки mutate (сервер ничего не знает).
async function trioTampered(mutate) {
    const ctx = await trio({ skipInit: true });
    ctx.alice = makeUser(ctx.server, 1, { transport: tamperingTransport(ctx.server, 1, mutate) });
    await ctx.alice.init();
    await ctx.bob.init();
    return ctx;
}

// ===================== Тесты =====================

async function main() {
    console.log('One-time PQ prekeys: client protocol\n');

    // ---- 1. Пул и подписи ----

    await test('init() uploads a pool of 20 in batches of 10; the label signature verifies, the raw-bytes one does not', async () => {
        const server = makeFakeServer();
        const t = server.transportFor(1);
        const batches = [];
        const realPost = t.postPqOneTimePrekeys;
        t.postPqOneTimePrekeys = async (body) => { batches.push(body.keys.length); return realPost(body); };
        const alice = makeUser(server, 1, { transport: t });
        const { signPub } = await alice.init();
        assert.deepStrictEqual(batches, [PQ_OPK_BATCH, PQ_OPK_BATCH]);
        assert.strictEqual(TOPUP_PQ_OPK, 20);
        const pool = server._pqOneTimePrekeys.get(1);
        assert.strictEqual(pool.size, 20);
        assert.ok(pool.size >= LOW_WATER_PQ_OPK);
        for (const key of pool.values()) {
            const pk = unb64(key.public_key);
            assert.strictEqual(pk.length, 1184);
            assert.ok(await verifyEd25519(signPub, key.signature, labelled(key.key_id, pk)), 'label signature');
            assert.ok(!(await verifyEd25519(signPub, key.signature, pk)), 'it is not a raw-bytes signature');
            assert.ok(!(await verifyEd25519(signPub, key.signature, labelled(key.key_id + 1, pk))), 'bound to its key_id');
        }
        // Секреты — на устройстве, по одному семени на ключ.
        const seeds = await pqSeeds(alice);
        assert.deepStrictEqual(seeds.map(n => Number(n.slice(6))).sort((a, b) => a - b), [...pool.keys()].sort((a, b) => a - b));
        const rec = await alice._storage.get(seeds[0]);
        assert.strictEqual(unb64(rec.seed).length, 64);
        assert.strictEqual(typeof rec.createdAt, 'number');
        assert.strictEqual(rec.retiredAt, undefined);
    });

    await test('a repeated init() with a full pool uploads nothing and creates no seeds', async () => {
        const server = makeFakeServer();
        const alice = makeUser(server, 1);
        await alice.init();
        const ids = pqPoolIds(server, 1);
        const seeds = await pqSeeds(alice);
        await alice.init();
        await alice.init();
        assert.deepStrictEqual(pqPoolIds(server, 1), ids);
        assert.deepStrictEqual(await pqSeeds(alice), seeds);
    });

    await test('key_id above 2^32 is signed as u64be (the high word is not lost)', async () => {
        const server = makeFakeServer();
        const storage = new E2EE.MemoryStorage();
        await storage.set('nextKeyId', 2 ** 32 + 10);
        const alice = makeUser(server, 1, { storage });
        await alice.init();
        const ids = pqPoolIds(server, 1);
        assert.strictEqual(ids.length, 20);
        assert.ok(ids.every(id => id > 2 ** 32), 'ids really are above 2^32');
    });

    // ---- 2. Использование ключа ----

    await test('ensureRoomSession spends one PQ one-time prekey; the header says pqOneTime; the recipient applies the share and deletes the seed', async () => {
        const ctx = await trio();
        const pool = pqPoolIds(ctx.server, 2);
        const first = pool[0];
        assert.ok(await ctx.bob._storage.get('pqopk:' + first));
        const r = await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.deepStrictEqual(r.warnings, []);
        assert.deepStrictEqual(pqPoolIds(ctx.server, 2), pool.slice(1), 'the server handed out the first key (FIFO)');
        const init = initOf(ctx.server._keyShares[0]);
        assert.strictEqual(init.pqOneTime, true);
        assert.strictEqual(init.usedPqPrekeyId, first);
        assert.notStrictEqual(init.usedOneTimePrekeyId, null, 'together with the classical one-time prekey');
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
        assert.strictEqual(await ctx.bob._storage.get('pqopk:' + first), null, 'the seed is gone after the use');
        assert.strictEqual((await pqSeeds(ctx.bob)).length, 19);
        assert.ok(await ctx.bob._storage.get('pqpk'), 'the last-resort key is untouched');
        await assertMessage(ctx.alice, ctx.bob, 1, 'после одноразового PQ-prekey');
    });

    await test('an empty pool falls back to the last-resort key: no pqOneTime in the header, everything works', async () => {
        const ctx = await trio();
        ctx.server._pqOneTimePrekeys.get(2).clear();
        const r = await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.deepStrictEqual(r.warnings, []);
        const init = initOf(ctx.server._keyShares[0]);
        assert.strictEqual('pqOneTime' in init, false);
        assert.strictEqual(init.usedPqPrekeyId, ctx.server._pqPrekeys.get(2).key_id);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
        await assertMessage(ctx.alice, ctx.bob, 1, 'через запасной ключ');
        assert.strictEqual((await pqSeeds(ctx.bob)).length, 20, 'no one-time seed spent');
    });

    await test('the pool running out in the middle of a group: the first initiators get one-time keys, the rest the last-resort one', async () => {
        const ctx = await trio();
        const pool = ctx.server._pqOneTimePrekeys.get(2);
        for (const id of [...pool.keys()].slice(1)) pool.delete(id); // остался один
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        await ctx.carol.ensureRoomSession(33, 100, ctx.withCarol);
        const inits = ctx.server._keyShares.map(initOf);
        assert.deepStrictEqual(inits.map(i => i.pqOneTime === true), [true, false]);
        const r = await ctx.bob.syncKeyShares(22, 100);
        assert.deepStrictEqual([r.applied, r.failed], [2, 0]);
        await assertMessage(ctx.alice, ctx.bob, 1, 'от Alice');
        await assertMessage(ctx.carol, ctx.bob, 3, 'от Carol');
    });

    // ---- 3. Одноразовость ----

    await test('one PQ key handed to two initiators: the first share applies, the second is rejected, nothing else burns', async () => {
        const ctx = await trio();
        ctx.server.evil.reusePqOneTime(2);
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        await ctx.carol.ensureRoomSession(33, 100, ctx.withCarol);
        const [a, c] = ctx.server._keyShares.map(initOf);
        assert.strictEqual(a.usedPqPrekeyId, c.usedPqPrekeyId, 'the malicious server reused the key');
        assert.notStrictEqual(a.usedOneTimePrekeyId, c.usedOneTimePrekeyId);
        const r = await ctx.bob.syncKeyShares(22, 100);
        assert.deepStrictEqual([r.applied, r.failed], [1, 1]);
        assert.strictEqual((await pqSeeds(ctx.bob)).length, 19, 'only the used seed is gone');
        assert.ok(await ctx.bob._storage.get('pqpk'), 'last-resort untouched');
        assert.ok(await ctx.bob._storage.get('opk:' + c.usedOneTimePrekeyId), 'the classical key of the rejected share is not burned');
        assert.strictEqual(await ctx.bob._storage.get('opk:' + a.usedOneTimePrekeyId), null);
        await assertMessage(ctx.alice, ctx.bob, 1, 'Alice принята');
    });

    await test('a replayed delivered share is rejected and the session keeps working', async () => {
        const ctx = await trio();
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
        ctx.server.evil.replayDeliveredKeyShare(0);
        const r = await ctx.bob.syncKeyShares(22, 100);
        assert.deepStrictEqual([r.applied, r.failed], [0, 1]);
        await assertMessage(ctx.alice, ctx.bob, 1, 'после повтора');
    });

    await test('a forged share (flipped bit in pqCiphertext or in the AEAD part) does not burn the PQ key; the real share restores the session', async () => {
        const ctx = await trio();
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        const original = ctx.server._keyShares.splice(0, 1)[0];
        const used = initOf(original).usedPqPrekeyId;
        const flipped = (mutate) => {
            const env = JSON.parse(original.ciphertext);
            mutate(env);
            return JSON.stringify(env);
        };
        const forgeries = [
            flipped(env => { const ct = unb64(env.init.pqCiphertext); ct[10] ^= 1; env.init.pqCiphertext = b64(ct); }),
            flipped(env => { const ct = unb64(env.ct); ct[0] ^= 1; env.ct = b64(ct); }),
        ];
        for (const ciphertext of forgeries) {
            ctx.server.evil.injectKeyShare({ roomId: 100, senderId: 1, recipientId: 2, ciphertext });
        }
        const bad = await ctx.bob.syncKeyShares(22, 100);
        assert.deepStrictEqual([bad.applied, bad.failed], [0, 2]);
        assert.ok(await ctx.bob._storage.get('pqopk:' + used), 'the one-time seed survived the forgeries');
        ctx.server.evil.injectKeyShare({ roomId: 100, senderId: 1, recipientId: 2, ciphertext: original.ciphertext });
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
        assert.strictEqual(await ctx.bob._storage.get('pqopk:' + used), null, 'the real share spent it');
        await assertMessage(ctx.alice, ctx.bob, 1, 'сессия восстановлена');
    });

    await test('a key of one role is never taken for the other: the pqOneTime flag decides where the secret is looked up', async () => {
        const ctx = await trio();
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        const original = ctx.server._keyShares.splice(0, 1)[0];
        const used = initOf(original).usedPqPrekeyId;
        const lastResortId = ctx.server._pqPrekeys.get(2).key_id;
        const variants = [
            (env) => { delete env.init.pqOneTime; },                                     // одноразовый ключ как запасной
            (env) => { env.init.pqOneTime = false; },
            (env) => { env.init.pqOneTime = 'true'; },                                   // не булево true
            (env) => { env.init.usedPqPrekeyId = lastResortId; },                        // запасной id с флагом одноразового
        ];
        for (const mutate of variants) {
            const env = JSON.parse(original.ciphertext);
            mutate(env);
            ctx.server.evil.injectKeyShare({ roomId: 100, senderId: 1, recipientId: 2, ciphertext: JSON.stringify(env) });
        }
        const r = await ctx.bob.syncKeyShares(22, 100);
        assert.deepStrictEqual([r.applied, r.failed], [0, 4]);
        assert.ok(await ctx.bob._storage.get('pqopk:' + used), 'not burned');
        ctx.server.evil.injectKeyShare({ roomId: 100, senderId: 1, recipientId: 2, ciphertext: original.ciphertext });
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
    });

    await test('the one-time secret key is zeroed after decapsulation; the cached last-resort one is not', async () => {
        const captured = [];
        const spyKem = {
            keygen: (seed) => mlkem.keygen(seed),
            encapsulate: (pk) => mlkem.encapsulate(pk),
            decapsulate: (sk, ct) => { captured.push(sk); return mlkem.decapsulate(sk, ct); },
        };
        const ctx = await trio({ byUser: { 2: { kem: spyKem } } });
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
        assert.strictEqual(captured.length, 1);
        assert.ok(captured[0].every(b => b === 0), 'one-time secret key wiped');
        // Запасной ключ: Carol приходит, когда одноразовых не осталось.
        ctx.server._pqOneTimePrekeys.get(2).clear();
        await ctx.carol.ensureRoomSession(33, 100, ctx.withCarol);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
        assert.strictEqual(captured.length, 2);
        assert.ok(captured[1].some(b => b !== 0), 'the cached last-resort key is intact');
    });

    // ---- 4. Подмена сервером ----

    await test('a bad signature on the one-time key (random, other key_id, other public key, missing) → loud refusal, no share, no fallback', async () => {
        const cases = {
            'random signature': (b) => { b.pq_one_time_prekey.signature = b64(globalThis.crypto.getRandomValues(new Uint8Array(64))); },
            'signature of another key_id': (b) => { b.pq_one_time_prekey.key_id += 1; },
            'another public key': (b) => { b.pq_one_time_prekey.public_key = b64(mlkem.keygen(globalThis.crypto.getRandomValues(new Uint8Array(64))).publicKey); },
        };
        for (const [what, mutate] of Object.entries(cases)) {
            const ctx = await trioTampered(mutate);
            const r = await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
            assert.strictEqual(r.warnings.length, 1, what);
            assert.match(r.warnings[0].reason, /неверная подпись одноразового PQ-prekey у пользователя 2/, what);
            assert.match(r.warnings[0].reason, /подмен/, what);
            assert.strictEqual(ctx.server._keyShares.length, 0, what + ': nothing was sent');
        }
        const ctx = await trioTampered((b) => { delete b.pq_one_time_prekey.signature; });
        const r = await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.match(r.warnings[0].reason, /некорректный одноразовый PQ-prekey/);
        assert.strictEqual(ctx.server._keyShares.length, 0);
    });

    await test('a garbage one-time key (wrong length) is refused the same way', async () => {
        const ctx = await trioTampered((b) => { b.pq_one_time_prekey.public_key = b64(new Uint8Array(1183)); });
        const r = await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.match(r.warnings[0].reason, /некорректный одноразовый PQ-prekey/);
        assert.strictEqual(ctx.server._keyShares.length, 0);
    });

    await test('role swap in both directions is refused: a one-time key as last-resort and a last-resort key as one-time', async () => {
        const asLastResort = await trio();
        asLastResort.server.evil.relabelPqOneTimeAsLastResort(2);
        let r = await asLastResort.alice.ensureRoomSession(11, 100, asLastResort.withAlice);
        assert.strictEqual(r.warnings.length, 1);
        assert.match(r.warnings[0].reason, /неверная подпись PQ-prekey у пользователя 2/);
        assert.strictEqual(asLastResort.server._keyShares.length, 0);

        const asOneTime = await trio();
        asOneTime.server.evil.relabelLastResortAsPqOneTime(2);
        r = await asOneTime.alice.ensureRoomSession(11, 100, asOneTime.withAlice);
        assert.strictEqual(r.warnings.length, 1);
        assert.match(r.warnings[0].reason, /неверная подпись одноразового PQ-prekey у пользователя 2/);
        assert.strictEqual(asOneTime.server._keyShares.length, 0);
    });

    await test('a server that cuts the one-time key only downgrades to last-resort (no worse than before); cutting every PQ key is refused', async () => {
        const stripped = await trio();
        stripped.server.evil.stripPqOneTime(2);
        let r = await stripped.alice.ensureRoomSession(11, 100, stripped.withAlice);
        assert.deepStrictEqual(r.warnings, []);
        assert.strictEqual('pqOneTime' in initOf(stripped.server._keyShares[0]), false);
        assert.strictEqual((await stripped.bob.syncKeyShares(22, 100)).applied, 1);
        await assertMessage(stripped.alice, stripped.bob, 1, 'last-resort');

        const hidden = await trio();
        hidden.server.evil.hidePqPrekey(2);
        r = await hidden.alice.ensureRoomSession(11, 100, hidden.withAlice);
        assert.deepStrictEqual(r.warnings, [{ userId: 2, reason: 'у собеседника устаревшая версия E2EE' }]);
        assert.strictEqual(hidden.server._keyShares.length, 0, 'no fallback to classic X3DH');
    });

    // ---- 5. Старый сервер и сбои загрузки ----

    await test('a server without the new field/routes works: no pool is uploaded, the initiator uses last-resort', async () => {
        const server = makeFakeServer();
        for (const [id, chat] of [[1, 11], [2, 22]]) server.addParticipant(100, id, chat);
        // Bob за «старым» сервером: счётчик без pq_count, маршрутов пула нет.
        const legacy = server.transportFor(2);
        const realCount = legacy.getOneTimePrekeyCount;
        legacy.getOneTimePrekeyCount = async () => { const res = await realCount(); delete res.data.pq_count; return res; };
        delete legacy.postPqOneTimePrekeys;
        delete legacy.deletePqOneTimePrekeys;
        const bob = makeUser(server, 2, { transport: legacy });
        const alice = makeUser(server, 1);
        await alice.init();
        await bob.init();
        assert.strictEqual(server._pqOneTimePrekeys.get(2), undefined);
        assert.strictEqual((await pqSeeds(bob)).length, 0);
        const r = await alice.ensureRoomSession(11, 100, [{ id: 1 }, { id: 2 }]);
        assert.deepStrictEqual(r.warnings, []);
        assert.strictEqual('pqOneTime' in initOf(server._keyShares[0]), false);
        assert.strictEqual((await bob.syncKeyShares(22, 100)).applied, 1);
        await assertMessage(alice, bob, 1, 'старый сервер');

        // Только count без pq_count при наличии методов транспорта: пул не создаётся.
        const server2 = makeFakeServer();
        const t = server2.transportFor(1);
        const realCount2 = t.getOneTimePrekeyCount;
        t.getOneTimePrekeyCount = async () => { const res = await realCount2(); delete res.data.pq_count; return res; };
        let posts = 0;
        const realPost = t.postPqOneTimePrekeys;
        t.postPqOneTimePrekeys = async (b) => { posts++; return realPost(b); };
        await makeUser(server2, 1, { transport: t }).init();
        assert.strictEqual(posts, 0);
    });

    await test('a bundle without the pq_one_time_prekey field (old server) is read as "none": last-resort', async () => {
        const ctx = await trioTampered((b) => { delete b.pq_one_time_prekey; });
        const r = await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        assert.deepStrictEqual(r.warnings, []);
        assert.strictEqual('pqOneTime' in initOf(ctx.server._keyShares[0]), false);
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1);
    });

    await test('upload failure: an explicit refusal deletes the new seeds, a network error keeps them; init() itself does not fail', async () => {
        // Явный отказ на первой пачке: ни у сервера, ни на устройстве нет ключей.
        let server = makeFakeServer();
        server.failNextPqUpload('refuse');
        let alice = makeUser(server, 1);
        await withWarnings(async (seen) => {
            await alice.init();
            assert.strictEqual(seen.length, 1);
            assert.match(seen[0], /пул одноразовых PQ-prekey не пополнен/);
        });
        assert.strictEqual((await pqSeeds(alice)).length, 0);
        assert.strictEqual(server._pqOneTimePrekeys.get(1), undefined);
        await alice.init(); // следующий init пополняет пул
        assert.strictEqual(pqPoolIds(server, 1).length, 20);
        assert.strictEqual((await pqSeeds(alice)).length, 20);

        // Отказ на второй пачке: остаются семена принятой пачки.
        server = makeFakeServer();
        server.failNextPqUpload('refuse', 1);
        alice = makeUser(server, 1);
        await withWarnings(() => alice.init());
        const accepted = pqPoolIds(server, 1);
        assert.strictEqual(accepted.length, 10);
        assert.deepStrictEqual((await pqSeeds(alice)).map(n => Number(n.slice(6))).sort((a, b) => a - b), accepted.slice().sort((a, b) => a - b));

        // Сетевая ошибка: сервер мог принять пачку, поэтому все семена остаются.
        server = makeFakeServer();
        server.failNextPqUpload('network');
        alice = makeUser(server, 1);
        await withWarnings(() => alice.init());
        assert.strictEqual(server._pqOneTimePrekeys.get(1), undefined);
        assert.strictEqual((await pqSeeds(alice)).length, 20);
    });

    // ---- 6. Пополнение и обновление пула ----

    await test('the pool is topped up when fewer than 5 remain, and left alone at 5', async () => {
        const server = makeFakeServer();
        const bob = makeUser(server, 2);
        await bob.init();
        const pool = server._pqOneTimePrekeys.get(2);
        for (const id of [...pool.keys()].slice(0, 15)) pool.delete(id); // осталось 5
        await bob.init();
        assert.strictEqual(pool.size, 5, 'at the low-water mark nothing is added');
        pool.delete(pool.keys().next().value); // осталось 4
        await bob.init();
        assert.strictEqual(pool.size, TOPUP_PQ_OPK, 'topped up to 20');
    });

    await test('new identity registration wipes every local opk:* and pqopk:* (and the server pools are rebuilt)', async () => {
        const server = makeFakeServer();
        const alice = makeUser(server, 1);
        await alice.init();
        const oldOpk = await alice._storage.keys('opk:');
        const oldPq = await pqSeeds(alice);
        assert.ok(oldOpk.length > 0 && oldPq.length === 20);
        await alice._storage.delete('up:identity'); // как после установки с новой identity
        await alice.init();
        const newOpk = await alice._storage.keys('opk:');
        const newPq = await pqSeeds(alice);
        assert.ok(newOpk.length > 0 && newPq.length === 20, 'pools rebuilt');
        assert.deepStrictEqual(oldOpk.filter(n => newOpk.includes(n)), [], 'no old classical seed survived');
        assert.deepStrictEqual(oldPq.filter(n => newPq.includes(n)), [], 'no old PQ seed survived');
        assert.deepStrictEqual(pqPoolIds(server, 1).map(id => 'pqopk:' + id).sort(), newPq.slice().sort(), 'server pool = local seeds');
    });

    await test('the pool is replaced every 30 days: server pool wiped and refilled, old seeds retired and kept for 14 days', async () => {
        const clock = { t: 1700000000000 };
        const ctx = await trio({ now: () => clock.t });
        const oldIds = pqPoolIds(ctx.server, 2);
        assert.strictEqual(await ctx.bob._storage.get('pqopk:refreshedAt'), clock.t);

        // Alice берёт bundle сейчас (ключ из старого пула), а Bob заберёт share позже.
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        const usedOld = initOf(ctx.server._keyShares[0]).usedPqPrekeyId;
        assert.ok(oldIds.includes(usedOld));

        // На 29-й день замены ещё нет.
        clock.t += 29 * DAY;
        await ctx.bob.init();
        assert.deepStrictEqual(pqPoolIds(ctx.server, 2), oldIds.filter(id => id !== usedOld), 'not due yet: the pool is untouched');

        // На 31-й — замена.
        clock.t += 2 * DAY;
        const replacedAt = clock.t;
        await ctx.bob.init();
        const poolNow = pqPoolIds(ctx.server, 2);
        assert.strictEqual(poolNow.length, TOPUP_PQ_OPK);
        assert.deepStrictEqual(poolNow.filter(id => oldIds.includes(id)), [], 'the server holds only new keys');
        assert.strictEqual(await ctx.bob._storage.get('pqopk:refreshedAt'), replacedAt);
        const retired = await ctx.bob._storage.get('pqopk:' + usedOld);
        assert.strictEqual(retired.retiredAt, replacedAt, 'old seed is retired, not deleted');
        for (const id of poolNow) assert.strictEqual((await ctx.bob._storage.get('pqopk:' + id)).retiredAt, undefined);

        // Share, собранный по старому bundle, ещё в пределах 14 дней применяется.
        clock.t = replacedAt + 5 * DAY;
        assert.strictEqual((await ctx.bob.syncKeyShares(22, 100)).applied, 1, 'share built from a pre-refresh bundle');
        assert.strictEqual(await ctx.bob._storage.get('pqopk:' + usedOld), null);
        // Ключ комнаты Alice за 36 суток просрочен: плановая ротация в ensureRoomSession.
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        await ctx.bob.syncKeyShares(22, 100);
        await assertMessage(ctx.alice, ctx.bob, 1, 'после обновления пула');
    });

    await test('retired seeds are deleted after 14 days; a share that arrives later is rejected', async () => {
        const clock = { t: 1700000000000 };
        const ctx = await trio({ now: () => clock.t });
        await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
        const used = initOf(ctx.server._keyShares[0]).usedPqPrekeyId;
        clock.t += 31 * DAY;
        const replacedAt = clock.t;
        await ctx.bob.init();
        assert.ok(await ctx.bob._storage.get('pqopk:' + used), 'retired, still there');
        clock.t = replacedAt + PREKEY_RETAIN_MS + DAY;
        await ctx.bob.init(); // уборка
        assert.strictEqual(await ctx.bob._storage.get('pqopk:' + used), null, 'pruned');
        const r = await ctx.bob.syncKeyShares(22, 100);
        assert.deepStrictEqual([r.applied, r.failed], [0, 1]);
        assert.strictEqual(PQ_OPK_REFRESH_MS, 30 * DAY);
    });

    await test('a retired seed that was not pruned yet is accepted for 14 days and not a day longer (the SPK is current, so only the seed decides)', async () => {
        // День 25: Bob ротирует SPK (пул ещё не просрочен). День 26: Alice собирает
        // share по новому SPK, но с ключом из пула дня 0. День 31: замена пула; SPK
        // моложе 7 дней и не ротируется. Дальше Bob только забирает share, init()
        // не вызывает — отставленная запись лежит на месте, решает проверка срока.
        const scenario = async (syncAfterDays) => {
            const clock = { t: 1700000000000 };
            const ctx = await trio({ now: () => clock.t });
            clock.t += 25 * DAY;
            await ctx.bob.init();
            clock.t += DAY;
            await ctx.alice.ensureRoomSession(11, 100, ctx.withAlice);
            const used = initOf(ctx.server._keyShares[0]).usedPqPrekeyId;
            clock.t += 5 * DAY;
            const replacedAt = clock.t;
            await ctx.bob.init();
            assert.strictEqual((await ctx.bob._storage.get('pqopk:' + used)).retiredAt, replacedAt);
            clock.t = replacedAt + syncAfterDays * DAY;
            assert.ok(await ctx.bob._storage.get('pqopk:' + used), 'the record is still there');
            return ctx.bob.syncKeyShares(22, 100);
        };
        const within = await scenario(13);
        assert.deepStrictEqual([within.applied, within.failed], [1, 0], 'day 13 after the replacement');
        const late = await scenario(15);
        assert.deepStrictEqual([late.applied, late.failed], [0, 1], 'day 15 after the replacement');
    });

    // ---- 7. Совместимость реализаций ML-KEM ----

    await test('interop on the one-time path: public/mlkem.js ↔ Node WebCrypto ML-KEM-768, both directions', async () => {
        let webKem = null;
        try {
            const alg = { name: 'ML-KEM-768' };
            webKem = {
                async keygen(seed) {
                    const priv = await subtle.importKey('raw-seed', seed, alg, false, ['decapsulateBits']);
                    const pub = await subtle.getPublicKey(priv, ['encapsulateBits']);
                    return { publicKey: new Uint8Array(await subtle.exportKey('raw-public', pub)), secretKey: seed.slice() };
                },
                async encapsulate(publicKey) {
                    const pub = await subtle.importKey('raw-public', publicKey, alg, false, ['encapsulateBits']);
                    const r = await subtle.encapsulateBits(alg, pub);
                    return { ciphertext: new Uint8Array(r.ciphertext), sharedSecret: new Uint8Array(r.sharedKey) };
                },
                async decapsulate(secretKey, ciphertext) {
                    const priv = await subtle.importKey('raw-seed', secretKey, alg, false, ['decapsulateBits']);
                    return new Uint8Array(await subtle.decapsulateBits(alg, priv, ciphertext));
                },
            };
            await webKem.keygen(globalThis.crypto.getRandomValues(new Uint8Array(64)));
        } catch {
            console.log('        (пропущено: ML-KEM в Node WebCrypto недоступен)');
            return;
        }
        const server = makeFakeServer();
        server.addParticipant(100, 1, 11);
        server.addParticipant(100, 2, 22);
        const alice = makeUser(server, 1, { kem: mlkem });
        const bob = makeUser(server, 2, { kem: webKem });
        await alice.init();
        await bob.init();
        const parts = [{ id: 1 }, { id: 2 }];
        await alice.ensureRoomSession(11, 100, parts);
        await bob.ensureRoomSession(22, 100, parts);
        assert.deepStrictEqual(server._keyShares.map(s => initOf(s).pqOneTime), [true, true]);
        assert.strictEqual((await bob.syncKeyShares(22, 100)).applied, 1, 'mlkem.js encapsulate → WebCrypto decapsulate');
        assert.strictEqual((await alice.syncKeyShares(11, 100)).applied, 1, 'WebCrypto encapsulate → mlkem.js decapsulate');
        await assertMessage(alice, bob, 1, 'от mlkem.js');
        await assertMessage(bob, alice, 2, 'от WebCrypto');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
