'use strict';
// Sealed sender на клиенте (docs/security/sealed-sender.md, разделы 9.2-9.4, 10, 11,
// 15): автора сообщения комнаты определяет клиент по senderKeyId через индекс
// отправителей skIndex; senderKeyId привязан к отправителю и проверяется при
// установке чужого ключа; удалённые ключи остаются надгробиями; порядок проверок
// расшифровки и «ничего не пишем до конца проверок».
// Запуск: node test/sender-index.protocol.test.js

const nodeCrypto = require('crypto');
const {
    assert, E2EE, test, finish, makeClock, makeUser, makeRoom, chatOf, participantsOf,
    send, read, stored, HOUR,
} = require('./sender-keys-helpers');

const I = E2EE._internal;
const { b64encode: b64, b64decode } = I;
const subtle = nodeCrypto.webcrypto.subtle;
const ROOM = 100;
const OTHER_ROOM = 200;
const keyName = (id, room = ROOM) => 'senderKey:' + room + ':' + id;
const indexName = (keyId, room = ROOM) => 'skIndex:' + room + ':' + keyId;
const enc = (s) => new TextEncoder().encode(s);
const UNBOUND = 'ключ участника не принят: идентификатор не выведен из отправителя';

// Alice (1), Bob (2), Mallory (3) в комнате; ключи ещё не розданы.
async function trio(opts = {}) {
    const ids = opts.ids || [1, 2, 3];
    const server = makeRoom(ROOM, ids);
    const clock = opts.clock || null;
    const users = {};
    for (const [name, id] of [['alice', 1], ['bob', 2], ['mallory', 3]]) {
        if (!ids.includes(id)) continue;
        users[name] = makeUser(server, id, { now: clock && clock.now });
        await users[name].init();
    }
    return Object.assign({ server, clock, parts: participantsOf(server, ROOM) }, users);
}

const share = (ctx, who) => ctx[who].ensureRoomSession(chatOf(ctx[who]._userId), ROOM, ctx.parts);
const sync = (ctx, who) => ctx[who].syncKeyShares(chatOf(ctx[who]._userId), ROOM);
const keyIdOf = async (client) => (await stored(client, keyName(client._userId))).senderKeyId;

// Всё хранилище клиента одной строкой: сравнение «до» и «после» отказа.
function snapshot(client) {
    return JSON.stringify(Array.from(client._storage.map.entries())
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([name, value]) => [name, value]));
}

// ---- Подделки ----

// Участник, умеющий подобрать идентификатор ключа (прообраз SHA-256 по 128 битам): на
// время fn вывод senderKeyId для senderId возвращает заданные 16 байт. Остальные
// вызовы SHA-256 (и вывод у других участников) честные.
async function withSpoofedSkid(senderId, keyIdB64, fn) {
    const real = subtle.digest;
    const fixed = b64decode(keyIdB64);
    const label = enc('nyxo-skid-v1');
    subtle.digest = async function (alg, data) {
        const bytes = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
        if (bytes.length === 52 && label.every((b, i) => bytes[i] === b)
            && new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(16) === senderId) {
            const out = new Uint8Array(32);
            out.set(fixed);
            return out.buffer;
        }
        return real.call(this, alg, data);
    };
    try { return await fn(); } finally { delete subtle.digest; }
}

async function hmac(key, byte) {
    const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', k, new Uint8Array([byte])));
}

// Конверт, подписанный настоящим ключом подписи владельца и зашифрованный его
// цепочкой, но с заданным содержимым / AAD: даёт состояния, которых честный
// encryptOutgoing не создаёт (мусор вместо содержимого, чужой id в AAD).
async function forge(client, room, { iteration = 0, plaintext, aadSender, mid = null, ts = 1800000000000 } = {}) {
    const st = await stored(client, keyName(client._userId, room));
    assert.ok(st.nextIteration <= iteration, 'forge: цепочка уже ушла вперёд');
    let chain = b64decode(st.chainKey);
    for (let it = st.nextIteration; it < iteration; it++) chain = await hmac(chain, 2);
    const messageKey = await hmac(chain, 1);
    const ikm = await subtle.importKey('raw', messageKey, 'HKDF', false, ['deriveBits']);
    const aesRaw = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc('nyxo-e2ee-msgkey-v2') }, ikm, 256));
    const aesKey = await subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = new Uint8Array(nodeCrypto.randomBytes(12));
    const body = plaintext || I.padMessage(enc(JSON.stringify({ t: 'text', b: 'подделка', mid, ts })));
    const sender = aadSender === undefined ? client._userId : aadSender;
    const aad = enc('senderkey-v3:' + room + ':' + sender + ':' + st.senderKeyId);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aesKey, body));
    // Подпись v3, собранная независимо от кода клиента: метка ‖ u32be(комната) ‖ senderKeyId[16] ‖ u32be(итерация) ‖ iv ‖ ct.
    const u32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    const sigInput = new Uint8Array([...enc('nyxo-skmsg-v3\0'), ...u32(Number(room)), ...b64decode(st.senderKeyId), ...u32(iteration), ...iv, ...ct]);
    const sig = new Uint8Array(await subtle.sign('Ed25519', st.signingPrivateKey, sigInput));
    return JSON.stringify({ v: 3, alg: 'senderkey-v3', senderKeyId: st.senderKeyId, iteration, iv: b64(iv), ct: b64(ct), sig: b64(sig) });
}

// Конверт с изменённым полем (подпись и AEAD при этом не пересчитываются).
const tweak = (envelope, patch) => JSON.stringify(Object.assign(JSON.parse(envelope), patch));

(async () => {
    console.log('Индекс отправителей skIndex и привязка senderKeyId (sealed sender, клиент)\n');

    // ===================== Автор по индексу =====================

    await test('расшифровка без senderId находит автора по индексу; свои сообщения — свои', async () => {
        const ctx = await trio();
        await share(ctx, 'alice');
        await share(ctx, 'mallory');
        await sync(ctx, 'bob');
        await sync(ctx, 'alice');
        const fromAlice = await send(ctx.alice, ROOM, 'от Алисы');
        const fromMallory = await send(ctx.mallory, ROOM, 'от Мэллори');
        for (const reader of [ctx.bob, ctx.alice]) {
            const a = await reader.decryptIncoming(ROOM, null, fromAlice.env, fromAlice.id);
            assert.strictEqual(a.ok, true);
            assert.strictEqual(a.senderId, 1);
            const m = await reader.decryptIncoming(ROOM, null, fromMallory.env, fromMallory.id);
            assert.strictEqual(m.ok, true);
            assert.strictEqual(m.senderId, 3);
            assert.strictEqual(m.text, 'от Мэллори');
        }
        // Свои сообщения Алиса читает как свои: автор — она сама, ключ в индексе с момента создания.
        assert.strictEqual((await ctx.alice.decryptIncoming(ROOM, null, fromAlice.env, fromAlice.id)).senderId, ctx.alice._userId);
        assert.deepStrictEqual(await stored(ctx.alice, indexName(await keyIdOf(ctx.alice))), { v: 1, sender: 1 });
        assert.deepStrictEqual(await stored(ctx.bob, indexName(await keyIdOf(ctx.alice))), { v: 1, sender: 1 }, 'индекс получателя — отправитель из AAD key-share');
    });

    await test('подсказка отправителя только для тестов: неверная — sender-mismatch, верная и null — успех; ложная mine ничего не скрывает', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const m = await send(ctx.alice, ROOM, 'привет');
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, 2, m.env, m.id), { ok: false, reason: 'sender-mismatch' }, '«это моё» (ложная mine) не принимается');
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, 99, m.env, m.id), { ok: false, reason: 'sender-mismatch' });
        assert.strictEqual((await ctx.bob.decryptIncoming(ROOM, 1, m.env, m.id)).ok, true, 'верная подсказка');
        const clean = await ctx.bob.decryptIncoming(ROOM, null, m.env, m.id);
        assert.strictEqual(clean.ok, true, 'production-вызов с null не зависит от подсказок сервера');
        assert.strictEqual(clean.senderId, 1);
        // Неверная подсказка отказывает до любых записей.
        const fresh = await send(ctx.alice, ROOM, 'ещё');
        const before = snapshot(ctx.bob);
        await ctx.bob.decryptIncoming(ROOM, 2, fresh.env, fresh.id);
        assert.strictEqual(snapshot(ctx.bob), before);
    });

    // ===================== Привязка senderKeyId =====================

    await test('M присылает SKDM с keyId участника A (тот же ключ подписи и даже тот же chainKey): не устанавливается, индекс и хранилище не меняются, сообщение A атрибутируется A', async () => {
        const ctx = await trio();
        await share(ctx, 'alice'); // ключ A создан; Bob ещё не забирал — окно атаки (офлайн/новичок)
        const alice = await stored(ctx.alice, keyName(1));
        // M создаёт состояние под идентификатором A (в мире, где он умеет его подобрать)
        // и целиком копирует в него ключ подписи и цепочку A.
        await withSpoofedSkid(3, alice.senderKeyId, async () => {
            await ctx.mallory.rotateRoomKey(ROOM);
            const own = await stored(ctx.mallory, keyName(3));
            assert.strictEqual(own.senderKeyId, alice.senderKeyId, 'подготовка: M присвоил идентификатор A');
            own.signingPublicKey = alice.signingPublicKey;
            own.chainKey = alice.chainKey;
            own.origin = { chainKey0: alice.origin.chainKey0 };
            await ctx.mallory._storage.set(keyName(3), own);
            await share(ctx, 'mallory'); // key-share к Бобу с SKDM «как у A»
        });
        const toBob = ctx.server._keyShares.filter(s => s.recipientId === 2);
        assert.deepStrictEqual(toBob.map(s => s.senderId).sort(), [1, 3], 'в очереди Боба и настоящий ключ A, и подделка M');
        const aliceShare = toBob.find(s => s.senderId === 1);
        ctx.server._keyShares.splice(ctx.server._keyShares.indexOf(aliceShare), 1); // пока дошла только подделка

        const before = snapshot(ctx.bob);
        const first = await sync(ctx, 'bob');
        assert.strictEqual(first.applied, 0);
        assert.strictEqual(first.failed, 1);
        assert.deepStrictEqual(first.warnings, [{ userId: 3, reason: UNBOUND }]);
        assert.strictEqual(snapshot(ctx.bob), before, 'состояние и индекс не изменились (в том числе попарная сессия и одноразовые ключи)');
        assert.deepStrictEqual(await ctx.bob._storage.keys('skIndex:'), []);
        assert.strictEqual(await stored(ctx.bob, keyName(3)), null);

        // Настоящий ключ A доходит позже и устанавливается: подделка его не вытеснила.
        ctx.server._keyShares.push(aliceShare);
        const second = await sync(ctx, 'bob');
        assert.strictEqual(second.applied, 1);
        assert.strictEqual(second.warnings, undefined);
        const m = await send(ctx.alice, ROOM, 'настоящее сообщение A');
        const res = await ctx.bob.decryptIncoming(ROOM, null, m.env, m.id);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.senderId, 1, 'автор — A, а не M');
        assert.deepStrictEqual(await stored(ctx.bob, indexName(alice.senderKeyId)), { v: 1, sender: 1 });
    });

    await test('SKDM с идентификатором, не выведенным из (комната, отправитель, ключ подписи), не устанавливается', async () => {
        const ctx = await trio({ ids: [1, 3] });
        // Прежние (до sealed sender) ключи имели случайный идентификатор — такой SKDM не принимается.
        const random = b64(new Uint8Array(nodeCrypto.randomBytes(16)));
        await withSpoofedSkid(3, random, () => share(ctx, 'mallory'));
        const before = snapshot(ctx.alice);
        const result = await sync(ctx, 'alice');
        assert.strictEqual(result.applied, 0);
        assert.deepStrictEqual(result.warnings, [{ userId: 3, reason: UNBOUND }]);
        assert.strictEqual(snapshot(ctx.alice), before);
        assert.deepStrictEqual(await ctx.alice._storage.keys('skIndex:'), [], 'в индекс ничего не попало');
    });

    await test('подмена поля senderId в ответе сервера (при настоящем AAD) не заносит чужой ключ в индекс под другим отправителем', async () => {
        const ctx = await trio();
        await share(ctx, 'mallory');
        // Сервер выдаёт key-share M как пришедший от A.
        for (const s of ctx.server._keyShares) if (s.recipientId === 2) s.senderId = 1;
        const before = snapshot(ctx.bob);
        const result = await sync(ctx, 'bob');
        assert.strictEqual(result.applied, 0);
        assert.deepStrictEqual(await ctx.bob._storage.keys('skIndex:'), []);
        assert.strictEqual(await stored(ctx.bob, keyName(1)), null, 'под отправителем A ничего не создано');
        assert.strictEqual(snapshot(ctx.bob), before);
    });

    await test('обход проверки привязки (запись M для keyId A в индексе и состоянии): сообщение A всё равно не атрибутируется M — вторая линия (AAD с id отправителя)', async () => {
        const ctx = await trio();
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const aliceKeyId = await keyIdOf(ctx.alice);
        const m = await send(ctx.alice, ROOM, 'только от A');
        // Искусственная порча устройства Боба: ключ A записан и как ключ M, индекс указывает на M.
        const asAlice = await stored(ctx.bob, keyName(1));
        await ctx.bob._storage.set(keyName(3), JSON.parse(JSON.stringify(asAlice)));
        await ctx.bob._storage.set(indexName(aliceKeyId), { v: 1, sender: 3 });
        const before = snapshot(ctx.bob);
        const res = await ctx.bob.decryptIncoming(ROOM, null, m.env, m.id);
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.reason, 'decrypt-failed', 'AEAD с AAD отправителя M не проходит');
        assert.strictEqual(res.senderId, undefined);
        assert.strictEqual(snapshot(ctx.bob), before, 'отказ ничего не записал');
    });

    await test('индекс получателя не принимает второго отправителя для того же keyId (коллизия): SKDM отвергается, запись не меняется', async () => {
        const ctx = await trio();
        await share(ctx, 'alice');
        const aliceKeyId = await keyIdOf(ctx.alice);
        // На устройстве Боба под этим keyId уже стоит другой отправитель.
        await ctx.bob._storage.set(indexName(aliceKeyId), { v: 1, sender: 3 });
        const before = snapshot(ctx.bob);
        const result = await sync(ctx, 'bob');
        assert.strictEqual(result.applied, 0);
        assert.deepStrictEqual(result.warnings, [{ userId: 1, reason: UNBOUND }]);
        assert.strictEqual(snapshot(ctx.bob), before);
    });

    await test('индекс не хранит unverifiedSender и вообще ничего, кроме { v, sender, gone? }', async () => {
        const ctx = await trio();
        await share(ctx, 'alice');
        await share(ctx, 'mallory');
        await sync(ctx, 'bob');
        for (const name of await ctx.bob._storage.keys('skIndex:')) {
            assert.deepStrictEqual(Object.keys(await stored(ctx.bob, name)).sort(), ['sender', 'v']);
        }
        assert.strictEqual((await ctx.bob._storage.keys('skIndex:')).length, 2);
    });

    // ===================== Порядок причин отказа =====================

    await test('порядок причин: bad-envelope (в том числе senderkey-v1 и senderkey-v2), no-sender-key, bad-signature, stale-sender-key, too-far-ahead, replay, decrypt-failed, bad-plaintext; после отказа хранилище не изменилось', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const m = await send(ctx.alice, ROOM, 'исходное');
        const env = JSON.parse(m.env);
        const unknownKey = () => tweak(m.env, { senderKeyId: b64(new Uint8Array(nodeCrypto.randomBytes(16))) });
        const flipped = (field) => { const bytes = b64decode(env[field]); bytes[0] ^= 1; return tweak(m.env, { [field]: b64(bytes) }); };

        const refusals = [
            ['bad-envelope', 'не JSON'],
            ['bad-envelope', '"строка"'],
            ['bad-envelope', JSON.stringify({ v: 1, alg: 'senderkey-v1', senderKeyId: env.senderKeyId, iteration: 0, iv: env.iv, ct: env.ct, sig: env.sig })],
            ['bad-envelope', tweak(m.env, { alg: 'senderkey-v2' })],
            ['bad-envelope', tweak(m.env, { v: 2, alg: 'senderkey-v2' })],
            ['bad-envelope', tweak(m.env, { senderKeyId: 'не-ключ' })],
            ['bad-envelope', tweak(m.env, { senderKeyId: b64(new Uint8Array(15)) })],
            ['bad-envelope', tweak(m.env, { iteration: -1 })],
            ['bad-envelope', tweak(m.env, { iteration: 1.5 })],
            ['bad-envelope', tweak(m.env, { iv: b64(new Uint8Array(11)) })],
            ['bad-envelope', tweak(m.env, { sig: b64(new Uint8Array(63)) })],
            ['bad-envelope', tweak(m.env, { ct: b64(new Uint8Array(15)) })],
            ['no-sender-key', unknownKey()],
            ['bad-signature', flipped('sig')],
            ['bad-signature', flipped('ct')],
            ['bad-signature', tweak(m.env, { iteration: 1 })],
        ];
        for (const [reason, envelope] of refusals) {
            const before = snapshot(ctx.bob);
            const res = await ctx.bob.decryptIncoming(ROOM, null, envelope, m.id);
            assert.deepStrictEqual(res, { ok: false, reason }, reason + ': ' + envelope.slice(0, 60));
            assert.strictEqual(snapshot(ctx.bob), before, reason + ': хранилище не изменилось');
        }

        // replay: тот же (ключ, итерация) под другим id сообщения — после принятия оригинала.
        assert.strictEqual((await ctx.bob.decryptIncoming(ROOM, null, m.env, m.id)).ok, true);
        const beforeReplay = snapshot(ctx.bob);
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, m.env, '1999999'), { ok: false, reason: 'replay' });
        assert.strictEqual(snapshot(ctx.bob), beforeReplay);
    });

    await test('too-far-ahead, stale-sender-key (после final), decrypt-failed, bad-plaintext: отказ до записи, цепочка не двигается', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const firstKey = await keyIdOf(ctx.alice);
        const before = snapshot(ctx.bob);

        // decrypt-failed: подпись и цепочка верные, а AAD — с id другого отправителя.
        const wrongAad = await forge(ctx.alice, ROOM, { iteration: 0, aadSender: 2, mid: '1000001' });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, wrongAad, '1000001'), { ok: false, reason: 'decrypt-failed' });
        // bad-plaintext: AEAD проходит, содержимое — мусор.
        const garbage = await forge(ctx.alice, ROOM, { iteration: 0, plaintext: new Uint8Array(nodeCrypto.randomBytes(300)) });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, garbage, '1000001'), { ok: false, reason: 'bad-plaintext' });
        // Содержимое без mid / с чужим mid / с плохим ts — проверки 9.4, тоже до записи.
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, await forge(ctx.alice, ROOM, { iteration: 0 }), '1000001'), { ok: false, reason: 'no-mid' });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, await forge(ctx.alice, ROOM, { iteration: 0, mid: '1000002' }), '1000001'), { ok: false, reason: 'id-mismatch' });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, await forge(ctx.alice, ROOM, { iteration: 0, mid: '1000001', ts: -5 }), '1000001'), { ok: false, reason: 'bad-plaintext' });
        // too-far-ahead: итерация дальше MAX_SKIP от позиции цепочки получателя.
        const far = await forge(ctx.alice, ROOM, { iteration: I.MAX_SKIP + 1, mid: '1000001' });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, far, '1000001'), { ok: false, reason: 'too-far-ahead' });
        assert.strictEqual(snapshot(ctx.bob), before, 'ни один из отказов ничего не записал: цепочка, seen и записи о версиях на месте');
        assert.deepStrictEqual(await ctx.bob._storage.keys('seen:'), []);
        assert.deepStrictEqual(await ctx.bob._storage.keys('edit:'), []);

        // Настоящее сообщение после всех отказов читается с итерации 0.
        const ok = await forge(ctx.alice, ROOM, { iteration: 0, mid: '1000003' });
        assert.strictEqual((await ctx.bob.decryptIncoming(ROOM, null, ok, '1000003')).text, 'подделка');
    });

    await test('stale-sender-key: итерация дальше final закрытой цепочки; ключ в индексе, но не текущий и не в архиве', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const firstKey = await keyIdOf(ctx.alice);
        await send(ctx.alice, ROOM, 'ноль');
        const last = await send(ctx.alice, ROOM, 'один');
        await ctx.alice.rotateRoomKey(ROOM);
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const archiveName = 'skArchive:' + ROOM + ':1:' + firstKey;
        const archived = await stored(ctx.bob, archiveName);
        assert.ok(archived && Number.isInteger(archived.final), 'цепочка старого ключа закрыта по prev.final');
        assert.strictEqual(archived.final, 1);
        // Отправитель сообщил, что дальше итерации 0 ключ не использовался; конверт итерации 1 подписан его ключом.
        archived.final = 0;
        await ctx.bob._storage.set(archiveName, archived);
        const before = snapshot(ctx.bob);
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, last.env, last.id), { ok: false, reason: 'stale-sender-key' });
        assert.strictEqual(snapshot(ctx.bob), before);

        // Идентификатор есть в индексе отправителя, но у отправителя это не текущий ключ и не архивный.
        const ghost = b64(new Uint8Array(nodeCrypto.randomBytes(16)));
        await ctx.bob._storage.set(indexName(ghost), { v: 1, sender: 1 });
        const ghostBefore = snapshot(ctx.bob);
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, tweak(last.env, { senderKeyId: ghost }), last.id), { ok: false, reason: 'stale-sender-key' });
        assert.strictEqual(snapshot(ctx.bob), ghostBefore);
    });

    // ===================== Надгробия =====================

    await test('ключ удалён по сроку комнаты: запись индекса — надгробие, причина key-expired, а не no-sender-key', async () => {
        const clock = makeClock();
        const ctx = await trio({ ids: [1, 2], clock });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const old = await send(ctx.alice, ROOM, 'на первом ключе');
        const oldKey = await keyIdOf(ctx.alice);
        assert.strictEqual((await read(ctx.bob, ROOM, old)).text, 'на первом ключе');
        await ctx.alice.rotateRoomKey(ROOM);
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        await ctx.bob.setRoomPolicy(ROOM, { expirySeconds: 3600 });
        clock.advance(3 * HOUR);
        const stats = await ctx.bob.maintainRoomKeys(ROOM);
        assert.ok(stats.removedArchives >= 1, JSON.stringify(stats));
        assert.deepStrictEqual(await stored(ctx.bob, indexName(oldKey)), { v: 1, sender: 1, gone: true });
        const after = await ctx.bob.decryptIncoming(ROOM, null, old.env, old.id);
        assert.deepStrictEqual(after, { ok: false, reason: 'key-expired' }, 'не no-sender-key: интерфейс не запросит ключ заново');
        // Надгробие не воскресает от повторного key-share той же записи.
        assert.deepStrictEqual(await stored(ctx.bob, indexName(oldKey)), { v: 1, sender: 1, gone: true });
    });

    await test('режим «Не хранить историю»: архивные ключи — надгробия, причина history-not-kept', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const old = await send(ctx.alice, ROOM, 'раньше');
        const oldKey = await keyIdOf(ctx.alice);
        assert.strictEqual((await read(ctx.bob, ROOM, old)).ok, true);
        await ctx.alice.rotateRoomKey(ROOM);
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        await ctx.bob.setRoomHistoryMode(ROOM, 'none');
        assert.deepStrictEqual(await stored(ctx.bob, indexName(oldKey)), { v: 1, sender: 1, gone: true });
        assert.deepStrictEqual(await ctx.bob.decryptIncoming(ROOM, null, old.env, old.id), { ok: false, reason: 'history-not-kept' });
        // Текущий ключ остаётся «живым» записью индекса: новые сообщения читаются.
        const fresh = await send(ctx.alice, ROOM, 'новое');
        assert.strictEqual((await read(ctx.bob, ROOM, fresh)).text, 'новое');
        assert.deepStrictEqual(await stored(ctx.bob, indexName(await keyIdOf(ctx.alice))), { v: 1, sender: 1 }, 'текущий ключ — не надгробие');
    });

    await test('надгробие в state.archive вытеснено по пределу: запись индекса удалена вместе с ним, дальше no-sender-key', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const state = await stored(ctx.alice, keyName(1));
        // Подготовка: ровно предел надгробий без подробных записей, у каждого — запись индекса.
        const limit = I.MAX_ARCHIVE_INDEX + I.MAX_ARCHIVE_TOMBSTONES;
        const ids = [];
        for (let i = 0; i < limit; i++) {
            const id = b64(new Uint8Array(nodeCrypto.randomBytes(16)));
            ids.push(id);
            await ctx.alice._storage.set(indexName(id), { v: 1, sender: 1, gone: true });
        }
        state.archive = ids.slice();
        await ctx.alice._storage.set(keyName(1), state);
        await ctx.alice.rotateRoomKey(ROOM); // +1 подробная запись → сдвиг: самое старое надгробие забывается
        const after = await stored(ctx.alice, keyName(1));
        assert.strictEqual(after.archive.length, limit);
        assert.strictEqual(after.archive.filter(e => typeof e === 'object').length, 1);
        assert.strictEqual(await stored(ctx.alice, indexName(ids[ids.length - 1])), null, 'запись забытого надгробия удалена');
        assert.deepStrictEqual(await stored(ctx.alice, indexName(ids[0])), { v: 1, sender: 1, gone: true }, 'остальные надгробия на месте');
        // Для устройства этот ключ теперь «никогда не виденный».
        const forgotten = tweak((await send(ctx.alice, ROOM, 'x')).env, { senderKeyId: ids[ids.length - 1] });
        assert.deepStrictEqual(await ctx.alice.decryptIncoming(ROOM, null, forgotten, '1000009'), { ok: false, reason: 'no-sender-key' });
    });

    await test('индекс очищается (с надгробиями) только локальной очисткой комнаты; другая комната не затрагивается', async () => {
        const ctx = await trio({ ids: [1, 2] });
        ctx.server.addParticipant(OTHER_ROOM, 1, chatOf(1) + 1000);
        ctx.server.addParticipant(OTHER_ROOM, 2, chatOf(2) + 1000);
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        await ctx.alice.ensureRoomSession(chatOf(1) + 1000, OTHER_ROOM, ctx.server.participantsOf(OTHER_ROOM));
        await ctx.bob.syncKeyShares(chatOf(2) + 1000, OTHER_ROOM);
        await ctx.alice.rotateRoomKey(ROOM);
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        await ctx.bob.setRoomHistoryMode(ROOM, 'none'); // у архивного ключа появилось надгробие
        const inRoom = async () => (await ctx.bob._storage.keys('skIndex:' + ROOM + ':')).length;
        assert.strictEqual(await inRoom(), 2, 'два ключа A: текущий и надгробие');
        // Обычные операции индекс не очищают: выход участника, техобслуживание, повторный sync.
        await ctx.bob.maintainRoomKeys(ROOM);
        await sync(ctx, 'bob');
        assert.strictEqual(await inRoom(), 2);
        const otherBefore = (await ctx.bob._storage.keys('skIndex:' + OTHER_ROOM + ':')).length;
        assert.strictEqual(otherBefore, 1);
        await ctx.bob.forgetRoom(ROOM);
        assert.strictEqual(await inRoom(), 0, 'индекс и надгробия очищены');
        assert.deepStrictEqual(await ctx.bob._storage.keys('senderKey:' + ROOM + ':'), []);
        assert.deepStrictEqual(await ctx.bob._storage.keys('skArchive:' + ROOM + ':'), []);
        assert.strictEqual(await stored(ctx.bob, 'members:' + ROOM), null);
        assert.strictEqual((await ctx.bob._storage.keys('skIndex:' + OTHER_ROOM + ':')).length, otherBefore, 'соседняя комната на месте');
        assert.ok(await stored(ctx.bob, keyName(1, OTHER_ROOM)));
    });

    await test('перезагрузка вкладки: индекс переживает её, авторы прежние', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        const m = await send(ctx.alice, ROOM, 'до перезагрузки');
        assert.strictEqual((await ctx.bob.decryptIncoming(ROOM, null, m.env, m.id)).senderId, 1);
        const reloaded = makeUser(ctx.server, 2, { storage: ctx.bob._storage });
        const again = await reloaded.decryptIncoming(ROOM, null, m.env, m.id);
        assert.strictEqual(again.ok, true);
        assert.strictEqual(again.senderId, 1);
    });

    await test('свой прежний ключ с невыведенным идентификатором: ротация upgrade, прежний ключ остаётся в индексе — свои старые сообщения читаются', async () => {
        const ctx = await trio({ ids: [1, 2] });
        await share(ctx, 'alice');
        await sync(ctx, 'bob');
        // Устройство со старым ключом: идентификатор случайный, записи индекса нет.
        const own = await stored(ctx.alice, keyName(1));
        const legacyId = b64(new Uint8Array(nodeCrypto.randomBytes(16)));
        await ctx.alice._storage.delete(indexName(own.senderKeyId));
        own.senderKeyId = legacyId;
        await ctx.alice._storage.set(keyName(1), own);
        const result = await share(ctx, 'alice');
        assert.strictEqual(result.rotated, true);
        assert.strictEqual(result.rotationReason, 'upgrade');
        const fresh = await stored(ctx.alice, keyName(1));
        assert.strictEqual(fresh.senderKeyId, await I.deriveSenderKeyId(ROOM, 1, fresh.signingPublicKey));
        assert.deepStrictEqual(await stored(ctx.alice, indexName(legacyId)), { v: 1, sender: 1 }, 'прежний свой ключ в индексе');
        assert.deepStrictEqual(await stored(ctx.alice, indexName(fresh.senderKeyId)), { v: 1, sender: 1 });
    });

    await test('имена участников (9.5): карта пополняется при ensureRoomSession, ушедшие в ней остаются, forgetRoom и режим «без истории» её стирают', async () => {
        const ctx = await trio();
        await share(ctx, 'alice');
        assert.deepStrictEqual(await ctx.alice.getRoomMemberNames(ROOM), { 1: 'user1', 2: 'user2', 3: 'user3' });
        // Мэллори вышла: в списке участников её нет, а имя в карте осталось.
        ctx.server.removeParticipant(ROOM, 3);
        await ctx.alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(ctx.server, ROOM));
        assert.deepStrictEqual((await stored(ctx.alice, 'members:' + ROOM)).map(p => p.id), [1, 2]);
        assert.deepStrictEqual(await ctx.alice.getRoomMemberNames(ROOM), { 1: 'user1', 2: 'user2', 3: 'user3' });
        assert.deepStrictEqual(await ctx.alice.getRoomMemberNames(OTHER_ROOM), {}, 'у другой комнаты своей карты нет');
        await ctx.alice.setRoomHistoryMode(ROOM, 'none');
        assert.deepStrictEqual(await ctx.alice.getRoomMemberNames(ROOM), {}, 'карта живёт вместе с историей комнаты');
        await ctx.alice.ensureRoomSession(chatOf(1), ROOM, participantsOf(ctx.server, ROOM));
        assert.ok(Object.keys(await ctx.alice.getRoomMemberNames(ROOM)).length > 0, 'и пополняется заново');
        await ctx.alice.forgetRoom(ROOM);
        assert.deepStrictEqual(await ctx.alice.getRoomMemberNames(ROOM), {});
    });

    finish();
})().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
