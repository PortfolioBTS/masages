'use strict';
// Привязка содержимого E2EE к сообщению: mid, ts, правки
// (docs/security/message-ordering.md, разделы 9, 12 и 15). Базовый протокол
// проверяет test/e2ee.protocol.test.js; здесь — то, что добавил порядок
// сообщений:
//   - конверт под чужим id ('id-mismatch'), правка, перенесённая на другое
//     сообщение, и таблицы seen/edit после отказа БАЙТ В БАЙТ те же (О4);
//   - откат правки ('stale-edit') и повторный показ той же версии;
//   - чужой автор того же mid ('sender-mismatch');
//   - сообщение без mid ('no-mid') и испорченный ts ('bad-plaintext');
//   - ts правки не меньше ts прошлой версии + 1 при отстающих часах;
//   - предел 5000 записей о версиях, вытеснение по наименьшему ts;
//   - encryptOutgoing без корректного messageId — E2eeError('protocol');
//   - две вкладки на одном хранилище: с общей блокировкой итерации разные.
// Запуск: node test/e2ee.ordering.test.js

// ML-KEM в Node WebCrypto экспериментальный и шумит предупреждениями — глушим
// только их, как в test/e2ee.protocol.test.js.
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const E2EE = require('../public/e2ee.js');
const kem = require('../public/mlkem.js');
const { makeFakeServer } = require('./fake-server');

const subtle = globalThis.crypto.subtle;
const { b64encode: b64, b64decode: unb64, padMessage, MAX_EDIT_ENTRIES } = E2EE._internal;
const ROOM = 100;

// ===================== Мини-раннер =====================

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

function makeUser(server, userId, opts = {}) {
    const storage = opts.storage || new E2EE.MemoryStorage();
    const client = E2EE.createClient({
        userId, storage, transport: server.transportFor(userId), kem, now: opts.now, lock: opts.lock,
    });
    client._storage = storage;
    return client;
}

// Комната на n участников (id 1..n, чат участника id — id * 11): все раздали
// Sender Key и забрали чужие.
async function setupRoom(count = 2, clocks = {}) {
    const server = makeFakeServer();
    const ids = Array.from({ length: count }, (_, i) => i + 1);
    for (const id of ids) server.addParticipant(ROOM, id, id * 11);
    const users = {};
    for (const id of ids) {
        users[id] = makeUser(server, id, { now: clocks[id] });
        await users[id].init();
    }
    const parts = ids.map(id => ({ id, username: 'user' + id }));
    for (const id of ids) await users[id].ensureRoomSession(id * 11, ROOM, parts);
    for (const id of ids) await users[id].syncKeyShares(id * 11, ROOM);
    return { server, users, parts };
}

// Содержимое таблиц seen и edit (то, что обязаны беречь проверки 9.4) и полный
// набор ключей хранилища: после отказа не должно появиться ни одного нового.
async function snapshot(storage) {
    const tables = {};
    for (const prefix of ['seen:', 'edit:']) {
        for (const name of await storage.keys(prefix)) tables[name] = JSON.stringify(await storage.get(name));
    }
    return { tables, names: (await storage.keys('')).sort() };
}

async function assertUnchanged(storage, before, what) {
    const after = await snapshot(storage);
    assert.deepStrictEqual(after.tables, before.tables, what + ': таблицы seen/edit изменились');
    assert.deepStrictEqual(after.names, before.names, what + ': в хранилище появились новые ключи');
}

// Клиент ведёт себя как script.js: собственное сообщение сразу же проходит
// decryptIncoming (рендер), поэтому у автора есть запись о версии.
async function sendAndShow(user, userId, roomId, content, options) {
    const envelope = await user.encryptOutgoing(roomId, content, options);
    const own = await user.decryptIncoming(roomId, userId, envelope, options.messageId);
    assert.strictEqual(own.ok, true, 'собственный конверт должен расшифровываться');
    return { envelope, own };
}

// Конверт v2 с произвольным содержимым, собранный вручную ровно так, как его
// собирает encryptOutgoing: тем же ключом отправителя и теми же правилами
// AAD/подписи. Нужен, чтобы получить то, чего честный клиент не пошлёт
// (без mid, с испорченным ts).
async function hmac(keyBytes, byte) {
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', key, new Uint8Array([byte])));
}

async function craftEnvelope(storage, roomId, userId, body) {
    const name = 'senderKey:' + roomId + ':' + userId;
    const state = await storage.get(name);
    const iteration = state.nextIteration;
    const chainKey = unb64(state.chainKey);
    const messageKey = await hmac(chainKey, 0x01);
    state.cachedKeys[iteration] = b64(messageKey);
    state.chainKey = b64(await hmac(chainKey, 0x02));
    state.nextIteration = iteration + 1;
    await storage.set(name, state);

    const hkdfKey = await subtle.importKey('raw', messageKey, 'HKDF', false, ['deriveBits']);
    const aesRaw = new Uint8Array(await subtle.deriveBits({
        name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('nyxo-e2ee-msgkey-v2'),
    }, hkdfKey, 256));
    const aesKey = await subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = new Uint8Array(globalThis.crypto.getRandomValues(new Uint8Array(12)));
    const aad = new TextEncoder().encode('senderkey-v2:' + roomId + ':' + userId + ':' + state.senderKeyId);
    const padded = padMessage(new TextEncoder().encode(JSON.stringify(body)));
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aesKey, padded));
    const itBytes = new Uint8Array(4);
    new DataView(itBytes.buffer).setUint32(0, iteration, false);
    const idBytes = new TextEncoder().encode(state.senderKeyId);
    const sigInput = new Uint8Array(iv.length + ct.length + 4 + idBytes.length);
    sigInput.set(iv, 0);
    sigInput.set(ct, iv.length);
    sigInput.set(itBytes, iv.length + ct.length);
    sigInput.set(idBytes, iv.length + ct.length + 4);
    const signKey = state.signingPrivateKey && state.signingPrivateKey.kty
        ? await subtle.importKey('jwk', state.signingPrivateKey, { name: 'Ed25519' }, false, ['sign'])
        : state.signingPrivateKey;
    const sig = new Uint8Array(await subtle.sign('Ed25519', signKey, sigInput));
    return JSON.stringify({
        v: 2, alg: 'senderkey-v2', senderKeyId: state.senderKeyId, iteration, iv: b64(iv), ct: b64(ct), sig: b64(sig),
    });
}

// ===================== Привязка к id =====================

async function main() {
    await test('id-mismatch: конверт под чужим id не принят, seen и edit не изменились; под верным id он затем принимается', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        // Сначала в таблицах Боба что-то лежит: сравнивать пустое с пустым нечего.
        const warm = server.newMessageId();
        const first = await alice.encryptOutgoing(ROOM, 'прогрев', { messageId: warm });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, first, warm)).ok, true);
        assert.ok((await bob._storage.keys('seen:')).length > 0 && (await bob._storage.keys('edit:')).length > 0);

        const idA = server.newMessageId();
        const idB = server.newMessageId();
        const envelope = await alice.encryptOutgoing(ROOM, 'секрет', { messageId: idA });
        const before = await snapshot(bob._storage);
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, envelope, idB), { ok: false, reason: 'id-mismatch' });
        await assertUnchanged(bob._storage, before, 'после конверта под чужим id');

        // Отказ не «отравил» таблицы: настоящий id по-прежнему проходит.
        const shown = await bob.decryptIncoming(ROOM, 1, envelope, idA);
        assert.strictEqual(shown.ok, true);
        assert.strictEqual(shown.text, 'секрет');
    });

    await test('id-mismatch: правка, перенесённая сервером на другое сообщение, не принята, таблицы не изменились', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const idA = server.newMessageId();
        const idB = server.newMessageId();
        const a = await sendAndShow(alice, 1, ROOM, 'первое', { messageId: idA });
        const b = await sendAndShow(alice, 1, ROOM, 'второе', { messageId: idB });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, a.envelope, idA)).text, 'первое');
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, b.envelope, idB)).text, 'второе');

        const edit = await alice.encryptOutgoing(ROOM, 'исправлено', { messageId: idA, edit: true });
        const before = await snapshot(bob._storage);
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, edit, idB), { ok: false, reason: 'id-mismatch' });
        await assertUnchanged(bob._storage, before, 'после перенесённой правки');
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, b.envelope, idB)).text, 'второе', 'второе сообщение не затронуто');
        const real = await bob.decryptIncoming(ROOM, 1, edit, idA);
        assert.strictEqual(real.ok, true);
        assert.strictEqual(real.text, 'исправлено');
        assert.strictEqual(real.edit, true);
    });

    await test('id-mismatch: оригинал с другой итерацией при уже известном mid (чужая «вторая версия» без признака правки)', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const id = server.newMessageId();
        const one = await alice.encryptOutgoing(ROOM, 'один', { messageId: id });
        const two = await alice.encryptOutgoing(ROOM, 'два', { messageId: id }); // не правка, но тот же mid
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, one, id)).ok, true);
        const before = await snapshot(bob._storage);
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, two, id), { ok: false, reason: 'id-mismatch' });
        await assertUnchanged(bob._storage, before, 'после второго оригинала');
    });

    // ===================== Версии =====================

    await test('stale-edit: старая правка после новой отвергнута, повторный показ той же версии принимается; записи не меняются', async () => {
        const T = 1900000000000;
        const clocks = { 1: () => T };
        const { server, users: { 1: alice, 2: bob } } = await setupRoom(2, clocks);
        const id = server.newMessageId();
        const original = await sendAndShow(alice, 1, ROOM, 'оригинал', { messageId: id });
        // Часы Alice стоят: ts правки обязан расти сам (раздел 9.2), иначе вторая правка не отличалась бы по ts.
        const edit1 = await sendAndShow(alice, 1, ROOM, 'правка 1', { messageId: id, edit: true });
        const edit2 = await sendAndShow(alice, 1, ROOM, 'правка 2', { messageId: id, edit: true });
        assert.strictEqual(original.own.ts, T);
        assert.strictEqual(edit1.own.ts, T + 1);
        assert.strictEqual(edit2.own.ts, T + 2);
        assert.strictEqual(edit2.own.edit, true);

        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, original.envelope, id)).text, 'оригинал');
        const shown2 = await bob.decryptIncoming(ROOM, 1, edit2.envelope, id); // правка 1 Боб не видел
        assert.strictEqual(shown2.text, 'правка 2');
        assert.strictEqual(shown2.ts, T + 2);

        const before = await snapshot(bob._storage);
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, edit1.envelope, id), { ok: false, reason: 'stale-edit' });
        await assertUnchanged(bob._storage, before, 'после отката правки');
        // Откат к самому оригиналу — тоже не принимается: оригинал с другой итерацией.
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, original.envelope, id), { ok: false, reason: 'id-mismatch' });
        await assertUnchanged(bob._storage, before, 'после отката к оригиналу');

        // Повторный показ той же версии (история) — принимается, запись не меняется.
        const again = await bob.decryptIncoming(ROOM, 1, edit2.envelope, id);
        assert.strictEqual(again.ok, true);
        assert.strictEqual(again.text, 'правка 2');
        await assertUnchanged(bob._storage, before, 'после повторного показа');
        const record = await bob._storage.get('edit:' + ROOM + ':' + id);
        assert.deepStrictEqual(record, { author: 1, ts: T + 2, keyId: JSON.parse(edit2.envelope).senderKeyId, it: JSON.parse(edit2.envelope).iteration });
    });

    await test('ts правки не меньше ts прошлой версии + 1, даже если часы автора ушли назад', async () => {
        let t = 1900000000000;
        const { server, users: { 1: alice, 2: bob } } = await setupRoom(2, { 1: () => t });
        const id = server.newMessageId();
        const original = await sendAndShow(alice, 1, ROOM, 'оригинал', { messageId: id });
        t -= 3600 * 1000; // часы отстали на час
        const edit = await sendAndShow(alice, 1, ROOM, 'правка', { messageId: id, edit: true });
        assert.strictEqual(edit.own.ts, original.own.ts + 1, 'ts правки = ts оригинала + 1');
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, original.envelope, id)).ok, true);
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, edit.envelope, id)).text, 'правка', 'правка с отстающими часами принята');
        // Часы вернулись и ушли вперёд: ts идёт по часам.
        t += 7200 * 1000;
        const later = await sendAndShow(alice, 1, ROOM, 'позже', { messageId: id, edit: true });
        assert.strictEqual(later.own.ts, t);
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, later.envelope, id)).text, 'позже');
    });

    await test('первая правка принимается и без записи об оригинале; запись создаётся при первом показе любой версии', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const id = server.newMessageId();
        const edit = await alice.encryptOutgoing(ROOM, 'сразу правка', { messageId: id, edit: true });
        assert.ok(!(await bob._storage.get('edit:' + ROOM + ':' + id)), 'до показа записи нет');
        const shown = await bob.decryptIncoming(ROOM, 1, edit, id);
        assert.strictEqual(shown.ok, true);
        assert.strictEqual(shown.edit, true);
        const record = await bob._storage.get('edit:' + ROOM + ':' + id);
        assert.strictEqual(record.author, 1);
        assert.strictEqual(record.ts, shown.ts);
    });

    await test('sender-mismatch: правка и оригинал другого участника с тем же mid отвергнуты, запись автора не тронута', async () => {
        const { server, users: { 1: alice, 2: bob, 3: carol } } = await setupRoom(3);
        const id = server.newMessageId();
        const a = await sendAndShow(alice, 1, ROOM, 'сообщение Alice', { messageId: id });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, a.envelope, id)).text, 'сообщение Alice');

        const before = await snapshot(bob._storage);
        // Carol подписывает правку честно, своим ключом, но mid берёт у Alice (а сервер подсовывает её как сообщение Alice).
        const hijackEdit = await carol.encryptOutgoing(ROOM, 'подмена', { messageId: id, edit: true });
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 3, hijackEdit, id), { ok: false, reason: 'sender-mismatch' });
        await assertUnchanged(bob._storage, before, 'после правки чужого автора');
        const hijackOriginal = await carol.encryptOutgoing(ROOM, 'захват id', { messageId: id });
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 3, hijackOriginal, id), { ok: false, reason: 'sender-mismatch' });
        await assertUnchanged(bob._storage, before, 'после оригинала чужого автора');

        // Настоящий автор правит свой текст — это проходит.
        const own = await alice.encryptOutgoing(ROOM, 'моя правка', { messageId: id, edit: true });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, own, id)).text, 'моя правка');
    });

    // ===================== no-mid и испорченный ts =====================

    await test('no-mid: конверт v2 без mid отвергнут, таблицы не изменились', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const warm = server.newMessageId();
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, await alice.encryptOutgoing(ROOM, 'прогрев', { messageId: warm }), warm)).ok, true);
        const id = server.newMessageId();
        const envelope = await craftEnvelope(alice._storage, ROOM, 1, { t: 'text', b: 'без mid', ts: 1900000000000 });
        const before = await snapshot(bob._storage);
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, envelope, id), { ok: false, reason: 'no-mid' });
        await assertUnchanged(bob._storage, before, 'после конверта без mid');
    });

    await test('сверка mid идёт как строка и раньше проверки ts: чужой mid → id-mismatch, а не bad-plaintext', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const id = server.newMessageId();
        const envelope = await craftEnvelope(alice._storage, ROOM, 1, { t: 'text', b: 'x', mid: String(Number(id) + 1), ts: -5 });
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, envelope, id), { ok: false, reason: 'id-mismatch' });
        // Числовой mid, равный id как строка, — то же сообщение.
        const numeric = await craftEnvelope(alice._storage, ROOM, 1, { t: 'text', b: 'числом', mid: Number(id), ts: 1900000000000 });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, numeric, id)).text, 'числом');
    });

    await test('bad-plaintext: ts не безопасное целое >= 0 (минус, дробь, строка, null, слишком большое), признак правки у файла', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const bad = [-1, 1.5, '1900000000000', null, 2 ** 53, undefined];
        for (const ts of bad) {
            const id = server.newMessageId();
            const body = { t: 'text', b: 'x', mid: id };
            if (ts !== undefined) body.ts = ts;
            const envelope = await craftEnvelope(alice._storage, ROOM, 1, body);
            const before = await snapshot(bob._storage);
            const res = await bob.decryptIncoming(ROOM, 1, envelope, id);
            assert.deepStrictEqual(res, { ok: false, reason: 'bad-plaintext' }, 'ts=' + String(ts));
            await assertUnchanged(bob._storage, before, 'после ts=' + String(ts));
        }
        const id = server.newMessageId();
        const file = await craftEnvelope(alice._storage, ROOM, 1, {
            t: 'file', mime: 'a/b', name: 'f', size: 1, key: b64(new Uint8Array(32)), iv: b64(new Uint8Array(12)),
            caption: '', mid: id, ts: 1900000000000, e: 1,
        });
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, file, id), { ok: false, reason: 'bad-plaintext' }, 'правка у файла не бывает');
    });

    // ===================== Предел записей =====================

    await test('предел записей о версиях: на комнату не больше MAX_EDIT_ENTRIES, вытесняется наименьший ts', async () => {
        assert.strictEqual(MAX_EDIT_ENTRIES, 5000);
        const { server, users: { 1: alice, 2: bob, 3: carol } } = await setupRoom(3);
        // 5000 записей напрямую: ts = 1..5000, автор — Alice. Прогонять через расшифровку тысячи
        // сообщений незачем — проверяется именно учёт и вытеснение.
        const base = 2000000;
        for (let i = 0; i < MAX_EDIT_ENTRIES; i++) {
            await bob._storage.set('edit:' + ROOM + ':' + (base + i), { author: 1, ts: i + 1, keyId: 'old', it: i });
        }
        assert.strictEqual((await bob._storage.keys('edit:' + ROOM + ':')).length, MAX_EDIT_ENTRIES);

        const id1 = server.newMessageId();
        const m1 = await alice.encryptOutgoing(ROOM, 'шестая тысячная', { messageId: id1 });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, m1, id1)).ok, true);
        let names = await bob._storage.keys('edit:' + ROOM + ':');
        assert.strictEqual(names.length, MAX_EDIT_ENTRIES, 'запись добавлена, одна вытеснена');
        assert.ok(names.includes('edit:' + ROOM + ':' + id1), 'новая запись на месте');
        assert.ok(!names.includes('edit:' + ROOM + ':' + base), 'вытеснена запись с наименьшим ts');
        assert.ok(names.includes('edit:' + ROOM + ':' + (base + 1)), 'следующая по ts осталась');

        // Счётчик ведётся и дальше: ещё одно сообщение — ещё одно вытеснение.
        const id2 = server.newMessageId();
        const m2 = await alice.encryptOutgoing(ROOM, 'ещё одно', { messageId: id2 });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, m2, id2)).ok, true);
        names = await bob._storage.keys('edit:' + ROOM + ':');
        assert.strictEqual(names.length, MAX_EDIT_ENTRIES);
        assert.ok(!names.includes('edit:' + ROOM + ':' + (base + 1)));
        assert.ok(names.includes('edit:' + ROOM + ':' + (base + 2)));

        // Защита работает, пока запись жива, и пропадает вместе с вытесненной записью.
        const kept = await carol.encryptOutgoing(ROOM, 'захват живого mid', { messageId: String(base + 2) });
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 3, kept, String(base + 2)), { ok: false, reason: 'sender-mismatch' });
        const evicted = await carol.encryptOutgoing(ROOM, 'захват вытесненного mid', { messageId: String(base) });
        const shown = await bob.decryptIncoming(ROOM, 3, evicted, String(base));
        assert.strictEqual(shown.ok, true, 'предел модели: у вытесненного mid записи нет, версия принимается');
        assert.strictEqual(shown.text, 'захват вытесненного mid');
    });

    await test('предел записей считается по комнате: записи другой комнаты не вытесняются и не считаются', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        for (let i = 0; i < MAX_EDIT_ENTRIES; i++) {
            await bob._storage.set('edit:777:' + (3000000 + i), { author: 1, ts: i + 1, keyId: 'old', it: i });
        }
        const id = server.newMessageId();
        const m = await alice.encryptOutgoing(ROOM, 'в другой комнате', { messageId: id });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, m, id)).ok, true);
        assert.strictEqual((await bob._storage.keys('edit:777:')).length, MAX_EDIT_ENTRIES, 'чужая комната не тронута');
        assert.strictEqual((await bob._storage.keys('edit:' + ROOM + ':')).length, 1);
    });

    await test('очищенное хранилище: записи нет, откат правки принимается (предел модели, раздел 9.4)', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom();
        const id = server.newMessageId();
        const one = await sendAndShow(alice, 1, ROOM, 'правка 1', { messageId: id, edit: true });
        const two = await sendAndShow(alice, 1, ROOM, 'правка 2', { messageId: id, edit: true });
        assert.strictEqual((await bob.decryptIncoming(ROOM, 1, two.envelope, id)).ok, true);
        assert.deepStrictEqual(await bob.decryptIncoming(ROOM, 1, one.envelope, id), { ok: false, reason: 'stale-edit' });
        await bob._storage.delete('edit:' + ROOM + ':' + id);
        const rolled = await bob.decryptIncoming(ROOM, 1, one.envelope, id);
        assert.strictEqual(rolled.ok, true, 'без записи о версии откат неотличим от первого показа');
        assert.strictEqual(rolled.text, 'правка 1');
    });

    // ===================== encryptOutgoing =====================

    await test('encryptOutgoing без корректного messageId — E2eeError("protocol"), цепочка не расходуется', async () => {
        const { server, users: { 1: alice } } = await setupRoom();
        const refused = [
            undefined, null, 5, 1000001, '', 'abc', '123456', '0123456', '2147483648', '12345678901', ' 1000001', '1000001 ', '1e7000000', '1000001\n',
        ];
        for (const messageId of refused) {
            await assert.rejects(
                () => alice.encryptOutgoing(ROOM, 'x', { messageId }),
                (err) => err instanceof E2EE.E2eeError && err.code === 'protocol',
                'messageId=' + JSON.stringify(messageId));
        }
        await assert.rejects(() => alice.encryptOutgoing(ROOM, 'x'), (err) => err instanceof E2EE.E2eeError && err.code === 'protocol');
        await assert.rejects(() => alice.encryptOutgoing(ROOM, 'x', null), (err) => err instanceof E2EE.E2eeError && err.code === 'protocol');
        // Отказ случился до шифрования: первая настоящая отправка — итерация 0.
        const ok = await alice.encryptOutgoing(ROOM, 'x', { messageId: server.newMessageId() });
        assert.strictEqual(JSON.parse(ok).iteration, 0);
        // Границы формата (раздел 6.1) допустимы.
        assert.strictEqual(JSON.parse(await alice.encryptOutgoing(ROOM, 'x', { messageId: '1000000' })).iteration, 1);
        assert.strictEqual(JSON.parse(await alice.encryptOutgoing(ROOM, 'x', { messageId: '2147483647' })).iteration, 2);
    });

    await test('правятся только текстовые сообщения: файл с edit:true не шифруется', async () => {
        const { server, users: { 1: alice } } = await setupRoom();
        const enc = await alice.encryptFile(new Uint8Array([1, 2, 3]));
        await assert.rejects(() => alice.encryptOutgoing(ROOM, {
            type: 'file', mime: 'a/b', name: 'f', size: enc.size, key: enc.key, iv: enc.iv, caption: '',
        }, { messageId: server.newMessageId(), edit: true }), /правятся только текстовые/);
    });

    await test('mid и ts внутри шифротекста: в конверте их нет открытым текстом, отправитель знает ts своей версии', async () => {
        const { server, users: { 1: alice, 2: bob } } = await setupRoom(2, { 1: () => 1900000123456 });
        const id = server.newMessageId();
        const envelope = await alice.encryptOutgoing(ROOM, 'привет', { messageId: id });
        assert.ok(!envelope.includes(id), 'mid не виден серверу');
        assert.ok(!envelope.includes('1900000123456'));
        assert.deepStrictEqual(Object.keys(JSON.parse(envelope)).sort(), ['alg', 'ct', 'iteration', 'iv', 'senderKeyId', 'sig', 'v'], 'формат конверта не менялся');
        const shown = await bob.decryptIncoming(ROOM, 1, envelope, id);
        assert.strictEqual(shown.ts, 1900000123456);
        assert.strictEqual(shown.senderId, 1);
    });

    // ===================== Две вкладки =====================

    await test('две вкладки на одном хранилище: с общей блокировкой итерации разные, без неё — коллизия (контрольный прогон)', async () => {
        async function run(withLock) {
            const server = makeFakeServer();
            server.addParticipant(ROOM, 1, 11);
            server.addParticipant(ROOM, 2, 22);
            const storage = new E2EE.MemoryStorage();
            // Общая очередь вместо Web Locks: то же поведение (секции строго по одной).
            let tail = Promise.resolve();
            const lock = withLock ? (fn) => {
                const run = tail.then(fn);
                tail = run.then(() => undefined, () => undefined);
                return run;
            } : undefined;
            const tabA = makeUser(server, 1, { storage, lock });
            const tabB = makeUser(server, 1, { storage, lock });
            await tabA.init();
            await tabA.ensureRoomSession(11, ROOM, [{ id: 1, username: 'u1' }, { id: 2, username: 'u2' }]);
            const ids = [server.newMessageId(), server.newMessageId(), server.newMessageId(), server.newMessageId()];
            const envelopes = await Promise.all([
                tabA.encryptOutgoing(ROOM, 'a1', { messageId: ids[0] }),
                tabB.encryptOutgoing(ROOM, 'b1', { messageId: ids[1] }),
                tabA.encryptOutgoing(ROOM, 'a2', { messageId: ids[2] }),
                tabB.encryptOutgoing(ROOM, 'b2', { messageId: ids[3] }),
            ]);
            return envelopes.map(e => JSON.parse(e).iteration);
        }
        const locked = await run(true);
        assert.strictEqual(new Set(locked).size, 4, 'с общей блокировкой итерации различны: ' + locked);
        const unlocked = await run(false);
        assert.ok(new Set(unlocked).size < 4, 'без блокировки итерации повторяются (контроль): ' + unlocked);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
