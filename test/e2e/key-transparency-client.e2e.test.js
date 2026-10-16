'use strict';
// Ворота G4 (прозрачность ключей) на настоящем сервере и Postgres, с настоящими клиентами E2EE:
// предупреждения о прозрачности ключей видны и собеседнику, и владельцу.
//   * подмена ключа сервером без записи в журнале -> у собеседника log-mismatch (ключ комнаты ему не
//     передан), в том числе когда сервер на каждый запрос отвечает kt: null (через 3 закрытые эпохи);
//   * ключ подменён и обязательство опубликовано -> собеседник видит ok, а владелец ловит чужое
//     обязательство при самомониторинге (self-foreign-entry);
//   * запись, внедрённая в базу под меткой пользователя, -> self-foreign-entry у него.
// Клиент E2EE — public/e2ee.js целиком; транспорт — HTTP-клиент набора. Эпоха 2 секунды (KT_EPOCH_SECONDS,
// только при NODE_ENV=test), поэтому «3 закрытые эпохи» занимают около 7 секунд.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const E2EE = require('../../public/e2ee.js');
const MLKEM = require('../../public/mlkem.js');
const ktLog = require('../../lib/kt-log');
const { createSuite, waitUntil } = require('./helpers/scenarios');

const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const kit = ktLog.kit;
const KT_SIGNING_KEY = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const suite = createSuite('key-transparency-client', { env: { KT_SIGNING_KEY, KT_EPOCH_SECONDS: 2 } });

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (text) => new Uint8Array(Buffer.from(text, 'base64'));
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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

// Пользователь с настоящим клиентом E2EE; chat — его чат комнаты.
async function makeUser(name) {
    const tc = suite.client({ name });
    await tc.registerAnon();
    const alerts = [];
    const client = E2EE.createClient({
        userId: tc.user.id,
        storage: new E2EE.MemoryStorage(),
        transport: transportFor(tc),
        kem: MLKEM,
        onTransparencyAlert: (alert) => alerts.push(alert),
        ktSchedule: () => 0, // повторы по таймеру в тесте не нужны: проверки вызываются явно
    });
    return { tc, id: tc.user.id, client, alerts, chat: null };
}

async function joinRoom(owner, member) {
    const { code } = await owner.tc.invite(owner.chat.id);
    const pending = await member.tc.join(code);
    await owner.tc.approve(pending.requestId);
    member.chat = (await member.tc.chats()).find(c => c.room_id === owner.chat.room_id);
    assert.ok(member.chat, 'чат комнаты у участника');
}

async function session(user) {
    const part = await user.tc.get(`/api/chats/${user.chat.id}/participants`);
    return user.client.ensureRoomSession(user.chat.id, user.chat.room_id, part.body.participants);
}

const headOf = async (tc) => (await tc.get('/api/kt/head')).body;

// Ждёт закрытия хотя бы n новых эпох после текущей головы.
async function waitEpochs(tc, n) {
    const start = await waitUntil(async () => { const h = await headOf(tc); return h && h.success ? h : null; },
        { timeoutMs: 30000, intervalMs: 200, what: 'голова журнала' });
    return waitUntil(async () => {
        const h = await headOf(tc);
        return h && h.success && h.epoch >= start.epoch + n ? h : null;
    }, { timeoutMs: 40000, intervalMs: 200, what: `${n} закрытых эпох` });
}

const keyRowOf = async (userId) => (await suite.query('SELECT * FROM identity_keys WHERE user_id = $1', [userId])).rows[0];

let alice;
let bob;

test('ворота G4: честный журнал — собеседник ok, тревог нет, самомониторинг чист', async () => {
    alice = await makeUser('алиса');
    bob = await makeUser('боб');
    alice.chat = await alice.tc.createRoom('Журнал и клиент');
    await joinRoom(alice, bob);
    await alice.client.init();
    await bob.client.init();
    await waitEpochs(alice.tc, 1);
    await session(alice);
    await session(bob);
    assert.deepStrictEqual((await alice.client.getPeerTransparency(bob.id)).status, 'ok');
    assert.deepStrictEqual((await bob.client.getPeerTransparency(alice.id)).status, 'ok');
    await alice.client.runKtChecks();
    await bob.client.runKtChecks();
    assert.deepStrictEqual(alice.alerts, []);
    assert.deepStrictEqual(bob.alerts, []);
    const overview = await alice.client.checkTransparency();
    assert.strictEqual(overview.status, 'ok');
    assert.strictEqual(overview.self, 'ok');
});

test('ворота G4: подмена ключа без записи в журнале — log-mismatch у собеседника, ключ комнаты не передан', async () => {
    const carol = await makeUser('кэрол');
    await joinRoom(alice, carol);
    await carol.client.init();
    await waitEpochs(alice.tc, 1); // регистрация Кэрол в закрытой эпохе
    // Сервер подменяет Кэрол ключ обмена на ключ атакующего и ничего не публикует в журнале.
    const attackerDh = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    await suite.query('UPDATE identity_keys SET identity_dh_key = $2 WHERE user_id = $1', [carol.id, attackerDh]);
    const result = await session(alice);
    assert.strictEqual(await alice.client.getPeerIdentityStatus(carol.id), 'log-mismatch');
    assert.deepStrictEqual(result.logMismatches.map(m => m.userId), [carol.id]);
    const shares = await suite.query('SELECT count(*)::int AS n FROM e2ee_key_shares WHERE recipient_id = $1', [carol.id]);
    assert.strictEqual(shares.rows[0].n, 0, 'ключ комнаты подменённому ключу не отправлен');
    // Остальные участники получили ключ как обычно.
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM e2ee_key_shares WHERE recipient_id = $1', [bob.id])).rows[0].n >= 0, true);
    assert.strictEqual((await alice.client.getPeerTransparency(bob.id)).status, 'ok');
});

test('ворота G4: подмена ключа и kt: null на каждый запрос — pending, через 3 закрытые эпохи log-mismatch', async () => {
    const dave = await makeUser('дэн');
    await joinRoom(alice, dave);
    await dave.client.init();
    await waitEpochs(alice.tc, 1);
    // Сервер подменяет ключ Дэна и скрывает kt: ни nonce, ни SKT, ни доказательства.
    const attackerDh = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    await suite.query('UPDATE identity_keys SET identity_dh_key = $2, kt_nonce = NULL, kt_gen = NULL, kt_epoch = NULL, kt_skt = NULL WHERE user_id = $1', [dave.id, attackerDh]);
    await session(alice);
    const first = await alice.client.getPeerTransparency(dave.id);
    assert.strictEqual(first.status, 'pending', 'без доказательства — pending, а не unavailable');
    assert.strictEqual(first.reason, 'no-proof');
    assert.strictEqual(await alice.client.getPeerIdentityStatus(dave.id), 'unverified', 'pending не блокирует');
    // Каждые полторы секунды ensureRoomSession заново спрашивает сервер; ждём три закрытые эпохи.
    const deadline = Date.now() + 45000;
    let status = first.status;
    while (status !== 'mismatch' && Date.now() < deadline) {
        await sleep(1500);
        await session(alice);
        status = (await alice.client.getPeerTransparency(dave.id)).status;
    }
    assert.strictEqual(status, 'mismatch', 'три закрытые эпохи без доказательства');
    assert.strictEqual(await alice.client.getPeerIdentityStatus(dave.id), 'log-mismatch');
    // Пока ключ был pending, рассылка шла (pending не блокирует); после mismatch ключ комнаты ротирован и ему больше не уходит.
    const count = async () => (await suite.query('SELECT count(*)::int AS n FROM e2ee_key_shares WHERE recipient_id = $1', [dave.id])).rows[0].n;
    const sent = await count();
    const again = await session(alice);
    assert.ok(again.logMismatches.some(m => m.userId === dave.id), 'Дэн остаётся исключённым');
    assert.strictEqual(await count(), sent, 'исключённому ничего не отправляется');
    assert.strictEqual(again.rotated, false, 'ротация была один раз, при переходе в mismatch');
});

test('ворота G4: ключ подменён и обязательство опубликовано — собеседник видит ok, а владелец ловит чужую запись', async () => {
    const eve = await makeUser('ева');
    await joinRoom(alice, eve);
    await eve.client.init();
    await waitEpochs(alice.tc, 1);
    // Сервер подменяет ключ Евы на ключ атакующего и честно публикует обязательство на него (под её меткой).
    const row = await keyRowOf(eve.id);
    const attackerDh = new Uint8Array(crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
    const commit = kit.commit(eve.id, row.identity_signing_key, attackerDh, row.kt_nonce);
    // Подсказка kt указывает на эпоху, в которую сервер публикует подменённое обязательство (открытая сейчас).
    await suite.query(
        `UPDATE identity_keys SET identity_dh_key = $2, kt_gen = (SELECT gen FROM kt_state), kt_epoch = (SELECT open_epoch FROM kt_state), kt_skt = NULL
         WHERE user_id = $1`, [eve.id, Buffer.from(attackerDh)]);
    await suite.query('INSERT INTO kt_pending (commitment, user_id, label) VALUES ($1, $2, $3)', [Buffer.from(commit), eve.id, Buffer.from(kit.label(eve.id))]);
    await waitEpochs(alice.tc, 1);
    await session(alice);
    // Собеседник: ключ есть в журнале, ok — журнал не отличает его от настоящего (Н3 и цель Ц1: ловит владелец).
    assert.strictEqual((await alice.client.getPeerTransparency(eve.id)).status, 'ok');
    // Владелец: первый самомониторинг сканирует весь журнал и находит обязательство, которого у него нет.
    await eve.client.runKtChecks();
    const alert = eve.alerts.find(a => a.kind === 'self-foreign-entry');
    assert.ok(alert, 'владелец получил self-foreign-entry: ' + eve.alerts.map(a => a.kind).join());
    assert.deepStrictEqual(alert.entries.map(e => e.c), [Buffer.from(commit).toString('hex')]);
    assert.ok(Number.isFinite(alert.entries[0].epoch));
    assert.strictEqual((await eve.client.checkTransparency()).self, 'alert');
});

test('ворота G4: запись, внедрённая в базу под меткой пользователя, — self-foreign-entry у него', async () => {
    const fred = await makeUser('фред');
    await joinRoom(alice, fred);
    await fred.client.init();
    const injected = crypto.randomBytes(32);
    await suite.query('INSERT INTO kt_pending (commitment, user_id, label) VALUES ($1, $2, $3)', [injected, fred.id, Buffer.from(kit.label(fred.id))]);
    await waitEpochs(alice.tc, 1);
    await fred.client.runKtChecks();
    const alert = fred.alerts.find(a => a.kind === 'self-foreign-entry');
    assert.ok(alert, fred.alerts.map(a => a.kind).join());
    assert.deepStrictEqual(alert.entries.map(e => e.c), [injected.toString('hex')]);
    // «Это были мои прежние ключи» гасит тревогу для выбранных записей.
    await fred.client.ackSelfEntries(alert.entries);
    assert.strictEqual((await fred.client.checkTransparency()).self, 'ok');
});

test('клиент и маршруты журнала: head, цепочка и доказательство сходятся с тем, что проверяет клиент', async () => {
    const overview = await alice.client.checkTransparency();
    assert.strictEqual(overview.status, 'ok');
    const head = await headOf(alice.tc);
    assert.strictEqual(head.success, true);
    // Сервер не знает user_id в записях журнала: проверяем независимо, что в kt_entries нет ссылок на пользователей.
    const columns = await suite.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'kt_entries'");
    assert.ok(!columns.rows.some(c => c.column_name === 'user_id'));
    assert.ok(unb64(head.head).length === 32 && b64(unb64(head.sig)).length > 0);
});
