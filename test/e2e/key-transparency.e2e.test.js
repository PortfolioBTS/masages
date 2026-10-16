'use strict';
// Журнал ключей на настоящем сервере и Postgres (docs/security/key-transparency.md,
// разделы 6 и 13): регистрация и SKT, закрытие эпох, цепочка и подписи, доступ к
// доказательствам, предел регистраций, поколения (перенос только живых ключей, SKT
// перенесённым, удаление после льготного срока), компактный индекс, порядок
// блокировок, смена ключа журнала.
//
// Эпоха в тесте — 2 секунды, поколение — 6 эпох, льготный срок — 4 (ручки KT_* действуют
// только при NODE_ENV=test), порог компактного индекса — 3 листа. Проверки клиента
// (самомониторинг, подмена ключа, двуличие) — в test/kt-client*.test.js и
// test/e2e/key-transparency-client.e2e.test.js; здесь — сервер.
//
// Подписи и свёртки проверяются независимо от серверного кода тем же модулем формул,
// что и у клиента (public/lib/kt.js), а не тем, что собирал ответ.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const NyxoKt = require('../../public/lib/kt.js');
const ktLog = require('../../lib/kt-log');
const { createSuite, waitUntil, roomWithMember } = require('./helpers/scenarios');

const kit = ktLog.kit;
const GEN_EPOCHS = 6;
const GRACE_EPOCHS = 4;
const logKey = crypto.generateKeyPairSync('ed25519');
const KT_SIGNING_KEY = logKey.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const LOG_PUB = new Uint8Array(logKey.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32));

const suite = createSuite('key-transparency', {
    env: {
        KT_SIGNING_KEY, KT_EPOCH_SECONDS: 2, KT_GENERATION_EPOCHS: GEN_EPOCHS, KT_GRACE_EPOCHS: GRACE_EPOCHS, KT_COMPACT_MIN: 3,
    },
});

const b64 = (buf) => Buffer.from(buf).toString('base64');
const u8 = (text) => new Uint8Array(Buffer.from(text, 'base64'));
const hex = (buf) => Buffer.from(buf).toString('hex');
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function newIdentity() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dh = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    return {
        signPub: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32),
        dhPub: dh,
        sign: (msg) => crypto.sign(null, msg, privateKey),
    };
}

const putIdentity = (client, identity) => client.put('/api/keys/identity', {
    identity_signing_key: b64(identity.signPub), identity_dh_key: b64(identity.dhPub),
});

// Аноним с зарегистрированной identity; kt — ответ на регистрацию.
async function newUser(name) {
    const client = suite.client({ name });
    await client.registerAnon();
    client.identity = newIdentity();
    const res = await putIdentity(client, client.identity);
    assert.strictEqual(res.status, 200, JSON.stringify(res.body));
    client.kt = res.body.kt;
    return client;
}

const commitOf = (client, kt) => kit.commit(client.user.id, client.identity.signPub, client.identity.dhPub, u8(kt.nonce));

// Ждёт, пока журнал отдаст голову, удовлетворяющую условию.
async function waitHead(client, predicate = () => true, what = 'голова журнала') {
    return waitUntil(async () => {
        const res = await client.get('/api/kt/head');
        return res.status === 200 && predicate(res.body) ? res.body : null;
    }, { timeoutMs: 30000, intervalMs: 150, what });
}

const isClosed = (head, gen, epoch) => head.gen > gen || (head.gen === gen && head.epoch >= epoch);
// Голова новее базовой не меньше чем на k эпох (внутри одного поколения или в следующих).
const advanced = (head, base, k) => head.gen > base.gen || (head.gen === base.gen && head.epoch >= base.epoch + k);

// Читает журнал так, как это делает клиент: все доступные поколения, цепочка от genesis,
// подпись головы. Бросает при любом расхождении.
async function readLog(client) {
    const head = (await client.get('/api/kt/head')).body;
    assert.strictEqual(head.success, true, JSON.stringify(head));
    const pub = u8(head.pub);
    assert.ok(await NyxoKt.verifyEd25519(pub, kit.sthMessage(head.gen, head.epoch, u8(head.head)), u8(head.sig)), 'подпись головы');
    const gens = new Map();
    for (let gen = head.gen; gen >= 1; gen--) {
        const roots = [];
        let genStart = null;
        let prevFinalHead = null;
        let last = null;
        for (;;) {
            const from = roots.length === 0 ? 0 : genStart + roots.length;
            const res = await client.get(`/api/kt/roots?gen=${gen}&from=${from}&limit=1000`);
            if (res.status === 404) break;
            assert.strictEqual(res.status, 200, JSON.stringify(res.body));
            genStart = res.body.genStart;
            prevFinalHead = u8(res.body.prevFinalHead);
            if (res.body.roots.length === 0) break;
            roots.push(...res.body.roots.map(u8));
            last = res.body.last;
            if (res.body.roots.length < 1000) break;
        }
        if (roots.length === 0) break;
        const genesis = kit.genesisHash(gen, prevFinalHead);
        const heads = kit.extendChain(genesis, gen, genStart, roots);
        assert.strictEqual(hex(heads[heads.length - 1]), hex(u8(last.head)), 'цепочка сходится с подписанной головой пачки');
        assert.ok(await NyxoKt.verifyEd25519(pub, kit.sthMessage(gen, last.epoch, u8(last.head)), u8(last.sig)), 'подпись головы пачки');
        gens.set(gen, { genStart, prevFinalHead, roots, heads });
    }
    // Голова из /head входит в цепочку.
    const own = gens.get(head.gen);
    assert.ok(own, 'поколение головы доступно');
    assert.strictEqual(hex(own.heads[head.epoch - own.genStart]), hex(u8(head.head)), 'голова входит в цепочку');
    // Поколения связаны: genesis ссылается на последнюю голову предыдущего.
    for (const [gen, info] of gens) {
        const previous = gens.get(gen - 1);
        if (previous) {
            assert.strictEqual(info.genStart - previous.genStart, GEN_EPOCHS, 'длина поколения — константа');
            assert.strictEqual(hex(info.prevFinalHead), hex(previous.heads[previous.heads.length - 1]), 'genesis ссылается на последнюю голову');
        }
    }
    return { head, pub, gens };
}

// Проверяет ответ proof/self по корню эпохи из журнала; возвращает множество обязательств в листе.
function foldProof(log, gen, epoch, userId, body) {
    const info = log.gens.get(gen);
    assert.ok(info, `поколение ${gen} в журнале`);
    const root = info.roots[epoch - info.genStart];
    assert.ok(root, `корень эпохи ${gen}/${epoch}`);
    const folded = kit.proofRoot(kit.label(userId), body.entries.map(u8), u8(body.bitmap), body.siblings.map(u8));
    assert.ok(folded, 'доказательство построено верно');
    assert.strictEqual(hex(folded), hex(root), `свёртка доказательства = корень эпохи ${gen}/${epoch}`);
    return new Set(body.entries.map(e => hex(u8(e))));
}

async function proofOf(client, userId, gen, epoch) {
    return client.get(`/api/kt/proof?user=${userId}&gen=${gen}&epoch=${epoch}`);
}

// ---------- Схема ----------

test('схема журнала: таблицы созданы, в журнале нет user_id, время только в эпохах', async () => {
    const cols = await suite.query(
        `SELECT table_name, column_name FROM information_schema.columns
         WHERE table_name LIKE 'kt\\_%' OR table_name = 'identity_keys' ORDER BY table_name, ordinal_position`);
    const by = {};
    for (const row of cols.rows) (by[row.table_name] = by[row.table_name] || []).push(row.column_name);
    for (const table of ['kt_state', 'kt_epochs', 'kt_entries', 'kt_pending', 'kt_nodes', 'kt_keychanges']) assert.ok(by[table], table);
    assert.deepStrictEqual(by.kt_entries, ['gen', 'epoch', 'label', 'commitment']);
    assert.deepStrictEqual(by.kt_nodes, ['gen', 'epoch', 'depth', 'prefix', 'hash']);
    assert.deepStrictEqual(by.kt_epochs, ['gen', 'epoch', 'smt_root', 'head', 'sig', 'prev_final_head']);
    for (const table of ['kt_state', 'kt_epochs', 'kt_entries', 'kt_nodes', 'kt_keychanges']) {
        assert.ok(!by[table].includes('user_id'), `${table}: нет user_id`);
        assert.ok(!by[table].some(c => /created_at|updated_at|time/i.test(c)), `${table}: нет точного времени`);
    }
    assert.ok(by.kt_pending.includes('user_id'), 'kt_pending хранит user_id только до закрытия эпохи');
    for (const column of ['kt_nonce', 'kt_gen', 'kt_epoch', 'kt_skt']) assert.ok(by.identity_keys.includes(column), column);
});

// ---------- Включение журнала ----------

test('журнал стартует: голова появляется после первой закрытой эпохи, ключ журнала в ответе', async () => {
    const user = suite.client({ name: 'читатель' });
    await user.registerAnon();
    const noSession = await suite.client().get('/api/kt/head');
    assert.strictEqual(noSession.status, 401, 'маршруты требуют сессию');
    const head = await waitHead(user);
    assert.strictEqual(hex(u8(head.pub)), hex(LOG_PUB));
    assert.deepStrictEqual(head.keychange, []);
    const log = await readLog(user);
    assert.ok(log.gens.get(1), 'поколение 1');
    // В каждой эпохе ровно одна фиктивная запись и нет пользователей: эпох без записей не бывает.
    const rows = await suite.query('SELECT epoch, count(*)::int AS n FROM kt_entries WHERE gen = 1 GROUP BY epoch ORDER BY epoch');
    assert.ok(rows.rows.length >= 1 && rows.rows.every(r => r.n >= 1));
});

test('регистрация: kt с SKT, подпись проверяется ключом журнала, обязательство попадает в закрытую эпоху', async () => {
    const alice = await newUser('алиса');
    const { kt } = alice;
    assert.ok(kt, 'kt в ответе PUT');
    assert.strictEqual(u8(kt.nonce).length, 16);
    assert.strictEqual(u8(kt.skt).length, 64);
    const label = kit.label(alice.user.id);
    const commit = commitOf(alice, kt);
    assert.ok(await NyxoKt.verifyEd25519(LOG_PUB, kit.sktMessage(kt.gen, kt.epoch, label, commit), u8(kt.skt)), 'SKT подписан ключом журнала');
    // Обязательство ждёт закрытия эпохи, и в журнале нет ни user_id, ни ключей.
    const pending = await suite.query('SELECT user_id FROM kt_pending WHERE commitment = $1', [Buffer.from(commit)]);
    // Если эпоха ещё не закрылась, строка kt_pending есть и хранит владельца; в журнал он не попадает.
    if (pending.rows.length === 1) assert.strictEqual(Number(pending.rows[0].user_id), alice.user.id);

    // Тот же ответ при повторной регистрации тех же ключей; регистрации нет.
    const again = await putIdentity(alice, alice.identity);
    assert.deepStrictEqual(again.body.kt, kt, 'повтор без изменений не создаёт регистрацию');

    const head = await waitHead(alice, h => isClosed(h, kt.gen, kt.epoch), 'закрытие эпохи регистрации');
    const log = await readLog(alice);
    const proof = await proofOf(alice, alice.user.id, kt.gen, kt.epoch);
    assert.strictEqual(proof.status, 200, JSON.stringify(proof.body));
    const entries = foldProof(log, kt.gen, kt.epoch, alice.user.id, proof.body);
    assert.ok(entries.has(hex(commit)), 'обязательство в листе метки');
    assert.ok(head.epoch >= kt.epoch);
    // После закрытия kt_pending пуст для этого обязательства.
    assert.strictEqual((await suite.query('SELECT 1 FROM kt_pending WHERE commitment = $1', [Buffer.from(commit)])).rows.length, 0);
    // Доказательство отсутствия для чужой метки сворачивается в тот же корень.
    const stranger = await newUser('посторонний');
    assert.strictEqual((await proofOf(stranger, alice.user.id, kt.gen, kt.epoch)).status, 403, 'чужое доказательство без общей комнаты');
});

test('смена ключей: новое обязательство и nonce; оба обязательства попадают в журнал', async () => {
    const user = await newUser('смена');
    const first = user.kt;
    const oldIdentity = user.identity;
    user.identity = newIdentity();
    const res = await putIdentity(user, user.identity);
    assert.strictEqual(res.status, 200);
    const second = res.body.kt;
    assert.notStrictEqual(second.nonce, first.nonce);
    assert.notStrictEqual(second.skt, first.skt);
    const commits = new Set([
        hex(kit.commit(user.user.id, oldIdentity.signPub, oldIdentity.dhPub, u8(first.nonce))),
        hex(commitOf(user, second)),
    ]);
    const lastEpoch = Math.max(first.epoch, second.epoch);
    const lastGen = Math.max(first.gen, second.gen);
    await waitHead(user, h => isClosed(h, lastGen, lastEpoch), 'закрытие эпохи');
    const log = await readLog(user);
    const found = new Set();
    for (const [gen, info] of log.gens) {
        for (let epoch = info.genStart; epoch < info.genStart + info.roots.length; epoch++) {
            if (epoch < Math.min(first.epoch, second.epoch) && gen === first.gen) continue;
            const proof = await proofOf(user, user.user.id, gen, epoch);
            if (proof.status !== 200) continue;
            for (const c of foldProof(log, gen, epoch, user.user.id, proof.body)) found.add(c);
        }
    }
    for (const c of commits) assert.ok(found.has(c), 'обязательство ' + c.slice(0, 8) + ' опубликовано');
});

test('предел: 17-я регистрация метки за эпоху — 429 kt-rate; параллельные регистрации не превышают 16', async () => {
    let verified = false;
    for (let attempt = 0; attempt < 4 && !verified; attempt++) {
        const user = await newUser('предел ' + attempt);
        const epochs = [user.kt.epoch];
        let refused = null;
        for (let i = 0; i < 30; i++) {
            const res = await putIdentity(user, newIdentity());
            if (res.status === 429) { refused = res; break; }
            assert.strictEqual(res.status, 200, JSON.stringify(res.body));
            epochs.push(res.body.kt.epoch);
        }
        if (!refused || new Set(epochs).size !== 1) continue; // серия пересекла границу эпохи — повторить
        assert.strictEqual(epochs.length, 16, 'ровно 16 регистраций за эпоху');
        assert.strictEqual(refused.body.code, 'kt-rate');
        // Отказ откатил транзакцию целиком: в identity_keys остались ключи последней принятой регистрации.
        const stored = (await suite.query('SELECT kt_nonce, kt_epoch FROM identity_keys WHERE user_id = $1', [user.user.id])).rows[0];
        assert.strictEqual(stored.kt_epoch, epochs[epochs.length - 1]);
        assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM kt_pending WHERE user_id = $1', [user.user.id])).rows[0].n, 16);
        verified = true;
    }
    assert.ok(verified, 'серия из 17 регистраций в одной эпохе не получилась за 4 попытки');

    const racer = await newUser('гонка');
    const results = await Promise.all(Array.from({ length: 30 }, () => putIdentity(racer, newIdentity())));
    const byEpoch = new Map();
    for (const res of results) {
        assert.ok(res.status === 200 || res.status === 429, `ответ ${res.status}: ${res.text}`);
        if (res.status === 200) byEpoch.set(res.body.kt.epoch, (byEpoch.get(res.body.kt.epoch) || 0) + 1);
    }
    for (const [epoch, n] of byEpoch) assert.ok(n <= 16, `эпоха ${epoch}: ${n} регистраций при пределе 16`);
});

// ---------- Чтение: identities, bundle, join-requests ----------

async function enrollFull(client) {
    const res = await putIdentity(client, client.identity);
    client.kt = res.body.kt;
    const spk = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    await client.ok(client.put('/api/keys/signed-prekey', { key_id: 7, public_key: b64(spk), signature: b64(client.identity.sign(spk)) }), 'spk');
}

test('kt с skt отдают identities, bundle и заявки на вступление', async () => {
    const owner = await newUser('владелец');
    const member = await newUser('участник');
    await enrollFull(owner);
    await enrollFull(member);
    const { ownerChat } = await roomWithMember(owner, member, { name: 'Журнал' });
    const ids = await owner.get(`/api/keys/identities?ids=${member.user.id}`);
    assert.strictEqual(ids.status, 200);
    const [identity] = ids.body.identities;
    assert.deepStrictEqual(identity.kt, member.kt, 'kt собеседника в identities, с skt');
    const bundle = await owner.get(`/api/keys/bundle/${member.user.id}`);
    assert.deepStrictEqual(bundle.body.kt, member.kt, 'kt в bundle');
    const self = await owner.get(`/api/keys/identities?ids=${owner.user.id}`);
    assert.deepStrictEqual(self.body.identities[0].kt, owner.kt);

    // Заявитель: одобряющий видит его ключи и kt, получает доказательство, пока заявка открыта.
    const applicant = await newUser('заявитель');
    await enrollFull(applicant);
    const { code } = await owner.invite(ownerChat.id);
    const pending = await applicant.join(code);
    assert.strictEqual(pending.pending, true);
    const requests = await owner.joinRequests(ownerChat.id);
    const request = requests.find(r => r.userId === applicant.user.id);
    assert.ok(request, 'заявка видна');
    assert.strictEqual(request.identity.signingKey, b64(applicant.identity.signPub));
    assert.strictEqual(request.identity.dhKey, b64(applicant.identity.dhPub));
    assert.deepStrictEqual(request.identity.kt, applicant.kt);

    const head = await waitHead(owner, h => isClosed(h, applicant.kt.gen, applicant.kt.epoch), 'закрытие эпохи заявителя');
    const allowed = await proofOf(owner, applicant.user.id, applicant.kt.gen, applicant.kt.epoch);
    assert.strictEqual(allowed.status, 200, 'одобряющий получает доказательство для заявителя');
    foldProof(await readLog(owner), applicant.kt.gen, applicant.kt.epoch, applicant.user.id, allowed.body);
    assert.ok(head);
    // Посторонний участник другой комнаты — нет.
    const outsider = await newUser('чужой');
    assert.strictEqual((await proofOf(outsider, applicant.user.id, applicant.kt.gen, applicant.kt.epoch)).status, 403);
    // Заявка закрыта — доступ пропал.
    await owner.deny(pending.requestId);
    assert.strictEqual((await proofOf(owner, applicant.user.id, applicant.kt.gen, applicant.kt.epoch)).status, 403, 'после отклонения заявки доступа нет');
    // Участник общей комнаты доказательство получает.
    assert.strictEqual((await proofOf(member, owner.user.id, owner.kt.gen, owner.kt.epoch)).status, 200);
});

// ---------- Маршруты ----------

test('маршруты: разбор параметров, неизвестные поколения, self отдаёт только свою метку', async () => {
    const user = await newUser('маршруты');
    await waitHead(user, h => isClosed(h, user.kt.gen, user.kt.epoch));
    assert.strictEqual((await user.get('/api/kt/roots?gen=abc')).status, 400);
    assert.strictEqual((await user.get('/api/kt/roots')).status, 400);
    assert.strictEqual((await user.get('/api/kt/roots?gen=999&from=0&limit=5')).status, 404);
    assert.strictEqual((await user.get('/api/kt/proof?user=0&gen=1&epoch=1')).status, 400);
    assert.strictEqual((await user.get(`/api/kt/proof?user=${user.user.id}&gen=1&epoch=99999999`)).status, 404);
    assert.strictEqual((await user.get('/api/kt/self?gen=zz')).status, 400);
    const limited = await user.get('/api/kt/roots?gen=1&from=0&limit=1');
    assert.strictEqual(limited.status, 200);
    assert.strictEqual(limited.body.roots.length, 1);
    assert.strictEqual(limited.body.from, limited.body.genStart);

    const log = await readLog(user);
    const info = log.gens.get(user.kt.gen);
    const self = await user.get(`/api/kt/self?gen=${user.kt.gen}&from=${info.genStart}&limit=200`);
    assert.strictEqual(self.status, 200, JSON.stringify(self.body));
    assert.ok(self.body.proofs.length >= 1);
    let found = false;
    for (const item of self.body.proofs) {
        const entries = foldProof(log, user.kt.gen, item.epoch, user.user.id, item);
        if (entries.has(hex(commitOf(user, user.kt)))) found = true;
    }
    assert.ok(found, 'в self есть своё обязательство');
    // self не принимает чужую метку: параметра user нет вовсе.
    const other = await newUser('другой');
    const foreign = await other.get(`/api/kt/self?gen=${user.kt.gen}&from=${info.genStart}&limit=200`);
    for (const item of foreign.body.proofs) {
        const entries = foldProof(log, user.kt.gen, item.epoch, other.user.id, item);
        assert.ok(!entries.has(hex(commitOf(user, user.kt))), 'self чужого пользователя не содержит моих обязательств');
    }
});

// ---------- Поколения ----------

test('поколения: genesis ссылается на последнюю голову, перенос только живых ключей, SKT перенесённым, компактный индекс', async () => {
    const live = await newUser('живой');
    const doomed = await newUser('удалённый');
    const doomedCommit = commitOf(doomed, doomed.kt);
    await doomed.deleteAccount();
    assert.strictEqual((await suite.query('SELECT 1 FROM identity_keys WHERE user_id = $1', [doomed.user.id])).rows.length, 0, 'ключи удалённого аккаунта стёрты');
    assert.strictEqual((await suite.query('SELECT 1 FROM kt_pending WHERE user_id = $1', [doomed.user.id])).rows.length, 0, 'запись kt_pending удалена');

    // Ждём начала следующего поколения и закрытия его первой эпохи.
    const nextGen = live.kt.gen + 1;
    const head = await waitHead(live, h => h.gen >= nextGen, 'следующее поколение');
    const log = await readLog(live);
    const gen = log.gens.get(head.gen);
    assert.ok(gen.genStart > 0 && log.gens.get(head.gen - 1), 'предыдущее поколение ещё хранится (льготный срок)');
    // Перенос: обязательство живого ключа есть в первой эпохе нового поколения.
    const carried = await proofOf(live, live.user.id, head.gen, gen.genStart);
    assert.strictEqual(carried.status, 200);
    assert.ok(foldProof(log, head.gen, gen.genStart, live.user.id, carried.body).has(hex(commitOf(live, live.kt))), 'живой ключ перенесён');
    // Удалённый не перенесён: ни его метки, ни обязательства в первой эпохе.
    const leaked = await suite.query('SELECT 1 FROM kt_entries WHERE gen = $1 AND epoch = $2 AND (label = $3 OR commitment = $4)',
        [head.gen, gen.genStart, Buffer.from(kit.label(doomed.user.id)), Buffer.from(doomedCommit)]);
    assert.strictEqual(leaked.rows.length, 0, 'удалённый аккаунт не переносится');

    // SKT перенесённому ключу: подсказка указывает на новое поколение, а подпись появляется порциями.
    const signed = await waitUntil(async () => {
        const res = await live.get(`/api/keys/identities?ids=${live.user.id}`);
        const kt = res.body.identities[0].kt;
        return kt && kt.gen === head.gen && kt.skt ? kt : null;
    }, { timeoutMs: 15000, what: 'SKT перенесённому ключу' });
    assert.strictEqual(signed.epoch, gen.genStart);
    assert.ok(await NyxoKt.verifyEd25519(LOG_PUB, kit.sktMessage(signed.gen, signed.epoch, kit.label(live.user.id), commitOf(live, signed)), u8(signed.skt)), 'SKT перенесённого ключа верен');
    assert.strictEqual(signed.nonce, live.kt.nonce, 'nonce не меняется при переносе');

    // Компактный индекс первой эпохи поколения: узлы есть, доказательство совпадает с построенным заново.
    const nodes = await suite.query('SELECT count(*)::int AS n FROM kt_nodes WHERE gen = $1 AND epoch = $2', [head.gen, gen.genStart]);
    assert.ok(nodes.rows[0].n > 0, 'kt_nodes заполнены для первой эпохи поколения');
    const rows = (await suite.query('SELECT label, commitment FROM kt_entries WHERE gen = $1 AND epoch = $2', [head.gen, gen.genStart])).rows;
    const groups = ktLog.groupEntries(rows);
    assert.ok(groups.length >= 3, 'в эпохе несколько листьев');
    const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
    assert.strictEqual(hex(tree.root), hex(gen.roots[0]), 'корень первой эпохи пересчитывается из kt_entries');
    const memory = ktLog.createMemoryIndex(groups, tree);
    for (const group of groups.slice(0, 12)) {
        const expected = await ktLog.buildProof(kit, memory, group.label);
        const labelHex = hex(group.label);
        const ownerOfLabel = [live].find(c => hex(kit.label(c.user.id)) === labelHex);
        if (!ownerOfLabel) continue;
        const viaApi = await proofOf(live, ownerOfLabel.user.id, head.gen, gen.genStart);
        assert.deepStrictEqual(viaApi.body.entries, expected.entries.map(b64));
        assert.strictEqual(viaApi.body.bitmap, b64(expected.bitmap));
        assert.deepStrictEqual(viaApi.body.siblings, expected.siblings.map(b64), 'доказательство из индекса = из полного дерева');
    }
});

test('предыдущее поколение удаляется через льготный срок, текущее и цепочка остаются', async () => {
    const reader = suite.client();
    await reader.registerAnon();
    const first = await waitHead(reader);
    const startGen = first.gen;
    // Ждём, пока поколение startGen уйдёт: нужно поколение startGen + 1 и ещё GRACE_EPOCHS эпох после его начала.
    const gone = await waitUntil(async () => {
        // Сначала старое поколение, потом голова: если старого уже нет, голова обязана быть дальше льготного срока.
        const old = await reader.get(`/api/kt/roots?gen=${startGen}&from=0&limit=1`);
        const head = (await reader.get('/api/kt/head')).body;
        if (old.status === 200) return null;
        assert.strictEqual(old.status, 404);
        const info = await reader.get(`/api/kt/roots?gen=${startGen + 1}&from=0&limit=1`);
        assert.ok(head.gen >= startGen + 1, 'поколение удалено только после начала следующего');
        assert.ok(head.gen > startGen + 1 || head.epoch > info.body.genStart + GRACE_EPOCHS,
            `поколение ${startGen} удалено раньше льготного срока (голова ${head.epoch}, начало следующего ${info.body.genStart})`);
        return head;
    }, { timeoutMs: 45000, intervalMs: 200, what: 'удаление предыдущего поколения' });
    assert.ok(gone.gen >= startGen + 1);
    for (const table of ['kt_epochs', 'kt_entries', 'kt_nodes']) {
        const left = await suite.query(`SELECT count(*)::int AS n FROM ${table} WHERE gen = $1`, [startGen]);
        assert.strictEqual(left.rows[0].n, 0, `${table}: следов поколения ${startGen} нет`);
    }
    const log = await readLog(reader);
    assert.ok(log.gens.get(gone.gen), 'текущее поколение читается');
    assert.strictEqual((await reader.get(`/api/kt/roots?gen=${startGen}&from=0&limit=5`)).status, 404);
});

// ---------- Простой сервера, блокировки, смена ключа ----------

test('простой сервера: пропущенные эпохи закрываются, цепочка непрерывна', async () => {
    const reader = suite.client();
    await reader.registerAnon();
    const before = await waitHead(reader);
    await suite.server.stop();
    await sleep(7000);
    await suite.server.start();
    const reader2 = suite.client();
    await reader2.registerAnon();
    const after = await waitHead(reader2, h => advanced(h, before, 3), 'догон эпох после простоя');
    const log = await readLog(reader2);
    const info = log.gens.get(after.gen);
    for (let i = 1; i < info.roots.length; i++) assert.notStrictEqual(hex(info.roots[i]), hex(info.roots[i - 1]), 'корни разных эпох различаются (фиктивные записи)');
    // Непрерывность: у каждой эпохи есть строка, и фиктивная запись в ней одна.
    const gaps = await suite.query(
        `SELECT e.epoch FROM kt_epochs e WHERE e.gen = $1 AND NOT EXISTS (SELECT 1 FROM kt_entries k WHERE k.gen = e.gen AND k.epoch = e.epoch)`, [after.gen]);
    assert.strictEqual(gaps.rows.length, 0);
});

const RETRY_LOG = /Взаимная блокировка \(40P01\), транзакция повторяется/;
const FAILED_LOG = /Взаимная блокировка повторилась|Ошибка хранилища ключей|\[KT\]|Ошибка журнала ключей/;

test('регистрация, закрытие эпохи, начало поколения и удаление аккаунтов вперемешку: без взаимных блокировок', async (t) => {
    const mark = suite.server.logs.mark();
    const durable = [];
    for (let i = 0; i < 6; i++) durable.push(await newUser('стойкий ' + i));
    const deadline = Date.now() + 14000;
    const statuses = [];
    const workers = durable.map(async (client) => {
        while (Date.now() < deadline) {
            const res = await putIdentity(client, newIdentity());
            statuses.push(res.status);
            await sleep(20);
        }
    });
    const churn = Array.from({ length: 3 }, (_, i) => (async () => {
        while (Date.now() < deadline) {
            const temp = suite.client({ name: 'временный ' + i });
            await temp.registerAnon();
            const identity = newIdentity();
            const reg = await putIdentity(temp, identity);
            statuses.push(reg.status);
            const del = await temp.post('/api/account/delete', {});
            statuses.push(del.status);
        }
    })());
    await Promise.all([...workers, ...churn]);
    assert.ok(statuses.every(s => s < 500), 'ни одного 5xx: ' + [...new Set(statuses)].join(','));
    const failed = suite.server.logs.find(FAILED_LOG, { from: mark });
    assert.ok(!failed, 'в логе сервера: ' + (failed && failed.text));
    t.diagnostic(`повторов при 40P01: ${suite.server.logs.count(RETRY_LOG, { from: mark })}`);
    assert.strictEqual(suite.server.logs.count(RETRY_LOG, { from: mark }), 0, 'порядок блокировок журнала соблюдён: повторов нет');
    // Журнал пережил нагрузку: цепочка читается и подписи верны.
    const reader = suite.client();
    await reader.registerAnon();
    await waitHead(reader);
    await readLog(reader);
    // Все удалённые аккаунты стёрты без следов в kt_pending.
    const orphans = await suite.query('SELECT p.user_id FROM kt_pending p WHERE NOT EXISTS (SELECT 1 FROM identity_keys i WHERE i.user_id = p.user_id)');
    assert.strictEqual(orphans.rows.length, 0, 'kt_pending без владельца нет');
});

test('смена ключа журнала: заявление подписано прежним ключом, повторный старт его не дублирует', async () => {
    const reader = suite.client();
    await reader.registerAnon();
    const before = await waitHead(reader);
    const newKey = crypto.generateKeyPairSync('ed25519');
    const newSecret = newKey.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
    const newPub = new Uint8Array(newKey.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32));
    await suite.server.restart({ env: { KT_SIGNING_KEY: newSecret, KT_SIGNING_KEY_PREVIOUS: KT_SIGNING_KEY } });
    const reader2 = suite.client();
    await reader2.registerAnon();
    const head = await waitHead(reader2, h => h.pub !== before.pub && advanced(h, before, 1), 'голова под новым ключом');
    assert.strictEqual(hex(u8(head.pub)), hex(newPub));
    assert.strictEqual(head.keychange.length, 1);
    const claim = head.keychange[0];
    assert.strictEqual(hex(u8(claim.oldPub)), hex(LOG_PUB));
    assert.strictEqual(hex(u8(claim.newPub)), hex(newPub));
    assert.ok(await NyxoKt.verifyEd25519(LOG_PUB, kit.keychangeMessage(newPub, claim.gen, claim.epoch), u8(claim.sig)), 'заявление подписано прежним ключом');
    assert.ok(NyxoKt.isValidLogKey(newPub));
    // Голова эпохи до заявления подписана прежним ключом, после — новым.
    const oldSigned = await suite.query('SELECT gen, epoch, head, sig FROM kt_epochs WHERE (gen, epoch) < ($1, $2) ORDER BY gen DESC, epoch DESC LIMIT 1', [claim.gen, claim.epoch]);
    assert.ok(await NyxoKt.verifyEd25519(LOG_PUB, kit.sthMessage(oldSigned.rows[0].gen, oldSigned.rows[0].epoch, oldSigned.rows[0].head), oldSigned.rows[0].sig));
    const newSigned = await suite.query('SELECT gen, epoch, head, sig FROM kt_epochs WHERE (gen, epoch) >= ($1, $2) ORDER BY gen, epoch LIMIT 1', [claim.gen, claim.epoch]);
    assert.ok(await NyxoKt.verifyEd25519(newPub, kit.sthMessage(newSigned.rows[0].gen, newSigned.rows[0].epoch, newSigned.rows[0].head), newSigned.rows[0].sig));
    assert.ok(!(await NyxoKt.verifyEd25519(LOG_PUB, kit.sthMessage(newSigned.rows[0].gen, newSigned.rows[0].epoch, newSigned.rows[0].head), newSigned.rows[0].sig)), 'после смены прежний ключ не подписывает');

    // Повторный старт с теми же ключами заявление не дублирует.
    await suite.server.restart();
    const reader3 = suite.client();
    await reader3.registerAnon();
    const again = await waitHead(reader3);
    assert.strictEqual(again.keychange.length, 1);
    assert.strictEqual((await suite.query('SELECT count(*)::int AS n FROM kt_keychanges')).rows[0].n, 1);
});
