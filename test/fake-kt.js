'use strict';
// Журнал ключей в памяти для протокольных тестов клиента (public/lib/kt-client.js) и
// «злонамеренный сервер» (docs/security/key-transparency.md, раздел 13). Те же формулы и тот же код
// дерева, что у настоящего сервера (lib/kt-log.js, public/lib/kt.js), без Postgres и HTTP: тест сам
// закрывает эпохи и подменяет ответы.
//
//   const kt = new FakeKt({ genEpochs: 6, graceEpochs: 4 });
//   kt.register(userId, { identity_signing_key, identity_dh_key })  → kt-подсказка (SKT на открытую эпоху)
//   await kt.closeEpoch() / closeEpochs(n)       → закрыть открытую эпоху (перенос при смене поколения)
//   kt.transportFor(userId)                      → { ktHead, ktRoots, ktProof, ktSelf } как у makeFetchTransport
//   kt.hintFor(userId)                           → kt в ответах identities и bundle
//
// Подмены (kt.evil): hideHint (Set userId) — kt: null; disabled — 503 kt-disabled; notFound — 404;
//   networkDown — отказ сети; noProof — 404 на proof; badProof — чужое доказательство; notReady — 503 kt-not-ready;
//   dropGen (Set) — поколение не отдаётся; earlyPurge — предыдущее поколение не отдаётся сразу.
// Методы: clone() (развилка: общая история, дальше разные эпохи), rollbackTo(epoch), rewrite(epoch),
//   rotateKey({ claim, backdated }), conflictingClaim(), injectEntry(), forgetUser().

const crypto = require('crypto');
const ktLog = require('../lib/kt-log');

const kit = ktLog.kit;
const b64 = (buf) => Buffer.from(buf).toString('base64');
const hex = (buf) => Buffer.from(buf).toString('hex');
const unb64 = (text) => new Uint8Array(Buffer.from(text, 'base64'));
const EPOCH_BASE = 40000;

function newLogKey() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
        pub: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)),
        sign: (msg) => new Uint8Array(crypto.sign(null, Buffer.from(msg), privateKey)),
    };
}

const respond = (status, data) => ({ status, data });

class FakeKt {
    constructor({ genEpochs = 6, graceEpochs = 4, startEpoch = EPOCH_BASE, key = newLogKey() } = {}) {
        this.key = key;
        this.genEpochs = genEpochs;
        this.graceEpochs = graceEpochs;
        this.gen = 1;
        this.genStart = startEpoch;
        this.openEpoch = startEpoch;
        this.lastHead = new Uint8Array(32);
        this.pending = [];                                        // { label, commit }
        this.users = new Map();                                   // userId -> { signPub, dhPub, nonce, gen, epoch, skt }
        this.epochs = new Map();                                  // 'gen:epoch' -> запись закрытой эпохи
        this.gens = new Map([[1, { genStart: startEpoch, prevFinalHead: new Uint8Array(32) }]]);
        this.keychanges = [];                                     // { oldPub, newPub, gen, epoch, sig }
        this.signWith = null;                                     // ключ, которым подписываются головы (по умолчанию key)
        this.visibleUntil = null;                                 // { gen, epoch }: показываем только эпохи не новее
        this.evil = {
            hideHint: new Set(), disabled: false, notFound: false, networkDown: false,
            noProof: false, badProof: false, notReady: false, dropGen: new Set(), earlyPurge: false,
        };
        this.calls = { head: 0, roots: 0, proof: 0, self: 0 };
        this.canRead = () => true;
    }

    // ---------- Регистрация и закрытие эпох ----------

    register(userId, body) {
        const signPub = unb64(body.identity_signing_key);
        const dhPub = unb64(body.identity_dh_key);
        const old = this.users.get(userId);
        if (old && hex(old.signPub) === hex(signPub) && hex(old.dhPub) === hex(dhPub)) return this.hintFor(userId, { raw: true });
        const nonce = new Uint8Array(crypto.randomBytes(16));
        const commit = kit.commit(userId, signPub, dhPub, nonce);
        const label = kit.label(userId);
        const skt = this.key.sign(kit.sktMessage(this.gen, this.openEpoch, label, commit));
        this.pending.push({ label, commit });
        this.users.set(userId, { signPub, dhPub, nonce, gen: this.gen, epoch: this.openEpoch, skt });
        return this.hintFor(userId, { raw: true });
    }

    // kt в ответах сервера: { gen, epoch, nonce, skt } либо null (в том числе при подмене).
    hintFor(userId, { raw = false } = {}) {
        if (!raw && (this.evil.hideHint.has(userId) || this.evil.disabled)) return null;
        const u = this.users.get(userId);
        if (!u) return null;
        return { gen: u.gen, epoch: u.epoch, nonce: b64(u.nonce), skt: u.skt ? b64(u.skt) : null };
    }

    // Подмена: обязательство под чужой меткой, которого владелец не регистрировал, — в ближайшую эпоху.
    injectEntry(userId, commit = new Uint8Array(crypto.randomBytes(32))) {
        this.pending.push({ label: kit.label(userId), commit });
        return commit;
    }

    // Сервер забывает запись пользователя в журнале (но продолжает выдавать его ключи): ключи без обещания.
    forgetUser(userId) { this.users.delete(userId); }

    signHead(gen, epoch, head) {
        return (this.signWith || this.key).sign(kit.sthMessage(gen, epoch, head));
    }

    async closeEpoch() {
        const gen = this.gen;
        const epoch = this.openEpoch;
        const pairs = this.pending.map(p => ({ label: p.label, commitment: p.commit }));
        if (epoch === this.genStart) {
            for (const [userId, u] of this.users) {
                pairs.push({ label: kit.label(userId), commitment: kit.commit(userId, u.signPub, u.dhPub, u.nonce) });
            }
        }
        pairs.push({ label: new Uint8Array(crypto.randomBytes(16)), commitment: new Uint8Array(crypto.randomBytes(32)) });
        const groups = ktLog.groupEntries(pairs);
        const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
        const info = this.gens.get(gen);
        const prev = epoch === this.genStart ? kit.genesisHash(gen, info.prevFinalHead) : this.lastHead;
        const head = new Uint8Array(kit.headHash(gen, epoch, prev, tree.root));
        const sig = this.signHead(gen, epoch, head);
        this.epochs.set(gen + ':' + epoch, { gen, epoch, groups, tree, root: new Uint8Array(tree.root), head, sig });
        this.lastHead = head;
        this.pending = [];
        this.openEpoch = epoch + 1;
        if (this.openEpoch - this.genStart >= this.genEpochs) {
            this.gen = gen + 1;
            this.genStart = this.openEpoch;
            this.gens.set(this.gen, { genStart: this.genStart, prevFinalHead: head });
            for (const [userId, u] of this.users) {
                u.gen = this.gen;
                u.epoch = this.genStart;
                u.skt = this.key.sign(kit.sktMessage(this.gen, this.genStart, kit.label(userId), kit.commit(userId, u.signPub, u.dhPub, u.nonce)));
            }
        }
        return { gen, epoch };
    }

    async closeEpochs(n) {
        const out = [];
        for (let i = 0; i < n; i++) out.push(await this.closeEpoch());
        return out;
    }

    // Закрыть эпохи, пока открытой не станет эпоха epoch (включительно закрытые до epoch - 1).
    async closeUntilOpen(epoch) {
        while (this.openEpoch < epoch) await this.closeEpoch();
    }

    // ---------- Подмены ----------

    // Развилка: общая история до сих пор, дальше эпохи закрываются по-разному (у каждой своя фиктивная запись).
    clone() {
        const copy = new FakeKt({ genEpochs: this.genEpochs, graceEpochs: this.graceEpochs, key: this.key });
        copy.gen = this.gen; copy.genStart = this.genStart; copy.openEpoch = this.openEpoch; copy.lastHead = this.lastHead;
        copy.pending = this.pending.slice();
        copy.users = new Map([...this.users].map(([id, u]) => [id, { ...u }]));
        copy.epochs = new Map(this.epochs);
        copy.gens = new Map([...this.gens].map(([g, info]) => [g, { ...info }]));
        copy.keychanges = this.keychanges.slice();
        copy.signWith = this.signWith;
        return copy;
    }

    // Откат: показываем эпохи не новее (gen, epoch).
    rollbackTo(gen, epoch) { this.visibleUntil = { gen, epoch }; }

    // Переписать историю: корень закрытой эпохи заменяется, головы всех последующих пересчитываются и переподписываются.
    async rewrite(gen, epoch) {
        const record = this.epochs.get(gen + ':' + epoch);
        if (!record) throw new Error('нет эпохи');
        const groups = ktLog.groupEntries([
            ...record.groups.flatMap(g => g.entries.map(c => ({ label: g.label, commitment: c }))),
            { label: new Uint8Array(crypto.randomBytes(16)), commitment: new Uint8Array(crypto.randomBytes(32)) },
        ]);
        const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
        const info = this.gens.get(gen);
        let prev = epoch === info.genStart ? kit.genesisHash(gen, info.prevFinalHead) : this.epochs.get(gen + ':' + (epoch - 1)).head;
        record.groups = groups; record.tree = tree; record.root = new Uint8Array(tree.root);
        for (let e = epoch; this.epochs.has(gen + ':' + e); e++) {
            const r = this.epochs.get(gen + ':' + e);
            r.head = new Uint8Array(kit.headHash(gen, e, prev, r.root));
            r.sig = this.signHead(gen, e, r.head);
            prev = r.head;
        }
        if (this.gen === gen) this.lastHead = prev;
    }

    // Смена ключа журнала. claim: приложить заявление, подписанное прежним ключом, действующее с первой эпохи под новым;
    // backdated — датировать заявление раньше уже принятых голов; staleSigner — головы после смены всё ещё подписывает прежний.
    rotateKey({ claim = true, backdated = false, staleSigner = false } = {}) {
        const old = this.key;
        const next = newLogKey();
        let statement = null;
        if (claim) {
            const epoch = backdated ? Math.max(0, this.openEpoch - 3) : this.openEpoch;
            statement = { oldPub: old.pub, newPub: next.pub, gen: this.gen, epoch, sig: old.sign(kit.keychangeMessage(next.pub, this.gen, epoch)) };
            this.keychanges.push(statement);
        }
        this.key = next;
        this.signWith = staleSigner ? old : null;
        return { old, next, claim: statement };
    }

    // Второе заявление тем же прежним ключом на другой новый ключ — двуличие.
    conflictingClaim(oldKey, gen = this.gen, epoch = this.openEpoch) {
        const other = newLogKey();
        const statement = { oldPub: oldKey.pub, newPub: other.pub, gen, epoch, sig: oldKey.sign(kit.keychangeMessage(other.pub, gen, epoch)) };
        this.keychanges.push(statement);
        return statement;
    }

    // ---------- Ответы маршрутов ----------

    visible() {
        const list = [...this.epochs.values()].sort((a, b) => a.gen - b.gen || a.epoch - b.epoch);
        if (!this.visibleUntil) return list;
        return list.filter(r => r.gen < this.visibleUntil.gen || (r.gen === this.visibleUntil.gen && r.epoch <= this.visibleUntil.epoch));
    }

    // Поколение хранится: текущее и предыдущее до конца льготного срока (как задача purge на сервере).
    available(gen) {
        if (this.evil.dropGen.has(gen) || !this.gens.has(gen)) return false;
        if (gen === this.gen) return true;
        if (this.evil.earlyPurge) return false;
        const lastClosed = this.openEpoch - 1;
        const next = this.gens.get(gen + 1);
        if (!next) return true;
        return gen === this.gen - 1 && lastClosed <= next.genStart + this.graceEpochs;
    }

    gate() {
        if (this.evil.networkDown) throw new TypeError('fetch failed');
        if (this.evil.disabled) return respond(503, { success: false, code: 'kt-disabled' });
        if (this.evil.notFound) return respond(404, { success: false });
        return null;
    }

    head() {
        this.calls.head++;
        const blocked = this.gate();
        if (blocked) return blocked;
        const list = this.visible();
        if (this.evil.notReady || list.length === 0) return respond(503, { success: false, code: 'kt-not-ready' });
        const last = list[list.length - 1];
        const info = this.gens.get(last.gen);
        return respond(200, {
            success: true, pub: b64(this.key.pub), gen: last.gen, epoch: last.epoch, head: b64(last.head), sig: b64(last.sig),
            genStart: info.genStart, prevFinalHead: b64(info.prevFinalHead),
            keychange: this.keychanges.map(c => ({ oldPub: b64(c.oldPub), newPub: b64(c.newPub), gen: c.gen, epoch: c.epoch, sig: b64(c.sig) })),
        });
    }

    roots(gen, from, limit) {
        this.calls.roots++;
        const blocked = this.gate();
        if (blocked) return blocked;
        if (!this.available(gen)) return respond(404, { success: false, code: 'kt-not-found' });
        const info = this.gens.get(gen);
        const list = this.visible().filter(r => r.gen === gen && r.epoch >= Math.max(from, info.genStart)).slice(0, Math.min(limit, 1000));
        const last = list[list.length - 1];
        return respond(200, {
            success: true, gen, genStart: info.genStart, prevFinalHead: b64(info.prevFinalHead),
            from: list.length > 0 ? list[0].epoch : Math.max(from, info.genStart),
            roots: list.map(r => b64(r.root)),
            last: last ? { epoch: last.epoch, head: b64(last.head), sig: b64(last.sig) } : null,
        });
    }

    async proofFor(requester, target, gen, epoch) {
        const record = this.epochs.get(gen + ':' + epoch);
        if (!record || !this.available(gen)) return null;
        const label = Buffer.from(kit.label(this.evil.badProof ? (target + 1) : target));
        const index = ktLog.createMemoryIndex(record.groups, record.tree);
        const proof = await ktLog.buildProof(kit, index, label);
        return { entries: proof.entries.map(b64), bitmap: b64(proof.bitmap), siblings: proof.siblings.map(b64) };
    }

    async proof(requester, target, gen, epoch) {
        this.calls.proof++;
        const blocked = this.gate();
        if (blocked) return blocked;
        if (this.evil.noProof) return respond(404, { success: false, code: 'kt-not-found' });
        if (!this.canRead(requester, target)) return respond(403, { success: false, code: 'forbidden' });
        const proof = await this.proofFor(requester, target, gen, epoch);
        return proof ? respond(200, { success: true, ...proof }) : respond(404, { success: false, code: 'kt-not-found' });
    }

    async self(userId, gen, from, limit) {
        this.calls.self++;
        const blocked = this.gate();
        if (blocked) return blocked;
        if (!this.available(gen)) return respond(404, { success: false, code: 'kt-not-found' });
        const info = this.gens.get(gen);
        const epochs = this.visible().filter(r => r.gen === gen && r.epoch >= Math.max(from, info.genStart)).slice(0, Math.min(limit, 200));
        const proofs = [];
        for (const r of epochs) proofs.push({ epoch: r.epoch, ...(await this.proofFor(userId, userId, gen, r.epoch)) });
        return respond(200, { success: true, proofs, next: epochs.length === Math.min(limit, 200) ? epochs[epochs.length - 1].epoch + 1 : null });
    }

    // Транспорт клиента userId (методы makeFetchTransport).
    transportFor(userId) {
        return {
            ktHead: async () => this.head(),
            ktRoots: async (gen, from, limit) => this.roots(gen, from, limit),
            ktProof: async (target, gen, epoch) => this.proof(userId, target, gen, epoch),
            ktSelf: async (gen, from, limit) => this.self(userId, gen, from, limit),
        };
    }
}

module.exports = { FakeKt, newLogKey };
