'use strict';
// Серверные чистые функции журнала ключей (lib/kt-log.js): построение дерева
// эпохи, доказательства из памяти и из компактного индекса (kt_nodes + листья),
// ключ журнала, настройки. Сам SQL проверяют сквозные тесты на Postgres
// (test/e2e/key-transparency.e2e.test.js); здесь индекс базы заменён фейком,
// который отвечает на те же пять запросов по массивам.
// Запуск: node test/kt-log.test.js

const assert = require('assert');
const crypto = require('crypto');
const NyxoKt = require('../public/lib/kt.js');
const ktLog = require('../lib/kt-log');

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

const hex = (buf) => Buffer.from(buf).toString('hex');
const { kit } = ktLog;

// Эталон: корень разреженного дерева «в лоб» по отфильтрованным спискам меток.
function sparseRoot(k, items, level) {
    if (items.length === 0) return k.emptyHash(128 - level);
    if (level === 128) return items[0].leaf;
    const left = items.filter(it => k.bitOf(it.label, level) === 0);
    const right = items.filter(it => k.bitOf(it.label, level) === 1);
    return k.nodeHash(sparseRoot(k, left, level + 1), sparseRoot(k, right, level + 1));
}

function sparseProof(k, items, target) {
    const bitmap = Buffer.alloc(16);
    const siblings = [];
    let scope = items;
    for (let i = 0; i < 128; i++) {
        const bit = k.bitOf(target, i);
        const other = scope.filter(it => k.bitOf(it.label, i) !== bit);
        if (other.length > 0) {
            bitmap[i >> 3] |= 0x80 >> (i & 7);
            siblings.push(sparseRoot(k, other, i + 1));
        }
        scope = scope.filter(it => k.bitOf(it.label, i) === bit);
    }
    return { bitmap, siblings };
}

function randomGroups(n, { sharePrefix = 0 } = {}) {
    const pairs = [];
    const base = crypto.randomBytes(16);
    for (let i = 0; i < n; i++) {
        const label = crypto.randomBytes(16);
        if (sharePrefix > 0) {
            // Длинный общий префикс: первые sharePrefix бит как у base.
            for (let bit = 0; bit < sharePrefix; bit++) {
                const mask = 0x80 >> (bit & 7);
                label[bit >> 3] = (label[bit >> 3] & ~mask) | (base[bit >> 3] & mask);
            }
        }
        const count = 1 + (i % 3 === 0 ? 1 : 0);
        for (let c = 0; c < count; c++) pairs.push({ label, commitment: crypto.randomBytes(32) });
    }
    return ktLog.groupEntries(pairs);
}

// Фейковый query для createDbIndex: отвечает на запросы индекса по тем же
// массивам, из которых строится хранилище (kt_entries и kt_nodes одной эпохи).
function fakeQuery(groups, tree, gen, epoch) {
    const rows = [];
    for (const g of groups) for (const c of g.entries) rows.push({ label: g.label, commitment: c });
    rows.sort((a, b) => Buffer.compare(a.label, b.label) || Buffer.compare(a.commitment, b.commitment));
    const nodes = tree.nodes.map(n => ({ depth: n.depth, prefix: n.prefix, hash: n.hash }));
    return async (sql, params) => {
        const s = sql.replace(/\s+/g, ' ');
        assert.strictEqual(params[0], gen);
        assert.strictEqual(params[1], epoch);
        if (s.startsWith('SELECT commitment FROM kt_entries')) {
            return rows.filter(r => r.label.equals(params[2])).map(r => ({ commitment: r.commitment }));
        }
        if (s.includes('label < $3')) {
            const below = rows.filter(r => Buffer.compare(r.label, params[2]) < 0);
            return below.length ? [{ label: below[below.length - 1].label }] : [];
        }
        if (s.includes('label > $3')) {
            const above = rows.find(r => Buffer.compare(r.label, params[2]) > 0);
            return above ? [{ label: above.label }] : [];
        }
        if (s.startsWith('SELECT min(label)')) {
            const inside = rows.filter(r => Buffer.compare(r.label, params[2]) >= 0 && Buffer.compare(r.label, params[3]) <= 0);
            return [{ min: inside.length ? inside[0].label : null, max: inside.length ? inside[inside.length - 1].label : null }];
        }
        if (s.startsWith('SELECT hash FROM kt_nodes')) {
            const node = nodes.find(n => n.depth === params[2] && n.prefix.equals(params[3]));
            return node ? [{ hash: node.hash }] : [];
        }
        throw new Error('неожиданный запрос: ' + s);
    };
}

async function main() {
    await test('lcpBits, prefixBytes, prefixRange', () => {
        const a = Buffer.from('ff00' + '00'.repeat(14), 'hex');
        const b = Buffer.from('ff80' + '00'.repeat(14), 'hex');
        assert.strictEqual(ktLog.lcpBits(a, b), 8);
        assert.strictEqual(ktLog.lcpBits(a, a), 128);
        assert.strictEqual(ktLog.lcpBits(Buffer.alloc(16), Buffer.from('01' + '00'.repeat(15), 'hex')), 7);
        assert.strictEqual(hex(ktLog.prefixBytes(Buffer.from('ffee' + '11'.repeat(14), 'hex'), 12)), 'ffe0');
        assert.strictEqual(hex(ktLog.prefixBytes(Buffer.from('ffee' + '11'.repeat(14), 'hex'), 8)), 'ff');
        const { lo, hi } = ktLog.prefixRange(ktLog.prefixBytes(Buffer.from('ffee' + '11'.repeat(14), 'hex'), 12), 12);
        assert.strictEqual(hex(lo), 'ffe0' + '00'.repeat(14));
        assert.strictEqual(hex(hi), 'ffef' + 'ff'.repeat(14));
    });

    await test('вектор раздела 5: дерево из листа пользователя и фиктивного листа, доказательство из индекса', async () => {
        const signPub = Buffer.from('4721b5b632272e65a68dda7ac25b4185f8b01916db185c14287db92e2b770fae', 'hex');
        const nonce = Buffer.from(Array.from({ length: 16 }, (_, i) => 0x20 + i));
        const label = Buffer.from(kit.label(7654321));
        const commit = Buffer.from(kit.commit(7654321, signPub, Buffer.alloc(32, 0xb2), nonce));
        const groups = ktLog.groupEntries([
            { label, commitment: commit },
            { label: Buffer.alloc(16, 0x55), commitment: Buffer.alloc(32, 0x66) },
        ]);
        const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
        assert.strictEqual(hex(tree.root), 'd4bb40e5820083f70dc0cbc63bc0f560b72ceea47731aa3059bbe39459966e96');
        // Метки расходятся с первого бита: корень ветвится (в kt_epochs), в kt_nodes — два его ребёнка на глубине 1.
        assert.deepStrictEqual(tree.nodes.map(n => n.depth), [1, 1]);
        const proof = await ktLog.buildProof(kit, ktLog.createMemoryIndex(groups, tree), label);
        assert.strictEqual(hex(proof.bitmap), '80' + '00'.repeat(15));
        assert.deepStrictEqual(proof.siblings.map(hex), ['6f83e2cff52dc23b2c597251854733db44658089895166dedeb7e1929c5f5c64']);
        assert.deepStrictEqual(proof.entries.map(hex), [hex(commit)]);
    });

    await test('пустая эпоха: корень E₁₂₈, доказательство отсутствия без братьев', async () => {
        const tree = await ktLog.buildTree(kit, [], { collectNodes: true });
        assert.strictEqual(hex(tree.root), '9c337c9f019bbd96d4e11587fb18c0a032c3bb4db6af7d319694c2777f33f17e');
        const proof = await ktLog.buildProof(kit, ktLog.createMemoryIndex([], tree), crypto.randomBytes(16));
        assert.deepStrictEqual(proof.entries, []);
        assert.strictEqual(hex(proof.bitmap), '00'.repeat(16));
        assert.deepStrictEqual(proof.siblings, []);
    });

    for (const [n, sharePrefix] of [[1, 0], [2, 0], [3, 100], [7, 0], [40, 0], [60, 120], [200, 0], [300, 70]]) {
        await test(`дерево из ${n} меток${sharePrefix ? ` с общим префиксом ${sharePrefix} бит` : ''}: корень и доказательства совпадают с эталоном`, async () => {
            const groups = randomGroups(n, { sharePrefix });
            const items = groups.map(g => ({ label: g.label, entries: g.entries, leaf: kit.leafHash(g.label, kit.valueHash(g.entries)) }));
            const expectedRoot = sparseRoot(kit, items, 0);
            const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
            assert.strictEqual(hex(tree.root), hex(expectedRoot), 'корень');
            const memory = ktLog.createMemoryIndex(groups, tree);
            const db = ktLog.createDbIndex(kit, fakeQuery(groups, tree, 3, 777), 3, 777);
            const targets = [...groups.map(g => g.label).slice(0, 25), crypto.randomBytes(16), crypto.randomBytes(16)];
            for (const target of targets) {
                const reference = sparseProof(kit, items, target);
                for (const index of [memory, db]) {
                    const proof = await ktLog.buildProof(kit, index, target);
                    assert.strictEqual(hex(proof.bitmap), hex(reference.bitmap), 'bitmap');
                    assert.deepStrictEqual(proof.siblings.map(hex), reference.siblings.map(hex), 'siblings');
                    const folded = kit.proofRoot(target, proof.entries.map(e => new Uint8Array(e)), new Uint8Array(proof.bitmap),
                        proof.siblings.map(s => new Uint8Array(s)));
                    assert.ok(folded && hex(folded) === hex(tree.root), 'свёртка доказательства даёт корень');
                }
            }
            // kt_nodes: ветвящиеся узлы и их дети, глубина 1…127, без повторов; не больше 3(n − 1) строк.
            assert.ok(tree.nodes.length <= 3 * (n - 1), `строк ${tree.nodes.length}`);
            const keys = new Set(tree.nodes.map(node => node.depth + ':' + hex(node.prefix)));
            assert.strictEqual(keys.size, tree.nodes.length, 'повторов нет');
            for (const node of tree.nodes) assert.ok(node.depth >= 1 && node.depth <= 127);
        });
    }

    await test('компактный индекс: доказательство без перестройки дерева — число хэшей на доказательство', async () => {
        // Считаем вызовы хэша отдельным набором формул: построение дерева — вне счёта.
        let calls = 0;
        const counting = ktLog.makeKit((data) => { calls++; return ktLog.sha256Native(data); });
        counting.emptyHash(128); // таблица пустых поддеревьев считается один раз на набор формул — не входит в стоимость доказательства
        const sizes = [1, 100, 5000, 20000];
        for (const n of sizes) {
            const groups = randomGroups(n);
            const tree = await ktLog.buildTree(ktLog.kit, groups, { collectNodes: true });
            const index = ktLog.createDbIndex(counting, fakeQuery(groups, tree, 1, 5), 1, 5);
            const memory = ktLog.createMemoryIndex(groups, tree);
            const counts = [];
            for (let i = 0; i < 40; i++) {
                const target = i < 30 ? groups[(i * 7919) % groups.length].label : crypto.randomBytes(16);
                calls = 0;
                const proof = await ktLog.buildProof(counting, index, target);
                counts.push(calls);
                const reference = await ktLog.buildProof(ktLog.kit, memory, target);
                assert.strictEqual(hex(proof.bitmap), hex(reference.bitmap));
                assert.deepStrictEqual(proof.siblings.map(hex), reference.siblings.map(hex));
                const folded = ktLog.kit.proofRoot(target, proof.entries.map(e => new Uint8Array(e)), new Uint8Array(proof.bitmap),
                    proof.siblings.map(s => new Uint8Array(s)));
                assert.strictEqual(hex(folded), hex(tree.root));
            }
            counts.sort((a, b) => a - b);
            const median = counts[counts.length >> 1];
            const max = counts[counts.length - 1];
            // Полная перестройка дерева — не меньше 100 хэшей на каждую метку; доказательство из индекса не зависит от N.
            // Раздел 13: не больше 128 + 127. Метка, которой в эпохе нет, стоит подъёма одного брата-цепочки (до 127 хэшей).
            assert.ok(max <= 128 + 127, `n=${n}: максимум ${max} хэшей на доказательство`);
            assert.ok(median <= 128, `n=${n}: медиана ${median} хэшей на доказательство`);
            console.log(`        n=${n}: хэшей на доказательство — медиана ${median}, максимум ${max}`);
        }
    });

    await test('метки с длинным общим префиксом: цепочка без ветвления сворачивается, число хэшей ограничено', async () => {
        let calls = 0;
        const counting = ktLog.makeKit((data) => { calls++; return ktLog.sha256Native(data); });
        const label = crypto.randomBytes(16);
        const twin = Buffer.from(label);
        twin[15] ^= 1; // расходятся на последнем бите
        const groups = ktLog.groupEntries([
            { label, commitment: crypto.randomBytes(32) },
            { label: twin, commitment: crypto.randomBytes(32) },
        ]);
        const tree = await ktLog.buildTree(ktLog.kit, groups, { collectNodes: true });
        // Ветвящийся узел глубины 127; его дети — листья глубины 128 — в kt_nodes не хранятся.
        assert.deepStrictEqual(tree.nodes.map(n => n.depth), [127]);
        const index = ktLog.createDbIndex(counting, fakeQuery(groups, tree, 1, 5), 1, 5);
        calls = 0;
        const proof = await ktLog.buildProof(counting, index, label);
        assert.ok(calls <= 128 + 127, `хэшей: ${calls}`);
        assert.strictEqual(proof.siblings.length, 1);
        const folded = ktLog.kit.proofRoot(label, proof.entries.map(e => new Uint8Array(e)), new Uint8Array(proof.bitmap),
            proof.siblings.map(s => new Uint8Array(s)));
        assert.strictEqual(hex(folded), hex(tree.root));
    });

    await test('неполный kt_nodes — ошибка, а не неверное доказательство', async () => {
        const groups = randomGroups(50);
        const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
        tree.nodes.length = 0;
        const index = ktLog.createMemoryIndex(groups, tree);
        await assert.rejects(() => ktLog.buildProof(kit, index, groups[0].label), /kt_nodes неполон/);
    });

    await test('groupEntries: сортировка меток и обязательств, дубликаты отбрасываются', () => {
        const a = Buffer.alloc(16, 2);
        const b = Buffer.alloc(16, 1);
        const c1 = Buffer.alloc(32, 9);
        const c2 = Buffer.alloc(32, 3);
        const groups = ktLog.groupEntries([
            { label: a, commitment: c1 }, { label: b, commitment: c1 }, { label: a, commitment: c2 }, { label: a, commitment: c1 },
        ]);
        assert.deepStrictEqual(groups.map(g => hex(g.label)), [hex(b), hex(a)]);
        assert.deepStrictEqual(groups[1].entries.map(hex), [hex(c2), hex(c1)]);
    });

    await test('ключ журнала: загрузка, подпись, отказы', async () => {
        const seedKey = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0xc1)]).toString('base64');
        const key = ktLog.loadSigningKey(seedKey);
        assert.strictEqual(hex(key.pub), 'acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228');
        const head = Buffer.alloc(32, 7);
        const sig = ktLog.signSth(key, 1, 5, head);
        assert.ok(await NyxoKt.verifyEd25519(new Uint8Array(key.pub), kit.sthMessage(1, 5, head), new Uint8Array(sig)));
        assert.ok(!(await NyxoKt.verifyEd25519(new Uint8Array(key.pub), kit.sthMessage(1, 6, head), new Uint8Array(sig))));
        const skt = ktLog.signSkt(key, 1, 5, Buffer.alloc(16, 1), Buffer.alloc(32, 2));
        assert.ok(await NyxoKt.verifyEd25519(new Uint8Array(key.pub), kit.sktMessage(1, 5, Buffer.alloc(16, 1), Buffer.alloc(32, 2)), new Uint8Array(skt)));
        const change = ktLog.signKeychange(key, Buffer.alloc(32, 4), 2, 9);
        assert.ok(await NyxoKt.verifyEd25519(new Uint8Array(key.pub), kit.keychangeMessage(Buffer.alloc(32, 4), 2, 9), new Uint8Array(change)));

        assert.throws(() => ktLog.loadSigningKey(''), /пуст/);
        assert.throws(() => ktLog.loadSigningKey('не base64!'), /base64/);
        assert.throws(() => ktLog.loadSigningKey(Buffer.from('мусор').toString('base64')), /PKCS#8/);
        const rsa = crypto.generateKeyPairSync('x25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
        assert.throws(() => ktLog.loadSigningKey(rsa), /Ed25519/);
        const generated = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
        assert.strictEqual(ktLog.loadSigningKey(generated).pub.length, 32);
    });

    await test('настройки: тестовые ручки действуют только при NODE_ENV=test', () => {
        const env = { KT_SIGNING_KEY: ' abc ', KT_SIGNING_KEY_PREVIOUS: 'old', KT_EPOCH_SECONDS: '2', KT_GENERATION_EPOCHS: '5', KT_GRACE_EPOCHS: '3', KT_COMPACT_MIN: '2' };
        const prod = ktLog.ktSettings({ ...env, NODE_ENV: 'production' });
        assert.strictEqual(prod.signingKey, 'abc');
        assert.strictEqual(prod.previousKey, 'old');
        assert.strictEqual(prod.epochSeconds, 3600);
        assert.strictEqual(prod.genEpochs, 720);
        assert.strictEqual(prod.graceEpochs, 336);
        assert.strictEqual(prod.compactMin, 4096);
        const test = ktLog.ktSettings({ ...env, NODE_ENV: 'test' });
        assert.deepStrictEqual([test.epochSeconds, test.genEpochs, test.graceEpochs, test.compactMin], [2, 5, 3, 2]);
        assert.strictEqual(ktLog.ktSettings({ NODE_ENV: 'test', KT_EPOCH_SECONDS: 'x' }).epochSeconds, 3600);
        assert.strictEqual(ktLog.ktSettings({}).signingKey, '');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
