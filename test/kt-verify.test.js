'use strict';
// Формулы журнала ключей (public/lib/kt.js, docs/security/key-transparency.md,
// разделы 5 и 11): контрольные векторы, SHA-256 против node:crypto, полный
// перебор малых деревьев с уменьшенной глубиной, случайные деревья глубины 128,
// отказы на неверных доказательствах, цепочка, проверка ключа Ed25519.
// Запуск: node test/kt-verify.test.js

const assert = require('assert');
const crypto = require('crypto');
const kt = require('../public/lib/kt.js');

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

const hex = kt.toHex;
const unhex = kt.fromHex;
const nativeSha = (data) => new Uint8Array(crypto.createHash('sha256').update(data).digest());
const fast = kt.create({ sha256: nativeSha });

// Ключ журнала из раздела 5: seed = 0xc1 × 32.
const LOG_PRIV = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0xc1)]),
    format: 'der', type: 'pkcs8',
});
const LOG_PUB = new Uint8Array(crypto.createPublicKey(LOG_PRIV).export({ type: 'spki', format: 'der' }).subarray(-32));
const sign = (message) => new Uint8Array(crypto.sign(null, message, LOG_PRIV));

// ---- Данные контрольных векторов ----
const U = 7654321;
const SIGN_PUB = unhex('4721b5b632272e65a68dda7ac25b4185f8b01916db185c14287db92e2b770fae');
const DH_PUB = new Uint8Array(32).fill(0xb2);
const NONCE = new Uint8Array(16).map((_, i) => 0x20 + i);
const GEN = 1;
const EPOCH = 497652;

// Эталон малого дерева: уровни считаются снизу вверх «в лоб». leaves: Map(индекс пути → хэш листа).
function naiveLevels(kit, leaves, depth) {
    const hashes = [];
    const filled = [];
    hashes[depth] = Array.from({ length: 1 << depth }, (_, i) => (leaves.has(i) ? leaves.get(i) : kit.emptyHash(0)));
    filled[depth] = Array.from({ length: 1 << depth }, (_, i) => leaves.has(i));
    for (let level = depth - 1; level >= 0; level--) {
        hashes[level] = [];
        filled[level] = [];
        for (let i = 0; i < (1 << level); i++) {
            hashes[level][i] = kit.nodeHash(hashes[level + 1][2 * i], hashes[level + 1][2 * i + 1]);
            filled[level][i] = filled[level + 1][2 * i] || filled[level + 1][2 * i + 1];
        }
    }
    return { hashes, filled };
}

function naiveProof(levels, depth, pathIndex) {
    const bitmap = new Uint8Array(Math.ceil(depth / 8));
    const siblings = [];
    for (let i = 0; i < depth; i++) {
        const prefix = pathIndex >> (depth - i); // первые i бит пути
        const bit = (pathIndex >> (depth - 1 - i)) & 1;
        const sibIndex = prefix * 2 + (1 - bit);
        if (levels.filled[i + 1][sibIndex]) {
            bitmap[i >> 3] |= 0x80 >> (i & 7);
            siblings.push(levels.hashes[i + 1][sibIndex]);
        }
    }
    return { bitmap, siblings };
}

// Метка для пути p глубины d: первые d бит — p, остальное — детерминированный хвост.
function labelForPath(p, depth) {
    const label = new Uint8Array(16).fill(0xa5);
    for (let i = 0; i < depth; i++) {
        const bit = (p >> (depth - 1 - i)) & 1;
        if (bit) label[i >> 3] |= 0x80 >> (i & 7);
        else label[i >> 3] &= ~(0x80 >> (i & 7));
    }
    return label;
}

const commitOf = (n) => new Uint8Array(32).fill(n);

async function main() {
    // ===================== Контрольные векторы раздела 5 =====================

    await test('SHA-256 из kt.js совпадает с node:crypto на входах всех длин', () => {
        for (let n = 0; n <= 300; n++) {
            const data = crypto.randomBytes(n);
            assert.strictEqual(hex(kt.pureSha256(data)), crypto.createHash('sha256').update(data).digest('hex'), 'длина ' + n);
        }
        assert.strictEqual(hex(kt.pureSha256(new Uint8Array(0))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        const big = crypto.randomBytes(100000);
        assert.strictEqual(hex(kt.pureSha256(big)), crypto.createHash('sha256').update(big).digest('hex'));
    });

    await test('вектор: пустые поддеревья E₁ и E₁₂₈', () => {
        assert.strictEqual(hex(kt.emptyHash(0)), '00'.repeat(32));
        assert.strictEqual(hex(kt.emptyHash(1)), 'ae0798d0ecaed2b778eddebf18f071a561c53658c05e76cedecc27cafbdbc577');
        assert.strictEqual(hex(kt.emptyHash(128)), '9c337c9f019bbd96d4e11587fb18c0a032c3bb4db6af7d319694c2777f33f17e');
        assert.throws(() => kt.emptyHash(129), RangeError);
    });

    await test('вектор: метка, обязательство, значение, лист', () => {
        const label = kt.label(U);
        assert.strictEqual(hex(label), 'c1a5a3845ad4b9222125e41482613b35');
        const commit = kt.commit(U, SIGN_PUB, DH_PUB, NONCE);
        assert.strictEqual(hex(commit), '80ccc8c31b5a61529df08b288ce3d938991a7c9f9d0c9df8bd448bec68dc6776');
        const value = kt.valueHash([commit]);
        assert.strictEqual(hex(value), 'fb73e31f1aebaa8f65feedf8045be774f933fd12a5c2bfb91177d6bbd05a510a');
        assert.strictEqual(hex(kt.leafHash(label, value)), 'bfe0b2bf046c8cb4d2a4dbcf76ecb1aa4f7a21737311ed862b3d4285d8825682');
    });

    await test('вектор: корень, доказательство, genesis, head, ключ журнала, STH, SKT', async () => {
        const label = kt.label(U);
        const commit = kt.commit(U, SIGN_PUB, DH_PUB, NONCE);
        const bitmap = new Uint8Array(16);
        bitmap[0] = 0x80;
        const siblings = [unhex('6f83e2cff52dc23b2c597251854733db44658089895166dedeb7e1929c5f5c64')];
        const root = kt.proofRoot(label, [commit], bitmap, siblings);
        assert.strictEqual(hex(root), 'd4bb40e5820083f70dc0cbc63bc0f560b72ceea47731aa3059bbe39459966e96');

        // Тот же корень получается из дерева двух листьев: пользователь и фиктивная запись.
        const dummyLabel = new Uint8Array(16).fill(0x55);
        const dummyLeaf = kt.leafHash(dummyLabel, kt.valueHash([commitOf(0x66)]));
        // Фиктивный лист лежит в левой половине (бит 0 метки 0x55 равен 0), пользователь — в правой.
        let dummyUp = dummyLeaf;
        for (let i = 127; i >= 1; i--) {
            dummyUp = kt.bitOf(dummyLabel, i) === 0 ? kt.nodeHash(dummyUp, kt.emptyHash(127 - i)) : kt.nodeHash(kt.emptyHash(127 - i), dummyUp);
        }
        assert.strictEqual(hex(dummyUp), '6f83e2cff52dc23b2c597251854733db44658089895166dedeb7e1929c5f5c64');

        const genesis = kt.genesisHash(GEN, new Uint8Array(32));
        assert.strictEqual(hex(genesis), '301540463c6ec94bfec7acd8e745d5e3842538df75a155ad94984c33fe1fbd43');
        const head = kt.headHash(GEN, EPOCH, genesis, root);
        assert.strictEqual(hex(head), '76cc59f043c3c8023ba7e525c11bc835a63e0b303a74e9966da1c16ac81e41e6');

        assert.strictEqual(hex(LOG_PUB), 'acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228');
        const sth = sign(kt.sthMessage(GEN, EPOCH, head));
        assert.strictEqual(hex(sth), '206c833403335ea235886edd55e0c5e3625a2e3be193b1dd673c988f46d91cd3a7c097bdb07f3299ea404016f13384fc6185099437eca479dacb3357b502e406');
        const skt = sign(kt.sktMessage(GEN, EPOCH, label, commit));
        assert.strictEqual(hex(skt), '40e6c831d39634d9d346eec71622b756dce61b314c1fcbf4d54a6afb035c0a917db64b08b8d97768067ec3343924941cefdac141d8aee6ae5fb8176a6078c101');

        assert.ok(await kt.verifyEd25519(LOG_PUB, kt.sthMessage(GEN, EPOCH, head), sth));
        assert.ok(await kt.verifyEd25519(LOG_PUB, kt.sktMessage(GEN, EPOCH, label, commit), skt));
        assert.ok(!(await kt.verifyEd25519(LOG_PUB, kt.sthMessage(GEN, EPOCH + 1, head), sth)), 'подпись привязана к эпохе');
        assert.ok(!(await kt.verifyEd25519(LOG_PUB, kt.sktMessage(GEN, EPOCH, label, commit), sth)), 'метки домена различают подписи');
    });

    await test('доказательство вектора отвергается при любом изменении', () => {
        const label = kt.label(U);
        const commit = kt.commit(U, SIGN_PUB, DH_PUB, NONCE);
        const bitmap = new Uint8Array(16);
        bitmap[0] = 0x80;
        const sib = unhex('6f83e2cff52dc23b2c597251854733db44658089895166dedeb7e1929c5f5c64');
        const good = hex(kt.proofRoot(label, [commit], bitmap, [sib]));
        const other = commitOf(1);
        assert.notStrictEqual(hex(kt.proofRoot(label, [other], bitmap, [sib])), good);
        const flipped = new Uint8Array(sib);
        flipped[5] ^= 1;
        assert.notStrictEqual(hex(kt.proofRoot(label, [commit], bitmap, [flipped])), good);
        const wrongLabel = new Uint8Array(label);
        wrongLabel[15] ^= 1;
        assert.notStrictEqual(hex(kt.proofRoot(wrongLabel, [commit], bitmap, [sib])), good);
    });

    // ===================== Структура доказательства =====================

    await test('proofRoot: bitmap и siblings несогласованы, неверные длины — отказ', () => {
        const label = kt.label(U);
        const c = commitOf(7);
        const empty16 = new Uint8Array(16);
        const one = new Uint8Array(16);
        one[0] = 0x80;
        const sib = new Uint8Array(32).fill(3);
        assert.notStrictEqual(kt.proofRoot(label, [c], empty16, []), null, 'пустое доказательство допустимо');
        assert.strictEqual(kt.proofRoot(label, [c], one, []), null, 'бит есть, хэша нет');
        assert.strictEqual(kt.proofRoot(label, [c], empty16, [sib]), null, 'хэш есть, бита нет');
        assert.strictEqual(kt.proofRoot(label, [c], one, [sib, sib]), null, 'лишний хэш');
        assert.strictEqual(kt.proofRoot(label, [c], new Uint8Array(15), []), null, 'bitmap короче 16 байт');
        assert.strictEqual(kt.proofRoot(label, [c], new Uint8Array(17), []), null, 'bitmap длиннее 16 байт');
        assert.strictEqual(kt.proofRoot(label, [c], one, [new Uint8Array(31)]), null, 'хэш не 32 байта');
        assert.strictEqual(kt.proofRoot(label.subarray(0, 15), [c], empty16, []), null, 'метка не 16 байт');
        assert.strictEqual(kt.proofRoot(label, [new Uint8Array(31)], empty16, []), null, 'обязательство не 32 байта');
        assert.strictEqual(kt.proofRoot(label, 'x', empty16, []), null);
    });

    await test('proofRoot: entries не по возрастанию, с дубликатом, k = 0 как присутствие и k > 65535', () => {
        const label = kt.label(U);
        const empty16 = new Uint8Array(16);
        const a = commitOf(1);
        const b = commitOf(2);
        assert.notStrictEqual(kt.proofRoot(label, [a, b], empty16, []), null);
        assert.strictEqual(kt.proofRoot(label, [b, a], empty16, []), null, 'перестановка');
        assert.strictEqual(kt.proofRoot(label, [a, a], empty16, []), null, 'дубликат');
        // k = 0 — это доказательство отсутствия: свёртка от E₀, а не от листа.
        const absence = kt.proofRoot(label, [], empty16, []);
        assert.strictEqual(hex(absence), hex(kt.emptyHash(128)), 'пустое дерево, отсутствие метки');
        assert.throws(() => kt.valueHash([]), RangeError, 'value требует k ≥ 1');
        const tooMany = Array.from({ length: 65536 }, (_, i) => {
            const c = new Uint8Array(32);
            c[0] = i >> 8; c[1] = i & 255;
            return c;
        });
        assert.strictEqual(kt.proofRoot(label, tooMany, empty16, []), null, 'k = 65536');
        assert.throws(() => kt.valueHash(tooMany), RangeError);
        assert.notStrictEqual(kt.proofRoot(label, tooMany.slice(0, 65535), empty16, []), null, 'k = 65535 допустимо');
    });

    // ===================== Полный перебор малых деревьев =====================

    await test('малые деревья: все наборы листьев глубины 3 и 4096 случайных наборов глубины 4 совпадают с эталоном', () => {
        for (const depth of [3, 4]) {
            const positions = 1 << depth;
            // Глубина 3 — все 256 наборов; глубина 4 (65536 наборов) — 4096 наборов по детерминированному генератору.
            let seed = 12345;
            const masks = depth === 3
                ? Array.from({ length: 1 << positions }, (_, i) => i)
                : Array.from({ length: 4096 }, () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return (seed >> 4) & 0xffff; });
            for (const mask of masks) {
                const leaves = new Map();
                const entriesOf = new Map();
                for (let p = 0; p < positions; p++) {
                    if (!(mask & (1 << p))) continue;
                    // У каждой третьей метки два обязательства: лист с k = 2.
                    const entries = p % 3 === 0 ? [commitOf(p + 1), commitOf(p + 100)] : [commitOf(p + 1)];
                    entriesOf.set(p, entries);
                    leaves.set(p, fast.leafHash(labelForPath(p, depth), fast.valueHash(entries)));
                }
                const levels = naiveLevels(fast, leaves, depth);
                const root = levels.hashes[0][0];
                for (let p = 0; p < positions; p++) {
                    const { bitmap, siblings } = naiveProof(levels, depth, p);
                    const entries = entriesOf.get(p) || [];
                    const folded = fast.proofRoot(labelForPath(p, depth), entries, bitmap, siblings, depth);
                    assert.ok(folded && Buffer.from(folded).equals(Buffer.from(root)), `глубина ${depth}, маска ${mask}, путь ${p}`);
                    // Подмена: вместо настоящих обязательств — чужие (для присутствия) либо вымышленное (для отсутствия).
                    const fake = entries.length === 0 ? [commitOf(250)] : [commitOf(251)];
                    const bad = fast.proofRoot(labelForPath(p, depth), fake, bitmap, siblings, depth);
                    assert.ok(bad === null || !Buffer.from(bad).equals(Buffer.from(root)), 'подмена обязательства не даёт корень');
                }
            }
        }
    });

    await test('случайные деревья глубины 128: доказательство присутствия и отсутствия сворачивается в корень', () => {
        // Эталон глубины 128 — разреженное дерево по отсортированным меткам.
        function sparseRoot(kit, items, level) {
            // items: [{ label, leaf }] — метки, у которых первые `level` бит общие.
            if (items.length === 0) return kit.emptyHash(128 - level);
            if (level === 128) return items[0].leaf;
            const left = items.filter(it => kit.bitOf(it.label, level) === 0);
            const right = items.filter(it => kit.bitOf(it.label, level) === 1);
            return kit.nodeHash(sparseRoot(kit, left, level + 1), sparseRoot(kit, right, level + 1));
        }
        function sparseProof(kit, items, target) {
            const bitmap = new Uint8Array(16);
            const siblings = [];
            let scope = items;
            const hashes = [];
            for (let i = 0; i < 128; i++) {
                const bit = kit.bitOf(target, i);
                const mine = scope.filter(it => kit.bitOf(it.label, i) === bit);
                const other = scope.filter(it => kit.bitOf(it.label, i) !== bit);
                if (other.length > 0) {
                    bitmap[i >> 3] |= 0x80 >> (i & 7);
                    hashes.push(sparseRoot(kit, other, i + 1));
                }
                scope = mine;
            }
            return { bitmap, siblings: hashes };
        }
        for (let round = 0; round < 6; round++) {
            const items = [];
            const n = [1, 2, 5, 17, 40, 80][round];
            for (let i = 0; i < n; i++) {
                const label = new Uint8Array(crypto.randomBytes(16));
                const entries = [commitOf(i + 1)];
                items.push({ label, entries, leaf: fast.leafHash(label, fast.valueHash(entries)) });
            }
            // Две метки с длинным общим префиксом.
            if (n >= 5) {
                const twin = new Uint8Array(items[0].label);
                twin[15] ^= 1;
                const entries = [commitOf(200)];
                items.push({ label: twin, entries, leaf: fast.leafHash(twin, fast.valueHash(entries)) });
            }
            const root = sparseRoot(fast, items, 0);
            for (const it of items) {
                const { bitmap, siblings } = sparseProof(fast, items, it.label);
                const folded = fast.proofRoot(it.label, it.entries, bitmap, siblings);
                assert.ok(folded && Buffer.from(folded).equals(Buffer.from(root)), 'присутствие, раунд ' + round);
            }
            const absent = new Uint8Array(crypto.randomBytes(16));
            const { bitmap, siblings } = sparseProof(fast, items, absent);
            const folded = fast.proofRoot(absent, [], bitmap, siblings);
            assert.ok(folded && Buffer.from(folded).equals(Buffer.from(root)), 'отсутствие, раунд ' + round);
        }
    });

    // ===================== Цепочка =====================

    await test('цепочка: головы продолжаются от prev, первая эпоха поколения опирается на genesis', () => {
        const roots = Array.from({ length: 5 }, (_, i) => new Uint8Array(32).fill(i + 1));
        const genesis = kt.genesisHash(3, new Uint8Array(32).fill(9));
        const all = kt.extendChain(genesis, 3, 1000, roots);
        assert.strictEqual(all.length, 5);
        assert.strictEqual(hex(all[0]), hex(kt.headHash(3, 1000, genesis, roots[0])));
        // Продолжение с середины даёт те же головы.
        const tail = kt.extendChain(all[1], 3, 1002, roots.slice(2));
        assert.deepStrictEqual(tail.map(hex), all.slice(2).map(hex));
        // Подмена корня в прошлом меняет все последующие головы (развилка видна).
        const rewritten = roots.slice();
        rewritten[1] = new Uint8Array(32).fill(77);
        const forked = kt.extendChain(genesis, 3, 1000, rewritten);
        assert.strictEqual(hex(forked[0]), hex(all[0]));
        assert.notStrictEqual(hex(forked[4]), hex(all[4]));
        // genesis зависит от номера поколения и от последней головы прежнего.
        assert.notStrictEqual(hex(kt.genesisHash(3, new Uint8Array(32).fill(9))), hex(kt.genesisHash(4, new Uint8Array(32).fill(9))));
        assert.notStrictEqual(hex(kt.genesisHash(3, new Uint8Array(32).fill(9))), hex(kt.genesisHash(3, new Uint8Array(32).fill(8))));
    });

    // ===================== Ключ журнала и подпись (раздел 11) =====================

    await test('проверка ключа: восемь точек малого порядка и их неканоничные записи — отказ', () => {
        // Восемь точек порядка 1, 2, 4, 8 в каноническом виде.
        const eight = [
            '0100000000000000000000000000000000000000000000000000000000000000',
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
            '0000000000000000000000000000000000000000000000000000000000000000',
            '0000000000000000000000000000000000000000000000000000000000000080',
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
        ];
        for (const key of eight) assert.ok(!kt.isValidLogKey(unhex(key)), 'малый порядок: ' + key);
        // Знаковый бит при x = 0 — неканоническая запись тех же точек.
        assert.ok(!kt.isValidLogKey(unhex('0100000000000000000000000000000000000000000000000000000000000080')));
        assert.ok(!kt.isValidLogKey(unhex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')));
        // Настоящие ключи малого порядка действительно принимаются платформой — потому проверка явная.
        assert.ok(kt.isValidLogKey(LOG_PUB));
        assert.ok(!kt.isValidLogKey(new Uint8Array(31)));
        assert.ok(!kt.isValidLogKey('x'));
    });

    await test('проверка ключа: y ≥ p (неканоническая кодировка) — отказ, y = p − 1 с обычным ключом — нет', () => {
        const p = (b0) => { const k = new Uint8Array(32).fill(0xff); k[0] = b0; k[31] = 0x7f; return k; };
        assert.ok(!kt.isValidLogKey(p(0xed)), 'y = p');
        assert.ok(!kt.isValidLogKey(p(0xff)), 'y = 2^255 − 1');
        const justBelow = p(0xec);
        justBelow[1] = 0xfe; // y < p
        assert.ok(kt.isCanonicalY(justBelow));
        const withSign = p(0xed);
        withSign[31] = 0xff; // знаковый бит не меняет y: всё равно y = p
        assert.ok(!kt.isCanonicalY(withSign));
    });

    await test('подпись: S ≥ L и неканоническая R — отказ; настоящая принимается', async () => {
        const message = new Uint8Array([1, 2, 3]);
        const sig = sign(message);
        assert.ok(kt.isCanonicalSignature(sig));
        assert.ok(await kt.verifyEd25519(LOG_PUB, message, sig));
        // S + L: та же подпись по модулю L, но S ≥ L — неканоническая.
        const L = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
        let s = 0n;
        for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]);
        const malleable = new Uint8Array(sig);
        let t = s + L;
        for (let i = 0; i < 32; i++) { malleable[32 + i] = Number(t & 255n); t >>= 8n; }
        // 2^253 > S + L (L ≈ 2^252, S < L), значит значение влезает в 32 байта.
        assert.ok(!kt.isCanonicalSignature(malleable), 'S + L');
        assert.ok(!(await kt.verifyEd25519(LOG_PUB, message, malleable)));
        const badR = new Uint8Array(sig);
        badR.set(unhex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), 0);
        assert.ok(!kt.isCanonicalSignature(badR), 'y(R) ≥ p');
        assert.ok(!kt.isCanonicalSignature(new Uint8Array(63)));
        // Ключ малого порядка отвергается и в verifyEd25519, хотя платформа его принимает.
        assert.ok(!(await kt.verifyEd25519(unhex('0100000000000000000000000000000000000000000000000000000000000000'), message, sig)));
        const wrong = new Uint8Array(sig);
        wrong[0] ^= 1;
        assert.ok(!(await kt.verifyEd25519(LOG_PUB, message, wrong)));
    });

    await test('заявление о смене ключа: сообщение привязано к новому ключу и эпохе', async () => {
        const newPub = new Uint8Array(crypto.randomBytes(32));
        const msg = kt.keychangeMessage(newPub, 2, 1234);
        assert.strictEqual(msg.length, 21 + 32 + 4 + 4);
        const sig = sign(msg);
        assert.ok(await kt.verifyEd25519(LOG_PUB, msg, sig));
        assert.ok(!(await kt.verifyEd25519(LOG_PUB, kt.keychangeMessage(newPub, 2, 1235), sig)));
        const other = new Uint8Array(newPub);
        other[0] ^= 1;
        assert.ok(!(await kt.verifyEd25519(LOG_PUB, kt.keychangeMessage(other, 2, 1234), sig)));
    });

    await test('кодирование: строгий base64 и hex', () => {
        const bytes = new Uint8Array(crypto.randomBytes(37));
        const text = kt.b64encode(bytes);
        assert.strictEqual(text, Buffer.from(bytes).toString('base64'));
        assert.deepStrictEqual(Array.from(kt.b64decode(text)), Array.from(bytes));
        assert.strictEqual(kt.b64decode(text, 36), null, 'длина не та');
        assert.strictEqual(kt.b64decode(text.slice(0, -1)), null, 'без выравнивания');
        assert.strictEqual(kt.b64decode('AA=A'), null);
        assert.strictEqual(kt.b64decode('A'.repeat(42) + 'B='), null, 'неканонические биты');
        assert.strictEqual(kt.b64decode(5), null);
        assert.deepStrictEqual(Array.from(kt.fromHex('00ff10')), [0, 255, 16]);
        assert.throws(() => kt.fromHex('0'), TypeError);
        assert.strictEqual(kt.compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3])), -1);
        assert.strictEqual(kt.comparePos({ gen: 2, epoch: 1 }, { gen: 1, epoch: 99 }), 1);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
