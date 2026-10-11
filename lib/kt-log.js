'use strict';
// Журнал ключей, серверная часть без базы: дерево эпохи, доказательства
// (в том числе из компактного индекса), ключ журнала и подписи
// (docs/security/key-transparency.md, разделы 5, 6.3, 11).
//
// Формулы лежат в public/lib/kt.js и общие с клиентом: сервер и браузер считают
// метки, обязательства и узлы одним и тем же кодом. Здесь — то, чего клиенту не
// нужно: построение дерева по всем меткам эпохи, доказательство для метки из
// готового дерева (память) либо из компактного индекса kt_nodes (База), подпись.
//
// Дерево разреженное: глубина 128, пустые поддеревья — предвычисленные E_h. В
// памяти и в kt_nodes хранятся только ВЕТВЯЩИЕСЯ узлы (с двумя непустыми
// потомками, не больше N−1); цепочки без ветвления сворачиваются при подсчёте.

const crypto = require('crypto');
const NyxoKt = require('../public/lib/kt.js');

const sha256Native = (data) => crypto.createHash('sha256').update(data).digest();
// Общий набор формул с хэшем из node:crypto. Тесты создают свой через makeKit
// (счётчик вызовов хэша).
const kit = NyxoKt.create({ sha256: sha256Native });
const makeKit = (sha256 = sha256Native) => NyxoKt.create({ sha256 });

const DEPTH = NyxoKt.DEPTH;
// Эпоха больше этого числа листьев хранится с индексом ветвящихся узлов (6.3).
const KT_COMPACT_MIN = 4096;
// Не больше стольких обязательств одной метки за эпоху (6.2).
const MAX_REGISTRATIONS_PER_EPOCH = 16;

// ---------- Ключ журнала ----------

// KT_SIGNING_KEY — base64 PKCS#8 Ed25519. Бросает Error с понятным текстом (без
// значения ключа). pub проходит ту же явную проверку, что и на клиенте.
function loadSigningKey(encoded) {
    if (typeof encoded !== 'string' || encoded.trim() === '') throw new Error('ключ журнала пуст');
    const text = encoded.trim();
    const der = Buffer.from(text, 'base64');
    if (der.length === 0 || der.toString('base64').replace(/=+$/, '') !== text.replace(/=+$/, '')) {
        throw new Error('ключ журнала: не base64');
    }
    let privateKey;
    try {
        privateKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    } catch {
        throw new Error('ключ журнала: не PKCS#8');
    }
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('ключ журнала: нужен Ed25519');
    const pub = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32);
    if (!NyxoKt.isValidLogKey(new Uint8Array(pub))) throw new Error('ключ журнала: недопустимая точка');
    return { pub: Buffer.from(pub), sign: (message) => crypto.sign(null, Buffer.from(message), privateKey) };
}

// Подписи: STH — голова эпохи, SKT — обещание включения, keychange — смена ключа.
const signSth = (key, gen, epoch, head) => key.sign(kit.sthMessage(gen, epoch, head));
const signSkt = (key, gen, epoch, label, commitment) => key.sign(kit.sktMessage(gen, epoch, label, commitment));
const signKeychange = (key, newPub, gen, epoch) => key.sign(kit.keychangeMessage(newPub, gen, epoch));

// ---------- Биты и префиксы ----------

// Число общих старших бит двух меток (128, если метки равны).
function lcpBits(a, b) {
    for (let i = 0; i < 16; i++) {
        const x = a[i] ^ b[i];
        if (x !== 0) return i * 8 + Math.clz32(x) - 24;
    }
    return DEPTH;
}

// Первые depth бит метки; остаток последнего байта — нули.
function prefixBytes(label, depth) {
    const out = Buffer.alloc(Math.ceil(depth / 8));
    for (let i = 0; i < out.length; i++) out[i] = label[i];
    if (depth % 8 !== 0) out[out.length - 1] &= (0xff << (8 - (depth % 8))) & 0xff;
    return out;
}

// Границы меток (включительно) с данным префиксом: низ — хвост нулей, верх — единиц.
function prefixRange(prefix, depth) {
    const lo = Buffer.alloc(16);
    const hi = Buffer.alloc(16, 0xff);
    prefix.copy(lo, 0, 0, prefix.length);
    prefix.copy(hi, 0, 0, prefix.length);
    if (depth % 8 !== 0) hi[prefix.length - 1] |= 0xff >> (depth % 8);
    return { lo, hi };
}

// Хэш узла на глубине fromDepth, поднятый по пути метки до глубины toDepth:
// на каждом шаге брат — пустое поддерево.
function foldUp(k, hash, label, fromDepth, toDepth) {
    let cur = hash;
    for (let level = fromDepth - 1; level >= toDepth; level--) {
        const sibling = k.emptyHash(DEPTH - (level + 1));
        cur = k.bitOf(label, level) === 0 ? k.nodeHash(cur, sibling) : k.nodeHash(sibling, cur);
    }
    return cur;
}

const yieldNow = () => new Promise(resolve => setImmediate(resolve));

// ---------- Построение дерева эпохи ----------

// groups — [{ label: Buffer(16), entries: [Buffer(32), …] }] по возрастанию
// метки; entries внутри — по возрастанию и без повторов. Возвращает
// { root, nodes: [{ depth, prefix, hash }], leafHashes }.
//
// nodes (только при collectNodes) — содержимое kt_nodes эпохи: хэши поддеревьев
// глубины 1…127 (корень хранится в kt_epochs, листья — в kt_entries):
//   * ветвящиеся узлы (оба потомка непусты, не больше N−1);
//   * дети ветвящихся узлов — именно они и бывают братьями в доказательстве для
//     метки, лежащей в эпохе (брат непуст ⇒ узел на пути ветвится), поэтому
//     такое доказательство собирается без единого хэша. Всего порядка 2N строк.
// Без детей доказательство для метки с несколькими братьями-цепочками стоило бы
// сотен хэшей (измерено: до 570 на N = 20000; раздел 13 требует не больше 255).
//
// Построение уступает циклу событий каждые yieldEvery листьев: перенос в
// первую эпоху поколения — порядка 10^7 хэшей (раздел 6.3).
async function buildTree(k, groups, { collectNodes = false, yieldEvery = 1000 } = {}) {
    if (groups.length === 0) return { root: k.emptyHash(DEPTH), nodes: [], leafHashes: [] };
    const leafHashes = [];
    for (let i = 0; i < groups.length; i++) {
        leafHashes.push(k.leafHash(groups[i].label, k.valueHash(groups[i].entries)));
        if ((i + 1) % 20000 === 0) await yieldNow();
    }
    const nodes = new Map();
    const keep = (depth, label, hash) => {
        if (!collectNodes || depth < 1 || depth > DEPTH - 1) return;
        const prefix = prefixBytes(label, depth);
        nodes.set(depth + ':' + prefix.toString('hex'), { depth, prefix, hash });
    };
    let leaves = 0;

    // Хэш узла глубины depth над groups[lo..hi) (все метки делят первые depth бит).
    async function sub(lo, hi, depth) {
        if (hi - lo === 1) {
            if (++leaves % yieldEvery === 0) await yieldNow();
            return foldUp(k, leafHashes[lo], groups[lo].label, DEPTH, depth);
        }
        // Первый бит, на котором метки расходятся; метки уникальны, поэтому c < 128.
        const c = lcpBits(groups[lo].label, groups[hi - 1].label);
        let a = lo;
        let b = hi;
        while (a < b) {
            const m = (a + b) >> 1;
            if (k.bitOf(groups[m].label, c) === 1) b = m; else a = m + 1;
        }
        const left = await sub(lo, a, c + 1);
        const right = await sub(a, hi, c + 1);
        const hash = k.nodeHash(left, right);
        keep(c, groups[lo].label, hash);
        keep(c + 1, groups[lo].label, left);
        keep(c + 1, groups[a].label, right);
        return foldUp(k, hash, groups[lo].label, c, depth);
    }
    const root = await sub(0, groups.length, 0);
    return { root, nodes: [...nodes.values()], leafHashes };
}

// ---------- Индекс эпохи и доказательство ----------

// Индекс эпохи — то, из чего собирается доказательство (в памяти или в базе):
//   entries(label)          → [Buffer(32)] обязательства метки, по возрастанию (пусто — метки нет);
//   neighbors(label)        → { pred, succ }: ближайшие другие метки снизу и сверху (или null);
//   span(prefix, depth)     → { min, max } меток с этим префиксом либо null;
//   node(depth, prefix)     → хэш ветвящегося узла либо null;
//   leafHash(label)         → хэш листа метки.
function createMemoryIndex(groups, tree) {
    const labels = groups.map(g => g.label);
    const nodeMap = new Map(tree.nodes.map(n => [n.depth + ':' + n.prefix.toString('hex'), n.hash]));
    const lower = (target) => { // первый индекс с labels[i] >= target
        let a = 0;
        let b = labels.length;
        while (a < b) {
            const m = (a + b) >> 1;
            if (Buffer.compare(labels[m], target) < 0) a = m + 1; else b = m;
        }
        return a;
    };
    const upper = (target) => { // первый индекс с labels[i] > target
        let a = 0;
        let b = labels.length;
        while (a < b) {
            const m = (a + b) >> 1;
            if (Buffer.compare(labels[m], target) <= 0) a = m + 1; else b = m;
        }
        return a;
    };
    return {
        async entries(label) {
            const i = lower(label);
            return i < labels.length && labels[i].equals(label) ? groups[i].entries : [];
        },
        async neighbors(label) {
            const lo = lower(label);
            const hi = upper(label);
            return { pred: lo > 0 ? labels[lo - 1] : null, succ: hi < labels.length ? labels[hi] : null };
        },
        async span(prefix, depth) {
            const { lo, hi } = prefixRange(prefix, depth);
            const first = lower(lo);
            const last = upper(hi);
            return first < last ? { min: labels[first], max: labels[last - 1] } : null;
        },
        async node(depth, prefix) {
            return nodeMap.get(depth + ':' + prefix.toString('hex')) || null;
        },
        async leafHash(label) {
            const i = lower(label);
            return tree.leafHashes[i];
        },
    };
}

// query(sql, params) → rows. Индекс по kt_entries (листья) и kt_nodes
// (ветвящиеся узлы) одной эпохи. Запросы по диапазону меток идут по первичному
// ключу (gen, epoch, label, commitment).
function createDbIndex(k, query, gen, epoch) {
    return {
        async entries(label) {
            const rows = await query(
                'SELECT commitment FROM kt_entries WHERE gen = $1 AND epoch = $2 AND label = $3 ORDER BY commitment',
                [gen, epoch, label]
            );
            return rows.map(r => Buffer.from(r.commitment));
        },
        async neighbors(label) {
            const [pred] = await query(
                'SELECT label FROM kt_entries WHERE gen = $1 AND epoch = $2 AND label < $3 ORDER BY label DESC LIMIT 1',
                [gen, epoch, label]
            );
            const [succ] = await query(
                'SELECT label FROM kt_entries WHERE gen = $1 AND epoch = $2 AND label > $3 ORDER BY label ASC LIMIT 1',
                [gen, epoch, label]
            );
            return { pred: pred ? Buffer.from(pred.label) : null, succ: succ ? Buffer.from(succ.label) : null };
        },
        async span(prefix, depth) {
            const { lo, hi } = prefixRange(prefix, depth);
            const [row] = await query(
                `SELECT min(label) AS min, max(label) AS max FROM kt_entries
                 WHERE gen = $1 AND epoch = $2 AND label >= $3 AND label <= $4`,
                [gen, epoch, lo, hi]
            );
            return row && row.min ? { min: Buffer.from(row.min), max: Buffer.from(row.max) } : null;
        },
        async node(depth, prefix) {
            const [row] = await query(
                'SELECT hash FROM kt_nodes WHERE gen = $1 AND epoch = $2 AND depth = $3 AND prefix = $4',
                [gen, epoch, depth, prefix]
            );
            return row ? Buffer.from(row.hash) : null;
        },
        async leafHash(label) {
            return k.leafHash(label, k.valueHash(await this.entries(label)));
        },
    };
}

// Доказательство для метки: { entries, bitmap, siblings } (раздел 5). Брат на
// глубине i+1 непуст, только если у какой-то другой метки с меткой совпадают ровно
// первые i бит; наибольшее такое совпадение даёт один из ближайших соседей
// в отсортированном порядке, поэтому глубже него проверять нечего: запросов
// порядка log2(N), а не 128, хэшей — порядка 128 независимо от размера эпохи.
async function buildProof(k, index, label) {
    const entries = await index.entries(label);
    const { pred, succ } = await index.neighbors(label);
    const deepest = Math.max(pred ? lcpBits(label, pred) : -1, succ ? lcpBits(label, succ) : -1);
    const bitmap = Buffer.alloc(16);
    const siblings = [];
    for (let i = 0; i <= Math.min(deepest, DEPTH - 1); i++) {
        const sibling = Buffer.from(label);
        sibling[i >> 3] ^= 0x80 >> (i & 7);
        const depth = i + 1;
        const prefix = prefixBytes(sibling, depth);
        // Хэш поддерева-брата лежит в индексе, если оно ребёнок ветвящегося узла
        // (так бывает всегда, кроме самого глубокого брата для метки, которой в
        // эпохе нет); иначе — по диапазону меток под ним, с подъёмом по цепочке.
        let hash = await index.node(depth, prefix);
        if (!hash) {
            const span = await index.span(prefix, depth);
            if (!span) continue;
            hash = await subtreeHash(k, index, span, depth);
        }
        bitmap[i >> 3] |= 0x80 >> (i & 7);
        siblings.push(hash);
    }
    return { entries, bitmap, siblings };
}

// Хэш поддерева на глубине depth по диапазону меток span под ним.
async function subtreeHash(k, index, span, depth) {
    if (span.min.equals(span.max)) {
        return foldUp(k, await index.leafHash(span.min), span.min, DEPTH, depth);
    }
    const c = lcpBits(span.min, span.max);
    const hash = await index.node(c, prefixBytes(span.min, c));
    if (!hash) throw new Error('kt: в индексе эпохи нет ветвящегося узла — kt_nodes неполон');
    return foldUp(k, hash, span.min, c, depth);
}

// Эпоха из обязательств (метка → набор обязательств) → groups для buildTree.
function groupEntries(pairs) {
    const byLabel = new Map();
    for (const { label, commitment } of pairs) {
        const key = Buffer.from(label).toString('hex');
        let group = byLabel.get(key);
        if (!group) {
            group = { label: Buffer.from(label), seen: new Set(), entries: [] };
            byLabel.set(key, group);
        }
        const ck = Buffer.from(commitment).toString('hex');
        if (!group.seen.has(ck)) {
            group.seen.add(ck);
            group.entries.push(Buffer.from(commitment));
        }
    }
    const groups = [...byLabel.values()].sort((a, b) => Buffer.compare(a.label, b.label));
    for (const g of groups) {
        g.entries.sort(Buffer.compare);
        delete g.seen;
    }
    return groups;
}

// ---------- Настройки из окружения ----------

// Длина эпохи и поколения — константы протокола. Тестовые ручки действуют только
// при NODE_ENV=test (в production env-check считает их ошибкой).
const TEST_KNOBS = Object.freeze(['KT_EPOCH_SECONDS', 'KT_GENERATION_EPOCHS', 'KT_GRACE_EPOCHS', 'KT_COMPACT_MIN']);

function positiveInt(value) {
    const n = Number(value);
    return Number.isInteger(n) && n > 0 ? n : null;
}

function ktSettings(env = process.env) {
    const test = env.NODE_ENV === 'test';
    const knob = (name, fallback) => (test && positiveInt(env[name])) || fallback;
    return {
        signingKey: typeof env.KT_SIGNING_KEY === 'string' ? env.KT_SIGNING_KEY.trim() : '',
        previousKey: typeof env.KT_SIGNING_KEY_PREVIOUS === 'string' ? env.KT_SIGNING_KEY_PREVIOUS.trim() : '',
        epochSeconds: knob('KT_EPOCH_SECONDS', NyxoKt.EPOCH_SECONDS),
        genEpochs: knob('KT_GENERATION_EPOCHS', NyxoKt.GEN_EPOCHS),
        graceEpochs: knob('KT_GRACE_EPOCHS', NyxoKt.GRACE_EPOCHS),
        compactMin: knob('KT_COMPACT_MIN', KT_COMPACT_MIN),
    };
}

module.exports = {
    kit, makeKit, sha256Native,
    DEPTH, KT_COMPACT_MIN, MAX_REGISTRATIONS_PER_EPOCH, TEST_KNOBS,
    loadSigningKey, signSth, signSkt, signKeychange,
    lcpBits, prefixBytes, prefixRange, foldUp,
    buildTree, createMemoryIndex, createDbIndex, buildProof, groupEntries,
    ktSettings,
};
