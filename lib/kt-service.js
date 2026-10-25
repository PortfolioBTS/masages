'use strict';
// Журнал ключей на сервере: работа с базой (docs/security/key-transparency.md,
// разделы 6.1–6.5, 11). Чистые формулы и дерево — lib/kt-log.js, маршруты —
// lib/kt-routes.js, регистрация ключа — lib/key-store.js (через registerInTx).
//
// Порядок блокировок домена журнала (message-ordering.md, 8.1):
//   kt_state → identity_keys → kt_pending
// регистрация ключа и удаление аккаунта берут kt_state FOR SHARE, закрытие
// эпохи и начало поколения — FOR UPDATE. Так SKT, выданный при регистрации,
// всегда относится к той эпохе (и поколению), в которую запись попала.
//
// В журнале нет user_id и времени точнее часа: метка, обязательство, час.
// Без KT_SIGNING_KEY сервис выключен (enabled = false): регистраций нет, kt в
// ответах null, маршруты отвечают 503, задачи нет.

const crypto = require('crypto');
const NyxoKt = require('../public/lib/kt.js');
const ktLog = require('./kt-log');
const { KeyStoreError } = require('./key-store');
const { guardClient } = require('./pg-client-guard');

const { kit } = ktLog;
const BATCH = 5000;
// Сколько эпох закрывается за один проход задачи (после долгого простоя
// остальные закроются на следующих проходах).
const MAX_EPOCHS_PER_RUN = 2000;
const SKT_BATCH = 1000;
const MAX_ROOTS_PER_REQUEST = 1000;
const MAX_SELF_EPOCHS = 200;
const CACHE_SIZE = 8;

const b64 = (buf) => Buffer.from(buf).toString('base64');
const yieldNow = () => new Promise(resolve => setImmediate(resolve));

function createKtService(options = {}) {
    const { pool, withTransaction, now = Date.now, log = console } = options;
    const settings = options.settings || ktLog.ktSettings(options.env || process.env);
    if (!pool || typeof pool.query !== 'function') throw new TypeError('createKtService: нужен pool');

    let key = null;
    let previous = null;
    if (settings.signingKey) {
        try {
            key = ktLog.loadSigningKey(settings.signingKey);
        } catch (err) {
            log.error(`[KT] KT_SIGNING_KEY не загружен (${err.message}) — журнал ключей выключен`);
        }
    }
    if (key && settings.previousKey) {
        try {
            previous = ktLog.loadSigningKey(settings.previousKey);
        } catch (err) {
            log.error(`[KT] KT_SIGNING_KEY_PREVIOUS не загружен (${err.message}) — заявление о смене ключа не будет записано`);
        }
    }
    const enabled = Boolean(key);
    const maxRegistrations = options.maxRegistrations || ktLog.MAX_REGISTRATIONS_PER_EPOCH;

    const epochNow = () => Math.floor(now() / 1000 / settings.epochSeconds);
    const query = async (sql, params) => (await pool.query(sql, params)).rows;

    async function inTransaction(work) {
        if (typeof withTransaction === 'function') return withTransaction(work);
        const client = await pool.connect();
        const release = guardClient(client, '[KT] Обрыв соединения во время транзакции');
        let broken;
        try {
            await client.query('BEGIN');
            const result = await work(client);
            await client.query('COMMIT');
            return result;
        } catch (err) {
            await client.query('ROLLBACK').catch((rollbackErr) => { broken = rollbackErr; });
            throw err;
        } finally {
            release(broken);
        }
    }

    // ---------- Подсказка kt в ответах ключевого хранилища ----------

    // { gen, epoch, nonce, skt } по строке identity_keys; null — журнал выключен или ключ ещё не зарегистрирован.
    function hintOf(row) {
        if (!enabled || !row || !row.kt_nonce) return null;
        return {
            gen: Number(row.kt_gen),
            epoch: Number(row.kt_epoch),
            nonce: b64(row.kt_nonce),
            skt: row.kt_skt ? b64(row.kt_skt) : null,
        };
    }

    // ---------- Регистрация ключа (6.2) ----------

    // Первый шаг транзакции регистрации: строка kt_state FOR SHARE. null — задача
    // эпох ещё не стартовала (регистрации нет, kt: null).
    async function lockState(client) {
        if (!enabled) return null;
        const { rows } = await client.query('SELECT gen, gen_start, open_epoch FROM kt_state FOR SHARE');
        return rows[0] || null;
    }

    // Внутри транзакции после записи identity_keys. keysChanged — ключи изменились
    // (RETURNING upsert-а не пуст). Возвращает kt для ответа; бросает 429 kt-rate.
    async function registerInTx(client, state, { userId, keysChanged }) {
        const { rows: [row] } = await client.query(
            `SELECT identity_signing_key, identity_dh_key, kt_nonce, kt_gen, kt_epoch, kt_skt
             FROM identity_keys WHERE user_id = $1 FOR UPDATE`,
            [userId]
        );
        if (!row) return null;
        if (!keysChanged && row.kt_nonce) return hintOf(row);
        const label = kit.label(Number(userId));
        // Подсчёт после блокировки строки identity_keys: параллельные регистрации
        // одного пользователя выстраиваются в очередь, и предел точен.
        const { rows: [count] } = await client.query('SELECT count(*)::int AS n FROM kt_pending WHERE label = $1', [Buffer.from(label)]);
        if (count.n >= maxRegistrations) {
            throw new KeyStoreError(429, 'Слишком много смен ключей за час. Повторите позже', 'kt-rate');
        }
        const nonce = crypto.randomBytes(16);
        const commitment = Buffer.from(kit.commit(Number(userId), row.identity_signing_key, row.identity_dh_key, nonce));
        const skt = ktLog.signSkt(key, state.gen, state.open_epoch, label, commitment);
        await client.query(
            'UPDATE identity_keys SET kt_nonce = $2, kt_gen = $3, kt_epoch = $4, kt_skt = $5 WHERE user_id = $1',
            [userId, nonce, state.gen, state.open_epoch, skt]
        );
        await client.query('INSERT INTO kt_pending (commitment, user_id, label) VALUES ($1, $2, $3)', [commitment, userId, Buffer.from(label)]);
        return { gen: state.gen, epoch: state.open_epoch, nonce: b64(nonce), skt: b64(skt) };
    }

    // ---------- Закрытие эпох (6.3) и поколения (6.4) ----------

    async function insertEntries(client, gen, epoch, groups) {
        const labels = [];
        const commits = [];
        for (const group of groups) {
            for (const entry of group.entries) {
                labels.push(group.label);
                commits.push(entry);
            }
        }
        for (let i = 0; i < labels.length; i += BATCH) {
            await client.query(
                `INSERT INTO kt_entries (gen, epoch, label, commitment)
                 SELECT $1, $2, t.label, t.commitment FROM UNNEST($3::bytea[], $4::bytea[]) AS t(label, commitment)
                 ON CONFLICT DO NOTHING`,
                [gen, epoch, labels.slice(i, i + BATCH), commits.slice(i, i + BATCH)]
            );
        }
    }

    async function insertNodes(client, gen, epoch, nodes) {
        for (let i = 0; i < nodes.length; i += BATCH) {
            const part = nodes.slice(i, i + BATCH);
            await client.query(
                `INSERT INTO kt_nodes (gen, epoch, depth, prefix, hash)
                 SELECT $1, $2, t.depth, t.prefix, t.hash FROM UNNEST($3::smallint[], $4::bytea[], $5::bytea[]) AS t(depth, prefix, hash)`,
                [gen, epoch, part.map(n => n.depth), part.map(n => n.prefix), part.map(n => n.hash)]
            );
        }
    }

    // Закрывает открытую эпоху состояния st (строка kt_state уже заблокирована FOR UPDATE).
    async function closeEpoch(client, st) {
        const gen = st.gen;
        const epoch = st.open_epoch;
        const pairs = [];
        const { rows: pending } = await client.query('SELECT label, commitment FROM kt_pending');
        for (const row of pending) pairs.push({ label: row.label, commitment: row.commitment });
        if (epoch === st.gen_start) {
            // Перенос: обязательства всех живых ключей — в первую эпоху поколения.
            // Строки удалённых аккаунтов в identity_keys отсутствуют.
            const { rows: carried } = await client.query(
                'SELECT user_id, identity_signing_key, identity_dh_key, kt_nonce FROM identity_keys WHERE kt_nonce IS NOT NULL ORDER BY user_id'
            );
            let n = 0;
            for (const row of carried) {
                const userId = Number(row.user_id);
                pairs.push({
                    label: kit.label(userId),
                    commitment: kit.commit(userId, row.identity_signing_key, row.identity_dh_key, row.kt_nonce),
                });
                if (++n % BATCH === 0) await yieldNow();
            }
        }
        // Фиктивная запись: в каждой эпохе ровно одна (скрывает «пустую» эпоху).
        pairs.push({ label: crypto.randomBytes(16), commitment: crypto.randomBytes(32) });

        const groups = ktLog.groupEntries(pairs);
        await insertEntries(client, gen, epoch, groups);
        const compact = epoch === st.gen_start || groups.length > settings.compactMin;
        const tree = await ktLog.buildTree(kit, groups, { collectNodes: compact });
        const lastHead = Buffer.from(st.last_head);
        const prev = epoch === st.gen_start ? kit.genesisHash(gen, lastHead) : lastHead;
        const head = Buffer.from(kit.headHash(gen, epoch, prev, tree.root));
        const sig = ktLog.signSth(key, gen, epoch, head);
        // prev_final_head — финальная голова предыдущего поколения у первой эпохи
        // поколения: из неё клиент считает genesis, когда предыдущее уже удалено.
        await client.query(
            'INSERT INTO kt_epochs (gen, epoch, smt_root, head, sig, prev_final_head) VALUES ($1, $2, $3, $4, $5, $6)',
            [gen, epoch, Buffer.from(tree.root), head, sig, epoch === st.gen_start ? lastHead : null]
        );
        if (compact) await insertNodes(client, gen, epoch, tree.nodes);
        await client.query('DELETE FROM kt_pending');

        const next = epoch + 1;
        let nextGen = gen;
        let nextStart = st.gen_start;
        if (next - st.gen_start >= settings.genEpochs) {
            nextGen = gen + 1;
            nextStart = next;
            // Подсказки kt всех живых ключей указывают на новое поколение; SKT
            // подпишет signCarryOverSkts после фиксации транзакции.
            await client.query(
                'UPDATE identity_keys SET kt_gen = $1, kt_epoch = $2, kt_skt = NULL WHERE kt_nonce IS NOT NULL',
                [nextGen, nextStart]
            );
        }
        await client.query(
            'UPDATE kt_state SET gen = $1, gen_start = $2, open_epoch = $3, last_head = $4',
            [nextGen, nextStart, next, head]
        );
        return { newGeneration: nextGen !== gen };
    }

    let bootstrapped = false;
    let stats = { openEpoch: null, pending: 0 };

    // Строка kt_state и заявление о смене ключа журнала (раздел 11).
    async function bootstrap() {
        const epoch = epochNow();
        await pool.query(
            `INSERT INTO kt_state (singleton, gen, gen_start, open_epoch, last_head) VALUES (TRUE, 1, $1, $1, $2)
             ON CONFLICT (singleton) DO NOTHING`,
            [epoch, Buffer.alloc(32)]
        );
        const [last] = await query('SELECT gen, epoch, head, sig FROM kt_epochs ORDER BY gen DESC, epoch DESC LIMIT 1');
        if (!last) return;
        const message = kit.sthMessage(last.gen, last.epoch, last.head);
        const signedByCurrent = await verifySig(key.pub, message, last.sig);
        if (signedByCurrent) return;
        if (previous && await verifySig(previous.pub, message, last.sig)) {
            const [state] = await query('SELECT gen, open_epoch FROM kt_state');
            // Заявление действует с первой эпохи, открытой под новым ключом: эта — ещё не закрыта.
            const sig = ktLog.signKeychange(previous, key.pub, state.gen, state.open_epoch);
            await pool.query(
                `INSERT INTO kt_keychanges (old_pub, new_pub, gen, epoch, sig) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (old_pub) DO NOTHING`,
                [previous.pub, key.pub, state.gen, state.open_epoch, sig]
            );
            return;
        }
        log.error('[KT] KT_SIGNING_KEY не подписывал журнал в базе и заявления о смене нет (KT_SIGNING_KEY_PREVIOUS). ' +
            'Клиенты увидят «ключ журнала изменился»; после сброса базы нужен новый ключ, после смены ключа — прежний в KT_SIGNING_KEY_PREVIOUS');
    }

    async function verifySig(pub, message, sig) {
        return NyxoKt.verifyEd25519(new Uint8Array(pub), new Uint8Array(message), new Uint8Array(sig));
    }

    // SKT перенесённым ключам: порциями, после фиксации транзакции начала поколения.
    async function signCarryOverSkts() {
        const [st] = await query('SELECT gen, gen_start FROM kt_state');
        if (!st) return 0;
        let total = 0;
        for (;;) {
            const rows = await query(
                `SELECT user_id, identity_signing_key, identity_dh_key, kt_nonce FROM identity_keys
                 WHERE kt_nonce IS NOT NULL AND kt_skt IS NULL AND kt_gen = $1 AND kt_epoch = $2
                 ORDER BY user_id LIMIT ${SKT_BATCH}`,
                [st.gen, st.gen_start]
            );
            if (rows.length === 0) break;
            const ids = [];
            const skts = [];
            const signing = [];
            const nonces = [];
            for (const row of rows) {
                const userId = Number(row.user_id);
                const label = kit.label(userId);
                const commitment = kit.commit(userId, row.identity_signing_key, row.identity_dh_key, row.kt_nonce);
                ids.push(userId);
                skts.push(ktLog.signSkt(key, st.gen, st.gen_start, label, commitment));
                signing.push(row.identity_signing_key);
                nonces.push(row.kt_nonce);
            }
            // Условие kt_skt IS NULL не даёт затереть SKT свежей регистрации, а
            // совпадение ключей и nonce — подписать обязательство, которого у строки уже нет.
            const result = await pool.query(
                `UPDATE identity_keys i SET kt_skt = t.skt
                 FROM UNNEST($1::bigint[], $2::bytea[], $3::bytea[], $4::bytea[]) AS t(user_id, skt, signing, nonce)
                 WHERE i.user_id = t.user_id AND i.kt_skt IS NULL AND i.kt_gen = $5 AND i.kt_epoch = $6
                   AND i.identity_signing_key = t.signing AND i.kt_nonce = t.nonce`,
                [ids, skts, signing, nonces, st.gen, st.gen_start]
            );
            total += result.rowCount;
            if (result.rowCount === 0) break;
            await yieldNow();
        }
        return total;
    }

    // Предыдущее поколение хранится ещё graceEpochs после начала текущего.
    async function purgeOldGenerations() {
        const [st] = await query('SELECT gen, gen_start, open_epoch FROM kt_state');
        if (!st || st.gen <= 1) return;
        const lastClosed = st.open_epoch - 1;
        const keepFrom = lastClosed <= st.gen_start + settings.graceEpochs ? st.gen - 1 : st.gen;
        for (const table of ['kt_nodes', 'kt_entries', 'kt_epochs']) {
            await pool.query(`DELETE FROM ${table} WHERE gen < $1`, [keepFrom]);
        }
    }

    // Один проход задачи: закрыть все закончившиеся эпохи, подписать SKT, убрать старое.
    async function run() {
        if (!enabled) return { closed: 0 };
        if (!bootstrapped) {
            await bootstrap();
            bootstrapped = true;
        }
        let closed = 0;
        let newGeneration = false;
        while (closed < MAX_EPOCHS_PER_RUN) {
            const result = await inTransaction(async (client) => {
                const { rows: [st] } = await client.query('SELECT gen, gen_start, open_epoch, last_head FROM kt_state FOR UPDATE');
                if (!st || st.open_epoch >= epochNow()) return null;
                return closeEpoch(client, st);
            });
            if (!result) break;
            closed++;
            if (result.newGeneration) newGeneration = true;
            if (options.onEpochClosed) options.onEpochClosed();
            await yieldNow();
        }
        const signed = await signCarryOverSkts();
        if (closed > 0 || newGeneration || signed > 0) await purgeOldGenerations();
        const [st] = await query('SELECT open_epoch FROM kt_state');
        const [pending] = await query('SELECT count(*)::int AS n FROM kt_pending');
        stats = { openEpoch: st ? st.open_epoch : null, pending: pending.n };
        return { closed, newGeneration, signed };
    }

    // ---------- Чтение журнала для маршрутов (6.5) ----------

    async function generationInfo(gen) {
        const [first] = await query('SELECT epoch, prev_final_head FROM kt_epochs WHERE gen = $1 ORDER BY epoch LIMIT 1', [gen]);
        return first ? { genStart: first.epoch, prevFinalHead: first.prev_final_head ? Buffer.from(first.prev_final_head) : Buffer.alloc(32) } : null;
    }

    async function getHead() {
        if (!enabled) return null;
        const [last] = await query('SELECT gen, epoch, head, sig FROM kt_epochs ORDER BY gen DESC, epoch DESC LIMIT 1');
        if (!last) return null;
        const info = await generationInfo(last.gen);
        const keychange = await query('SELECT old_pub, new_pub, gen, epoch, sig FROM kt_keychanges ORDER BY gen, epoch');
        return {
            pub: key.pub, gen: last.gen, epoch: last.epoch, head: last.head, sig: last.sig,
            genStart: info.genStart, prevFinalHead: info.prevFinalHead,
            keychange: keychange.map(r => ({ oldPub: r.old_pub, newPub: r.new_pub, gen: r.gen, epoch: r.epoch, sig: r.sig })),
        };
    }

    // Корни поколения gen с эпохи from; null — поколения нет (удалено или не было).
    async function getRoots(gen, from, limit) {
        if (!enabled) return null;
        const info = await generationInfo(gen);
        if (!info) return null;
        const count = Math.min(Math.max(1, limit), MAX_ROOTS_PER_REQUEST);
        const rows = await query(
            'SELECT epoch, smt_root, head, sig FROM kt_epochs WHERE gen = $1 AND epoch >= $2 ORDER BY epoch LIMIT $3',
            [gen, Math.max(from, info.genStart), count]
        );
        const last = rows[rows.length - 1];
        return {
            gen, genStart: info.genStart, prevFinalHead: info.prevFinalHead,
            from: rows.length > 0 ? rows[0].epoch : Math.max(from, info.genStart),
            roots: rows.map(r => r.smt_root),
            last: last ? { epoch: last.epoch, head: last.head, sig: last.sig } : null,
        };
    }

    // Индексы небольших эпох (до compactMin листьев) строятся из kt_entries и
    // кэшируются: закрытая эпоха не меняется.
    const cache = new Map();

    async function epochIndex(gen, epoch, genStart) {
        const cacheKey = gen + ':' + epoch;
        if (cache.has(cacheKey)) {
            const hit = cache.get(cacheKey);
            cache.delete(cacheKey);
            cache.set(cacheKey, hit);
            return hit;
        }
        const indexed = epoch === genStart
            || (await query('SELECT 1 FROM kt_nodes WHERE gen = $1 AND epoch = $2 LIMIT 1', [gen, epoch])).length > 0;
        if (indexed) return ktLog.createDbIndex(kit, query, gen, epoch);
        const rows = await query('SELECT label, commitment FROM kt_entries WHERE gen = $1 AND epoch = $2', [gen, epoch]);
        const groups = ktLog.groupEntries(rows);
        const tree = await ktLog.buildTree(kit, groups, { collectNodes: true });
        const index = ktLog.createMemoryIndex(groups, tree);
        cache.set(cacheKey, index);
        while (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
        return index;
    }

    // Доказательство для метки пользователя в закрытой эпохе или null (эпохи нет). Прежде
    // чем отдать, сервер сворачивает его сам: повреждённый индекс не должен превратиться в ответ.
    async function proofIn(userId, gen, epoch, info, root) {
        const label = Buffer.from(kit.label(Number(userId)));
        const index = await epochIndex(gen, epoch, info.genStart);
        const proof = await ktLog.buildProof(kit, index, label);
        const folded = kit.proofRoot(new Uint8Array(label), proof.entries.map(e => new Uint8Array(e)), new Uint8Array(proof.bitmap), proof.siblings.map(s => new Uint8Array(s)));
        if (!folded || !Buffer.from(folded).equals(Buffer.from(root))) throw new Error('kt: доказательство не сходится с корнем эпохи — индекс повреждён');
        return proof;
    }

    async function getProof(userId, gen, epoch) {
        if (!enabled) return null;
        const info = await generationInfo(gen);
        if (!info) return null;
        const [row] = await query('SELECT smt_root FROM kt_epochs WHERE gen = $1 AND epoch = $2', [gen, epoch]);
        if (!row) return null;
        return proofIn(userId, gen, epoch, info, row.smt_root);
    }

    async function getSelfProofs(userId, gen, from, limit) {
        if (!enabled) return null;
        const info = await generationInfo(gen);
        if (!info) return null;
        const count = Math.min(Math.max(1, limit), MAX_SELF_EPOCHS);
        const rows = await query(
            'SELECT epoch, smt_root FROM kt_epochs WHERE gen = $1 AND epoch >= $2 ORDER BY epoch LIMIT $3',
            [gen, Math.max(from, info.genStart), count]
        );
        const proofs = [];
        for (const row of rows) {
            const proof = await proofIn(userId, gen, row.epoch, info, row.smt_root);
            proofs.push({ epoch: row.epoch, ...proof });
        }
        const next = rows.length === count ? rows[rows.length - 1].epoch + 1 : null;
        return { proofs, next };
    }

    return {
        get enabled() { return enabled; },
        get pub() { return key ? key.pub : null; },
        settings, hintOf, lockState, registerInTx, run, getHead, getRoots, getProof, getSelfProofs,
        signCarryOverSkts,
        stats: () => ({ enabled, epochSeconds: settings.epochSeconds, ...stats }),
        _epochNow: epochNow,
    };
}

// Задача эпох для реестра lib/jobs (JOB_MODULES): раз в минуту, под runExclusive.
// Минута, а не час: эпоха должна закрываться в пределах нескольких минут от
// границы часа (раздел 15), иначе у клиента «открытая» эпоха висит дольше положенного.
function jobs(ctx) {
    const kt = ctx && ctx.kt;
    if (!kt || !kt.enabled) return [];
    return [{
        name: 'closeKeyEpochs',
        run: () => kt.run(),
        firstDelayMs: 1000,
        intervalMs: 60 * 1000,
        maintenance: true,
    }];
}

module.exports = { createKtService, jobs, MAX_ROOTS_PER_REQUEST, MAX_SELF_EPOCHS };
