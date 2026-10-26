'use strict';
// Таблицы встроенного хранилища E2EE-ключей (lib/key-store.js) в памяти —
// ровно те запросы, что шлёт модуль, с семантикой Postgres (upsert, UNNEST
// ... ON CONFLICT DO NOTHING, атомарная выдача одноразового prekey).
// Только для тестов; на настоящем Postgres модуль проверяется отдельно.

function makeFakeKeyDb() {
    const identities = new Map(); // userId -> { identity_signing_key, identity_dh_key }
    const spks = new Map();       // userId -> { key_id, public_key, signature }
    const pqs = new Map();        // userId -> { key_id, public_key, signature }
    const opks = [];              // { id, user_id, key_id, public_key }
    const pqOpks = [];            // { id, user_id, key_id, public_key, signature }
    let nextOpkId = 1;
    let nextPqOpkId = 1;
    let failNext = null;
    // Удалённые аккаунты: строки users нет (по умолчанию строка есть у любого id).
    const deletedUsers = new Set();

    const isKeySql = (sql) => /identity_keys|signed_prekeys|signed_pq_prekeys|one_time_prekeys|kt_pending/.test(sql);

    // Пул пользователя по возрастанию id — порядок вставки.
    const poolOf = (list, uid) => list.filter(o => o.user_id === uid);

    async function dbAll(sql, params = []) {
        if (failNext) { const err = failNext; failNext = null; throw err; }
        const q = sql.replace(/\s+/g, ' ').trim();
        const uid = Number(params[0]);
        if (q.startsWith('INSERT INTO identity_keys')) {
            // Как в Postgres: строка возвращается, если она вставлена или
            // изменена; при повторной регистрации той же identity — пусто.
            const old = identities.get(uid);
            const same = old && Buffer.from(old.identity_signing_key).equals(Buffer.from(params[1]))
                && Buffer.from(old.identity_dh_key).equals(Buffer.from(params[2]));
            if (same) return [];
            identities.set(uid, { identity_signing_key: params[1], identity_dh_key: params[2] });
            return [{ inserted: !old }];
        }
        if (q === 'SELECT 1 FROM users WHERE id = $1 FOR KEY SHARE') return deletedUsers.has(uid) ? [] : [{ '?column?': 1 }];
        let m = /^INSERT INTO (signed_prekeys|signed_pq_prekeys)/.exec(q);
        if (m) {
            (m[1] === 'signed_prekeys' ? spks : pqs).set(uid, { key_id: params[1], public_key: params[2], signature: params[3] });
            return [];
        }
        if (q.startsWith('INSERT INTO one_time_prekeys')) {
            const out = [];
            params[1].forEach((keyId, i) => {
                if (opks.some(o => o.user_id === uid && o.key_id === keyId)) return;
                opks.push({ id: nextOpkId++, user_id: uid, key_id: keyId, public_key: params[2][i] });
                out.push({ '?column?': 1 });
            });
            return out;
        }
        if (q.startsWith('INSERT INTO pq_one_time_prekeys')) {
            const out = [];
            params[1].forEach((keyId, i) => {
                if (pqOpks.some(o => o.user_id === uid && o.key_id === keyId)) return;
                pqOpks.push({ id: nextPqOpkId++, user_id: uid, key_id: keyId, public_key: params[2][i], signature: params[3][i] });
                out.push({ '?column?': 1 });
            });
            return out;
        }
        m = /^SELECT COUNT\(\*\)::int AS count FROM (one_time_prekeys|pq_one_time_prekeys) WHERE user_id = \$1$/.exec(q);
        if (m) return [{ count: poolOf(m[1] === 'one_time_prekeys' ? opks : pqOpks, uid).length }];
        if (q.startsWith('SELECT (SELECT COUNT(*)::int FROM one_time_prekeys WHERE user_id = $1) AS count')) {
            return [{ count: poolOf(opks, uid).length, pq_count: poolOf(pqOpks, uid).length }];
        }
        if (q.startsWith('SELECT identity_signing_key FROM identity_keys')) {
            const row = identities.get(uid);
            return row ? [{ identity_signing_key: row.identity_signing_key }] : [];
        }
        // С журналом ключей (lib/key-store.js, kt) к выборке добавляются столбцы kt_*: тест кладёт их прямо в строку identities.
        if (/^SELECT user_id, identity_signing_key, identity_dh_key(, kt_nonce, kt_gen, kt_epoch, kt_skt)? FROM identity_keys WHERE user_id = ANY/.test(q)) {
            return params[0].filter(id => identities.has(id)).sort((a, b) => a - b)
                .map(id => Object.assign({ user_id: String(id) }, identities.get(id))); // BIGINT приходит строкой
        }
        if (/^SELECT identity_signing_key, identity_dh_key(, kt_nonce, kt_gen, kt_epoch, kt_skt)? FROM identity_keys/.test(q)) {
            const row = identities.get(uid);
            return row ? [row] : [];
        }
        m = /^SELECT key_id, public_key, signature FROM (signed_prekeys|signed_pq_prekeys)/.exec(q);
        if (m) {
            const row = (m[1] === 'signed_prekeys' ? spks : pqs).get(uid);
            return row ? [Object.assign({}, row, { key_id: String(row.key_id) })] : [];
        }
        if (q.startsWith('DELETE FROM one_time_prekeys WHERE id = (')) {
            const idx = opks.findIndex(o => o.user_id === uid); // по возрастанию id — порядок вставки
            if (idx < 0) return [];
            const [row] = opks.splice(idx, 1);
            return [{ key_id: String(row.key_id), public_key: row.public_key }];
        }
        if (q.startsWith('DELETE FROM pq_one_time_prekeys WHERE id = (')) {
            const idx = pqOpks.findIndex(o => o.user_id === uid);
            if (idx < 0) return [];
            const [row] = pqOpks.splice(idx, 1);
            return [{ key_id: String(row.key_id), public_key: row.public_key, signature: row.signature }];
        }
        // Потолок: оставить cap самых старых (OFFSET по убыванию id), остальное удалить.
        m = /^DELETE FROM (one_time_prekeys|pq_one_time_prekeys) WHERE user_id = \$1 AND id IN \( SELECT id FROM \1 WHERE user_id = \$1 ORDER BY id DESC OFFSET \$2 \)$/.exec(q);
        if (m) {
            const list = m[1] === 'one_time_prekeys' ? opks : pqOpks;
            const surplus = poolOf(list, uid).sort((a, b) => b.id - a.id).slice(Number(params[1]));
            for (const row of surplus) list.splice(list.indexOf(row), 1);
            return [];
        }
        m = /^DELETE FROM (\w+) WHERE user_id = \$1$/.exec(q);
        if (m) {
            if (m[1] === 'kt_pending') return [];
            if (m[1] === 'one_time_prekeys' || m[1] === 'pq_one_time_prekeys') {
                const list = m[1] === 'one_time_prekeys' ? opks : pqOpks;
                for (let i = list.length - 1; i >= 0; i--) if (list[i].user_id === uid) list.splice(i, 1);
            } else {
                ({ signed_prekeys: spks, signed_pq_prekeys: pqs, identity_keys: identities })[m[1]].delete(uid);
            }
            return [];
        }
        throw new Error('fake-key-db: неизвестный запрос: ' + q.slice(0, 80));
    }

    async function dbGet(sql, params) {
        const rows = await dbAll(sql, params);
        return rows[0] || null;
    }

    return {
        dbGet, dbAll, isKeySql,
        failNextQuery(err) { failNext = err; },
        deleteUser(uid) { deletedUsers.add(Number(uid)); },
        _state: { identities, spks, pqs, opks, pqOpks },
    };
}

module.exports = { makeFakeKeyDb };
