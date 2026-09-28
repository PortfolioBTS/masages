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
    let nextOpkId = 1;
    let failNext = null;

    const isKeySql = (sql) => /identity_keys|signed_prekeys|signed_pq_prekeys|one_time_prekeys/.test(sql);

    async function dbAll(sql, params = []) {
        if (failNext) { const err = failNext; failNext = null; throw err; }
        const q = sql.replace(/\s+/g, ' ').trim();
        const uid = Number(params[0]);
        if (q.startsWith('INSERT INTO identity_keys')) {
            identities.set(uid, { identity_signing_key: params[1], identity_dh_key: params[2] });
            return [];
        }
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
        if (q.startsWith('SELECT COUNT(*)::int AS count FROM one_time_prekeys')) {
            return [{ count: opks.filter(o => o.user_id === uid).length }];
        }
        if (q.startsWith('SELECT identity_signing_key FROM identity_keys')) {
            const row = identities.get(uid);
            return row ? [{ identity_signing_key: row.identity_signing_key }] : [];
        }
        if (q.startsWith('SELECT user_id, identity_signing_key, identity_dh_key FROM identity_keys WHERE user_id = ANY')) {
            return params[0].filter(id => identities.has(id)).sort((a, b) => a - b)
                .map(id => Object.assign({ user_id: String(id) }, identities.get(id))); // BIGINT приходит строкой
        }
        if (q.startsWith('SELECT identity_signing_key, identity_dh_key FROM identity_keys')) {
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
        m = /^DELETE FROM (\w+) WHERE user_id = \$1$/.exec(q);
        if (m) {
            if (m[1] === 'one_time_prekeys') {
                for (let i = opks.length - 1; i >= 0; i--) if (opks[i].user_id === uid) opks.splice(i, 1);
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
        _state: { identities, spks, pqs, opks },
    };
}

module.exports = { makeFakeKeyDb };
