// Встроенное хранилище публичных E2EE-ключей — замена отдельного сервиса
// e2ee-key-server, когда он не развёрнут.
//
// Раньше без e2ee-key-server (а на Railway его отдельно никто не поднимал)
// все /api/keys/* отвечали 503, клиент не мог зарегистрировать ключи
// устройства и показывал «Сквозное шифрование недоступно». Хранилище
// держит только ПУБЛИЧНЫЙ материал (identity, подписанные prekey, одноразовые
// prekey), поэтому может жить в той же базе, что и остальное приложение, —
// так же, как это делает Signal. Отдельный сервис остаётся вариантом: если
// задан INTERNAL_KEY_SERVER_SECRET, lib/e2ee-proxy.js ходит в него.
//
// Внутренний API и ответы повторяют e2ee-key-server (handlers.rs) один в
// один — прокси не знает, какой из двух за ним. Таблицы — те же, что в его
// миграциях 0001/0002, так что позже можно переключиться на отдельный
// сервис без переноса данных.

const crypto = require('crypto');

const PUBKEY_LEN = 32;
const SIGNATURE_LEN = 64;
// ML-KEM-768 encapsulation key: 3 полинома × 384 байта (коэффициенты по
// 12 бит) + 32 байта ρ (FIPS 203).
const PQ_PUBKEY_LEN = 1184;
const PQ_T_LEN = 1152;
const MLKEM_Q = 3329;
const MAX_OTPK_BATCH = 200;
const MAX_IDENTITY_IDS = 200;
// Префикс SPKI-обёртки Ed25519 (RFC 8410) — чтобы проверить подпись сырым
// 32-байтовым ключом через node:crypto.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

async function initKeyStoreSchema(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS identity_keys (
            user_id               BIGINT PRIMARY KEY,
            identity_signing_key  BYTEA NOT NULL,
            identity_dh_key       BYTEA NOT NULL,
            created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS signed_prekeys (
            user_id      BIGINT PRIMARY KEY,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            signature    BYTEA NOT NULL,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS one_time_prekeys (
            id           BIGSERIAL PRIMARY KEY,
            user_id      BIGINT NOT NULL,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (user_id, key_id)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekeys(user_id)');
    await pool.query(`
        CREATE TABLE IF NOT EXISTS signed_pq_prekeys (
            user_id      BIGINT PRIMARY KEY,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            signature    BYTEA NOT NULL,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    `);
}

class KeyStoreError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

// Тексты — как у AppError в e2ee-key-server ("bad request: …", "conflict: …").
const badRequest = (message) => new KeyStoreError(400, 'bad request: ' + message);

// Строгий base64 (как STANDARD в Rust): Buffer.from(…, 'base64') молча
// пропускает мусорные символы, и "ключ" с посторонними байтами прошёл бы.
function decodeB64(field, value) {
    if (typeof value !== 'string' || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
        throw badRequest(`${field}: invalid base64`);
    }
    const bytes = Buffer.from(value, 'base64');
    if (bytes.toString('base64') !== value) throw badRequest(`${field}: invalid base64`);
    return bytes;
}

function decodePubkey(field, value) {
    const bytes = decodeB64(field, value);
    if (bytes.length !== PUBKEY_LEN) throw badRequest(`${field}: must be ${PUBKEY_LEN} bytes`);
    if (bytes.every(b => b === 0)) throw badRequest(`${field}: all-zero key rejected (low-order point)`);
    return bytes;
}

function decodeSignature(field, value) {
    const bytes = decodeB64(field, value);
    if (bytes.length !== SIGNATURE_LEN) throw badRequest(`${field}: must be ${SIGNATURE_LEN} bytes`);
    return bytes;
}

// Проверка ввода ML-KEM из FIPS 203 (§7.2): каждый 12-битный коэффициент t
// меньше q, и t не нулевой вектор. Честный KeyGen такие ключи не выдаёт.
function decodePqPubkey(field, value) {
    const bytes = decodeB64(field, value);
    if (bytes.length !== PQ_PUBKEY_LEN) throw badRequest(`${field}: must be ${PQ_PUBKEY_LEN} bytes`);
    let nonZero = false;
    for (let i = 0; i < PQ_T_LEN; i += 3) {
        const c0 = bytes[i] | ((bytes[i + 1] & 0x0f) << 8);
        const c1 = (bytes[i + 1] >> 4) | (bytes[i + 2] << 4);
        if (c0 >= MLKEM_Q || c1 >= MLKEM_Q) throw badRequest(`${field}: coefficient out of range (FIPS 203 modulus check)`);
        if (c0 !== 0 || c1 !== 0) nonZero = true;
    }
    if (!nonZero) throw badRequest(`${field}: all-zero key rejected`);
    return bytes;
}

function parseKeyId(value) {
    if (!Number.isSafeInteger(value)) throw badRequest('key_id: must be an integer');
    return value;
}

function verifySignature(label, identitySigningKey, message, signature) {
    let ok = false;
    try {
        const key = crypto.createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, identitySigningKey]),
            format: 'der',
            type: 'spki',
        });
        ok = crypto.verify(null, message, key, signature);
    } catch {
        throw badRequest('identity_signing_key: invalid Ed25519 point');
    }
    if (!ok) throw badRequest(`${label}: signature verification failed`);
}

// "1,2,3" → [1, 2, 3] (отсортировано, без повторов). Те же правила, что у
// parse_id_list в handlers.rs.
function parseIdList(raw) {
    if (typeof raw !== 'string' || raw === '') throw badRequest('ids: must not be empty');
    const parts = raw.split(',');
    if (parts.length > MAX_IDENTITY_IDS) throw badRequest(`ids: max ${MAX_IDENTITY_IDS} ids per request`);
    const ids = new Set();
    for (const part of parts) {
        if (!/^\d{1,18}$/.test(part)) throw badRequest('ids: invalid id');
        const id = Number(part);
        if (!Number.isSafeInteger(id) || id <= 0) throw badRequest('ids: invalid id');
        ids.add(id);
    }
    return [...ids].sort((a, b) => a - b);
}

const b64 = (buf) => Buffer.from(buf).toString('base64');
const ok = (data = { success: true }) => ({ status: 200, ok: true, data });

function createKeyStore({ dbGet, dbAll }) {
    if (typeof dbGet !== 'function' || typeof dbAll !== 'function') {
        throw new TypeError('createKeyStore({ dbGet, dbAll }): нужны функции dbGet и dbAll');
    }

    async function identitySigningKey(userId) {
        const row = await dbGet('SELECT identity_signing_key FROM identity_keys WHERE user_id = $1', [userId]);
        return row ? row.identity_signing_key : null;
    }

    async function putIdentity(userId, body) {
        const signing = decodePubkey('identity_signing_key', body.identity_signing_key);
        const dh = decodePubkey('identity_dh_key', body.identity_dh_key);
        await dbAll(
            `INSERT INTO identity_keys (user_id, identity_signing_key, identity_dh_key, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (user_id) DO UPDATE
                 SET identity_signing_key = EXCLUDED.identity_signing_key,
                     identity_dh_key = EXCLUDED.identity_dh_key,
                     updated_at = now()`,
            [userId, signing, dh]
        );
        return ok();
    }

    async function putSignedPrekey(userId, body, table, decodeKey, label) {
        const publicKey = decodeKey('public_key', body.public_key);
        const signature = decodeSignature('signature', body.signature);
        const keyId = parseKeyId(body.key_id);
        const signing = await identitySigningKey(userId);
        if (!signing) {
            throw new KeyStoreError(409, `conflict: identity keys must be registered before a ${label}`);
        }
        verifySignature(label, signing, publicKey, signature);
        await dbAll(
            `INSERT INTO ${table} (user_id, key_id, public_key, signature, created_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (user_id) DO UPDATE
                 SET key_id = EXCLUDED.key_id,
                     public_key = EXCLUDED.public_key,
                     signature = EXCLUDED.signature,
                     created_at = now()`,
            [userId, keyId, publicKey, signature]
        );
        return ok();
    }

    async function postOneTimePrekeys(userId, body) {
        const keys = body && body.keys;
        if (!Array.isArray(keys) || keys.length === 0) throw badRequest('keys must not be empty');
        if (keys.length > MAX_OTPK_BATCH) throw badRequest(`batch too large: max ${MAX_OTPK_BATCH} keys per request`);
        const keyIds = [];
        const publicKeys = [];
        for (const item of keys) {
            keyIds.push(parseKeyId(item && item.key_id));
            publicKeys.push(decodePubkey('keys[].public_key', item && item.public_key));
        }
        const rows = await dbAll(
            `INSERT INTO one_time_prekeys (user_id, key_id, public_key)
             SELECT $1, t.key_id, t.public_key
             FROM UNNEST($2::bigint[], $3::bytea[]) AS t(key_id, public_key)
             ON CONFLICT (user_id, key_id) DO NOTHING
             RETURNING 1`,
            [userId, keyIds, publicKeys]
        );
        return ok({ success: true, inserted: rows.length });
    }

    async function countOneTimePrekeys(userId) {
        const row = await dbGet('SELECT COUNT(*)::int AS count FROM one_time_prekeys WHERE user_id = $1', [userId]);
        return ok({ count: row ? row.count : 0 });
    }

    async function getIdentities(query) {
        const ids = parseIdList(query.get('ids'));
        const rows = await dbAll(
            `SELECT user_id, identity_signing_key, identity_dh_key FROM identity_keys
             WHERE user_id = ANY($1::bigint[]) ORDER BY user_id`,
            [ids]
        );
        return ok({
            identities: rows.map(r => ({
                user_id: Number(r.user_id),
                identity_signing_key: b64(r.identity_signing_key),
                identity_dh_key: b64(r.identity_dh_key),
            })),
        });
    }

    // Bundle для X3DH/PQXDH. Одноразовый prekey забирается атомарно одним
    // DELETE … FOR UPDATE SKIP LOCKED — параллельные запросы не получат один
    // и тот же OPK. Без identity или SPK — 404 ДО расхода OPK.
    async function getBundle(targetUserId) {
        const identity = await dbGet(
            'SELECT identity_signing_key, identity_dh_key FROM identity_keys WHERE user_id = $1',
            [targetUserId]
        );
        if (!identity) throw new KeyStoreError(404, 'not found');
        const spk = await dbGet('SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = $1', [targetUserId]);
        if (!spk) throw new KeyStoreError(404, 'not found');
        const pq = await dbGet('SELECT key_id, public_key, signature FROM signed_pq_prekeys WHERE user_id = $1', [targetUserId]);
        const otpk = await dbGet(
            `DELETE FROM one_time_prekeys
             WHERE id = (
                 SELECT id FROM one_time_prekeys WHERE user_id = $1
                 ORDER BY id ASC LIMIT 1 FOR UPDATE SKIP LOCKED
             )
             RETURNING key_id, public_key`,
            [targetUserId]
        );
        return ok({
            identity_signing_key: b64(identity.identity_signing_key),
            identity_dh_key: b64(identity.identity_dh_key),
            signed_prekey: { key_id: Number(spk.key_id), public_key: b64(spk.public_key), signature: b64(spk.signature) },
            one_time_prekey: otpk ? { key_id: Number(otpk.key_id), public_key: b64(otpk.public_key) } : null,
            pq_prekey: pq ? { key_id: Number(pq.key_id), public_key: b64(pq.public_key), signature: b64(pq.signature) } : null,
        });
    }

    async function deleteAll(userId) {
        for (const table of ['one_time_prekeys', 'signed_prekeys', 'signed_pq_prekeys', 'identity_keys']) {
            await dbAll(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
        }
        return ok();
    }

    // Тот же интерфейс, что у вызова отдельного сервиса в e2ee-proxy.js:
    // (userId, метод, путь внутреннего API, тело) → { status, ok, data }.
    async function call(userId, method, path, body) {
        const url = new URL(path, 'http://key-store.internal');
        const route = `${method} ${url.pathname}`;
        const payload = body || {};
        try {
            switch (route) {
                case 'PUT /internal/v1/keys/identity':
                    return await putIdentity(userId, payload);
                case 'PUT /internal/v1/keys/signed-prekey':
                    return await putSignedPrekey(userId, payload, 'signed_prekeys', decodePubkey, 'signed prekey');
                case 'PUT /internal/v1/keys/pq-prekey':
                    return await putSignedPrekey(userId, payload, 'signed_pq_prekeys', decodePqPubkey, 'pq prekey');
                case 'POST /internal/v1/keys/one-time-prekeys':
                    return await postOneTimePrekeys(userId, payload);
                case 'GET /internal/v1/keys/one-time-prekeys/count':
                    return await countOneTimePrekeys(userId);
                case 'GET /internal/v1/keys/identities':
                    return await getIdentities(url.searchParams);
                case 'DELETE /internal/v1/keys':
                    return await deleteAll(userId);
                default: {
                    const m = method === 'GET' && /^\/internal\/v1\/keys\/bundle\/(\d{1,18})$/.exec(url.pathname);
                    if (m) return await getBundle(Number(m[1]));
                    return { status: 404, ok: false, data: { success: false, message: 'not found' } };
                }
            }
        } catch (err) {
            if (err instanceof KeyStoreError) {
                return { status: err.status, ok: false, data: { success: false, message: err.message } };
            }
            throw err; // ошибка БД — прокси ответит 502, как при недоступном сервисе
        }
    }

    return { call, deleteAll: (userId) => deleteAll(userId) };
}

module.exports = {
    initKeyStoreSchema,
    createKeyStore,
    _internal: { decodeB64, decodePubkey, decodePqPubkey, decodeSignature, parseIdList, verifySignature },
};
