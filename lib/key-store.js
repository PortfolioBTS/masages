// Встроенное хранилище публичных E2EE-ключей: свои таблицы в той же базе,
// что и остальное приложение, без отдельного сервиса.
//
// Оно держит только ПУБЛИЧНЫЙ материал (identity, подписанные prekey,
// одноразовые prekey), поэтому может жить в общей базе — так же, как это
// делает Signal; приватные ключи не покидают устройство клиента.
//
// Времени создания и обновления ключей в таблицах нет вовсе: срок жизни
// prekey решает клиент (ротация раз в 7 дней), серверу он не нужен, а по
// `created_at` в дампе базы было бы видно, в какие дни устройство выходило
// в сеть (docs/security/message-ordering.md, раздел 11).
//
// Маршруты lib/e2ee-keys.js обращаются к хранилищу через call() с путями
// вида /internal/v1/keys/...: это ключи маршрутизации внутри процесса,
// HTTP-сервера на этих путях нет. Статусы ответов (400, 404, 409) — часть
// контракта с клиентом (public/e2ee.js: по 409 он заново регистрирует
// identity), менять их можно только вместе с ним.

const crypto = require('crypto');

const PUBKEY_LEN = 32;
const SIGNATURE_LEN = 64;
// ML-KEM-768 encapsulation key: 3 полинома × 384 байта (коэффициенты по
// 12 бит) + 32 байта ρ (FIPS 203).
const PQ_PUBKEY_LEN = 1184;
const PQ_T_LEN = 1152;
const MLKEM_Q = 3329;
const MAX_OTPK_BATCH = 200;
// Потолки на пользователя: без них любой участник забил бы базу своими
// ключами. Клиент держит около 30 классических и 20 постквантовых
// одноразовых ключей, потолки оставляют запас на повторную загрузку после
// сбоя сети.
const MAX_OTPK_STORED = 500;
// Одноразовый PQ-prekey весит ~1,2 КБ: пачка больше 50 ключей вышла бы за
// разумный размер запроса (лимит JSON для маршрута — 256 КБ), а потолок в 100
// покрывает пул клиента (20) с запасом на обновление пула раз в 30 дней.
const MAX_PQ_OTPK_BATCH = 50;
const MAX_PQ_OTPK_STORED = 100;
const MAX_IDENTITY_IDS = 200;
// Таблицы prekey пользователя (всё, кроме identity_keys), от одноразовых к
// подписанным: порядок важен только для читаемости.
const PREKEY_TABLES = ['pq_one_time_prekeys', 'one_time_prekeys', 'signed_pq_prekeys', 'signed_prekeys'];
// Метка домена подписи одноразового PQ-prekey (docs: план криптографии, §1.1).
// Подпись identity-ключа над «сырыми» байтами существует только для SPK
// (32 байта) и PQ last-resort (1184 байта); любая новая подпись начинается с
// метки, поэтому сервер не может выдать одноразовый ключ за last-resort и
// наоборот, а подпись нельзя перенести на другой key_id.
const PQ_OTPK_LABEL = Buffer.from('nyxo-pqopk-v1\0', 'utf8');
// Префикс SPKI-обёртки Ed25519 (RFC 8410) — чтобы проверить подпись сырым
// 32-байтовым ключом через node:crypto.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

async function initKeyStoreSchema(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS identity_keys (
            user_id               BIGINT PRIMARY KEY,
            identity_signing_key  BYTEA NOT NULL,
            identity_dh_key       BYTEA NOT NULL,
            -- Журнал ключей (key-transparency.md, 6.1): nonce обязательства, поколение и эпоха
            -- регистрации и обещание включения (SKT, 64 байта). Журнал выключен или ключ ещё не
            -- зарегистрирован в нём — NULL; удаление аккаунта удаляет nonce вместе со строкой.
            kt_nonce              BYTEA,
            kt_gen                INTEGER,
            kt_epoch              INTEGER,
            kt_skt                BYTEA
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS signed_prekeys (
            user_id      BIGINT PRIMARY KEY,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            signature    BYTEA NOT NULL
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS one_time_prekeys (
            id           BIGSERIAL PRIMARY KEY,
            user_id      BIGINT NOT NULL,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            UNIQUE (user_id, key_id)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekeys(user_id)');
    await pool.query(`
        CREATE TABLE IF NOT EXISTS signed_pq_prekeys (
            user_id      BIGINT PRIMARY KEY,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            signature    BYTEA NOT NULL
        )
    `);
    // Одноразовые постквантовые prekey (ML-KEM-768) с подписью identity-ключа.
    // Порядок выдачи — по id (первым пришёл — первым ушёл), id же не несёт
    // времени.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS pq_one_time_prekeys (
            id           BIGSERIAL PRIMARY KEY,
            user_id      BIGINT NOT NULL,
            key_id       BIGINT NOT NULL,
            public_key   BYTEA NOT NULL,
            signature    BYTEA NOT NULL,
            UNIQUE (user_id, key_id)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_pqotpk_user ON pq_one_time_prekeys(user_id, id)');
    await initKeyTransparencySchema(pool);
}

// Таблицы журнала ключей (docs/security/key-transparency.md, 6.1). В журнале нет
// user_id и времени точнее часа: метка, обязательство, час и хэши. Исключение —
// kt_pending (живёт до закрытия эпохи): user_id без внешнего ключа, запись
// удаляет deleteUserAccount.
async function initKeyTransparencySchema(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS kt_state (
            singleton    BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
            gen          INTEGER NOT NULL,
            gen_start    INTEGER NOT NULL,      -- первая эпоха текущего поколения
            open_epoch   INTEGER NOT NULL,      -- эпоха, в которую сейчас попадают регистрации
            last_head    BYTEA NOT NULL         -- голова последней закрытой эпохи (в начале журнала — 32 нулевых байта)
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS kt_epochs (
            gen INTEGER NOT NULL, epoch INTEGER NOT NULL,
            smt_root BYTEA NOT NULL, head BYTEA NOT NULL, sig BYTEA NOT NULL,
            -- Только у первой эпохи поколения: финальная голова предыдущего поколения.
            -- Из неё считается genesis, а после удаления предыдущего поколения взять её негде.
            prev_final_head BYTEA,
            PRIMARY KEY (gen, epoch)
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS kt_entries (
            gen INTEGER NOT NULL, epoch INTEGER NOT NULL,
            label BYTEA NOT NULL, commitment BYTEA NOT NULL,
            PRIMARY KEY (gen, epoch, label, commitment)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_kt_entries_label ON kt_entries (label, gen, epoch)');
    await pool.query(`
        CREATE TABLE IF NOT EXISTS kt_pending (
            commitment BYTEA PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            label      BYTEA NOT NULL
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_kt_pending_user ON kt_pending (user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_kt_pending_label ON kt_pending (label)');
    // Компактный индекс эпохи (6.3): хэши поддеревьев — ветвящихся узлов и их детей.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS kt_nodes (
            gen INTEGER NOT NULL, epoch INTEGER NOT NULL,
            depth  SMALLINT NOT NULL CHECK (depth BETWEEN 1 AND 127),
            prefix BYTEA NOT NULL,
            hash   BYTEA NOT NULL CHECK (octet_length(hash) = 32),
            PRIMARY KEY (gen, epoch, depth, prefix)
        )
    `);
    // Заявления о смене ключа журнала (раздел 11): не больше одного на прежний ключ.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS kt_keychanges (
            old_pub BYTEA PRIMARY KEY CHECK (octet_length(old_pub) = 32),
            new_pub BYTEA NOT NULL    CHECK (octet_length(new_pub) = 32),
            gen INTEGER NOT NULL, epoch INTEGER NOT NULL,
            sig BYTEA NOT NULL        CHECK (octet_length(sig) = 64)
        )
    `);
}

class KeyStoreError extends Error {
    // code — необязательный машинный код ответа (например, 'kt-rate'): клиент разбирает его, а не текст.
    constructor(status, message, code) {
        super(message);
        this.status = status;
        if (code) this.code = code;
    }
}

// Ошибка ввода: статус 400, текст "bad request: <поле>: <причина>".
const badRequest = (message) => new KeyStoreError(400, 'bad request: ' + message);

// Строгий base64 (стандартный алфавит, обязательное '=' и канонические биты):
// Buffer.from(…, 'base64') молча пропускает мусорные символы, и "ключ" с
// посторонними байтами прошёл бы.
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

// Для подписанных одноразовых PQ-prekey key_id входит в подписываемые байты
// как u64be, поэтому отрицательные значения (у которых нет такой записи)
// недопустимы.
function parseSignedKeyId(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw badRequest('key_id: must be a non-negative integer');
    return value;
}

// u64be(n) = u32be(floor(n / 2^32)) ‖ u32be(n mod 2^32): запись целого до
// 2^53 в восемь байт, одинаковая в браузере (Number) и здесь.
function u64be(n) {
    const out = Buffer.alloc(8);
    out.writeUInt32BE(Math.floor(n / 0x100000000), 0);
    out.writeUInt32BE(n >>> 0, 4);
    return out;
}

// Подписываемые байты одноразового PQ-prekey: метка ‖ u64be(key_id) ‖ pk[1184].
// Все части фиксированной длины (14 + 8 + 1184), поэтому два разных набора
// полей не дают одну и ту же строку.
function pqOneTimePrekeyMessage(keyId, publicKey) {
    return Buffer.concat([PQ_OTPK_LABEL, u64be(keyId), publicKey]);
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

// "1,2,3" → [1, 2, 3]: отсортировано, без повторов, не больше
// MAX_IDENTITY_IDS положительных целых.
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

// withTransaction(work(client)) — транзакция: регистрация ключа (identity,
// удаление prekey при смене ключа и запись в журнал) выполняется целиком или не
// выполняется. kt — журнал ключей (lib/kt-service.js): если он передан, ответы
// содержат поле kt (null, пока журнал выключен или ключ не зарегистрирован в нём).
// Без withTransaction и kt (юнит-тесты хранилища) работает прежний путь.
function createKeyStore({ dbGet, dbAll, withTransaction, kt }) {
    if (typeof dbGet !== 'function' || typeof dbAll !== 'function') {
        throw new TypeError('createKeyStore({ dbGet, dbAll }): нужны функции dbGet и dbAll');
    }
    if (kt && typeof withTransaction !== 'function') {
        throw new TypeError('createKeyStore: для журнала ключей нужна withTransaction');
    }
    const ktColumns = kt ? ', kt_nonce, kt_gen, kt_epoch, kt_skt' : '';

    async function identitySigningKey(userId) {
        const row = await dbGet('SELECT identity_signing_key FROM identity_keys WHERE user_id = $1', [userId]);
        return row ? row.identity_signing_key : null;
    }

    // Если у пользователя уже была другая identity, все его prekey подписаны
    // старым ключом: подписанные (SPK, PQ last-resort, одноразовые PQ) больше
    // не проверяются новым, а классические одноразовые принадлежат старой
    // установке. Их удаляют, чтобы сервер не раздавал инициаторам ключи,
    // которые получатель уже не расшифрует. Повторная регистрация той же
    // identity (клиент делает её при каждом init) ничего не стирает: UPDATE
    // не выполняется, и RETURNING пуст.
    async function putIdentity(userId, body) {
        const signing = decodePubkey('identity_signing_key', body.identity_signing_key);
        const dh = decodePubkey('identity_dh_key', body.identity_dh_key);
        const upsert = `INSERT INTO identity_keys (user_id, identity_signing_key, identity_dh_key)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id) DO UPDATE
                 SET identity_signing_key = EXCLUDED.identity_signing_key,
                     identity_dh_key = EXCLUDED.identity_dh_key
                 WHERE identity_keys.identity_signing_key <> EXCLUDED.identity_signing_key
                    OR identity_keys.identity_dh_key <> EXCLUDED.identity_dh_key
             RETURNING (xmax = 0) AS inserted`;
        if (typeof withTransaction !== 'function') {
            const rows = await dbAll(upsert, [userId, signing, dh]);
            if (rows.length > 0 && !rows[0].inserted) {
                for (const table of PREKEY_TABLES) await dbAll(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
            }
            return ok();
        }
        // Одна транзакция (key-transparency.md, 6.2). Порядок блокировок
        // kt_state FOR SHARE → identity_keys → kt_pending: закрытие эпохи ждёт
        // регистрации, а SKT относится к той эпохе, в которую запись попала.
        // Оборванная регистрация не оставит identity_keys без записи в kt_pending.
        return withTransaction(async (client) => {
            const state = kt ? await kt.lockState(client) : null;
            const { rows } = await client.query(upsert, [userId, signing, dh]);
            if (rows.length > 0 && !rows[0].inserted) {
                for (const table of PREKEY_TABLES) await client.query(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
            }
            if (!kt) return ok();
            // Нет строки kt_state (задача эпох не стартовала) или журнал выключен: kt = null.
            const hint = state ? await kt.registerInTx(client, state, { userId, keysChanged: rows.length > 0 }) : null;
            return ok({ success: true, kt: hint });
        });
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
            `INSERT INTO ${table} (user_id, key_id, public_key, signature)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id) DO UPDATE
                 SET key_id = EXCLUDED.key_id,
                     public_key = EXCLUDED.public_key,
                     signature = EXCLUDED.signature`,
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
        await assertRoomForKeys('one_time_prekeys', userId, keys.length, MAX_OTPK_STORED);
        const rows = await dbAll(
            `INSERT INTO one_time_prekeys (user_id, key_id, public_key)
             SELECT $1, t.key_id, t.public_key
             FROM UNNEST($2::bigint[], $3::bytea[]) AS t(key_id, public_key)
             ON CONFLICT (user_id, key_id) DO NOTHING
             RETURNING 1`,
            [userId, keyIds, publicKeys]
        );
        if (rows.length > 0) await trimToCap('one_time_prekeys', userId, MAX_OTPK_STORED);
        return ok({ success: true, inserted: rows.length });
    }

    // Одноразовые постквантовые prekey. Подпись — identity-ключом над
    // «метка ‖ u64be(key_id) ‖ pk» (pqOneTimePrekeyMessage): ключ без подписи
    // или с подписью «сырых» байтов (формат last-resort) не принимается, как и
    // подпись, снятая с другого key_id. Identity обязана быть
    // зарегистрирована раньше (409, как для SPK).
    async function postPqOneTimePrekeys(userId, body) {
        const keys = body && body.keys;
        if (!Array.isArray(keys) || keys.length === 0) throw badRequest('keys must not be empty');
        if (keys.length > MAX_PQ_OTPK_BATCH) throw badRequest(`batch too large: max ${MAX_PQ_OTPK_BATCH} keys per request`);
        const signing = await identitySigningKey(userId);
        if (!signing) throw new KeyStoreError(409, 'conflict: identity keys must be registered before a pq one-time prekey');
        const keyIds = [];
        const publicKeys = [];
        const signatures = [];
        for (const item of keys) {
            const keyId = parseSignedKeyId(item && item.key_id);
            const publicKey = decodePqPubkey('keys[].public_key', item && item.public_key);
            const signature = decodeSignature('keys[].signature', item && item.signature);
            verifySignature('keys[].signature', signing, pqOneTimePrekeyMessage(keyId, publicKey), signature);
            keyIds.push(keyId);
            publicKeys.push(publicKey);
            signatures.push(signature);
        }
        await assertRoomForKeys('pq_one_time_prekeys', userId, keys.length, MAX_PQ_OTPK_STORED);
        const rows = await dbAll(
            `INSERT INTO pq_one_time_prekeys (user_id, key_id, public_key, signature)
             SELECT $1, t.key_id, t.public_key, t.signature
             FROM UNNEST($2::bigint[], $3::bytea[], $4::bytea[]) AS t(key_id, public_key, signature)
             ON CONFLICT (user_id, key_id) DO NOTHING
             RETURNING 1`,
            [userId, keyIds, publicKeys, signatures]
        );
        if (rows.length > 0) await trimToCap('pq_one_time_prekeys', userId, MAX_PQ_OTPK_STORED);
        return ok({ success: true, inserted: rows.length });
    }

    // Клиент раз в 30 дней обновляет пул: стирает старые одноразовые PQ-prekey
    // и загружает новые, чтобы выданные «вхолостую» ключи не копились.
    async function deletePqOneTimePrekeys(userId) {
        await dbAll('DELETE FROM pq_one_time_prekeys WHERE user_id = $1', [userId]);
        return ok();
    }

    // Проверка потолка ДО вставки: понятный 400 вместо тихой обрезки. Между
    // проверкой и вставкой параллельный запрос может проскочить, поэтому после
    // вставки trimToCap добивает превышение — потолок держится жёстко.
    async function assertRoomForKeys(table, userId, adding, cap) {
        const row = await dbGet(`SELECT COUNT(*)::int AS count FROM ${table} WHERE user_id = $1`, [userId]);
        const stored = row ? row.count : 0;
        if (stored + adding > cap) throw badRequest(`too many stored keys: max ${cap} per user`);
    }

    // Оставляет у пользователя не больше cap самых старых ключей (они уйдут в
    // bundle первыми); излишек новее — его и убираем.
    async function trimToCap(table, userId, cap) {
        await dbAll(
            `DELETE FROM ${table}
             WHERE user_id = $1 AND id IN (
                 SELECT id FROM ${table} WHERE user_id = $1 ORDER BY id DESC OFFSET $2
             )`,
            [userId, cap]
        );
    }

    // Оба пула одним запросом: клиент решает по этим числам, пополнять ли
    // классические (count) и постквантовые (pq_count) одноразовые ключи.
    async function countOneTimePrekeys(userId) {
        const row = await dbGet(
            `SELECT (SELECT COUNT(*)::int FROM one_time_prekeys WHERE user_id = $1) AS count,
                    (SELECT COUNT(*)::int FROM pq_one_time_prekeys WHERE user_id = $1) AS pq_count`,
            [userId]
        );
        return ok({ count: row ? row.count : 0, pq_count: row ? row.pq_count : 0 });
    }

    async function getIdentities(query) {
        const ids = parseIdList(query.get('ids'));
        const rows = await dbAll(
            `SELECT user_id, identity_signing_key, identity_dh_key${ktColumns} FROM identity_keys
             WHERE user_id = ANY($1::bigint[]) ORDER BY user_id`,
            [ids]
        );
        return ok({
            identities: rows.map(r => ({
                user_id: Number(r.user_id),
                identity_signing_key: b64(r.identity_signing_key),
                identity_dh_key: b64(r.identity_dh_key),
                ...(kt ? { kt: kt.hintOf(r) } : {}),
            })),
        });
    }

    // Bundle для X3DH/PQXDH. Одноразовые prekey (классический и
    // постквантовый) забираются атомарно одним DELETE … FOR UPDATE SKIP
    // LOCKED — параллельные запросы не получат один и тот же ключ. Без
    // identity или SPK — 404 ДО расхода ключей. pq_prekey (last-resort)
    // остаётся в ответе всегда: он выручает, когда одноразовые кончились.
    async function getBundle(targetUserId) {
        const identity = await dbGet(
            `SELECT identity_signing_key, identity_dh_key${ktColumns} FROM identity_keys WHERE user_id = $1`,
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
        const pqOtpk = await dbGet(
            `DELETE FROM pq_one_time_prekeys
             WHERE id = (
                 SELECT id FROM pq_one_time_prekeys WHERE user_id = $1
                 ORDER BY id ASC LIMIT 1 FOR UPDATE SKIP LOCKED
             )
             RETURNING key_id, public_key, signature`,
            [targetUserId]
        );
        return ok({
            identity_signing_key: b64(identity.identity_signing_key),
            identity_dh_key: b64(identity.identity_dh_key),
            ...(kt ? { kt: kt.hintOf(identity) } : {}),
            signed_prekey: { key_id: Number(spk.key_id), public_key: b64(spk.public_key), signature: b64(spk.signature) },
            one_time_prekey: otpk ? { key_id: Number(otpk.key_id), public_key: b64(otpk.public_key) } : null,
            pq_one_time_prekey: pqOtpk
                ? { key_id: Number(pqOtpk.key_id), public_key: b64(pqOtpk.public_key), signature: b64(pqOtpk.signature) }
                : null,
            pq_prekey: pq ? { key_id: Number(pq.key_id), public_key: b64(pq.public_key), signature: b64(pq.signature) } : null,
        });
    }

    async function deleteAll(userId) {
        for (const table of [...PREKEY_TABLES, 'identity_keys']) {
            await dbAll(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
        }
        return ok();
    }

    // Единая точка входа для lib/e2ee-keys.js:
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
                case 'POST /internal/v1/keys/pq-one-time-prekeys':
                    return await postPqOneTimePrekeys(userId, payload);
                case 'DELETE /internal/v1/keys/pq-one-time-prekeys':
                    return await deletePqOneTimePrekeys(userId);
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
                return { status: err.status, ok: false, data: { success: false, ...(err.code ? { code: err.code } : {}), message: err.message } };
            }
            throw err; // ошибка БД — маршрут ответит 502
        }
    }

    return { call, deleteAll: (userId) => deleteAll(userId) };
}

module.exports = {
    initKeyStoreSchema,
    createKeyStore,
    KeyStoreError,
    _internal: {
        decodeB64, decodePubkey, decodePqPubkey, decodeSignature, parseIdList, verifySignature,
        pqOneTimePrekeyMessage, u64be,
        MAX_OTPK_STORED, MAX_PQ_OTPK_BATCH, MAX_PQ_OTPK_STORED,
    },
};
