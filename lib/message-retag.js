'use strict';
// Перетегирование и перешифровка сообщений комнат после смены MESSAGE_ENCRYPTION_KEY
// (docs/security/sealed-sender.md, 14.1; процедура — docs/ops/message-key-rotation.md,
// CLI — scripts/retag-messages.js).
//
// Зачем. Тег автора и ключ шифрования строки (K_enc3) выводятся из MESSAGE_ENCRYPTION_KEY,
// а тег входит в AAD enc:v3. После смены ключа старые строки читаются через
// MESSAGE_ENCRYPTION_KEY_PREVIOUS, но остаются под старым тегом и старым kid. Пока так,
// …_PREVIOUS убирать нельзя: пропадут чтение, правка и удаление по тегу. Скрипт
// переводит каждую такую строку под новый ключ: расшифровывает enc:v3 старым ключом с
// её старым тегом, находит владельца тега, считает новый тег по тому же created_at,
// шифрует под K_enc3 нового ключа с AAD, где уже НОВЫЙ тег, и записывает author_tag и
// text одним UPDATE.
//
// Владелец тега находится перебором: для каждого user_id из room_participants ∪
// user_left_rooms комнаты и каждой недели — tagsForAccount под всеми ключами. Тег, не
// совпавший ни с кем (владелец удалил аккаунт — строк бы не было; значит, утерян
// …_PREVIOUS или запись повреждена), фиксируется в отчёте и НЕ меняется.
//
// Идемпотентность и возобновляемость: строка, уже лежащая под kid текущего ключа и
// под тегом текущего ключа, пропускается; пачка — одна транзакция (по умолчанию 500
// строк, FOR NO KEY UPDATE, только таблица messages, строка за строкой по id), так что
// прерванный прогон просто запускается снова. Просматриваются ВСЕ строки комнаты, а не
// только со старым kid: правка, записанная сервером с новым ключом до перетегирования,
// имеет новый kid, но старый тег - такая строка тоже переписывается. Тексты сообщений
// в отчёт и журнал не попадают; id строк - только с verbose.
//
// Чистая часть (retagRow, ownerIndex) не знает про БД и проверяется юнит-тестом;
// циклы по БД - retagDatabase / verifyDatabase (сквозной тест на настоящем Postgres).

const DEFAULT_BATCH = 500;
const PREFIX_V3 = 'enc:v3:';

// Kid записи enc:v3:<kid>:… или null.
function recordKid(text) {
    if (typeof text !== 'string' || !text.startsWith(PREFIX_V3)) return null;
    const kid = text.slice(PREFIX_V3.length).split(':', 1)[0];
    return /^[0-9a-f]{8}$/.test(kid) ? kid : null;
}

// Тег (hex) -> userId для всех пользователей комнаты: участники и вышедшие с сообщениями,
// теги за все недели со дня создания аккаунта под всеми ключами. users — [{ user_id, created_at }].
function ownerIndex(authorTags, roomId, users, now = Date.now()) {
    const index = new Map();
    for (const user of users) {
        for (const tag of authorTags.tagsForAccount(roomId, user.user_id, user.created_at, now)) {
            index.set(tag.toString('hex'), user.user_id);
        }
    }
    return index;
}

// Одна строка -> решение (ничего не пишет):
//   { status: 'current' }                    - уже под текущим kid, трогать не нужно;
//   { status: 'foreign', reason }            - не enc:v3 или kid, которого нет среди ключей: чинить нечем;
//   { status: 'undecryptable' }              - расшифровка старым ключом не удалась;
//   { status: 'orphan' }                     - владелец тега не найден;
//   { status: 'retag', author_tag, text }    - новые значения для UPDATE.
// owners = { all, current }: теги владельцев под всеми ключами и только под текущим.
// deps: { authorTags, crypto: { decryptRoomText, encryptRoomText, messageAadV3, DECRYPT_FAILED }, currentKid, knownKids }
function retagRow(row, owners, deps) {
    const kid = recordKid(row.text);
    if (kid === null) return { status: 'foreign', reason: 'not-v3' };
    if (!deps.knownKids.has(kid)) return { status: 'foreign', reason: 'unknown-kid' };
    const tagHex = Buffer.from(row.author_tag).toString('hex');
    if (kid === deps.currentKid && owners.current.has(tagHex)) return { status: 'current' };
    const { decryptRoomText, encryptRoomText, messageAadV3, DECRYPT_FAILED } = deps.crypto;
    const plain = decryptRoomText(row.text, messageAadV3({ room_id: row.room_id, id: row.id, author_tag: row.author_tag }));
    if (plain === DECRYPT_FAILED) return { status: 'undecryptable' };
    const owner = owners.all.get(tagHex);
    if (owner === undefined) return { status: 'orphan' };
    const authorTag = deps.authorTags.tagFor(row.room_id, owner, row.created_at);
    const text = encryptRoomText(plain, messageAadV3({ room_id: row.room_id, id: row.id, author_tag: authorTag }));
    return { status: 'retag', author_tag: authorTag, text };
}

function newTotals() {
    return { rooms: 0, scanned: 0, retagged: 0, current: 0, foreign: 0, undecryptable: 0, orphan: 0, problems: [] };
}

// Пользователи комнаты: участники и вышедшие с сообщениями.
async function roomUsers(client, roomId) {
    const result = await client.query(
        `SELECT u.id AS user_id, u.created_at FROM users u
         WHERE u.id IN (SELECT user_id FROM room_participants WHERE room_id = $1
                        UNION SELECT user_id FROM user_left_rooms WHERE room_id = $1)`,
        [roomId]
    );
    return result.rows;
}

// Перетегирование всей базы. pool - pg Pool; opts: { batchSize, dryRun, roomId, verbose, log }.
// Возвращает итоги (counts) и список проблемных строк (id только в problems, их печатает
// CLI при verbose).
async function retagDatabase(pool, deps, opts = {}) {
    const batchSize = opts.batchSize || DEFAULT_BATCH;
    const log = opts.log || (() => {});
    const totals = newTotals();
    const rooms = opts.roomId
        ? [{ id: opts.roomId }]
        : (await pool.query('SELECT id FROM rooms ORDER BY id')).rows;
    for (const { id: roomId } of rooms) {
        totals.rooms++;
        let lastId = 0;
        const users = await roomUsers(pool, roomId);
        const owners = { all: ownerIndex(deps.authorTags, roomId, users), current: ownerIndex(deps.currentKeyTags, roomId, users) };
        for (;;) {
            const client = await pool.connect();
            let batch;
            try {
                await client.query('BEGIN');
                // Блокировка NO KEY UPDATE не мешает внешним ключам реакций (KEY SHARE).
                batch = (await client.query(
                    `SELECT id, room_id, author_tag, text, created_at FROM messages
                     WHERE room_id = $1 AND id > $2
                     ORDER BY id LIMIT $3 FOR NO KEY UPDATE`,
                    [roomId, lastId, batchSize]
                )).rows;
                for (const row of batch) {
                    const decision = retagRow(row, owners, deps);
                    totals.scanned++;
                    if (decision.status === 'retag') {
                        if (!opts.dryRun) {
                            await client.query('UPDATE messages SET author_tag = $1, text = $2 WHERE id = $3', [decision.author_tag, decision.text, row.id]);
                        }
                        totals.retagged++;
                    } else {
                        totals[decision.status]++;
                        if (decision.status !== 'current') totals.problems.push({ roomId, id: row.id, status: decision.status, reason: decision.reason });
                    }
                }
                await client.query('COMMIT');
            } catch (err) {
                await client.query('ROLLBACK').catch(() => {});
                throw err;
            } finally {
                client.release();
            }
            if (batch.length > 0) lastId = batch[batch.length - 1].id;
            log(`комната ${roomId}: пачка ${batch.length}, всего переписано ${totals.retagged}`);
            if (batch.length < batchSize) break;
        }
    }
    return totals;
}

// Проверка после перетегирования (только чтение): нет строк enc:v3 с kid, отличным от нового, и
// нет тегов, не входящих в tagsForAccount владельцев комнаты под НОВЫМ ключом (deps.currentKeyTags -
// author-tag только с текущим ключом). Прежний ключ можно убирать из …_PREVIOUS только при
// ok === true (или осознанно, зная проблемные строки).
async function verifyDatabase(pool, deps, opts = {}) {
    const result = { ok: true, rooms: 0, otherKid: 0, unknownTag: 0, notV3: 0, problems: [] };
    const rooms = opts.roomId ? [{ id: opts.roomId }] : (await pool.query('SELECT id FROM rooms ORDER BY id')).rows;
    for (const { id: roomId } of rooms) {
        result.rooms++;
        const owners = ownerIndex(deps.currentKeyTags, roomId, await roomUsers(pool, roomId));
        let lastId = 0;
        for (;;) {
            const batch = (await pool.query(
                `SELECT id, author_tag, text FROM messages WHERE room_id = $1 AND id > $2 ORDER BY id LIMIT $3`,
                [roomId, lastId, opts.batchSize || DEFAULT_BATCH]
            )).rows;
            for (const row of batch) {
                const kid = recordKid(row.text);
                let status = null;
                if (kid === null) { result.notV3++; status = 'not-v3'; }
                else if (kid !== deps.currentKid) { result.otherKid++; status = 'other-kid'; }
                if (!owners.has(Buffer.from(row.author_tag).toString('hex'))) { result.unknownTag++; status = status ? `${status}+unknown-tag` : 'unknown-tag'; }
                if (status) result.problems.push({ roomId, id: row.id, status });
            }
            if (batch.length < (opts.batchSize || DEFAULT_BATCH)) break;
            lastId = batch[batch.length - 1].id;
        }
    }
    result.ok = result.otherKid === 0 && result.unknownTag === 0 && result.notV3 === 0;
    return result;
}

module.exports = { DEFAULT_BATCH, recordKid, ownerIndex, retagRow, retagDatabase, verifyDatabase };
