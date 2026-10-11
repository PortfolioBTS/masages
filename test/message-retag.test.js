'use strict';
// Перетегирование сообщений комнат после смены MESSAGE_ENCRYPTION_KEY
// (docs/security/sealed-sender.md, 14.1): lib/message-retag.js. Решение по строке и цикл по
// пачкам проверяются на настоящих ключах и фейковом пуле; сквозную проверку на Postgres (CLI,
// рестарт сервера с новым ключом, правка и удаление без …_PREVIOUS) делает набор sealed-sender.
// Запуск: node test/message-retag.test.js

const assert = require('assert');
const crypto = require('crypto');

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

const KEY_A = crypto.randomBytes(32);
const KEY_B = crypto.randomBytes(32);
const b64 = (buf) => buf.toString('base64');
const quiet = (fn) => { const saved = console.error; console.error = () => {}; try { return fn(); } finally { console.error = saved; } };

// Модули читают ключи при загрузке: набор ключей = окружение + свежая загрузка.
function loadWorld(current, previous = []) {
    process.env.MESSAGE_ENCRYPTION_KEY = b64(current);
    if (previous.length) process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS = previous.map(b64).join(',');
    else delete process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS;
    for (const name of ['message-crypto', 'author-tag', 'message-retag']) delete require.cache[require.resolve(`../lib/${name}.js`)];
    const messageCrypto = require('../lib/message-crypto.js');
    const { createAuthorTags } = require('../lib/author-tag.js');
    const retag = require('../lib/message-retag.js');
    const ring = messageCrypto.messageKeyRing();
    return {
        messageCrypto, retag,
        deps: {
            authorTags: createAuthorTags(ring.map(e => e.ikm)),
            currentKeyTags: createAuthorTags([ring[0].ikm]),
            crypto: {
                decryptRoomText: messageCrypto.decryptRoomText, encryptRoomText: messageCrypto.encryptRoomText,
                messageAadV3: messageCrypto.messageAadV3, DECRYPT_FAILED: messageCrypto.DECRYPT_FAILED,
            },
            currentKid: ring[0].kid,
            knownKids: new Set(ring.map(e => e.kid)),
        },
    };
}

const ROOM = 4242;
const USERS = [
    { user_id: 11, created_at: new Date('2026-09-01T00:00:00Z') },
    { user_id: 12, created_at: new Date('2026-09-20T00:00:00Z') },
];
const NOW = Date.parse('2026-10-11T12:00:00Z');
const CREATED = new Date('2026-10-05T10:00:00Z');

// Строка комнаты так, как её пишет сервер выбранной «эпохи».
function makeRow(world, { id, user, plain, createdAt = CREATED }) {
    const tag = world.deps.authorTags.tagFor(ROOM, user, createdAt);
    const aad = world.messageCrypto.messageAadV3({ room_id: ROOM, id, author_tag: tag });
    return { id, room_id: ROOM, author_tag: tag, text: world.messageCrypto.encryptRoomText(plain, aad), created_at: createdAt };
}

function owners(world) {
    return {
        all: world.retag.ownerIndex(world.deps.authorTags, ROOM, USERS, NOW),
        current: world.retag.ownerIndex(world.deps.currentKeyTags, ROOM, USERS, NOW),
    };
}

async function main() {
    await test('строка под старым ключом: новый тег по тому же created_at, шифрование под K_enc3 нового ключа с новым тегом в AAD', async () => {
        const before = loadWorld(KEY_A);
        const row = makeRow(before, { id: 1000001, user: 11, plain: 'конверт-один' });
        const after = loadWorld(KEY_B, [KEY_A]);
        const decision = after.retag.retagRow(row, owners(after), after.deps);
        assert.strictEqual(decision.status, 'retag');
        assert.ok(decision.author_tag.equals(after.deps.authorTags.tagFor(ROOM, 11, CREATED)), 'тег - от нового ключа, владельца и недели created_at');
        assert.ok(!decision.author_tag.equals(row.author_tag));
        assert.strictEqual(after.retag.recordKid(decision.text), after.deps.currentKid);
        const aad = after.messageCrypto.messageAadV3({ room_id: ROOM, id: 1000001, author_tag: decision.author_tag });
        assert.strictEqual(after.messageCrypto.decryptRoomText(decision.text, aad), 'конверт-один');
        // Со старым тегом в AAD новая запись не читается (тег входит в AAD).
        const oldAad = after.messageCrypto.messageAadV3({ room_id: ROOM, id: 1000001, author_tag: row.author_tag });
        assert.strictEqual(quiet(() => after.messageCrypto.decryptRoomText(decision.text, oldAad)), after.deps.crypto.DECRYPT_FAILED);
        // Результат стабилен: перетегированная строка дальше считается готовой.
        const done = { ...row, author_tag: decision.author_tag, text: decision.text };
        assert.deepStrictEqual(after.retag.retagRow(done, owners(after), after.deps), { status: 'current' });
    });

    await test('владелец тега находится среди участников и вышедших; разные авторы и недели - свои теги', async () => {
        const before = loadWorld(KEY_A);
        const after = loadWorld(KEY_B, [KEY_A]);
        const older = new Date('2026-09-25T08:00:00Z');
        const rows = [
            makeRow(before, { id: 1000011, user: 11, plain: 'a', createdAt: older }),
            makeRow(before, { id: 1000012, user: 12, plain: 'b' }),
            makeRow(before, { id: 1000013, user: 12, plain: 'c', createdAt: older }),
        ];
        for (const [i, row] of rows.entries()) {
            const decision = after.retag.retagRow(row, owners(after), after.deps);
            assert.strictEqual(decision.status, 'retag', String(i));
            const owner = [11, 12, 12][i];
            assert.ok(decision.author_tag.equals(after.deps.authorTags.tagFor(ROOM, owner, row.created_at)), `владелец ${owner}`);
        }
    });

    await test('правка, записанная новым ключом со старым тегом (до перетегирования): kid новый, тег старый - тоже переписывается', async () => {
        const before = loadWorld(KEY_A);
        const after = loadWorld(KEY_B, [KEY_A]);
        const oldTag = before.deps.authorTags.tagFor(ROOM, 11, CREATED);
        const aad = after.messageCrypto.messageAadV3({ room_id: ROOM, id: 1000021, author_tag: oldTag });
        const row = { id: 1000021, room_id: ROOM, author_tag: oldTag, created_at: CREATED, text: after.messageCrypto.encryptRoomText('правка', aad) };
        assert.strictEqual(after.retag.recordKid(row.text), after.deps.currentKid);
        const decision = after.retag.retagRow(row, owners(after), after.deps);
        assert.strictEqual(decision.status, 'retag');
        assert.ok(decision.author_tag.equals(after.deps.authorTags.tagFor(ROOM, 11, CREATED)));
    });

    await test('нельзя починить - не трогаем и сообщаем: чужой тег, испорченный шифротекст, не enc:v3, неизвестный kid', async () => {
        const before = loadWorld(KEY_A);
        const after = loadWorld(KEY_B, [KEY_A]);
        const stranger = makeRow(before, { id: 1000031, user: 99, plain: 'владелец удалён или ключ утерян' });
        assert.deepStrictEqual(after.retag.retagRow(stranger, owners(after), after.deps), { status: 'orphan' });
        const good = makeRow(before, { id: 1000032, user: 11, plain: 'x' });
        const parts = good.text.split(':');
        parts[5] = Buffer.from(parts[5], 'base64').fill(1).toString('base64');
        const broken = { ...good, text: parts.join(':') };
        assert.deepStrictEqual(quiet(() => after.retag.retagRow(broken, owners(after), after.deps)), { status: 'undecryptable' });
        assert.deepStrictEqual(after.retag.retagRow({ ...good, text: 'открытый текст' }, owners(after), after.deps), { status: 'foreign', reason: 'not-v3' });
        assert.deepStrictEqual(after.retag.retagRow({ ...good, text: 'enc:v2:deadbeef:a:b:c' }, owners(after), after.deps), { status: 'foreign', reason: 'not-v3' });
        const unknownKid = good.text.replace(/^enc:v3:[0-9a-f]{8}:/, 'enc:v3:deadbeef:');
        assert.deepStrictEqual(after.retag.retagRow({ ...good, text: unknownKid }, owners(after), after.deps), { status: 'foreign', reason: 'unknown-kid' });
        // Без …_PREVIOUS старая строка - неизвестный kid: поэтому ключ нельзя убирать до перетегирования.
        const lost = loadWorld(KEY_B);
        assert.deepStrictEqual(lost.retag.retagRow(good, owners(lost), lost.deps), { status: 'foreign', reason: 'unknown-kid' });
    });

    await test('цикл по пачкам на фейковом пуле: все комнаты и пачки, dry-run ничего не пишет, повторный прогон ничего не находит', async () => {
        const before = loadWorld(KEY_A);
        const after = loadWorld(KEY_B, [KEY_A]);
        const rows = [];
        for (let i = 0; i < 7; i++) rows.push(makeRow(before, { id: 1000100 + i, user: i % 2 ? 12 : 11, plain: 'сообщение ' + i }));
        rows.push(makeRow(before, { id: 1000200, user: 55, plain: 'чужой' })); // владелец не найден
        const updates = [];
        const makePool = (data) => ({
            async query(sql) {
                if (/FROM rooms/.test(sql)) return { rows: [{ id: ROOM }] };
                if (/FROM users u/.test(sql)) return { rows: USERS };
                throw new Error('неожиданный запрос ' + sql);
            },
            async connect() {
                return {
                    async query(sql, params) {
                        if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)) return { rows: [] };
                        if (/FOR NO KEY UPDATE/.test(sql)) {
                            const [, lastId, limit] = params;
                            return { rows: data.filter(r => r.id > lastId).sort((a, b) => a.id - b.id).slice(0, limit) };
                        }
                        if (/^UPDATE messages SET author_tag/.test(sql)) {
                            const [tag, text, id] = params;
                            updates.push(id);
                            Object.assign(data.find(r => r.id === id), { author_tag: tag, text });
                            return { rowCount: 1 };
                        }
                        throw new Error('неожиданный запрос ' + sql);
                    },
                    release() {},
                };
            },
        });
        const dry = JSON.parse(JSON.stringify(rows.map(r => r.id)));
        const data = rows.map(r => ({ ...r }));
        let totals = await after.retag.retagDatabase(makePool(data), after.deps, { batchSize: 3, dryRun: true });
        assert.deepStrictEqual({ scanned: totals.scanned, retagged: totals.retagged, orphan: totals.orphan }, { scanned: 8, retagged: 7, orphan: 1 });
        assert.deepStrictEqual(updates, [], 'dry-run ничего не записал');
        assert.deepStrictEqual(data.map(r => r.id), dry);
        totals = await after.retag.retagDatabase(makePool(data), after.deps, { batchSize: 3 });
        assert.strictEqual(totals.retagged, 7);
        assert.deepStrictEqual(totals.problems, [{ roomId: ROOM, id: 1000200, status: 'orphan', reason: undefined }]);
        assert.deepStrictEqual(updates.slice().sort(), rows.slice(0, 7).map(r => r.id).sort(), 'переписаны ровно починяемые строки');
        // Результат читается новым ключом, а строка без владельца не изменилась.
        for (const row of data.slice(0, 7)) {
            const aad = after.messageCrypto.messageAadV3({ room_id: ROOM, id: row.id, author_tag: row.author_tag });
            assert.match(after.messageCrypto.decryptRoomText(row.text, aad), /^сообщение \d$/);
            assert.strictEqual(after.retag.recordKid(row.text), after.deps.currentKid);
        }
        assert.strictEqual(data[7].text, rows[7].text);
        // Идемпотентность: второй прогон не находит работы (кроме того же сироту).
        updates.length = 0;
        totals = await after.retag.retagDatabase(makePool(data), after.deps, { batchSize: 3 });
        assert.strictEqual(totals.retagged, 0);
        assert.strictEqual(totals.current, 7);
        assert.deepStrictEqual(updates, []);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
