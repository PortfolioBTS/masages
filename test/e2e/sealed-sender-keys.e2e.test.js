'use strict';
// Sealed sender на хранении, вторая часть (docs/security/sealed-sender.md, разделы 13 и 14.1):
//  * квота вложений в таблице upload_quota под псевдонимом qkey: окно 30 суток, 413, откат при
//    повторах, удаление сообщения квоту не возвращает, суточная уборка, чат с ботом;
//  * смена MESSAGE_ENCRYPTION_KEY с …_PREVIOUS: старые сообщения читаются, правятся и удаляются;
//    scripts/retag-messages.js переводит строки под новый ключ (kid и тег), --verify, коды выхода;
//    после удаления прежнего ключа из списка всё продолжает работать; удаление аккаунта чистит окна
//    квоты под прежним и новым qkey.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');
const { REPO_ROOT } = require('./helpers/env');
const { createAuthorTags, computeQkey, deriveQuotaKey } = require('../../lib/author-tag');

const QUOTA_BYTES = Math.floor(0.002 * 1024 * 1024);   // 2097 байт
const suite = createSuite('sealed-sender-keys', { env: { UPLOAD_QUOTA_MB: '0.002' } });

// Текущий MESSAGE_ENCRYPTION_KEY сервера набора (меняется restartWithKeys).
let currentKey = suite.secrets.MESSAGE_ENCRYPTION_KEY;
const keyOf = (b64) => Buffer.from(b64, 'base64');
const qkeyFor = (userId, ikm = keyOf(currentKey)) => computeQkey(deriveQuotaKey(ikm), userId);
const quotaRow = async (userId, ikm) => (await suite.query('SELECT window_start, bytes::int AS bytes FROM upload_quota WHERE qkey = $1', [qkeyFor(userId, ikm)])).rows[0] || null;
const cipher = (n) => crypto.randomBytes(n);

async function pair(name = 'Квота') {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    return { owner, member, ...(await roomWithMember(owner, member, { name })) };
}

// ---------- квота вложений ----------

test('квота: строка под qkey = HMAC(K_quota, user_id), накапливается в окне; сверх квоты - 413 без строки сообщения и без изменения квоты; удаление сообщения квоту не возвращает', async () => {
    const p = await pair();
    assert.strictEqual(await quotaRow(p.owner.user.id), null, 'до первой загрузки строки нет');
    const first = await p.owner.uploadCipher(p.ownerChat.id, { bytes: cipher(1000), label: 'один' });
    const row1 = await quotaRow(p.owner.user.id);
    assert.strictEqual(row1.bytes, 1000);
    const today = (await suite.query('SELECT current_date AS d')).rows[0].d;
    assert.strictEqual(new Date(row1.window_start).toDateString(), new Date(today).toDateString(), 'окно началось сегодня');
    await p.owner.uploadCipher(p.ownerChat.id, { bytes: cipher(1000), label: 'два' });
    assert.strictEqual((await quotaRow(p.owner.user.id)).bytes, 2000);

    const messagesBefore = Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1', [p.roomId])).rows[0].n);
    const filesBefore = fs.readdirSync(suite.server.uploadsDir).length;
    const over = await p.owner.uploadCipherRaw(p.ownerChat.id, { bytes: cipher(1000), label: 'три' });
    assert.strictEqual(over.status, 413, over.text);
    assert.deepStrictEqual(over.body, { success: false, message: 'Превышена квота хранилища вложений' });
    assert.strictEqual((await quotaRow(p.owner.user.id)).bytes, 2000, 'квота не изменилась');
    assert.strictEqual(Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1', [p.roomId])).rows[0].n), messagesBefore, 'строки сообщения нет');
    await waitUntil(() => fs.readdirSync(suite.server.uploadsDir).length === filesBefore, { what: 'отклонённый файл убран с диска' });

    // Удаление сообщения квоту не возвращает (окно считает загрузки, а не хранимое).
    assert.strictEqual((await p.owner.del(`/api/messages/${first.id}`)).body.success, true);
    assert.strictEqual((await quotaRow(p.owner.user.id)).bytes, 2000);
    assert.strictEqual((await p.owner.uploadCipherRaw(p.ownerChat.id, { bytes: cipher(1000), label: 'после удаления' })).status, 413);
});

test('квота: одиночный файл больше квоты - 413 без записи строки; у участника комнаты своя квота (псевдоним зависит от пользователя)', async () => {
    const p = await pair();
    const big = await p.owner.uploadCipherRaw(p.ownerChat.id, { bytes: cipher(QUOTA_BYTES + 1), label: 'огромный' });
    assert.strictEqual(big.status, 413);
    assert.strictEqual(await quotaRow(p.owner.user.id), null, 'строка квоты не создана');
    await p.member.uploadCipher(p.memberChat.id, { bytes: cipher(1500), label: 'участник' });
    assert.strictEqual((await quotaRow(p.member.user.id)).bytes, 1500);
    assert.strictEqual(await quotaRow(p.owner.user.id), null, 'у владельца квота не тронута');
    assert.notDeepStrictEqual(qkeyFor(p.owner.user.id), qkeyFor(p.member.user.id));
});

test('квота: окно 30 суток - старше 30 суток начинается заново; чат с ботом тратит ту же квоту', async () => {
    const p = await pair();
    await p.owner.uploadCipher(p.ownerChat.id, { bytes: cipher(1800), label: 'почти вся' });
    assert.strictEqual((await p.owner.uploadCipherRaw(p.ownerChat.id, { bytes: cipher(500), label: 'не влезет' })).status, 413);
    const bot = await p.owner.botChat();
    const botFile = await p.owner.uploadRaw(bot.id, Buffer.from('текст для бота\n'.repeat(30), 'utf8'), 'text/plain', { filename: 'a.txt' });
    assert.strictEqual(botFile.status, 413, 'файл бота - тоже из этой квоты: ' + botFile.text);
    // Окно сдвигается в прошлое больше чем на 30 суток: следующая загрузка открывает новое.
    await suite.query('UPDATE upload_quota SET window_start = current_date - 31 WHERE qkey = $1', [qkeyFor(p.owner.user.id)]);
    await p.owner.uploadCipher(p.ownerChat.id, { bytes: cipher(500), label: 'новое окно' });
    const row = await quotaRow(p.owner.user.id);
    assert.strictEqual(row.bytes, 500, 'окно началось заново, а не продолжилось');
    const botOk = await p.owner.upload(bot.id, Buffer.from('текст для бота\n', 'utf8'), 'text/plain', { filename: 'b.txt' });
    assert.ok(botOk.file_url);
    assert.ok((await quotaRow(p.owner.user.id)).bytes > 500, 'файл бота прибавился к тому же окну');
});

test('квота: одинаковые запросы одновременно - одна строка и один файл, квота расходуется один раз (откат повторов возвращает её)', async () => {
    const p = await pair();
    const { newClientMessageId } = require('./helpers/client');
    const id = newClientMessageId();
    const bytes = cipher(1000);
    const filesBefore = fs.readdirSync(suite.server.uploadsDir).length;
    const results = await Promise.all(Array.from({ length: 4 }, () => p.owner.uploadCipherRaw(p.ownerChat.id, { bytes, label: 'одно и то же', clientMessageId: id })));
    for (const res of results) assert.ok([200, 409].includes(res.status), `ответ ${res.status}: ${res.text}`);
    assert.ok(results.some(r => r.status === 200));
    assert.strictEqual(Number((await suite.query('SELECT count(*) AS n FROM messages WHERE id = $1', [id])).rows[0].n), 1);
    assert.strictEqual((await quotaRow(p.owner.user.id)).bytes, 1000, 'квота учтена один раз');
    await waitUntil(() => fs.readdirSync(suite.server.uploadsDir).length === filesBefore + 1, { what: 'на диске ровно один файл' });
});

test('квота: суточная задача убирает окна старше 30 суток и не трогает свежие; удаление аккаунта убирает строку', async () => {
    const p = await pair();
    await p.owner.uploadCipher(p.ownerChat.id, { bytes: cipher(300), label: 'свежее' });
    const stale = crypto.randomBytes(16);
    await suite.query(`INSERT INTO upload_quota (qkey, window_start, bytes) VALUES ($1, current_date - 31, 10)`, [stale]);
    const staleBoundary = crypto.randomBytes(16);
    await suite.query(`INSERT INTO upload_quota (qkey, window_start, bytes) VALUES ($1, current_date - 29, 10)`, [staleBoundary]);
    await waitUntil(async () => (await suite.query('SELECT 1 FROM upload_quota WHERE qkey = $1', [stale])).rows.length === 0, { what: 'просроченное окно убрано задачей' });
    assert.strictEqual((await suite.query('SELECT 1 FROM upload_quota WHERE qkey = $1', [staleBoundary])).rows.length, 1, 'окно 29 суток цело');
    assert.ok(await quotaRow(p.owner.user.id), 'свежее окно цело');
    await p.owner.deleteAccount();
    assert.strictEqual(await quotaRow(p.owner.user.id), null, 'удаление аккаунта убрало строку квоты');
});

// ---------- смена MESSAGE_ENCRYPTION_KEY ----------

// Скрипт - отдельный процесс, как у оператора: свои переменные окружения, без .env разработчика.
const retagScript = (env, args = []) => {
    const run = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'retag-messages.js'), ...args], {
        cwd: suite.server.workDir,
        env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, NODE_ENV: 'test', DATABASE_URL: suite.databaseUrl, ...env },
        encoding: 'utf8',
    });
    return { code: run.status, out: `${run.stdout}${run.stderr}` };
};
const kidOf = (b64) => crypto.createHash('sha256').update(keyOf(b64)).digest('hex').slice(0, 8);

// Перезапуск сервера набора с другими ключами (шаги 2 и 7 процедуры).
async function restartWithKeys(current, previous) {
    await suite.server.restart({ env: { MESSAGE_ENCRYPTION_KEY: current, MESSAGE_ENCRYPTION_KEY_PREVIOUS: previous } });
    currentKey = current;
}

test('смена ключа: с …_PREVIOUS старые сообщения читаются, правятся и удаляются; retag-messages переводит строки под новый ключ (kid и тег); без …_PREVIOUS всё продолжает работать', async () => {
    const keyA = currentKey;
    const keyB = crypto.randomBytes(32).toString('base64');
    const p = await pair('Смена ключа');
    const ghost = suite.client();
    await ghost.registerAnon();
    const ghostPending = await ghost.join(p.code);
    await p.owner.approve(ghostPending.requestId);
    const ghostChat = (await ghost.chats()).find(c => c.room_id === p.roomId);

    const a1 = await p.owner.send(p.ownerChat.id, 'владелец один');
    const a2 = await p.owner.send(p.ownerChat.id, 'владелец два');
    const a3 = await p.owner.send(p.ownerChat.id, 'владелец три');
    const b1 = await p.member.send(p.memberChat.id, 'участник один');
    const b2 = await p.member.send(p.memberChat.id, 'участник два');
    await p.owner.uploadCipher(p.ownerChat.id, { bytes: cipher(500), label: 'файл владельца' });
    await ghost.uploadCipher(ghostChat.id, { bytes: cipher(400), label: 'файл призрака до смены' });
    assert.ok(await quotaRow(ghost.user.id, keyOf(keyA)), 'окно квоты под qkey прежнего ключа');

    // Шаг 2 процедуры: оба ключа, перезапуск.
    await restartWithKeys(keyB, keyA);
    const textOf = async (client, chatId, id) => (await client.messages(chatId)).messages.find(m => m.id === id).text;
    assert.strictEqual(await textOf(p.member, p.memberChat.id, a1.id), fakeEnvelope('владелец один'), 'старая строка читается через …_PREVIOUS');
    // Правка и удаление старых сообщений: теги проверяются по всем ключам.
    assert.strictEqual((await p.owner.editRaw(a2.id, 'владелец два, правка')).body.success, true);
    assert.strictEqual((await p.member.del(`/api/messages/${b2.id}`)).body.success, true);
    assert.strictEqual((await p.member.editRaw(a1.id, 'чужая правка')).body.success, false, 'чужое по-прежнему не правится');
    const fresh = await p.member.send(p.memberChat.id, 'участник после смены');
    assert.strictEqual(await textOf(p.owner, p.ownerChat.id, a2.id), fakeEnvelope('владелец два, правка'));
    await ghost.uploadCipher(ghostChat.id, { bytes: cipher(400), label: 'файл призрака после смены' });
    assert.ok(await quotaRow(ghost.user.id, keyOf(keyB)), 'после смены окно под qkey нового ключа');

    // Состояние до перетегирования: строки на разных kid.
    const kids = async () => (await suite.query(`SELECT substr(text, 8, 8) AS kid, count(*)::int AS n FROM messages WHERE room_id = $1 GROUP BY 1 ORDER BY 1`, [p.roomId])).rows;
    const before = await kids();
    assert.ok(before.some(r => r.kid === kidOf(keyA)), 'есть строки под прежним kid');
    assert.ok(before.some(r => r.kid === kidOf(keyB)), 'и под новым (правка, новое сообщение)');

    // Проверка до перетегирования не проходит (код 2), пробный прогон ничего не пишет.
    const env = { MESSAGE_ENCRYPTION_KEY: keyB, MESSAGE_ENCRYPTION_KEY_PREVIOUS: keyA };
    assert.strictEqual(retagScript(env, ['--verify']).code, 2);
    const dry = retagScript(env, ['--dry-run']);
    assert.strictEqual(dry.code, 0, dry.out);
    assert.match(dry.out, /Пробный прогон/);
    assert.deepStrictEqual(await kids(), before, 'пробный прогон ничего не записал');
    assert.ok(!dry.out.includes(String(a1.id)), 'id сообщений в отчёт не попадают');

    // Перетегирование: все строки под новый ключ, теги - теги нового ключа.
    const run = retagScript(env);
    assert.strictEqual(run.code, 0, run.out);
    assert.match(run.out, /Готово/);
    assert.deepStrictEqual(await kids(), [{ kid: kidOf(keyB), n: before.reduce((sum, r) => sum + r.n, 0) }], 'все строки комнаты под новым kid');
    const newTags = createAuthorTags([keyOf(keyB)]);
    const people = [p.owner, p.member, ghost];
    for (const row of (await suite.query('SELECT id, author_tag, created_at FROM messages WHERE room_id = $1', [p.roomId])).rows) {
        assert.ok(people.some(person => row.author_tag.equals(newTags.tagFor(p.roomId, person.user.id, row.created_at))),
            `тег строки ${row.id} - тег одного из участников под новым ключом`);
    }
    const again = retagScript(env);
    assert.strictEqual(again.code, 0, 'повторный запуск идемпотентен');
    assert.match(again.out, /переписано 0/);
    const verify = retagScript(env, ['--verify']);
    assert.strictEqual(verify.code, 0, verify.out);
    assert.match(verify.out, /Проверка пройдена/);

    // Удаление аккаунта при действующем …_PREVIOUS: окна квоты и под старым, и под новым qkey.
    await ghost.deleteAccount();
    assert.strictEqual(await quotaRow(ghost.user.id, keyOf(keyA)), null, 'окно под qkey прежнего ключа удалено');
    assert.strictEqual(await quotaRow(ghost.user.id, keyOf(keyB)), null, 'окно под qkey нового ключа удалено');

    // Прежний ключ убран из …_PREVIOUS - всё работает на новом.
    await restartWithKeys(keyB, null);
    assert.strictEqual(await textOf(p.member, p.memberChat.id, a1.id), fakeEnvelope('владелец один'), 'старые сообщения читаются без …_PREVIOUS');
    assert.strictEqual(await textOf(p.member, p.memberChat.id, a2.id), fakeEnvelope('владелец два, правка'));
    assert.strictEqual((await p.owner.editRaw(a3.id, 'правка без прежнего ключа')).body.success, true, 'правка работает');
    assert.strictEqual(await textOf(p.member, p.memberChat.id, a3.id), fakeEnvelope('правка без прежнего ключа'));
    assert.strictEqual((await p.member.editRaw(fresh.id, 'и свою')).body.success, true);
    assert.strictEqual((await p.owner.del(`/api/messages/${a1.id}`)).body.success, true, 'удаление по тегу работает');
    assert.strictEqual((await p.member.del(`/api/messages/${b1.id}`)).body.success, true);
    assert.strictEqual(retagScript({ MESSAGE_ENCRYPTION_KEY: keyB }, ['--verify']).code, 0);

    // Выход с удалением сообщений находит строки по тегам нового ключа.
    const memberCreated = (await suite.query('SELECT created_at FROM users WHERE id = $1', [p.member.user.id])).rows[0].created_at;
    const memberTags = newTags.tagsForAccount(p.roomId, p.member.user.id, memberCreated, Date.now());
    const memberRows = async () => Number((await suite.query('SELECT count(*) AS n FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[])', [p.roomId, memberTags])).rows[0].n);
    assert.ok(await memberRows() >= 1);
    await p.member.leave(p.memberChat.id, { deleteMessages: true });
    assert.strictEqual(await memberRows(), 0);
});

test('retag-messages: строки, которые починить нельзя, не меняются и дают код выхода 2; --verify не проходит, пока они есть; id печатаются только с --verbose', async () => {
    const p = await pair('Битые строки');
    const good = await p.owner.send(p.ownerChat.id, 'нормальное');
    const junk = await p.owner.send(p.ownerChat.id, 'будет испорчено');
    await suite.query(`UPDATE messages SET text = 'открытый текст в комнате' WHERE id = $1`, [junk.id]);
    const env = { MESSAGE_ENCRYPTION_KEY: currentKey };
    const run = retagScript(env);
    assert.strictEqual(run.code, 2, run.out);
    assert.match(run.out, /не под enc:v3 текущей схемы 1/);
    assert.ok(!run.out.includes(String(junk.id)), 'без --verbose id не печатаются');
    const verbose = retagScript(env, ['--verbose']);
    assert.ok(verbose.out.includes(String(junk.id)), 'с --verbose id проблемной строки печатается');
    assert.ok(!verbose.out.includes(String(good.id)), 'исправные строки не перечисляются');
    assert.strictEqual((await suite.query('SELECT text FROM messages WHERE id = $1', [junk.id])).rows[0].text, 'открытый текст в комнате', 'строка не изменена');
    const verify = retagScript(env, ['--verify']);
    assert.strictEqual(verify.code, 2);
    assert.match(verify.out, /НЕ пройдена/);
    await suite.query('DELETE FROM messages WHERE id = $1', [junk.id]);
    assert.strictEqual(retagScript(env, ['--verify']).code, 0, 'после удаления испорченной строки проверка проходит');
});
