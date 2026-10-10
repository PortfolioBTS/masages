'use strict';
// Обязательное E2EE в комнатах (R7, план криптографии, раздел 3). Настоящий
// Postgres и настоящий сервер.
//
// * комната принимает только конверт senderkey-v2 правильной формы: открытый
//   текст, чужой формат, v1, лишний ключ и мусор — 400 { success:false, code,
//   message } (e2ee-required или bad-envelope), в базу и на диск ничего не попадает;
// * то же для вложений (POST /api/messages/file): открытый файл в комнате отвергается
//   ДО записи на диск;
// * правка (PUT /api/messages/:id) — тоже только новый конверт правильной формы;
//   правка открытого сообщения комнаты (в базе его быть не должно) — 400;
// * чат с ботом остаётся открытым: текст и файлы — ок, шифротекст — 400 e2ee-not-allowed.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const crypto = require('crypto');
const { createSuite, roomWithMember } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');
const samples = require('./helpers/samples');

const suite = createSuite('e2ee-required');

const REQUIRED_MESSAGE = 'Обновите страницу: в группах сообщения отправляются только со сквозным шифрованием';

const dirFiles = () => (fs.existsSync(suite.server.uploadsDir) ? fs.readdirSync(suite.server.uploadsDir).sort() : []);
const countRows = async (sql, params = []) => Number((await suite.query(sql, params)).rows[0].n);
const roomMessages = (roomId) => countRows('SELECT count(*) AS n FROM messages WHERE room_id = $1', [roomId]);

async function pair() {
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();
    return { owner, member, ...await roomWithMember(owner, member, { name: 'Шифрование' }) };
}

function envelopeWith(overrides) {
    const parsed = { ...JSON.parse(fakeEnvelope('образец')), ...overrides };
    for (const key of Object.keys(parsed)) if (parsed[key] === undefined) delete parsed[key];
    return JSON.stringify(parsed);
}

// ---------- текст ----------

test('открытый текст в комнате — 400 e2ee-required, в базу ничего не попадает', async () => {
    const p = await pair();
    const before = await roomMessages(p.roomId);
    const plain = await p.owner.sendRaw(p.ownerChat.id, 'привет всем', { raw: true });
    assert.strictEqual(plain.status, 400);
    assert.deepStrictEqual(plain.body, { success: false, code: 'e2ee-required', message: REQUIRED_MESSAGE });
    // Флаг encrypted не булево true — такой же отказ, а не «почти шифрование».
    for (const flag of ['true', 1, 'yes', null]) {
        const res = await p.owner.sendRaw(p.ownerChat.id, 'привет всем', { raw: true, encrypted: flag });
        assert.strictEqual(res.status, 400, JSON.stringify(flag));
        assert.strictEqual(res.body.code, 'e2ee-required', JSON.stringify(flag));
    }
    // encrypted: false — то же самое.
    const explicit = await p.owner.sendRaw(p.ownerChat.id, 'привет всем', { raw: true, encrypted: false });
    assert.strictEqual(explicit.status, 400);
    assert.strictEqual(explicit.body.code, 'e2ee-required');
    assert.strictEqual(await roomMessages(p.roomId), before);
});

test('конверт неправильной формы — 400 bad-envelope: не JSON, v1, лишний ключ, короткие поля, открытый текст под видом шифротекста', async () => {
    const p = await pair();
    const before = await roomMessages(p.roomId);
    const parsed = JSON.parse(fakeEnvelope('образец'));
    const cases = [
        ['обычный текст с encrypted: true', 'привет всем'],
        ['оборванный JSON', '{"v":2,'],
        ['JSON-массив', '[]'],
        ['v1 (новые сообщения только v2)', JSON.stringify({ alg: 'senderkey-v1', senderKeyId: parsed.senderKeyId, iteration: 0, iv: parsed.iv, ct: parsed.ct, sig: parsed.sig })],
        ['v: 1 с алгоритмом v2', envelopeWith({ v: 1 })],
        ['чужой алгоритм', envelopeWith({ alg: 'aes-gcm' })],
        ['лишний ключ с открытым текстом', envelopeWith({ text: 'привет всем' })],
        ['нет подписи', envelopeWith({ sig: undefined })],
        ['короткая подпись', envelopeWith({ sig: Buffer.alloc(63, 1).toString('base64') })],
        ['короткий iv', envelopeWith({ iv: Buffer.alloc(11, 1).toString('base64') })],
        ['короткий идентификатор ключа', envelopeWith({ senderKeyId: Buffer.alloc(15, 1).toString('base64') })],
        ['ct короче 272 байт', envelopeWith({ ct: Buffer.alloc(271, 1).toString('base64') })],
        ['ct — не base64', envelopeWith({ ct: 'привет всем '.repeat(40) })],
        ['итерация отрицательная', envelopeWith({ iteration: -1 })],
        ['итерация дробная', envelopeWith({ iteration: 1.5 })],
        ['итерация строкой', envelopeWith({ iteration: '3' })],
    ];
    for (const [what, text] of cases) {
        const res = await p.owner.sendRaw(p.ownerChat.id, text, { raw: true, encrypted: true });
        assert.strictEqual(res.status, 400, `${what}: ${res.text}`);
        assert.strictEqual(res.body.success, false, what);
        assert.strictEqual(res.body.code, 'bad-envelope', what);
        assert.match(res.body.message, /^Обновите страницу/, what);
    }
    // Длиннее 12000 символов отсекает проверка длины запроса раньше разбора конверта (прежний ответ 200 с success:false).
    const long = await p.owner.sendRaw(p.ownerChat.id, envelopeWith({ ct: crypto.randomBytes(9300).toString('base64') }), { raw: true, encrypted: true });
    assert.strictEqual(long.body.success, false);
    assert.match(long.body.message, /не может быть длиннее 12000/);
    assert.strictEqual(await roomMessages(p.roomId), before, 'ничего из отказанного не записалось');
});

test('конверт правильной формы принимается и возвращается участникам без изменений', async (t) => {
    const p = await pair();
    const sock = await p.member.socket();
    t.after(() => sock.close());
    const envelope = fakeEnvelope('настоящее сообщение');
    const sent = await p.owner.send(p.ownerChat.id, 'настоящее сообщение');
    assert.strictEqual(sent.text, envelope);
    assert.strictEqual(sent.encrypted, true);
    const delivered = await sock.waitFor('newMessage', m => m.id === sent.id);
    assert.strictEqual(delivered.text, envelope, 'сервер доставил конверт байт-в-байт');
    const stored = (await p.member.messages(p.memberChat.id)).messages.find(m => m.id === sent.id);
    assert.strictEqual(stored.text, envelope);
    assert.strictEqual(stored.encrypted, true);
    // Пробелы вокруг конверта срезаются (как у любого текста), содержимое не меняется.
    const padded = await p.owner.sendRaw(p.ownerChat.id, `  ${fakeEnvelope('с пробелами')}\n`, { raw: true, encrypted: true });
    assert.strictEqual(padded.status, 200, padded.text);
    assert.strictEqual(padded.body.message.text, fakeEnvelope('с пробелами'));
});

test('старая вкладка без clientMessageId получает client-outdated: «Обновите страницу» и в этом случае', async () => {
    const p = await pair();
    const res = await p.owner.sendRaw(p.ownerChat.id, 'привет всем', { raw: true, clientMessageId: undefined });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.code, 'client-outdated');
    assert.match(res.body.message, /^Обновите страницу/);
});

// ---------- вложения ----------

test('открытое вложение в комнате — 400 e2ee-required, файл на диск не пишется', async () => {
    const p = await pair();
    const png = await require('sharp')({ create: { width: 8, height: 8, channels: 3, background: { r: 1, g: 2, b: 3 } } }).png().toBuffer();
    const before = dirFiles();
    const rows = await countRows('SELECT count(*) AS n FROM messages WHERE room_id = $1 AND file_url IS NOT NULL', [p.roomId]);
    const plain = await p.owner.uploadRaw(p.ownerChat.id, png, 'image/png', { filename: 'photo.png' });
    assert.strictEqual(plain.status, 400, plain.text);
    assert.deepStrictEqual(plain.body, { success: false, code: 'e2ee-required', message: REQUIRED_MESSAGE });
    // Открытый PDF и текст — то же.
    for (const [bytes, mime, filename] of [[Buffer.from('текст\n', 'utf8'), 'text/plain', 'a.txt'], [samples.makePdf(), 'application/pdf', 'a.pdf']]) {
        const res = await p.owner.uploadRaw(p.ownerChat.id, bytes, mime, { filename });
        assert.strictEqual(res.status, 400, mime);
        assert.strictEqual(res.body.code, 'e2ee-required', mime);
    }
    // Шифротекст, но без флага encrypted — отказ по типу, как и раньше.
    const octet = await p.owner.uploadRaw(p.ownerChat.id, crypto.randomBytes(300), 'application/octet-stream', { filename: 'x.bin' });
    assert.strictEqual(octet.status, 400);
    assert.strictEqual(octet.body.success, false);
    assert.deepStrictEqual(dirFiles(), before, 'ничего не осталось на диске');
    assert.strictEqual(await countRows('SELECT count(*) AS n FROM messages WHERE room_id = $1 AND file_url IS NOT NULL', [p.roomId]), rows);
});

test('вложение с конвертом неправильной формы — 400 bad-envelope до записи файла; правильное принимается', async () => {
    const p = await pair();
    const before = dirFiles();
    const bad = [
        ['без конверта', undefined],
        ['пустой конверт', ''],
        ['конверт «x»', 'x'],
        ['старая форма с короткими полями', '{"v":2,"alg":"senderkey-v2","senderKeyId":"k","iteration":0,"iv":"AA","ct":"AA","sig":"AA"}'],
        ['v1', JSON.stringify({ alg: 'senderkey-v1', senderKeyId: 'AAAAAAAAAAAAAAAAAAAAAA==', iteration: 0, iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA', sig: 'AAAA' })],
        ['лишний ключ', envelopeWith({ caption: 'открытая подпись' })],
    ];
    for (const [what, envelope] of bad) {
        const res = await p.owner.uploadCipherRaw(p.ownerChat.id, { envelope });
        assert.strictEqual(res.status, 400, `${what}: ${res.text}`);
        assert.strictEqual(res.body.code, 'bad-envelope', what);
        assert.strictEqual(res.body.success, false, what);
    }
    assert.deepStrictEqual(dirFiles(), before, 'отказанные загрузки не оставили файлов');
    const ok = await p.owner.uploadCipher(p.ownerChat.id, { label: 'фото' });
    assert.strictEqual(ok.text, fakeEnvelope('фото'));
    assert.strictEqual(ok.encrypted, true);
    assert.strictEqual(ok.file_name, null, 'имени файла сервер не хранит');
    assert.strictEqual(dirFiles().length, before.length + 1);
});

test('поля формы после файла: правила те же (проверка в обработчике), файл удаляется', async () => {
    const p = await pair();
    const before = dirFiles();
    const { newClientMessageId } = require('./helpers/client');
    // Все поля после файла: до приёма файла сервер не знает ни чата, ни флага.
    const plainLate = new FormData();
    plainLate.append('file', new Blob([Buffer.from('текст\n', 'utf8')], { type: 'text/plain' }), 'a.txt');
    plainLate.append('chatId', String(p.ownerChat.id));
    plainLate.append('clientMessageId', newClientMessageId());
    const res = await p.owner.request('POST', '/api/messages/file', { body: plainLate });
    assert.strictEqual(res.status, 400, res.text);
    assert.ok(['client-outdated', 'e2ee-required'].includes(res.body.code), JSON.stringify(res.body));
    // Флаг и id до файла, а чат и неправильный конверт — после него: файл уже принят, и
    // отказывает обработчик, который сам удаляет файл с диска.
    const form = new FormData();
    form.append('encrypted', 'true');
    form.append('clientMessageId', newClientMessageId());
    form.append('file', new Blob([crypto.randomBytes(300)], { type: 'application/octet-stream' }), 'file.bin');
    form.append('chatId', String(p.ownerChat.id));
    form.append('envelope', 'x');
    const late = await p.owner.request('POST', '/api/messages/file', { body: form });
    assert.strictEqual(late.status, 400, late.text);
    assert.strictEqual(late.body.code, 'bad-envelope');
    const deadline = Date.now() + 5000;
    while (JSON.stringify(dirFiles()) !== JSON.stringify(before) && Date.now() < deadline) await new Promise(r => setTimeout(r, 25));
    assert.deepStrictEqual(dirFiles(), before, 'принятый файл удалён с диска');
    // То же с открытым файлом: чат пришёл после файла, флага encrypted нет.
    const plain = new FormData();
    plain.append('clientMessageId', newClientMessageId());
    plain.append('file', new Blob([Buffer.from('текст\n', 'utf8')], { type: 'text/plain' }), 'a.txt');
    plain.append('chatId', String(p.ownerChat.id));
    const plainRes = await p.owner.request('POST', '/api/messages/file', { body: plain });
    assert.strictEqual(plainRes.status, 400, plainRes.text);
    assert.strictEqual(plainRes.body.code, 'e2ee-required');
    const deadline2 = Date.now() + 5000;
    while (JSON.stringify(dirFiles()) !== JSON.stringify(before) && Date.now() < deadline2) await new Promise(r => setTimeout(r, 25));
    assert.deepStrictEqual(dirFiles(), before, 'открытый файл тоже удалён');
});

// ---------- правка ----------

test('правка: новый конверт правильной формы принимается, открытый текст и мусор — 400; открытое сообщение комнаты не правится', async () => {
    const p = await pair();
    const sent = await p.owner.send(p.ownerChat.id, 'первая версия');
    const storedBefore = (await suite.query('SELECT text, edited_at FROM messages WHERE id = $1', [sent.id])).rows[0];

    const plain = await p.owner.put(`/api/messages/${sent.id}`, { text: 'открытая правка' });
    assert.strictEqual(plain.status, 400);
    assert.strictEqual(plain.body.code, 'bad-envelope');
    const junk = await p.owner.put(`/api/messages/${sent.id}`, { text: envelopeWith({ ct: 'AAAA' }) });
    assert.strictEqual(junk.status, 400);
    assert.strictEqual(junk.body.code, 'bad-envelope');
    const v1 = await p.owner.put(`/api/messages/${sent.id}`, { text: JSON.stringify({ alg: 'senderkey-v1', senderKeyId: 'a', iteration: 0, iv: 'a', ct: 'a', sig: 'a' }) });
    assert.strictEqual(v1.status, 400);
    assert.deepStrictEqual((await suite.query('SELECT text, edited_at FROM messages WHERE id = $1', [sent.id])).rows[0], storedBefore, 'отказанные правки ничего не изменили');

    const good = await p.owner.put(`/api/messages/${sent.id}`, { text: fakeEnvelope('вторая версия') });
    assert.strictEqual(good.status, 200);
    assert.strictEqual(good.body.success, true);
    assert.strictEqual(good.body.text, fakeEnvelope('вторая версия'));
    const history = (await p.member.messages(p.memberChat.id)).messages.find(m => m.id === sent.id);
    assert.strictEqual(history.text, fakeEnvelope('вторая версия'));

    // Открытое сообщение в комнате не ляжет в базу даже в обход маршрутов:
    // CHECK messages_room_e2ee (второй рубеж к проверкам маршрутов).
    await assert.rejects(
        suite.query(
            `INSERT INTO messages (id, chat_id, room_id, user_id, text, sent, status, encrypted)
             VALUES ($1, $2, $3, $4, $5, 1, 'sent', FALSE)`,
            ['7654321', p.ownerChat.id, p.roomId, p.owner.user.id, 'открытый текст']
        ),
        (err) => err.code === '23514' && err.constraint === 'messages_room_e2ee'
    );
});

// ---------- чат с ботом ----------

test('чат с ботом: открытый текст и файл — ок; шифротекст — 400 e2ee-not-allowed; правка открытого текста — ок', async () => {
    const client = suite.client();
    await client.registerAnon();
    const bot = await client.botChat();

    const sent = await client.send(bot.id, 'гайд');
    assert.strictEqual(sent.text, 'гайд');
    assert.strictEqual(sent.encrypted, false);

    // Сообщения пользователя (sent = 1): ответы бота приходят асинхронно и счёт сбили бы.
    const mine = () => countRows('SELECT count(*) AS n FROM messages WHERE chat_id = $1 AND sent = 1', [bot.id]);
    const before = await mine();
    const filesBefore = dirFiles();
    const encrypted = await client.sendRaw(bot.id, fakeEnvelope('секрет'), { raw: true, encrypted: true });
    assert.strictEqual(encrypted.status, 400);
    assert.strictEqual(encrypted.body.code, 'e2ee-not-allowed');
    assert.strictEqual(encrypted.body.success, false);
    assert.match(encrypted.body.message, /бот/i);
    // Шифротекст-вложение в чате с ботом: тоже отказ, файл на диск не пишется.
    const cipher = await client.uploadCipherRaw(bot.id, { label: 'секрет' });
    assert.strictEqual(cipher.status, 400, cipher.text);
    assert.strictEqual(cipher.body.code, 'e2ee-not-allowed');
    assert.strictEqual(await mine(), before);
    assert.deepStrictEqual(dirFiles(), filesBefore);

    const file = await client.upload(bot.id, Buffer.from('просто текстовый файл\n', 'utf8'), 'text/plain', { filename: 'a.txt' });
    assert.strictEqual(file.encrypted, false);
    const edit = await client.put(`/api/messages/${sent.id}`, { text: 'гайд ещё раз' });
    assert.strictEqual(edit.status, 200);
    assert.strictEqual(edit.body.success, true);
    assert.strictEqual(edit.body.text, 'гайд ещё раз');
});
