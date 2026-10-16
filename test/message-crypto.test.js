'use strict';
// Серверное шифрование строки комнаты: enc:v3 (docs/security/sealed-sender.md,
// раздел 7). Ключ K_enc3 = HKDF(ключ, "nyxo-msg-enc-v3"), AAD с комнатой, id и
// author_tag строки (без пользователя). Чат с ботом остаётся на enc:v2.
// Контрольный вектор документа проверяется дословно: шифрование с
// фиксированным nonce и расшифровка.
// Модуль читает ключи из окружения при загрузке: для смены ключей он
// загружается заново.
// Запуск: node test/message-crypto.test.js

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

// Глушит console.error на время fn и возвращает то, что туда писали.
function quiet(fn) {
    const saved = console.error;
    const logged = [];
    console.error = (...args) => logged.push(args.join(' '));
    try {
        return { result: fn(), logged };
    } finally {
        console.error = saved;
    }
}

const IKM = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const KEY_B = crypto.randomBytes(32);
const KEY_C = crypto.randomBytes(32);
const b64 = buf => buf.toString('base64');
const FAILED = '[Не удалось расшифровать]';
const TAG_A = Buffer.from('9b7e17d7b43443d552180143b92a140c', 'hex');
const TAG_B = Buffer.from('3de917f167c2f39aa146b22cc5b66485', 'hex');

function load(current, previous) {
    process.env.MESSAGE_ENCRYPTION_KEY = b64(current);
    if (previous) process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS = previous.map(b64).join(',');
    else delete process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS;
    delete require.cache[require.resolve('../lib/message-crypto.js')];
    return require('../lib/message-crypto.js');
}

// Запись с фиксированным nonce — так воспроизводится вектор документа.
function sealWithFixedNonce(enc3Key, kid, plain, aad, iv) {
    const cipher = crypto.createCipheriv('aes-256-gcm', enc3Key, iv, { authTagLength: 16 });
    cipher.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    return 'enc:v3:' + [kid, b64(iv), b64(cipher.getAuthTag()), b64(ct)].join(':');
}

const hkdf = (ikm, label) => Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), label, 32));
const kidOf = key => crypto.createHash('sha256').update(key).digest('hex').slice(0, 8);

async function main() {
    await test('messageAadV3: строка с комнатой, id и тегом (32 строчных hex), без пользователя', async () => {
        const { messageAadV3 } = load(IKM);
        const aad = messageAadV3({ room_id: 1234567, id: 1500000001, author_tag: TAG_A });
        assert.strictEqual(aad, 'nyxo:msg:v3:room=1234567:id=1500000001:tag=9b7e17d7b43443d552180143b92a140c');
        // Строки из req.params и числа из pg дают одно и то же; тег — Buffer или готовый hex.
        assert.strictEqual(messageAadV3({ room_id: '1234567', id: '1500000001', author_tag: '9b7e17d7b43443d552180143b92a140c' }), aad);
        // Лишние поля строки (user_id, chat_id) в AAD не попадают.
        assert.strictEqual(messageAadV3({ room_id: 1234567, id: 1500000001, author_tag: TAG_A, user_id: 7, chat_id: 9 }), aad);
        assert.throws(() => messageAadV3({ id: 5, author_tag: TAG_A }), TypeError);
        assert.throws(() => messageAadV3({ room_id: 5, author_tag: TAG_A }), TypeError);
        assert.throws(() => messageAadV3({ room_id: 5, id: 6 }), TypeError);
        assert.throws(() => messageAadV3({ room_id: 5, id: 6, author_tag: TAG_A.subarray(0, 15) }), TypeError);
        assert.throws(() => messageAadV3({ room_id: 5, id: 6, author_tag: '9B7E17D7B43443D552180143B92A140C' }), TypeError, 'верхний регистр — другой AAD');
        assert.throws(() => messageAadV3({ room_id: 5, id: 6, author_tag: 'xyz' }), TypeError);
        assert.throws(() => messageAadV3({ room_id: 0, id: 6, author_tag: TAG_A }), TypeError);
        assert.throws(() => messageAadV3(null), TypeError);
    });

    await test('вектор раздела 7: запись enc:v3 с фиксированным nonce совпадает дословно и расшифровывается', async () => {
        const { messageAadV3, decryptRoomText } = load(IKM);
        const aad = messageAadV3({ room_id: 1234567, id: 1500000001, author_tag: TAG_A });
        const kEnc3 = hkdf(IKM, 'nyxo-msg-enc-v3');
        assert.strictEqual(kEnc3.toString('hex'), '42852f99e3a8b7db0b0ef0b4df36b24f0ab0641b07e7c8ab6721a0cd6252d3fb');
        const iv = Buffer.from(Array.from({ length: 12 }, (_, i) => i));
        const record = sealWithFixedNonce(kEnc3, '630dcd29', 'hello', aad, iv);
        assert.strictEqual(record, 'enc:v3:630dcd29:AAECAwQFBgcICQoL:Ega3fBUjzPPsIzXp1qjw5g==:6v/gkIk=');
        assert.strictEqual(decryptRoomText(record, aad), 'hello');
        // Тот же текст с другим тегом или другой комнатой в AAD — отказ.
        const wrongTag = messageAadV3({ room_id: 1234567, id: 1500000001, author_tag: TAG_B });
        const wrongRoom = messageAadV3({ room_id: 1234568, id: 1500000001, author_tag: TAG_A });
        for (const other of [wrongTag, wrongRoom]) {
            const { result, logged } = quiet(() => decryptRoomText(record, other));
            assert.strictEqual(result, FAILED);
            assert.ok(logged.length > 0, 'отказ пишется в лог');
        }
    });

    await test('encryptRoomText: формат enc:v3:<kid>:<iv>:<tag>:<ct>, kid — по исходному ключу, nonce случайный', async () => {
        const { messageAadV3, encryptRoomText, decryptRoomText } = load(IKM);
        const aad = messageAadV3({ room_id: 5, id: 1000001, author_tag: TAG_A });
        for (const text of ['Привет, мир! 👋', '', 'a:b:c', 'x'.repeat(10000)]) {
            const stored = encryptRoomText(text, aad);
            const parts = stored.split(':');
            assert.strictEqual(parts.length, 6);
            assert.strictEqual(parts[0] + ':' + parts[1], 'enc:v3');
            assert.strictEqual(parts[2], '630dcd29');
            assert.strictEqual(Buffer.from(parts[3], 'base64').length, 12);
            assert.strictEqual(Buffer.from(parts[4], 'base64').length, 16);
            assert.strictEqual(decryptRoomText(stored, aad), text);
        }
        assert.notStrictEqual(encryptRoomText('same', aad), encryptRoomText('same', aad));
        assert.strictEqual(encryptRoomText(null, aad), null);
        assert.strictEqual(encryptRoomText(undefined, aad), undefined);
        assert.strictEqual(decryptRoomText(null, aad), null);
    });

    await test('enc:v3 расшифровывается только при том же (room, id, tag): перенос и подмена тега отвергаются', async () => {
        const { messageAadV3, encryptRoomText, decryptRoomText } = load(IKM);
        const original = { room_id: 5, id: 1000001, author_tag: TAG_A };
        const stored = encryptRoomText('только для этой строки', messageAadV3(original));
        const cases = [
            ['другая комната', messageAadV3({ ...original, room_id: 6 })],
            ['другой id внутри комнаты', messageAadV3({ ...original, id: 1000002 })],
            ['другой author_tag (подмена тега в строке)', messageAadV3({ ...original, author_tag: TAG_B })],
        ];
        for (const [label, aad] of cases) {
            const { result, logged } = quiet(() => decryptRoomText(stored, aad));
            assert.strictEqual(result, FAILED, label);
            assert.ok(logged.length > 0, label + ': отказ пишется в лог');
        }
        assert.strictEqual(decryptRoomText(stored, messageAadV3(original)), 'только для этой строки');
        // Повреждённые записи.
        const [p1, p2, kid, iv, tag, ct] = stored.split(':');
        const flipped = Buffer.from(ct, 'base64');
        flipped[0] ^= 1;
        const damaged = [
            [p1, p2, kid, iv, tag, b64(flipped)].join(':'),
            [p1, p2, kid, iv, b64(Buffer.from(tag, 'base64').subarray(0, 4)), ct].join(':'),
            [p1, p2, kid, iv, ct].join(':'),
            [p1, p2, 'deadbeef', iv, tag, ct].join(':'),
        ];
        for (const value of damaged) {
            assert.strictEqual(quiet(() => decryptRoomText(value, messageAadV3(original))).result, FAILED);
        }
    });

    await test('шифруется ключом K_enc3, а не сырым MESSAGE_ENCRYPTION_KEY: расшифровка сырым ключом отклоняется', async () => {
        const { messageAadV3, encryptRoomText } = load(IKM);
        const aad = messageAadV3({ room_id: 5, id: 1000001, author_tag: TAG_A });
        const [, , , iv, tag, ct] = encryptRoomText('секрет', aad).split(':');
        const decryptWith = (key) => {
            const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'), { authTagLength: 16 });
            d.setAAD(Buffer.from(aad));
            d.setAuthTag(Buffer.from(tag, 'base64'));
            return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
        };
        assert.throws(() => decryptWith(IKM), /authenticate data/, 'сырой ключ не подходит');
        assert.strictEqual(decryptWith(hkdf(IKM, 'nyxo-msg-enc-v3')), 'секрет', 'K_enc3 подходит');
        // Ключ для enc:v2 бота (сырой) и ключ комнат — разные роли.
        assert.throws(() => decryptWith(hkdf(IKM, 'nyxo-author-tag-key-v1')), /authenticate data/, 'ключ тега не подходит');
    });

    await test('комната принимает только enc:v3: без префикса, enc:v1 и enc:v2 — отказ', async () => {
        const { messageAadV3, encryptText, decryptRoomText, messageAad } = load(IKM);
        const aad = messageAadV3({ room_id: 5, id: 1000001, author_tag: TAG_A });
        const v2 = encryptText('старая запись', messageAad({ chat_id: 3, user_id: 4 }));
        const v1iv = crypto.randomBytes(12);
        const c = crypto.createCipheriv('aes-256-gcm', IKM, v1iv);
        const v1 = 'enc:v1:' + [b64(v1iv), b64(Buffer.concat([c.update('v1', 'utf8'), c.final()])), ''].join(':');
        for (const value of ['открытый текст в комнате', '[Сообщение удалено]', v2, v1, '', 42, {}]) {
            const { result, logged } = quiet(() => decryptRoomText(value, aad));
            assert.strictEqual(result, FAILED, String(value).slice(0, 20));
            assert.ok(logged.length > 0);
        }
    });

    await test('без AAD или с чужим форматом AAD enc:v3 не шифруется и не расшифровывается (исключение)', async () => {
        const { messageAadV3, encryptRoomText, decryptRoomText } = load(IKM);
        const aad = messageAadV3({ room_id: 5, id: 1000001, author_tag: TAG_A });
        const stored = encryptRoomText('x', aad);
        for (const bad of [undefined, null, '', 'nyxo:msg:v2:chat=1:user=1', 'nyxo:msg:v3:room=5:id=1000001:tag=XYZ', 'nyxo:msg:v3:room=05:id=1000001:tag=' + TAG_A.toString('hex')]) {
            assert.throws(() => encryptRoomText('x', bad), /AAD/);
            assert.throws(() => decryptRoomText(stored, bad), /AAD/);
        }
    });

    await test('чат с ботом остаётся на enc:v2; v2 не принимает комнатный AAD, а decryptText не читает enc:v3', async () => {
        const { messageAad, messageAadV3, encryptText, decryptText, encryptRoomText } = load(IKM);
        const botAad = messageAad({ room_id: null, chat_id: 11, user_id: 7 });
        assert.strictEqual(botAad, 'nyxo:msg:v2:chat=11:user=7');
        const stored = encryptText('привет, бот', botAad);
        assert.ok(stored.startsWith('enc:v2:'));
        assert.strictEqual(decryptText(stored, botAad), 'привет, бот');
        assert.throws(() => messageAad({ room_id: 5, user_id: 7 }), /enc:v3/, 'комнатного AAD v2 больше нет');
        assert.throws(() => messageAad({ room_id: 5, chat_id: 11, user_id: 7 }), TypeError);
        const roomRecord = encryptRoomText('комната', messageAadV3({ room_id: 5, id: 1000001, author_tag: TAG_A }));
        assert.strictEqual(quiet(() => decryptText(roomRecord, botAad)).result, FAILED, 'запись комнаты не читается как запись бота');
    });

    await test('ротация: enc:v3 читается по kid текущего и предыдущих ключей; без PREVIOUS — отказ; запись идёт под текущим', async () => {
        const first = load(IKM);
        const row = { room_id: 9, id: 1000009, author_tag: TAG_A };
        const aad = first.messageAadV3(row);
        const underA = first.encryptRoomText('до ротации', aad);

        const rotated = load(KEY_B, [KEY_C, IKM]);
        assert.strictEqual(rotated.decryptRoomText(underA, aad), 'до ротации');
        const underB = rotated.encryptRoomText('после ротации', aad);
        assert.strictEqual(underB.split(':')[2], kidOf(KEY_B), 'новые записи под текущим ключом');
        assert.strictEqual(rotated.decryptRoomText(underB, aad), 'после ротации');
        // Ключ шифрования каждого kid выводится от своего исходного ключа: запись под B
        // расшифровывается K_enc3(B), а не K_enc3(A).
        const [, , , iv, tag, ct] = underB.split(':');
        const d = crypto.createDecipheriv('aes-256-gcm', hkdf(KEY_B, 'nyxo-msg-enc-v3'), Buffer.from(iv, 'base64'), { authTagLength: 16 });
        d.setAAD(Buffer.from(aad));
        d.setAuthTag(Buffer.from(tag, 'base64'));
        assert.strictEqual(Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8'), 'после ротации');

        const withoutPrevious = load(KEY_B);
        const { result, logged } = quiet(() => withoutPrevious.decryptRoomText(underA, aad));
        assert.strictEqual(result, FAILED);
        assert.ok(logged.some(l => l.includes(kidOf(IKM))), 'неизвестный kid назван в логе');
        const backToA = load(IKM);
        assert.strictEqual(quiet(() => backToA.decryptRoomText(underB, aad)).result, FAILED);
    });

    await test('messageKeyRing: текущий ключ первым, затем предыдущие; это копии', async () => {
        const mc = load(KEY_B, [IKM, KEY_C]);
        const ring = mc.messageKeyRing();
        assert.deepStrictEqual(ring.map(entry => entry.kid), [kidOf(KEY_B), kidOf(IKM), kidOf(KEY_C)]);
        assert.ok(ring[0].ikm.equals(KEY_B) && ring[1].ikm.equals(IKM));
        ring[0].ikm.fill(0);
        assert.ok(mc.messageKeyRing()[0].ikm.equals(KEY_B), 'изменение копии ключ модуля не меняет');
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
