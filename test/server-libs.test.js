'use strict';
// Тесты серверных модулей без БД и сети:
//   - lib/message-crypto.js — at rest v2 для чата с ботом (kid + AAD), чтение v1, ротация
//     ключей (enc:v3 комнат — test/message-crypto.test.js);
//   - lib/privacy.js — заголовки и оставшиеся помощники.
// Модули читают ключи из окружения при загрузке, поэтому env выставляется
// ДО require, а для смены ключей модуль загружается заново.
// Запуск: node test/server-libs.test.js

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

// Глушит console.error/warn на время fn и возвращает то, что туда писали:
// ожидаемые ошибки расшифровки не должны засорять вывод тестов.
async function withQuietConsole(fn) {
    const saved = { error: console.error, warn: console.warn };
    const logged = [];
    console.error = (...args) => logged.push(args.join(' '));
    console.warn = (...args) => logged.push(args.join(' '));
    try {
        await fn();
    } finally {
        console.error = saved.error;
        console.warn = saved.warn;
    }
    return logged;
}

// ---------------- message-crypto ----------------

const KEY_A = crypto.randomBytes(32);
const KEY_B = crypto.randomBytes(32);
const KEY_C = crypto.randomBytes(32);
const b64 = buf => buf.toString('base64');
const kidOf = key => crypto.createHash('sha256').update(key).digest('hex').slice(0, 8);
const FAILED = '[Не удалось расшифровать]';

function loadMessageCrypto(current, previous) {
    if (current) process.env.MESSAGE_ENCRYPTION_KEY = current;
    else delete process.env.MESSAGE_ENCRYPTION_KEY;
    if (previous !== undefined) process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS = previous;
    else delete process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS;
    delete require.cache[require.resolve('../lib/message-crypto.js')];
    return require('../lib/message-crypto.js');
}

// Запись старого формата — так её писала предыдущая версия модуля.
function encryptV1(key, text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return 'enc:v1:' + [b64(iv), b64(cipher.getAuthTag()), b64(data)].join(':');
}

async function main() {
    console.log('Server lib tests\n');

    // ======== message-crypto ========

    await test('message-crypto: refuses to load without a valid MESSAGE_ENCRYPTION_KEY (fail closed)', async () => {
        assert.throws(() => loadMessageCrypto(null), /MESSAGE_ENCRYPTION_KEY/);
        assert.throws(() => loadMessageCrypto(b64(crypto.randomBytes(16))), /32 байта/);
        assert.throws(() => loadMessageCrypto(b64(KEY_A), b64(KEY_B) + ',c2hvcnQ='), /MESSAGE_ENCRYPTION_KEY_PREVIOUS/);
    });

    await test('messageAad (enc:v2): только чат с ботом — чат и владелец; комнатный AAD v2 больше не существует', async () => {
        const { messageAad } = loadMessageCrypto(b64(KEY_A));
        assert.strictEqual(messageAad({ room_id: null, chat_id: 11, user_id: 7 }), 'nyxo:msg:v2:chat=11:user=7');
        assert.strictEqual(messageAad({ chat_id: 11, user_id: 7 }), 'nyxo:msg:v2:chat=11:user=7');
        // Строки из req.params и числа из pg дают одно и то же.
        assert.strictEqual(messageAad({ chat_id: '11', user_id: '7' }), 'nyxo:msg:v2:chat=11:user=7');
        // Комнаты шифруются enc:v3 (messageAadV3): v2 с room_id — ошибка программиста.
        assert.throws(() => messageAad({ room_id: 5, chat_id: 11, user_id: 7 }), /enc:v3/);
        assert.throws(() => messageAad({ room_id: 5, user_id: 7 }), /enc:v3/);
        assert.throws(() => messageAad({ chat_id: 11 }), TypeError);
        assert.throws(() => messageAad({ user_id: 7 }), TypeError);
        assert.throws(() => messageAad({ chat_id: 'abc', user_id: 7 }), TypeError);
        assert.throws(() => messageAad({ chat_id: 0, user_id: 7 }), TypeError);
        assert.throws(() => messageAad({ chat_id: 1.5, user_id: 7 }), TypeError);
        assert.throws(() => messageAad(null), TypeError);
    });

    await test('message-crypto: v2 round trip, format enc:v2:<kid>:<iv>:<tag>:<ct>', async () => {
        const { encryptText, decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const aad = messageAad({ chat_id: 11, user_id: 7 });
        for (const text of ['Привет, мир! 👋', '', 'a:b:c', 'x'.repeat(10000)]) {
            const stored = encryptText(text, aad);
            const parts = stored.split(':');
            assert.strictEqual(parts.length, 6);
            assert.strictEqual(parts[0] + ':' + parts[1], 'enc:v2');
            assert.strictEqual(parts[2], kidOf(KEY_A));
            assert.strictEqual(Buffer.from(parts[3], 'base64').length, 12);
            assert.strictEqual(Buffer.from(parts[4], 'base64').length, 16);
            assert.strictEqual(decryptText(stored, aad), text);
        }
        // Одинаковый текст — разный шифротекст (случайный nonce).
        assert.notStrictEqual(encryptText('same', aad), encryptText('same', aad));
        // null/undefined — осознанно пустые значения, проходят насквозь.
        assert.strictEqual(encryptText(null, aad), null);
        assert.strictEqual(encryptText(undefined, aad), undefined);
        assert.strictEqual(decryptText(null, aad), null);
    });

    await test('message-crypto: v2 without AAD throws (encrypt and decrypt)', async () => {
        const { encryptText, decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        assert.throws(() => encryptText('secret'), /AAD/);
        assert.throws(() => encryptText('secret', ''), /AAD/);
        const stored = encryptText('secret', messageAad({ chat_id: 3, user_id: 4 }));
        assert.throws(() => decryptText(stored), /AAD/);
        assert.throws(() => decryptText(stored, null), /AAD/);
    });

    await test('message-crypto: ciphertext moved to another chat / sender, or altered, does not decrypt', async () => {
        const { encryptText, decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const original = { chat_id: 11, user_id: 7 };
        const stored = encryptText('только для чата 11', messageAad(original));
        const [prefix1, prefix2, kid, iv, tag, ct] = stored.split(':');
        const flipped = Buffer.from(ct, 'base64');
        flipped[0] ^= 1;
        const cases = [
            ['another chat', stored, messageAad({ chat_id: 12, user_id: 7 })],
            ['another sender', stored, messageAad({ chat_id: 11, user_id: 8 })],
            ['raw AAD swapped', stored, 'nyxo:msg:v2:chat=11:user=77'],
            ['room AAD of the same numbers', stored, 'nyxo:msg:v2:room=11:user=7'],
            ['ciphertext bit flip', [prefix1, prefix2, kid, iv, tag, b64(flipped)].join(':'), messageAad(original)],
            ['truncated tag', [prefix1, prefix2, kid, iv, b64(Buffer.from(tag, 'base64').subarray(0, 4)), ct].join(':'), messageAad(original)],
            ['missing field', [prefix1, prefix2, kid, iv, ct].join(':'), messageAad(original)],
        ];
        for (const [label, value, aad] of cases) {
            let result;
            const logged = await withQuietConsole(() => { result = decryptText(value, aad); });
            assert.strictEqual(result, FAILED, label);
            assert.ok(logged.length > 0, label + ': failure must be logged');
        }
        // А на своём месте — расшифровывается.
        assert.strictEqual(decryptText(stored, messageAad({ room_id: null, chat_id: 11, user_id: 7 })), 'только для чата 11');
    });

    await test('message-crypto: legacy v1 records and unprefixed strings still read', async () => {
        const { decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const v1 = encryptV1(KEY_A, 'старое сообщение');
        assert.strictEqual(decryptText(v1), 'старое сообщение');
        // AAD для v1 не используется, но и не мешает — сервер передаёт его всегда.
        assert.strictEqual(decryptText(v1, messageAad({ chat_id: 1, user_id: 1 })), 'старое сообщение');
        assert.strictEqual(decryptText('[Сообщение удалено]', 'nyxo:msg:v2:chat=1:user=1'), '[Сообщение удалено]');
        assert.strictEqual(decryptText('plain text before encryption'), 'plain text before encryption');
        let result;
        await withQuietConsole(() => { result = decryptText(encryptV1(KEY_C, 'чужой ключ')); });
        assert.strictEqual(result, FAILED);
    });

    await test('message-crypto: key rotation via MESSAGE_ENCRYPTION_KEY_PREVIOUS, key picked by kid', async () => {
        const oldModule = loadMessageCrypto(b64(KEY_A));
        const aad = oldModule.messageAad({ chat_id: 9, user_id: 2 });
        const storedUnderA = oldModule.encryptText('до ротации', aad);
        const v1UnderA = encryptV1(KEY_A, 'совсем старое');

        // Новый ключ B, старые A и C — в PREVIOUS (через запятую, с пробелами).
        const rotated = loadMessageCrypto(b64(KEY_B), ` ${b64(KEY_C)} , ${b64(KEY_A)} `);
        assert.strictEqual(rotated.decryptText(storedUnderA, aad), 'до ротации');
        assert.strictEqual(rotated.decryptText(v1UnderA), 'совсем старое');
        const storedUnderB = rotated.encryptText('после ротации', aad);
        assert.strictEqual(storedUnderB.split(':')[2], kidOf(KEY_B), 'new records use the current key');
        assert.strictEqual(rotated.decryptText(storedUnderB, aad), 'после ротации');

        // PREVIOUS — только для чтения: без него старые записи не читаются,
        // а новые (под B) старый процесс с ключом A не прочитает.
        const withoutPrevious = loadMessageCrypto(b64(KEY_B));
        let result;
        const logged = await withQuietConsole(() => { result = withoutPrevious.decryptText(storedUnderA, aad); });
        assert.strictEqual(result, FAILED);
        assert.ok(logged.some(l => l.includes(kidOf(KEY_A))), 'unknown kid is named in the log');
        const backToA = loadMessageCrypto(b64(KEY_A));
        await withQuietConsole(() => { result = backToA.decryptText(storedUnderB, aad); });
        assert.strictEqual(result, FAILED);
    });

    await test('message-crypto: unknown kid is rejected even if the key would fit', async () => {
        const { encryptText, decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const aad = messageAad({ chat_id: 1, user_id: 1 });
        const parts = encryptText('hello', aad).split(':');
        parts[2] = 'deadbeef';
        let result;
        await withQuietConsole(() => { result = decryptText(parts.join(':'), aad); });
        assert.strictEqual(result, FAILED);
    });

    // ======== privacy ========

    await test('privacy: only the used helpers remain exported', async () => {
        const privacy = require('../lib/privacy.js');
        // addRandomDelay выравнивал время ответа при входе — входа больше нет.
        assert.deepStrictEqual(Object.keys(privacy).sort(), ['createHstsMiddleware', 'getHstsHeader', 'getPrivacyHeaders', 'sanitizeText']);
    });

    await test('privacy: headers — X-XSS-Protection 0, Referrer-Policy no-referrer, rest unchanged', async () => {
        const { getPrivacyHeaders } = require('../lib/privacy.js');
        assert.deepStrictEqual(getPrivacyHeaders(), {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '0',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
        });
    });

    await test('privacy: sanitizeText strips zero-width characters', async () => {
        const { sanitizeText } = require('../lib/privacy.js');
        assert.strictEqual(sanitizeText('при​вет‌ ‍мир﻿'), 'привет мир');
        assert.strictEqual(sanitizeText(null), null);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
