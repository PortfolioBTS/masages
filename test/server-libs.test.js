'use strict';
// Тесты серверных модулей без БД и сети:
//   - lib/message-crypto.js — at rest v2 (kid + AAD), чтение v1, ротация ключей;
//   - lib/passwords.js — $nyxo1$ (HMAC перед bcrypt), старые bcrypt-хэши,
//     политика паролей, проверка по утечкам только при HIBP_CHECK=true;
//   - lib/privacy.js — заголовки и оставшиеся помощники.
// Модули читают ключи из окружения при загрузке, поэтому env выставляется
// ДО require, а для смены ключей модуль загружается заново.
// Запуск: node test/server-libs.test.js

const assert = require('assert');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

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

// ---------------- passwords ----------------

function loadPasswords(pepper) {
    if (pepper) process.env.PASSWORD_PEPPER = pepper;
    else delete process.env.PASSWORD_PEPPER;
    delete require.cache[require.resolve('../lib/passwords.js')];
    return require('../lib/passwords.js');
}

const realFetch = global.fetch;
function installFakeFetch(handler) {
    const calls = [];
    global.fetch = async (url, opts = {}) => {
        calls.push({ url: String(url), headers: opts.headers || {}, signal: opts.signal });
        return handler(String(url));
    };
    return calls;
}
function restoreFetch() { global.fetch = realFetch; }

async function main() {
    console.log('Server lib tests\n');

    // ======== message-crypto ========

    await test('message-crypto: refuses to load without a valid MESSAGE_ENCRYPTION_KEY (fail closed)', async () => {
        assert.throws(() => loadMessageCrypto(null), /MESSAGE_ENCRYPTION_KEY/);
        assert.throws(() => loadMessageCrypto(b64(crypto.randomBytes(16))), /32 байта/);
        assert.throws(() => loadMessageCrypto(b64(KEY_A), b64(KEY_B) + ',c2hvcnQ='), /MESSAGE_ENCRYPTION_KEY_PREVIOUS/);
    });

    await test('messageAad: room messages bind room+sender (chat_id ignored), personal chats bind chat+sender', async () => {
        const { messageAad } = loadMessageCrypto(b64(KEY_A));
        assert.strictEqual(messageAad({ room_id: 5, chat_id: 11, user_id: 7 }), 'nyxo:msg:v2:room=5:user=7');
        // chat_id у сообщения комнаты обнуляется при удалении чата отправителя — AAD от этого не меняется.
        assert.strictEqual(messageAad({ room_id: 5, chat_id: null, user_id: 7 }), 'nyxo:msg:v2:room=5:user=7');
        // Строки из req.params и числа из pg дают одно и то же.
        assert.strictEqual(messageAad({ room_id: '5', user_id: '7' }), 'nyxo:msg:v2:room=5:user=7');
        assert.strictEqual(messageAad({ room_id: null, chat_id: 11, user_id: 7 }), 'nyxo:msg:v2:chat=11:user=7');
        assert.strictEqual(messageAad({ chat_id: 11, user_id: 7 }), 'nyxo:msg:v2:chat=11:user=7');
        assert.throws(() => messageAad({ room_id: 5 }), TypeError);
        assert.throws(() => messageAad({ user_id: 7 }), TypeError);
        assert.throws(() => messageAad({ room_id: 'abc', user_id: 7 }), TypeError);
        assert.throws(() => messageAad({ room_id: 0, user_id: 7 }), TypeError);
        assert.throws(() => messageAad({ room_id: 1.5, user_id: 7 }), TypeError);
        assert.throws(() => messageAad(null), TypeError);
    });

    await test('message-crypto: v2 round trip, format enc:v2:<kid>:<iv>:<tag>:<ct>', async () => {
        const { encryptText, decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const aad = messageAad({ room_id: 5, chat_id: 11, user_id: 7 });
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

    await test('message-crypto: ciphertext moved to another room / sender / chat, or altered, does not decrypt', async () => {
        const { encryptText, decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const original = { room_id: 5, chat_id: 11, user_id: 7 };
        const stored = encryptText('только для комнаты 5', messageAad(original));
        const [prefix1, prefix2, kid, iv, tag, ct] = stored.split(':');
        const flipped = Buffer.from(ct, 'base64');
        flipped[0] ^= 1;
        const cases = [
            ['another room', stored, messageAad({ room_id: 6, user_id: 7 })],
            ['another sender', stored, messageAad({ room_id: 5, user_id: 8 })],
            ['personal chat with the same number', stored, messageAad({ chat_id: 5, user_id: 7 })],
            ['raw AAD swapped', stored, 'nyxo:msg:v2:room=5:user=77'],
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
        assert.strictEqual(decryptText(stored, messageAad({ room_id: 5, chat_id: null, user_id: 7 })), 'только для комнаты 5');
    });

    await test('message-crypto: legacy v1 records and unprefixed strings still read', async () => {
        const { decryptText, messageAad } = loadMessageCrypto(b64(KEY_A));
        const v1 = encryptV1(KEY_A, 'старое сообщение');
        assert.strictEqual(decryptText(v1), 'старое сообщение');
        // AAD для v1 не используется, но и не мешает — сервер передаёт его всегда.
        assert.strictEqual(decryptText(v1, messageAad({ room_id: 1, user_id: 1 })), 'старое сообщение');
        assert.strictEqual(decryptText('[Сообщение удалено]', 'nyxo:msg:v2:chat=1:user=1'), '[Сообщение удалено]');
        assert.strictEqual(decryptText('plain text before encryption'), 'plain text before encryption');
        let result;
        await withQuietConsole(() => { result = decryptText(encryptV1(KEY_C, 'чужой ключ')); });
        assert.strictEqual(result, FAILED);
    });

    await test('message-crypto: key rotation via MESSAGE_ENCRYPTION_KEY_PREVIOUS, key picked by kid', async () => {
        const oldModule = loadMessageCrypto(b64(KEY_A));
        const aad = oldModule.messageAad({ room_id: 9, user_id: 2 });
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

    // ======== passwords ========

    delete process.env.HIBP_CHECK;
    const passwords = loadPasswords(null);

    await test('passwords: exports the agreed API', async () => {
        assert.deepStrictEqual(Object.keys(passwords).sort(),
            ['DUMMY_PASSWORD_HASH', 'checkPasswordPolicy', 'hashPassword', 'needsRehash', 'verifyPassword'].sort());
    });

    await test('passwords: new $nyxo1$ scheme round trip, cost 12', async () => {
        const stored = await passwords.hashPassword('correct horse battery staple');
        assert.ok(stored.startsWith('$nyxo1$$2'), stored);
        assert.strictEqual(bcrypt.getRounds(stored.slice('$nyxo1$'.length)), 12);
        assert.strictEqual(await passwords.verifyPassword('correct horse battery staple', stored), true);
        assert.strictEqual(await passwords.verifyPassword('correct horse battery stapler', stored), false);
        assert.strictEqual(passwords.needsRehash(stored), false);
    });

    await test('passwords: passwords longer than 72 bytes differ (bcrypt alone would truncate)', async () => {
        const common = 'пароль-'.repeat(15); // 105 символов, 195 байт UTF-8
        const a = common + 'A', b = common + 'B';
        // Демонстрация проблемы: чистый bcrypt не видит разницы после 72 байт.
        const legacy = bcrypt.hashSync(a, 4);
        assert.strictEqual(await bcrypt.compare(b, legacy), true);
        // Новая схема — видит.
        const stored = await passwords.hashPassword(a);
        assert.strictEqual(await passwords.verifyPassword(a, stored), true);
        assert.strictEqual(await passwords.verifyPassword(b, stored), false);
    });

    await test('passwords: Unicode forms are normalized (NFKC) — composed and decomposed "й" match', async () => {
        const composed = 'мой ключ й-12345';
        const decomposed = composed.normalize('NFD');
        assert.notStrictEqual(composed, decomposed);
        const stored = await passwords.hashPassword(composed);
        assert.strictEqual(await passwords.verifyPassword(decomposed, stored), true);
    });

    await test('passwords: legacy $2a$/$2b$/$2y$ bcrypt hashes verify and need rehash', async () => {
        const legacy = bcrypt.hashSync('legacy-password', 4);
        for (const variant of ['$2a$', '$2b$', '$2y$']) {
            const stored = variant + legacy.slice(4);
            assert.strictEqual(await passwords.verifyPassword('legacy-password', stored), true, variant);
            assert.strictEqual(await passwords.verifyPassword('legacy-passwordX', stored), false, variant);
            assert.strictEqual(passwords.needsRehash(stored), true, variant);
        }
        // $nyxo1$ с cost ниже текущего тоже стоит пересчитать.
        assert.strictEqual(passwords.needsRehash('$nyxo1$' + bcrypt.hashSync('x', 4)), true);
    });

    await test('passwords: unknown formats and bad input never verify', async () => {
        for (const stored of ['', 'plaintext', '$argon2id$v=19$m=65536', '$nyxo1$', '$nyxo1$garbage', null, undefined, 42]) {
            assert.strictEqual(await passwords.verifyPassword('whatever', stored), false, String(stored));
            assert.strictEqual(passwords.needsRehash(stored), false, String(stored));
        }
        assert.strictEqual(await passwords.verifyPassword(null, passwords.DUMMY_PASSWORD_HASH), false);
        await assert.rejects(() => passwords.hashPassword(12345678), TypeError);
    });

    await test('passwords: DUMMY_PASSWORD_HASH is in the new format and matches nothing', async () => {
        assert.ok(passwords.DUMMY_PASSWORD_HASH.startsWith('$nyxo1$$2'));
        assert.strictEqual(passwords.needsRehash(passwords.DUMMY_PASSWORD_HASH), false);
        assert.strictEqual(await passwords.verifyPassword('', passwords.DUMMY_PASSWORD_HASH), false);
    });

    await test('passwords: PASSWORD_PEPPER is part of the hash (and changing it breaks old hashes)', async () => {
        const stored = await passwords.hashPassword('pepper test password');
        const peppered = loadPasswords('server-side-secret');
        try {
            assert.strictEqual(await peppered.verifyPassword('pepper test password', stored), false);
            // Старые bcrypt-хэши от pepper не зависят.
            const legacy = bcrypt.hashSync('legacy-password', 4);
            assert.strictEqual(await peppered.verifyPassword('legacy-password', legacy), true);
        } finally {
            delete process.env.PASSWORD_PEPPER;
        }
    });

    await test('policy: length 8..256 characters (code points, not UTF-16 units)', async () => {
        const ctx = { username: 'alice', email: 'alice@example.com' };
        assert.match(await passwords.checkPasswordPolicy('Tr0ub4!', ctx), /минимум 8/);
        assert.strictEqual(await passwords.checkPasswordPolicy('tr0ub4d0r', ctx), null);
        // 7 эмодзи — это 14 UTF-16-единиц, но только 7 символов.
        assert.match(await passwords.checkPasswordPolicy('🐱🐶🦊🐻🐼🐨🐯', ctx), /минимум 8/);
        const longOk = Array.from({ length: 256 }, (_, i) => String.fromCharCode(0x430 + (i * 7) % 32)).join('');
        assert.strictEqual(await passwords.checkPasswordPolicy(longOk, ctx), null);
        assert.match(await passwords.checkPasswordPolicy(longOk + 'я', ctx), /256/);
        assert.match(await passwords.checkPasswordPolicy(undefined, ctx), /Некорректный/);
    });

    await test('policy: common passwords rejected case-insensitively, including keyboard-layout variants', async () => {
        for (const pw of ['password', 'PASSWORD1', 'Qwerty123', '123456789', 'йцукенгш', 'ЙЦУКЕН123',
            'пароль123', 'gfhjkm123', 'ghbdtn123', 'qwertyui', '1q2w3e4r', 'iloveyou']) {
            assert.match(await passwords.checkPasswordPolicy(pw, {}), /распространён/, pw);
        }
        // «asdf1234», набранное в русской раскладке, — тоже он, хотя «фыва1234» в списке нет.
        assert.match(await passwords.checkPasswordPolicy('ФЫВА1234', {}), /распространён/);
    });

    await test('policy: repeated or sequential characters rejected', async () => {
        for (const pw of ['zzzzzzzz', 'xyxyxyxy', 'abcabcabc', 'lmnopqrs', '98765432', 'трамтрам', 'ёёёёёёёё']) {
            assert.match(await passwords.checkPasswordPolicy(pw, {}), /повторяющихся или идущих подряд/, pw);
        }
    });

    await test('policy: must not equal or contain the username / email local part (≥ 4 chars)', async () => {
        const ctx = { username: 'Snowflake', email: 'Ivan.Petrov@example.com' };
        assert.match(await passwords.checkPasswordPolicy('snowflake', ctx), /именем пользователя/);
        assert.match(await passwords.checkPasswordPolicy('my-SNOWFLAKE-2024', ctx), /именем пользователя/);
        assert.match(await passwords.checkPasswordPolicy('ivan.petrov', ctx), /почты/);
        assert.match(await passwords.checkPasswordPolicy('xx-ivan.petrov-xx', ctx), /почты/);
        // Короткие имена проверяются только на равенство.
        assert.strictEqual(await passwords.checkPasswordPolicy('annabelle-river', { username: 'ann', email: 'bo@x.io' }), null);
        // Без контекста — только общие проверки.
        assert.strictEqual(await passwords.checkPasswordPolicy('snowflake-river-77'), null);
    });

    await test('policy: no composition rules (NIST) — long lowercase passphrases pass', async () => {
        for (const pw of ['correct horse battery staple', 'в лесу родилась ёлочка', 'mylittlesecretgarden']) {
            assert.strictEqual(await passwords.checkPasswordPolicy(pw, { username: 'bob', email: 'bob@example.com' }), null, pw);
        }
    });

    await test('policy: HIBP is NOT called unless HIBP_CHECK=true', async () => {
        const calls = installFakeFetch(() => { throw new Error('must not be called'); });
        try {
            delete process.env.HIBP_CHECK;
            assert.strictEqual(await passwords.checkPasswordPolicy('an uncommon passphrase 42', {}), null);
            process.env.HIBP_CHECK = '1';
            assert.strictEqual(await passwords.checkPasswordPolicy('an uncommon passphrase 42', {}), null);
            assert.strictEqual(calls.length, 0);
        } finally {
            delete process.env.HIBP_CHECK;
            restoreFetch();
        }
    });

    await test('policy: HIBP_CHECK=true — k-anonymity range query with padding, count 0 ignored, fail open', async () => {
        const pw = 'an uncommon passphrase 42';
        const sha1 = crypto.createHash('sha1').update(pw, 'utf8').digest('hex').toUpperCase();
        const [prefix, suffix] = [sha1.slice(0, 5), sha1.slice(5)];
        const reply = body => ({ ok: true, status: 200, text: async () => body });
        process.env.HIBP_CHECK = 'true';
        try {
            let calls = installFakeFetch(() => reply(`0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${suffix}:3861493\r\n`));
            assert.match(await passwords.checkPasswordPolicy(pw, {}), /утечках/);
            assert.strictEqual(calls.length, 1);
            assert.strictEqual(calls[0].url, `https://api.pwnedpasswords.com/range/${prefix}`);
            assert.strictEqual(calls[0].headers['Add-Padding'], 'true');
            assert.ok(calls[0].signal instanceof AbortSignal, 'request must have a timeout');
            assert.ok(!calls[0].url.includes(suffix), 'only the 5-char prefix leaves the server');

            // Строка-заполнитель (count 0) с тем же хвостом — не совпадение.
            installFakeFetch(() => reply(`${suffix}:0\r\nFFFFF00000000000000000000000000000000:0\r\n`));
            assert.strictEqual(await passwords.checkPasswordPolicy(pw, {}), null);

            // Сервис недоступен — не мешаем регистрации, но предупреждаем.
            for (const failing of [() => { throw new Error('timeout'); }, () => ({ ok: false, status: 503, text: async () => '' })]) {
                installFakeFetch(failing);
                let result;
                const logged = await withQuietConsole(async () => { result = await passwords.checkPasswordPolicy(pw, {}); });
                assert.strictEqual(result, null);
                assert.ok(logged.some(l => l.includes('HIBP')), 'fail-open must warn');
            }

            // Локальные проверки отсекают раньше — без обращения наружу.
            calls = installFakeFetch(() => { throw new Error('must not be called'); });
            assert.match(await passwords.checkPasswordPolicy('password1', {}), /распространён/);
            assert.strictEqual(calls.length, 0);
        } finally {
            delete process.env.HIBP_CHECK;
            restoreFetch();
        }
    });

    // ======== privacy ========

    await test('privacy: only the used helpers remain exported', async () => {
        const privacy = require('../lib/privacy.js');
        assert.deepStrictEqual(Object.keys(privacy).sort(), ['addRandomDelay', 'getPrivacyHeaders', 'sanitizeText']);
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

    await test('privacy: sanitizeText strips zero-width characters, addRandomDelay waits within bounds', async () => {
        const { sanitizeText, addRandomDelay } = require('../lib/privacy.js');
        assert.strictEqual(sanitizeText('при​вет‌ ‍мир﻿'), 'привет мир');
        assert.strictEqual(sanitizeText(null), null);
        const started = Date.now();
        await addRandomDelay(20, 30);
        assert.ok(Date.now() - started >= 15);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
