'use strict';
// enc:v1 (без kid и без AAD) больше не читается (ревью R4 W7, З5; R0: старых данных нет). Запись без AAD позволяла тому,
// кто пишет в БД, переносить шифротекст между строками чата с ботом: расшифровка v1 не привязана ни к чату, ни к
// пользователю. Теперь строка enc:v1 - "[Не удалось расшифровать]", а не текст и не открытый текст "как есть".
// Запуск: node test/message-crypto-no-v1.test.js

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

const KEY = crypto.randomBytes(32);
const b64 = (buf) => Buffer.from(buf).toString('base64');

function load() {
    process.env.MESSAGE_ENCRYPTION_KEY = b64(KEY);
    delete process.env.MESSAGE_ENCRYPTION_KEY_PREVIOUS;
    delete require.cache[require.resolve('../lib/message-crypto.js')];
    return require('../lib/message-crypto.js');
}

// Запись старого формата - так её писала первая версия модуля.
function encryptV1(key, text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return 'enc:v1:' + [b64(iv), b64(cipher.getAuthTag()), b64(data)].join(':');
}

function quiet(fn) {
    const saved = console.error;
    console.error = () => {};
    try { return fn(); } finally { console.error = saved; }
}

(async () => {
    console.log('Серверное шифрование: enc:v1 не читается (З5)\n');

    await test('decryptText: запись enc:v1 под верным ключом - отказ расшифровки, с AAD и без него', () => {
        const { decryptText, messageAad, DECRYPT_FAILED } = load();
        const v1 = encryptV1(KEY, 'старое сообщение');
        assert.strictEqual(quiet(() => decryptText(v1)), DECRYPT_FAILED);
        assert.strictEqual(quiet(() => decryptText(v1, messageAad({ chat_id: 1, user_id: 1 }))), DECRYPT_FAILED);
        // Перенос такой записи в другую строку тоже не даёт текста: раньше v1 расшифровывалась где угодно.
        assert.strictEqual(quiet(() => decryptText(v1, messageAad({ chat_id: 2, user_id: 9 }))), DECRYPT_FAILED);
    });

    await test('служебные строки без префикса и enc:v2 читаются как раньше', () => {
        const { encryptText, decryptText, messageAad } = load();
        assert.strictEqual(decryptText('[Сообщение удалено]'), '[Сообщение удалено]');
        const aad = messageAad({ chat_id: 5, user_id: 3 });
        assert.strictEqual(decryptText(encryptText('привет', aad), aad), 'привет');
    });

    await test('в модуле нет кода чтения v1: ни PREFIX_V1, ни decryptV1', () => {
        const source = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'message-crypto.js'), 'utf8');
        assert.ok(!/function decryptV1\b/.test(source), 'decryptV1 удалён');
        assert.ok(!/gcmDecrypt\(key, parts\[0\]/.test(source), 'расшифровка без AAD удалена');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
})().catch((err) => { console.error(err); process.exitCode = 1; });
