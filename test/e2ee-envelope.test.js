'use strict';
// Форма E2EE-конверта (lib/e2ee-envelope.js, R7): граничные значения каждого
// поля, лишний ключ, v1, не-JSON; плюс настоящий конверт клиента public/e2ee.js
// обязан проходить проверку (иначе сервер отвергал бы честных пользователей).
// Запуск: node test/e2ee-envelope.test.js

const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].type);
    if (type === 'ExperimentalWarning' && /ML-KEM|capsulate|getPublicKey/i.test(String(warning))) return;
    return originalEmitWarning.call(process, warning, ...args);
};

const assert = require('assert');
const {
    MAX_ENVELOPE_LENGTH,
    MIN_CT_BYTES,
    isE2eeEnvelopeShape,
    E2EE_REQUIRED,
    BAD_ENVELOPE,
    E2EE_NOT_ALLOWED,
} = require('../lib/e2ee-envelope');

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

const b64 = (length, fill = 7) => Buffer.alloc(length, fill).toString('base64');

// Правильный конверт с возможностью подменить поля; поле undefined — удалить.
function envelope(overrides = {}) {
    const base = {
        v: 3, alg: 'senderkey-v3',
        senderKeyId: b64(16, 1), iteration: 5,
        iv: b64(12, 2), ct: b64(MIN_CT_BYTES, 3), sig: b64(64, 4),
    };
    const merged = { ...base, ...overrides };
    for (const key of Object.keys(merged)) if (merged[key] === undefined) delete merged[key];
    return JSON.stringify(merged);
}

const ok = (text, what) => assert.strictEqual(isE2eeEnvelopeShape(text), true, what);
const bad = (text, what) => assert.strictEqual(isE2eeEnvelopeShape(text), false, what);

async function main() {
    await test('правильный конверт проходит; минимальный ct — 272 байта', () => {
        ok(envelope(), 'эталон');
        assert.strictEqual(MIN_CT_BYTES, 272);
    });

    await test('не JSON, не объект, не строка', () => {
        bad('привет', 'обычный текст');
        bad('', 'пустая строка');
        bad('{', 'оборванный JSON');
        bad('null', 'null');
        bad('[]', 'массив');
        bad('"senderkey-v3"', 'JSON-строка');
        bad('42', 'число');
        bad(undefined, 'undefined');
        bad(null, 'null как значение');
        bad(42, 'число как значение');
        bad({ v: 3 }, 'объект вместо строки: сервер ждёт текст');
    });

    await test('версия и алгоритм: только v3/senderkey-v3, v1 и v2 запрещены (R0: подпись v2 была без метки домена и комнаты)', () => {
        bad(envelope({ v: 1 }), 'v: 1');
        bad(envelope({ v: 2 }), 'v: 2');
        bad(envelope({ v: 2, alg: 'senderkey-v2' }), 'настоящий v2');
        bad(envelope({ v: '3' }), 'v строкой');
        bad(envelope({ v: 4 }), 'v: 4');
        bad(envelope({ v: undefined }), 'нет v');
        bad(envelope({ alg: 'senderkey-v1' }), 'alg v1');
        bad(envelope({ alg: 'senderkey-v2' }), 'alg v2');
        bad(envelope({ alg: 'senderkey-v4' }), 'alg v4');
        bad(envelope({ alg: undefined }), 'нет alg');
        bad(JSON.stringify({ alg: 'senderkey-v1', senderKeyId: b64(16), iteration: 0, iv: b64(12), ct: b64(300), sig: b64(64) }), 'настоящий v1 без v');
    });

    await test('senderKeyId: ровно 16 байт (24 символа), каноническое base64', () => {
        ok(envelope({ senderKeyId: b64(16) }), '16 байт');
        bad(envelope({ senderKeyId: b64(15) }), '15 байт');
        bad(envelope({ senderKeyId: b64(17) }), '17 байт');
        bad(envelope({ senderKeyId: b64(32) }), '32 байта');
        bad(envelope({ senderKeyId: '' }), 'пусто');
        bad(envelope({ senderKeyId: undefined }), 'нет поля');
        bad(envelope({ senderKeyId: 123 }), 'число');
        bad(envelope({ senderKeyId: b64(16).replace(/=+$/, '') }), 'без дополнения =');
        bad(envelope({ senderKeyId: Buffer.alloc(16, 0xfb).toString('base64').replace(/\+/g, '-').replace(/\//g, '_') }), 'url-safe алфавит');
        // Последний значащий символ несёт 4 бита данных и 2 нулевых: другой символ — то же число байт, но иное написание.
        const canonical = b64(16, 1);
        const lastIndex = canonical.indexOf('=') - 1;
        const alt = canonical.slice(0, lastIndex) + (canonical[lastIndex] === 'B' ? 'C' : 'B') + canonical.slice(lastIndex + 1);
        assert.strictEqual(Buffer.from(alt, 'base64').length, 16, 'проверка самого теста: байт столько же');
        bad(envelope({ senderKeyId: alt }), 'неканонические лишние биты');
        bad(envelope({ senderKeyId: ' ' + b64(16) }), 'пробел в начале');
    });

    await test('iteration: целое 0..2^32-1', () => {
        ok(envelope({ iteration: 0 }), '0');
        ok(envelope({ iteration: 1 }), '1');
        ok(envelope({ iteration: 4294967295 }), '2^32-1');
        bad(envelope({ iteration: 4294967296 }), '2^32');
        bad(envelope({ iteration: -1 }), '-1');
        bad(envelope({ iteration: 1.5 }), 'дробное');
        bad(envelope({ iteration: '5' }), 'строкой');
        bad(envelope({ iteration: null }), 'null');
        bad(envelope({ iteration: undefined }), 'нет поля');
        bad(envelope({ iteration: true }), 'булево');
        bad(envelope({ iteration: 1e300 }), 'огромное');
    });

    await test('iv: ровно 12 байт (16 символов)', () => {
        ok(envelope({ iv: b64(12) }), '12 байт');
        assert.strictEqual(b64(12).length, 16);
        bad(envelope({ iv: b64(11) }), '11 байт');
        bad(envelope({ iv: b64(13) }), '13 байт');
        bad(envelope({ iv: b64(16) }), '16 байт');
        bad(envelope({ iv: '' }), 'пусто');
        bad(envelope({ iv: undefined }), 'нет поля');
        bad(envelope({ iv: [1, 2, 3] }), 'массив');
    });

    await test('sig: ровно 64 байта (88 символов)', () => {
        ok(envelope({ sig: b64(64) }), '64 байта');
        assert.strictEqual(b64(64).length, 88);
        bad(envelope({ sig: b64(63) }), '63 байта');
        bad(envelope({ sig: b64(65) }), '65 байт');
        bad(envelope({ sig: b64(32) }), '32 байта');
        bad(envelope({ sig: '' }), 'пусто');
        bad(envelope({ sig: undefined }), 'нет поля');
        bad(envelope({ sig: null }), 'null');
    });

    await test('ct: не короче 272 байт, каноническое base64', () => {
        ok(envelope({ ct: b64(272) }), '272 байта');
        ok(envelope({ ct: b64(273) }), '273 байта');
        ok(envelope({ ct: b64(400) }), '400 байт');
        bad(envelope({ ct: b64(271) }), '271 байт');
        bad(envelope({ ct: b64(256) }), '256 байт (без тега)');
        bad(envelope({ ct: b64(16) }), '16 байт');
        bad(envelope({ ct: '' }), 'пусто');
        bad(envelope({ ct: undefined }), 'нет поля');
        bad(envelope({ ct: 'A'.repeat(400) + '!' }), 'посторонний символ');
        assert.ok(b64(301).endsWith('='), 'проверка самого теста: у 301 байта есть дополнение');
        bad(envelope({ ct: b64(301).replace(/=+$/, '') }), 'ct без =: длина не кратна четырём');
        bad(envelope({ ct: 'открытый текст сообщения'.repeat(30) }), 'не base64');
        bad(envelope({ ct: b64(300).slice(0, 5) + '\n' + b64(300).slice(5) }), 'перевод строки внутри');
    });

    await test('лишние и недостающие ключи верхнего уровня', () => {
        bad(envelope({ extra: 1 }), 'лишний ключ');
        bad(envelope({ text: 'открытый текст' }), 'открытый текст в лишнем ключе');
        bad(`{"__proto__":{},"v":3,"alg":"senderkey-v3","senderKeyId":"${b64(16)}","iteration":0,"iv":"${b64(12)}","ct":"${b64(300)}","sig":"${b64(64)}"}`, '__proto__ в исходной строке');
        for (const key of ['v', 'alg', 'senderKeyId', 'iteration', 'iv', 'ct', 'sig']) {
            bad(envelope({ [key]: undefined }), `нет ${key}`);
        }
    });

    await test('порядок ключей и пробелы не важны', () => {
        const parsed = JSON.parse(envelope());
        ok(JSON.stringify({ sig: parsed.sig, ct: parsed.ct, iv: parsed.iv, iteration: parsed.iteration, senderKeyId: parsed.senderKeyId, alg: parsed.alg, v: parsed.v }), 'обратный порядок');
        ok(JSON.stringify(parsed, null, 2), 'с отступами');
    });

    await test('длина: не больше 12000 символов', () => {
        assert.strictEqual(MAX_ENVELOPE_LENGTH, 12000);
        const base = envelope();
        ok(base + ' '.repeat(MAX_ENVELOPE_LENGTH - base.length), 'ровно 12000');
        bad(base + ' '.repeat(MAX_ENVELOPE_LENGTH - base.length + 1), '12001');
        // Самый большой возможный ct укладывается в предел с запасом по остальным полям.
        let bytes = MIN_CT_BYTES;
        while (envelope({ ct: b64(bytes + 3) }).length <= MAX_ENVELOPE_LENGTH) bytes += 3;
        ok(envelope({ ct: b64(bytes) }), `ct ${bytes} байт`);
        bad(envelope({ ct: b64(bytes + 3) }), `ct ${bytes + 3} байт (длиннее предела)`);
        bad(envelope({ ct: b64(9000) }), 'ct 9000 байт');
    });

    await test('тела ответов: код и понятный текст с призывом обновить страницу', () => {
        for (const [body, code] of [[E2EE_REQUIRED, 'e2ee-required'], [BAD_ENVELOPE, 'bad-envelope'], [E2EE_NOT_ALLOWED, 'e2ee-not-allowed']]) {
            assert.strictEqual(body.success, false);
            assert.strictEqual(body.code, code);
            assert.ok(Object.isFrozen(body), `${code}: тело должно быть заморожено`);
        }
        assert.match(E2EE_REQUIRED.message, /^Обновите страницу/);
        assert.match(E2EE_REQUIRED.message, /только со сквозным шифрованием/);
        assert.match(BAD_ENVELOPE.message, /^Обновите страницу/);
    });

    // Настоящие конверты: тот же код, что грузится в браузере.
    await test('настоящий конверт клиента (текст, правка, длинный текст) проходит проверку', async () => {
        const E2EE = require('../public/e2ee.js');
        const kem = require('../public/mlkem.js');
        const { makeFakeServer } = require('./fake-server');
        const ROOM = 100;
        const server = makeFakeServer();
        server.addParticipant(ROOM, 1, 11);
        server.addParticipant(ROOM, 2, 22);
        const users = {};
        for (const id of [1, 2]) {
            users[id] = E2EE.createClient({ userId: id, storage: new E2EE.MemoryStorage(), transport: server.transportFor(id), kem });
            await users[id].init();
        }
        const parts = [1, 2].map(id => ({ id, username: 'user' + id }));
        for (const id of [1, 2]) await users[id].ensureRoomSession(id * 11, ROOM, parts);

        const samples = [
            ['1000001', 'a'],
            ['1000002', 'x'.repeat(3000)],
            ['1000003', 'привет, мир '.repeat(100)],
        ];
        for (const [messageId, body] of samples) {
            const text = await users[1].encryptOutgoing(ROOM, body, { messageId });
            ok(text, `текст из ${body.length} символов`);
        }
        const edited = await users[1].encryptOutgoing(ROOM, 'правка', { messageId: '1000001', edit: true });
        ok(edited, 'правка');
        const file = await users[1].encryptOutgoing(ROOM, {
            type: 'file', mime: 'image/png', name: 'a.png', size: 10, key: b64(32), iv: b64(12), caption: '',
        }, { messageId: '1000004' });
        ok(file, 'описание файла');
        assert.deepStrictEqual(Object.keys(JSON.parse(file)).sort(), ['alg', 'ct', 'iteration', 'iv', 'senderKeyId', 'sig', 'v']);
    });

    console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
