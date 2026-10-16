'use strict';
// Тег автора и псевдоним квоты (docs/security/sealed-sender.md, разделы 6 и 13):
// lib/author-tag.js. Контрольные векторы документа посчитаны независимо
// (Node 24, ikm = 00 01 02 … 1f) и здесь сверяются дословно.
// Запуск: node test/author-tag.test.js

const assert = require('assert');
const {
    WEEK_MS, MAX_ACCOUNT_WEEKS, weekOf, deriveTagKey, deriveQuotaKey, computeTag, computeQkey,
    createAuthorTags,
} = require('../lib/author-tag');
const { deriveKey } = require('../lib/derive-key');

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

const IKM = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const IKM_B = Buffer.from(Array.from({ length: 32 }, (_, i) => 255 - i));
const hex = (buf) => buf.toString('hex');
const T_VECTOR = new Date('2026-10-09T12:00:00Z');

async function main() {
    await test('контрольный вектор 6.1: K_tag и три значения author_tag', async () => {
        assert.strictEqual(hex(deriveTagKey(IKM)), 'e20d5edfd0264834a97068cefd5e8215ca292a5972799988b6cbc6fc659f734d');
        assert.strictEqual(weekOf(T_VECTOR), 2962);
        const tags = createAuthorTags([IKM]);
        assert.strictEqual(hex(tags.tagFor(1234567, 7654321, T_VECTOR)), '9b7e17d7b43443d552180143b92a140c');
        assert.strictEqual(hex(tags.tagFor(1234568, 7654321, T_VECTOR)), '3de917f167c2f39aa146b22cc5b66485');
        assert.strictEqual(hex(computeTag(deriveTagKey(IKM), 1234567, 7654321, 2963)), '8f144b87119f6a6aa9597c7d6d7f56ba');
    });

    await test('контрольные значения 6.4: K_quota и qkey(7654321)', async () => {
        assert.strictEqual(hex(deriveQuotaKey(IKM)), '44583b51f6f291f9e02b3e313dbf82e294a50e75e5b9209f4a739dc3326b70cb');
        assert.strictEqual(hex(computeQkey(deriveQuotaKey(IKM), 7654321)), 'ef743331763c51d7be1de5290d7096d4');
        assert.strictEqual(hex(createAuthorTags([IKM]).qkey(7654321)), 'ef743331763c51d7be1de5290d7096d4');
    });

    await test('K_enc3 из того же ikm — третий отличный ключ (метки доменов разделяют роли)', async () => {
        const kEnc3 = deriveKey(IKM, 'nyxo-msg-enc-v3');
        assert.strictEqual(hex(kEnc3), '42852f99e3a8b7db0b0ef0b4df36b24f0ab0641b07e7c8ab6721a0cd6252d3fb');
        const keys = [hex(deriveTagKey(IKM)), hex(kEnc3), hex(deriveQuotaKey(IKM)), hex(IKM)];
        assert.strictEqual(new Set(keys).size, 4, 'K_tag, K_enc3, K_quota и исходный ключ попарно различны');
    });

    await test('тест-ловушка: ikm — 32 байта после parseKey, а не текст base64 (HKDF от текста даёт другой K_tag)', async () => {
        const fromText = deriveTagKey(Buffer.from(IKM.toString('base64'), 'utf8'));
        assert.notStrictEqual(hex(fromText), 'e20d5edfd0264834a97068cefd5e8215ca292a5972799988b6cbc6fc659f734d');
        assert.throws(() => createAuthorTags([Buffer.from(IKM.toString('base64'), 'utf8')]), TypeError, '44 байта текста — не ключ');
        assert.throws(() => createAuthorTags([IKM.toString('base64')]), TypeError, 'строка — не ключ');
        assert.throws(() => createAuthorTags([]), TypeError);
    });

    await test('теги: разные комнаты, пользователи и недели дают разные значения; одна неделя — одно значение', async () => {
        const tags = createAuthorTags([IKM]);
        const base = tags.tagFor(10, 20, T_VECTOR);
        assert.strictEqual(hex(base).length, 32);
        assert.strictEqual(base.length, 16);
        assert.strictEqual(hex(tags.tagFor(10, 20, new Date(T_VECTOR.getTime() + 60000))), hex(base), 'сдвиг внутри недели тег не меняет');
        assert.notStrictEqual(hex(tags.tagFor(11, 20, T_VECTOR)), hex(base), 'другая комната');
        assert.notStrictEqual(hex(tags.tagFor(10, 21, T_VECTOR)), hex(base), 'другой пользователь');
        assert.notStrictEqual(hex(tags.tagFor(10, 20, new Date(T_VECTOR.getTime() + WEEK_MS))), hex(base), 'следующая неделя');
        // Поля фиксированной длины: перестановка значений не даёт тот же тег.
        assert.notStrictEqual(hex(tags.tagFor(20, 10, T_VECTOR)), hex(base));
    });

    await test('weekOf: границы четверга 00:00 UTC, вход Date / ISO-строка / миллисекунды', async () => {
        const thursday = Date.UTC(2026, 9, 8, 0, 0, 0); // четверг 8 октября 2026
        assert.strictEqual(new Date(thursday).getUTCDay(), 4);
        assert.strictEqual(thursday % WEEK_MS, 0, 'граница недели от эпохи приходится на четверг 00:00 UTC');
        assert.strictEqual(weekOf(thursday - 1), weekOf(thursday) - 1);
        assert.strictEqual(weekOf(thursday + WEEK_MS - 1), weekOf(thursday));
        assert.strictEqual(weekOf(thursday + WEEK_MS), weekOf(thursday) + 1);
        assert.strictEqual(weekOf(new Date(thursday)), weekOf(thursday));
        assert.strictEqual(weekOf(new Date(thursday).toISOString()), weekOf(thursday));
        assert.strictEqual(weekOf(0), 0);
        assert.throws(() => weekOf('не дата'), TypeError);
        assert.throws(() => weekOf(NaN), TypeError);
        assert.throws(() => weekOf(-1), TypeError);
    });

    await test('tagsForRow: по одному тегу на ключ, текущий первым; совпадает с tagFor', async () => {
        const tags = createAuthorTags([IKM, IKM_B]);
        const row = tags.tagsForRow(10, 20, T_VECTOR);
        assert.strictEqual(row.length, 2);
        assert.strictEqual(hex(row[0]), hex(createAuthorTags([IKM]).tagFor(10, 20, T_VECTOR)));
        assert.strictEqual(hex(row[1]), hex(createAuthorTags([IKM_B]).tagFor(10, 20, T_VECTOR)));
        assert.notStrictEqual(hex(row[0]), hex(row[1]));
        // Пишется текущим ключом.
        assert.strictEqual(hex(tags.tagFor(10, 20, T_VECTOR)), hex(row[0]));
    });

    await test('tagsForAccount: недели от создания аккаунта до now включительно, по всем ключам', async () => {
        const one = createAuthorTags([IKM]);
        const created = new Date(T_VECTOR);
        const now = new Date(T_VECTOR.getTime() + 3 * WEEK_MS + 12345);
        const list = one.tagsForAccount(10, 20, created, now);
        assert.strictEqual(list.length, 4, 'неделя создания и три следующие');
        assert.deepStrictEqual(list.map(hex), [0, 1, 2, 3].map(i => hex(computeTag(deriveTagKey(IKM), 10, 20, 2962 + i))));
        // Тот же день создания и now — одна неделя.
        assert.strictEqual(one.tagsForAccount(10, 20, created, created).length, 1);
        // Два ключа — вдвое больше значений.
        const two = createAuthorTags([IKM, IKM_B]);
        assert.strictEqual(two.tagsForAccount(10, 20, created, now).length, 8);
        // Каждый тег строки любой недели из диапазона входит в набор.
        for (let i = 0; i < 4; i++) {
            const rowTag = one.tagFor(10, 20, new Date(T_VECTOR.getTime() + i * WEEK_MS));
            assert.ok(one.ownsTag(rowTag, list), `неделя ${i}`);
        }
        // А тег другого пользователя или комнаты — нет.
        assert.ok(!one.ownsTag(one.tagFor(10, 21, T_VECTOR), list));
        assert.ok(!one.ownsTag(one.tagFor(11, 20, T_VECTOR), list));
    });

    await test('tagsForAccount: предел 600 последних недель', async () => {
        const tags = createAuthorTags([IKM]);
        const now = new Date('2026-10-09T12:00:00Z');
        const veryOld = new Date('1990-01-01T00:00:00Z');
        const list = tags.tagsForAccount(1, 2, veryOld, now);
        assert.strictEqual(list.length, MAX_ACCOUNT_WEEKS);
        assert.strictEqual(hex(list[list.length - 1]), hex(computeTag(deriveTagKey(IKM), 1, 2, weekOf(now))), 'последняя — текущая неделя');
        assert.strictEqual(hex(list[0]), hex(computeTag(deriveTagKey(IKM), 1, 2, weekOf(now) - (MAX_ACCOUNT_WEEKS - 1))));
        // Аккаунт в точности на границе предела.
        const edge = new Date(now.getTime() - (MAX_ACCOUNT_WEEKS - 1) * WEEK_MS);
        assert.strictEqual(tags.tagsForAccount(1, 2, edge, now).length, MAX_ACCOUNT_WEEKS);
    });

    await test('ownsTag: сравнение по всем кандидатам; не-Buffer и неверная длина — нет', async () => {
        const tags = createAuthorTags([IKM]);
        const mine = tags.tagFor(5, 6, T_VECTOR);
        assert.ok(tags.ownsTag(mine, [Buffer.alloc(16), mine]));
        assert.ok(!tags.ownsTag(mine, []));
        assert.ok(!tags.ownsTag(null, [mine]));
        assert.ok(!tags.ownsTag(hex(mine), [mine]), 'hex-строка — не тег');
        assert.ok(!tags.ownsTag(mine.subarray(0, 8), [mine]));
    });

    await test('ротация ключа: старый тег строки находится среди тегов пользователя, новый тег пишется текущим', async () => {
        const before = createAuthorTags([IKM]);
        const oldTag = before.tagFor(7, 8, T_VECTOR);
        const after = createAuthorTags([IKM_B, IKM]);
        assert.ok(after.ownsTag(oldTag, after.tagsForRow(7, 8, T_VECTOR)), 'старая строка читается через …_PREVIOUS');
        assert.notStrictEqual(hex(after.tagFor(7, 8, T_VECTOR)), hex(oldTag), 'новая запись — под новым ключом');
        // Без …_PREVIOUS старая строка теряется.
        const lost = createAuthorTags([IKM_B]);
        assert.ok(!lost.ownsTag(oldTag, lost.tagsForRow(7, 8, T_VECTOR)));
    });

    await test('qkeysFor: по псевдониму на ключ, текущий первым; у разных пользователей различны', async () => {
        const tags = createAuthorTags([IKM_B, IKM]);
        const list = tags.qkeysFor(7654321);
        assert.strictEqual(list.length, 2);
        assert.strictEqual(hex(list[0]), hex(tags.qkey(7654321)));
        assert.strictEqual(hex(list[1]), 'ef743331763c51d7be1de5290d7096d4', 'под прежним ключом — вектор документа');
        assert.notStrictEqual(hex(tags.qkey(7654322)), hex(tags.qkey(7654321)));
    });

    await test('некорректные идентификаторы отвергаются, а не усечением до 4 байт', async () => {
        const tags = createAuthorTags([IKM]);
        for (const bad of [0.5, -1, 2 ** 32, '5', null, undefined, NaN]) {
            assert.throws(() => tags.tagFor(bad, 1, T_VECTOR), TypeError, `room ${String(bad)}`);
            assert.throws(() => tags.tagFor(1, bad, T_VECTOR), TypeError, `user ${String(bad)}`);
            assert.throws(() => tags.qkey(bad), TypeError, `qkey ${String(bad)}`);
        }
        assert.doesNotThrow(() => tags.tagFor(2 ** 31 - 1, 2 ** 31 - 1, T_VECTOR));
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
