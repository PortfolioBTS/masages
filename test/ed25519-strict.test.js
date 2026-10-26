'use strict';
// Строгая проверка Ed25519 (public/lib/ed25519-strict.js, signed-membership.md 6.1):
// декодирование по RFC 8032 (пункт 1), [8]P ≠ O (пункт 2) и S < L (пункт 3) проверяются
// по отдельности, чтобы отказ одного не маскировал отсутствие другого; платформенный
// verify принимает оба отрицательных вектора раздела 6.6, а явная проверка их отвергает.
// Запуск: node test/ed25519-strict.test.js

const assert = require('assert');
const crypto = require('crypto');
const strict = require('../public/lib/ed25519-strict.js');

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

const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const ONE = '0100000000000000000000000000000000000000000000000000000000000000';
const ONE_SIGN = '0100000000000000000000000000000000000000000000000000000000000080';
const MINUS_ONE_SIGN = 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
// Подпись обоих отрицательных векторов: R = 01 00…00, S = 0.
const ZERO_S_SIG = new Uint8Array(64);
ZERO_S_SIG[0] = 1;

function realPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { pub: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)), privateKey };
}

async function main() {
    await test('пункт 1: декодер отвергает x = 0 при бите знака 1 (01 00…00 80 и ec ff…ff ff), y ≥ p и точки не на кривой', () => {
        assert.deepStrictEqual(strict.decodePoint(unhex(ONE_SIGN)), { error: 'zero-x-sign' });
        assert.deepStrictEqual(strict.decodePoint(unhex(MINUS_ONE_SIGN)), { error: 'zero-x-sign' });
        // Тот же x = 0 с битом знака 0 — корректная единичная точка и точка порядка 2.
        assert.deepStrictEqual(strict.decodePoint(unhex(ONE)), { x: 0n, y: 1n });
        assert.strictEqual(strict.decodePoint(unhex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')).y, strict.P - 1n);
        // y ≥ p.
        for (const high of [
            'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
            'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ]) assert.deepStrictEqual(strict.decodePoint(unhex(high)), { error: 'non-canonical-y' }, high);
        // Длина.
        assert.deepStrictEqual(strict.decodePoint(new Uint8Array(31)), { error: 'length' });
        assert.deepStrictEqual(strict.decodePoint('x'), { error: 'length' });
        // Около половины значений y не лежат на кривой (корня x нет).
        let off = 0;
        for (let y = 2; y < 60; y++) {
            const bytes = new Uint8Array(32);
            bytes[0] = y;
            if (strict.decodePoint(bytes).error === 'no-square-root') off++;
        }
        assert.ok(off > 10 && off < 50, 'точки вне кривой отвергаются: ' + off);
    });

    await test('пункт 2 отдельно: [8]P ≠ O ловит единичную точку и без проверки знака в декодере', () => {
        // Декодер без проверки бита знака при x = 0 (как OpenSSL) пропускает 01 00…00 80 как единичную точку —
        // и тогда её отвергает только [8]P = O. Оба пункта обязательны.
        const lax = strict.decodePoint(unhex(ONE_SIGN), { rejectZeroXSign: false });
        assert.deepStrictEqual(lax, { x: 0n, y: 1n });
        assert.ok(strict.hasSmallOrder(lax), '[8]P = O для единичной точки');
        assert.ok(strict.hasSmallOrder(strict.decodePoint(unhex(ONE))));
        // Все восемь канонических кодировок малого порядка проходят пункт 1 и отвергаются пунктом 2.
        for (const encoding of strict.SMALL_ORDER_ENCODINGS) {
            const point = strict.decodePoint(unhex(encoding));
            assert.ok(!point.error, 'пункт 1 пропускает каноническую кодировку: ' + encoding);
            assert.ok(strict.hasSmallOrder(point), 'пункт 2 отвергает: ' + encoding);
            assert.deepStrictEqual(strict.checkPublicKey(unhex(encoding)), { ok: false, reason: 'small-order' });
        }
    });

    await test('отрицательные векторы: платформенный verify принимает, явная проверка отвергает обе пары', async () => {
        const message = new Uint8Array([1, 2, 3, 4, 5]);
        for (const [label, keyHex, reason] of [
            ['единичная точка, порядок 1', ONE, 'small-order'],
            ['y = 1 с битом знака 1 (x = 0)', ONE_SIGN, 'zero-x-sign'],
        ]) {
            const key = unhex(keyHex);
            // Платформа: пара (R = 01 00…00, S = 0) «подходит» к любому сообщению.
            const subtle = globalThis.crypto.subtle;
            let platform = null;
            try {
                const imported = await subtle.importKey('raw', key, { name: 'Ed25519' }, false, ['verify']);
                platform = await subtle.verify({ name: 'Ed25519' }, imported, ZERO_S_SIG, message);
            } catch { platform = null; }
            console.log(`        ${label}: платформенный verify — ${platform}`);
            assert.deepStrictEqual(strict.checkPublicKey(key), { ok: false, reason }, label);
            assert.strictEqual(strict.isStrictKey(key), false);
            assert.strictEqual(await strict.verify(key, message, ZERO_S_SIG), false, label);
        }
        // Подпись с R малого порядка при настоящем ключе — тоже отказ (пункты 1 и 2 для R).
        const { pub } = realPair();
        assert.deepStrictEqual(strict.checkSignature(ZERO_S_SIG), { ok: false, reason: 'R-small-order' });
        assert.strictEqual(await strict.verify(pub, message, ZERO_S_SIG), false);
        const badR = new Uint8Array(ZERO_S_SIG);
        badR[31] = 0x80; // R = 01 00…00 80
        assert.deepStrictEqual(strict.checkSignature(badR), { ok: false, reason: 'R-zero-x-sign' });
    });

    await test('пункт 3: S < L — граничные значения', () => {
        const real = crypto.sign(null, Buffer.from('m'), realPair().privateKey);
        const sig = new Uint8Array(real);
        const withS = (value) => {
            const out = new Uint8Array(sig);
            let v = value;
            for (let i = 0; i < 32; i++) { out[32 + i] = Number(v & 255n); v >>= 8n; }
            return out;
        };
        assert.ok(strict.checkSignature(sig).ok);
        assert.ok(strict.checkSignature(withS(strict.L - 1n)).ok, 'S = L − 1');
        assert.deepStrictEqual(strict.checkSignature(withS(strict.L)), { ok: false, reason: 'S-not-less-than-L' });
        assert.deepStrictEqual(strict.checkSignature(withS(strict.L + 1n)), { ok: false, reason: 'S-not-less-than-L' });
        assert.deepStrictEqual(strict.checkSignature(withS((1n << 256n) - 1n)), { ok: false, reason: 'S-not-less-than-L' });
        assert.deepStrictEqual(strict.checkSignature(new Uint8Array(63)), { ok: false, reason: 'length' });
    });

    await test('настоящие ключи и подписи проходят: сто случайных пар, подмена сообщения и подписи — отказ', async () => {
        for (let i = 0; i < 100; i++) {
            const { pub, privateKey } = realPair();
            const message = new Uint8Array(crypto.randomBytes(1 + (i % 50)));
            const sig = new Uint8Array(crypto.sign(null, message, privateKey));
            assert.deepStrictEqual(strict.checkPublicKey(pub), { ok: true });
            assert.ok(strict.checkSignature(sig).ok);
            assert.ok(await strict.verify(pub, message, sig), 'пара ' + i);
            const other = new Uint8Array(message);
            other[0] ^= 1;
            assert.ok(!(await strict.verify(pub, other, sig)));
            const torn = new Uint8Array(sig);
            torn[40] ^= 1;
            assert.ok(!(await strict.verify(pub, message, torn)));
        }
    });

    await test('случайные 32 байта: либо корректная точка не малого порядка, либо точная причина отказа', () => {
        const reasons = new Set();
        for (let i = 0; i < 200; i++) {
            const bytes = new Uint8Array(crypto.randomBytes(32));
            const result = strict.checkPublicKey(bytes);
            if (!result.ok) reasons.add(result.reason);
            else assert.ok(!strict.hasSmallOrder(strict.decodePoint(bytes)));
        }
        assert.ok([...reasons].every(r => ['no-square-root', 'small-order', 'non-canonical-y'].includes(r)), [...reasons].join());
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
