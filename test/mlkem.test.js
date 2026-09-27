'use strict';
// Тесты public/mlkem.js (ML-KEM-768 по FIPS 203 + SHA-3/SHAKE) против
// эталонов, встроенных в Node 24: node:crypto (SHA-3/SHAKE) и WebCrypto
// ML-KEM-768 (экспериментальный, поверх OpenSSL 3.5). Сверка идёт побайтно:
// ключи из одного seed, секреты при инкапсуляции в обе стороны, implicit
// rejection, проверки ввода. Запуск: node test/mlkem.test.js
//
// Node печатает ExperimentalWarning про ML-KEM-768 — это ожидаемо.

const assert = require('assert');
const nodeCrypto = require('crypto');
const { performance } = require('perf_hooks');
const MLKEM = require('../public/mlkem.js');

const { subtle } = globalThis.crypto;
const ALG = { name: 'ML-KEM-768' };
const Q = 3329;
const K = 3;
const RANDOM_SEEDS = 64;

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

function randomBytes(n) {
    return new Uint8Array(nodeCrypto.randomBytes(n));
}

function randomInt(max) {
    return nodeCrypto.randomInt(max);
}

function toBuffer(bytes) {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function assertBytesEqual(actual, expected, message) {
    const a = toBuffer(actual), b = toBuffer(expected);
    if (a.equals(b)) return;
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    assert.fail(message + ': длины ' + a.length + '/' + b.length + ', первое расхождение в байте ' + i);
}

function bytesEqual(a, b) {
    return toBuffer(a).equals(toBuffer(b));
}

function nodeHash(alg, data, outputLength) {
    const opts = outputLength === undefined ? undefined : { outputLength };
    return new Uint8Array(nodeCrypto.createHash(alg, opts).update(data).digest());
}

// ---------- DER для PKCS#8 ML-KEM (формат IETF LAMPS: seed / expandedKey / both) ----------

function readTlv(buf, off) {
    const tag = buf[off];
    let len = buf[off + 1], p = off + 2;
    if (len & 0x80) {
        const n = len & 0x7f;
        len = 0;
        for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    }
    return { tag, start: p, end: p + len };
}

function derTlv(tag, body) {
    const n = body.length;
    const len = n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
    return Buffer.concat([Buffer.from([tag, ...len]), Buffer.from(body)]);
}

const ML_KEM_768_ALG_ID = Buffer.from('300b0609608648016503040402', 'hex'); // id-alg-ml-kem-768

// PKCS#8 с выбором expandedKey — так в Node можно загрузить произвольный dk на 2400 байт
function pkcs8ExpandedKey(dk) {
    return derTlv(0x30, Buffer.concat([Buffer.from('020100', 'hex'), ML_KEM_768_ALG_ID, derTlv(0x04, derTlv(0x04, dk))]));
}

// Node экспортирует приватный ключ в форме «both»: SEQUENCE { seed, expandedKey }
function nodeExportSeedAndExpanded(privateKey) {
    const der = nodeCrypto.KeyObject.from(privateKey).export({ format: 'der', type: 'pkcs8' });
    const top = readTlv(der, 0);
    const version = readTlv(der, top.start);
    const alg = readTlv(der, version.end);
    assert.ok(der.subarray(version.end, alg.end).equals(ML_KEM_768_ALG_ID), 'PKCS#8 должен быть id-alg-ml-kem-768');
    const octet = readTlv(der, alg.end);
    const both = readTlv(der, octet.start);
    assert.strictEqual(both.tag, 0x30, 'Node должен экспортировать форму both');
    const seed = readTlv(der, both.start);
    const expanded = readTlv(der, seed.end);
    return {
        seed: new Uint8Array(der.subarray(seed.start, seed.end)),
        expanded: new Uint8Array(der.subarray(expanded.start, expanded.end)),
    };
}

async function nodeKeysFromSeed(seed) {
    const privateKey = await subtle.importKey('raw-seed', seed, ALG, true, ['decapsulateBits']);
    const publicKey = await subtle.getPublicKey(privateKey, ['encapsulateBits']);
    const rawPublic = new Uint8Array(await subtle.exportKey('raw-public', publicKey));
    return { privateKey, publicKey, rawPublic };
}

async function nodeImportPublic(ek) {
    return subtle.importKey('raw-public', ek, ALG, true, ['encapsulateBits']);
}

async function nodeEncapsulate(publicKey) {
    const r = await subtle.encapsulateBits(ALG, publicKey);
    return { ciphertext: new Uint8Array(r.ciphertext), sharedSecret: new Uint8Array(r.sharedKey) };
}

async function nodeDecapsulate(privateKey, ciphertext) {
    return new Uint8Array(await subtle.decapsulateBits(ALG, privateKey, ciphertext));
}

// Коэффициент idx (0..767) вектора t̂ в ByteEncode_12: два коэффициента на три байта
function setEkCoefficient(ek, idx, value) {
    const b = (idx >> 1) * 3;
    if (idx % 2 === 0) {
        ek[b] = value & 0xff;
        ek[b + 1] = (ek[b + 1] & 0xf0) | (value >> 8);
    } else {
        ek[b + 1] = (ek[b + 1] & 0x0f) | ((value & 0x0f) << 4);
        ek[b + 2] = value >> 4;
    }
}

async function main() {
    console.log('ML-KEM-768 / SHA-3 tests\n');

    // Общий набор ключей: 64 случайных seed + вырожденные (все нули, все 0xff)
    const seeds = [new Uint8Array(64), new Uint8Array(64).fill(0xff)];
    for (let i = 0; i < RANDOM_SEEDS; i++) seeds.push(randomBytes(64));
    const cases = [];

    // ===================== SHA-3 / SHAKE =====================

    // Границы rate: 72 (SHA3-512), 136 (SHA3-256, SHAKE256), 168 (SHAKE128) и их кратные
    const boundaryLengths = [0, 1, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33, 63, 64, 65, 71, 72, 73, 135, 136, 137,
        143, 144, 145, 167, 168, 169, 271, 272, 273, 335, 336, 337, 503, 504, 505, 1000, 1184, 2400, 4097];
    const inputLengths = boundaryLengths.concat(Array.from({ length: 20 }, () => randomInt(3000)));
    const outputLengths = [0, 1, 31, 32, 33, 64, 128, 135, 136, 137, 167, 168, 169, 504, 1000, 1344, 5000];

    await test('SHA3-256 / SHA3-512 match node:crypto (rate boundaries and random lengths)', () => {
        for (const len of inputLengths) {
            const data = randomBytes(len);
            assertBytesEqual(MLKEM.sha3_256(data), nodeHash('sha3-256', data), 'SHA3-256, длина ' + len);
            assertBytesEqual(MLKEM.sha3_512(data), nodeHash('sha3-512', data), 'SHA3-512, длина ' + len);
        }
    });

    await test('SHAKE128 / SHAKE256 match node:crypto (all input × output lengths, outputs up to 5000 bytes)', () => {
        for (const len of inputLengths) {
            const data = randomBytes(len);
            for (const outLen of outputLengths) {
                assertBytesEqual(MLKEM.shake128(data, outLen), nodeHash('shake128', data, outLen), 'SHAKE128 ' + len + '→' + outLen);
                assertBytesEqual(MLKEM.shake256(data, outLen), nodeHash('shake256', data, outLen), 'SHAKE256 ' + len + '→' + outLen);
            }
        }
    });

    await test('SHAKE XOF: incremental squeeze in random chunks equals one-shot node output', () => {
        for (const bits of [128, 256]) {
            for (let round = 0; round < 20; round++) {
                const data = randomBytes(randomInt(400));
                const total = 3000 + randomInt(3000);
                const expected = nodeHash('shake' + bits, data, total);
                const xof = MLKEM._internal.xof(bits, data);
                const got = new Uint8Array(total);
                let off = 0;
                while (off < total) {
                    const chunk = Math.min(total - off, randomInt(3) === 0 ? 3 : randomInt(400));
                    got.set(xof.squeeze(chunk), off);
                    off += chunk;
                }
                assertBytesEqual(got, expected, 'SHAKE' + bits + ' потоковый squeeze');
            }
        }
    });

    await test('hash functions accept Buffer and reject non-bytes / bad output length', () => {
        const buf = Buffer.from('abc');
        assertBytesEqual(MLKEM.sha3_256(buf), nodeHash('sha3-256', buf), 'Buffer как вход');
        for (const bad of ['abc', [1, 2, 3], new ArrayBuffer(3), null, undefined, new Uint16Array(3)]) {
            assert.throws(() => MLKEM.sha3_256(bad), TypeError);
            assert.throws(() => MLKEM.sha3_512(bad), TypeError);
            assert.throws(() => MLKEM.shake128(bad, 32), TypeError);
            assert.throws(() => MLKEM.shake256(bad, 32), TypeError);
        }
        for (const badLen of [-1, 1.5, NaN, '32', undefined, 2 ** 60]) {
            assert.throws(() => MLKEM.shake128(buf, badLen), RangeError);
            assert.throws(() => MLKEM.shake256(buf, badLen), RangeError);
        }
    });

    // ===================== Compress / Decompress =====================

    await test('Compress_d / Decompress_d: exhaustive check against the exact FIPS 203 formulas (4.7), (4.8)', () => {
        // Эталон на BigInt: Compress_d(x) = ⌊(2^(d+1)·x + q) / 2q⌋ mod 2^d, Decompress_d(y) = ⌊(2qy + 2^d) / 2^(d+1)⌋.
        // Кроме d = 1, 4, 10 (ML-KEM-768) проверены 5 и 11 — запас точности умножения вместо деления.
        const q = BigInt(Q);
        for (const d of [1, 4, 5, 10, 11]) {
            const D = BigInt(d);
            for (let base = 0; base < Q; base += 256) {
                const xs = new Int32Array(256);
                for (let i = 0; i < 256; i++) xs[i] = Math.min(base + i, Q - 1);
                const got = MLKEM._internal.compress(xs, d);
                for (let i = 0; i < 256; i++) {
                    const x = BigInt(xs[i]);
                    const expected = Number(((x << (D + 1n)) + q) / (2n * q) % (1n << D));
                    assert.strictEqual(got[i], expected, 'Compress_' + d + '(' + xs[i] + ')');
                }
            }
            for (let base = 0; base < (1 << d); base += 256) {
                const ys = new Int32Array(256);
                for (let i = 0; i < 256; i++) ys[i] = Math.min(base + i, (1 << d) - 1);
                const got = MLKEM._internal.decompress(ys, d);
                for (let i = 0; i < 256; i++) {
                    const y = BigInt(ys[i]);
                    const expected = Number((2n * q * y + (1n << D)) / (1n << (D + 1n)));
                    assert.strictEqual(got[i], expected, 'Decompress_' + d + '(' + ys[i] + ')');
                }
            }
        }
    });

    // ===================== ML-KEM-768 против Node WebCrypto =====================

    await test('constants match FIPS 203 ML-KEM-768 sizes', () => {
        assert.strictEqual(MLKEM.PUBLIC_KEY_BYTES, 1184);
        assert.strictEqual(MLKEM.SECRET_KEY_BYTES, 2400);
        assert.strictEqual(MLKEM.CIPHERTEXT_BYTES, 1088);
        assert.strictEqual(MLKEM.SEED_BYTES, 64);
        assert.strictEqual(MLKEM.SHARED_SECRET_BYTES, 32);
    });

    await test('(а) keygen(seed): public key and expanded secret key are byte-identical to Node (' + seeds.length + ' seeds)', async () => {
        for (const seed of seeds) {
            const ours = MLKEM.keygen(seed);
            const node = await nodeKeysFromSeed(seed);
            assert.strictEqual(ours.publicKey.length, 1184);
            assert.strictEqual(ours.secretKey.length, 2400);
            assertBytesEqual(ours.publicKey, node.rawPublic, 'ek');
            const exported = nodeExportSeedAndExpanded(node.privateKey);
            assertBytesEqual(exported.seed, seed, 'seed в PKCS#8 Node');
            assertBytesEqual(ours.secretKey, exported.expanded, 'dk');
            // Раскладка dk (алг. 16): dk_PKE ‖ ek ‖ H(ek) ‖ z
            assertBytesEqual(ours.secretKey.subarray(384 * K, 768 * K + 32), ours.publicKey, 'ek внутри dk');
            assertBytesEqual(ours.secretKey.subarray(768 * K + 32, 768 * K + 64), nodeHash('sha3-256', ours.publicKey), 'H(ek) внутри dk');
            assertBytesEqual(ours.secretKey.subarray(768 * K + 64), seed.subarray(32), 'z внутри dk');
            cases.push({ seed, ours, node });
        }
    });

    await test('(б) Node encapsulates to our public key → our decapsulate returns the same secret', async () => {
        assert.strictEqual(cases.length, seeds.length, 'нужны ключи из теста (а)');
        for (const c of cases) {
            const nodePublic = await nodeImportPublic(c.ours.publicKey);
            for (let i = 0; i < 2; i++) {
                const enc = await nodeEncapsulate(nodePublic);
                assert.strictEqual(enc.ciphertext.length, 1088);
                assertBytesEqual(MLKEM.decapsulate(c.ours.secretKey, enc.ciphertext), enc.sharedSecret, 'общий секрет');
            }
        }
    });

    await test('(в) our encapsulate → Node decapsulate (key from the same seed) returns the same secret', async () => {
        for (const c of cases) {
            const enc = MLKEM.encapsulate(c.ours.publicKey);
            assert.strictEqual(enc.ciphertext.length, 1088);
            assert.strictEqual(enc.sharedSecret.length, 32);
            assertBytesEqual(await nodeDecapsulate(c.node.privateKey, enc.ciphertext), enc.sharedSecret, 'общий секрет');

            // Детерминированный m (алг. 17): K = первые 32 байта G(m ‖ H(ek)), независимо через node:crypto
            const m = randomBytes(32);
            const det1 = MLKEM.encapsulate(c.ours.publicKey, m);
            const det2 = MLKEM.encapsulate(c.ours.publicKey, m);
            assertBytesEqual(det1.ciphertext, det2.ciphertext, 'шифртекст при одном m');
            const g = nodeHash('sha3-512', Buffer.concat([m, nodeHash('sha3-256', c.ours.publicKey)]));
            assertBytesEqual(det1.sharedSecret, g.subarray(0, 32), 'K = G(m ‖ H(ek))[0:32]');
            assertBytesEqual(await nodeDecapsulate(c.node.privateKey, det1.ciphertext), det1.sharedSecret, 'Node принимает шифртекст для заданного m');
        }
    });

    await test('(г) implicit rejection: tampered ciphertext gives the same K̄ = J(z‖c) as Node, not the real secret', async () => {
        for (const c of cases) {
            const enc = await nodeEncapsulate(c.node.publicKey);
            const z = c.seed.subarray(32);
            // Порча в c1 (u), в c2 (v), в первом и последнем байте, плюс полностью случайный шифртекст
            const positions = [0, randomInt(960), 960 + randomInt(128), 1087];
            const tampered = positions.map((pos) => {
                const t = enc.ciphertext.slice();
                t[pos] ^= 1 << randomInt(8);
                return t;
            });
            tampered.push(randomBytes(1088));
            for (const bad of tampered) {
                const ours = MLKEM.decapsulate(c.ours.secretKey, bad);
                assertBytesEqual(ours, await nodeDecapsulate(c.node.privateKey, bad), 'K̄ совпадает с Node');
                assertBytesEqual(ours, nodeHash('shake256', Buffer.concat([z, bad]), 32), 'K̄ = SHAKE256(z ‖ c, 32)');
                assert.ok(!bytesEqual(ours, enc.sharedSecret), 'испорченный шифртекст не должен давать настоящий секрет');
            }
        }
    });

    await test('implicit rejection takes z from the secret key (dk with replaced z, imported into Node as expandedKey)', async () => {
        for (const c of cases.slice(0, 16)) {
            const dk = c.ours.secretKey.slice();
            const newZ = randomBytes(32);
            dk.set(newZ, 768 * K + 64); // z не покрыт hash check — ключ остаётся валидным
            const nodePrivate = nodeCrypto.createPrivateKey({ key: pkcs8ExpandedKey(dk), format: 'der', type: 'pkcs8' });
            const enc = MLKEM.encapsulate(c.ours.publicKey);
            assertBytesEqual(MLKEM.decapsulate(dk, enc.ciphertext), enc.sharedSecret, 'правильный шифртекст от z не зависит');
            assertBytesEqual(nodeCrypto.decapsulate(nodePrivate, enc.ciphertext), enc.sharedSecret, 'Node: правильный шифртекст');
            const bad = enc.ciphertext.slice();
            bad[randomInt(1088)] ^= 0x80;
            const ours = MLKEM.decapsulate(dk, bad);
            assertBytesEqual(ours, nodeCrypto.decapsulate(nodePrivate, bad), 'K̄ совпадает с Node');
            assertBytesEqual(ours, nodeHash('shake256', Buffer.concat([newZ, bad]), 32), 'K̄ = J(z′ ‖ c)');
        }
    });

    await test('(д) public key with a coefficient ≥ q fails the modulus check (Node rejects it too); q−1 is accepted', async () => {
        const base = cases[2].ours.publicKey;
        for (const idx of [0, 1, 255, 256, 511, 512, 766, 767]) {
            for (const value of [Q - 1, Q, Q + 1, 4095]) {
                const ek = base.slice();
                setEkCoefficient(ek, idx, value);
                let nodeAccepted = true;
                try {
                    await nodeImportPublic(ek);
                } catch (err) {
                    nodeAccepted = false;
                }
                if (value < Q) {
                    assert.ok(nodeAccepted, 'Node должен принять коэффициент q−1');
                    const enc = MLKEM.encapsulate(ek);
                    assert.strictEqual(enc.ciphertext.length, 1088);
                } else {
                    assert.ok(!nodeAccepted, 'Node должен отвергнуть коэффициент ' + value);
                    assert.throws(() => MLKEM.encapsulate(ek), /modulus check/, 'коэффициент ' + value + ' на позиции ' + idx);
                }
            }
        }
        // ρ (последние 32 байта ek) modulus check не касается
        const ek = base.slice();
        ek[1183] ^= 0xff;
        MLKEM.encapsulate(ek);
        await nodeImportPublic(ek);
    });

    await test('(д) wrong lengths and non-byte inputs throw', () => {
        const { publicKey, secretKey } = cases[3].ours;
        const ct = MLKEM.encapsulate(publicKey).ciphertext;
        for (const n of [0, 32, 63, 65, 128]) assert.throws(() => MLKEM.keygen(new Uint8Array(n)), RangeError, 'seed ' + n);
        for (const bad of [null, 'x'.repeat(64), new Array(64).fill(0), new ArrayBuffer(64)]) {
            assert.throws(() => MLKEM.keygen(bad), TypeError);
            assert.throws(() => MLKEM.encapsulate(bad), TypeError);
            assert.throws(() => MLKEM.decapsulate(bad, ct), TypeError);
            assert.throws(() => MLKEM.decapsulate(secretKey, bad), TypeError);
        }
        for (const n of [0, 1183, 1185, 2400]) assert.throws(() => MLKEM.encapsulate(new Uint8Array(n)), RangeError, 'ek ' + n);
        for (const n of [0, 31, 33, 64]) assert.throws(() => MLKEM.encapsulate(publicKey, new Uint8Array(n)), RangeError, 'm ' + n);
        assert.throws(() => MLKEM.encapsulate(publicKey, 'm'.repeat(32)), TypeError);
        for (const n of [0, 1087, 1089, 1184]) assert.throws(() => MLKEM.decapsulate(secretKey, new Uint8Array(n)), RangeError, 'ct ' + n);
        for (const n of [0, 1184, 2399, 2401]) assert.throws(() => MLKEM.decapsulate(new Uint8Array(n), ct), RangeError, 'dk ' + n);
    });

    await test('(д) secret key failing the hash check (broken H(ek) or embedded ek) throws; Node rejects it too', async () => {
        const { publicKey, secretKey } = cases[4].ours;
        const ct = MLKEM.encapsulate(publicKey).ciphertext;
        for (const pos of [384 * K, 384 * K + 500, 768 * K + 31, 768 * K + 32, 768 * K + 63]) {
            const dk = secretKey.slice();
            dk[pos] ^= 0x01;
            assert.throws(() => MLKEM.decapsulate(dk, ct), /hash check/, 'байт ' + pos);
            assert.throws(() => nodeCrypto.createPrivateKey({ key: pkcs8ExpandedKey(dk), format: 'der', type: 'pkcs8' }),
                'Node должен отвергнуть dk с испорченным байтом ' + pos);
        }
        // Неизменённый ключ через ту же обёртку Node принимает — значит, отказ выше именно из-за hash check
        nodeCrypto.createPrivateKey({ key: pkcs8ExpandedKey(secretKey), format: 'der', type: 'pkcs8' });
    });

    await test('keygen() and encapsulate() without optional arguments use fresh randomness', async () => {
        const a = MLKEM.keygen();
        const b = MLKEM.keygen();
        assert.ok(!bytesEqual(a.publicKey, b.publicKey), 'два keygen() должны дать разные ключи');
        const e1 = MLKEM.encapsulate(a.publicKey);
        const e2 = MLKEM.encapsulate(a.publicKey);
        assert.ok(!bytesEqual(e1.ciphertext, e2.ciphertext), 'две инкапсуляции должны отличаться');
        assert.ok(!bytesEqual(e1.sharedSecret, e2.sharedSecret));
        assertBytesEqual(MLKEM.decapsulate(a.secretKey, e1.ciphertext), e1.sharedSecret, 'круг keygen→encaps→decaps');
        const nodePublic = await nodeImportPublic(a.publicKey);
        const enc = await nodeEncapsulate(nodePublic);
        assertBytesEqual(MLKEM.decapsulate(a.secretKey, enc.ciphertext), enc.sharedSecret, 'Node → случайный ключ');
    });

    await test('timings (informational)', () => {
        const kp = MLKEM.keygen();
        const enc = MLKEM.encapsulate(kp.publicKey);
        const measure = (fn, n) => {
            const start = performance.now();
            for (let i = 0; i < n; i++) fn();
            return (performance.now() - start) / n;
        };
        const keygenMs = measure(() => MLKEM.keygen(), 200);
        const encapsMs = measure(() => MLKEM.encapsulate(kp.publicKey), 200);
        const decapsMs = measure(() => MLKEM.decapsulate(kp.secretKey, enc.ciphertext), 200);
        console.log('         keygen ' + keygenMs.toFixed(3) + ' ms, encaps ' + encapsMs.toFixed(3) +
            ' ms, decaps ' + decapsMs.toFixed(3) + ' ms (среднее из 200 после прогрева JIT предыдущими тестами)');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
