'use strict';
// Контрольный вектор для общего секрета PQXDH (ревью W7 R5, З-4). Круговой обмен (Alice -> Bob) проходит и тогда,
// когда метка домена 'nyxo-e2ee-pqxdh-v1' одинаково изменена на обеих сторонах (public/e2ee.js: отправитель
// ~2091, получатель ~2280), порядок DH-вкладов переставлен или из входа убран секрет ML-KEM: обе стороны ошибаются
// одинаково. Закрепить это может только независимый расчёт.
//
// Метод: ключи X25519 клиентов перехватываются при создании (в тесте пара делается извлекаемой), и ожидаемый секрет
// считается средствами Node с литералами меток из этого файла:
//   SK  = HKDF-SHA256(ikm = FF32 || DH1 || DH2 || DH3 || DH4 || ss_ML-KEM, salt = 32 нуля, info = 'nyxo-e2ee-pqxdh-v1')
//   ck0 = HKDF-SHA256(SK, 32 нуля, 'nyxo-e2ee-pw-chain-v2')    - начало цепочки попарного канала
//   ck_n = HMAC-SHA256(ck_(n-1), 0x02)                         - после n сообщений; стороны хранят ck_n и n
//   DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) (нет OPK - пусто).
// Сверяются сохранённые ck_n отправителя (pw2Send) и получателя (pw2Recv): после одного key-share n = 1. Три варианта bundle: с одноразовым
// классическим prekey и одноразовым PQ, без классического, с запасным PQ-prekey.
// Запуск: node test/pqxdh-kat.test.js

const nodeCrypto = require('crypto');
const {
    assert, E2EE, mlkem, test, finish, makeUser, makeRoom, chatOf, participantsOf, stored,
} = require('./sender-keys-helpers');

const subtle = globalThis.crypto.subtle;
const { b64decode } = E2EE._internal;

const ZERO32 = Buffer.alloc(32);
const FF32 = Buffer.alloc(32, 0xff);
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const PQXDH_LABEL = 'nyxo-e2ee-pqxdh-v1';
const CHAIN_LABEL = 'nyxo-e2ee-pw-chain-v2';

// Все пары X25519, созданные клиентами в этом процессе: публичный ключ (hex) -> закрытый ключ Node.
const privateByPub = new Map();
const realGenerateKey = subtle.generateKey.bind(subtle);
subtle.generateKey = async (algorithm, extractable, usages) => {
    if (!algorithm || algorithm.name !== 'X25519') return realGenerateKey(algorithm, extractable, usages);
    const pair = await realGenerateKey(algorithm, true, usages);   // только в тесте: клиент выпускает их невыгружаемыми
    const pub = Buffer.from(await subtle.exportKey('raw', pair.publicKey));
    const pkcs8 = Buffer.from(await subtle.exportKey('pkcs8', pair.privateKey));
    privateByPub.set(pub.toString('hex'), nodeCrypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' }));
    return pair;
};

function dh(privateHexPub, publicRaw) {
    const privateKey = privateByPub.get(Buffer.from(privateHexPub).toString('hex'));
    assert.ok(privateKey, 'закрытый ключ перехвачен');
    const publicKey = nodeCrypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(publicRaw)]), format: 'der', type: 'spki' });
    return nodeCrypto.diffieHellman({ privateKey, publicKey });
}
const hkdf = (ikm, info) => Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, ZERO32, info, 32));
const hmac = (key, byte) => nodeCrypto.createHmac('sha256', key).update(Buffer.from([byte])).digest();
// Цепочка после n шагов: ключ сообщения - HMAC(ck, 0x01), следующая цепочка - HMAC(ck, 0x02).
const advance = (ck, steps) => { let value = ck; for (let i = 0; i < steps; i++) value = hmac(value, 0x02); return value; };

// Alice (1) инициирует канал к Bob (2); bundle Bob правит mutate, ML-KEM оборачивается для перехвата общего секрета.
async function runHandshake({ mutate = () => {}, stripPqOneTime = false } = {}) {
    const server = makeRoom(100, [1, 2]);
    const bob = makeUser(server, 2);
    await bob.init();
    if (stripPqOneTime) server.evil.stripPqOneTime(2);

    let bundle = null;
    const transport = server.transportFor(1);
    const realGetBundle = transport.getBundle;
    transport.getBundle = async (id) => {
        const res = await realGetBundle(id);
        if (res.status === 200) { mutate(res.data); bundle = JSON.parse(JSON.stringify(res.data)); }
        return res;
    };
    let pqShared = null;
    const kem = {
        ...mlkem,
        encapsulate: async (publicKey) => {
            const result = await mlkem.encapsulate(publicKey);
            pqShared = Buffer.from(result.sharedSecret);
            return result;
        },
    };
    const alice = makeUser(server, 1, { transport, kem });
    await alice.init();
    await alice.ensureRoomSession(chatOf(1), 100, participantsOf(server, 100));
    assert.strictEqual((await bob.syncKeyShares(chatOf(2), 100)).applied, 1, 'Bob принял key-share');
    assert.ok(bundle && pqShared, 'bundle и секрет ML-KEM перехвачены');

    const send = await stored(alice, 'pw2Send:2');
    const recv = await stored(bob, 'pw2Recv:1');
    const identityA = await stored(alice, 'identity');
    return { bundle, pqShared, send, recv, identityA };
}

// Ожидаемая цепочка по независимой реализации.
function expectedChain({ bundle, pqShared, send, identityA }) {
    const ikA = b64decode(identityA.dhPub);
    const ikB = b64decode(bundle.identity_dh_key);
    const spkB = b64decode(bundle.signed_prekey.public_key);
    const opkB = bundle.one_time_prekey ? b64decode(bundle.one_time_prekey.public_key) : null;
    const ek = b64decode(send.header.senderEphemeralPub);
    const parts = [FF32, dh(ikA, spkB), dh(ek, ikB), dh(ek, spkB), opkB ? dh(ek, opkB) : Buffer.alloc(0), pqShared];
    const sk = hkdf(Buffer.concat(parts), PQXDH_LABEL);
    return { sk, ck0: hkdf(sk, CHAIN_LABEL), withOpk: Boolean(opkB), pqOneTime: Boolean(send.header.pqOneTime) };
}

(async () => {
    console.log('Контрольный вектор общего секрета PQXDH\n');

    const variants = [
        ['одноразовый prekey X25519 и одноразовый PQ-prekey', {}, { withOpk: true, pqOneTime: true }],
        ['без одноразового prekey X25519 (DH4 пуст)', { mutate: (b) => { b.one_time_prekey = null; } }, { withOpk: false, pqOneTime: true }],
        ['запасной PQ-prekey вместо одноразового', { stripPqOneTime: true }, { withOpk: true, pqOneTime: false }],
    ];
    for (const [title, options, shape] of variants) {
        await test(`${title}: сохранённые цепочки отправителя и получателя равны независимому расчёту`, async () => {
            const run = await runHandshake(options);
            const expected = expectedChain(run);
            assert.strictEqual(expected.withOpk, shape.withOpk, 'форма bundle');
            assert.strictEqual(expected.pqOneTime, shape.pqOneTime, 'форма PQ-prekey');
            assert.strictEqual(run.send.n, 1, 'отправитель использовал одно сообщение цепочки');
            assert.strictEqual(run.recv.n, 1, 'получатель использовал одно сообщение цепочки');
            const want = advance(expected.ck0, 1).toString('hex');
            assert.strictEqual(Buffer.from(b64decode(run.send.ck)).toString('hex'), want, 'цепочка отправителя');
            assert.strictEqual(Buffer.from(b64decode(run.recv.ck)).toString('hex'), want, 'цепочка получателя');
        });
    }

    await test('контроль расчёта: другая метка, другой порядок DH, без ML-KEM или без FF32 дают другой секрет (вектор различает эти поломки)', async () => {
        const run = await runHandshake();
        const ikA = b64decode(run.identityA.dhPub);
        const ek = b64decode(run.send.header.senderEphemeralPub);
        const spkB = b64decode(run.bundle.signed_prekey.public_key);
        const ikB = b64decode(run.bundle.identity_dh_key);
        const opkB = b64decode(run.bundle.one_time_prekey.public_key);
        const [dh1, dh2, dh3, dh4] = [dh(ikA, spkB), dh(ek, ikB), dh(ek, spkB), dh(ek, opkB)];
        const reference = hkdf(Buffer.concat([FF32, dh1, dh2, dh3, dh4, run.pqShared]), PQXDH_LABEL).toString('hex');
        const others = [
            hkdf(Buffer.concat([FF32, dh1, dh2, dh3, dh4, run.pqShared]), 'nyxo-e2ee-pqxdh-v2'),
            hkdf(Buffer.concat([FF32, dh1, dh3, dh2, dh4, run.pqShared]), PQXDH_LABEL),
            hkdf(Buffer.concat([FF32, dh1, dh2, dh3, dh4]), PQXDH_LABEL),
            hkdf(Buffer.concat([dh1, dh2, dh3, dh4, run.pqShared]), PQXDH_LABEL),
        ].map(value => value.toString('hex'));
        assert.ok(!others.includes(reference), 'измененный вход дал тот же секрет');
        assert.strictEqual(new Set(others).size, others.length);
    });

    finish();
})().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
