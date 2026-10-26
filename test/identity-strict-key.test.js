'use strict';
// Ключ подписи собеседника от сервера закрепляется только после строгой проверки (ревью R4 W7, З6): fetchServerIdentities
// использовал canonicalPubKey (длина и не нули) вместо canonicalSigningKey (плюс строгая проверка Ed25519: малый порядок,
// неканоническая точка). Слабый ключ закреплялся при первом контакте (TOFU), и подписи под ним принимались бы как подписи
// "собеседника". Теперь такая запись сервера игнорируется, как если бы identity не было.
// Запуск: node test/identity-strict-key.test.js

const { assert, E2EE, mlkem, makeFakeServer, test, finish, HOUR } = require('./membership-world');

const SMALL_ORDER = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]).toString('base64');   // нейтральная точка: порядок 1

async function pair(mutate) {
    const server = makeFakeServer();
    const clock = { t: Date.UTC(2027, 0, 15, 12, 0, 0), now() { return this.t; } };
    const base = server.transportFor(1);
    const transport = new Proxy(base, {
        get(target, name) {
            if (name !== 'getIdentities') return target[name];
            return async (ids) => {
                const res = await target.getIdentities(ids);
                if (res && res.data && Array.isArray(res.data.identities)) res.data.identities.forEach(mutate);
                return res;
            };
        },
    });
    const storage = new E2EE.MemoryStorage();
    const alice = E2EE.createClient({ userId: 1, storage, kem: mlkem, now: () => clock.t, transport });
    const bob = E2EE.createClient({ userId: 2, storage: new E2EE.MemoryStorage(), kem: mlkem, now: () => clock.t, transport: server.transportFor(2) });
    await alice.init();
    await bob.init();
    server.addParticipant(100, 1, 11);
    server.addParticipant(100, 2, 21);
    return { alice, storage, server, HOUR };
}

(async () => {
    console.log('Строгая проверка ключа подписи собеседника (З6)\n');

    await test('честный ответ: ключ закрепляется (контроль)', async () => {
        const { alice, storage } = await pair(() => {});
        await alice.checkPeerIdentities([2]);
        const pin = await storage.get('peer:2');
        assert.ok(pin && pin.signPub, 'закреплён');
    });

    await test('сервер выдал ключ подписи малого порядка: не закрепляется, участник - "ключей нет"', async () => {
        const { alice, storage } = await pair((item) => { if (Number(item.user_id) === 2) item.identity_signing_key = SMALL_ORDER; });
        const statuses = await alice.checkPeerIdentities([2]);
        assert.strictEqual(await storage.get('peer:2'), null, 'слабый ключ не закреплён');
        assert.ok(!statuses.some(s => s.userId === 2 && s.status === 'verified'), JSON.stringify(statuses));
    });

    finish();
})().catch((err) => { console.error(err); process.exitCode = 1; });
