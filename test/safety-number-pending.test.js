'use strict';
// Код безопасности при «ключ изменился» (повторное ревью W7, RR-0).
//
// Окно «Участники и ключи» для участника со сменившимся ключом просит сверить код безопасности и только потом нажимать
// «Принять новый ключ». Код поэтому обязан считаться по НОВОМУ (pending) ключу — тому, о котором решает пользователь:
//   * подмена ключа сервером: настоящий собеседник держит прежний ключ, его код с новым ключом не совпадает → видно;
//   * честная переустановка: код нового устройства совпадает с показанным → ключ можно принять.
// Раньше getSafetyNumber считал код по закреплённому (прежнему) ключу — и сверка работала наоборот: при подмене код
// совпадал, при честной смене — нет.
// Запуск: node test/safety-number-pending.test.js

const { assert, makeWorld, test, finish } = require('./membership-world');

async function twoPeers() {
    const w = makeWorld();
    const alice = await w.addUser(1);
    const bob = await w.addUser(2);
    await w.addUser(9);
    await w.createRoom(alice);
    await w.approve(alice, bob);
    await w.ensure(alice); await w.sync(bob); await w.ensure(bob); await w.sync(alice);
    await bob.client.checkPeerIdentities([1]);
    return { w, alice, bob };
}

(async () => {
    await test('подмена ключа сервером: код у Алисы считается по новому ключу и НЕ совпадает с кодом настоящего Боба', async () => {
        const { w, alice, bob } = await twoPeers();
        const before = await alice.client.getSafetyNumber(2);
        assert.strictEqual(before, await bob.client.getSafetyNumber(1), 'до подмены коды совпадают');
        w.server.evil.impersonate(2, 9);
        await w.ensure(alice);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'changed');
        const shown = await alice.client.getSafetyNumber(2);
        assert.ok(typeof shown === 'string' && shown.length > 0, 'код не показан');
        assert.notStrictEqual(shown, before, 'показан код прежнего ключа');
        assert.notStrictEqual(shown, await bob.client.getSafetyNumber(1), 'код совпал с устройством настоящего Боба — подмену не увидеть');
    });

    await test('честная переустановка: код у Алисы совпадает с кодом нового устройства Боба', async () => {
        const { w, alice } = await twoPeers();
        const bobNew = await w.addUser(2);
        await w.ensure(alice);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'changed');
        await bobNew.client.checkPeerIdentities([1]);
        assert.strictEqual(await alice.client.getSafetyNumber(2), await bobNew.client.getSafetyNumber(1));
    });

    await test('после «Принять новый ключ» код тот же, что показывался до принятия', async () => {
        const { w, alice } = await twoPeers();
        const bobNew = await w.addUser(2);
        await w.ensure(alice);
        const shown = await alice.client.getSafetyNumber(2);
        await alice.client.acceptPeerIdentityChange(2);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'unverified');
        assert.strictEqual(await alice.client.getSafetyNumber(2), shown);
        await bobNew.client.checkPeerIdentities([1]);
        assert.strictEqual(shown, await bobNew.client.getSafetyNumber(1));
    });

    finish();
})().catch((err) => { console.error(err); process.exitCode = 1; });
