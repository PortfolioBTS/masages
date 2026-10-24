'use strict';
// Признак suspended в составе группы (T7.3, п.13 ревью W7 R3): участник, которого вы подтверждали и
// у которого потом сменился ключ, выпадает из V в отложенные (suspended:<комната>, 9.7). Интерфейс
// должен сказать о нём «ключ изменился после подтверждения», а не «вошёл без подписи» — для
// этого проверка состава и getMembers помечают таких участников suspended: true.
// «Призрак» (добавлен сервером, никто не подписывал) признака не получает.
// Запуск: node test/membership.suspended-flag.test.js

const { assert, makeWorld, test, finish, chatOf } = require('./membership-world');

const at = (user, room) => ({ ...user, room, chatId: chatOf(user.id, room) });
const memberOf = (result, id) => result.members.find(m => m.id === id);
const R2 = 200;

(async () => {
    console.log('Признак suspended в составе группы\n');

    async function scene() {
        const w = makeWorld();
        const alice = await w.addUser(1);
        const bob = await w.addUser(2);
        const carol = await w.addUser(3);
        await w.createRoom(alice); await w.approve(alice, bob); await w.ensure(alice);
        const carol2 = at(carol, R2);
        const alice2 = at(alice, R2);
        const bob2 = at(bob, R2);
        await w.createRoom(carol2); await w.approve(carol2, alice2); await w.approve(carol2, bob2);
        await w.ensure(carol2); await w.sync(alice2); await w.ensure(alice2);
        w.server.evil.addGhost(R2, 9, chatOf(9, R2));   // «призрак» без записи V
        await w.addUser(9);
        return { w, alice, bob, alice2, bob2 };
    }

    await test('смена ключа подтверждённого участника: suspended в members, unconfirmed и getMembers; у «призрака» признака нет', async () => {
        const { w, bob, alice2 } = await scene();
        const before = await w.ensure(alice2);
        assert.strictEqual(memberOf(before, bob.id).status, 'confirmed');
        assert.ok(!('suspended' in memberOf(before, bob.id)), 'подтверждённому признак не нужен');

        await w.addUser(2);                              // Боб сменил ключи; сервер показывает новые
        const during = await w.ensure(alice2);
        assert.strictEqual(memberOf(during, bob.id).status, 'unconfirmed');
        assert.strictEqual(memberOf(during, bob.id).suspended, true, 'выпавший из-за смены ключа помечен');
        assert.strictEqual(during.unconfirmed.find(u => u.id === bob.id).suspended, true);
        assert.strictEqual(memberOf(during, 9).status, 'unconfirmed');
        assert.ok(!('suspended' in memberOf(during, 9)), 'призрак без подписи — не suspended');
        assert.ok(!('suspended' in during.unconfirmed.find(u => u.id === 9)));

        // Сохранённый вид (окно участников без новой проверки) говорит то же.
        const stored = await alice2.client.getMembers(R2);
        assert.strictEqual(stored.find(m => m.id === bob.id).suspended, true);
        assert.ok(!('suspended' in stored.find(m => m.id === 9)));
        w.noViolations();
    });

    await test('после принятия нового ключа участник снова подтверждён и без признака; ушедший признак не оставляет', async () => {
        const { w, alice, bob, alice2 } = await scene();
        await w.ensure(alice2);
        await w.addUser(2);
        await w.ensure(alice2);
        assert.strictEqual(await alice.client.acceptPeerIdentityChange(bob.id), true);
        const after = memberOf(await w.ensure(alice2), bob.id);
        assert.strictEqual(after.status, 'confirmed');
        assert.ok(!('suspended' in after));
        assert.ok(!('suspended' in (await alice2.client.getMembers(R2)).find(m => m.id === bob.id)));

        await w.addUser(2);
        await w.ensure(alice2);
        w.server.removeParticipant(R2, bob.id);
        const left = await w.ensure(alice2);
        assert.ok(!left.members.some(m => m.id === bob.id));
        w.noViolations();
    });

    finish();
})();
