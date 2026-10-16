'use strict';
// Журнал только растёт, ключ журнала, самомониторинг и сплетни клиента (docs/security/key-transparency.md,
// 7.2, 7.4, 7.5, 11, 12, 13): переписанная история, двуличие, откат, длина поколения и льготный срок,
// неверная подпись, смена и потеря ключа журнала, чужое обязательство под моей меткой, «обещанное не
// опубликовано», потеря kt:self, головы журнала в SKDM. Сервер — fake-server с журналом и подменами.
// Запуск: node test/kt-client.log.test.js

const assert = require('assert');
const crypto = require('crypto');
const E2EE = require('../public/e2ee.js');
require('./membership-harness').install(E2EE);
const NyxoKt = require('../public/lib/kt.js');
const { makeWorld, statusOf, HOUR } = require('./kt-harness');
const { FakeKt, newLogKey } = require('./fake-kt');

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

const kinds = (user) => user.alerts.map(a => a.kind);
const alertOf = (user, kind) => user.alerts.find(a => a.kind === kind);

// Алиса с журналом, в котором закрыто n эпох; она их уже видела.
async function aliceSeeing(n, options) {
    const world = makeWorld(options);
    const alice = await world.addUser(1);
    await world.kt.closeEpochs(n);
    await alice.check();
    return { world, alice };
}

async function main() {
    // ===================== Журнал только растёт =====================

    await test('честный журнал: цепочка продолжается, поколения связаны, старые удаляются, тревог нет', async () => {
        const { world, alice } = await aliceSeeing(2);
        for (let i = 0; i < 16; i++) {
            await world.kt.closeEpoch();
            await alice.check();
        }
        assert.deepStrictEqual(alice.alerts, []);
        const gens = (await alice.storage.keys('kt:gen:')).sort();
        assert.deepStrictEqual(gens, ['kt:gen:2', 'kt:gen:3'], 'хранится текущее и предыдущее поколение, старше — удалено');
        const overview = await alice.client.checkTransparency();
        assert.strictEqual(overview.status, 'ok');
        assert.strictEqual(overview.self, 'ok');
    });

    await test('клиент пришёл в середине поколения (первая синхронизация): доверие к серверу, тревоги нет', async () => {
        const world = makeWorld();
        await world.kt.closeEpochs(9);
        const late = await world.addUser(1);
        await late.check();
        assert.deepStrictEqual(late.alerts, []);
        assert.ok((await late.storage.get('kt:gen:2')));
    });

    await test('голова журнала отстаёт от текущей эпохи на 3 и больше: предупреждение stale (один раз), не блокировка', async () => {
        const { world, alice } = await aliceSeeing(2);
        assert.deepStrictEqual(alice.alerts, []);
        world.advance(4 * HOUR); // журнал не обновляется, часы идут
        await alice.check();
        await alice.check();
        const stale = alice.alerts.filter(a => a.kind === 'stale');
        assert.strictEqual(stale.length, 1, 'одно предупреждение на значение эпохи');
        assert.ok(stale[0].behind >= 3);
        assert.deepStrictEqual(await alice.client.getTransparencyAlerts(), [], 'stale не хранится');
        assert.strictEqual((await alice.client.checkTransparency()).status, 'ok', 'не делает журнал несогласованным');
    });

    await test('переписанная история: корень прошлой эпохи заменён — log-fork', async () => {
        const { world, alice } = await aliceSeeing(3);
        await world.kt.rewrite(1, 40001);
        await world.kt.closeEpoch();
        await alice.check();
        const alert = alertOf(alice, 'log-fork');
        assert.ok(alert, kinds(alice).join());
        assert.strictEqual(alert.reason, 'chain-mismatch');
        assert.strictEqual((await alice.client.checkTransparency()).status, 'inconsistent');
    });

    await test('откат: сервер показывает голову старше уже виденной — log-fork с нашей подписанной головой', async () => {
        const { world, alice } = await aliceSeeing(4);
        world.kt.rollbackTo(1, 40001);
        await alice.check();
        // syncLog берётся из кэша, пока голова свежая; новая попытка — после паузы.
        world.advance(60 * 1000);
        await alice.check();
        const alert = alertOf(alice, 'log-fork');
        assert.ok(alert, kinds(alice).join());
        assert.strictEqual(alert.reason, 'rollback');
        assert.ok(alert.mine && alert.mine.sig && alert.theirs);
    });

    await test('две подписанные головы одной эпохи (база сброшена, ключ журнала прежний) — equivocation; длиннее — log-fork', async () => {
        const { world, alice } = await aliceSeeing(3);
        const reset = new FakeKt({ key: world.kt.key, genEpochs: 6, graceEpochs: 4 });
        await reset.closeEpochs(3);
        world.server = null;
        // Алиса теперь говорит с другой базой того же журнала.
        const original = alice.client;
        assert.ok(original);
        const ref = { model: reset };
        const swapped = await world.addUser(7, { roomId: 777, init: false, transport: {
            ktHead: async () => ref.model.head(), ktRoots: async (...a) => ref.model.roots(...a),
            ktProof: async (...a) => ref.model.proof(7, ...a), ktSelf: async (...a) => ref.model.self(7, ...a),
        } });
        // Клиент 7 с тем же состоянием, что у Алисы: копируем журнальные записи в его хранилище.
        for (const name of await alice.storage.keys('kt:')) await swapped.storage.set(name, await alice.storage.get(name));
        await swapped.check();
        assert.ok(swapped.alerts.some(a => a.kind === 'equivocation'), kinds(swapped).join());
        assert.strictEqual(alertOf(swapped, 'equivocation').reason, 'same-epoch');

        await reset.closeEpoch(); // новая база ушла дальше: цепочка Алисы с ней не сходится
        for (const name of await alice.storage.keys('kt:')) await swapped.storage.set(name, await alice.storage.get(name));
        await swapped.storage.delete('kt:alerts');
        world.advance(60 * 1000);
        await swapped.check();
        assert.strictEqual(alertOf(swapped, 'log-fork').reason, 'chain-mismatch');
    });

    await test('неверная подпись головы — bad-signature, ключ не закрепляется', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        world.kt.signWith = newLogKey(); // подписывает не тот ключ, чей pub отдаётся
        await world.kt.closeEpoch();
        await alice.check();
        assert.ok(kinds(alice).includes('bad-signature'));
        assert.deepStrictEqual(await alice.storage.get('kt:pub'), null, 'ключ с неверной подписью не закреплён');
        assert.strictEqual((await alice.client.checkTransparency()).status, 'inconsistent');
    });

    await test('поколение не той длины — log-fork generation-length; досрочное удаление предыдущего — grace-violated', async () => {
        const short = new FakeKt({ genEpochs: 5, graceEpochs: 4 }); // сервер укоротил поколение
        const world = makeWorld({ kt: short });
        const alice = await world.addUser(1);
        await short.closeEpochs(3);
        await alice.check();
        await short.closeEpochs(3); // началось второе поколение через 5, а не 6 эпох
        world.advance(60 * 1000);
        await alice.check();
        const alert = alertOf(alice, 'log-fork');
        assert.ok(alert, kinds(alice).join());
        assert.strictEqual(alert.reason, 'generation-length');

        // Досрочное удаление: клиент не дотянул предыдущее поколение, а сервер его уже не отдаёт.
        const world2 = makeWorld();
        const bob = await world2.addUser(1);
        await world2.kt.closeEpochs(3);
        await bob.check();
        await world2.kt.closeEpochs(4); // поколение 1 закончилось на эпохе 5, началось 2; клиент остановился на эпохе 2
        world2.kt.evil.earlyPurge = true;
        world2.advance(60 * 1000);
        await bob.check();
        assert.strictEqual(alertOf(bob, 'log-fork').reason, 'grace-violated');
    });

    await test('предыдущее поколение удалено после льготного срока: непрерывность потеряна без тревоги', async () => {
        const { world, alice } = await aliceSeeing(2);
        await world.kt.closeEpochs(10); // поколение 2 началось, и ещё больше четырёх эпох после его начала
        world.advance(60 * 1000);
        await alice.check();
        assert.deepStrictEqual(alice.alerts, []);
        assert.deepStrictEqual((await alice.storage.keys('kt:gen:')).sort(), ['kt:gen:2']);
    });

    // ===================== Ключ журнала (раздел 11) =====================

    await test('ключ журнала сменился без заявления: key-changed, принять можно только вручную; цепочки сбрасываются', async () => {
        const { world, alice } = await aliceSeeing(3);
        const before = await alice.storage.get('kt:pub');
        world.kt.rotateKey({ claim: false });
        await world.kt.closeEpoch();
        world.advance(60 * 1000);
        await alice.check();
        assert.strictEqual(alertOf(alice, 'key-changed').reason, 'no-claim');
        assert.deepStrictEqual(await alice.storage.get('kt:pub'), before, 'закреплённый ключ не изменился');
        const pending = await alice.client.getPendingLogKey();
        assert.strictEqual(pending.hex, Buffer.from(world.kt.key.pub).toString('hex'));
        assert.strictEqual((await alice.client.checkTransparency()).status, 'inconsistent');
        assert.strictEqual(await alice.client.acceptLogKey(), true, 'ручное принятие после сверки отпечатка');
        assert.deepStrictEqual((await alice.storage.get('kt:pub')).map(p => p.pub), [Buffer.from(world.kt.key.pub).toString('base64')]);
        assert.deepStrictEqual(await alice.storage.keys('kt:gen:'), [], 'сохранённые цепочки сброшены');
        world.advance(60 * 1000);
        await alice.check();
        assert.strictEqual((await alice.client.checkTransparency()).status, 'ok');
    });

    await test('смена ключа с заявлением, подписанным прежним ключом: принята; голова после смены под прежним ключом — bad-signature', async () => {
        const { world, alice } = await aliceSeeing(3);
        const { next } = world.kt.rotateKey({ claim: true });
        await world.kt.closeEpoch();
        world.advance(60 * 1000);
        await alice.check();
        assert.deepStrictEqual(alice.alerts, []);
        const pins = await alice.storage.get('kt:pub');
        assert.strictEqual(pins.length, 2);
        assert.strictEqual(pins[1].pub, Buffer.from(next.pub).toString('base64'));
        assert.deepStrictEqual(pins[1].from, { gen: 1, epoch: 40003 });

        const stale = await aliceSeeing(3);
        stale.world.kt.rotateKey({ claim: true, staleSigner: true });
        await stale.world.kt.closeEpoch();
        stale.world.advance(60 * 1000);
        await stale.alice.check();
        assert.ok(kinds(stale.alice).includes('bad-signature'), kinds(stale.alice).join());
    });

    await test('два разных заявления одним прежним ключом — equivocation (keychange); заявление задним числом — key-changed', async () => {
        const dual = await aliceSeeing(3);
        const { old } = dual.world.kt.rotateKey({ claim: true });
        dual.world.kt.conflictingClaim(old);
        await dual.world.kt.closeEpoch();
        dual.world.advance(60 * 1000);
        await dual.alice.check();
        const alert = alertOf(dual.alice, 'equivocation');
        assert.ok(alert, kinds(dual.alice).join());
        assert.strictEqual(alert.reason, 'keychange');
        assert.strictEqual(alert.claims.length, 2);

        const back = await aliceSeeing(4);
        back.world.kt.rotateKey({ claim: true, backdated: true });
        await back.world.kt.closeEpoch();
        back.world.advance(60 * 1000);
        await back.alice.check();
        assert.strictEqual(alertOf(back.alice, 'key-changed').reason, 'backdated');
    });

    await test('заявление с ключом малого порядка отвергается (key-changed bad-claim)', async () => {
        const { world, alice } = await aliceSeeing(3);
        const old = world.kt.key;
        const evilPub = new Uint8Array(Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex'));
        const epoch = world.kt.openEpoch;
        world.kt.keychanges.push({ oldPub: old.pub, newPub: evilPub, gen: 1, epoch, sig: old.sign(NyxoKt.keychangeMessage(evilPub, 1, epoch)) });
        world.kt.key = { pub: evilPub, sign: () => new Uint8Array(64) };
        await world.kt.closeEpoch();
        world.advance(60 * 1000);
        await alice.check();
        assert.strictEqual(alertOf(alice, 'key-changed').reason, 'bad-claim');
    });

    await test('ключ журнала при первом контакте сверяется с манифестом релиза: несовпадение — key-changed', async () => {
        const world = makeWorld();
        const other = newLogKey();
        const alice = await world.addUser(1, { clientOptions: { ktManifestKey: () => Buffer.from(other.pub).toString('base64') } });
        await world.kt.closeEpoch();
        await alice.check();
        assert.strictEqual(alertOf(alice, 'key-changed').reason, 'manifest');
        assert.strictEqual(await alice.storage.get('kt:pub'), null);
        const honest = makeWorld();
        const bob = await honest.addUser(1, { clientOptions: { ktManifestKey: () => Buffer.from(honest.kt.key.pub).toString('base64') } });
        await honest.kt.closeEpoch();
        await bob.check();
        assert.deepStrictEqual(bob.alerts, []);
    });

    // ===================== Самомониторинг (7.4) =====================

    await test('чужое обязательство под моей меткой в эпохе регистрации: self-foreign-entry с эпохой и временем создания identity', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        const injected = world.kt.injectEntry(1);
        await world.kt.closeEpoch();
        await alice.check();
        const alert = alertOf(alice, 'self-foreign-entry');
        assert.ok(alert, kinds(alice).join());
        assert.deepStrictEqual(alert.entries.map(e => e.c), [Buffer.from(injected).toString('hex')]);
        assert.strictEqual(alert.entries[0].epoch, 40000);
        assert.strictEqual(alert.identityCreatedHour, Math.floor(world.clock.t / HOUR));
        assert.strictEqual((await alice.client.checkTransparency()).self, 'alert');
    });

    await test('запись под моей меткой ДО моей регистрации: первый запуск сканирует весь сохранённый журнал', async () => {
        const world = makeWorld();
        const injected = world.kt.injectEntry(1);
        await world.kt.closeEpoch();
        await world.kt.closeEpoch();
        const alice = await world.addUser(1); // идентификаторы выдаёт сервер: запись могла появиться раньше регистрации
        await world.kt.closeEpoch();
        await alice.check();
        const alert = alertOf(alice, 'self-foreign-entry');
        assert.ok(alert, kinds(alice).join());
        assert.ok(alert.entries.some(e => e.c === Buffer.from(injected).toString('hex') && e.epoch === 40000));
    });

    await test('обещанное не опубликовано: self-missing с SKT; текущая регистрация не вызывает тревоги', async () => {
        const honest = makeWorld();
        const fine = await honest.addUser(1);
        await honest.kt.closeEpoch();
        await fine.check();
        assert.deepStrictEqual(fine.alerts, []);

        const world = makeWorld();
        await world.kt.closeEpoch(); // первая эпоха поколения переносит все ключи — обещание нарушается в следующей
        const alice = await world.addUser(1);
        world.kt.pending = []; // сервер выдал SKT и не включил обязательство
        await world.kt.closeEpoch();
        await alice.check();
        const alert = alertOf(alice, 'self-missing');
        assert.ok(alert, kinds(alice).join());
        assert.strictEqual(alert.reason, 'skt');
        assert.ok(alert.skt, 'SKT сохранён как доказательство');
    });

    await test('SKT в ответе на регистрацию с неверной подписью — bad-signature', async () => {
        const world = makeWorld();
        const original = world.kt.hintFor.bind(world.kt);
        world.kt.hintFor = (userId, options) => {
            const hint = original(userId, options);
            if (!hint || !hint.skt) return hint;
            const skt = Buffer.from(hint.skt, 'base64');
            skt[3] ^= 1;
            return { ...hint, skt: skt.toString('base64') };
        };
        const alice = await world.addUser(1);
        await world.kt.closeEpoch();
        await alice.check();
        assert.ok(alice.alerts.some(a => a.kind === 'bad-signature' && a.reason === 'own-skt'), kinds(alice).join());
    });

    await test('перенос в новое поколение: сервер не перенёс мой ключ — self-missing carry-over', async () => {
        const { world, alice } = await aliceSeeing(2);
        await world.kt.closeEpochs(4); // поколение 1 закончилось на эпохе 5
        world.kt.users.delete(1);      // дальше сервер «забывает» мой ключ при переносе
        await world.kt.closeEpoch();   // первая эпоха поколения 2
        world.advance(HOUR); // плановый самомониторинг: таймер раз в час, не чаще раза в 20 минут
        alice.client.startTransparency();
        await alice.scheduled.find(item => item.ms === HOUR).fn();
        const alert = alertOf(alice, 'self-missing');
        assert.ok(alert, kinds(alice).join());
        assert.strictEqual(alert.reason, 'carry-over');
        assert.strictEqual(alert.gen, 2);
    });

    await test('потеря kt:self: текущие ключи (nonce от сервера) тревоги не вызывают, прежние — вызывают; «мои прежние ключи» гасит', async () => {
        const world = makeWorld();
        // Прежние ключи аккаунта: зарегистрированы в журнале до того, как устройство потеряло данные.
        const old = {
            identity_signing_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
            identity_dh_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
        };
        world.kt.register(1, old);
        await world.kt.closeEpoch();
        const alice = await world.addUser(1); // новая установка: новая identity, регистрация меняет ключи
        await world.kt.closeEpoch();
        await alice.check();
        const alert = alertOf(alice, 'self-foreign-entry');
        assert.ok(alert, kinds(alice).join());
        assert.strictEqual(alert.entries.length, 1, 'чужим выглядит только обязательство прежних ключей');
        assert.strictEqual(alert.entries[0].epoch, 40000);
        // Пользователь подтверждает, что это его прежние ключи.
        await alice.client.ackSelfEntries(alert.entries);
        assert.deepStrictEqual((await alice.client.getTransparencyAlerts()).filter(a => a.kind === 'self-foreign-entry'), []);
        assert.strictEqual((await alice.client.checkTransparency()).self, 'ok');

        // Устройство очистило kt:self, сессия жива: свежий init подбирает nonce от сервера.
        await alice.storage.delete('kt:self');
        await alice.client.init();
        await world.kt.closeEpoch();
        world.advance(HOUR);
        await alice.check();
        const entries = (await alice.client.getTransparencyAlerts()).filter(a => a.kind === 'self-foreign-entry');
        assert.ok(entries.every(a => a.entries.every(e => e.epoch === 40000)), 'текущие ключи чужими не считаются');
    });

    await test('самомониторинг идёт раз в час (таймер) и не чаще раза в 20 минут', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.kt.closeEpochs(2);
        await alice.check();
        const scans = world.kt.calls.self;
        assert.ok(scans >= 1);
        await alice.check();
        assert.strictEqual(world.kt.calls.self, scans, 'повторный запуск сразу — без нового скана');
        alice.client.startTransparency();
        const tick = alice.scheduled.find(s => s.ms === HOUR);
        assert.ok(tick, 'плановая проверка раз в час');
        world.advance(HOUR);
        await world.kt.closeEpoch();
        await tick.fn();
        assert.ok(world.kt.calls.self > scans);
        alice.client.stopTransparency();
    });

    await test('проверка ключа заявителя до вступления (одобряющий): ok после закрытия эпохи, mismatch для чужого ключа', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        const applicant = await world.addUser(5, { roomId: 555 });
        await world.kt.closeEpoch();
        await alice.check();
        const hint = world.kt.hintFor(5);
        const real = world.server._signedPrekeys; // не нужен: ключи берём из identity заявителя
        assert.ok(real);
        const identity = await applicant.storage.get('identity');
        const good = await alice.client.checkApplicantKey(5, { signingKey: identity.signPub, dhKey: identity.dhPub, kt: hint });
        assert.strictEqual(good.status, 'ok');
        const wrong = await alice.client.checkApplicantKey(5, { signingKey: Buffer.alloc(32, 9).toString('base64'), dhKey: identity.dhPub, kt: hint });
        assert.strictEqual(wrong.status, 'mismatch');
        const none = await alice.client.checkApplicantKey(5, { signingKey: identity.signPub, dhKey: identity.dhPub, kt: null });
        assert.strictEqual(none.status, 'pending');
    });

    // ===================== Сплетни (7.5) =====================

    // Мир с двумя представлениями журнала: у Алисы своё, у Боба — развилка той же истории.
    async function gossipWorld() {
        const base = new FakeKt();
        const views = new Map();
        const forked = base.clone();
        const world = makeWorld({ kt: base, ktOf: (id) => views.get(id) || base, ktAll: [base, forked] });
        const alice = await world.addUser(1);
        const bob = await world.addUser(2);
        await base.closeEpochs(2);
        await forked.closeEpochs(2); // общая история до сих пор: корни эпох 0 и 1 уже разошлись из-за фиктивных записей
        return { world, base, forked, views, alice, bob };
    }

    await test('сплетни: совпадающие головы — тишина; SKDM несёт ext.kt, получатель сверяет голову по своей цепочке', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        const bob = await world.addUser(2);
        await world.kt.closeEpochs(2);
        await world.session(alice);
        await world.session(bob);
        assert.strictEqual((await world.sync(bob)).applied, 1);
        await bob.check();
        assert.deepStrictEqual(bob.alerts, []);
        // В SKDM Алисы уже есть её последняя голова (вторая отправка после обновления журнала).
        await world.kt.closeEpoch();
        await alice.check();
        const head = await alice.client.checkTransparency();
        assert.strictEqual(head.status, 'ok');
        const rotated = await alice.client.rotateRoomKey(100);
        assert.ok(rotated.senderKeyId);
        await world.session(alice);
        assert.strictEqual((await world.sync(bob)).applied, 1);
        await bob.check();
        assert.deepStrictEqual(bob.alerts, []);
    });

    await test('сплетни: верная подпись под иной головой той же эпохи — equivocation; пара «чужая подписанная голова, моя цепочка» сохранена', async () => {
        const { world, base, views, alice, bob } = await gossipWorld();
        const fork = base.clone();
        views.set(2, fork);
        await fork.closeEpoch(); // у Боба эпоха 2 закрыта иначе, чем у Алисы
        await base.closeEpoch();
        await alice.check(); // Алиса видит свою голову эпохи 2
        await bob.check();
        assert.deepStrictEqual(bob.alerts, []);
        await world.session(alice);
        await world.sync(bob);
        await bob.check();
        const alert = alertOf(bob, 'equivocation');
        assert.ok(alert, kinds(bob).join());
        assert.strictEqual(alert.reason, 'gossip');
        assert.ok(alert.theirs.s && alert.mine.s, 'обе подписанные головы сохранены');
    });

    await test('сплетни: SKDM пришёл позже — клиент уже ушёл вперёд, голова пересчитывается по локальной цепочке', async () => {
        const { world, base, views, alice, bob } = await gossipWorld();
        const fork = base.clone();
        views.set(2, fork);
        await fork.closeEpoch();
        await base.closeEpoch();
        await alice.check();
        await world.session(alice); // в SKDM голова эпохи 2 мира Алисы
        await fork.closeEpochs(3); // Боб ушёл вперёд по своему миру
        await bob.check();
        world.advance(60 * 1000);
        await world.sync(bob);
        await bob.check();
        assert.ok(kinds(bob).includes('equivocation'), kinds(bob).join());
    });

    await test('сплетни: подпись под головой не проходит ни одним закреплённым ключом — syncLog, затем key-split с доказательством', async () => {
        const { world, base, views, alice, bob } = await gossipWorld();
        const other = new FakeKt({ genEpochs: 6, graceEpochs: 4 }); // мир Боба подписан другим ключом журнала
        for (const [id, u] of base.users) other.users.set(id, { ...u });
        views.set(2, other);
        await other.closeEpochs(3);
        await bob.check(); // Боб закрепил другой ключ
        await base.closeEpoch();
        await alice.check();
        await world.session(alice);
        await world.sync(bob);
        await bob.check();
        const alert = alertOf(bob, 'key-split');
        assert.ok(alert, kinds(bob).join());
        assert.ok(alert.sent.s && alert.pinned.length === 1);
    });

    await test('сплетни: эпоха новее нашей, а сервер её не отдаёт — equivocation (behind)', async () => {
        const { world, base, views, alice, bob } = await gossipWorld();
        const fork = base.clone();
        views.set(2, fork);
        await base.closeEpochs(2); // мир Алисы ушёл на две эпохи вперёд; мир Боба (fork) стоит
        await alice.check();
        await bob.check();
        await world.session(alice);
        await world.sync(bob);
        await bob.check();
        const alert = alertOf(bob, 'equivocation');
        assert.ok(alert, kinds(bob).join());
        assert.strictEqual(alert.reason, 'behind');
    });

    await test('ext.kt в SKDM: испорченное поле или ext длиннее 2048 — поле отброшено, SKDM принят', async () => {
        const { parseSkdmExt, MAX_EXT_CHARS } = E2EE._internal;
        const good = { g: 1, e: 40001, h: Buffer.alloc(32, 1).toString('base64'), s: Buffer.alloc(64, 2).toString('base64') };
        assert.deepStrictEqual(parseSkdmExt({ kt: good }).kt, good);
        const warnings = [];
        const originalWarn = console.warn;
        console.warn = (...args) => warnings.push(args.join(' '));
        try {
            for (const broken of [{ ...good, g: 0 }, { ...good, h: 'AAAA' }, { ...good, s: 5 }, 'строка', [good], { ...good, e: -1 }, null]) {
                const ext = parseSkdmExt({ kt: broken });
                assert.ok(ext && !('kt' in ext), JSON.stringify(broken));
            }
            const bloated = parseSkdmExt({ kt: { ...good, pad: 'x'.repeat(MAX_EXT_CHARS) } });
            assert.ok(bloated && !('kt' in bloated), 'ext длиннее предела: kt отброшен');
            // prev по-прежнему строгий: испорченный prev отвергает SKDM целиком.
            assert.strictEqual(parseSkdmExt({ kt: good, prev: { id: 'x', final: 1 } }), null);
            assert.strictEqual(parseSkdmExt({ prev: { id: 'x'.repeat(MAX_EXT_CHARS) } }), null);
        } finally {
            console.warn = originalWarn;
        }
        assert.ok(warnings.length >= 8, 'предупреждения в консоли: ' + warnings.length);
        assert.deepStrictEqual(parseSkdmExt(undefined), {});
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
