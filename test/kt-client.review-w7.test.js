'use strict';
// Повторное ревью криптографии, волна 7 (R4), часть про журнал ключей (key-transparency.md):
//   F2  сервер ответами 5xx / kt-not-ready не держит подменённый ключ собеседника в pending бессрочно (7.3, п. 2 и 6);
//       4xx на /api/kt/head, кроме оговорённых, - тревога, а не сетевая ошибка;
//   F3  404 на /api/kt/self не гасит самомониторинг молча (7.4);
//   З4  тревога key-split записывает отправителя ext.kt (7.5).
// Запуск: node test/kt-client.review-w7.test.js

const assert = require('assert');
const { makeWorld, statusOf, HOUR } = require('./kt-harness');
const { FakeKt } = require('./fake-kt');

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

const noViolations = (world) => assert.deepStrictEqual(world.lockViolations, [], 'сеть внутри withLock: ' + world.lockViolations.join(', '));
const sharesTo = (world, recipientId, senderId) => world.server._keyShares.filter(s => s.recipientId === recipientId && s.senderId === senderId).length;

// Алиса видела журнал; новый собеседник Дэн (4) выдан сервером под ключами атакующего (3), доказательства для них нет.
async function substitutedPeer(breakHead) {
    const world = makeWorld();
    const alice = await world.addUser(1);
    await world.addUser(2);
    await world.addUser(3, { roomId: 999 });        // 3 - учётная запись атакующего
    await world.kt.closeEpoch();
    await world.session(alice);                      // kt:pub появился: журнал виден
    await world.addUser(4);
    world.server.evil.impersonate(4, 3);
    world.kt.evil.hideHint.add(4);
    breakHead(world);
    return { world, alice };
}

// Часы идут, эпохи на сервере закрываются, клиент заходит в комнату каждый час и отрабатывает таймеры повтора.
async function liveHours(world, alice, hours) {
    let last = null;
    for (let h = 0; h < hours; h++) {
        world.advance(HOUR);
        if (h % 2 === 0) await world.kt.closeEpoch();
        last = await world.session(alice);
        for (const item of alice.scheduled.splice(0)) await item.fn();
    }
    return last;
}

async function main() {
    console.log('Ревью W7 R4: журнал ключей\n');

    // ===================== F2: pending не бессрочный при недоступном журнале =====================

    for (const [mode, breakHead] of [
        ['503 kt-not-ready', (world) => { world.kt.evil.notReady = true; }],
        ['5xx на /api/kt/head', (world) => { world.kt.head = () => ({ status: 500, data: { success: false } }); }],
        ['429 на /api/kt/head', (world) => { world.kt.head = () => ({ status: 429, data: { success: false } }); }],
    ]) {
        await test(`F2: ${mode} при уже виденном журнале - подменённый ключ через 4 часа mismatch (kt-unreachable), не pending навсегда`, async () => {
            const { world, alice } = await substitutedPeer(breakHead);
            await world.session(alice);
            assert.strictEqual((await statusOf(alice, 4)).status, 'pending', 'в первый час - ожидание, ключ комнаты уходит как при ok (7.3)');
            const before = sharesTo(world, 4, 1);
            assert.ok(before > 0);
            const early = await liveHours(world, alice, 3);
            assert.strictEqual((await statusOf(alice, 4)).status, 'pending', 'до 4 часов - всё ещё pending');
            assert.deepStrictEqual(early.logMismatches, []);
            const late = await liveHours(world, alice, 2);
            const kt = await statusOf(alice, 4);
            assert.strictEqual(kt.status, 'mismatch');
            assert.strictEqual(kt.reason, 'kt-unreachable');
            assert.deepStrictEqual(late.logMismatches.map(m => m.userId), [4], 'исключён из рассылки');
            assert.strictEqual(await alice.client.getPeerIdentityStatus(4), 'log-mismatch');
            // Дальнейшая рассылка ему не идёт: ключ комнаты ротирован, новый ключ подменённому ключу не отправляется.
            const after = sharesTo(world, 4, 1);
            await liveHours(world, alice, 6);
            assert.strictEqual(sharesTo(world, 4, 1), after, 'после mismatch новых key-share на подменённый ключ нет');
            noViolations(world);
        });
    }

    await test('F2: журнал вернулся и подтвердил ключ - mismatch kt-unreachable снимается (status ok)', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        const carol = await world.addUser(3);
        void carol;
        world.kt.evil.notReady = true;
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 3)).status, 'pending');
        await liveHours(world, alice, 5);
        assert.strictEqual((await statusOf(alice, 3)).reason, 'kt-unreachable');
        world.kt.evil.notReady = false;
        await world.kt.closeEpoch();
        await liveHours(world, alice, 2);
        assert.strictEqual((await statusOf(alice, 3)).status, 'ok', 'честный ключ с доказательством в журнале проходит');
        noViolations(world);
    });

    await test('F2: 4xx на /api/kt/head у клиента, видевшего журнал, - тревога log-disabled, а не тихий повтор; 401 и 429 - сеть', async () => {
        const { world, alice } = await substitutedPeer((w) => { w.kt.head = () => ({ status: 403, data: { success: false } }); });
        await world.session(alice);
        const alerts = await alice.client.getTransparencyAlerts();
        const alert = alerts.find(a => a.kind === 'log-disabled');
        assert.ok(alert, 'тревога log-disabled');
        assert.strictEqual(alert.status, 403);
        assert.strictEqual((await alice.client.checkTransparency()).status, 'inconsistent');
        for (const status of [401, 429]) {
            const second = await substitutedPeer((w) => { w.kt.head = () => ({ status, data: { success: false } }); });
            await second.world.session(second.alice);
            assert.ok(!(await second.alice.client.getTransparencyAlerts()).some(a => a.kind === 'log-disabled'), String(status));
        }
    });

    // ===================== F3: самомониторинг и ответы /api/kt/self =====================

    // Транспорт Алисы: всё как у сервера, кроме /api/kt/self - им управляет тест через ctl.self(gen).
    function selfWorld() {
        const world = makeWorld();
        const base = world.server.transportFor(1);
        const ctl = { self: null };
        const transport = new Proxy(base, {
            get(target, name) {
                if (name === 'ktSelf') {
                    return async (gen, from, limit) => {
                        const forced = ctl.self ? ctl.self(gen) : null;
                        return forced || target.ktSelf(gen, from, limit);
                    };
                }
                return target[name];
            },
        });
        return { world, ctl, transport };
    }

    // stale - информационное предупреждение (голова журнала давно не двигалась), в хранилище не пишется.
    const alertKinds = (user) => user.alerts.map(a => a.kind).filter(kind => kind !== 'stale');
    const selfState = (user) => user.storage.get('kt:self');
    const notFound = { status: 404, data: { success: false, code: 'kt-not-found' } };

    await test('F3: честный сервер - чужое обязательство под моей меткой даёт self-foreign-entry (контроль сценария)', async () => {
        const { world, transport } = selfWorld();
        const alice = await world.addUser(1, { transport });
        await world.addUser(2);
        world.kt.injectEntry(1);
        await world.kt.closeEpoch();
        await alice.check();
        assert.ok(alertKinds(alice).includes('self-foreign-entry'));
        assert.strictEqual((await alice.client.checkTransparency()).self, 'alert');
    });

    await test('F3: 404 на /api/kt/self для ТЕКУЩЕГО поколения - тревога log-fork grace-violated, скан не считается успешным', async () => {
        const { world, ctl, transport } = selfWorld();
        const alice = await world.addUser(1, { transport });
        await world.addUser(2);
        world.kt.injectEntry(1);                    // чужое обязательство, которое 404 и прячет
        await world.kt.closeEpoch();
        ctl.self = () => notFound;
        for (let i = 0; i < 3; i++) {
            await alice.check();
            for (const item of alice.scheduled.splice(0)) await item.fn();
        }
        const fork = alice.alerts.find(a => a.kind === 'log-fork');
        assert.ok(fork, 'тревога: ' + alertKinds(alice).join());
        assert.strictEqual(fork.reason, 'grace-violated');
        assert.strictEqual(fork.gen, 1);
        const state = await selfState(alice);
        assert.ok(!state || !state.lastScanAt, 'lastScanAt не обновляется, как после успеха');
        assert.ok(!state || !state.scanned, 'прогресс скана не двигается');
        const t = await alice.client.checkTransparency();
        assert.strictEqual(t.status, 'inconsistent');
        assert.strictEqual(t.self, 'alert', 'самопроверка не выполнена: self не unknown и не ok');
    });

    await test('F3: 404 на предыдущее поколение в пределах льготного срока - тревога; после срока - тихий пропуск (как раньше)', async () => {
        for (const [closed, expectAlert] of [[5, true], [10, false]]) {
            const { world, ctl, transport } = selfWorld();
            const alice = await world.addUser(1, { transport });
            await world.addUser(2);
            await world.kt.closeEpochs(3);
            await alice.check();                    // Алиса просканировала начало поколения 1
            ctl.self = (gen) => (gen === 1 ? notFound : null);
            await world.kt.closeEpochs(closed);      // поколение 1 закончилось на эпохе 5; поколение 2 идёт
            world.advance(60 * 60 * 1000);
            alice.client.startTransparency();         // плановая проверка раз в час запрашивает самомониторинг
            await alice.scheduled.find(item => item.ms === HOUR).fn();
            const forks = alice.alerts.filter(a => a.kind === 'log-fork');
            assert.strictEqual(forks.length > 0, expectAlert, 'закрыто ' + closed + ': ' + alertKinds(alice).join());
            if (expectAlert) assert.strictEqual(forks[0].reason, 'grace-violated');
        }
    });

    await test('F3: затяжной сбой /api/kt/self (5xx) дольше 6 часов - тревога self-unreachable, self = alert; после восстановления тревога снимается', async () => {
        const { world, ctl, transport } = selfWorld();
        const alice = await world.addUser(1, { transport });
        await world.addUser(2);
        world.kt.injectEntry(1);
        await world.kt.closeEpoch();
        ctl.self = () => ({ status: 503, data: { success: false } });
        for (let h = 0; h < 5; h++) {
            await alice.check();
            for (const item of alice.scheduled.splice(0)) await item.fn();
            world.advance(HOUR);
        }
        assert.ok(!alertKinds(alice).includes('self-unreachable'), 'до 6 часов тревоги нет: ' + alertKinds(alice).join());
        assert.strictEqual((await selfState(alice)).lastScanAt, 0);
        for (let h = 0; h < 3; h++) {
            await alice.check();
            for (const item of alice.scheduled.splice(0)) await item.fn();
            world.advance(HOUR);
        }
        assert.ok(alertKinds(alice).includes('self-unreachable'), alertKinds(alice).join());
        assert.strictEqual((await alice.client.checkTransparency()).self, 'alert', 'self не unknown молча');
        // Сервер ответил: скан прошёл, чужая запись найдена, тревога о недоступности снята.
        ctl.self = null;
        await alice.check();
        assert.ok(alertKinds(alice).includes('self-foreign-entry'));
        assert.ok(!(await alice.client.getTransparencyAlerts()).some(a => a.kind === 'self-unreachable'));
        assert.ok((await selfState(alice)).lastScanAt > 0);
    });

    await test('F3: короткий сбой /api/kt/self (меньше 6 часов) тревоги не даёт', async () => {
        const { world, ctl, transport } = selfWorld();
        const alice = await world.addUser(1, { transport });
        await world.kt.closeEpoch();
        ctl.self = () => ({ status: 503, data: { success: false } });
        await alice.check();
        world.advance(2 * HOUR);
        await alice.check();
        ctl.self = null;
        world.advance(HOUR);
        await alice.check();
        assert.deepStrictEqual(alertKinds(alice), []);
        assert.ok((await selfState(alice)).lastScanAt > 0);
    });

    // ===================== Повторное ревью W7 (клиент): RR-1, RR-2 =====================

    // Транспорт Алисы с фильтром ответа /api/kt/self: ctl.filter(res) получает настоящий ответ сервера.
    function filteredSelfWorld() {
        const world = makeWorld();
        const base = world.server.transportFor(1);
        const ctl = { filter: null };
        const transport = new Proxy(base, {
            get(target, name) {
                if (name === 'ktSelf') {
                    return async (gen, from, limit) => {
                        const res = await target.ktSelf(gen, from, limit);
                        return ctl.filter ? ctl.filter(res, { gen, from, limit }) : res;
                    };
                }
                return target[name];
            },
        });
        return { world, ctl, transport };
    }

    // RR-1: F3 обходился ответом 200 с пустым (или обрезанным) списком доказательств: цикл выходил, «как будто эпохи
    // кончились», скан засчитывался успешным, а эпоха с чужим обязательством не проверялась никогда.
    for (const [mode, filter] of [
        ['пустой список (200, proofs: [], next: null)', () => ({ status: 200, data: { success: true, proofs: [], next: null } })],
        ['обрезанный список (честные доказательства до эпохи с чужой записью, next: null)', (res) => {
            const proofs = res.data.proofs;
            return res.data.next === null && proofs.length > 0 ? { status: 200, data: { ...res.data, proofs: proofs.slice(0, -1), next: null } } : res;
        }],
    ]) {
        await test(`RR-1: ${mode} на /api/kt/self - тревога log-fork self-incomplete, self не ok, скан не засчитан`, async () => {
            const { world, ctl, transport } = filteredSelfWorld();
            const alice = await world.addUser(1, { transport });
            await world.addUser(2);
            await world.kt.closeEpochs(2);
            world.kt.injectEntry(1);
            await world.kt.closeEpoch();
            ctl.filter = filter;
            await alice.check();
            for (const item of alice.scheduled.splice(0)) await item.fn();
            const fork = alice.alerts.find(a => a.kind === 'log-fork');
            assert.ok(fork, 'тревога: ' + alertKinds(alice).join());
            assert.strictEqual(fork.reason, 'self-incomplete');
            assert.strictEqual(fork.gen, 1);
            const t = await alice.client.checkTransparency();
            assert.strictEqual(t.status, 'inconsistent');
            assert.strictEqual(t.self, 'alert');
            const state = await selfState(alice);
            assert.ok(!state || !state.lastScanAt, 'lastScanAt не обновляется, как после успеха');
            noViolations(world);
        });
    }

    await test('RR-1: честный сервер с несколькими страницами доказательств - тревоги нет, скан засчитан (контроль)', async () => {
        const { world, transport } = filteredSelfWorld();
        const alice = await world.addUser(1, { transport });
        await world.addUser(2);
        await world.kt.closeEpochs(5);
        await alice.check();
        assert.deepStrictEqual(alertKinds(alice), []);
        assert.ok((await selfState(alice)).lastScanAt > 0);
    });

    // RR-2: F2 и self-unreachable обходились зависшим запросом журнала: ни kt-client call(), ни fetch-транспорт не
    // ограничены по времени, runKtChecks склеивал все следующие вызовы в тот же зависший проход, и подменённый ключ
    // оставался pending бессрочно — ключ комнаты уходил на него.
    const hang = () => new Promise(() => {});
    const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    // Таймеры клиента не держат процесс (unref), а «зависший» ответ — просто невыполняемое обещание: без этого таймера
    // Node завершился бы посреди теста, решив, что работы больше нет.
    const keepAlive = setInterval(() => {}, 60 * 1000);

    await test('RR-2: зависший /api/kt/head - каждый вызов журнала ограничен по времени: через 4 часа mismatch kt-unreachable, рассылка прекращена', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1, { clientOptions: { ktCallTimeoutMs: 20, ktWaitMs: 2000 } });
        await world.addUser(2);
        await world.addUser(3, { roomId: 999 });
        await world.kt.closeEpoch();
        await world.session(alice);
        await world.addUser(4);
        world.server.evil.impersonate(4, 3);
        world.kt.evil.hideHint.add(4);
        world.kt.head = hang;
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        // Проход проверок заканчивается (вызов журнала прерван тайм-аутом), а не висит, склеивая все следующие вызовы.
        const finished = await Promise.race([alice.client.runKtChecks().then(() => 'done'), delay(1000).then(() => 'hung')]);
        assert.strictEqual(finished, 'done', 'проход проверок завершился');
        await liveHours(world, alice, 3);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending', 'до 4 часов - pending');
        const late = await liveHours(world, alice, 2);
        const kt = await statusOf(alice, 4);
        assert.strictEqual(kt.status, 'mismatch');
        assert.strictEqual(kt.reason, 'kt-unreachable');
        assert.deepStrictEqual(late.logMismatches.map(m => m.userId), [4]);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(4), 'log-mismatch');
        const after = sharesTo(world, 4, 1);
        await liveHours(world, alice, 3);
        assert.strictEqual(sharesTo(world, 4, 1), after, 'новых key-share на подменённый ключ нет');
        noViolations(world);
    });

    await test('RR-2: проход проверок завис совсем (сеть без ответа дольше теста) - правило «pending дольше 4 часов» срабатывает локально, без сети', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1, { clientOptions: { ktCallTimeoutMs: 10 * 60 * 1000, ktWaitMs: 20 } });
        await world.addUser(2);
        await world.addUser(3, { roomId: 999 });
        await world.kt.closeEpoch();
        await world.session(alice);
        await world.addUser(4);
        world.server.evil.impersonate(4, 3);
        world.kt.evil.hideHint.add(4);
        world.kt.head = hang;
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        const late = await liveHours(world, alice, 5);
        assert.deepStrictEqual(late.logMismatches.map(m => m.userId), [4], 'исключён из рассылки по локальным часам');
        assert.strictEqual(await alice.client.getPeerIdentityStatus(4), 'log-mismatch');
        assert.strictEqual((await statusOf(alice, 4)).reason, 'kt-unreachable');
    });

    await test('RR-2: зависший /api/kt/self дольше 6 часов - тревога self-unreachable; отсчёт идёт с начала попытки', async () => {
        const { world, ctl, transport } = selfWorld();
        const alice = await world.addUser(1, { transport, clientOptions: { ktCallTimeoutMs: 20 } });
        await world.addUser(2);
        await world.kt.closeEpoch();
        ctl.self = hang;
        const bounded = (promise) => Promise.race([promise, delay(1000)]);
        await bounded(alice.check());
        for (let h = 0; h < 7; h++) {
            world.advance(HOUR);
            await bounded(alice.check());
            for (const item of alice.scheduled.splice(0)) await bounded(item.fn());
        }
        assert.ok(alertKinds(alice).includes('self-unreachable'), alertKinds(alice).join());
        assert.strictEqual((await alice.client.checkTransparency()).self, 'alert');
        ctl.self = null;
        world.advance(HOUR);
        await alice.check();
        assert.ok(!(await alice.client.getTransparencyAlerts()).some(a => a.kind === 'self-unreachable'), 'после ответа тревога снята');
    });

    await test('RR-2: срок самомониторинга идёт с начала попытки - даже если проход проверок завис и не вернулся', async () => {
        const { world, ctl, transport } = selfWorld();
        const alice = await world.addUser(1, { transport, clientOptions: { ktCallTimeoutMs: 10 * 60 * 1000 } });
        await world.addUser(2);
        await world.kt.closeEpoch();
        ctl.self = hang;
        await Promise.race([alice.check(), delay(300)]);
        assert.ok((await selfState(alice)).failSince > 0, 'попытка начата - отсчёт идёт, хотя ответа нет');
    });

    clearInterval(keepAlive);

    // ===================== З4: отправитель сплетни записывается в доказательство =====================

    async function gossipWorld() {
        const base = new FakeKt();
        const views = new Map();
        const forked = base.clone();
        const world = makeWorld({ kt: base, ktOf: (id) => views.get(id) || base, ktAll: [base, forked] });
        const alice = await world.addUser(1);
        const bob = await world.addUser(2);
        await base.closeEpochs(2);
        await forked.closeEpochs(2);
        return { world, base, views, alice, bob };
    }

    await test('З4: key-split и equivocation по сплетне несут отправителя ext.kt', async () => {
        const split = await gossipWorld();
        const other = new FakeKt({ genEpochs: 6, graceEpochs: 4 });      // мир Боба подписан другим ключом журнала
        for (const [id, u] of split.base.users) other.users.set(id, { ...u });
        split.views.set(2, other);
        await other.closeEpochs(3);
        await split.bob.check();
        await split.base.closeEpoch();
        await split.alice.check();
        await split.world.session(split.alice);
        await split.world.sync(split.bob);
        await split.bob.check();
        const keySplit = split.bob.alerts.find(a => a.kind === 'key-split');
        assert.ok(keySplit, split.bob.alerts.map(a => a.kind).join());
        assert.strictEqual(keySplit.sender, 1, 'кто прислал подпись, которую мы не можем проверить');

        const fork = await gossipWorld();
        const clone = fork.base.clone();
        fork.views.set(2, clone);
        await clone.closeEpoch();
        await fork.base.closeEpoch();
        await fork.alice.check();
        await fork.bob.check();
        await fork.world.session(fork.alice);
        await fork.world.sync(fork.bob);
        await fork.bob.check();
        const equivocation = fork.bob.alerts.find(a => a.kind === 'equivocation');
        assert.ok(equivocation);
        assert.strictEqual(equivocation.sender, 1);
    });

    await test('З4: один участник не заводит много тревог key-split подряд (по одной на отправителя), чужие тревоги не вытесняются', async () => {
        const { world, base, views, alice, bob } = await gossipWorld();
        const other = new FakeKt({ genEpochs: 6, graceEpochs: 4 });
        for (const [id, u] of base.users) other.users.set(id, { ...u });
        views.set(2, other);
        await other.closeEpochs(3);
        await bob.check();
        for (let i = 0; i < 4; i++) {
            await base.closeEpoch();
            await alice.check();
            await alice.client.rotateRoomKey(100);   // каждая ротация кладёт в SKDM свежую голову Алисы (другая эпоха)
            await world.session(alice);
            await world.sync(bob);
            world.advance(60 * 1000);
            await bob.check();
        }
        const splits = bob.alerts.filter(a => a.kind === 'key-split');
        assert.strictEqual(splits.length, 1, 'тревог key-split: ' + splits.length);
        assert.strictEqual(splits[0].sender, 1);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exitCode = 1; });
