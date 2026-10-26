'use strict';
// Проверка ключей собеседников по журналу (docs/security/key-transparency.md, 7.3, 7.6, 12, 13):
// ok / pending / mismatch / unavailable, обход через «недоступно» (ревью К1, блокер) и ответ kt: null,
// сетевая ошибка не равна «нет доказательства», сеть вне withLock (К6), исключение mismatch из рассылки
// и ротация ключа комнаты по статусу, overrideLogMismatch и markPeerVerified.
// Сервер здесь — fake-server с журналом (test/fake-kt.js) и методами злонамеренного сервера.
// Запуск: node test/kt-client.protocol.test.js

const assert = require('assert');
const { makeWorld, statusOf, HOUR } = require('./kt-harness');

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

// Алиса и Боб в одной комнате, обе identity зарегистрированы в открытой эпохе.
async function pair(options) {
    const world = makeWorld(options);
    const alice = await world.addUser(1);
    const bob = await world.addUser(2);
    return { world, alice, bob };
}

const noViolations = (world) => assert.deepStrictEqual(world.lockViolations, [], 'сеть внутри withLock: ' + world.lockViolations.join(', '));

async function main() {
    await test('клиент, никогда не видевший журнал: unavailable без блокировки, ключ комнаты уходит как раньше', async () => {
        const { world, alice, bob } = await pair();
        const result = await world.session(alice); // ни одна эпоха ещё не закрыта: /api/kt/head отвечает 503
        assert.strictEqual((await statusOf(alice, 2)).status, 'unavailable');
        assert.deepStrictEqual(result.warnings, []);
        assert.strictEqual((await world.sync(bob)).applied, 1, 'ключ комнаты доставлен');
        const overview = await alice.client.checkTransparency();
        assert.strictEqual(overview.status, 'unavailable');
        assert.deepStrictEqual(alice.alerts, []);
        noViolations(world);
    });

    await test('журнал выключен на сервере с самого начала: unavailable, тревог нет, работа не блокируется', async () => {
        const { world, alice, bob } = await pair();
        world.kt.evil.disabled = true;
        await world.kt.closeEpochs(2);
        const result = await world.session(alice);
        assert.strictEqual((await statusOf(alice, 2)).status, 'unavailable');
        assert.strictEqual(result.logMismatches.length, 0);
        assert.strictEqual((await world.sync(bob)).applied, 1);
        assert.deepStrictEqual(alice.alerts, []);
        assert.strictEqual((await alice.client.checkTransparency()).status, 'unavailable');
    });

    await test('ключ в журнале после закрытия эпохи: ok; идентичность без изменений не перепроверяется', async () => {
        const { world, alice } = await pair();
        await world.kt.closeEpoch();
        await world.session(alice);
        const kt = await statusOf(alice, 2);
        assert.strictEqual(kt.status, 'ok');
        assert.strictEqual((await alice.client.getPeerTransparency(2)).status, 'ok');
        const overview = await alice.client.checkTransparency();
        assert.strictEqual(overview.status, 'ok');
        assert.deepStrictEqual(overview.peers, [{ userId: 2, status: 'ok' }]);
        // Статус ok и закрепление не менялось: следующий вход в комнату доказательства не запрашивает.
        const proofsBefore = world.kt.calls.proof;
        await world.session(alice);
        assert.strictEqual(world.kt.calls.proof, proofsBefore);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'unverified', 'ok журнала не меняет статус сверки по коду');
        noViolations(world);
    });

    await test('эпоха регистрации ещё открыта и SKT верен: pending (open-epoch), отправка не блокируется', async () => {
        const { world, alice } = await pair();
        await world.kt.closeEpoch();
        await world.session(alice); // журнал виден, Боб уже ok — нужен новый ключ
        const carol = await world.addUser(3);
        await world.session(alice);
        const kt = await statusOf(alice, 3);
        assert.strictEqual(kt.status, 'pending');
        assert.strictEqual(kt.reason, 'open-epoch');
        assert.strictEqual((await world.sync(carol)).applied, 1, 'pending ключ получает ключ комнаты');
        // Эпоха закрылась — следующая проверка подтверждает ключ.
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 3)).status, 'ok');
    });

    await test('SKT с неверной подписью при открытой эпохе: pending без доказательства (no-proof)', async () => {
        const { world, alice } = await pair();
        await world.kt.closeEpoch();
        await world.session(alice);
        const carol = await world.addUser(3);
        const user = world.kt.users.get(3);
        user.skt = new Uint8Array(user.skt); user.skt[5] ^= 1;
        await world.session(alice);
        const kt = await statusOf(alice, 3);
        assert.strictEqual(kt.status, 'pending');
        assert.strictEqual(kt.reason, 'no-proof');
        assert.ok(carol);
    });

    await test('подмена ключа без записи в журнале: mismatch сразу после закрытия эпохи; исключён из рассылки', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        const bob = await world.addUser(2);
        const attacker = await world.addUser(3, { roomId: 999 });
        await world.kt.closeEpoch();
        world.server.evil.impersonate(2, 3); // сервер выдаёт Алисе ключи атакующего за ключи Боба, hint остаётся Боба
        const result = await world.session(alice);
        const kt = await statusOf(alice, 2);
        assert.strictEqual(kt.status, 'mismatch');
        assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'log-mismatch');
        assert.deepStrictEqual(result.logMismatches.map(m => m.userId), [2]);
        assert.ok(result.warnings.some(w => w.userId === 2));
        assert.strictEqual((await world.sync(bob)).applied, 0, 'ключ комнаты Бобу не отправлен');
        const overview = await alice.client.checkTransparency();
        assert.deepStrictEqual(overview.peers, [{ userId: 2, status: 'mismatch' }]);
        assert.ok(attacker);
        noViolations(world);
    });

    await test('markPeerVerified и overrideLogMismatch возвращают собеседника в адресаты', async () => {
        for (const how of ['verified', 'override']) {
            const world = makeWorld();
            const alice = await world.addUser(1);
            const bob = await world.addUser(2);
            await world.addUser(3, { roomId: 999 });
            await world.kt.closeEpoch();
            world.server.evil.impersonate(2, 3);
            await world.session(alice);
            assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'log-mismatch');
            if (how === 'verified') assert.strictEqual(await alice.client.markPeerVerified(2), true);
            else assert.strictEqual(await alice.client.overrideLogMismatch(2), true);
            const result = await world.session(alice);
            assert.deepStrictEqual(result.logMismatches, [], how);
            assert.strictEqual(await alice.client.getPeerIdentityStatus(2), how === 'verified' ? 'verified' : 'unverified');
            // Ключ комнаты уходит не раньше, чем настоящий Боб согласится принять ключи атакующего; сервер подменил
            // bundle, так что тут достаточно того, что Боб больше не исключён из рассылки.
            assert.ok(!result.warnings.some(w => w.userId === 2 && /журнал/.test(w.reason)), how);
            assert.ok(bob);
        }
    });

    await test('К1: сервер подменил ключ и отвечает kt: null — pending (не unavailable), перепроверка на каждом входе, через 3 эпохи mismatch', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.addUser(3, { roomId: 999 });
        await world.kt.closeEpoch();
        await world.session(alice); // Алиса видела журнал, Боб ok
        assert.strictEqual((await statusOf(alice, 2)).status, 'ok');
        // Новый собеседник Дэн: ключи подменены и подсказки kt нет.
        const dan = await world.addUser(4);
        world.server.evil.impersonate(4, 3);
        world.kt.evil.hideHint.add(4);
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        assert.strictEqual((await statusOf(alice, 4)).reason, 'no-proof');
        assert.ok(dan);
        assert.strictEqual((await alice.client.checkTransparency()).status, 'ok', 'pending не инцидент журнала');
        // Три закрытые эпохи: каждый вход заново спрашивает сервер и видит, что доказательства нет.
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        await world.kt.closeEpoch();
        const result = await world.session(alice);
        const kt = await statusOf(alice, 4);
        assert.strictEqual(kt.status, 'mismatch');
        assert.strictEqual(kt.reason, 'no-proof-timeout');
        assert.deepStrictEqual(result.logMismatches.map(m => m.userId), [4]);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(4), 'log-mismatch');
        noViolations(world);
    });

    await test('К1: то же через 404 на proof и через 4 часа, если голова журнала не продвигается', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.addUser(3, { roomId: 999 });
        await world.kt.closeEpoch();
        await world.session(alice);
        world.kt.evil.noProof = true; // сервер не даёт доказательств
        const eve = await world.addUser(4);
        world.server.evil.impersonate(4, 3);
        world.kt.evil.hideHint.add(4);
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        // Голова не продвигается, часы идут: через 4 часа pending становится mismatch.
        world.advance(3 * HOUR + 59 * 60 * 1000);
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        world.advance(2 * 60 * 1000);
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'mismatch');
        assert.ok(eve);
    });

    await test('сетевая ошибка при запросе доказательства не даёт mismatch: повтор с нарастающей паузой, статус не меняется', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice); // Боб ok
        await world.kt.closeEpoch();
        const carol = await world.addUser(3);
        await world.kt.closeEpoch();
        assert.ok(carol);
        world.kt.evil.networkDown = true;
        for (let i = 0; i < 4; i++) {
            await world.session(alice);
            // Сеть до журнала упала: статус Кэрол остаётся прежним (ещё не проверена), «нет доказательства» не засчитывается.
            const kt = await statusOf(alice, 3);
            assert.ok(!kt || kt.status !== 'mismatch', 'шаг ' + i);
            assert.ok(!kt || kt.status === 'pending', 'ожидание, а не отказ');
        }
        const delays = alice.scheduled.map(s => s.ms);
        assert.ok(delays.length >= 1, 'повтор запланирован');
        assert.strictEqual(delays[0], 1000);
        // Повторы при каждом запуске: пауза растёт 1, 2, 4 … секунд (таймер не дублируется, пока не сработал).
        world.kt.evil.networkDown = false;
        for (const item of alice.scheduled.splice(0)) await item.fn();
        assert.strictEqual((await statusOf(alice, 3)).status, 'ok', 'после восстановления сети проверка завершилась');
        noViolations(world);
    });

    await test('пауза повтора растёт: 1, 2, 4, 8, 16 секунд (не больше 300), после успеха начинается заново', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        await world.addUser(3);
        await world.kt.closeEpoch();
        world.kt.evil.networkDown = true;
        await world.session(alice); // отказ сети: повтор запланирован
        const delays = [];
        for (let i = 0; i < 5; i++) {
            const item = alice.scheduled.pop();
            delays.push(item.ms);
            await item.fn(); // таймер сработал, сети всё ещё нет — следующая пауза длиннее
        }
        assert.deepStrictEqual(delays, [1000, 2000, 4000, 8000, 16000]);
        for (let i = 0; i < 12; i++) await alice.scheduled.pop().fn();
        assert.strictEqual(alice.scheduled[0].ms, 300000, 'потолок паузы — 300 секунд');
        world.kt.evil.networkDown = false;
        await alice.scheduled.pop().fn(); // сеть вернулась
        assert.strictEqual((await statusOf(alice, 3)).status, 'ok');
        assert.deepStrictEqual(alice.scheduled, []);
        // После успеха отсчёт начинается с секунды.
        world.kt.evil.networkDown = true;
        await world.addUser(4);
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual(alice.scheduled.pop().ms, 1000);
    });

    await test('журнал отключили после того, как клиент его видел: тревога log-disabled, inconsistent, ключи — pending', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        world.kt.evil.disabled = true;
        const carol = await world.addUser(3);
        assert.ok(carol);
        await world.session(alice);
        assert.ok(alice.alerts.some(a => a.kind === 'log-disabled'));
        assert.strictEqual((await alice.client.checkTransparency()).status, 'inconsistent');
        const kt = await statusOf(alice, 3);
        assert.strictEqual(kt.status, 'pending', 'новый ключ без доказательства — pending, не unavailable');
        // Журнал снова отвечает — тревога снимается.
        world.kt.evil.disabled = false;
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.ok(!(await alice.client.getTransparencyAlerts()).some(a => a.kind === 'log-disabled'));
        assert.strictEqual((await alice.client.checkTransparency()).status, 'ok');
    });

    await test('404 на маршрутах журнала у клиента, видевшего его: log-disabled', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        world.kt.evil.notFound = true;
        await world.addUser(3);
        await world.session(alice);
        assert.ok(alice.alerts.some(a => a.kind === 'log-disabled'));
    });

    await test('неверное доказательство для закрытой эпохи: mismatch, SKT сохраняется как доказательство', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice); // журнал виден
        const carol = await world.addUser(3);
        await world.kt.closeEpoch();
        world.kt.evil.badProof = true; // сервер отдаёт доказательство чужой метки
        await world.session(alice);
        const kt = await statusOf(alice, 3);
        assert.strictEqual(kt.status, 'mismatch');
        assert.strictEqual(kt.reason, 'bad-proof');
        assert.ok(kt.evidence && kt.evidence.skt, 'SKT сохранён');
        assert.ok(carol);
    });

    await test('сервер не включил обещанное: после закрытия эпохи в листе нет обязательства — mismatch', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        const carol = await world.addUser(3);
        world.kt.pending = world.kt.pending.filter(p => Buffer.from(p.label).toString('hex') !== Buffer.from(world.kt.pending[world.kt.pending.length - 1].label).toString('hex'));
        await world.kt.closeEpoch();
        await world.session(alice);
        const kt = await statusOf(alice, 3);
        assert.strictEqual(kt.status, 'mismatch');
        assert.strictEqual(kt.reason, 'not-in-log');
        assert.ok(carol);
    });

    await test('ротация своего ключа комнаты по статусу mismatch: по статусу, а не по отметкам рассылки; один раз; исключённый ключа не получает', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        const bob = await world.addUser(2);
        const attacker = await world.addUser(3, { roomId: 999 });
        const carol = await world.addUser(4);
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await world.sync(bob)).applied, 1);
        assert.strictEqual((await world.sync(carol)).applied, 1);
        const keyBefore = (await alice.storage.get('senderKey:100:1')).senderKeyId;
        // Сервер подсовывает Алисе ключи атакующего вместо Бобовых; Алиса, не сверив код, принимает смену ключа.
        // Принятие стирает отметки рассылки Бобу, а ключа Боба в журнале нет — mismatch.
        world.server.evil.impersonate(2, 3);
        assert.deepStrictEqual((await world.session(alice)).identityChanges.map(c => c.userId), [2]);
        assert.strictEqual(await alice.client.acceptPeerIdentityChange(2), true);
        const marks = (await alice.storage.keys('sharedWith2:')).filter(name => name.endsWith(':2'));
        assert.deepStrictEqual(marks, [], 'отметки рассылки Бобу стёрты принятием ключа');
        const result = await world.session(alice);
        assert.strictEqual(await alice.client.getPeerIdentityStatus(2), 'log-mismatch');
        assert.strictEqual(result.rotated, true, 'ключ комнаты ротирован, хотя отметок рассылки нет');
        assert.strictEqual(result.rotationReason, 'log-mismatch');
        assert.deepStrictEqual(result.logMismatches.map(m => m.userId), [2]);
        const own = await alice.storage.get('senderKey:100:1');
        assert.notStrictEqual(own.senderKeyId, keyBefore);
        assert.deepStrictEqual(own.logExcluded, [2]);
        assert.ok(!own.entitled.includes(2) && own.entitled.includes(4));
        assert.strictEqual((await world.sync(bob)).applied, 0, 'исключённый не получает нового ключа');
        // Первый новый ключ - при смене ключа Боба (changed выводит его из V: ротация по журналу доставок, signed-membership.md,
        // 9.1), второй - при log-mismatch после принятия ключа; Кэрол, не успев забрать первый, получает оба.
        assert.strictEqual((await world.sync(carol)).applied, 2, 'остальные получают');
        // Повторный вход: статус прежний — второй ротации нет.
        const again = await world.session(alice);
        assert.strictEqual(again.rotated, false);
        assert.strictEqual((await alice.storage.get('senderKey:100:1')).senderKeyId, own.senderKeyId);
        // Запрос ключа от исключённого отметки стирает, но в рассылку его не возвращает.
        await alice.client.answerKeyRequests(alice.chatId, 100, [{ fromUserId: 2, senderKeyIds: [own.senderKeyId] }]);
        const afterRequest = await world.session(alice);
        assert.strictEqual(afterRequest.rotated, false);
        assert.strictEqual((await world.sync(bob)).applied, 0);
        // Явное продолжение или сверка кода возвращают его в адресаты.
        assert.strictEqual(await alice.client.overrideLogMismatch(2), true);
        const resumed = await world.session(alice);
        assert.deepStrictEqual(resumed.logMismatches, []);
        assert.ok(attacker);
        noViolations(world);
    });

    await test('pending не исключает из рассылки и не вызывает ротацию', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        const attacker = await world.addUser(3, { roomId: 999 });
        const dan = await world.addUser(4);
        world.server.evil.impersonate(4, 3);
        world.kt.evil.hideHint.add(4); // подсказки нет — доказательства не будет
        const result = await world.session(alice);
        assert.strictEqual((await statusOf(alice, 4)).status, 'pending');
        assert.strictEqual(result.rotated, false);
        assert.deepStrictEqual(result.logMismatches, []);
        assert.ok(!result.warnings.some(w => w.userId === 4 && /журнал/.test(w.reason)), 'pending не причина для предупреждения о рассылке');
        assert.strictEqual(await alice.client.getPeerIdentityStatus(4), 'unverified', 'pending журнала не меняет статус сверки по коду');
        assert.ok(attacker && dan);
    });

    await test('сеть вне withLock (К6): applyShare и reconcile только ставят задачи, проверки идут в runKtChecks', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        const bob = await world.addUser(2);
        await world.kt.closeEpoch();
        await world.session(alice);
        await world.sync(bob);
        await world.session(bob);
        await world.sync(alice);
        await world.kt.closeEpochs(2);
        await world.session(alice);
        await world.session(bob);
        noViolations(world);
        // Результат не применяется, если закрепление изменилось за время запроса: задача снимается без записи.
        const pinBefore = await alice.storage.get('peer:2');
        assert.ok(pinBefore.kt);
    });

    await test('закрепление изменилось за время запроса: устаревший результат не записывается', async () => {
        const world = makeWorld();
        const alice = await world.addUser(1);
        await world.addUser(2);
        await world.kt.closeEpoch();
        // Замедленный proof: пока он «идёт», закрепление Боба меняется.
        const original = world.kt.proof.bind(world.kt);
        let swapped = false;
        world.kt.proof = async (...args) => {
            if (!swapped) {
                swapped = true;
                const pin = await alice.storage.get('peer:2');
                pin.signPub = Buffer.alloc(32, 7).toString('base64');
                await alice.storage.set('peer:2', pin);
            }
            return original(...args);
        };
        await world.session(alice);
        const pin = await alice.storage.get('peer:2');
        assert.ok(!pin.kt || pin.kt.status !== 'ok', 'результат старой проверки не записан в изменившееся закрепление');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
