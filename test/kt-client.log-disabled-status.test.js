'use strict';
// Статус собеседника после тревоги log-disabled (ревью W7 R5, З-7; key-transparency.md, 7.3, К1).
//
// Тревога log-disabled у kt-client.protocol.test.js проверена, а вот что она делает со СТАТУСОМ ключей - нет:
// public/lib/kt-client.js, evaluatePeer, ветка `!sync.ok`: клиент, видевший журнал, получает для нового
// ключа { status: 'pending', reason: 'no-proof' }, а не 'unavailable' (единственный случай 'unavailable' -
// клиент, никогда не видевший журнал). Замена на 'unavailable' - это и есть обход через «недоступно»: сервер
// выключает журнал и ответом kt: null выдаёт подменённый ключ за не подлежащий проверке.
// Здесь: точная причина no-proof, неизменность уже подтверждённого ключа, перепроверка pending на КАЖДОМ
// ensureRoomSession (причина меняется, когда журнал вернулся), переход в mismatch за 4 часа без доказательства и
// тот же результат для ответа 404.
// Запуск: node test/kt-client.log-disabled-status.test.js

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

// Алиса видела журнал (Боб подтверждён: ok), затем сервер скрыл журнал; Карол с новым ключом появилась уже без него.
async function seenThenHidden(hide) {
    const world = makeWorld();
    const alice = await world.addUser(1);
    await world.addUser(2);
    await world.kt.closeEpoch();
    await world.session(alice);
    assert.strictEqual((await statusOf(alice, 2)).status, 'ok', 'фикстура: Боб подтверждён журналом');
    hide(world.kt.evil);
    const carol = await world.addUser(3);
    await world.session(alice);
    return { world, alice, carol };
}

const hideByDisabled = (evil) => { evil.disabled = true; };
const hideByNotFound = (evil) => { evil.notFound = true; };
const showAgain = (evil) => { evil.disabled = false; evil.notFound = false; };

async function main() {
    await test('503 kt-disabled у клиента, видевшего журнал: новый ключ - pending/no-proof (не unavailable), подтверждённый Боб остаётся ok', async () => {
        const { world, alice, carol } = await seenThenHidden(hideByDisabled);
        assert.ok(alice.alerts.some(a => a.kind === 'log-disabled'), 'тревога log-disabled');
        const kt = await statusOf(alice, 3);
        assert.strictEqual(kt.status, 'pending');
        assert.strictEqual(kt.reason, 'no-proof');
        assert.ok(kt.since && Number.isInteger(kt.since.headEpoch) && kt.since.at > 0, 'pending ведёт since для перехода в mismatch');
        assert.strictEqual((await statusOf(alice, 2)).status, 'ok', 'неизменный подтверждённый ключ не понижается');
        assert.strictEqual((await alice.client.checkTransparency()).status, 'inconsistent');
        // pending не блокирует отправку: ключ комнаты доставлен.
        assert.strictEqual((await world.sync(carol)).applied, 1, 'pending-собеседник получает ключ комнаты');
    });

    await test('404 на маршрутах журнала у клиента, видевшего его: тот же результат - pending/no-proof', async () => {
        const { alice } = await seenThenHidden(hideByNotFound);
        assert.ok(alice.alerts.some(a => a.kind === 'log-disabled'), 'тревога log-disabled');
        const kt = await statusOf(alice, 3);
        assert.deepStrictEqual([kt.status, kt.reason], ['pending', 'no-proof']);
    });

    await test('pending перепроверяется на каждом ensureRoomSession: since не сбрасывается, а вернувшийся журнал меняет причину до закрытия эпохи', async () => {
        const { world, alice } = await seenThenHidden(hideByDisabled);
        const first = await statusOf(alice, 3);
        await world.session(alice);
        await world.session(alice);
        const again = await statusOf(alice, 3);
        assert.deepStrictEqual([again.status, again.reason], ['pending', 'no-proof']);
        assert.deepStrictEqual(again.since, first.since, 'отсчёт 3 эпох / 4 часов идёт с первого pending, а не с каждой сессии');
        // Журнал вернулся, эпоха Карол ещё открыта: следующая же сессия пересчитывает статус по SKT.
        showAgain(world.kt.evil);
        world.advance(31 * 1000);
        await world.session(alice);
        const open = await statusOf(alice, 3);
        assert.deepStrictEqual([open.status, open.reason], ['pending', 'open-epoch'], 'перепроверка случилась на этом входе, не ждёт таймера');
        await world.kt.closeEpoch();
        await world.session(alice);
        assert.strictEqual((await statusOf(alice, 3)).status, 'ok');
        assert.ok(!(await alice.client.getTransparencyAlerts()).some(a => a.kind === 'log-disabled'), 'тревога снята');
    });

    await test('без доказательства 4 часа при выключенном журнале pending становится mismatch (no-proof-timeout), тревога остаётся', async () => {
        const { world, alice } = await seenThenHidden(hideByDisabled);
        world.advance(4 * HOUR + 60 * 1000);
        await world.session(alice);
        const kt = await statusOf(alice, 3);
        assert.deepStrictEqual([kt.status, kt.reason], ['mismatch', 'no-proof-timeout']);
        assert.ok(alice.alerts.some(a => a.kind === 'log-disabled'));
        assert.strictEqual((await statusOf(alice, 2)).status, 'ok', 'подтверждённый Боб не затронут');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error('Test runner crashed:', err); process.exitCode = 1; });
