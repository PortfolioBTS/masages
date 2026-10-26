'use strict';
// Журнал ключей выключен на сервере (T7.3, п.12 ревью W7 R3): окно «Участники и ключи» писало
// «Проверка журнала ключей сейчас недоступна» под каждым участником, хотя журнала просто
// нет. Теперь при /api/kt/head { enabled: false } эти строки не показываются; при
// настоящей недоступности (нет связи, сервер не ответил) всё как раньше.
// Логика в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-kt-off-members.test.js

const assert = require('assert');
const { createClient, createHarness } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();

function ktClient(responses) {
    const calls = [];
    let clock = 1_000_000;
    const client = createClient({
        functions: ['ktEnabledOnServer', 'dropKtUnavailableWhenOff'],
        consts: ['KT_SERVER_STATE_TTL_MS'],
        prelude: 'let ktServerState = { enabled: null, at: 0 };',
        sandbox: {
            Date: { now: () => clock },
            api: async (url, options) => {
                calls.push({ url, options });
                return responses.shift();
            },
        },
    });
    return { ...client, calls, advance: (ms) => { clock += ms; } };
}

test('журнал выключен ({success, enabled:false}) — ktEnabledOnServer() === false, ответ запоминается', async () => {
    const c = ktClient([{ success: true, enabled: false, code: 'kt-disabled' }]);
    assert.strictEqual(await c.run('ktEnabledOnServer()'), false);
    assert.strictEqual(await c.run('ktEnabledOnServer()'), false);
    assert.strictEqual(c.calls.length, 1, 'второй раз сервер не спрашивали');
    assert.strictEqual(c.calls[0].url, '/api/kt/head');
    c.advance(6 * 60 * 1000);
    c.calls.length = 0;
    const again = ktClient([{ success: true, enabled: false }]);
    assert.strictEqual(await again.run('ktEnabledOnServer()'), false);
});

test('после TTL сервер спрашивается заново: журнал могли включить', async () => {
    const c = ktClient([{ success: true, enabled: false }, { success: true, gen: 1, epoch: 3, httpStatus: 200 }]);
    assert.strictEqual(await c.run('ktEnabledOnServer()'), false);
    c.advance(6 * 60 * 1000);
    assert.strictEqual(await c.run('ktEnabledOnServer()'), true);
    assert.strictEqual(c.calls.length, 2);
});

test('журнал включён — true; не готов (503 kt-not-ready) — тоже «включён»', async () => {
    const on = ktClient([{ success: true, gen: 1, epoch: 3, httpStatus: 200 }]);
    assert.strictEqual(await on.run('ktEnabledOnServer()'), true);
    const warming = ktClient([{ success: false, code: 'kt-not-ready', httpStatus: 503 }]);
    assert.strictEqual(await warming.run('ktEnabledOnServer()'), true);
});

test('другие версии сервера: kt-disabled в коде или 404 — тоже выключен', async () => {
    assert.strictEqual(await ktClient([{ success: false, code: 'kt-disabled', httpStatus: 503 }]).run('ktEnabledOnServer()'), false);
    assert.strictEqual(await ktClient([{ success: false, httpStatus: 404 }]).run('ktEnabledOnServer()'), false);
});

test('нет связи или таймаут — null и без запоминания: строку показываем как раньше, спросим снова', async () => {
    for (const failure of [{ success: false, networkError: true }, { success: false, timedOut: true }]) {
        const c = ktClient([failure, { success: true, enabled: false }]);
        assert.strictEqual(await c.run('ktEnabledOnServer()'), null);
        assert.strictEqual(await c.run('ktEnabledOnServer()'), false, 'повторный запрос, ответ не закеширован');
    }
});

test('dropKtUnavailableWhenOff: при выключенном журнале убирает только «unavailable»', () => {
    const c = ktClient([]);
    c.context.__map = new Map([[1, 'unavailable'], [2, 'ok'], [3, 'pending'], [4, 'unavailable'], [5, 'mismatch']]);
    c.run('dropKtUnavailableWhenOff(__map, false)');
    assert.deepStrictEqual([...c.context.__map.entries()], [[2, 'ok'], [3, 'pending'], [5, 'mismatch']]);
});

test('dropKtUnavailableWhenOff: журнал включён или неизвестно — строки остаются', () => {
    for (const enabled of ['true', 'null', 'undefined']) {
        const c = ktClient([]);
        c.context.__map = new Map([[1, 'unavailable'], [2, 'ok']]);
        c.run(`dropKtUnavailableWhenOff(__map, ${enabled})`);
        assert.deepStrictEqual([...c.context.__map.keys()], [1, 2], enabled);
    }
});

test('код: окно участников спрашивает сервер только когда есть «unavailable» и до проверки seq', () => {
    const script = readClientScript();
    const call = script.indexOf("dropKtUnavailableWhenOff(ktStatuses, await ktEnabledOnServer())");
    assert.ok(call > 0, 'вызов не найден');
    assert.ok(script.slice(call - 80, call).includes("includes('unavailable')"));
    assert.ok(script.indexOf('if (seq !== membersModalSeq) return;', call) - call < 120, 'после await нужна проверка seq: окно могли закрыть');
});

done();
