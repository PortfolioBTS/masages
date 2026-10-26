'use strict';
// Повторная регистрация в том же браузере (контракт волны 1, §3
// «POST /api/register/anonymous»):
//
//   * живая сессия -> HTTP 409 {success:false, code:'already-authenticated',
//     message:'Вы уже вошли в аккаунт'}; проверяется ДО PoW (и до проверки
//     lifetime): решение одноразовое, и тратить его на отказ незачем;
//   * PoW не прошёл -> {success:false, powRequired:true, message};
//   * неверный lifetime -> {success:false, message}.
//
// Чистка анонимов в этом наборе выключена (NYXO_TEST_MAINTENANCE_MS — час):
// нужен аккаунт, у которого срок вышел, а строка ещё есть.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { registerRaw, sessionCookie, setCookies, setLastActive, userRow, count } = require('./helpers/anon');

const suite = createSuite('double-register', { env: { NYXO_TEST_MAINTENANCE_MS: 3600000 } });

const ALREADY = { success: false, code: 'already-authenticated', message: 'Вы уже вошли в аккаунт' };
const usersCount = () => count(suite, 'SELECT 1 FROM users');

test('живая сессия: 409 already-authenticated — без PoW, с неверным PoW, с верным PoW и с неверным lifetime', async () => {
    const client = suite.client();
    const user = await client.registerAnon({ lifetime: 'day' });
    const before = sessionCookie(client);
    const usersBefore = await usersCount();
    const goodPow = await client.solvePow('register-anon');

    const attempts = [
        ['без PoW', { lifetime: 'tab' }],
        ['без тела', {}],
        ['неверный PoW', { lifetime: 'tab', pow: { token: 'garbage', nonce: '0' } }],
        ['верный PoW', { lifetime: 'week', pow: goodPow }],
        ['неверный lifetime', { lifetime: 'month' }],
    ];
    for (const [what, body] of attempts) {
        const res = await client.post('/api/register/anonymous', body);
        assert.strictEqual(res.status, 409, `${what}: ${JSON.stringify(res.body)}`);
        assert.deepStrictEqual(res.body, ALREADY, what);
        assert.deepStrictEqual(setCookies(res), [], `${what}: сессия не меняется`);
    }

    // Ничего не создано и не изменено.
    assert.strictEqual(await usersCount(), usersBefore, 'второй аккаунт не создан');
    assert.strictEqual(sessionCookie(client).sid, before.sid);
    const auth = await client.auth();
    assert.strictEqual(auth.authenticated, true);
    assert.strictEqual(auth.user.id, user.id);
    assert.strictEqual(auth.user.anonLifetime, 'day', 'срок прежний');

    // Решение, которое не понадобилось (409 раньше PoW), не потрачено: после выхода оно ещё годится.
    await client.deleteAccount();
    const res = await client.post('/api/register/anonymous', { lifetime: 'tab', pow: goodPow });
    assert.strictEqual(res.status, 200, JSON.stringify(res.body));
    assert.strictEqual(res.body.success, true, 'PoW не должен был расходоваться на отказ 409');
    assert.notStrictEqual(res.body.user.id, user.id);
});

test('копия куки на втором устройстве — тоже живая сессия: 409', async () => {
    const first = suite.client();
    await first.registerAnon();
    const second = suite.client();
    second.withCookie('connect.sid', sessionCookie(first).value);
    const res = await second.post('/api/register/anonymous', { lifetime: 'tab', pow: await second.solvePow('register-anon') });
    assert.strictEqual(res.status, 409);
    assert.deepStrictEqual(res.body, ALREADY);
});

test('после выхода (удаления аккаунта) в том же браузере можно зарегистрироваться снова', async () => {
    const client = suite.client();
    const first = await client.registerAnon({ lifetime: 'week' });
    await client.logout();
    assert.deepStrictEqual(await client.auth(), { authenticated: false, onionUrl: null });
    const second = await client.registerAnon({ lifetime: 'tab' });
    assert.notStrictEqual(second.id, first.id);
    assert.strictEqual((await client.auth()).user.id, second.id);
});

test('сессия с истёкшим сроком — не живая: регистрация в том же браузере проходит, /api/auth у другого такого же сообщает reason expired', async () => {
    const expired = suite.client();
    const old = await expired.registerAnon({ lifetime: 'tab' });
    const probe = suite.client();
    const probeUser = await probe.registerAnon({ lifetime: 'tab' });
    // Срок вышел минуту назад, а чистка (раз в час) ещё не пришла; кэш активности сервера сбрасывает рестарт.
    await setLastActive(suite, old.id, 'tab', { pastMs: 60 * 1000 });
    await setLastActive(suite, probeUser.id, 'tab', { pastMs: 60 * 1000 });
    await suite.server.restart();

    // /api/auth с такой сессией: аккаунт удалён по сроку.
    assert.deepStrictEqual(await probe.auth(), { authenticated: false, reason: 'expired', expired: true, onionUrl: null });

    // Регистрация первым же запросом: 409 нет, аккаунт новый, сессия новая.
    const oldSid = sessionCookie(expired).sid;
    const res = await registerRaw(expired, 'day');
    assert.strictEqual(res.status, 200, JSON.stringify(res.body));
    assert.strictEqual(res.body.success, true);
    assert.notStrictEqual(res.body.user.id, old.id);
    assert.notStrictEqual(sessionCookie(expired).sid, oldSid);
    assert.strictEqual((await expired.auth()).user.id, res.body.user.id);
    assert.ok(await userRow(suite, old.id), 'строка просроченного аккаунта ждёт чистки (она выключена в наборе)');
});

test('без сессии: неверный PoW — powRequired, неверный lifetime — ошибка без powRequired (и до PoW), срок по умолчанию — tab', async () => {
    const client = suite.client();
    const usersBefore = await usersCount();

    for (const [what, body] of [
        ['без PoW', { lifetime: 'tab' }],
        ['мусорный токен', { lifetime: 'tab', pow: { token: 'garbage', nonce: '0' } }],
    ]) {
        const res = await client.post('/api/register/anonymous', body);
        assert.strictEqual(res.body.success, false, what);
        assert.strictEqual(res.body.powRequired, true, `${what}: ${JSON.stringify(res.body)}`);
        assert.ok(typeof res.body.message === 'string' && res.body.message.length > 0, what);
        assert.notStrictEqual(res.status, 409, what);
    }
    // Верный токен, неверное решение.
    const challenge = await client.get('/api/pow/challenge?purpose=register-anon');
    const wrong = await client.post('/api/register/anonymous', { lifetime: 'tab', pow: { token: challenge.body.token, nonce: 'не число' } });
    assert.strictEqual(wrong.body.powRequired, true);

    // Неверный lifetime отказывает раньше PoW: решение не нужно и не тратится.
    // (до 10 регистраций в час с одного IP — лимит считает и отказы)
    for (const lifetime of ['month', 42, ['tab']]) {
        const res = await client.post('/api/register/anonymous', { lifetime });
        assert.strictEqual(res.body.success, false, JSON.stringify(lifetime));
        assert.ok(!('powRequired' in res.body), `lifetime ${JSON.stringify(lifetime)}: отказ должен быть про срок, а не про PoW`);
        assert.ok(typeof res.body.message === 'string' && res.body.message.length > 0);
    }
    assert.strictEqual(await usersCount(), usersBefore, 'ни один из отказов не создал аккаунт');

    // Решение одноразовое.
    const pow = await client.solvePow('register-anon');
    const ok = await client.post('/api/register/anonymous', { pow });
    assert.strictEqual(ok.body.success, true, JSON.stringify(ok.body));
    assert.strictEqual(ok.body.user.anonLifetime, 'tab', 'без lifetime — tab');
    const replay = suite.client();
    const reused = await replay.post('/api/register/anonymous', { lifetime: 'tab', pow });
    assert.strictEqual(reused.body.powRequired, true, 'то же решение второй раз не принимается');
});
