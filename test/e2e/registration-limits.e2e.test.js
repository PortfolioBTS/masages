'use strict';
// Массовые аккаунты (W7 R1 п.3): глобальный потолок регистраций в минуту - в том числе через
// onion, где IP-лимита нет, - и рост сложности proof-of-work вместе с темпом регистраций.
// Потолок считается после успешного PoW: запросы без решения его не расходуют.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { freePort } = require('./helpers/server');
const { TestClient } = require('./helpers/client');
const { testOnionAddress } = require('./helpers/env');

// База PoW в e2e - 8 бит (helpers/env.js). Темп 2 в минуту: 2 регистрации - +1 бит, 4 - +2.
// Потолок 6 в минуту.
const ADDRESS = testOnionAddress('registration-limits');
const suite = createSuite('registration-limits', { startServer: false });

async function difficultyNow(client) {
    const res = await client.get('/api/pow/challenge?purpose=register-anon');
    assert.strictEqual(res.status, 200);
    return res.body.difficulty;
}

test('сложность PoW растёт с темпом регистраций, потолок в минуту действует и через onion; запросы без решения потолок не тратят', async () => {
    const onionPort = await freePort();
    await suite.startServer({ env: {
        REGISTER_GLOBAL_PER_MIN: '6', REGISTER_PACE_PER_MIN: '2', ONION_ADDRESS: ADDRESS, ONION_PORT: onionPort,
    } });
    const probe = suite.client();
    // Через onion запрос считается защищённым (куки Secure), поэтому клиенту нужен secureContext.
    const newOnionClient = () => new TestClient({ baseUrl: `http://127.0.0.1:${onionPort}` }, { secureContext: true });

    // Запросы без решённой задачи: мусорный PoW, потолок не тратится.
    for (let i = 0; i < 12; i++) {
        const res = await suite.client().post('/api/register/anonymous', { lifetime: 'tab', pow: { token: 'x', nonce: '1' } });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.powRequired, true, 'без решения - powRequired, а не 429');
    }

    assert.strictEqual(await difficultyNow(probe), 8, 'без наплыва - базовая сложность');
    // Задача, выданная ДО наплыва: решить её можно, но после наплыва она не пройдёт.
    const stale = suite.client();
    const stalePow = await stale.solvePow('register-anon');

    await suite.client().registerAnon();
    assert.strictEqual(await difficultyNow(probe), 8, 'одна регистрация - ниже темпа');
    await newOnionClient().registerAnon();
    assert.strictEqual(await difficultyNow(probe), 9, 'темп 2 в минуту - +1 бит');
    await suite.client().registerAnon();
    await suite.client().registerAnon();
    assert.strictEqual(await difficultyNow(probe), 10, 'темп 4 в минуту - +2 бита');

    const rejected = await stale.post('/api/register/anonymous', { lifetime: 'tab', pow: stalePow });
    assert.strictEqual(rejected.body.success, false);
    assert.strictEqual(rejected.body.powRequired, true, 'лёгкая задача, выданная до наплыва, не принимается');

    // Ещё две регистрации (одна через onion) - шестая последняя в минуту.
    await newOnionClient().registerAnon();
    await suite.client().registerAnon();
    const seventh = suite.client();
    const pow = await seventh.solvePow('register-anon');
    const blocked = await seventh.post('/api/register/anonymous', { lifetime: 'tab', pow });
    assert.strictEqual(blocked.status, 429, JSON.stringify(blocked.body));
    assert.strictEqual(blocked.body.code, 'registration-busy');
    assert.match(blocked.body.message, /регистрируется слишком много/);
    assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
    const onionSeventh = newOnionClient();
    const viaOnion = await onionSeventh.post('/api/register/anonymous', { lifetime: 'tab', pow: await onionSeventh.solvePow('register-anon') });
    assert.strictEqual(viaOnion.status, 429, 'через onion потолок тот же');

    const users = (await suite.query('SELECT count(*)::int AS n FROM users')).rows[0].n;
    assert.strictEqual(users, 6, 'аккаунтов создано ровно по потолку');
});
