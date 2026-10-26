'use strict';
// Чистка просроченных анонимов при наплыве (ревью W7 R2.11): раньше проход удалял не
// больше 200 аккаунтов (раз в 5 минут), и при наплыве данные жили дольше выбранного
// срока. Теперь проход берёт пачки до исчерпания (с бюджетом времени). В тестах проходы
// идут каждые 300 мс (NYXO_TEST_MAINTENANCE_MS); признак — один проход удалил больше
// 200 (старый код за проход удалял не больше 200 и писал это число в лог).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('anon-purge-batches');

const COUNT = 230;

test(`${COUNT} просроченных аккаунтов удаляются за один проход, живой — остаётся`, async () => {
    const live = suite.client();
    await live.registerAnon();
    const mark = suite.server.logs.mark();
    // Просроченные «tab»-аккаунты напрямую в базе: регистрация через API с PoW была бы
    // слишком долгой. id — вне диапазона, который выдаёт сервер.
    await suite.query(`
        INSERT INTO users (id, unique_code, username, anon_lifetime, last_active_at)
        SELECT 2000000000 + g, 'purge-' || g, 'Просроченный-' || g, 'tab', now() - interval '3 days'
        FROM generate_series(1, $1::int) AS g`, [COUNT]);
    const expired = async () => (await suite.query('SELECT count(*)::int AS n FROM users WHERE id > 2000000000')).rows[0].n;
    assert.strictEqual(await expired(), COUNT);
    // Два новых прохода: второй целиком начался после вставки.
    await suite.server.waitForTick(2, { timeoutMs: 50000 });
    assert.strictEqual(await expired(), 0, 'все просроченные удалены');
    const passes = [...suite.server.logs.text({ from: mark }).matchAll(/Удалено просроченных анонимных аккаунтов: (\d+)/g)].map(m => Number(m[1]));
    assert.ok(passes.some(n => n > 200), `один проход удалил больше одной пачки: ${JSON.stringify(passes)}`);
    assert.ok((await live.auth()).authenticated, 'живой аккаунт на месте');
});
