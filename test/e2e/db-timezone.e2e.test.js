'use strict';
// Часовой пояс сессий Postgres сервера — UTC при любом умолчании базы (src/db/pool.js,
// DB_SESSION_OPTIONS). Колонки session.expire и message_expiry.expires_at — TIMESTAMP без
// пояса: без закреплённого пояса их значения зависели бы от timezone базы (смена пояса
// сдвинула бы все сроки, в поясе с летним временем час перехода неоднозначен).
// Проверка: у базы набора пояс +13:45, а срок сессии и исчезающего сообщения в базе —
// в UTC, и сообщение удаляется в свой срок.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');

const suite = createSuite('db-timezone', { startServer: false });

const HOUR = 60 * 60 * 1000;

test('сроки в колонках без пояса пишутся в UTC, даже если у базы другой пояс', async () => {
    await suite.query(`ALTER DATABASE "${suite.dbName}" SET timezone = 'Pacific/Chatham'`);
    await suite.startServer();
    const owner = suite.client({ name: 'владелец' });
    const member = suite.client({ name: 'участник' });
    await owner.registerAnon();
    await member.registerAnon();

    // Срок tab-сессии — сутки от последнего обращения (lib/session-store.js); значение
    // TIMESTAMP читается как UTC: со сдвигом пояса базы оно ушло бы на 13 ч 45 мин.
    const rows = (await suite.query(`SELECT EXTRACT(EPOCH FROM (expire AT TIME ZONE 'UTC'))::float8 * 1000 AS ms FROM session`)).rows;
    assert.ok(rows.length >= 2, 'у обоих клиентов есть строки сессий');
    for (const { ms } of rows) {
        const offsetHours = (ms - (Date.now() + 24 * HOUR)) / HOUR;
        assert.ok(Math.abs(offsetHours) < 1, `срок сессии в UTC: расхождение ${offsetHours.toFixed(2)} ч`);
    }

    // Исчезающее сообщение: срок в message_expiry — тоже в UTC, и удаление в срок.
    const { ownerChat } = await roomWithMember(owner, member);
    await owner.isRoomChat(ownerChat.id);
    const message = await owner.send(ownerChat.id, 'исчезнет');
    const expiry = await owner.post(`/api/messages/${message.id}/set-expiry`, { expirySeconds: 120 });
    assert.strictEqual(expiry.body.success, true, JSON.stringify(expiry.body));
    const { ms } = (await suite.query(`SELECT EXTRACT(EPOCH FROM (expires_at AT TIME ZONE 'UTC'))::float8 * 1000 AS ms FROM message_expiry WHERE message_id = $1`, [message.id])).rows[0];
    const offsetMinutes = (ms - (Date.now() + 120 * 1000)) / 60000;
    assert.ok(offsetMinutes > -1 && offsetMinutes < 3, `срок сообщения в UTC: расхождение ${offsetMinutes.toFixed(1)} мин`);

    // Короткий срок — сообщение действительно удаляется.
    const short = await owner.send(ownerChat.id, 'исчезнет быстро');
    await owner.post(`/api/messages/${short.id}/set-expiry`, { expirySeconds: 2 });
    await waitUntil(async () => (await suite.query('SELECT 1 FROM messages WHERE id = $1', [short.id])).rows.length === 0,
        { timeoutMs: 15000, what: 'исчезающее сообщение удалено' });
});
