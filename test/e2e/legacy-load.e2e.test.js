'use strict';
// Легаси-фикстура (база версии 2.0.0, test/e2e/fixtures/) загружается в
// свежую базу, и текущий сервер на ней стартует. Больше ничего: реальных
// пользователей нет, и новая версия при первом запуске на старой схеме один
// раз сбросит базу (задача волны 1).

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('legacy-load', { legacy: true, startServer: false });

test('фикстура загружена в свежую базу', async () => {
    const meta = suite.legacy;
    const ids = Object.values(meta.users).map(u => u.id).sort((a, b) => a - b);
    const users = await suite.query('SELECT id FROM users ORDER BY id');
    assert.deepStrictEqual(users.rows.map(r => r.id), ids);
    const rooms = await suite.query('SELECT id, name FROM rooms ORDER BY id');
    assert.deepStrictEqual(rooms.rows, Object.values(meta.rooms).map(r => ({ id: r.id, name: r.name })).sort((a, b) => a.id - b.id));
    const messages = await suite.query('SELECT count(*)::int AS n FROM messages');
    assert.strictEqual(messages.rows[0].n, Object.keys(meta.messages).length);
    const sessions = await suite.query('SELECT count(*)::int AS n FROM session');
    assert.strictEqual(sessions.rows[0].n, 3);
    // Схемы версии 2.0.0 ещё не знала о версии схемы.
    const meta2 = await suite.query(`SELECT to_regclass('schema_meta') AS t`);
    assert.strictEqual(meta2.rows[0].t, null);
});

test('текущий сервер стартует на легаси-базе', async () => {
    const server = await suite.startServer();
    await server.logs.waitFor('База данных инициализирована');
    assert.deepStrictEqual(await suite.client().auth(), { authenticated: false });
    const version = await suite.query('SELECT schema_version FROM schema_meta');
    assert.deepStrictEqual(version.rows, [{ schema_version: 0 }]);
    // меняется в волне 1: новая версия при первом старте на схеме 2.0.0
    // сбрасывает базу — легаси-аккаунтов после старта не останется.
    const users = await suite.query('SELECT count(*)::int AS n FROM users');
    assert.strictEqual(users.rows[0].n, Object.keys(suite.legacy.users).length);
});
