'use strict';
// Легаси-фикстура (база версии 2.0.0, test/e2e/fixtures/) загружается в
// свежую базу, и сервер на ней стартует. Реальных пользователей нет, поэтому
// новая версия при первом старте на старой схеме один раз сбрасывает базу
// целиком и создаёт итоговую схему (roadmap R0, контракт волны 1 §1).
//
// Здесь — только проверка, что сброс случился, а повторный старт его не
// повторяет. Полный набор «reset» (файлы вложений, снимок схемы) — в наборах
// волны 1.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');
const { schemaSnapshot } = require('./helpers/pg');

const suite = createSuite('legacy-load', { legacy: true, startServer: false });

const RESET_SCHEMA_LINE = /^\[Reset\] Обнаружена старая схема: удаляются тестовые данные \(пользователей: (\d+), сообщений: (\d+)\)$/;
const RESET_FILES_LINE = /^\[Reset\] Удалено файлов вложений: (\d+)$/;

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
    // Схема версии 2.0.0 ещё не знала о версии схемы.
    const meta2 = await suite.query(`SELECT to_regclass('schema_meta') AS t`);
    assert.strictEqual(meta2.rows[0].t, null);
    // Старая схема: у users есть email и пароль, есть журнал безопасности.
    const legacyColumns = await suite.query(
        `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users' AND column_name IN ('email', 'password') ORDER BY 1`
    );
    assert.deepStrictEqual(legacyColumns.rows.map(r => r.column_name), ['email', 'password']);
    const events = await suite.query(`SELECT to_regclass('security_events') AS t`);
    assert.notStrictEqual(events.rows[0].t, null);
});

test('первый старт на схеме 2.0.0: строки [Reset] в логе, старых данных нет, схема итоговая', async () => {
    const server = await suite.startServer();
    await server.logs.waitFor('База данных инициализирована');

    // Обе строки лога — как в контракте, только числа (в фикстуре 3 аккаунта и 7 сообщений).
    const schemaLine = server.logs.find(RESET_SCHEMA_LINE);
    assert.ok(schemaLine, `нет строки о сбросе схемы:\n${server.logs.tail(30)}`);
    assert.strictEqual(Number(schemaLine.match[1]), Object.keys(suite.legacy.users).length);
    assert.strictEqual(Number(schemaLine.match[2]), Object.keys(suite.legacy.messages).length);
    assert.ok(server.logs.find(RESET_FILES_LINE), `нет строки об удалённых файлах:\n${server.logs.tail(30)}`);
    server.logs.assertNoSensitive({
        ids: [...Object.values(suite.legacy.users).map(u => u.id), ...Object.values(suite.legacy.rooms).map(r => r.id)],
        emails: Object.values(suite.legacy.users).map(u => u.email).filter(Boolean),
        sids: Object.values(suite.legacy.users).map(u => u.sid),
    });

    assert.deepStrictEqual(await suite.client().auth(), { authenticated: false });

    // Старых данных нет: ни аккаунтов, ни комнат, ни сообщений, ни старых сессий.
    for (const table of ['users', 'rooms', 'chats', 'messages', 'room_participants', 'session']) {
        const count = await suite.query(`SELECT count(*)::int AS n FROM ${table}`);
        assert.strictEqual(count.rows[0].n, 0, `в ${table} остались строки`);
    }
    // Схема итоговая: у users нет email и пароля, нет журнала безопасности и unread.
    const legacyColumns = await suite.query(
        `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users' AND column_name IN ('email', 'password')`
    );
    assert.deepStrictEqual(legacyColumns.rows, []);
    for (const table of ['security_events', 'unread']) {
        const present = await suite.query(`SELECT to_regclass('${table}') AS t`);
        assert.strictEqual(present.rows[0].t, null, `таблица ${table} должна исчезнуть`);
    }
    // Версию схемы записал раннер миграций (миграций ещё нет — версия 0).
    const version = await suite.query('SELECT schema_version FROM schema_meta');
    assert.deepStrictEqual(version.rows, [{ schema_version: 0 }]);
});

test('повторный старт: строк [Reset] нет, снимок схемы и строка schema_meta те же', async () => {
    const before = await schemaSnapshot(suite.db);
    // Строка версии целиком, вместе с updated_at: раннер обновляет её только
    // когда меняется сама версия, а не на каждом старте.
    const metaBefore = (await suite.query('SELECT schema_version, updated_at FROM schema_meta')).rows;
    assert.strictEqual(metaBefore.length, 1);
    const mark = suite.server.logs.mark();
    await suite.server.restart();
    await suite.server.logs.waitFor('База данных инициализирована', { from: mark });
    assert.strictEqual(suite.server.logs.count('[Reset]', { from: mark }), 0, 'сброс не должен повторяться');
    assert.deepStrictEqual(await schemaSnapshot(suite.db), before);
    assert.deepStrictEqual((await suite.query('SELECT schema_version, updated_at FROM schema_meta')).rows, metaBefore);
});
