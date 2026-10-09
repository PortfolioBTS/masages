'use strict';
// Сброс старой схемы (контракт волны 1, §1; roadmap R0).
//
// Реальных пользователей нет, поэтому новая версия при первом старте на базе
// v2.0.0 (аккаунты с email и паролем) один раз сбрасывает её целиком и
// создаёт итоговую схему. База — фикстура test/e2e/fixtures/legacy-2.0.0.*,
// в папку вложений до старта кладутся файлы по шаблону загрузок v2.0.0 и
// посторонние. Проверяется: ровно две строки [Reset] с числами, итоговая
// схема (колонки, индексы, ничего лишнего), нет ни одной строки данных, файлы
// по шаблону удалены, а чужие и папки — нет, повторный старт ничего не меняет.
//
// Базовый набор legacy-load.e2e.test.js проверяет только, что фикстура
// загружается; поведение при старте на ней — здесь.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createSuite } = require('./helpers/scenarios');
const { createDatabase, dropDatabase, connectPool, schemaSnapshot } = require('./helpers/pg');
const { ServerHandle } = require('./helpers/server');
const { loadLegacyFixture, legacyServerSecrets } = require('./helpers/legacy');
const { randomSecrets } = require('./helpers/env');
const { signSessionCookie, sessionCookie, SESSION_COOKIE } = require('./helpers/anon');

const suite = createSuite('reset', { legacy: true, startServer: false });

// Строки лога — ровно как в контракте §1: только числа.
const FOUND_LINE = (users, messages) => `[Reset] Обнаружена старая схема: удаляются тестовые данные (пользователей: ${users}, сообщений: ${messages})`;
const FILES_LINE = (count) => `[Reset] Удалено файлов вложений: ${count}`;

const resetLines = (server, from = 0) => server.logs.entries({ from }).map(l => l.text).filter(text => text.includes('[Reset]'));

const countRows = async (db, table) => Number((await db.query(`SELECT count(*) AS n FROM ${table}`)).rows[0].n);

// Положить файлы в папку вложений сервера до его старта.
function plant(uploadsDir, files) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(uploadsDir, name), content);
}

// Отдельная база и сервер на тест (с уборкой): легаси-фикстура или пустая.
async function withScratch({ legacy = false, name }, fn) {
    const { name: dbName, url } = await createDatabase();
    const db = connectPool(url);
    const server = new ServerHandle({ databaseUrl: url, secrets: legacy ? legacyServerSecrets() : randomSecrets(), name });
    try {
        if (legacy) await loadLegacyFixture(url);
        return await fn({ db, server });
    } catch (err) {
        err.message += `\n--- хвост лога сервера ${name}:\n${server.logs.tail(40)}`;
        throw err;
    } finally {
        await server.dispose().catch(() => {});
        await db.end().catch(() => {});
        await dropDatabase(dbName).catch(() => {});
    }
}

test('старт на базе v2.0.0: ровно две строки [Reset], итоговая схема, пустые данные, файлы по шаблону удалены', async () => {
    const meta = suite.legacy;
    const legacyUsers = Object.keys(meta.users).length;
    const legacyMessages = Object.keys(meta.messages).length;

    // Исходное состояние — действительно старая схема с данными.
    const legacyColumns = await suite.query(`SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users' AND column_name IN ('email', 'password') ORDER BY 1`);
    assert.deepStrictEqual(legacyColumns.rows.map(r => r.column_name), ['email', 'password'], 'в фикстуре у users есть email и password');
    assert.ok((await suite.query(`SELECT to_regclass('security_events') AS t`)).rows[0].t, 'в фикстуре есть журнал безопасности');
    assert.strictEqual(await countRows(suite.db, 'users'), legacyUsers);
    assert.strictEqual(await countRows(suite.db, 'messages'), legacyMessages);
    const legacyNames = (await suite.query('SELECT username FROM users')).rows.map(r => r.username);
    // Сессии фикстуры живые на момент теста (в дампе у них срок 2026-09/10):
    // иначе проверка «старые куки недействительны» была бы пустой.
    await suite.query(`UPDATE session SET expire = NOW() + INTERVAL '1 day'`);

    // Файлы вложений: два по шаблону v2.0.0 и один посторонний.
    const oldFiles = { '1759000000000-0123456789abcdef01234567.jpg': 'старое фото', '1759000000001-fedcba9876543210fedcba98.pdf': 'старый pdf' };
    const foreign = 'volume-note.txt';
    const server = suite.newServer({ name: 'reset-first' });
    plant(server.uploadsDir, { ...oldFiles, [foreign]: 'чужое на volume' });
    await server.start();
    suite.server = server;

    // Лог: обе строки, ровно в таком виде и в таком порядке, и больше ничего с [Reset].
    assert.deepStrictEqual(
        resetLines(server),
        [FOUND_LINE(legacyUsers, legacyMessages), FILES_LINE(Object.keys(oldFiles).length)],
        `ожидались ровно две строки [Reset]\n${server.logs.tail(30)}`
    );
    // В лог — только числа: ни id, ни имён, ни email, ни паролей, ни имён файлов.
    server.logs.assertNoSensitive({
        ids: [...Object.values(meta.users).map(u => u.id), ...Object.values(meta.rooms).map(r => r.id)],
        usernames: legacyNames,
        emails: Object.values(meta.users).map(u => u.email),
        passwords: Object.values(meta.users).map(u => u.password),
        files: [...Object.keys(oldFiles), foreign],
    });

    // Итоговая схема: нет колонок email/password, нет журнала безопасности.
    const columns = (await suite.query(`SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users'`)).rows.map(r => r.column_name);
    assert.ok(columns.length > 0, 'таблица users создана заново');
    assert.ok(!columns.includes('email') && !columns.includes('password'), `у users остались ${columns.join(', ')}`);
    assert.strictEqual((await suite.query(`SELECT to_regclass('security_events') AS t`)).rows[0].t, null, 'журнала безопасности нет');

    // Ни одной строки старых данных — ни в users, ни в одной другой таблице (кроме версии схемы).
    assert.strictEqual(await countRows(suite.db, 'users'), 0, 'users пуста');
    const tables = (await suite.query(`SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`)).rows.map(r => r.table_name);
    // session — отдельно: в неё может попасть строка пробы готовности самого харнесса, но не легаси-сессия.
    for (const table of tables.filter(name => name !== 'schema_meta' && name !== 'session')) {
        assert.strictEqual(await countRows(suite.db, `"${table}"`), 0, `таблица ${table} должна быть пуста после сброса`);
    }
    assert.strictEqual(await countRows(suite.db, 'schema_meta'), 1, 'версия схемы записана');
    const legacySids = Object.values(meta.users).map(u => u.sid);
    assert.strictEqual(
        (await suite.query('SELECT count(*)::int AS n FROM session WHERE sid = ANY($1)', [legacySids])).rows[0].n, 0,
        'легаси-сессий в таблице session нет'
    );

    // Файлы: по шаблону удалены, посторонний на месте с тем же содержимым.
    assert.deepStrictEqual(fs.readdirSync(server.uploadsDir).sort(), [foreign]);
    assert.strictEqual(fs.readFileSync(path.join(server.uploadsDir, foreign), 'utf8'), 'чужое на volume');

    // Приложение работает: аккаунт создаётся; куки легаси-сессий недействительны.
    const fresh = suite.client();
    const user = await fresh.registerAnon();
    const secret = suite.secrets.SESSION_SECRET;
    const own = sessionCookie(fresh);
    assert.strictEqual(signSessionCookie(own.sid, secret), own.value, 'подпись куки в тесте совпадает с серверной — подложные куки ниже настоящие');
    for (const who of Object.keys(meta.users)) {
        const old = suite.client();
        old.withCookie(SESSION_COOKIE, signSessionCookie(meta.users[who].sid, secret));
        assert.strictEqual((await old.auth()).authenticated, false, `легаси-сессия ${who} после сброса недействительна`);
    }

    // Повторный старт: строк [Reset] нет, схема та же, данные нового аккаунта целы.
    const snapshot = await schemaSnapshot(suite.db);
    const mark = server.logs.mark();
    await server.restart();
    assert.deepStrictEqual(resetLines(server, mark), [], 'сброс при повторном старте не выполняется');
    assert.deepStrictEqual(await schemaSnapshot(suite.db), snapshot, 'схема после повторного старта та же');
    assert.strictEqual(await countRows(suite.db, 'users'), 1, 'новый аккаунт пережил рестарт');
    assert.strictEqual((await fresh.auth()).user.id, user.id);
});

test('схема после сброса совпадает со схемой свежей базы и соответствует контракту §2', async () => {
    // Свой сброс на отдельной базе: тест не зависит от предыдущего.
    const resetSnapshot = await withScratch({ legacy: true, name: 'reset-schema-legacy' }, async ({ server, db }) => {
        await server.start();
        return schemaSnapshot(db);
    });
    await withScratch({ name: 'reset-fresh' }, async ({ server, db }) => {
        await server.start();
        const fresh = await schemaSnapshot(db);
        // Сброс и первая установка дают одну и ту же схему.
        assert.deepStrictEqual(resetSnapshot.columns, fresh.columns, 'колонки');
        assert.deepStrictEqual(resetSnapshot.indexes, fresh.indexes, 'индексы');
        assert.deepStrictEqual(resetSnapshot.constraints, fresh.constraints, 'ограничения');
        assert.deepStrictEqual(resetSnapshot.functions, fresh.functions, 'функции');

        // §2: users.
        const users = fresh.columns.filter(c => c.table_name === 'users');
        assert.deepStrictEqual(
            users.map(c => c.column_name).sort(),
            ['anon_lifetime', 'avatar', 'created_at', 'id', 'last_active_at', 'read_receipts', 'unique_code', 'username']
        );
        const column = (name) => users.find(c => c.column_name === name);
        assert.match(column('id').column_default, /nyxo_random_id/);
        assert.strictEqual(column('created_at').data_type, 'timestamp with time zone');
        assert.match(column('created_at').column_default, /date_trunc\('minute'/i, 'created_at по умолчанию — до минуты');
        assert.strictEqual(column('read_receipts').is_nullable, 'NO');
        assert.match(column('read_receipts').column_default, /false/i, 'отметки о прочтении по умолчанию выключены');
        assert.strictEqual(column('anon_lifetime').is_nullable, 'NO');
        assert.strictEqual(column('last_active_at').is_nullable, 'NO');
        const lifetimeCheck = fresh.constraints.find(c => c.table_name === 'users' && /^CHECK/.test(c.def) && /anon_lifetime/.test(c.def));
        assert.ok(lifetimeCheck, 'нет CHECK на users.anon_lifetime');
        for (const value of ['tab', 'day', 'week']) assert.match(lifetimeCheck.def, new RegExp(value));
        const lifetimeIndex = fresh.indexes.find(i => i.indexname === 'idx_users_lifetime');
        assert.ok(lifetimeIndex, 'нет индекса idx_users_lifetime');
        assert.match(lifetimeIndex.indexdef, /\(anon_lifetime, last_active_at\)/);

        // §2: session и то, чего быть не должно.
        const sessionIndex = fresh.indexes.find(i => i.indexname === 'idx_session_user');
        assert.ok(sessionIndex, 'нет индекса idx_session_user');
        assert.match(sessionIndex.indexdef, /sess ->> 'userId'/);
        assert.ok(!fresh.columns.some(c => c.table_name === 'security_events'), 'таблицы security_events нет');
        assert.ok(!fresh.indexes.some(i => /idx_users_anon/.test(i.indexname)), 'индекса по email/password нет');
    });
});

test('в папке вложений удаляются только файлы по шаблону v2.0.0 и временные «-cleaned-»; чужое и папки целы', async () => {
    await withScratch({ legacy: true, name: 'reset-files' }, async ({ server }) => {
        // Под шаблон ^\d{13}-[0-9a-f]{24}(\.[a-z0-9]{2,5})?$ и временные файлы очистки метаданных.
        const doomed = [
            '1759000000000-0123456789abcdef01234567',
            '1759000000001-aaaaaaaaaaaaaaaaaaaaaaaa.png',
            '1759000000002-bbbbbbbbbbbbbbbbbbbbbbbb-cleaned-1a2b3c4d.jpg',
        ];
        // Почти шаблон, но не он — остаётся: чужие файлы на volume не наши.
        const lookalikes = [
            'volume-note.txt',
            '1759000000000-ABCDEF0123456789ABCDEF01.jpg',      // hex в верхнем регистре
            '175900000000-0123456789abcdef01234567.jpg',       // 12 цифр вместо 13
            '1759000000000-0123456789abcdef0123456.jpg',       // 23 hex-символа вместо 24
            '1759000000000-0123456789abcdef01234567.JPG',      // расширение в верхнем регистре
            '1759000000000-0123456789abcdef01234567.abcdef',   // расширение длиннее 5
        ];
        const folder = '1759000000003-cccccccccccccccccccccccc';   // папка с именем по шаблону
        const nested = '1759000000004-dddddddddddddddddddddddd.jpg';
        const uploadsDir = server.uploadsDir;
        plant(uploadsDir, Object.fromEntries([...doomed, ...lookalikes].map(name => [name, `содержимое ${name}`])));
        fs.mkdirSync(path.join(uploadsDir, folder));
        fs.writeFileSync(path.join(uploadsDir, folder, nested), 'файл в папке');

        await server.start();

        const lines = resetLines(server);
        assert.strictEqual(lines[1], FILES_LINE(doomed.length), lines.join('\n'));
        assert.deepStrictEqual(fs.readdirSync(uploadsDir).sort(), [...lookalikes, folder].sort());
        assert.strictEqual(fs.readFileSync(path.join(uploadsDir, folder, nested), 'utf8'), 'файл в папке', 'папки не трогаются, в том числе их содержимое');
        for (const name of lookalikes) {
            assert.strictEqual(fs.readFileSync(path.join(uploadsDir, name), 'utf8'), `содержимое ${name}`, name);
        }
    });
});

test('признак старой схемы: колонка email или password, либо users без schema_meta; иначе сброса нет', async () => {
    await withScratch({ name: 'reset-detect' }, async ({ server, db }) => {
        await server.start();
        assert.deepStrictEqual(resetLines(server), [], 'на пустой базе сбрасывать нечего');

        // Итоговая схема: у users нет ни email, ни password — иначе следующие шаги проверяли бы не то.
        const legacyColumns = async () => (await db.query(`SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'users' AND column_name IN ('email', 'password') ORDER BY 1`))
            .rows.map(r => r.column_name);
        assert.deepStrictEqual(await legacyColumns(), [], 'в итоговой схеме у users нет колонок email и password');

        // Данные, которые сброс должен стереть: аккаунт, комната и сообщение в ней (плюс приветствие бота).
        const seed = async (who) => {
            const client = server.client();
            await client.registerAnon();
            const room = await client.createRoom(`Комната ${who}`);
            await client.send(room.id, `сообщение ${who}`);
            return client;
        };

        // Схема новая (schema_meta есть, колонок нет): рестарт ничего не сбрасывает, данные на месте.
        const owner = await seed('до сброса');
        let mark = server.logs.mark();
        await server.restart();
        assert.deepStrictEqual(resetLines(server, mark), [], 'при schema_meta и без колонок email/password сброса нет');
        assert.strictEqual(await countRows(db, 'users'), 1);
        assert.ok((await owner.auth()).authenticated, 'аккаунт на месте');

        // Каждый признак старой схемы — отдельно: сброс, ровно две строки лога с числами, пустые таблицы, схема снова итоговая.
        const markers = [
            ['у users появилась колонка email', async () => { await db.query('ALTER TABLE users ADD COLUMN email TEXT'); }],
            ['у users появилась колонка password', async () => { await db.query('ALTER TABLE users ADD COLUMN password TEXT'); }],
            ['таблица users есть, а schema_meta нет', async () => { await db.query('DROP TABLE schema_meta'); }],
        ];
        for (const [what, mutate] of markers) {
            await server.stop();
            await mutate();
            const users = await countRows(db, 'users');
            const messages = await countRows(db, 'messages');
            assert.ok(users >= 1 && messages >= 2, `${what}: ожидались данные для сброса (users ${users}, messages ${messages})`);
            mark = server.logs.mark();
            await server.start();
            assert.deepStrictEqual(resetLines(server, mark), [FOUND_LINE(users, messages), FILES_LINE(0)], `${what}\n${server.logs.tail(20)}`);
            assert.strictEqual(await countRows(db, 'users'), 0, `${what}: users пуста`);
            assert.strictEqual(await countRows(db, 'messages'), 0, `${what}: messages пуста`);
            assert.strictEqual(await countRows(db, 'rooms'), 0, `${what}: rooms пуста`);
            assert.deepStrictEqual(await legacyColumns(), [], `${what}: колонок email и password нет`);
            assert.strictEqual(await countRows(db, 'schema_meta'), 1, `${what}: schema_meta на месте`);
            assert.strictEqual((await owner.auth()).authenticated, false, `${what}: сессия удалённого аккаунта недействительна`);

            // После сброса приложение работает, и ещё один рестарт его не трогает.
            const next = await seed(what);
            mark = server.logs.mark();
            await server.restart();
            assert.deepStrictEqual(resetLines(server, mark), [], `${what}: повторный старт не сбрасывает`);
            assert.ok((await next.auth()).authenticated, `${what}: аккаунт после сброса пережил рестарт`);
            assert.strictEqual(await countRows(db, 'users'), 1);
        }
    });
});
