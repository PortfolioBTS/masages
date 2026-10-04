'use strict';
// Сброс старой схемы lib/legacy-reset.js: признак старой схемы, транзакция
// сброса и удаление файлов вложений — на поддельном клиенте БД и временной
// папке. На настоящем Postgres (фикстура v2.0.0, старт сервера, повторный
// старт) — test/e2e/legacy-load.e2e.test.js и наборы волны 1.
// Запуск: node test/legacy-reset.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
    LEGACY_TABLES,
    isLegacyUploadName,
    isLegacySchema,
    detectLegacySchema,
    resetLegacySchema,
    deleteLegacyUploads,
    resetLegacyDatabase,
} = require('../lib/legacy-reset');

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

const tempDirs = [];
function tempDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-legacy-reset-'));
    tempDirs.push(dir);
    return dir;
}

// Имена по старому шаблону загрузок: 13 цифр, дефис, 24 hex, расширение.
const OLD_A = '1727000000000-0123456789abcdef01234567.jpg';
const OLD_B = '1727000000001-fedcba9876543210fedcba98.pdf';
const OLD_NO_EXT = '1727000000002-aaaaaaaaaaaaaaaaaaaaaaaa';
const OLD_TEMP = '1727000000003-bbbbbbbbbbbbbbbbbbbbbbbb-cleaned-1a2b3c4d.png';

// Поддельный клиент: facts — строка, которую отдаёт запрос признаков;
// tables — какие таблицы есть и сколько в них строк; failOn — запрос, который
// падает (как lock_timeout, 55P03). events — все запросы по порядку, туда же
// пишет log, чтобы видеть, что строка лога идёт после COMMIT.
function makeFakeClient({
    facts = { has_users: true, has_schema_meta: false, has_legacy_columns: true },
    tables = { users: 3, messages: 7 },
    failOn = null,
    failRollback = false,
} = {}) {
    const events = [];
    return {
        events,
        released: false,
        releasedWith: undefined,
        async query(sql, params) {
            const text = sql.replace(/\s+/g, ' ').trim();
            events.push(text);
            if (failOn && failOn.test(text)) throw Object.assign(new Error('сбой запроса'), { code: '55P03' });
            if (text === 'ROLLBACK' && failRollback) throw new Error('сбой ROLLBACK');
            if (text.includes('has_legacy_columns')) return { rows: [facts] };
            if (text.startsWith('SELECT to_regclass($1)')) return { rows: [{ present: Object.hasOwn(tables, params[0]) }] };
            const count = /^SELECT count\(\*\) AS n FROM (\w+)$/.exec(text);
            if (count) return { rows: [{ n: String(tables[count[1]]) }] };
            return { rows: [], rowCount: 0 };
        },
        release(err) {
            this.released = true;
            this.releasedWith = err;
        },
    };
}

async function main() {
    console.log('Legacy reset tests\n');

    await test('список таблиц сброса — как в контракте волны 1 §1', () => {
        assert.deepStrictEqual([...LEGACY_TABLES], [
            'reactions', 'message_expiry', 'chat_settings', 'room_settings', 'e2ee_key_shares', 'join_requests',
            'security_events', 'unread', 'room_participants', 'messages', 'chats', 'rooms', 'users',
            'identity_keys', 'signed_prekeys', 'one_time_prekeys', 'signed_pq_prekeys', 'session',
        ]);
        assert.ok(!LEGACY_TABLES.includes('schema_meta'), 'версия схемы переживает сброс');
    });

    // ---- признак старой схемы ----

    await test('признак: колонка email или password — старая схема, с schema_meta или без', () => {
        for (const hasSchemaMeta of [false, true]) {
            assert.strictEqual(isLegacySchema({ hasUsers: true, hasSchemaMeta, hasLegacyColumns: true }), true);
        }
    });

    await test('признак: users есть, schema_meta нет — старая схема, даже без колонок email и password', () => {
        assert.strictEqual(isLegacySchema({ hasUsers: true, hasSchemaMeta: false, hasLegacyColumns: false }), true);
    });

    await test('признак: schema_meta есть и колонок нет — никогда не сбрасывать', () => {
        assert.strictEqual(isLegacySchema({ hasUsers: true, hasSchemaMeta: true, hasLegacyColumns: false }), false);
    });

    await test('признак: пустая база и база без users — сбрасывать нечего', () => {
        assert.strictEqual(isLegacySchema({ hasUsers: false, hasSchemaMeta: false, hasLegacyColumns: false }), false);
        assert.strictEqual(isLegacySchema({ hasUsers: false, hasSchemaMeta: true, hasLegacyColumns: false }), false);
        assert.strictEqual(isLegacySchema({}), false);
    });

    await test('detectLegacySchema: ответ запроса признаков на поддельном клиенте', async () => {
        const cases = [
            [{ has_users: true, has_schema_meta: false, has_legacy_columns: true }, true],
            [{ has_users: true, has_schema_meta: true, has_legacy_columns: true }, true],
            [{ has_users: true, has_schema_meta: false, has_legacy_columns: false }, true],
            [{ has_users: true, has_schema_meta: true, has_legacy_columns: false }, false],
            [{ has_users: false, has_schema_meta: false, has_legacy_columns: false }, false],
        ];
        for (const [facts, expected] of cases) {
            const client = makeFakeClient({ facts });
            assert.strictEqual(await detectLegacySchema(client), expected, JSON.stringify(facts));
            assert.strictEqual(client.events.length, 1, 'один запрос, без транзакции');
        }
        const empty = { async query() { return { rows: [] }; } };
        assert.strictEqual(await detectLegacySchema(empty), false, 'нет строки — нет признаков');
    });

    await test('detectLegacySchema: схема — current_schema(), колонки ищутся именно email и password', async () => {
        const client = makeFakeClient();
        await detectLegacySchema(client);
        const sql = client.events[0];
        assert.match(sql, /current_schema\(\)/);
        assert.match(sql, /table_name = 'users'/);
        assert.match(sql, /column_name IN \('email', 'password'\)/);
        assert.match(sql, /schema_meta/);
    });

    await test('detectLegacySchema: ошибка запроса не превращается в «схема не старая»', async () => {
        const client = makeFakeClient({ failOn: /has_legacy_columns/ });
        await assert.rejects(detectLegacySchema(client), /сбой запроса/);
    });

    // ---- шаблон имён файлов ----

    await test('шаблон имён: что считается загрузкой v2.0.0', () => {
        const removed = [
            OLD_A, OLD_B, OLD_NO_EXT, OLD_TEMP,
            '1727000000000-0123456789abcdef01234567.webm',   // расширение из 4 символов
            '1727000000000-0123456789abcdef01234567.mp4',
            '1727000000000-0123456789abcdef01234567.bin',    // шифротекст E2EE-вложения
            '1727000000000-0123456789abcdef01234567.gz',     // 2 символа — нижняя граница
            '1727000000000-0123456789abcdef01234567.abcde',  // 5 символов — верхняя граница
            'x-cleaned-1',                                   // любое имя с маркером временной копии
        ];
        for (const name of removed) assert.strictEqual(isLegacyUploadName(name), true, name);
    });

    await test('шаблон имён: что остаётся на месте', () => {
        const kept = [
            'README.txt',
            'photo.jpg',
            'lost+found',
            '.write-test-1234',
            '.gitkeep',
            '',
            '172700000000-0123456789abcdef01234567.jpg',      // 12 цифр
            '17270000000000-0123456789abcdef01234567.jpg',    // 14 цифр
            '1727000000000-0123456789abcdef0123456.jpg',      // 23 hex
            '1727000000000-0123456789abcdef012345678.jpg',    // 25 hex
            '1727000000000-0123456789ABCDEF01234567.jpg',     // hex только в нижнем регистре
            '1727000000000-0123456789abcdef0123456g.jpg',     // не hex
            '1727000000000-0123456789abcdef01234567.j',       // расширение из 1 символа
            '1727000000000-0123456789abcdef01234567.abcdef',  // расширение из 6 символов
            '1727000000000-0123456789abcdef01234567.JPG',     // расширение в нижнем регистре
            '1727000000000-0123456789abcdef01234567.tar.gz',  // два расширения
            '1727000000000-0123456789abcdef01234567.jpg.bak', // хвост после расширения
            ' 1727000000000-0123456789abcdef01234567.jpg',    // пробел в начале
            '1727000000000-0123456789abcdef01234567.jpg\n',   // перевод строки в конце
            'backup-1727000000000-0123456789abcdef01234567.jpg',
        ];
        for (const name of kept) assert.strictEqual(isLegacyUploadName(name), false, JSON.stringify(name));
        for (const value of [undefined, null, 123, {}, ['a']]) assert.strictEqual(isLegacyUploadName(value), false);
    });

    // ---- удаление файлов вложений ----

    await test('файлы: удаляются только обычные файлы по шаблону, посторонние файлы и папки остаются', async () => {
        const dir = tempDir();
        for (const name of [OLD_A, OLD_B, OLD_NO_EXT, OLD_TEMP]) fs.writeFileSync(path.join(dir, name), 'старое вложение');
        fs.writeFileSync(path.join(dir, 'README.txt'), 'чужой файл');
        fs.writeFileSync(path.join(dir, 'photo.jpg'), 'похож на вложение, но имя не по шаблону');
        fs.writeFileSync(path.join(dir, '.write-test-1'), '');
        // Папка с именем по шаблону и вложенный файл по шаблону: в папки не заходим.
        const folderLikeUpload = path.join(dir, '1727000000009-cccccccccccccccccccccccc.jpg');
        fs.mkdirSync(folderLikeUpload);
        fs.writeFileSync(path.join(folderLikeUpload, OLD_A), 'внутри папки');
        fs.mkdirSync(path.join(dir, 'lost+found'));
        fs.writeFileSync(path.join(dir, 'lost+found', OLD_B), 'внутри чужой папки');

        const logs = [];
        const removed = await deleteLegacyUploads(dir, { log: (line) => logs.push(line), error: (line) => logs.push(`ERR ${line}`) });

        assert.strictEqual(removed, 4);
        assert.deepStrictEqual(logs, ['[Reset] Удалено файлов вложений: 4']);
        assert.deepStrictEqual(fs.readdirSync(dir).sort(), ['.write-test-1', '1727000000009-cccccccccccccccccccccccc.jpg', 'README.txt', 'lost+found', 'photo.jpg']);
        assert.deepStrictEqual(fs.readdirSync(folderLikeUpload), [OLD_A]);
        assert.deepStrictEqual(fs.readdirSync(path.join(dir, 'lost+found')), [OLD_B]);
    });

    await test('файлы: ссылка с именем по шаблону не удаляется и не разыменовывается', async () => {
        const dir = tempDir();
        const target = path.join(tempDir(), 'target.txt');
        fs.writeFileSync(target, 'цель ссылки');
        const link = path.join(dir, OLD_A);
        try {
            fs.symlinkSync(target, link);
        } catch (err) {
            console.log('       пропущено: символические ссылки недоступны (' + err.code + ')');
            return;
        }
        const logs = [];
        assert.strictEqual(await deleteLegacyUploads(dir, { log: (line) => logs.push(line) }), 0);
        assert.deepStrictEqual(logs, ['[Reset] Удалено файлов вложений: 0']);
        assert.ok(fs.lstatSync(link).isSymbolicLink());
        assert.strictEqual(fs.readFileSync(target, 'utf8'), 'цель ссылки');
    });

    await test('файлы: пустая и несуществующая папка — ноль, без ошибки', async () => {
        const logs = [];
        const errors = [];
        const opts = { log: (line) => logs.push(line), error: (line) => errors.push(line) };
        assert.strictEqual(await deleteLegacyUploads(tempDir(), opts), 0);
        assert.strictEqual(await deleteLegacyUploads(path.join(tempDir(), 'нет-такой'), opts), 0);
        assert.deepStrictEqual(logs, ['[Reset] Удалено файлов вложений: 0', '[Reset] Удалено файлов вложений: 0']);
        assert.deepStrictEqual(errors, []);
    });

    await test('файлы: много файлов (больше порции удаления) — удаляются все, посторонний остаётся', async () => {
        const dir = tempDir();
        for (let i = 0; i < 100; i++) {
            fs.writeFileSync(path.join(dir, `${1727000000000 + i}-${String(i).padStart(24, '0')}.jpg`), '');
        }
        fs.writeFileSync(path.join(dir, 'keep.txt'), '');
        assert.strictEqual(await deleteLegacyUploads(dir, { log: () => {} }), 100);
        assert.deepStrictEqual(fs.readdirSync(dir), ['keep.txt']);
    });

    await test('файлы: сбой удаления не останавливает остальные; в логе числа и коды, без имён файлов', async () => {
        const entries = [OLD_A, OLD_B, OLD_NO_EXT, 'README.txt'].map(name => ({ name, isFile: () => true }));
        const unlinked = [];
        const fsApi = {
            async readdir() { return entries; },
            async unlink(file) {
                const name = path.basename(file);
                if (name === OLD_A) throw Object.assign(new Error(`EPERM: operation not permitted, unlink '${file}'`), { code: 'EPERM' });
                if (name === OLD_B) throw Object.assign(new Error('уже нет'), { code: 'ENOENT' });
                unlinked.push(name);
            },
        };
        const logs = [];
        const errors = [];
        const removed = await deleteLegacyUploads('/uploads', { log: (l) => logs.push(l), error: (l) => errors.push(l), fsApi });
        assert.strictEqual(removed, 1, 'считаются только реально удалённые: ENOENT и EPERM — нет');
        assert.deepStrictEqual(unlinked, [OLD_NO_EXT]);
        assert.deepStrictEqual(logs, ['[Reset] Удалено файлов вложений: 1']);
        assert.deepStrictEqual(errors, ['[Reset] Не удалось удалить файлов вложений: 1 (коды ошибок: EPERM)']);
        assert.ok(![...logs, ...errors].some(line => line.includes(OLD_A)), 'имя файла в логе недопустимо');
    });

    await test('файлы: папку нельзя прочитать — ноль и строка с кодом ошибки, старт не падает', async () => {
        const fsApi = { async readdir() { throw Object.assign(new Error('EACCES: permission denied, scandir \'/секрет\''), { code: 'EACCES' }); } };
        const logs = [];
        const errors = [];
        assert.strictEqual(await deleteLegacyUploads('/секрет', { log: (l) => logs.push(l), error: (l) => errors.push(l), fsApi }), 0);
        assert.deepStrictEqual(logs, ['[Reset] Удалено файлов вложений: 0']);
        assert.deepStrictEqual(errors, ['[Reset] Не удалось прочитать папку вложений (код ошибки: EACCES)']);
    });

    // ---- транзакция сброса ----

    await test('сброс: BEGIN, числа, DROP всех таблиц по порядку контракта, DROP функции, COMMIT; строка лога — после COMMIT', async () => {
        const client = makeFakeClient({ tables: { users: 3, messages: 7, rooms: 2 } });
        const events = client.events;
        const logs = [];
        const result = await resetLegacySchema(client, { log: (line) => { events.push('LOG'); logs.push(line); } });

        assert.deepStrictEqual(result, { users: 3, messages: 7 });
        assert.deepStrictEqual(logs, ['[Reset] Обнаружена старая схема: удаляются тестовые данные (пользователей: 3, сообщений: 7)']);
        assert.strictEqual(events[0], 'BEGIN');
        const drops = events.filter(e => e.startsWith('DROP TABLE'));
        assert.deepStrictEqual(drops, LEGACY_TABLES.map(t => `DROP TABLE IF EXISTS ${t} CASCADE`));
        assert.strictEqual(events.filter(e => e.startsWith('DROP FUNCTION')).length, 1);
        assert.ok(events.includes('DROP FUNCTION IF EXISTS nyxo_random_id(regclass)'));
        assert.deepStrictEqual(events.slice(-3), ['DROP FUNCTION IF EXISTS nyxo_random_id(regclass)', 'COMMIT', 'LOG']);
        // Сначала числа, потом удаление: после DROP считать уже нечего.
        const lastCount = Math.max(...events.map((e, i) => (e.startsWith('SELECT count(*)') ? i : -1)));
        const firstDrop = events.findIndex(e => e.startsWith('DROP TABLE'));
        assert.ok(lastCount < firstDrop, 'числа посчитаны до первого DROP');
        // Таблица schema_meta и сессионные настройки не затрагиваются.
        assert.ok(!events.some(e => /schema_meta/.test(e) && e.startsWith('DROP')));
        assert.ok(!events.includes('ROLLBACK'));
    });

    await test('сброс: таблиц users и messages нет (старая схема создана не до конца) — числа 0, сброс проходит', async () => {
        const client = makeFakeClient({ tables: {} });
        const logs = [];
        const result = await resetLegacySchema(client, { log: (line) => logs.push(line) });
        assert.deepStrictEqual(result, { users: 0, messages: 0 });
        assert.deepStrictEqual(logs, ['[Reset] Обнаружена старая схема: удаляются тестовые данные (пользователей: 0, сообщений: 0)']);
        assert.ok(!client.events.some(e => e.startsWith('SELECT count(*)')), 'count по несуществующей таблице не выполняется');
        assert.ok(client.events.includes('COMMIT'));
    });

    await test('сброс: DDL не дождался блокировки — ROLLBACK, ошибка наверх, ни COMMIT, ни строки лога', async () => {
        const client = makeFakeClient({ failOn: /^DROP TABLE IF EXISTS chats CASCADE$/ });
        const logs = [];
        await assert.rejects(
            resetLegacySchema(client, { log: (line) => logs.push(line) }),
            (err) => err.code === '55P03' && /сбой запроса/.test(err.message)
        );
        assert.deepStrictEqual(logs, []);
        assert.ok(client.events.includes('ROLLBACK'));
        assert.ok(!client.events.includes('COMMIT'));
        assert.ok(!client.events.some(e => e.startsWith('DROP FUNCTION')), 'после сбоя дальше не идём');
    });

    await test('сброс: сбой самого ROLLBACK не затирает исходную ошибку', async () => {
        const client = makeFakeClient({ failOn: /^DROP FUNCTION/, failRollback: true });
        await assert.rejects(resetLegacySchema(client, { log: () => {} }), /сбой запроса/);
    });

    await test('сброс: сбой COMMIT — лог не пишется (данные могли не удалиться)', async () => {
        const client = makeFakeClient({ failOn: /^COMMIT$/ });
        const logs = [];
        await assert.rejects(resetLegacySchema(client, { log: (line) => logs.push(line) }), /сбой запроса/);
        assert.deepStrictEqual(logs, []);
    });

    // ---- всё вместе: resetLegacyDatabase ----

    function fakePool(client) {
        return { async connect() { return client; } };
    }

    await test('resetLegacyDatabase: схема не старая — ничего не меняется, файлы на месте, соединение возвращено', async () => {
        const dir = tempDir();
        fs.writeFileSync(path.join(dir, OLD_A), 'файл новой версии, имя по тому же шаблону');
        const client = makeFakeClient({ facts: { has_users: true, has_schema_meta: true, has_legacy_columns: false } });
        const logs = [];
        const reset = await resetLegacyDatabase({ pool: fakePool(client), uploadsDir: dir, log: (line) => logs.push(line) });
        assert.strictEqual(reset, false);
        assert.deepStrictEqual(logs, []);
        assert.deepStrictEqual(client.events.some(e => e === 'BEGIN' || e.startsWith('DROP')), false);
        assert.deepStrictEqual(fs.readdirSync(dir), [OLD_A]);
        assert.strictEqual(client.released, true);
        assert.strictEqual(client.releasedWith, undefined, 'исправное соединение возвращается в пул');
    });

    await test('resetLegacyDatabase: пустая база — сброса нет', async () => {
        const client = makeFakeClient({ facts: { has_users: false, has_schema_meta: false, has_legacy_columns: false } });
        assert.strictEqual(await resetLegacyDatabase({ pool: fakePool(client), uploadsDir: tempDir(), log: () => {} }), false);
        assert.ok(!client.events.includes('BEGIN'));
    });

    await test('resetLegacyDatabase: старая схема — сначала база, потом файлы; обе строки лога, посторонний файл на месте', async () => {
        const dir = tempDir();
        fs.writeFileSync(path.join(dir, OLD_A), 'a');
        fs.writeFileSync(path.join(dir, OLD_B), 'b');
        fs.writeFileSync(path.join(dir, 'foreign.dat'), 'не наш');
        const client = makeFakeClient({ tables: { users: 3, messages: 7 } });
        const logs = [];
        const reset = await resetLegacyDatabase({ pool: fakePool(client), uploadsDir: dir, log: (line) => logs.push(line) });
        assert.strictEqual(reset, true);
        assert.deepStrictEqual(logs, [
            '[Reset] Обнаружена старая схема: удаляются тестовые данные (пользователей: 3, сообщений: 7)',
            '[Reset] Удалено файлов вложений: 2',
        ]);
        assert.deepStrictEqual(fs.readdirSync(dir), ['foreign.dat']);
        assert.ok(client.events.includes('COMMIT'));
        assert.strictEqual(client.released, true);
    });

    await test('resetLegacyDatabase: сбой сброса — файлы не трогаются, соединение закрывается, ошибка наверх', async () => {
        const dir = tempDir();
        fs.writeFileSync(path.join(dir, OLD_A), 'a');
        const client = makeFakeClient({ failOn: /^DROP TABLE IF EXISTS users CASCADE$/ });
        const logs = [];
        await assert.rejects(
            resetLegacyDatabase({ pool: fakePool(client), uploadsDir: dir, log: (line) => logs.push(line) }),
            (err) => err.code === '55P03'
        );
        assert.deepStrictEqual(logs, []);
        assert.deepStrictEqual(fs.readdirSync(dir), [OLD_A], 'файлы удаляются только после COMMIT');
        assert.strictEqual(client.released, true);
        assert.ok(client.releasedWith instanceof Error, 'после ошибки соединение уничтожается, а не возвращается в пул');
    });

    await test('resetLegacyDatabase: нет соединения — ошибка наверх до любых изменений', async () => {
        const pool = { async connect() { throw new Error('нет соединения'); } };
        await assert.rejects(resetLegacyDatabase({ pool, uploadsDir: tempDir(), log: () => {} }), /нет соединения/);
    });

    for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
