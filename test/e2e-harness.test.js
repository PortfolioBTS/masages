'use strict';
// Чистые части харнесса сквозных тестов, которые отвечают за то, чтобы сбой
// набора не оставался без следов: повторы на временных ошибках Postgres
// (helpers/pg.js) и сохранение причин и логов упавшего набора
// (helpers/failure-log.js). Без БД и без запуска серверов; поведение целиком
// (после падения хука, необработанного исключения, сбоя старта сервера) —
// в test/e2e/harness-failures.e2e.test.js.
// Запуск: node test/e2e-harness.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { isTransientDbError, withRetry } = require('./e2e/helpers/pg');
const { SuiteDiagnostics, describeError } = require('./e2e/helpers/failure-log');

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

const dbError = (props, message = 'ошибка БД') => Object.assign(new Error(message), props);

async function withTempDir(fn) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-harness-test-'));
    try {
        return await fn(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

const fakeServer = (name, text) => ({ name, logs: { text: () => text } });
const FIXED_NOW = () => new Date('2026-10-04T10:20:30.456Z');

async function main() {
    console.log('E2E harness (диагностика сбоев набора) tests\n');

    // ---- helpers/pg.js: какие сбои считаются временными ----

    await test('isTransientDbError: нехватка слотов соединений, обрыв и недоступность сервера — временные', () => {
        for (const props of [{ code: '53300' }, { code: '57P03' }, { code: '08006' }, { code: '55006' }, { code: 'ECONNRESET' }, { code: 'ECONNREFUSED' }, { code: 'EPIPE' }]) {
            assert.strictEqual(isTransientDbError(dbError(props)), true, JSON.stringify(props));
        }
        for (const message of ['sorry, too many clients already', 'remaining connection slots are reserved for non-replication superuser connections',
            'Connection terminated unexpectedly', 'timeout expired', 'the database system is starting up']) {
            assert.strictEqual(isTransientDbError(new Error(message)), true, message);
        }
    });

    await test('isTransientDbError: ошибки запроса и логики — не временные', () => {
        for (const props of [{ code: '42P04' }, { code: '42601' }, { code: '28P01' }, { code: '3D000' }, {}]) {
            assert.strictEqual(isTransientDbError(dbError(props)), false, JSON.stringify(props));
        }
        assert.strictEqual(isTransientDbError(new Error('не тестовая база: x')), false);
        assert.strictEqual(isTransientDbError(null), false);
        assert.strictEqual(isTransientDbError(undefined), false);
    });

    // ---- helpers/pg.js: повторы ----

    await test('withRetry: временная ошибка повторяется с растущей паузой, затем успех', async () => {
        const pauses = [];
        let calls = 0;
        const result = await withRetry(async () => {
            calls++;
            if (calls < 3) throw dbError({ code: '53300' });
            return 'готово';
        }, { sleep: async (ms) => { pauses.push(ms); }, baseDelayMs: 200 });
        assert.strictEqual(result, 'готово');
        assert.strictEqual(calls, 3);
        assert.deepStrictEqual(pauses, [200, 400]);
    });

    await test('withRetry: обычная ошибка пробрасывается сразу, без повторов', async () => {
        let calls = 0;
        await assert.rejects(
            withRetry(async () => { calls++; throw dbError({ code: '42P04' }, 'уже есть'); }, { sleep: async () => {} }),
            /уже есть/
        );
        assert.strictEqual(calls, 1);
    });

    await test('withRetry: попытки исчерпаны — последняя ошибка, ровно attempts вызовов', async () => {
        let calls = 0;
        await assert.rejects(
            withRetry(async () => { calls++; throw dbError({ code: 'ECONNRESET' }, `обрыв ${calls}`); }, { attempts: 4, sleep: async () => {} }),
            /обрыв 4/
        );
        assert.strictEqual(calls, 4);
    });

    await test('withRetry: свой признак временной ошибки', async () => {
        let calls = 0;
        const result = await withRetry(async () => {
            calls++;
            if (calls === 1) throw new Error('особый сбой');
            return calls;
        }, { isTransient: (err) => /особый/.test(err.message), sleep: async () => {} });
        assert.strictEqual(result, 2);
    });

    // ---- helpers/failure-log.js: текст причины ----

    await test('describeError: Error со стеком, cause и вложенными ошибками; строка; объект; пусто', () => {
        const withCause = new Error('верхняя', { cause: new Error('глубокая') });
        const text = describeError(withCause);
        assert.match(text, /верхняя/);
        assert.match(text, /Причина:/);
        assert.match(text, /глубокая/);
        const aggregate = describeError(new AggregateError([new Error('первая'), new Error('вторая')], 'несколько'));
        assert.match(aggregate, /Вложенные ошибки \(2\)/);
        assert.match(aggregate, /первая/);
        assert.match(aggregate, /вторая/);
        assert.strictEqual(describeError('просто строка'), 'просто строка');
        assert.strictEqual(describeError({ code: 7 }), '{"code":7}');
        assert.match(describeError(undefined), /нет сведений/);
        assert.match(describeError(null), /нет сведений/);
        const circular = {};
        circular.self = circular;
        assert.strictEqual(typeof describeError(circular), 'string');
    });

    // ---- helpers/failure-log.js: файлы упавшего набора ----

    await test('SuiteDiagnostics: пока всё хорошо, сохранять нечего', () => {
        const d = new SuiteDiagnostics('rooms', { logsDir: '/нет/такой/папки', log: () => {}, now: FIXED_NOW });
        assert.strictEqual(d.failed, false);
        assert.strictEqual(d.needsSave, false);
    });

    await test('SuiteDiagnostics: сбой набора и сбой уборки различаются', () => {
        const d = new SuiteDiagnostics('rooms', { logsDir: '/x', log: () => {}, now: FIXED_NOW });
        d.warn('удаление базы', new Error('не удалось'));
        assert.strictEqual(d.failed, false, 'сбой уборки сам по себе набор не роняет');
        assert.strictEqual(d.needsSave, true, 'но след остаётся');
        d.fail('тест «x»', new Error('упал'));
        assert.strictEqual(d.failed, true);
    });

    await test('SuiteDiagnostics.save: логи каждого сервера и suite.log с причинами, метка времени в именах', async () => {
        await withTempDir((dir) => {
            const lines = [];
            const d = new SuiteDiagnostics('files', { logsDir: dir, log: (line) => lines.push(line), now: FIXED_NOW });
            d.fail('before: подготовка набора', new Error('сервер не стартовал'));
            d.fail('тест «квота»', 'ожидали 413, получили 200');
            d.warn('удаление базы nyxo_e2e_1_ab', new Error('нет соединения'));
            const { suiteFile, files } = d.save({
                dbName: 'nyxo_e2e_1_ab',
                servers: [fakeServer('files-1', 'строка 1\nстрока 2'), fakeServer('files-2', 'реплика')],
            });

            const stamp = '2026-10-04T10-20-30-456Z';
            assert.strictEqual(path.basename(suiteFile), `${stamp}-files-suite.log`);
            assert.deepStrictEqual(files.map(f => path.basename(f.file)), [`${stamp}-files-files-1.log`, `${stamp}-files-files-2.log`]);
            assert.strictEqual(fs.readFileSync(files[0].file, 'utf8'), 'строка 1\nстрока 2\n');
            assert.strictEqual(fs.readFileSync(files[1].file, 'utf8'), 'реплика\n');

            const report = fs.readFileSync(suiteFile, 'utf8');
            assert.match(report, /^Набор: files$/m);
            assert.match(report, /^База: nyxo_e2e_1_ab$/m);
            assert.match(report, /Причины сбоя \(2\):/);
            assert.match(report, /1\. \[before: подготовка набора\]\nError: сервер не стартовал/);
            assert.match(report, /2\. \[тест «квота»\]\nожидали 413, получили 200/);
            assert.match(report, /Сбои уборки — тесты от них не падали \(1\):/);
            assert.match(report, /нет соединения/);
            assert.match(report, /files-1: .*-files-files-1\.log/);
            assert.match(report, /files-2: .*-files-files-2\.log/);

            assert.ok(lines.some(l => l.startsWith('# лог сервера files-1: ')), lines.join('\n'));
            assert.ok(lines.some(l => l.startsWith('# причины сбоя набора files: ')), lines.join('\n'));
            assert.ok(lines.some(l => l === '# сбой набора files [before: подготовка набора]: Error: сервер не стартовал'), lines.join('\n'));
            assert.ok(lines.some(l => l.startsWith('# ВНИМАНИЕ, уборка набора files [удаление базы nyxo_e2e_1_ab]: ')), lines.join('\n'));
        });
    });

    await test('SuiteDiagnostics.save: набор без серверов (сбой до их создания) — только suite.log', async () => {
        await withTempDir((dir) => {
            const d = new SuiteDiagnostics('early', { logsDir: path.join(dir, 'вложенная', 'папка'), log: () => {}, now: FIXED_NOW });
            d.fail('before', new Error('нет подключения к Postgres'));
            const { suiteFile, files } = d.save({ dbName: null, servers: [] });
            assert.deepStrictEqual(files, []);
            const report = fs.readFileSync(suiteFile, 'utf8');
            assert.match(report, /нет подключения к Postgres/);
            assert.match(report, /Серверов у набора не было/);
            assert.ok(!/^База:/m.test(report), 'имени базы нет — строки о ней нет');
            assert.deepStrictEqual(fs.readdirSync(path.dirname(suiteFile)), [path.basename(suiteFile)]);
        });
    });

    await test('SuiteDiagnostics.save: повторное сохранение перезаписывает те же файлы и не дублирует вывод', async () => {
        await withTempDir((dir) => {
            const lines = [];
            let tick = 0;
            // Время идёт, но метка файлов фиксируется при первом сохранении.
            const now = () => new Date(Date.parse('2026-10-04T10:20:30.000Z') + (tick++) * 1000);
            const d = new SuiteDiagnostics('replay', { logsDir: dir, log: (line) => lines.push(line), now });
            d.fail('uncaughtException', new Error('БУМ'));
            const first = d.save({ servers: [fakeServer('replay-1', 'старый лог')] });
            const linesAfterFirst = lines.length;
            d.warn('остановка сервера', new Error('завис'));
            const second = d.save({ servers: [fakeServer('replay-1', 'старый лог\nновая строка')] });

            assert.strictEqual(second.suiteFile, first.suiteFile);
            assert.strictEqual(second.files[0].file, first.files[0].file);
            assert.strictEqual(fs.readdirSync(dir).length, 2, 'два файла, а не четыре');
            assert.strictEqual(fs.readFileSync(second.files[0].file, 'utf8'), 'старый лог\nновая строка\n');
            const report = fs.readFileSync(second.suiteFile, 'utf8');
            assert.match(report, /БУМ/);
            assert.match(report, /завис/);
            // Новое предупреждение объявлено, прежние строки — нет.
            assert.strictEqual(lines.length, linesAfterFirst + 1, lines.join('\n'));
            assert.ok(lines[lines.length - 1].startsWith('# ВНИМАНИЕ, уборка набора replay [остановка сервера]: '));
        });
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main();
