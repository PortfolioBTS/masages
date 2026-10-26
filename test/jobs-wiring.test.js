'use strict';
// Проводка фоновых задач сервера (src/jobs/index.js; ревью W7 R5, З-6): сами функции чистки проверяют свои
// тесты (lib.test.js - cleanupStaleTempFiles, orphan-uploads.test.js, e2e - заявки и анонимы), а здесь -
// что задача зарегистрирована, смотрит в ту папку и с тем порогом возраста, каким надо. Раньше потеря
// вызова cleanupStaleTempFiles в реестре не краснила ни один тест: задача идёт раз в час, и сквозные
// наборы её не видят.
// Запуск: node test/jobs-wiring.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createJobs } = require('../src/jobs/index');

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

const HOUR = 60 * 60 * 1000;
const hex = () => crypto.randomBytes(16).toString('hex');

// Контекст сервера из заглушек: пул блокировок задач (new Pool) ни к чему не подключается, пока не нужен.
function makeJobs(uploadsDir, overrides = {}) {
    const calls = { touched: [] };
    const ctx = {
        UPLOADS_DIR: uploadsDir,
        metrics: { jobRan() {} },
        userSocketCount: { keys: () => [7, 9] },
        DB_POOL_CONFIG: { connectionString: 'postgresql://nobody:none@127.0.0.1:1/none' },
        dbAll: async () => [],
        dbRun: async () => ({ rowCount: 0 }),
        anonActivity: { touch: async (ids) => { calls.touched.push([...ids]); } },
        purgeExpiredJoinRequests: async () => {},
        purgeExpiredAnonymousUsers: async () => {},
        serverContext: { pool: { query: async () => ({ rows: [], rowCount: 0 }) }, kt: null },
        ...overrides,
    };
    return { jobs: createJobs(ctx).jobs, calls };
}

function touch(file, ageMs) {
    const when = new Date(Date.now() - ageMs);
    fs.utimesSync(file, when, when);
}

async function main() {
    await test('в реестре есть все задачи сервера: чистки анонимов и заявок, продление сокетов, временные файлы, сироты', () => {
        const { jobs } = makeJobs(os.tmpdir());
        const names = jobs.names();
        for (const name of ['purgeExpiredAnonymousUsers', 'touchOnlineSockets', 'purgeExpiredJoinRequests', 'cleanupStaleTempFiles', 'sweepOrphanUploads']) {
            assert.ok(names.includes(name), `нет задачи ${name}: ${names.join(', ')}`);
        }
    });

    await test('расписание: временные файлы раз в час и вне тестовой ручки, чистки заявок и анонимов - в тестовом режиме быстрее', () => {
        const { jobs } = makeJobs(os.tmpdir());
        assert.deepStrictEqual(jobs.schedule('cleanupStaleTempFiles'), { first: null, every: 60 * 60 * 1000 });
        assert.deepStrictEqual(jobs.schedule('purgeExpiredJoinRequests'), { first: 90 * 1000, every: 60 * 60 * 1000 });
        assert.deepStrictEqual(jobs.schedule('purgeExpiredAnonymousUsers'), { first: 60 * 1000, every: 5 * 60 * 1000 });
    });

    await test('cleanupStaleTempFiles в реестре: удаляет старый временный файл в UPLOADS_DIR, свежий и вложения не трогает', async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-jobs-'));
        try {
            const staleTemp = path.join(dir, `${hex()}-cleaned-deadbeef.jpg`);
            const freshTemp = path.join(dir, `${hex()}-cleaned-cafebabe.jpg`);
            const attachment = path.join(dir, `${hex()}.jpg`);
            for (const f of [staleTemp, freshTemp, attachment]) fs.writeFileSync(f, 'x');
            // Старше любого порога задачи (она берёт не меньше двух часов: mtime файлов огрублён до часа).
            touch(staleTemp, 30 * HOUR);
            touch(attachment, 30 * HOUR);
            touch(freshTemp, 10 * 60 * 1000);

            const { jobs } = makeJobs(dir);
            assert.strictEqual(await jobs.runJob('cleanupStaleTempFiles'), true);
            assert.ok(!fs.existsSync(staleTemp), 'старый временный файл не удалён');
            assert.ok(fs.existsSync(freshTemp), 'свежий временный файл (обработка идёт) удалён');
            assert.ok(fs.existsSync(attachment), 'вложение удалено задачей временных файлов');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await test('порог возраста временных файлов - не меньше двух часов: файл возрастом 1,5 часа (mtime мог округлиться вниз) остаётся', async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-jobs-'));
        try {
            const young = path.join(dir, `${hex()}-cleaned-aaaaaaaa.png`);
            fs.writeFileSync(young, 'x');
            touch(young, 1.5 * HOUR);
            const { jobs } = makeJobs(dir);
            await jobs.runJob('cleanupStaleTempFiles');
            assert.ok(fs.existsSync(young), 'файл младше двух часов удалён');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await test('sweepOrphanUploads в реестре: сирота из UPLOADS_DIR удаляется, файл со ссылкой в messages остаётся', async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-jobs-'));
        try {
            const orphan = `${hex()}.bin`;
            const kept = `${hex()}.bin`;
            for (const name of [orphan, kept]) {
                fs.writeFileSync(path.join(dir, name), 'x');
                touch(path.join(dir, name), 30 * HOUR);
            }
            const queries = [];
            const dbAll = async (sql, params) => {
                queries.push(sql);
                return params[0].includes(`/uploads/${kept}`) ? [{ file_url: `/uploads/${kept}` }] : [];
            };
            const { jobs } = makeJobs(dir, { dbAll });
            assert.strictEqual(await jobs.runJob('sweepOrphanUploads'), true);
            assert.ok(!fs.existsSync(path.join(dir, orphan)), 'сирота не удалена');
            assert.ok(fs.existsSync(path.join(dir, kept)), 'файл со ссылкой удалён');
            assert.ok(queries.length > 0 && /messages/.test(queries[0]), 'ссылки проверяются в таблице messages');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await test('touchOnlineSockets в реестре передаёт touch id пользователей с открытыми сокетами процесса и продлевает их сессии', async () => {
        const dbRunCalls = [];
        const { jobs, calls } = makeJobs(os.tmpdir(), { dbRun: async (sql, params) => { dbRunCalls.push(params); return { rowCount: 0 }; } });
        assert.strictEqual(await jobs.runJob('touchOnlineSockets'), true);
        assert.deepStrictEqual(calls.touched, [[7, 9]], 'touch получил id пользователей с открытыми сокетами');
        assert.ok(dbRunCalls.some(params => JSON.stringify(params).includes('7') && JSON.stringify(params).includes('9')), 'строки сессий tab продлеваются тем же списком');
    });



    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exitCode = 1; });
