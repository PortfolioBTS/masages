'use strict';
// Уборщик файлов-сирот (ревью W7 R2.5): lib/orphan-uploads.js. Удаляет только файлы с
// именем по шаблону загрузок, старше двух часов по mtime и без строки messages.file_url;
// чужие файлы, папки, свежие загрузки и файлы со ссылкой остаются.
// Сквозной сценарий с настоящей базой — test/e2e/orphan-uploads.e2e.test.js.
// Запуск: node test/orphan-uploads.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { isUploadFileName, sweepOrphanUploads, createOrphanSweeper } = require('../lib/orphan-uploads');

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

function makeDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-orphans-'));
}

function put(dir, name, ageMs) {
    const file = path.join(dir, name);
    fs.writeFileSync(file, 'x');
    const when = new Date(Date.now() - ageMs);
    fs.utimesSync(file, when, when);
    return name;
}

async function main() {
    await test('шаблон имён загрузок: 32 hex и расширение из списка, .bin или без расширения', () => {
        for (const ok of [`${hex()}.jpg`, `${hex()}.bin`, `${hex()}.pdf`, `${hex()}.mov`, hex()]) assert.ok(isUploadFileName(ok), ok);
        for (const bad of [
            `${hex()}.exe`, `${hex()}.JPG`, `${hex().slice(1)}.jpg`, `${hex()}-cleaned-1.jpg`,
            '1700000000000-0123456789abcdef01234567.jpg', 'lost+found', '.write-test-1', 'notes.txt',
            `${hex()}.jpg.bak`, `../${hex()}.jpg`,
        ]) assert.ok(!isUploadFileName(bad), bad);
    });

    await test('удаляются только старые файлы-сироты по шаблону; со ссылкой, свежие и чужие остаются', async () => {
        const dir = makeDir();
        try {
            const orphan = put(dir, `${hex()}.bin`, 3 * HOUR);
            const orphanNoExt = put(dir, hex(), 30 * HOUR);
            const referenced = put(dir, `${hex()}.png`, 5 * HOUR);
            const fresh = put(dir, `${hex()}.jpg`, 30 * 60 * 1000);
            const foreign = put(dir, 'notes.txt', 50 * HOUR);
            const temp = put(dir, `${hex()}-cleaned-123.jpg`, 50 * HOUR);
            fs.mkdirSync(path.join(dir, `${hex()}.jpg`)); // папка с «подходящим» именем
            const queries = [];
            const query = async (sql, params) => {
                queries.push({ sql, params });
                return params[0].filter(url => url === `/uploads/${referenced}`).map(url => ({ file_url: url }));
            };
            const logs = [];
            const result = await sweepOrphanUploads({ uploadsDir: dir, query, log: (line) => logs.push(line) });
            assert.deepStrictEqual(result, { candidates: 3, removed: 2, failed: 0 });
            const left = fs.readdirSync(dir).sort();
            for (const name of [orphan, orphanNoExt]) assert.ok(!left.includes(name), `сирота ${name} удалена`);
            for (const name of [referenced, fresh, foreign, temp]) assert.ok(left.includes(name), `${name} остался`);
            assert.strictEqual(left.length, 5, 'папка тоже осталась');
            assert.strictEqual(queries.length, 1);
            assert.match(queries[0].sql, /file_url = ANY\(\$1::text\[\]\)/);
            assert.deepStrictEqual(logs, ['[Uploads] Уборка файлов-сирот: удалено 2']);
            for (const line of logs) for (const name of [orphan, orphanNoExt]) assert.ok(!line.includes(name), 'имени файла нет в логе');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await test('порог возраста не ниже двух часов (mtime огрублён до часа)', async () => {
        const dir = makeDir();
        try {
            const name = put(dir, `${hex()}.bin`, 90 * 60 * 1000);
            const result = await sweepOrphanUploads({ uploadsDir: dir, query: async () => [], minAgeMs: 60 * 1000, log: () => {} });
            assert.strictEqual(result.removed, 0);
            assert.ok(fs.existsSync(path.join(dir, name)));
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await test('пачки ссылок; сбой базы — ошибка наружу, файлы не тронуты; папки нет — пустой проход', async () => {
        const dir = makeDir();
        try {
            const names = Array.from({ length: 5 }, () => put(dir, `${hex()}.bin`, 3 * HOUR));
            const sizes = [];
            const result = await sweepOrphanUploads({
                uploadsDir: dir, batchSize: 2, log: () => {},
                query: async (sql, params) => { sizes.push(params[0].length); return []; },
            });
            assert.deepStrictEqual(sizes.sort(), [1, 2, 2]);
            assert.strictEqual(result.removed, 5);

            const kept = Array.from({ length: 2 }, () => put(dir, `${hex()}.bin`, 3 * HOUR));
            await assert.rejects(sweepOrphanUploads({
                uploadsDir: dir, log: () => {}, query: async () => { throw Object.assign(new Error('timeout'), { code: '57014' }); },
            }), /timeout/);
            for (const name of kept) assert.ok(fs.existsSync(path.join(dir, name)), 'без ответа базы ничего не удаляется');
            assert.ok(names.every(name => !fs.existsSync(path.join(dir, name))));
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
        const missing = await sweepOrphanUploads({ uploadsDir: path.join(os.tmpdir(), `nyxo-no-such-${hex()}`), query: async () => [] });
        assert.deepStrictEqual(missing, { candidates: 0, removed: 0, failed: 0 });
    });

    await test('задача планировщика: проход не перекрывается с предыдущим', async () => {
        let calls = 0;
        let release;
        const gate = new Promise((resolve) => { release = resolve; });
        const dir = makeDir();
        try {
            put(dir, `${hex()}.bin`, 3 * HOUR);
            const run = createOrphanSweeper({ uploadsDir: dir, log: () => {}, query: async () => { calls++; await gate; return []; } });
            const first = run();
            const second = run();
            assert.strictEqual(first, second, 'второй вызов ждёт идущий проход');
            release();
            await first;
            assert.strictEqual(calls, 1);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
