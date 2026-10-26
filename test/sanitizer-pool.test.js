'use strict';
// Очистка не-изображений на сервере вне главного потока (повторное ревью W7, Н0): lib/sanitizer-pool.js,
// lib/sanitizer-worker.js и серверный бюджет распаковки PDF.
//
// PDF в 100 КБ из пяти ObjStm, каждый распаковывается в 20 МБ пробелов, раньше чистился синхронно в главном потоке:
// ~2 с не обслуживался ни один запрос и сокет. Теперь:
//   * разбор идёт в потоке (worker_threads) — цикл событий сервера не стоит;
//   * у сервера бюджет распаковки PDF меньше клиентского — такой файл отклоняется быстро;
//   * зависший или упавший поток отклоняет файл с понятным текстом и заменяется новым;
//   * у потока предел памяти (resourceLimits).
// Запуск: node test/sanitizer-pool.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { performance } = require('perf_hooks');
const MediaSanitizer = require('../public/media-sanitizer.js');
const { stripMetadataFromFile, _internal } = require('../lib/metadata-stripper');
const { createSanitizerPool } = require('../lib/sanitizer-pool');
const { createLimiter } = require('../lib/work-limiter');
const { objStmBomb, sample } = require('./pdf-fixtures');

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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-sanitizer-pool-'));
function tmpFile(name, data) {
    const file = path.join(tmp, name);
    fs.writeFileSync(file, data);
    return file;
}

async function rejection(promise) {
    try { await promise; } catch (err) { return err; }
    return assert.fail('ожидался отказ');
}

// Наибольшая задержка таймера в 10 мс за время работы fn: столько главный поток не обслуживал бы запросы.
async function maxEventLoopLag(fn) {
    let max = 0;
    let last = performance.now();
    const timer = setInterval(() => {
        const now = performance.now();
        max = Math.max(max, now - last - 10);
        last = now;
    }, 10);
    try {
        return { result: await fn(), lag: () => max };
    } catch (err) {
        return { error: err, lag: () => max };
    } finally {
        clearInterval(timer);
    }
}

const FIXTURE_WORKER = path.join(__dirname, 'fixtures', 'sanitizer-test-worker.js');

async function main() {
    const bomb = objStmBomb();

    await test('PDF-«бомба» (100 КБ → 100 МБ распаковки): главный поток не блокируется, файл отклонён с понятным текстом', async () => {
        const file = tmpFile('objstm.pdf', bomb);
        const started = performance.now();
        const run = await maxEventLoopLag(() => stripMetadataFromFile(file, 'application/pdf', { limiter: createLimiter({ concurrency: 1, maxQueue: 0 }) }));
        const elapsed = performance.now() - started;
        // До правки — ~2200 мс; порог с запасом на соседей по пулу тестов (4 процесса на тех же ядрах).
        assert.ok(run.lag() < 500, `цикл событий стоял ${Math.round(run.lag())} мс`);
        assert.ok(run.error, 'файл должен быть отклонён серверным бюджетом распаковки');
        assert.strictEqual(run.error.userFacing, true, String(run.error && run.error.message));
        assert.match(run.error.message, /Сохранить как PDF/);
        assert.ok(elapsed < 5000, `отказ не дольше тайм-аута потока: ${Math.round(elapsed)} мс`);
        assert.deepStrictEqual(fs.readdirSync(tmp).filter((n) => n.includes('-cleaned-')), [], 'временных файлов не осталось');
    });

    await test('обычный PDF чистится в потоке так же, как раньше: Info затёрт, длина прежняя', async () => {
        const original = sample({ info: 'plain' });
        assert.ok(original.includes('Ivan Petrov'));
        const file = tmpFile('plain.pdf', original);
        await stripMetadataFromFile(file, 'application/pdf', { limiter: createLimiter({ concurrency: 1, maxQueue: 0 }) });
        const cleaned = fs.readFileSync(file);
        assert.strictEqual(cleaned.length, original.length);
        assert.ok(!cleaned.includes('Ivan Petrov'), 'автор затёрт');
        // Отказ санитайзера в потоке приходит с тем же текстом и признаком userFacing, что и в браузере.
        const compressed = tmpFile('compressed.pdf', sample({ info: 'compressed' }));
        const err = await rejection(stripMetadataFromFile(compressed, 'application/pdf', { limiter: createLimiter({ concurrency: 1, maxQueue: 0 }) }));
        assert.strictEqual(err.userFacing, true);
        assert.match(err.message, /^PDF содержит сжатые метаданные/);
    });

    await test('бюджет распаковки PDF — параметр: клиент (без параметра) принимает «бомбу», серверный бюджет её отклоняет', () => {
        const small = objStmBomb({ streams: 2, streamBytes: 10 * 1024 * 1024 });
        assert.ok(MediaSanitizer.sanitize(small, 'application/pdf').length === small.length, 'без параметра — клиентские 100 МБ');
        assert.throws(() => MediaSanitizer.sanitize(small, 'application/pdf', { maxInflateTotal: 16 * 1024 * 1024 }),
            (err) => err.userFacing === true && /Сохранить как PDF/.test(err.message));
        assert.ok(_internal.SERVER_PDF_INFLATE_TOTAL < MediaSanitizer._internal.INFLATE_LIMITS.total, 'серверный бюджет меньше клиентского');
        // Мусор вместо бюджета не снимает предел: берётся клиентский.
        for (const bad of [0, -1, 1.5, NaN, '16', null]) {
            assert.ok(MediaSanitizer.sanitize(small, 'application/pdf', { maxInflateTotal: bad }).length === small.length, String(bad));
        }
    });

    await test('тайм-аут потока: долгий разбор прерывается, файл отклонён с понятным текстом, следующий файл проходит', async () => {
        const pool = createSanitizerPool({ timeoutMs: 100 });
        try {
            const started = performance.now();
            // Без серверного бюджета «бомба» разбирается ~2 с — дольше тайм-аута.
            const err = await rejection(pool.sanitize(bomb, 'application/pdf'));
            assert.ok(performance.now() - started < 1500, 'тайм-аут сработал раньше конца разбора (~2 с)');
            assert.strictEqual(err.userFacing, true);
            assert.match(err.message, /не удалось обработать/i);
            assert.strictEqual(pool.stats().idle, 0, 'прерванный поток не возвращается в пул');
            const out = await pool.sanitize(sample({ info: 'plain' }), 'application/pdf');
            assert.ok(!Buffer.from(out).includes('Ivan Petrov'));
            assert.strictEqual(pool.stats().idle, 1, 'новый поток после работы ждёт следующую задачу');
        } finally {
            await pool.close();
        }
    });

    await test('упавший поток: отказ с понятным текстом, пул создаёт новый поток', async () => {
        const pool = createSanitizerPool({ workerFile: FIXTURE_WORKER });
        try {
            const err = await rejection(pool.sanitize(new Uint8Array([0xFF, 1, 2]), 'application/pdf'));
            assert.strictEqual(err.userFacing, true);
            assert.match(err.message, /не удалось обработать/i);
            assert.strictEqual(pool.stats().idle, 0);
            const out = await pool.sanitize(new Uint8Array([7, 8, 9]), 'application/pdf');
            assert.deepStrictEqual(Array.from(out), [7, 8, 9]);
        } finally {
            await pool.close();
        }
    });

    await test('у потока предел памяти (resourceLimits), входной буфер не портится передачей', async () => {
        const pool = createSanitizerPool({ workerFile: FIXTURE_WORKER, memoryMb: 200 });
        try {
            const out = await pool.sanitize(new Uint8Array([0xFE]), 'application/pdf');
            const limits = JSON.parse(Buffer.from(out).toString('utf8'));
            assert.strictEqual(limits.maxOldGenerationSizeMb, 200);
            // Буфер вызывающего передаётся копией: исходные байты остаются у него (Buffer из пула Node тоже).
            const input = Buffer.from([1, 2, 3]);
            await pool.sanitize(input, 'application/pdf');
            assert.deepStrictEqual(Array.from(input), [1, 2, 3]);
        } finally {
            await pool.close();
        }
    });

    await test('простаивающий поток не держит процесс: после работы пул можно не закрывать', async () => {
        const { execFileSync } = require('child_process');
        const script = `const { createSanitizerPool } = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'sanitizer-pool.js'))});
            const pool = createSanitizerPool();
            pool.sanitize(new Uint8Array(Buffer.from('hello')), 'text/plain').then((out) => console.log(Buffer.from(out).toString()));`;
        const started = performance.now();
        const out = execFileSync(process.execPath, ['-e', script], { timeout: 20000 }).toString().trim();
        assert.strictEqual(out, 'hello');
        assert.ok(performance.now() - started < 10000);
    });

    fs.rmSync(tmp, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exitCode = 1; });
