'use strict';
// Потолки обработки изображений на сервере (W7 R1 п.1): lib/metadata-stripper.js и
// lib/work-limiter.js. «Бомба» (файл в сотни КБ, заявляющий 268 Мпикс) отклоняется по
// заголовку, до декодирования; обработка идёт через ограничитель; память не растёт.
// Запуск: node test/image-limits.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const sharp = require('sharp');
const { stripMetadataFromFile, stripImageMetadata, _internal } = require('../lib/metadata-stripper');
const { createLimiter, BusyError } = require('../lib/work-limiter');
const { forgedPng, forgedJpeg, realBombPng } = require('./image-bombs');

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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-image-limits-'));
function tmpFile(name, data) {
    const file = path.join(tmp, name);
    fs.writeFileSync(file, data);
    return file;
}

function probe(file, mime) {
    return new Promise((resolve, reject) => {
        execFile(process.execPath, [path.join(__dirname, 'fixtures', 'strip-probe.js'), file, mime],
            { timeout: 60000, maxBuffer: 1 << 20 }, (err, stdout) => {
                if (err) return reject(err);
                resolve(JSON.parse(stdout.trim().split('\n').pop()));
            });
    });
}

async function rejection(promise) {
    try { await promise; } catch (err) { return err; }
    return assert.fail('ожидался отказ');
}

async function main() {
    await test('sharp: кэш выключен, потоков один (иначе несколько файлов раздувают память)', () => {
        assert.strictEqual(sharp.cache().memory.max, 0);
        assert.strictEqual(sharp.concurrency(), 1);
    });

    await test('умолчания: 24 Мпикс, 500 кадров; окружение их переопределяет, мусор игнорируется', () => {
        assert.deepStrictEqual(_internal.resolveImageLimits({}), { maxPixels: 24000000, maxFrames: 500 });
        assert.deepStrictEqual(_internal.resolveImageLimits({ IMAGE_MAX_PIXELS: '1000000', IMAGE_MAX_FRAMES: '10' }),
            { maxPixels: 1000000, maxFrames: 10 });
        assert.deepStrictEqual(_internal.resolveImageLimits({ IMAGE_MAX_PIXELS: 'abc', IMAGE_MAX_FRAMES: '-3' }),
            { maxPixels: 24000000, maxFrames: 500 });
    });

    await test('PNG с заголовком 16383x16383 отклоняется по размерам, исходный файл не тронут, временных файлов нет', async () => {
        const bytes = forgedPng(16383, 16383);
        const file = tmpFile('forged.png', bytes);
        const err = await rejection(stripMetadataFromFile(file, 'image/png'));
        assert.strictEqual(err.userFacing, true, 'причина показывается пользователю');
        assert.match(err.message, /слишком большое.*24 мегапикселей/);
        assert.deepStrictEqual(fs.readFileSync(file), bytes);
        assert.ok(!fs.readdirSync(tmp).some(name => name.includes('-cleaned-')), 'временный файл убран');
    });

    await test('JPEG 16383x16383 с EXIF Orientation=6 (бомба ревью) отклоняется по размерам', async () => {
        const file = tmpFile('forged.jpg', await forgedJpeg(16383, 16383));
        const err = await rejection(stripMetadataFromFile(file, 'image/jpeg'));
        assert.strictEqual(err.userFacing, true);
        assert.match(err.message, /слишком большое/);
    });

    await test('обычная картинка проходит; предел можно поднять и опустить через options.limits', async () => {
        const png = await sharp({ create: { width: 300, height: 200, channels: 3, background: '#336699' } }).png().toBuffer();
        const ok = tmpFile('ok.png', png);
        await stripMetadataFromFile(ok, 'image/png');
        assert.strictEqual((await sharp(ok).metadata()).width, 300);
        const tight = tmpFile('tight.png', png);
        const err = await rejection(stripMetadataFromFile(tight, 'image/png', { limits: { maxPixels: 59999, maxFrames: 500 } }));
        assert.match(err.message, /слишком большое/);
        // Ровно на пределе - проходит (60000 = 300 x 200).
        await stripMetadataFromFile(tmpFile('edge.png', png), 'image/png', { limits: { maxPixels: 60000, maxFrames: 500 } });
    });

    await test('анимированный GIF: предел кадров и предел пикселей на все кадры вместе', async () => {
        const frames = [];
        for (let i = 0; i < 12; i++) {
            frames.push(await sharp({ create: { width: 40, height: 40, channels: 3, background: { r: i * 20, g: 30, b: 255 - i * 20 } } }).png().toBuffer());
        }
        const gif = await sharp(frames, { join: { animated: true } }).gif().toBuffer();
        const pages = (await sharp(gif).metadata()).pages;
        assert.ok(pages >= 6, `в тестовой анимации должно быть несколько кадров (есть ${pages})`);
        const byFrames = await rejection(stripMetadataFromFile(tmpFile('anim1.gif', gif), 'image/gif', { limits: { maxPixels: 24000000, maxFrames: 3 } }));
        assert.match(byFrames.message, /слишком много кадров/);
        assert.strictEqual(byFrames.userFacing, true);
        // 40x40 на pages кадров: суммарно больше 3000 пикселей.
        const byPixels = await rejection(stripMetadataFromFile(tmpFile('anim2.gif', gif), 'image/gif', { limits: { maxPixels: 3000, maxFrames: 500 } }));
        assert.match(byPixels.message, /на все кадры вместе/);
        await stripMetadataFromFile(tmpFile('anim3.gif', gif), 'image/gif');
        assert.strictEqual((await sharp(path.join(tmp, 'anim3.gif'), { animated: true }).metadata()).pages, pages, 'анимация сохранилась');
    });

    await test('stripImageMetadata сам проверяет размеры (а не только обёртка stripMetadataFromFile)', async () => {
        const file = tmpFile('direct.png', forgedPng(16383, 16383));
        const err = await rejection(stripImageMetadata(file, path.join(tmp, 'direct-out.png'), 'image/png'));
        assert.match(err.message, /слишком большое/);
        assert.ok(!fs.existsSync(path.join(tmp, 'direct-out.png')));
    });

    await test('ограничитель: лишние задачи ждут, переполнение очереди - BusyError, сбой задачи не занимает место', async () => {
        const limiter = createLimiter({ concurrency: 1, maxQueue: 1 });
        const order = [];
        let release;
        const gate = new Promise((resolve) => { release = resolve; });
        const first = limiter.run(async () => { order.push('first:start'); await gate; order.push('first:end'); return 1; });
        const second = limiter.run(async () => { order.push('second'); return 2; });
        assert.deepStrictEqual(limiter.stats(), { active: 1, queued: 1, concurrency: 1, maxQueue: 1 });
        const err = await rejection(limiter.run(async () => 3));
        assert.ok(err instanceof BusyError);
        assert.strictEqual(err.busy, true);
        assert.strictEqual(err.userFacing, true);
        release();
        assert.deepStrictEqual(await Promise.all([first, second]), [1, 2]);
        assert.deepStrictEqual(order, ['first:start', 'first:end', 'second']);
        await rejection(limiter.run(async () => { throw new Error('сбой'); }));
        assert.deepStrictEqual(limiter.stats(), { active: 0, queued: 0, concurrency: 1, maxQueue: 1 });
        assert.strictEqual(await limiter.run(() => 'снова работает'), 'снова работает');
    });

    await test('stripMetadataFromFile обрабатывает не больше concurrency файлов; лишний получает busy', async () => {
        const png = await sharp({ create: { width: 64, height: 64, channels: 3, background: '#aa5500' } }).png().toBuffer();
        const limiter = createLimiter({ concurrency: 1, maxQueue: 0 });
        const files = [tmpFile('b1.png', png), tmpFile('b2.png', png), tmpFile('b3.png', png)];
        const results = await Promise.allSettled(files.map(file => stripMetadataFromFile(file, 'image/png', { limiter })));
        assert.strictEqual(results[0].status, 'fulfilled');
        assert.ok(results.slice(1).every(r => r.status === 'rejected' && r.reason.busy === true), 'остальные отклонены busy');
        // Отказавший файл не тронут и читается.
        assert.strictEqual((await sharp(files[1]).metadata()).width, 64);
    });

    await test('настоящая бомба 16383x16383 (PNG, 268 Мпикс): отказ быстро, пик RSS не выше +250 МБ', async () => {
        const file = tmpFile('real-bomb.png', await realBombPng(16383, 16383));
        assert.ok(fs.statSync(file).size < 2 * 1024 * 1024, 'файл-бомба маленький');
        const result = await probe(file, 'image/png');
        assert.strictEqual(result.outcome, 'rejected', JSON.stringify(result));
        assert.ok(result.ms < 5000, `отказ должен быть быстрым: ${result.ms} мс`);
        assert.ok(result.peakMb - result.baseMb < 250, `пик RSS вырос на ${result.peakMb - result.baseMb} МБ (база ${result.baseMb})`);
    });

    fs.rmSync(tmp, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exit(1); });
