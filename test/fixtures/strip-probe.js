'use strict';
// Зонд для test/image-limits.test.js: гоняет lib/metadata-stripper на файле в
// ОТДЕЛЬНОМ процессе и печатает одну строку JSON — исход, время и пик RSS.
// Отдельный процесс нужен, чтобы память самого теста не искажала измерение.
// Запуск: node test/fixtures/strip-probe.js <файл> <mime>

const fs = require('fs');
const os = require('os');
const path = require('path');
const { stripMetadataFromFile } = require('../../lib/metadata-stripper');

const [file, mime] = process.argv.slice(2);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-probe-'));
const copy = path.join(dir, `probe${path.extname(file)}`);
fs.copyFileSync(file, copy);

const baseMb = process.memoryUsage().rss / 1048576;
let peak = process.memoryUsage().rss;
const timer = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); }, 10);
const started = Date.now();

function report(outcome, message) {
    clearInterval(timer);
    peak = Math.max(peak, process.memoryUsage().rss);
    fs.rmSync(dir, { recursive: true, force: true });
    console.log(JSON.stringify({
        outcome, message, ms: Date.now() - started,
        baseMb: Math.round(baseMb), peakMb: Math.round(peak / 1048576),
    }));
}

stripMetadataFromFile(copy, mime).then(() => report('ok'), (err) => report('rejected', err && err.message));
