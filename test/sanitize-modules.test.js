'use strict';
// Части санитайзера медиафайлов (public/lib/sanitize-*.js, roadmap R14, T6.5) и их подключение.
//
// Поведение санитайзера проверяют test/media-sanitizer.test.js, test/pdf-*.test.js и test/mime-policy.test.js;
// здесь - то, что они не видят:
//   1. части загружаются по отдельности (в Node через require) и отдают именно свои функции;
//   2. media-sanitizer.js берёт функции из частей, а не держит копию (иначе правка части молча перестала бы
//      действовать на клиент или сервер), и его публичный API не изменился;
//   3. index.html подключает части ДО media-sanitizer.js, в порядке зависимостей, каждую один раз;
//   4. в браузерном режиме (глобальные Nyxo*, без require) санитайзер собирается теми же файлами в порядке
//      index.html и работает, а без любой из частей отказывается загружаться и называет файл (fail closed);
//   5. ни один прод-файл санитайзера не длиннее 1200 строк (критерий G6).
//
// Запуск: node test/sanitize-modules.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const read = (name) => fs.readFileSync(path.join(PUBLIC_DIR, name), 'utf8');

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// Часть -> { глобальное имя, зависимости (по файлам), экспорт }. Порядок - порядок подключения в index.html.
const PARTS = [
    { file: 'lib/sanitize-common.js', global: 'NyxoSanitizeCommon', after: [],
        names: ['MediaSanitizeError', 'fail', 'refuse', 'makeGuard', 'need', 'u8', 'u16be', 'u16le', 'u24be', 'u32be', 'u32le', 'u64be', 's32be',
            'fourcc', 'asciiAt', 'writeAscii', 'concatBytes', 'latin1', 'toUint8Array', 'crc32', 'PDF_WS'] },
    { file: 'lib/sanitize-jpeg.js', global: 'NyxoSanitizeJpeg', after: ['lib/sanitize-common.js'], names: ['sanitizeJpeg'] },
    { file: 'lib/sanitize-png-gif.js', global: 'NyxoSanitizePngGif', after: ['lib/sanitize-common.js'], names: ['sanitizePng', 'sanitizeGif'] },
    { file: 'lib/sanitize-webp.js', global: 'NyxoSanitizeWebp', after: ['lib/sanitize-common.js'], names: ['sanitizeWebp'] },
    { file: 'lib/sanitize-mp4.js', global: 'NyxoSanitizeMp4', after: ['lib/sanitize-common.js'], names: ['sanitizeBmff'] },
    { file: 'lib/sanitize-webm.js', global: 'NyxoSanitizeWebm', after: ['lib/sanitize-common.js'], names: ['sanitizeMatroska'] },
    { file: 'lib/sanitize-inflate.js', global: 'NyxoSanitizeInflate', after: ['lib/sanitize-common.js'],
        names: ['INFLATE_MAX_STREAM', 'INFLATE_MAX_TOTAL', 'INFLATE_MAX_BLOCKS', 'inflateSync'] },
    { file: 'lib/sanitize-pdf.js', global: 'NyxoSanitizePdf', after: ['lib/sanitize-common.js', 'lib/sanitize-inflate.js'],
        names: ['blankPdfMetadata', 'sanitizePdf'] },
];
const CORE = 'media-sanitizer.js';

// Теги <script src> index.html по порядку.
function scriptSources() {
    const html = read('index.html');
    return [...html.matchAll(/<script\s+src="([^"]+)"[^>]*><\/script>/g)].map((m) => m[1]);
}

test('каждая часть существует, загружается отдельно и отдаёт замороженный набор ровно из своих имён', () => {
    for (const part of PARTS) {
        assert.ok(fs.existsSync(path.join(PUBLIC_DIR, part.file)), `нет файла ${part.file}`);
        const api = require(path.join(PUBLIC_DIR, part.file));
        assert.ok(Object.isFrozen(api), `${part.file}: набор должен быть заморожен`);
        assert.deepStrictEqual(Object.keys(api), part.names, `${part.file}: состав экспорта`);
        for (const name of part.names) assert.notStrictEqual(api[name], undefined, `${part.file}: ${name} не определено`);
    }
});

test('в lib/ нет лишних sanitize-*.js: каждая часть учтена в этом тесте', () => {
    const onDisk = fs.readdirSync(path.join(PUBLIC_DIR, 'lib')).filter((f) => /^sanitize-.*\.js$/.test(f)).map((f) => 'lib/' + f).sort();
    assert.deepStrictEqual(onDisk, PARTS.map((p) => p.file).sort());
});

test('публичный API ядра прежний: sanitize, isSupported, SUPPORTED_TYPES и _internal с теми же именами', () => {
    const M = require('../public/media-sanitizer.js');
    assert.deepStrictEqual(Object.keys(M), ['sanitize', 'isSupported', 'SUPPORTED_TYPES', '_internal']);
    assert.strictEqual(typeof M.sanitize, 'function');
    assert.strictEqual(typeof M.isSupported, 'function');
    assert.ok(Object.isFrozen(M.SUPPORTED_TYPES));
    assert.deepStrictEqual([...M.SUPPORTED_TYPES], [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/quicktime', 'video/webm', 'application/pdf', 'text/plain',
    ]);
    assert.deepStrictEqual(Object.keys(M._internal).sort(),
        ['INFLATE_LIMITS', 'MediaSanitizeError', 'blankPdfMetadata', 'crc32', 'inflateSync', 'normalizeMimeType']);
    assert.ok(Object.isFrozen(M._internal.INFLATE_LIMITS));
});

test('ядро берёт функции из частей: _internal ссылается на те же объекты', () => {
    const M = require('../public/media-sanitizer.js');
    const Common = require('../public/lib/sanitize-common.js');
    const Inflate = require('../public/lib/sanitize-inflate.js');
    const Pdf = require('../public/lib/sanitize-pdf.js');
    assert.strictEqual(M._internal.MediaSanitizeError, Common.MediaSanitizeError);
    assert.strictEqual(M._internal.crc32, Common.crc32);
    assert.strictEqual(M._internal.inflateSync, Inflate.inflateSync);
    assert.strictEqual(M._internal.blankPdfMetadata, Pdf.blankPdfMetadata);
    assert.deepStrictEqual({ ...M._internal.INFLATE_LIMITS }, {
        stream: Inflate.INFLATE_MAX_STREAM, total: Inflate.INFLATE_MAX_TOTAL, blocks: Inflate.INFLATE_MAX_BLOCKS,
    });
});

test('отказы разборщиков - экземпляры одного и того же MediaSanitizeError из sanitize-common.js', () => {
    const M = require('../public/media-sanitizer.js');
    const { MediaSanitizeError } = require('../public/lib/sanitize-common.js');
    for (const [mime, bytes] of [['image/jpeg', [1, 2, 3]], ['image/png', [1, 2, 3]], ['image/gif', [1, 2, 3]], ['image/webp', [1, 2, 3]],
        ['video/mp4', [1, 2, 3]], ['video/webm', [1, 2, 3]], ['application/pdf', [1, 2, 3]], ['audio/mpeg', [1, 2, 3]]]) {
        assert.throws(() => M.sanitize(Uint8Array.from(bytes), mime), (err) => err instanceof MediaSanitizeError && err.name === 'MediaSanitizeError', mime);
    }
});

test('каждое имя объявлено только в своей части, а в остальных файлах только импортируется', () => {
    const sources = new Map([[CORE, read(CORE)], ...PARTS.map((p) => [p.file, read(p.file)])]);
    for (const part of PARTS) {
        for (const name of part.names) {
            // Верхний уровень фабрики (отступ 4). Импорт "const { name } = X;" под шаблон не подпадает.
            const declared = new RegExp(`^ {4}(?:async\\s+)?function\\s+${name}\\s*\\(|^ {4}(?:const|let|class)\\s+${name}\\b`, 'm');
            for (const [file, source] of sources) {
                if (file === part.file) assert.ok(declared.test(source), `${name} не объявлена в ${file}`);
                else assert.ok(!declared.test(source), `${name} объявлена и в ${file}, и в ${part.file}`);
            }
        }
    }
});

test('ядро не содержит разборщиков форматов: только диспетчер (короткий файл)', () => {
    const source = read(CORE);
    const topLevelFunctions = [...source.matchAll(/^ {4}function\s+(\w+)/gm)].map((m) => m[1]);
    assert.deepStrictEqual(topLevelFunctions, ['normalizeMimeType', 'isSupported', 'sanitize']);
});

test('ни один прод-файл санитайзера не длиннее 1200 строк', () => {
    for (const file of [CORE, ...PARTS.map((p) => p.file)]) {
        const lines = read(file).split('\n').length;
        assert.ok(lines <= 1200, `${file}: ${lines} строк`);
    }
});

test('index.html подключает части до media-sanitizer.js и после их зависимостей, каждую один раз', () => {
    const sources = scriptSources();
    const core = sources.indexOf(CORE);
    assert.ok(core > 0, 'в index.html нет media-sanitizer.js');
    assert.strictEqual(sources.lastIndexOf(CORE), core, 'media-sanitizer.js подключён дважды');
    for (const part of PARTS) {
        const at = sources.indexOf(part.file);
        assert.ok(at >= 0, `в index.html нет ${part.file}`);
        assert.ok(at < core, `${part.file} должен идти раньше media-sanitizer.js`);
        assert.strictEqual(sources.lastIndexOf(part.file), at, `${part.file} подключён дважды`);
        for (const dep of part.after) {
            const depAt = sources.indexOf(dep);
            assert.ok(depAt >= 0 && depAt < at, `${dep} должен идти раньше ${part.file}`);
        }
    }
});

// ---- Браузерный режим: без require и module, глобальные Nyxo* ----

function browserContext() {
    const sandbox = { console };
    sandbox.self = sandbox;
    return vm.createContext(sandbox);
}
function runScripts(context, files) {
    for (const file of files) vm.runInContext(read(file), context, { filename: file });
}
// Файлы санитайзера в порядке index.html (части, затем ядро).
function sanitizerFiles() {
    return scriptSources().filter((src) => src === CORE || /^lib\/sanitize-.*\.js$/.test(src));
}

// Небольшой корректный PNG с текстовым чанком (метаданные, которые санитайзер обязан убрать).
function samplePng() {
    const { crc32 } = require('../public/lib/sanitize-common.js');
    const chunk = (type, data) => {
        const b = Buffer.alloc(12 + data.length);
        b.writeUInt32BE(data.length, 0);
        b.write(type, 4, 'latin1');
        data.copy(b, 8);
        b.writeUInt32BE(crc32(b, 4, 8 + data.length), 8 + data.length);
        return b;
    };
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(1, 0);
    ihdr.writeUInt32BE(1, 4);
    ihdr[8] = 8;
    ihdr[9] = 2;
    return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), chunk('IHDR', ihdr),
        chunk('tEXt', Buffer.from('Author\0Ivan Petrov')), chunk('IDAT', Buffer.from([0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01])),
        chunk('IEND', Buffer.alloc(0))]);
}

test('браузерный режим: скрипты в порядке index.html собирают window.MediaSanitizer и он чистит файл', () => {
    const files = sanitizerFiles();
    assert.strictEqual(files.length, PARTS.length + 1);
    const context = browserContext();
    runScripts(context, files);
    for (const part of PARTS) {
        const api = vm.runInContext(`self.${part.global}`, context);
        assert.ok(api && typeof api === 'object', `${part.global} не создан`);
        assert.deepStrictEqual(Object.keys(api), part.names, `${part.global}: состав`);
    }
    // Массив из другой области выполнения (vm) копируем в свою: deepStrictEqual сравнивает прототипы.
    assert.deepStrictEqual(Array.from(vm.runInContext('Object.keys(self.MediaSanitizer)', context)), ['sanitize', 'isSupported', 'SUPPORTED_TYPES', '_internal']);
    const png = samplePng();
    context.pngBytes = Array.from(png);
    const cleaned = vm.runInContext("Array.from(self.MediaSanitizer.sanitize(Uint8Array.from(pngBytes), 'image/png'))", context);
    assert.ok(Buffer.from(cleaned).length < png.length, 'чанк tEXt должен быть удалён');
    assert.ok(!Buffer.from(cleaned).toString('latin1').includes('Ivan Petrov'));
    const text = vm.runInContext("self.MediaSanitizer.sanitize(Uint8Array.of(104, 105), 'text/plain').length", context);
    assert.strictEqual(text, 2);
    assert.strictEqual(vm.runInContext("self.MediaSanitizer.isSupported('image/jpg')", context), true);
    assert.strictEqual(vm.runInContext("self.MediaSanitizer.isSupported('audio/mpeg')", context), false);
    // Отказ приходит как MediaSanitizeError из браузерной копии sanitize-common.js.
    assert.strictEqual(vm.runInContext(
        "(() => { try { self.MediaSanitizer.sanitize(Uint8Array.of(1, 2, 3), 'video/mp4'); return 'нет отказа'; } catch (e) { return e instanceof self.NyxoSanitizeCommon.MediaSanitizeError ? e.name : 'чужая ошибка: ' + e; } })()",
        context), 'MediaSanitizeError');
});

test('браузерный режим: без любой из частей ядро отказывается загружаться и называет файл (fail closed)', () => {
    const files = sanitizerFiles();
    for (const part of PARTS) {
        const context = browserContext();
        for (const file of files.filter((f) => f !== CORE && f !== part.file)) {
            // Части, зависящие от убранной, могут не собраться - важен отказ самого ядра.
            try { vm.runInContext(read(file), context, { filename: file }); } catch { /* ожидаемо */ }
        }
        assert.throws(
            () => vm.runInContext(read(CORE), context, { filename: CORE }),
            (err) => err.message === `MediaSanitizer: модуль ${part.file} не загружен`,
            `без ${part.file}`
        );
        assert.strictEqual(vm.runInContext('typeof self.MediaSanitizer', context), 'undefined', `без ${part.file} MediaSanitizer не должен появиться`);
    }
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
