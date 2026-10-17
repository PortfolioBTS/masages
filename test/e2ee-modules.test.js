'use strict';
// Чистые модули ядра E2EE (public/lib/e2ee-*.js, roadmap R14, T6.4) и их подключение.
//
// Протокол проверяют test/e2ee*.test.js; здесь - то, что они не видят:
//   1. модули загружаются по отдельности (в Node через require) и отдают именно свои функции;
//   2. public/e2ee.js берёт эти функции из модулей, а не держит копию (иначе правка модуля
//      молча перестала бы действовать на клиент);
//   3. index.html подключает модули ДО e2ee.js и после их зависимостей, в порядке зависимостей;
//   4. в браузерном режиме (глобальные Nyxo*, без require) клиент собирается теми же файлами
//      в порядке index.html, а без любого из модулей e2ee.js отказывает с понятной причиной.
//
// Запуск: node test/e2ee-modules.test.js

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

// Модуль -> { глобальное имя, зависимости (по файлам) }.
const MODULES = [
    { file: 'lib/e2ee-codec.js', global: 'NyxoE2eeCodec', after: [] },
    { file: 'lib/e2ee-crypto.js', global: 'NyxoE2eeCrypto', after: ['lib/e2ee-codec.js'] },
    { file: 'lib/e2ee-formats.js', global: 'NyxoE2eeFormats', after: ['lib/e2ee-codec.js', 'lib/ed25519-strict.js', 'lib/membership-client.js'] },
    { file: 'lib/e2ee-state.js', global: 'NyxoE2eeState', after: [] },
];
const loaded = MODULES.filter((m) => fs.existsSync(path.join(PUBLIC_DIR, m.file)));
assert.ok(loaded.length > 0, 'ни одного модуля e2ee-*.js');

// Теги <script src> index.html по порядку.
function scriptSources() {
    const html = read('index.html');
    return [...html.matchAll(/<script\s+src="([^"]+)"[^>]*><\/script>/g)].map((m) => m[1]);
}

test('каждый модуль загружается отдельно и экспортирует замороженный набор функций', () => {
    for (const mod of loaded) {
        const api = require(path.join(PUBLIC_DIR, mod.file));
        assert.ok(Object.isFrozen(api), `${mod.file}: набор должен быть заморожен`);
        const names = Object.keys(api);
        assert.ok(names.length >= 5, `${mod.file}: слишком мало имён (${names.length})`);
        for (const name of names) assert.notStrictEqual(api[name], undefined, `${mod.file}: ${name} не определено`);
    }
});

test('e2ee.js берёт функции из модулей: _internal ссылается на те же объекты', () => {
    const E2EE = require('../public/e2ee.js');
    const internal = E2EE._internal;
    let compared = 0;
    for (const mod of loaded) {
        const api = require(path.join(PUBLIC_DIR, mod.file));
        for (const [name, value] of Object.entries(api)) {
            if (!(name in internal)) continue;
            assert.strictEqual(internal[name], value, `${name}: e2ee.js держит копию, а не функцию из ${mod.file}`);
            compared++;
        }
    }
    assert.ok(compared >= 8, 'сравнено подозрительно мало имён: ' + compared);
});

test('e2ee.js не объявляет заново функции, вынесенные в модули', () => {
    const source = read('e2ee.js');
    for (const mod of loaded) {
        const api = require(path.join(PUBLIC_DIR, mod.file));
        for (const name of Object.keys(api)) {
            // Только верхний уровень модуля (отступ 4): одноимённые локальные помощники внутри функций не в счёт.
            const declared = new RegExp(`^ {4}(?:async\\s+)?function\\s+${name}\\s*\\(|^ {4}const\\s+${name}\\s*=`, 'm');
            assert.ok(!declared.test(source), `${name} объявлена и в ${mod.file}, и в e2ee.js`);
        }
    }
});

test('index.html подключает модули до e2ee.js и после их зависимостей', () => {
    const sources = scriptSources();
    const e2ee = sources.indexOf('e2ee.js');
    assert.ok(e2ee > 0, 'в index.html нет e2ee.js');
    for (const mod of loaded) {
        const at = sources.indexOf(mod.file);
        assert.ok(at >= 0, `в index.html нет ${mod.file}`);
        assert.ok(at < e2ee, `${mod.file} должен идти раньше e2ee.js`);
        assert.strictEqual(sources.lastIndexOf(mod.file), at, `${mod.file} подключён дважды`);
        for (const dep of mod.after) {
            const depAt = sources.indexOf(dep);
            assert.ok(depAt >= 0 && depAt < at, `${dep} должен идти раньше ${mod.file}`);
        }
    }
});

// ---- Браузерный режим: без require и module, глобальные Nyxo* ----

function browserContext() {
    const sandbox = { console, crypto: globalThis.crypto, TextEncoder, TextDecoder, structuredClone };
    sandbox.self = sandbox;
    return vm.createContext(sandbox);
}

function runScripts(context, files) {
    for (const file of files) vm.runInContext(read(file), context, { filename: file });
}

// Файлы, которые index.html подключает до e2ee.js включительно (без vendor и страничных помощников).
function browserFiles() {
    const sources = scriptSources();
    const upTo = sources.slice(0, sources.indexOf('e2ee.js') + 1);
    return upTo.filter((src) => src === 'mlkem.js' || src === 'e2ee.js' || src.startsWith('lib/'));
}

test('браузерный режим: скрипты в порядке index.html собирают E2EE из глобальных модулей', () => {
    const context = browserContext();
    runScripts(context, browserFiles());
    const E2EE = vm.runInContext('self.E2EE', context);
    assert.strictEqual(typeof E2EE.createClient, 'function');
    for (const mod of loaded) {
        const api = vm.runInContext(`self.${mod.global}`, context);
        assert.ok(api && typeof api === 'object', `${mod.global} не создан`);
        for (const [name, value] of Object.entries(api)) {
            if (name in E2EE._internal) assert.strictEqual(E2EE._internal[name], value, `${mod.global}.${name}`);
        }
    }
});

test('браузерный режим: без любого из модулей e2ee.js отказывает и называет файл', () => {
    for (const mod of loaded) {
        const context = browserContext();
        for (const file of browserFiles().filter((f) => f !== 'e2ee.js' && f !== mod.file)) {
            // Модули, зависящие от убранного, могут не собраться - важен отказ самого e2ee.js.
            try { vm.runInContext(read(file), context, { filename: file }); } catch { /* ожидаемо */ }
        }
        assert.throws(
            () => vm.runInContext(read('e2ee.js'), context, { filename: 'e2ee.js' }),
            (err) => err.message === `E2EE: модуль ${mod.file} не загружен`,
            `без ${mod.file}`
        );
    }
});


