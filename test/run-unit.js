'use strict';
// Раннер юнит-тестов: сам находит test/*.test.js и запускает каждый файл
// отдельным процессом Node (как раньше делала цепочка через && в
// package.json). Раньше каждый новый тестовый файл приходилось дописывать
// в одну строку scripts.test — при параллельной работе это была гарантия
// конфликта слияния. Сквозные тесты (test/e2e/, им нужен Postgres) сюда не
// попадают: они во вложенной папке и запускаются отдельно.
//
// Запуск: npm test                       — все файлы
//         node test/run-unit.js pow lib  — только файлы, в имени которых
//                                          есть одна из подстрок
//
// В отличие от цепочки через &&, упавший файл не останавливает остальные:
// в конце печатается сводка, код выхода — 1, если упал хотя бы один.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const TEST_DIR = __dirname;
const filters = process.argv.slice(2);

const files = fs.readdirSync(TEST_DIR)
    .filter(name => name.endsWith('.test.js'))
    .filter(name => filters.length === 0 || filters.some(f => name.includes(f)))
    .sort();

if (files.length === 0) {
    console.error(filters.length > 0
        ? `Нет тестовых файлов, подходящих под: ${filters.join(', ')}`
        : 'В test/ нет файлов *.test.js');
    process.exit(1);
}

const results = [];
for (const name of files) {
    console.log(`\n=== ${name} ===`);
    const started = Date.now();
    const run = spawnSync(process.execPath, [path.join(TEST_DIR, name)], {
        stdio: 'inherit',
        cwd: path.join(TEST_DIR, '..'),
    });
    // status === null — процесс убит сигналом (например, по тайм-ауту ОС).
    const ok = run.status === 0 && !run.error;
    results.push({ name, ok, ms: Date.now() - started, detail: run.error ? run.error.message : run.signal });
}

console.log('\n=== Итог ===');
for (const r of results) {
    const extra = r.detail ? ` (${r.detail})` : '';
    console.log(`  ${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}  ${(r.ms / 1000).toFixed(1)} с${extra}`);
}
const failed = results.filter(r => !r.ok).length;
console.log(`\nФайлов: ${results.length}, упало: ${failed}`);
process.exitCode = failed > 0 ? 1 : 0;
