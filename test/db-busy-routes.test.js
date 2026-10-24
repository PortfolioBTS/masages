'use strict';
// Маршруты при сбое доступности базы (ревью W7 R2.10): ответ 503 busy с Retry-After, а не
// «Ошибка …» / 500 / 502. Каждый catch-блок маршрута, который пишет ошибку в лог, первой
// строкой отдаёт её respondIfDbBusy (lib/db-errors.js); ошибки, ушедшие в next(), ловит
// обработчик ошибок Express (test/db-errors.test.js). Живые сценарии —
// test/e2e/db-resilience.e2e.test.js.
// Запуск: node test/db-busy-routes.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

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

const ROUTE_FILES = [
    ...fs.readdirSync(path.join(ROOT, 'src', 'http', 'routes')).filter(n => n.endsWith('.js')).map(n => `src/http/routes/${n}`),
    'lib/e2ee-groups.js', 'lib/e2ee-keys.js', 'lib/kt-routes.js',
];

test('catch-блоки маршрутов с logError сначала отвечают 503 busy при сбое базы', () => {
    const missing = [];
    let guarded = 0;
    for (const file of ROUTE_FILES) {
        const lines = fs.readFileSync(path.join(ROOT, file), 'utf8').split('\n');
        lines.forEach((line, i) => {
            const m = /^\s*\} catch \((\w+)\) \{$/.exec(line);
            if (!m) return;
            // Блок до первого logError: в нём должен быть respondIfDbBusy с той же ошибкой.
            const block = [];
            for (let j = i + 1; j < lines.length && j < i + 6; j++) {
                block.push(lines[j]);
                if (/^\s*logError\(/.test(lines[j])) break;
            }
            const logAt = block.findIndex(l => /^\s*logError\(/.test(l));
            if (logAt < 0) return;
            // Только блоки, которые отвечают клиенту (у служебных функций вроде
            // deleteKeysForUser ответа нет).
            const after = lines.slice(i + 2 + logAt, i + 5 + logAt).join('\n');
            if (!/\bres\.(json|status)\(/.test(after)) return;
            if (block.some(l => l.includes(`respondIfDbBusy(res, ${m[1]})`))) guarded++;
            else missing.push(`${file}:${i + 1}`);
        });
    }
    assert.deepStrictEqual(missing, [], 'catch без respondIfDbBusy:\n' + missing.join('\n'));
    assert.ok(guarded >= 30, `ожидалось не меньше 30 защищённых блоков, найдено ${guarded}`);
});

test('ответы маршрутов ключей без «E2EE key server» и 502: хранилище — эта же база', () => {
    for (const file of ROUTE_FILES) {
        const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
        assert.doesNotMatch(source, /status\(502\)/, file);
        assert.doesNotMatch(source, /message: '[^']*key server/i, file);
    }
});

test('удаление аккаунта: сбой базы (в том числе 40P01) — 503 busy, а не «Ошибка удаления аккаунта»', () => {
    const source = fs.readFileSync(path.join(ROOT, 'src', 'http', 'routes', 'auth.js'), 'utf8');
    const start = source.indexOf('async function deleteOwnAccount(');
    const body = source.slice(start, source.indexOf('\n    }\n', start));
    assert.ok(body.indexOf('respondIfDbBusy(res, error)') > 0 && body.indexOf('respondIfDbBusy(res, error)') < body.indexOf('Ошибка удаления аккаунта'));
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
