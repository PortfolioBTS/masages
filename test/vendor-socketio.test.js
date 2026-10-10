'use strict';
// Вендоринг клиента socket.io (пункт 6.1, roadmap R10): public/vendor/socket.io.min.js
// лежит в репозитории, а не отдаётся сервером из node_modules. Так его байты
// входят в манифест клиента и сверяются с релизом, как любой другой файл.
//
// Что охраняется:
//  - версия в заголовке файла совпадает с версией socket.io в package-lock.json:
//    клиент и сервер одной версии, а обновление зависимости не оставляет старый
//    вендор незамеченным;
//  - файл — байт-в-байт копия client-dist/socket.io.min.js из npm-пакета (если
//    node_modules на месте): правок «от руки» в вендоре нет;
//  - рядом лежит текст лицензии MIT (она требует сохранить уведомление);
//  - сервер не отдаёт клиент сам (serveClient: false), а index.html ссылается на вендор.
// Запуск: node test/vendor-socketio.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const VENDOR = path.join(ROOT, 'public', 'vendor', 'socket.io.min.js');
const LICENSE = path.join(ROOT, 'public', 'vendor', 'socket.io.LICENSE.txt');
const NPM_DIR = path.join(ROOT, 'node_modules', 'socket.io');

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

console.log('Vendored socket.io client tests\n');

const lock = JSON.parse(fs.readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
const lockedVersion = lock.packages['node_modules/socket.io'].version;

test('версия вендора в заголовке совпадает с socket.io из package-lock.json', () => {
    const head = fs.readFileSync(VENDOR, 'utf8').slice(0, 400);
    const match = /Socket\.IO v(\d+\.\d+\.\d+)/.exec(head);
    assert.ok(match, 'в начале файла нет заголовка «Socket.IO vX.Y.Z»');
    assert.strictEqual(match[1], lockedVersion,
        `вендор ${match[1]}, а в package-lock ${lockedVersion}: обновите public/vendor/socket.io.min.js ` +
        'копированием node_modules/socket.io/client-dist/socket.io.min.js');
});

test('вендор — файл client-dist/socket.io.min.js из npm без изменений', () => {
    const npmFile = path.join(NPM_DIR, 'client-dist', 'socket.io.min.js');
    if (!fs.existsSync(npmFile)) {
        console.log('       (нет node_modules/socket.io — сверка с npm пропущена)');
        return;
    }
    const npmVersion = JSON.parse(fs.readFileSync(path.join(NPM_DIR, 'package.json'), 'utf8')).version;
    assert.strictEqual(npmVersion, lockedVersion, 'node_modules рассинхронизирован с package-lock (npm ci)');
    assert.ok(fs.readFileSync(VENDOR).equals(fs.readFileSync(npmFile)), 'public/vendor/socket.io.min.js отличается от npm-пакета');
});

test('в вендоре нет CR: хэш одинаков на Windows и Linux', () => {
    assert.ok(!fs.readFileSync(VENDOR).includes(0x0d), 'в файле есть CR (CRLF)');
});

test('лицензия MIT лежит рядом и совпадает с лицензией пакета', () => {
    const text = fs.readFileSync(LICENSE, 'utf8');
    assert.match(text, /The MIT License/);
    assert.match(text, /Guillermo Rauch/);
    const npmLicense = path.join(NPM_DIR, 'LICENSE');
    if (fs.existsSync(npmLicense)) assert.strictEqual(text, fs.readFileSync(npmLicense, 'utf8'));
});

test('сервер не отдаёт клиент socket.io сам: serveClient: false', () => {
    const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    assert.match(server, /new Server\(server, \{[^}]*?serveClient:\s*false/s);
});

test('index.html подключает вендор, а не /socket.io/socket.io.js, и раньше остальных скриптов клиента', () => {
    const html = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
    assert.ok(!html.includes('/socket.io/'), 'index.html ссылается на /socket.io/');
    const vendorAt = html.indexOf('src="vendor/socket.io.min.js"');
    assert.ok(vendorAt > 0, 'нет подключения vendor/socket.io.min.js');
    assert.ok(vendorAt < html.indexOf('src="script.js"'), 'io() нужен script.js — вендор должен идти раньше');
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
