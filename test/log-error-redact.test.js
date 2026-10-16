'use strict';
// Чистка сообщений об ошибках от данных запроса (lib/log-error.js): значения
// из Postgres класса 22, текст разбираемого JSON, заголовки клиента и пути с
// именами вложений в лог попадать не должны.
// Запуск: node test/log-error-redact.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { describeError, logError } = require('../lib/log-error');

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

function main() {
    console.log('Log error redact tests\n');

    test('Postgres класс 22: значение из запроса в message не попадает, код остаётся', () => {
        const err = Object.assign(new Error('invalid input syntax for type integer: "1955890954-secret"'), { code: '22P02' });
        const text = describeError(err);
        assert.ok(!text.includes('1955890954'), text);
        assert.ok(!text.includes('secret'), text);
        assert.match(text, /code=22P02/);
    });

    test('Postgres класс 22: «value too long» и неверная кодировка тоже без значений', () => {
        for (const [code, message] of [
            ['22001', 'value too long for type character varying(64)'],
            ['22021', 'invalid byte sequence for encoding "UTF8": 0x00'],
            ['22003', 'integer out of range'],
        ]) {
            const text = describeError(Object.assign(new Error(message), { code }));
            assert.ok(!text.includes(message), text);
            assert.match(text, new RegExp(`code=${code}`));
        }
    });

    test('Postgres не из класса 22 (23505, 42P01, 40P01): message сохраняется', () => {
        const dup = Object.assign(new Error('duplicate key value violates unique constraint "users_pkey"'), { code: '23505', constraint: 'users_pkey' });
        assert.match(describeError(dup), /duplicate key value violates unique constraint/);
        assert.match(describeError(Object.assign(new Error('relation "session" does not exist'), { code: '42P01' })), /relation "session" does not exist/);
        assert.match(describeError(Object.assign(new Error('deadlock detected'), { code: '40P01' })), /deadlock detected/);
    });

    test('SyntaxError разбора JSON: текста из запроса в логе нет', () => {
        let parseError;
        try { JSON.parse('{"token":"hunter2-секрет", oops'); } catch (e) { parseError = e; }
        assert.ok(parseError instanceof SyntaxError);
        const text = describeError(parseError);
        assert.ok(!text.includes('hunter2'), text);
        assert.ok(!text.includes('секрет'), text);
        assert.match(text, /SyntaxError/);
    });

    test('ошибка body-parser (type и status): остаются type и status, message клиента — нет', () => {
        const err = Object.assign(new Error('unsupported charset "EVIL-user-supplied"'), { type: 'charset.unsupported', status: 415, statusCode: 415, expose: true });
        const text = describeError(err);
        assert.strictEqual(text, 'charset.unsupported (415)');
    });

    test('разбор тела запроса (entity.parse.failed): без body', () => {
        const err = Object.assign(new SyntaxError('Unexpected token \'h\', "hello-secret" is not valid JSON'), {
            type: 'entity.parse.failed', status: 400, statusCode: 400, body: 'hello-secret',
        });
        const text = describeError(err);
        assert.strictEqual(text, 'entity.parse.failed (400)');
    });

    test('ошибка файловой системы: имя вложения из пути заменено', () => {
        const file = path.join(os.tmpdir(), 'nyxo-redact-test', 'a1b2c3d4e5f6.bin');
        let fsError;
        try { fs.readFileSync(file); } catch (e) { fsError = e; }
        assert.ok(fsError && fsError.path === file, 'нужна настоящая ошибка fs с path');
        const text = describeError(fsError);
        assert.ok(!text.includes('a1b2c3d4e5f6'), text);
        assert.ok(!text.includes('nyxo-redact-test'), text);
        assert.match(text, /ENOENT/);
        assert.match(text, /<путь>/);
        assert.match(text, /code=ENOENT/);
    });

    test('rename с двумя путями: заменены и path, и dest', () => {
        const err = Object.assign(new Error("ENOENT: no such file or directory, rename '/up/one-secret.bin' -> '/up/two-secret.bin'"), {
            code: 'ENOENT', syscall: 'rename', path: '/up/one-secret.bin', dest: '/up/two-secret.bin',
        });
        const text = describeError(err);
        assert.ok(!text.includes('secret'), text);
        assert.match(text, /rename/);
    });

    test('короткий path не портит сообщение целиком', () => {
        const err = Object.assign(new Error("ENOENT: no such file or directory, open '.'"), { code: 'ENOENT', path: '.' });
        const text = describeError(err);
        assert.match(text, /no such file or directory/);
        assert.match(text, /<путь>/);
    });

    test('сетевая ошибка без path: сообщение как раньше', () => {
        const err = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET', syscall: 'read' });
        assert.strictEqual(describeError(err), 'read ECONNRESET (code=ECONNRESET)');
    });

    test('logError использует ту же чистку', () => {
        const lines = [];
        const err = Object.assign(new Error('invalid input syntax for type bigint: "42"'), { code: '22P02' });
        logError('[Test] ctx', err, { log: (line) => lines.push(line) });
        assert.strictEqual(lines.length, 1);
        assert.ok(!lines[0].includes('"42"'), lines[0]);
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main();
