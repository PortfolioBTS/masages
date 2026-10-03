'use strict';
// Запись ошибок в лог без персональных данных (lib/log-error.js).
// Запуск: node test/log-error.test.js

const assert = require('assert');
const { logError, describeError } = require('../lib/log-error');

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

// Так выглядит ошибка node-postgres при нарушении внешнего ключа.
function pgForeignKeyError() {
    const err = new Error('insert or update on table "messages" violates foreign key constraint "messages_user_id_fkey"');
    Object.assign(err, {
        code: '23503',
        constraint: 'messages_user_id_fkey',
        detail: 'Key (user_id)=(1955890954) is not present in table "users".',
        where: 'SQL statement "INSERT INTO messages ..." user 1955890954',
        parameters: ['1955890954', 'secret text'],
        table: 'messages',
        schema: 'public',
        hint: 'room 934210995',
    });
    return err;
}

function main() {
    console.log('Log error tests\n');

    test('ошибка Postgres: message, code и constraint есть, detail/where/parameters/hint и стека нет', () => {
        const text = describeError(pgForeignKeyError());
        assert.match(text, /violates foreign key constraint/);
        assert.match(text, /code=23503/);
        assert.match(text, /constraint=messages_user_id_fkey/);
        for (const leaked of ['1955890954', '934210995', 'secret text', 'Key (', 'SQL statement', '    at ']) {
            assert.ok(!text.includes(leaked), `в логе не должно быть «${leaked}»: ${text}`);
        }
    });

    test('logError пишет «контекст: описание» одной строкой через переданный log', () => {
        const lines = [];
        logError('[Anon] Purge error', pgForeignKeyError(), { log: (line) => lines.push(line) });
        assert.strictEqual(lines.length, 1);
        assert.ok(lines[0].startsWith('[Anon] Purge error: insert or update'));
        assert.ok(!lines[0].includes('\n'));
    });

    test('обычная ошибка без code — только сообщение', () => {
        assert.strictEqual(describeError(new TypeError('x is not a function')), 'x is not a function');
    });

    test('системная ошибка Node — сообщение и код', () => {
        const err = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:5432'), { code: 'ECONNREFUSED', address: '127.0.0.1' });
        assert.strictEqual(describeError(err), 'connect ECONNREFUSED 127.0.0.1:5432 (code=ECONNREFUSED)');
    });

    test('ошибка без сообщения (AggregateError) — имя вместо пустой строки', () => {
        const err = Object.assign(new AggregateError([new Error('a')], ''), { code: 'ECONNREFUSED' });
        assert.strictEqual(describeError(err), 'AggregateError (code=ECONNREFUSED)');
    });

    test('не-ошибки: строка, число, null, undefined, объект без полей', () => {
        assert.strictEqual(describeError('просто строка'), 'просто строка');
        assert.strictEqual(describeError(42), '42');
        assert.strictEqual(describeError(null), 'неизвестная ошибка');
        assert.strictEqual(describeError(undefined), 'неизвестная ошибка');
        assert.strictEqual(describeError({}), 'ошибка без описания');
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main();
