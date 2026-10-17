'use strict';
// Тест-запрет порядка по id (docs/security/message-ordering.md, раздел 6.1 и 15):
// id сообщения случайный и порядка не задаёт, порядок и курсоры — только seq.
// В server.js и public/js/*.js (бывший public/script.js) не должно быть выражений, которые молча
// превращают id обратно в порядок:
//   ORDER BY m.id    — сортировка по id;
//   id < $           — курсор «старше id» (старый ?before=<id>);
//   Number(m.id)     — числовое сравнение id сообщений.
// А также имён старой схемы и протокола: колонок visible_from_id,
// last_read_message_id, messages.deleted и полей upToId / up_to_id.
//
// Запуск: node test/message-order-guard.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { clientScriptFiles } = require('./client-script-source');

const ROOT = path.join(__dirname, '..');
// Сервер разбит на server.js + src/** (T6.1), скрипт приложения — на public/js/*.js (T6.2):
// проверяется каждый файл.
const { serverSourceFiles, readServerSource } = require('./server-source');
const FILES = [...serverSourceFiles(), ...clientScriptFiles().map(file => `public/${file}`)];

// Комментарии вырезаются (в них можно описывать, что именно запрещено).
function stripComments(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, match => match.replace(/[^\n]/g, ' '))
        .split('\n')
        .map(line => line.replace(/^\s*\/\/.*$/, '').replace(/\s\/\/\s.*$/, ''))
        .join('\n');
}

const RULES = [
    { name: 'ORDER BY m.id', re: /ORDER\s+BY\s+m\.id\b/i },
    { name: 'курсор id < $', re: /\bid\s*<\s*\$\d/ },
    { name: 'Number(m.id)', re: /Number\(\s*m\.id\s*\)/ },
    { name: 'visible_from_id', re: /\bvisible_from_id\b/ },
    { name: 'last_read_message_id', re: /\blast_read_message_id\b/ },
    { name: 'deleted = 0 (мягкое удаление убрано)', re: /\bdeleted\s*=\s*0\b/ },
    { name: 'upToId / up_to_id (курсор прочтения — upToSeq / up_to_seq)', re: /\bup_to_id\b/ },
];

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

for (const file of FILES) {
    test(`${file}: нет выражений, превращающих id сообщения в порядок`, () => {
        const source = stripComments(fs.readFileSync(path.join(ROOT, file), 'utf8'));
        const found = [];
        source.split('\n').forEach((line, index) => {
            for (const rule of RULES) {
                if (rule.re.test(line)) found.push(`${file}:${index + 1}  ${rule.name}: ${line.trim().slice(0, 100)}`);
            }
        });
        assert.deepStrictEqual(found, [], `найдено запрещённое:\n${found.join('\n')}`);
    });
}

test('upToId допустим в коде сервера только как признак старого клиента (400 client-outdated)', () => {
    const source = stripComments(readServerSource());
    const lines = source.split('\n').filter(line => /\bupToId\b/.test(line));
    assert.strictEqual(lines.length, 1, lines.join('\n'));
    assert.match(lines[0], /CLIENT_OUTDATED/);
});

test('самопроверка: правила находят то, что запрещают', () => {
    const bad = [
        'SELECT 1 FROM messages m ORDER BY m.id DESC',
        "AND id < $4",
        'const x = Number(m.id);',
        'visible_from_id',
        'last_read_message_id',
        'WHERE deleted = 0',
        'up_to_id',
    ];
    assert.strictEqual(bad.length, RULES.length);
    RULES.forEach((rule, index) => assert.ok(rule.re.test(bad[index]), rule.name));
    // Комментарий не считается.
    assert.strictEqual(stripComments('// ORDER BY m.id\nconst a = 1;').includes('ORDER'), false);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
