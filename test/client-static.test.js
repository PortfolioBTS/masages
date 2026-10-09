'use strict';
// Статические проверки клиента (public/) без браузера.
//
// Зачем: опечатка в id молча ломает интерфейс — getElementById вернёт null,
// обработчик не навесится, а ошибка вылезет только тогда, когда пользователь
// нажмёт кнопку. Клиентские задачи правят index.html и script.js независимо
// друг от друга, и именно такой рассинхрон при слиянии — самая вероятная
// тихая поломка.
//
// Что проверяется:
//   1. каждый id, на который ссылается клиентский скрипт, есть в index.html
//      (getElementById('x'), querySelector('#x'), closest('#x .y') и т. п.);
//   2. в index.html нет повторяющихся id, инлайновых скриптов, обработчиков
//      on*= и атрибутов style=: CSP (style-src 'self') их не пропускает, а
//      весь код клиента должен лежать в отдельных файлах;
//   3. каждый файл, подключённый в index.html через src/href, существует в
//      public/ (/socket.io/socket.io.js отдаёт сам socket.io).
//
// Запуск: node test/client-static.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const INDEX_HTML = path.join(PUBLIC_DIR, 'index.html');

// Файлы клиента, чьи ссылки на id проверяются. Появился новый файл, который
// обращается к элементам страницы, — допишите его сюда.
const CLIENT_SCRIPTS = ['script.js', 'lib/invite.js', 'lib/lifetime.js', 'lib/mime-policy.js'];

// Подключается не из public/, а самим сервером (socket.io).
const SERVED_BY_SERVER = new Set(['/socket.io/socket.io.js']);

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

function lineOf(text, index) {
    return text.slice(0, index).split('\n').length;
}

// ---------- Ссылки на id в скрипте ----------

// Подстановки ${...} в шаблонных строках заменяются на этот символ: id, у
// которого продолжение подставляется на лету, статически проверить нельзя.
const DYNAMIC = '\u0000';

// Возвращает [{ id, line }] — все id, на которые ссылается исходник:
// getElementById('x') и #x внутри селекторов querySelector(All)/closest/matches.
function collectReferencedIds(source) {
    const found = [];

    const byId = /\bgetElementById\(\s*(['"`])([^'"`\\$]+)\1\s*\)/g;
    for (const m of source.matchAll(byId)) {
        found.push({ id: m[2], line: lineOf(source, m.index) });
    }

    const bySelector = /\b(?:querySelector|querySelectorAll|closest|matches)\(\s*(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
    for (const m of source.matchAll(bySelector)) {
        // Значения атрибутных селекторов ([href="#x"]) — не id.
        const selector = m[2].replace(/\$\{[^}]*\}/g, DYNAMIC).replace(/\[[^\]]*\]/g, '');
        for (const hash of selector.matchAll(/#([A-Za-z_][\w-]*)(?![\w\u0000-])/g)) {
            found.push({ id: hash[1], line: lineOf(source, m.index) });
        }
    }
    return found;
}

// ---------- Разбор index.html ----------

function collectTags(html) {
    const tags = [];
    for (const m of html.matchAll(/<([a-zA-Z][\w-]*)\b([^>]*)>/g)) {
        tags.push({ name: m[1].toLowerCase(), attrs: m[2], line: lineOf(html, m.index) });
    }
    return tags;
}

function attrValue(attrs, name) {
    const m = new RegExp('\\s' + name + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\')', 'i').exec(attrs);
    return m ? (m[1] !== undefined ? m[1] : m[2]) : null;
}

function hasAttr(attrs, name) {
    return new RegExp('\\s' + name + '(?:\\s*=|\\s|$)', 'i').test(attrs);
}

// Путь файла в public/ для адреса из src/href; null — проверять нечего
// (якорь внутри страницы, data:/blob:, адрес, который отдаёт сам сервер).
function resolveLinkedFile(url) {
    if (!url || url.startsWith('#')) return null;
    if (/^(?:data|blob|mailto|tel):/i.test(url)) return null;
    if (SERVED_BY_SERVER.has(url)) return null;
    const clean = url.split(/[?#]/)[0];
    const relative = clean.startsWith('/') ? clean.slice(1) : clean;
    return path.resolve(PUBLIC_DIR, relative);
}

console.log('Client static tests\n');

// Сам разбор проверяется на выдуманном исходнике — чтобы поломанное
// регулярное выражение не превратило проверки ниже в «ничего не нашли».
test('reference extractor: literal ids and #id in selectors, nothing else', () => {
    const source = [
        "document.getElementById('a-b');",
        'document.getElementById("c_d");',
        "el.querySelector('#e .x');",
        "el.querySelectorAll('input[name=\"n\"], #f');",
        "el.closest('#g .h');",
        "node.matches(`#i:not(.j)`);",
        'el.querySelector(`#k-${index}`);',
        "el.querySelector('[href=\"#not-an-id\"]');",
        "el.querySelector('.plain');",
        'document.getElementById(variable);',
    ].join('\n');
    const found = collectReferencedIds(source);
    assert.deepStrictEqual(found.map(r => r.id), ['a-b', 'c_d', 'e', 'f', 'g', 'i']);
    assert.deepStrictEqual(found.map(r => r.line), [1, 2, 3, 4, 5, 6]);
});

const html = fs.readFileSync(INDEX_HTML, 'utf8');
const tags = collectTags(html);

test('every id referenced by the client scripts exists in index.html', () => {
    const htmlIds = new Set();
    for (const tag of tags) {
        const id = attrValue(tag.attrs, 'id');
        if (id !== null) htmlIds.add(id);
    }
    const missing = [];
    let total = 0;
    for (const file of CLIENT_SCRIPTS) {
        const source = fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
        const refs = collectReferencedIds(source);
        total += refs.length;
        for (const ref of refs) {
            if (!htmlIds.has(ref.id)) missing.push(`${file}:${ref.line}  #${ref.id}`);
        }
    }
    assert.ok(total > 0, 'в клиентских скриптах не найдено ни одной ссылки на id — сломан разбор?');
    assert.deepStrictEqual(missing, [], 'в index.html нет элементов с такими id:\n' + missing.join('\n'));
});

test('index.html has no duplicate ids (getElementById would take the first one)', () => {
    const seen = new Set();
    const duplicates = [];
    for (const tag of tags) {
        const id = attrValue(tag.attrs, 'id');
        if (id === null) continue;
        if (seen.has(id)) duplicates.push(`index.html:${tag.line}  #${id}`);
        seen.add(id);
    }
    assert.deepStrictEqual(duplicates, [], 'повторяющиеся id:\n' + duplicates.join('\n'));
});

test('index.html has no inline scripts, on*= handlers or style= attributes', () => {
    const problems = [];
    for (const tag of tags) {
        if (tag.name === 'script' && !hasAttr(tag.attrs, 'src')) {
            problems.push(`index.html:${tag.line}  инлайновый <script> без src`);
        }
        for (const m of tag.attrs.matchAll(/\s(on[a-z]+)\s*=/gi)) {
            problems.push(`index.html:${tag.line}  обработчик ${m[1]}=`);
        }
        if (hasAttr(tag.attrs, 'style')) {
            problems.push(`index.html:${tag.line}  атрибут style= у <${tag.name}>`);
        }
    }
    assert.deepStrictEqual(problems, [], 'CSP такое не пропускает:\n' + problems.join('\n'));
});

test('every file linked from index.html via src/href exists in public/', () => {
    const missing = [];
    let checked = 0;
    for (const tag of tags) {
        for (const attr of ['src', 'href']) {
            const url = attrValue(tag.attrs, attr);
            const file = resolveLinkedFile(url);
            if (!file) continue;
            checked++;
            const inside = file === PUBLIC_DIR || file.startsWith(PUBLIC_DIR + path.sep);
            const exists = inside && fs.existsSync(file) && fs.statSync(file).isFile();
            if (!exists) missing.push(`index.html:${tag.line}  <${tag.name} ${attr}="${url}">`);
        }
    }
    assert.ok(checked > 0, 'не найдено ни одного подключаемого файла — сломан разбор?');
    assert.deepStrictEqual(missing, [], 'нет файла в public/:\n' + missing.join('\n'));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
