'use strict';
// Двунаправленный текст в названиях (T7.3, п.16 ревью W7 R3): названия чатов, имена участников и
// авторов приходят от других людей и могут быть на арабском/иврите или содержать символы
// направления. Элементы с такими текстами изолированы (unicode-bidi: isolate, как <bdi>), чтобы чужой
// текст не переставлял соседние элементы строки. Сами символы направления в названиях чистит сервер (T7.2).
// Живая проверка вычисленного стиля — test/browser/composer.browser.test.js.
// Запуск: node test/client-bidi.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { readClientCss } = require('./client-css');
const { readClientScript } = require('./client-script-source');

const css = readClientCss().replace(/\/\*[\s\S]*?\*\//g, '');   // без комментариев: они иначе попадают в первый селектор
const script = readClientScript();
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

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

// Селекторы правила, в котором стоит unicode-bidi: isolate.
function isolatedSelectors() {
    const rule = [...css.matchAll(/([^{}]+)\{([^{}]*unicode-bidi:\s*isolate[^{}]*)\}/g)].find((m) => /#chat-name/.test(m[1]));
    assert.ok(rule, 'нет правила unicode-bidi: isolate для названий');
    return rule[1].split(',').map((s) => s.trim()).filter(Boolean);
}

test('названия чатов и имена людей изолированы: заголовок чата, список чатов, участники, авторы, предпросмотр, профиль, заявки, цитаты', () => {
    const selectors = isolatedSelectors();
    for (const required of ['#chat-name', '#join-preview-name', '#profile-username', '.chat-name', '.member-name', '.message-author', '.pending-card h4', '.reply-to small']) {
        assert.ok(selectors.includes(required), `${required} не изолирован`);
    }
});

test('каждый изолированный селектор указывает на то, что действительно есть в клиенте', () => {
    for (const selector of isolatedSelectors()) {
        const id = /^#([\w-]+)$/.exec(selector);
        if (id) {
            assert.ok(html.includes(`id="${id[1]}"`), `в разметке нет ${selector}`);
            continue;
        }
        const className = /^\.([\w-]+)/.exec(selector)[1];
        assert.ok(script.includes(`'${className}`) || script.includes(`"${className}`) || html.includes(className), `в клиенте нет класса .${className}`);
    }
});

test('правило стоит в базовом файле стилей (tokens.css), до компонентов, чтобы не зависеть от порядка', () => {
    const tokens = fs.readFileSync(path.join(__dirname, '..', 'public', 'css', 'tokens.css'), 'utf8');
    assert.match(tokens, /unicode-bidi:\s*isolate/);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
