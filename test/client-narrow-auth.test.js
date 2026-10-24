'use strict';
// Экран входа на 320×640 (T7.3, п.18 ревью W7 R3): «Начать анонимно» уходила ниже первого экрана
// на ~75 px. Отступы и размеры сжаты в конце responsive.css (после блоков «Узкие телефоны» —
// иначе они бы перебили), варианты срока остаются столбиком (controls.css, WCAG 1.4.10) и по 44 px.
// Проверка по тексту CSS; настоящий замер положения кнопок на 320×640 — test/browser/composer.browser.test.js.
// Запуск: node test/client-narrow-auth.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const css = fs.readFileSync(path.join(__dirname, '..', 'public', 'css', 'responsive.css'), 'utf8');
const controls = fs.readFileSync(path.join(__dirname, '..', 'public', 'css', 'controls.css'), 'utf8');

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

function mediaBody(source, condition) {
    const start = source.lastIndexOf(`@media ${condition} {`);
    assert.ok(start >= 0, `нет @media ${condition}`);
    let depth = 0;
    for (let i = source.indexOf('{', start); i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}' && --depth === 0) return { start, body: source.slice(source.indexOf('{', start) + 1, i) };
    }
    throw new Error('блок не закрыт');
}

const narrow = mediaBody(css, '(max-width: 359px)');
const rule = (selector) => {
    const m = new RegExp(`(?:^|\\n)\\s*${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([^}]*)\\}`).exec(narrow.body);
    assert.ok(m, `в блоке нет правила ${selector}`);
    return m[1];
};

test('блок для 320 px стоит после «Узких телефонов» (420 px), иначе те перебьют его отступы', () => {
    assert.ok(narrow.start > css.indexOf('@media (max-width: 420px) {'));
    assert.ok(narrow.start > css.lastIndexOf('.auth-container {', narrow.start - 1), 'после последнего другого правила карточки');
});

test('отступы карточки, знак, заголовок и промежутки сжаты', () => {
    assert.match(rule('.auth-container'), /padding:\s*16px;/);
    assert.match(rule('.auth-hero'), /margin-bottom:\s*16px/);
    assert.match(rule('.logo-icon'), /width:\s*36px/);
    assert.match(rule('.auth-hero h1'), /font-size:\s*22px/);
    assert.match(rule('.auth-hero h1'), /line-height:\s*28px/);
    assert.match(narrow.body, /\.lifetime-picker,\s*\.auth-warning\s*\{[^}]*margin-bottom:\s*12px/);
});

test('варианты срока остаются столбиком (без обрезки текста) и не ниже 44 px (цель нажатия)', () => {
    assert.match(controls, /@media \(max-width: 359px\) \{\s*\.segmented \{\s*grid-template-columns: 1fr;/);
    assert.match(rule('.segmented-option'), /min-height:\s*44px/);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
