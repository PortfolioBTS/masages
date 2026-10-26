'use strict';
// Цели нажатия на телефоне (T7.3, п.11 ревью W7 R3): кнопки шапки были 36×36 px,
// #e2ee-indicator 26×20, «Профиль» и «Удалить и выйти» 36 px. На сенсорном экране
// (@media (pointer: coarse)) кнопки не меньше 44×44, индикатор — не меньше 32 px.
// Проверка по тексту CSS: блок должен стоять в responsive.css ПОСЛЕ узкого экрана (там 36 px)
// и содержать нужные селекторы. Живой замер размеров — test/browser/composer.browser.test.js.
// Запуск: node test/client-touch-targets.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const css = fs.readFileSync(path.join(__dirname, '..', 'public', 'css', 'responsive.css'), 'utf8');

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

// Тело блока @media (условие) { … } по счёту скобок.
function mediaBlock(source, condition) {
    const start = source.indexOf(`@media ${condition} {`);
    assert.ok(start >= 0, `нет @media ${condition}`);
    let depth = 0;
    for (let i = source.indexOf('{', start); i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}' && --depth === 0) return { start, body: source.slice(source.indexOf('{', start) + 1, i) };
    }
    throw new Error('блок не закрыт');
}

// Правила внутри блока: [{ selectors: [...], declarations: { свойство: значение } }].
function rulesOf(body) {
    return [...body.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({
        selectors: m[1].split(',').map((s) => s.trim()).filter(Boolean),
        declarations: Object.fromEntries(m[2].split(';').map((d) => d.split(':').map((x) => x && x.trim())).filter(([k, v]) => k && v)),
    }));
}

const coarse = mediaBlock(css, '(pointer: coarse)');
const rules = rulesOf(coarse.body);
const declarationsFor = (selector) => Object.assign({}, ...rules.filter((r) => r.selectors.includes(selector)).map((r) => r.declarations));

test('блок для сенсорного экрана стоит после узкого экрана (иначе 36 px шапки его перебьют)', () => {
    const narrow = css.indexOf('@media (max-width: 420px) {');
    assert.ok(narrow >= 0 && coarse.start > narrow);
    // …и после всех правил, задающих 36 px кнопкам шапки.
    assert.ok(coarse.start > css.lastIndexOf('.chat-header .icon-btn {', coarse.start - 1));
});

test('кнопки-значки, закрытие окон, реакции и «вниз» — 44×44', () => {
    for (const selector of ['.icon-btn', '.icon-btn-sm', '.close-modal', '.chat-header .icon-btn', '.reaction-option', '.jump-down']) {
        const d = declarationsFor(selector);
        assert.strictEqual(d.width, '44px', `${selector}: width`);
        assert.strictEqual(d.height, '44px', `${selector}: height`);
    }
});

test('«Профиль»/«Удалить и выйти», обычные кнопки, пункты меню и подсказки бота — не ниже 44 px', () => {
    for (const selector of ['.footer-btn', '.btn', '.btn-sm', '.menu-item', '.suggestion', '.banner-btn']) {
        assert.strictEqual(declarationsFor(selector).height, '44px', selector);
    }
});

test('индикатор режима в шапке (button.indicator) — область нажатия не меньше 32 px', () => {
    const d = declarationsFor('button.indicator');
    assert.ok(parseInt(d['min-width'], 10) >= 32 && parseInt(d['min-height'], 10) >= 32, JSON.stringify(d));
});

test('поле сообщения на сенсорном экране не ниже кнопок рядом', () => {
    assert.strictEqual(declarationsFor('.input-wrapper textarea')['min-height'], '44px');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
