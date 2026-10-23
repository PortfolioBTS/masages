'use strict';
// Клик по затемнению закрывает окно (T7.3, п.8 ревью W7 R3): .modal лежит над .overlay на
// весь экран, поэтому клик попадал в .modal, а обработчик висел на .overlay и не срабатывал
// никогда. Теперь слушается документ: клик (с нажатием) на самом .modal вне содержимого
// закрывает окно, кроме alertdialog. Логика в vm с заглушками (test/client-vm.js); живой
// клик в Chrome — test/browser/composer.browser.test.js.
// Запуск: node test/client-modal-backdrop.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();

function makeClient() {
    const elements = fakeElements();
    const profile = new FakeEl();
    profile.classList.add('modal');
    profile.setAttribute('role', 'dialog');
    const content = new FakeEl();
    content.classList.add('modal-content');
    profile.appendChild(content);
    const alert = new FakeEl();
    alert.classList.add('modal');
    alert.setAttribute('role', 'alertdialog');
    const alertContent = new FakeEl();
    alert.appendChild(alertContent);
    const modals = [profile, alert];
    profile.classList.add('hidden');
    alert.classList.add('hidden');
    const document = {
        querySelector: () => modals.find((m) => !m.hidden) || null,
        querySelectorAll: () => modals.filter((m) => !m.hidden),
        get activeElement() { return FakeEl.active; },
    };
    const client = createClient({
        functions: ['backdropModalOf', 'rememberBackdropPress', 'closeOnBackdropClick', 'closeModal', 'closeAllModals', 'onConfirmClosed'],
        prelude: 'let backdropPress = null; let modalReturnFocus = null; let confirmResolve = null; let confirmChoice = null; let confirmReturnFocus = null;',
        sandbox: { elements, document },
    });
    // Клик мышью: нажатие и отпускание.
    const click = (pressTarget, releaseTarget = pressTarget) => {
        client.context.__press = { target: pressTarget };
        client.context.__click = { target: releaseTarget };
        client.run('rememberBackdropPress(__press)');
        client.run('closeOnBackdropClick(__click)');
    };
    return { ...client, profile, content, alert, alertContent, click, elements };
}

test('клик по затемнению (самому .modal) закрывает окно, overlay прячется', () => {
    const c = makeClient();
    c.profile.classList.remove('hidden');
    c.click(c.profile);
    assert.strictEqual(c.profile.hidden, true);
    assert.strictEqual(c.elements.overlay.hidden, true);
});

test('клик внутри содержимого окна не закрывает его', () => {
    const c = makeClient();
    c.profile.classList.remove('hidden');
    c.click(c.content);
    assert.strictEqual(c.profile.hidden, false);
});

test('выделение, начатое в окне и отпущенное на затемнении, окно не закрывает', () => {
    const c = makeClient();
    c.profile.classList.remove('hidden');
    c.click(c.content, c.profile);   // нажали внутри, отпустили снаружи: click всплывает на общего предка
    assert.strictEqual(c.profile.hidden, false);
    c.click(c.profile, c.content);   // и наоборот
    assert.strictEqual(c.profile.hidden, false);
});

test('alertdialog (подтверждение, удаление аккаунта) по затемнению не закрывается', () => {
    const c = makeClient();
    c.alert.classList.remove('hidden');
    c.click(c.alert);
    assert.strictEqual(c.alert.hidden, false);
});

test('окно поверх другого (alertdialog над профилем): клик по затемнению не закрывает ничего', () => {
    const c = makeClient();
    c.profile.classList.remove('hidden');
    c.alert.classList.remove('hidden');
    c.click(c.alert);   // затемнение верхнего окна — alertdialog
    assert.strictEqual(c.alert.hidden, false);
    assert.strictEqual(c.profile.hidden, false);
});

test('клик в страницу без открытых окон и по скрытому .modal ничего не делает', () => {
    const c = makeClient();
    c.click(new FakeEl());
    c.click(c.profile);   // скрыт
    assert.strictEqual(c.profile.hidden, true);
    c.click(null);
});

test('код: обработчик висит на документе, мёртвого обработчика на .overlay нет', () => {
    const script = readClientScript();
    assert.ok(!script.includes("elements.overlay.addEventListener('click'"), 'клик по .overlay не срабатывает: .modal лежит над ним');
    assert.ok(script.includes("document.addEventListener('pointerdown', rememberBackdropPress)"));
    assert.ok(script.includes("document.addEventListener('click', closeOnBackdropClick)"));
});

done();
