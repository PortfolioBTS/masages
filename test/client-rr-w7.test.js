'use strict';
// Повторное ревью клиента W7 (T7.6): мелкие дефекты клиента RR-3…RR-9 и «мелочи». Логика — в vm с заглушками
// (test/client-vm.js); вёрстка и настоящие события — сценарии test/browser.
// Запуск: node test/client-rr-w7.test.js

const assert = require('assert');
const { createClient, createHarness, fakeElements, FakeEl } = require('./client-vm');

const { test, done } = createHarness();

// ===================== RR-5: тексты состава после слияния T7.1 + T7.3 =====================

function membersClient() {
    const elements = fakeElements();
    const confirms = [];
    const client = createClient({
        functions: ['renderIdentityBanner', 'membershipHowLine', 'memberLabel', 'handleMembershipResult', 'appendMembershipInfo', 'trustUnconfirmedMember'],
        prelude: `
            const pendingIdentityChanges = new Map(); const pendingLogMismatches = new Map();
            const pendingUnconfirmed = new Map(); const pendingSuspended = new Map(); const pendingChangedUnconfirmed = new Map();
            const notedMembership = new Set(); const roomParticipants = new Map(); const roomMemberNames = new Map();
            let currentRoomId = 5;`,
        sandbox: {
            elements,
            appendSystemNotice: () => {},
            document: { createElement: (tag) => new FakeEl(tag) },
            setIconLabel: (el, icon, label) => { el.textContent = label; },
            confirmAction: async (text) => { confirms.push(text); return false; },
        },
    });
    return { ...client, elements, confirms };
}

test('RR-5а: «призрак» со сменившимся ключом — баннер говорит, что он и не подтверждён в группе', () => {
    const c = membersClient();
    c.context.__result = {
        unconfirmed: [{ id: 7, username: 'Боб' }, { id: 4, username: 'Гость' }],
        identityChanges: [{ userId: 7 }],
        logMismatches: [],
    };
    c.run("pendingIdentityChanges.set(7, 'Боб'); handleMembershipResult(5, __result)");
    const text = c.elements.e2eeBannerText.textContent;
    assert.match(text, /У участника Боб сменился ключ шифрования/);
    assert.match(text, /Боб к тому же не подтверждён в этой группе: ключ группы он не получит и после проверки кода, пока вы его не подтвердите/);
    assert.match(text, /неподтверждённые участники: Гость\./, 'обычный неподтверждённый — как раньше');
    // Подтверждённый ранее (suspended) со сменой ключа — не «призрак»: такой строки нет.
    c.context.__result = { unconfirmed: [{ id: 7, username: 'Боб', suspended: true }], identityChanges: [{ userId: 7 }], logMismatches: [] };
    c.run('handleMembershipResult(5, __result)');
    assert.doesNotMatch(c.elements.e2eeBannerText.textContent, /к тому же не подтверждён/);
});

function memberEntryRow(c, entry, status) {
    const li = new FakeEl('li');
    const info = new FakeEl('div');
    c.context.__args = { li, info, peer: { id: 7, username: 'Боб' }, ctx: { roomId: 5, chatId: 15, member: entry, client: {} }, status };
    c.run('appendMembershipInfo(__args.li, __args.info, __args.peer, __args.ctx, __args.status)');
    return li.children.find((el) => el.tagName === 'BUTTON') || null;
}

test('RR-5б: подтверждённый ранее с ключом «изменился» — кнопки «Доверять» нет (действие — «Принять новый ключ»)', () => {
    const c = membersClient();
    assert.strictEqual(memberEntryRow(c, { status: 'unconfirmed', suspended: true }, 'changed'), null);
});

test('RR-5б: suspended без ожидающего ключа — своё подтверждение, а не «никто не подписал»; призрак — прежний текст', async () => {
    const c = membersClient();
    const suspendedBtn = memberEntryRow(c, { status: 'unconfirmed', suspended: true }, 'unverified');
    assert.ok(suspendedBtn, 'кнопка есть');
    await suspendedBtn.fire('click');
    await new Promise((r) => setImmediate(r));
    assert.match(c.confirms[0], /Вы подтверждали Боб, но его ключ сменился/);
    assert.doesNotMatch(c.confirms[0], /никто из участников это не подписал/);
    const ghostBtn = memberEntryRow(c, { status: 'unconfirmed' }, 'unverified');
    await ghostBtn.fire('click');
    await new Promise((r) => setImmediate(r));
    assert.match(c.confirms[1], /Сервер добавил Боб в группу, но никто из участников это не подписал/);
});

done();
