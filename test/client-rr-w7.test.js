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

// ===================== RR-3: «Удалить и выйти» при таймауте api() =====================

function deleteClient({ apiResult, authState }) {
    const calls = { api: [], errors: [], left: [], events: [] };
    const client = createClient({
        functions: ['deleteAccountAndLeave'],
        consts: ['ACCOUNT_DELETE_TIMEOUT_MS'],
        prelude: 'let deletingAccount = false; let currentUser = { id: 9 };',
        sandbox: {
            api: async (url, options) => { calls.api.push({ url, options }); return apiResult; },
            fetchAuthState: async () => authState,
            showDeleteAccountError: (text) => { if (text) calls.errors.push(text); },
            isCurrentUser: () => true,
            postSessionEvent: (e) => calls.events.push(e),
            leaveApp: (notice) => calls.left.push(notice),
            AUTH_NOTICES: { deleted: 'удалён' },
        },
    });
    return { ...client, calls };
}

const TIMED_OUT = { success: false, timedOut: true, message: 'Сервер не отвечает' };

test('RR-3: таймаут удаления, а сессии уже нет — аккаунт удалён: ключи стираются, выход', async () => {
    const c = deleteClient({ apiResult: TIMED_OUT, authState: { authenticated: false } });
    await c.run('deleteAccountAndLeave()');
    assert.deepStrictEqual(c.calls.left, ['удалён']);
    assert.deepStrictEqual(c.calls.errors, []);
});

test('RR-3: таймаут удаления, сессия жива — не «Аккаунт не удалён», а «не ответил вовремя»; нет связи — «неизвестно»', async () => {
    const alive = deleteClient({ apiResult: TIMED_OUT, authState: { authenticated: true } });
    await alive.run('deleteAccountAndLeave()');
    assert.deepStrictEqual(alive.calls.left, []);
    assert.match(alive.calls.errors[0], /не ответил вовремя/);
    assert.doesNotMatch(alive.calls.errors[0], /^Сервер не отвечает\. Аккаунт не удалён/);
    const offline = deleteClient({ apiResult: TIMED_OUT, authState: null });
    await offline.run('deleteAccountAndLeave()');
    assert.match(offline.calls.errors[0], /неизвестно, удалён ли аккаунт/);
});

test('RR-3: у запроса удаления свой, увеличенный предел ожидания', async () => {
    const c = deleteClient({ apiResult: { success: true }, authState: null });
    await c.run('deleteAccountAndLeave()');
    assert.strictEqual(c.calls.api[0].url, '/api/account/delete');
    assert.ok(c.calls.api[0].options.timeoutMs >= 3 * 60 * 1000, String(c.calls.api[0].options.timeoutMs));
});

// ===================== Мелочь: повтор после 403 CSRF ждёт /api/auth без предела =====================

test('повтор после 403 CSRF: обновление куки ограничено по времени — зависший /api/auth не держит запрос', async () => {
    let calls = 0;
    const c = createClient({
        functions: ['api', 'getCsrfToken', 'refreshCsrfCookie'],
        consts: ['API_TIMEOUT_MS', 'TIMED_OUT_MESSAGE'],
        sandbox: {
            AbortController,
            document: { cookie: 'csrf_token=abc' },
            onUnauthorizedResponse() {},
            fetch: (url, init) => {
                calls++;
                if (url === '/api/auth') {
                    return new Promise((_resolve, reject) => init && init.signal && init.signal.addEventListener('abort', () => reject(new Error('aborted'))));
                }
                return Promise.resolve(calls === 1
                    ? { status: 403, json: async () => ({ success: false, message: 'Запрещено: неверный CSRF-токен' }) }
                    : { status: 200, json: async () => ({ success: true }) });
            },
        },
    });
    const started = Date.now();
    const result = await c.run("api('/api/x', { method: 'POST', timeoutMs: 50 })");
    assert.ok(Date.now() - started < 2000, 'повтор не завис на /api/auth');
    assert.strictEqual(result.success, true);
});

done();
