'use strict';
// Группы в настоящем Chrome, по два-три профиля (два-три аккаунта на «разных
// устройствах»):
//  1) подписанная ссылка-приглашение без одобрения: вход вторым профилем по
//     #join=КОД.СЕКРЕТ, надпись о составе группы, E2EE-сообщения в обе стороны,
//     авторы верны и после перезагрузки;
//  2) заявка по коду без секрета: заявка, одобрение первым профилем, статусы
//     участников, сообщения после передачи ключа.
// Вопрос «Создать новый код?» — окно приложения #confirm-modal (app.answerConfirm); родных
// диалогов в приложении нет (Page.javascriptDialogOpening, см. helpers/page.js, их не видит).

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');

const suite = createBrowserSuite('group');
const GROUP = 'Группа смоука';

// Статусы участника, при которых к нему нельзя писать без проверки ключа.
const BAD_STATUSES = ['changed', 'unknown'];

function assertMemberOk(members, name, label) {
    const member = members.find(m => m.name.startsWith(name));
    assert.ok(member, `${label}: участника ${name} нет в списке: ${JSON.stringify(members)}`);
    assert.strictEqual(member.unconfirmed, false, `${label}: ${name} не подтверждён в составе группы`);
    assert.ok(!BAD_STATUSES.includes(member.status), `${label}: у ${name} статус ключа «${member.status}»`);
    return member;
}

suite.test('подписанная ссылка впускает без одобрения; сообщения в обе стороны; авторы верны после перезагрузки', async () => {
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const pa = await alice.newPage();
        const pb = await bob.newPage();

        // Алиса: аккаунт, группа, приглашение без одобрения.
        await app.startAnonymously(pa, `${suite.baseUrl}/`);
        const aliceName = await app.username(pa);
        await app.createGroup(pa, GROUP);
        await app.openInvite(pa);
        const withApproval = await app.readInvite(pa);
        assert.strictEqual(withApproval.secret, null, 'у приглашения с одобрением нет секрета ссылки');
        const signed = await app.rotateToSignedInvite(pa);
        assert.strictEqual(pa.lastConfirmTitle, 'Создать новый код?', 'окно подтверждения «Создать новый код?» не появлялось');
        assert.strictEqual(pa.dialogs.length, 0, 'вопрос задан родным confirm, а не окном приложения');
        assert.notStrictEqual(signed.code, withApproval.code, 'код не сменился');
        const link = await app.copyInviteLink(pa, alice, suite.baseUrl);
        assert.strictEqual(link, `${suite.baseUrl}/#join=${signed.code}.${signed.secret}`, 'скопированная ссылка не та, что в окне приглашения');
        await pa.screenshot('group-01-invite');
        await app.closeInvite(pa);

        // Боб: открывает ссылку. Фрагмент со секретом стирается из адресной строки сразу.
        await app.openInviteAsNewcomer(pb, link);
        const url = await pb.evaluate(() => location.href);
        assert.ok(!url.includes('join=') && !url.includes('#'), `ссылка-приглашение осталась в адресной строке: ${url}`);
        assert.strictEqual((await pb.text('#join-preview-name')).trim(), GROUP);
        assert.strictEqual(await pb.isVisible('#join-preview-approval'), false, 'по подписанной ссылке одобрение не нужно');
        await pb.screenshot('group-02-join-preview');
        await app.confirmJoin(pb);
        await pb.waitForText('#chat-name', GROUP, { timeoutMs: app.APP_TIMEOUT_MS });
        await app.waitForNotice(pb, app.TEXT.membershipByInvite);
        const bobName = await app.username(pb);
        assert.notStrictEqual(bobName, aliceName);

        // Сообщения в обе стороны (шифруются на устройстве, сервер видит шифротекст).
        await app.sendMessage(pb, 'Привет от Боба');
        await app.waitForMessage(pa, 'Привет от Боба', { sent: false });
        await app.sendMessage(pa, 'Привет от Алисы');
        await app.waitForMessage(pb, 'Привет от Алисы', { sent: false });
        await app.waitForNotice(pa, bobName);
        await pa.screenshot('group-03-chat-alice');

        // Авторы — сразу и после перезагрузки (лента читается из сохранённых ключей).
        const authorsOf = async (page) => (await app.readChat(page)).filter(m => m.text).map(m => [m.sent ? 'я' : m.author, m.text]);
        assert.deepStrictEqual(await authorsOf(pa), [[bobName, 'Привет от Боба'], ['я', 'Привет от Алисы']]);
        assert.deepStrictEqual(await authorsOf(pb), [['я', 'Привет от Боба'], [aliceName, 'Привет от Алисы']]);
        await pa.reload();
        await app.waitForApp(pa);
        await app.openChat(pa, GROUP);
        await app.waitForMessage(pa, 'Привет от Алисы', { sent: true });
        await app.waitForMessage(pa, 'Привет от Боба', { sent: false });
        assert.deepStrictEqual(await authorsOf(pa), [[bobName, 'Привет от Боба'], ['я', 'Привет от Алисы']], 'авторы после перезагрузки (Алиса)');
        await pb.reload();
        await app.waitForApp(pb);
        await app.openChat(pb, GROUP);
        await app.waitForMessage(pb, 'Привет от Алисы', { sent: false });
        await app.waitForMessage(pb, 'Привет от Боба', { sent: true });
        assert.deepStrictEqual(await authorsOf(pb), [['я', 'Привет от Боба'], [aliceName, 'Привет от Алисы']], 'авторы после перезагрузки (Боб)');

        // Состав группы: Боб вошёл по приглашению Алисы и подтверждён.
        const members = await app.readMembers(pa, { expected: 2 });
        assert.strictEqual(members.length, 2);
        const bobRow = assertMemberOk(members, bobName, 'Алиса видит Боба');
        assert.ok(bobRow.how.join(' ').includes(aliceName), `у Боба нет строки «по приглашению ${aliceName}»: ${JSON.stringify(bobRow.how)}`);
        await pa.screenshot('group-04-members');
        await app.closeModal(pa, 'members-modal');
    });
});

suite.test('заявка по коду без секрета: одобрение первым участником, статусы, сообщения после передачи ключа', async () => {
    await suite.withProfiles(['alice', 'carol'], async ([alice, carol]) => {
        const pa = await alice.newPage();
        const pc = await carol.newPage();

        await app.startAnonymously(pa, `${suite.baseUrl}/`);
        const aliceName = await app.username(pa);
        await app.createGroup(pa, GROUP);
        await app.openInvite(pa);
        const invite = await app.readInvite(pa);
        assert.strictEqual(invite.secret, null);
        await app.closeInvite(pa);

        // Код диктуют группами по 5 символов — так он и вводится. Без секрета впускает только заявка.
        const dictated = invite.code.match(/.{1,5}/g).join(' ');
        await app.openCodeAsNewcomer(pc, `${suite.baseUrl}/`, dictated);
        assert.strictEqual((await pc.text('#join-preview-name')).trim(), GROUP);
        assert.strictEqual(await pc.isVisible('#join-preview-approval'), true, 'для кода без секрета нужно одобрение');
        await app.confirmJoin(pc);
        await pc.waitForSelector('#my-requests-list .pending-card');
        assert.strictEqual(await pc.count('#my-requests-list .pending-card'), 1);
        assert.strictEqual(await pc.isVisible('#message-input-container'), false, 'до одобрения чата группы нет');
        await pc.screenshot('group-05-request-pending');

        // Алиса видит заявку и впускает. Карлу чат открывается сам.
        await app.approveFirstRequest(pa);
        await pc.waitForText('#chat-name', GROUP, { timeoutMs: app.APP_TIMEOUT_MS });
        const carolName = await app.username(pc);

        // Статусы: у Алисы Карл «одобрен», у обоих состав без неподтверждённых.
        const aliceView = await app.readMembers(pa, { expected: 2 });
        const carolRow = assertMemberOk(aliceView, carolName, 'Алиса видит Карла');
        assert.ok(carolRow.how.join(' ').includes(aliceName), `у Карла нет строки «одобрил(а) ${aliceName}»: ${JSON.stringify(carolRow.how)}`);
        await app.closeModal(pa, 'members-modal');
        const carolView = await app.readMembers(pc, { expected: 2 });
        assertMemberOk(carolView, aliceName, 'Карл видит Алису');
        await pc.screenshot('group-06-members-carol');
        await app.closeModal(pc, 'members-modal');

        // Ключ группы передан: сообщения читаются в обе стороны, авторы верны.
        await app.sendMessage(pa, 'Заявка принята');
        await app.waitForMessage(pc, 'Заявка принята', { sent: false });
        await app.sendMessage(pc, 'Спасибо, что впустили');
        await app.waitForMessage(pa, 'Спасибо, что впустили', { sent: false });
        const authors = (await app.readChat(pc)).filter(m => m.text && !m.sent).map(m => m.author);
        assert.deepStrictEqual(authors, [aliceName]);
    });
});
