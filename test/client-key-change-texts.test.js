'use strict';
// Тексты о смене ключа и подтверждении участника (T7.3, п.13 ревью W7 R3):
//  * баннер «сменился ключ» не обещает, что «сообщения ему не отправляются»: отправка в группу не
//    блокируется, участнику не передаётся ключ группы — он не прочитает новые сообщения;
//  * участник, которого вы подтверждали и у которого потом сменился ключ (suspended), показан как
//    «ключ изменился после подтверждения», а не «вошёл без подписи».
// Логика в vm с заглушками (test/client-vm.js); признак suspended выдаёт membership-client.js
// (test/membership.suspended-flag.test.js).
// Запуск: node test/client-key-change-texts.test.js

const assert = require('assert');
const { createClient, createHarness, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();

function makeClient() {
    const notices = [];
    const elements = fakeElements();
    const client = createClient({
        functions: ['renderIdentityBanner', 'membershipHowLine', 'memberLabel', 'handleMembershipResult'],
        prelude: `
            const pendingIdentityChanges = new Map(); const pendingLogMismatches = new Map();
            const pendingUnconfirmed = new Map(); const pendingSuspended = new Map();
            const notedMembership = new Set(); const roomParticipants = new Map(); const roomMemberNames = new Map();
            let currentRoomId = 5;`,
        sandbox: { elements, appendSystemNotice: (roomId, text) => notices.push(text) },
    });
    return { ...client, notices, elements };
}

const bannerText = (c) => c.elements.e2eeBannerText.textContent;

test('сменился ключ: говорит о ключе группы, а не «сообщения не отправляются»', () => {
    const c = makeClient();
    c.run("pendingIdentityChanges.set(2, 'Боб'); renderIdentityBanner()");
    assert.match(bannerText(c), /^У участника Боб сменился ключ шифрования\. Ключ группы ему не передаётся, и новые сообщения он не прочитает, пока вы не проверите код безопасности$/);
    assert.strictEqual(c.elements.e2eeBanner.hidden, false);
    c.run("pendingIdentityChanges.set(3, 'Вика'); renderIdentityBanner()");
    assert.match(bannerText(c), /^У участников Боб, Вика сменились ключи шифрования\. Ключ группы им не передаётся, и новые сообщения они не прочитают, пока вы не проверите коды безопасности$/);
    assert.doesNotMatch(bannerText(c), /Сообщения (ему|им) не отправляются/);
});

test('неподтверждённые участники: ключ группы не передаётся, пока их не подтвердят', () => {
    const c = makeClient();
    c.run("pendingUnconfirmed.set(4, 'Гость'); renderIdentityBanner()");
    assert.strictEqual(bannerText(c), 'В группе есть неподтверждённые участники: Гость. Ключ группы ему не передаётся, пока вы не подтвердите его');
    c.run("pendingUnconfirmed.set(5, 'Ещё'); renderIdentityBanner()");
    assert.strictEqual(bannerText(c), 'В группе есть неподтверждённые участники: Гость, Ещё. Ключ группы им не передаётся, пока вы не подтвердите их');
});

test('подтверждённый ранее, у которого сменился ключ (suspended): отдельная строка баннера', () => {
    const c = makeClient();
    c.run("pendingSuspended.set(2, 'Боб'); renderIdentityBanner()");
    assert.strictEqual(bannerText(c), 'Боб: ключ изменился после подтверждения. Ключ группы ему не передаётся, пока вы не проверите код безопасности');
    assert.strictEqual(c.elements.e2eeBanner.hidden, false);
    c.run("pendingUnconfirmed.set(4, 'Гость'); renderIdentityBanner()");
    assert.match(bannerText(c), /неподтверждённые участники: Гость.*\. Боб: ключ изменился после подтверждения/);
    c.run('pendingSuspended.clear(); pendingUnconfirmed.clear(); renderIdentityBanner()');
    assert.strictEqual(c.elements.e2eeBanner.hidden, true);
    assert.strictEqual(bannerText(c), '');
});

test('подпись под именем: suspended — «ключ изменился после подтверждения», призрак — «вошёл без подписи», дубликат ключей — свой текст', () => {
    const c = makeClient();
    const line = (entry) => { c.context.__entry = entry; return c.run('membershipHowLine(5, __entry)'); };
    assert.strictEqual(line({ status: 'unconfirmed', how: null, by: null, suspended: true }), 'Не подтверждён: ключ изменился после подтверждения');
    assert.strictEqual(line({ status: 'unconfirmed', how: null, by: null }), 'Не подтверждён: вошёл без подписи участника');
    assert.strictEqual(line({ status: 'unconfirmed', how: null, by: null, duplicateKeys: true }), 'Не подтверждён: ключи шифрования такие же, как у другого участника');
    // Дубликат ключей важнее: у него отдельное предупреждение, и suspended его не затирает.
    assert.strictEqual(line({ status: 'unconfirmed', how: null, by: null, suspended: true, duplicateKeys: true }), 'Не подтверждён: ключи шифрования такие же, как у другого участника');
    assert.strictEqual(line({ status: 'confirmed', how: 'manual', by: null }), 'Подтверждён вами');
});

test('результат проверки состава раскладывает неподтверждённых и suspended по разным спискам баннера', () => {
    const c = makeClient();
    c.context.__result = {
        unconfirmed: [
            { id: 4, username: 'Гость', duplicateKeys: false },
            { id: 2, username: 'Боб', duplicateKeys: false, suspended: true },
            { id: 7, username: 'Сменил', duplicateKeys: false, suspended: true },
        ],
        identityChanges: [{ userId: 7 }],      // у этого ключ сменился и ещё не принят: о нём говорит строка «сменился ключ»
        logMismatches: [],
    };
    c.run('handleMembershipResult(5, __result)');
    assert.strictEqual(c.run("[...pendingUnconfirmed.values()].join(',')"), 'Гость');
    assert.strictEqual(c.run("[...pendingSuspended.values()].join(',')"), 'Боб');
    assert.match(bannerText(c), /Гость.*Боб: ключ изменился после подтверждения/);
});

test('код: «Доверять» снимает участника и из списка suspended; старой формулировки в клиенте нет', () => {
    const script = readClientScript();
    assert.ok(script.includes('pendingSuspended.delete(Number(peer.id))'));
    assert.doesNotMatch(script, /Сообщения (ему|им) не отправляются/);
});

done();
