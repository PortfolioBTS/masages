'use strict';
// Мелочи ревью клиента (T7.3, п.15 ревью W7 R3):
//  * строка о подмене ключа заявителя — предупреждение (member-warning), а не такая же неброская
//    member-kt, как «ключ проверен по журналу»;
//  * «N участник(ов) пока не могут читать…» — со склонением (plural) и согласованием глагола;
//  * всплывающие сообщения об ошибках показываются дольше, если текст длинный.
// Логика в vm с заглушками (test/client-vm.js).
// Запуск: node test/client-small-fixes.test.js

const assert = require('assert');
const { createClient, createHarness, FakeEl, fakeElements } = require('./client-vm');
const { readClientScript } = require('./client-script-source');

const { test, done } = createHarness();

// ---- подмена ключа заявителя ----

function applicantClient(status) {
    const client = createClient({
        functions: ['showApplicantKeyCheck'],
        consts: [],
        prelude: "const KT_PEER_TEXT = { pending: 'Ключ ждёт подтверждения журналом' };",
        sandbox: {
            getReadyE2eeClient: async () => ({ checkApplicantKey: async () => ({ status }) }),
            iconText: (tag, className, iconName, text) => Object.assign(new FakeEl(tag), { className, iconName, textContent: text }),
            document: { createElement: (tag) => new FakeEl(tag) },
        },
    });
    return client;
}

async function lineFor(status) {
    const c = applicantClient(status);
    const info = new FakeEl();
    c.context.__info = info;
    c.context.__req = { userId: 7, identity: { kt: true } };
    await c.run('showApplicantKeyCheck(__req, __info)');
    return info.children[0];
}

test('подмена (mismatch): предупреждение member-warning со значком, не неброская строка member-kt', async () => {
    const line = await lineFor('mismatch');
    assert.ok(line.classes.has('member-warning'));
    assert.ok(!line.classes.has('member-kt'));
    assert.strictEqual(line.iconName, 'alert-triangle');
    assert.match(line.textContent, /нет в журнале ключей.*Возможна подмена/);
});

test('ok и pending остаются неброскими строками member-kt', async () => {
    for (const [status, text] of [['ok', 'ключ проверен по журналу'], ['pending', 'Ключ ждёт подтверждения журналом']]) {
        const line = await lineFor(status);
        assert.ok(line.classes.has('member-kt'), status);
        assert.ok(!line.classes.has('member-warning'), status);
        assert.strictEqual(line.textContent, text);
    }
});

// ---- склонение ----

function pluralClient() {
    return createClient({ functions: ['plural', 'peersWithoutE2eeText'] });
}

test('peersWithoutE2eeText: склонение и согласование по числу', () => {
    const c = pluralClient();
    const text = (n) => c.run(`peersWithoutE2eeText(${n})`);
    assert.strictEqual(text(1), '1 участник пока не может читать зашифрованные сообщения: у него не настроено шифрование');
    assert.strictEqual(text(2), '2 участника пока не могут читать зашифрованные сообщения: у них не настроено шифрование');
    assert.strictEqual(text(5), '5 участников пока не могут читать зашифрованные сообщения: у них не настроено шифрование');
    assert.strictEqual(text(11), '11 участников пока не могут читать зашифрованные сообщения: у них не настроено шифрование');
    assert.strictEqual(text(21), '21 участник пока не может читать зашифрованные сообщения: у него не настроено шифрование');
    assert.strictEqual(text(24), '24 участника пока не могут читать зашифрованные сообщения: у них не настроено шифрование');
    assert.ok(!/\(ов\)/.test(readClientScript()), 'в клиенте не должно быть «участник(ов)»');
});

// ---- длительность всплывающих сообщений ----

function toastClient() {
    const timers = [];
    const elements = fakeElements();
    const client = createClient({
        functions: ['toastDurationMs', 'showToast'],
        prelude: "let toastTimer = null; const TOAST_ICONS = { success: 'check', error: 'alert-triangle', info: 'info' };",
        sandbox: {
            elements,
            document: { createElement: (tag) => new FakeEl(tag) },
            icon: () => new FakeEl('svg'),
            setTimeout: (fn, ms) => { timers.push(ms); return timers.length; },
            clearTimeout() {},
        },
    });
    return { ...client, timers };
}

test('длительность тоста: не меньше 3 с, длинный текст дольше, не больше 12 с', () => {
    const c = toastClient();
    const ms = (n) => c.run(`toastDurationMs('x'.repeat(${n}))`);
    assert.strictEqual(ms(0), 3000);
    assert.strictEqual(ms(10), 3000, 'короткий — минимум');
    assert.ok(ms(60) > 3000 && ms(60) < ms(120), 'чем длиннее, тем дольше');
    assert.strictEqual(ms(120), 8700);
    assert.strictEqual(ms(1000), 12000, 'потолок');
});

test('showToast без явной длительности берёт её по длине текста; явная длительность остаётся как есть', () => {
    const c = toastClient();
    c.run("showToast('Коротко', 'error')");
    c.run(`showToast('${'Длинная ошибка '.repeat(8)}', 'error')`);
    c.run("showToast('Свой срок', 'info', 6000)");
    c.run("showToast('Нулевой срок задан вызывающим', 'info', 0)");
    assert.strictEqual(c.timers[0], 3000);
    assert.ok(c.timers[1] > 3000, `длинная ошибка показана всего ${c.timers[1]} мс`);
    assert.strictEqual(c.timers[2], 6000);
    assert.strictEqual(c.timers[3], 0);
});

done();
