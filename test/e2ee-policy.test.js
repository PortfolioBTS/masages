'use strict';
// Правила обязательного E2EE на клиенте (public/lib/e2ee-policy.js, R7):
//   - открытый текст — только в чат с ботом, номер которого запомнен при регистрации;
//   - блокировка отправки, если ключ комнаты не дошёл ни до одного участника;
//   - причины недоступности шифрования по кодам E2eeError и «Повторить»;
//   - что показано под полем ввода и в шапке в каждом состоянии.
// Запуск: node test/e2ee-policy.test.js

const assert = require('assert');
const Policy = require('../public/lib/e2ee-policy.js');
const E2EE = require('../public/e2ee.js');

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

test('parseBotChatId: положительное целое строкой или числом, остальное — null', () => {
    assert.strictEqual(Policy.parseBotChatId('42'), 42);
    assert.strictEqual(Policy.parseBotChatId(42), 42);
    assert.strictEqual(Policy.parseBotChatId('2147483647'), 2147483647);
    for (const bad of [null, undefined, '', '0', '-5', '007', '1e3', '12abc', ' 5', '5 ', '1.5', 1.5, '99999999999', true, {}, [], NaN]) {
        assert.strictEqual(Policy.parseBotChatId(bad), null, JSON.stringify(bad));
    }
});

test('plaintextAllowed: открытый текст только в запомненный чат с ботом без комнаты', () => {
    assert.strictEqual(Policy.plaintextAllowed('7', 7, null), true, 'совпало: можно');
    assert.strictEqual(Policy.plaintextAllowed('7', '7', undefined), true, 'номер чата строкой');
    assert.strictEqual(Policy.plaintextAllowed(7, 7, null), true);
    assert.strictEqual(Policy.plaintextAllowed('7', 8, null), false, 'другой чат');
    assert.strictEqual(Policy.plaintextAllowed(null, 7, null), false, 'номер не запомнен');
    assert.strictEqual(Policy.plaintextAllowed('мусор', 7, null), false, 'в хранилище мусор');
    assert.strictEqual(Policy.plaintextAllowed('7', null, null), false, 'нет чата');
    assert.strictEqual(Policy.plaintextAllowed('7', 7, 55), false, 'комната: даже если номер совпал со «ботом» — шифруем');
    assert.strictEqual(Policy.plaintextAllowed('7', 7, 0), true, 'room_id 0/пусто — не комната');
});

test('sessionBlock: нет сессии или ключ не дошёл никому при других участниках — блок; остальное — нет', () => {
    const none = Policy.sessionBlock(null);
    assert.strictEqual(none.code, 'session-failed');
    assert.match(none.text, /не отправлено/);
    const undelivered = Policy.sessionBlock({ ok: false, peers: 2, keyHolders: 0 });
    assert.strictEqual(undelivered.code, 'keys-not-delivered');
    assert.match(undelivered.text, /ни одному участнику/);

    assert.strictEqual(Policy.sessionBlock({ ok: false, peers: 2, keyHolders: 1 }), null, 'дошёл до части — отправляем');
    assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 2, keyHolders: 2 }), null, 'дошёл до всех');
    assert.strictEqual(Policy.sessionBlock({ ok: true, peers: 2, keyHolders: 0 }), null, 'ok, но у остальных нет шифрования — не блокируем');
    assert.strictEqual(Policy.sessionBlock({ ok: false, peers: 0, keyHolders: 0 }), null, 'других участников нет — блокировать нечего');
    assert.strictEqual(Policy.sessionBlock({ ok: true }), null, 'без счётчиков (старый результат) — не блокируем');
});

test('initErrorReason и initErrorRetryable: по одному тексту на каждый код E2EE.ERROR_CODES', () => {
    const reasons = new Set();
    for (const code of E2EE.ERROR_CODES) {
        const err = new E2EE.E2eeError(code, 'x');
        const reason = Policy.initErrorReason(err);
        assert.ok(reason && reason !== Policy.initErrorReason(null), `для ${code} нужен свой текст`);
        reasons.add(reason);
        assert.strictEqual(Policy.initErrorRetryable(err), code !== 'unsupported' && code !== 'storage', code);
    }
    assert.strictEqual(reasons.size, E2EE.ERROR_CODES.length, 'тексты не повторяются');
    // Неизвестный код и «не ошибка»: общий текст, повтор допустим.
    assert.strictEqual(Policy.initErrorReason({ code: 'constructor' }), Policy.initErrorReason(null), 'имена из прототипа не находятся');
    assert.strictEqual(Policy.initErrorReason(new Error('сбой')), Policy.initErrorReason(null));
    assert.strictEqual(Policy.initErrorRetryable(null), true);
    assert.deepStrictEqual(Object.keys(Policy.INIT_REASONS).sort(), E2EE.ERROR_CODES.slice().sort(), 'тексты есть ровно для кодов модуля');
});

test('composerView: комната готова — замок, поле доступно, повтора нет', () => {
    const v = Policy.composerView({ inRoom: true, plaintextOk: false, e2ee: 'ready', initError: null, block: null });
    assert.strictEqual(v.kind, 'ready');
    assert.strictEqual(v.disabled, false);
    assert.strictEqual(v.retry, false);
    assert.strictEqual(v.icon, 'lock');
    assert.strictEqual(v.placeholder, 'Зашифрованное сообщение...');
    assert.deepStrictEqual(v.indicator, { show: true, ok: true, text: 'шифрование', title: v.indicator.title });
});

test('composerView: ключи готовятся — спиннер, поле доступно (отправка дождётся ключей)', () => {
    for (const e2ee of ['pending', 'off']) {
        const v = Policy.composerView({ inRoom: true, plaintextOk: false, e2ee, initError: null, block: null });
        assert.strictEqual(v.kind, 'pending', e2ee);
        assert.strictEqual(v.spin, true);
        assert.strictEqual(v.disabled, false);
        assert.match(v.text, /Готовим ключи шифрования/);
    }
});

test('composerView: шифрование недоступно — поле отключено, причина по коду, «Повторить» только где есть смысл', () => {
    for (const code of E2EE.ERROR_CODES) {
        const initError = new E2EE.E2eeError(code, 'x');
        const v = Policy.composerView({ inRoom: true, plaintextOk: false, e2ee: 'unavailable', initError, block: null });
        assert.strictEqual(v.kind, 'unavailable', code);
        assert.strictEqual(v.disabled, true, code);
        assert.strictEqual(v.retry, code !== 'unsupported' && code !== 'storage', code);
        assert.ok(v.text.includes(Policy.initErrorReason(initError)), `${code}: в тексте причина`);
        assert.strictEqual(v.indicator.ok, false);
        assert.strictEqual(v.indicator.text, 'нет шифрования');
        assert.strictEqual(v.icon, 'alert-triangle');
    }
});

test('composerView: отправка отклонена (ключ не дошёл) — поле доступно, показана причина и «Повторить»', () => {
    const block = Policy.sessionBlock({ ok: false, peers: 1, keyHolders: 0 });
    const v = Policy.composerView({ inRoom: true, plaintextOk: false, e2ee: 'ready', initError: null, block });
    assert.strictEqual(v.kind, 'blocked');
    assert.strictEqual(v.text, block.text);
    assert.strictEqual(v.retry, true);
    assert.strictEqual(v.disabled, false, 'черновик не теряется, повтор — отправкой или кнопкой');
    assert.strictEqual(v.indicator.ok, false);
});

test('composerView: недоступность важнее блокировки; в неготовом клиенте блок не показывается', () => {
    const block = Policy.sessionBlock(null);
    const unavailable = Policy.composerView({ inRoom: true, plaintextOk: false, e2ee: 'unavailable', initError: { code: 'network' }, block });
    assert.strictEqual(unavailable.kind, 'unavailable');
    const pending = Policy.composerView({ inRoom: true, plaintextOk: false, e2ee: 'pending', initError: null, block });
    assert.strictEqual(pending.kind, 'pending');
});

test('composerView: чат с ботом — открытый текст разрешён и об этом сказано; чужой чат без комнаты — отключён', () => {
    const bot = Policy.composerView({ inRoom: false, plaintextOk: true, e2ee: 'unavailable', initError: { code: 'server' }, block: null });
    assert.strictEqual(bot.kind, 'bot');
    assert.strictEqual(bot.disabled, false, 'бот не зависит от шифрования');
    assert.match(bot.text, /не защищены сквозным шифрованием/);
    assert.strictEqual(bot.indicator.show, false, 'значка шифрования в чате с ботом нет');
    assert.strictEqual(bot.placeholder, Policy.PLACEHOLDERS.bot);

    const unknown = Policy.composerView({ inRoom: false, plaintextOk: false, e2ee: 'ready', initError: null, block: null });
    assert.strictEqual(unknown.kind, 'unknown');
    assert.strictEqual(unknown.disabled, true);
    assert.strictEqual(unknown.retry, false);
});

test('composerView: в тексте нет эмодзи', () => {
    const emoji = /\p{Extended_Pictographic}/u;
    const states = [
        { inRoom: true, plaintextOk: false, e2ee: 'ready', initError: null, block: null },
        { inRoom: true, plaintextOk: false, e2ee: 'pending', initError: null, block: null },
        { inRoom: true, plaintextOk: false, e2ee: 'unavailable', initError: { code: 'storage' }, block: null },
        { inRoom: true, plaintextOk: false, e2ee: 'ready', initError: null, block: Policy.sessionBlock(null) },
        { inRoom: false, plaintextOk: true, e2ee: 'ready', initError: null, block: null },
        { inRoom: false, plaintextOk: false, e2ee: 'ready', initError: null, block: null },
    ];
    for (const state of states) {
        const v = Policy.composerView(state);
        assert.ok(!emoji.test(v.text + v.placeholder + v.indicator.text + v.indicator.title), v.kind);
    }
});

console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
if (failed > 0) process.exitCode = 1;
