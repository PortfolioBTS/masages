'use strict';
// Статические проверки клиента для R7 «обязательное E2EE в комнатах» (без браузера).
//
// Выключателя шифрования нет, открытый текст уходит только в чат с ботом, номер
// которого запомнен при регистрации, а не по признаку от сервера. Эти проверки
// не заменяют ручную проверку в браузере, но не дают вернуть удалённое
// незаметно (слиянием веток или «починкой»).
// Запуск: node test/client-e2ee-required.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const read = (name) => fs.readFileSync(path.join(PUBLIC_DIR, name), 'utf8');
const { readClientScript, clientScriptFiles } = require('./client-script-source');
const script = readClientScript();
const html = read('index.html');
const css = read('style.css');

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

// Тело функции верхнего уровня по имени: от «function name(» до закрывающей скобки на нулевом отступе.
function functionBody(source, name) {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    assert.ok(match, `функция ${name} не найдена`);
    const end = source.indexOf('\n}\n', match.index);
    assert.ok(end > 0, `у функции ${name} нет конца`);
    return source.slice(match.index, end + 2);
}

test('выключатель удалён: ни кнопки в разметке, ни прежних функций и стилей', () => {
    assert.ok(!html.includes('e2ee-toggle-btn'), 'в index.html осталась кнопка выключателя');
    for (const gone of [
        'isE2eePreferred', 'setE2eePreferred', 'isE2eeActiveForChat', 'onE2eeToggleClick',
        'updateE2eeToggleUI', 'prepareOutgoingE2ee', 'e2eePrefKey', 'e2eeToggleBtn', 'editingMessageEncrypted',
        'describeE2eeInitError', 'shouldMarkPlaintext', 'createPlaintextLabel', 'plaintext-label',
    ]) {
        assert.ok(!script.includes(gone), `в script.js осталось «${gone}»`);
    }
    assert.ok(!script.includes("'key-server'"), 'мёртвая ветка про код key-server должна быть удалена');
    assert.ok(!script.includes('e2ee-enabled:${'), 'ключи e2ee-enabled больше не пишутся');
    assert.doesNotMatch(css, /\.plaintext-label|\.e2ee-active|\.e2ee-unavailable/);
});

test('флаги e2ee-enabled:* стираются один раз при старте, первым шагом init()', () => {
    assert.match(script, /const LEGACY_E2EE_PREF_PREFIX = 'e2ee-enabled:';/);
    const sweep = functionBody(script, 'sweepLegacyPrefs');
    assert.match(sweep, /startsWith\(LEGACY_E2EE_PREF_PREFIX\)/);
    assert.match(sweep, /removeItem/);
    const init = functionBody(script, 'init');
    assert.ok(init.indexOf('sweepLegacyPrefs()') > 0 && init.indexOf('sweepLegacyPrefs()') < init.indexOf('checkAuth()'), 'чистка раньше проверки входа');
    // Из личных флагов пользователя префикс убран: removeLocalUserPrefs их не знает.
    assert.doesNotMatch(functionBody(script, 'removeLocalUserPrefs'), /e2ee-enabled|LEGACY_E2EE/);
});

test('открытый текст — только по номеру чата с ботом из localStorage, а не по признаку от сервера', () => {
    assert.match(script, /const BOT_CHAT_PREFIX = 'nyxo-bot-chat:';/);
    const read = functionBody(script, 'readRememberedBotChatId');
    assert.match(read, /localStorage\.getItem\(BOT_CHAT_PREFIX \+ userId\)/);
    const allowed = functionBody(script, 'plaintextAllowedForChat');
    assert.match(allowed, /NyxoE2eePolicy\.plaintextAllowed\(readRememberedBotChatId\(currentUser\.id\), chatId, roomId\)/);
    assert.doesNotMatch(allowed, /is_bot|isBot/);

    const prepare = functionBody(script, 'prepareOutgoing');
    assert.doesNotMatch(prepare, /is_bot|isBot|currentChatIsBot/, 'решение об открытом тексте не зависит от признака сервера');
    // В комнате null не возвращается: единственный «return null» стоит под условием «это чат с ботом».
    assert.strictEqual((prepare.match(/return null/g) || []).length, 1, 'return null ровно один');
    assert.match(prepare, /if \(!roomId\) \{\s*if \(plaintextAllowedForChat\(chatId, roomId\)\) return null;\s*throw new E2eeBlockedError\(/);
});

test('отправка текста, файлов и правки идёт через prepareOutgoing и E2eeBlockedError', () => {
    assert.match(script, /class E2eeBlockedError extends Error/);
    for (const name of ['sendText', 'sendOneFile']) {
        const body = functionBody(script, name);
        assert.match(body, /await prepareOutgoing\(chatId, roomId\)/, name);
        assert.match(body, /instanceof E2eeBlockedError/, name);
    }
    const prepare = functionBody(script, 'prepareOutgoing');
    assert.match(prepare, /NyxoE2eePolicy\.sessionBlock\(session\)/, 'правило блокировки при недоставке ключа');
    const send = functionBody(script, 'sendMessage');
    assert.match(send, /const encryptEdit = Boolean\(roomId\);/, 'правка в комнате шифруется всегда');
    assert.doesNotMatch(functionBody(script, 'sendText'), /выключите шифрование/);
});

test('сообщение комнаты без шифрования не показывается: подложить его мог только сервер', () => {
    assert.match(script, /'not-encrypted': '/);
    const decrypt = functionBody(script, 'decryptMessageInPlace');
    assert.match(decrypt, /if \(roomId && !message\.encrypted\) \{[^}]*e2eeFailureText\('not-encrypted'\)[^}]*_e2eeFailed = true/s);
    assert.match(decrypt, /file_url = null/);
    assert.match(script, /if \(roomId && !encrypted\) \{\s*\/\/ Правка без шифрования в комнате/);
    // Превью списка чатов не показывает текст сообщения комнаты.
    assert.match(functionBody(script, 'messagePreview'), /message\.encrypted \|\| message\.room_id/);
    assert.match(functionBody(script, 'chatLastPreview'), /chat\.room_id && chat\.last_message_id/);
});

test('разметка: значок шифрования в шапке, состояние и «Повторить» под полем ввода; политика подключена до script.js', () => {
    for (const id of ['e2ee-indicator', 'composer-status', 'composer-status-icon', 'composer-status-text', 'composer-status-retry']) {
        assert.strictEqual((html.match(new RegExp(`id="${id}"`, 'g')) || []).length, 1, id);
    }
    const sendBtn = html.indexOf('id="send-btn"');
    const status = html.indexOf('id="composer-status"');
    const fileInput = html.indexOf('id="file-input"');
    assert.ok(sendBtn > 0 && status > sendBtn && fileInput > status, 'строка состояния стоит под полем ввода');
    assert.ok(html.indexOf('<script src="lib/e2ee-policy.js">') > 0 && html.indexOf('lib/e2ee-policy.js') < html.indexOf(`<script src="${clientScriptFiles()[0]}">`));
    // Значок открывает «Участники и ключи».
    assert.match(functionBody(script, 'setupE2eeListeners'), /e2eeIndicator\.addEventListener\('click', openMembersModal\)/);
});

test('поле ввода комнаты отключается, когда шифрование недоступно: причина и «Повторить»', () => {
    const update = functionBody(script, 'updateComposerForChat');
    assert.match(update, /NyxoE2eePolicy\.composerView\(/);
    assert.match(update, /setComposerDisabled\(view\.disabled, view\.text\)/);
    assert.match(update, /composerStatusRetry\.classList\.toggle\('hidden', !view\.retry\)/);
    const disabled = functionBody(script, 'setComposerDisabled');
    for (const control of ['messageInput', 'sendBtn', 'attachBtn']) assert.match(disabled, new RegExp(`${control}\\.disabled`), control);
    assert.match(functionBody(script, 'onFilesChosen'), /composerDisabledReason/, 'перетаскивание файлов тоже учитывает отключение');
    assert.match(functionBody(script, 'setupE2eeListeners'), /composerStatusRetry\.addEventListener\('click'/);
});

console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
if (failed > 0) process.exitCode = 1;
