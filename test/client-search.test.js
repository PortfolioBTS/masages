'use strict';
// Статические проверки поиска только на устройстве (R6) без браузера: серверного
// поиска нет, при вводе запроса клиент не обращается к сети, открытый текст не
// пишется на диск (localStorage, sessionStorage, IndexedDB), разметка доступна.
// Поведение в браузере (подсветка, переход, сеть в DevTools) проверяется руками.
// Запуск: node test/client-search.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const read = (name) => fs.readFileSync(path.join(PUBLIC_DIR, name), 'utf8');
const { readClientScript, clientScriptFiles } = require('./client-script-source');
const { readClientCss } = require('./client-css');
const script = readClientScript();
const html = read('index.html');
const lib = read('lib/text-search.js');
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

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

// Тело функции верхнего уровня по имени.
function functionBody(source, name) {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    assert.ok(match, `функция ${name} не найдена`);
    const end = source.indexOf('\n}\n', match.index);
    assert.ok(end > 0, `у функции ${name} нет конца`);
    return source.slice(match.index, end + 2);
}

const NETWORK = /\bapi\(|fetch\(|XMLHttpRequest|postFormData|socket\.emit|navigator\.sendBeacon/;
const STORAGE = /localStorage|sessionStorage|indexedDB|caches\.|document\.cookie/;

test('серверного поиска нет ни на сервере, ни в клиенте', () => {
    assert.ok(!server.includes('/api/search'), 'в server.js остался маршрут поиска');
    assert.ok(!script.includes('/api/search'), 'клиент всё ещё ходит на /api/search');
    for (const gone of ['performSearch', 'chatListMode', 'renderSearchSection', 'searchSeq']) {
        assert.ok(!script.includes(gone), `в script.js осталось «${gone}»`);
    }
});

test('ввод в поиск не обращается к сети и не пишет на диск', () => {
    for (const name of [
        'applyChatFilter', 'setupSearchListeners', 'setHighlightedText', 'searchableText', 'collectSearchEntries',
        'matchRange', 'paintSearchHighlights', 'goToSearchMatch', 'runChatSearch', 'markChatSearchStale',
        'stepChatSearch', 'openChatSearch', 'closeChatSearch', 'setupChatSearchListeners', 'renderChatList',
    ]) {
        const body = functionBody(script, name);
        assert.doesNotMatch(body, NETWORK, `${name}: обращение к сети`);
        assert.doesNotMatch(body, STORAGE, `${name}: запись на диск`);
    }
    // Единственная загрузка — кнопка «Искать в более ранних»: обычная страница истории через loadOlderMessages.
    const older = functionBody(script, 'searchOlderMessages');
    assert.match(older, /await loadOlderMessages\(\)/);
    assert.doesNotMatch(older, NETWORK);
    assert.doesNotMatch(older, STORAGE);
    // Сама библиотека — чистые функции: ни сети, ни хранилищ, ни DOM.
    const libCode = lib.replace(/\/\/.*$/gm, '');   // комментарии не в счёт
    assert.doesNotMatch(libCode, NETWORK);
    assert.doesNotMatch(libCode, STORAGE);
    assert.doesNotMatch(libCode, /document\.|window\./);
});

test('свёртка текста хранится только в памяти сообщения', () => {
    assert.match(functionBody(script, 'collectSearchEntries'), /message\._fold = NyxoTextSearch\.foldText\(message\.text\)/);
    // Ничего из состояния поиска и свёрток не сериализуется и не уходит в хранилище.
    assert.doesNotMatch(script, /JSON\.stringify\(\s*(chatSearch|[a-z]+\._fold)/);
    assert.doesNotMatch(script, /(setItem|\.put|\.add)\([^)]*(_fold|chatSearch)/);
});

test('список чатов фильтруется на клиенте по названию; названия выделяются через mark без innerHTML', () => {
    const render = functionBody(script, 'renderChatList');
    assert.match(render, /NyxoTextSearch\.filterChats\(chatListData, chatFilter\)/);
    assert.match(render, /chatsEmpty\.classList\.toggle\('hidden', filtered\.length > 0\)/);
    const highlighted = functionBody(script, 'setHighlightedText');
    assert.match(highlighted, /createElement\('mark'\)/);
    assert.doesNotMatch(highlighted, /innerHTML|insertAdjacentHTML/);
    const listeners = functionBody(script, 'setupSearchListeners');
    assert.match(listeners, /requestAnimationFrame/);
    assert.match(listeners, /e\.key === 'Escape'/);
    assert.match(listeners, /ArrowDown/);
});

test('поиск в чате: нерасшифрованные пропускаются, выделение через CSS Custom Highlight API', () => {
    const searchable = functionBody(script, 'searchableText');
    assert.match(searchable, /message\._e2eeFailed/);
    assert.match(searchable, /node\.data === message\.text/, 'искать можно только когда DOM совпадает с текстом');
    assert.match(functionBody(script, 'paintSearchHighlights'), /CSS\.highlights\.set\(HIGHLIGHT_ALL/);
    assert.match(readClientCss(), /::highlight\(nyxo-search\)[^}]*\}[\s\S]*::highlight\(nyxo-search-current\)/);
    assert.match(functionBody(script, 'releaseChatResources'), /closeChatSearch\(\)/, 'смена чата закрывает поиск и снимает подсветку');
    // Новые, исправленные и удалённые сообщения помечают результаты устаревшими.
    for (const name of ['appendMessage', 'removeMessageElement', 'applyMessageEdit']) {
        assert.match(functionBody(script, name), /markChatSearchStale\(\)/, name);
    }
});

test('разметка: поле поиска чатов, пустой результат, панель поиска по сообщениям', () => {
    assert.match(html, /<input type="search" id="search-input" placeholder="Поиск чатов" aria-label="Поиск по названиям чатов" aria-controls="chats-list"/);
    assert.match(html, /id="chats-empty"[^>]*role="status"/);
    assert.match(html, /id="chat-search-btn"[^>]*aria-expanded="false"[^>]*aria-controls="chat-search"|id="chat-search-btn"[^>]*aria-controls="chat-search"[^>]*aria-expanded="false"/);
    assert.match(html, /id="chat-search"[^>]*role="search"/);
    assert.match(html, /id="chat-search-input"[^>]*aria-label="Поиск по сообщениям, загруженным на это устройство"/);
    assert.match(html, /id="chat-search-counter"[^>]*aria-live="polite"/);
    for (const id of ['chat-search-prev', 'chat-search-next', 'chat-search-older', 'chat-search-close']) {
        assert.strictEqual((html.match(new RegExp(`id="${id}"`, 'g')) || []).length, 1, id);
    }
    assert.ok(html.indexOf('lib/text-search.js') > 0 && html.indexOf('lib/text-search.js') < html.indexOf(`<script src="${clientScriptFiles()[0]}">`));
    assert.match(read('icons.js'), /'chevron-up':/);
    // Прежнего «Поиск чатов и сообщений» нет: серверного поиска по сообщениям не существует.
    assert.ok(!html.includes('Поиск чатов и сообщений'));
});

console.log(`\nИтого: ${passed} прошло, ${failed} упало`);
if (failed > 0) process.exitCode = 1;
