'use strict';
// Тесты политики типов вложений на клиенте (public/lib/mime-policy.js) и
// того, как она подключена к странице. Без браузера, БД и сети.
//
// Что проверяется:
//   1. сам модуль: белый список, определение типа файла, строгое
//      сравнение, тип для blob:, иконка, обезличенное имя — и что звук нигде
//      не проходит;
//   2. клиентский список совпадает с серверным (lib/security-utils.js): если
//      они разойдутся, клиент начнёт отправлять то, что сервер отклонит, или
//      наоборот;
//   3. страница подключена правильно: скрипт модуля стоит до script.js,
//      accept у выбора файла равен списку, нет кнопки записи, иконок звука и
//      любого следа записи и звука в public/ (критерий 2.4 из roadmap).
//
// Запуск: node test/mime-policy.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { readClientScript, clientScriptFiles } = require('./client-script-source');
const vm = require('vm');

const policy = require('../public/lib/mime-policy');
const serverUtils = require('../lib/security-utils');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const MODULE_FILE = path.join(PUBLIC_DIR, 'lib', 'mime-policy.js');

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

const readPublic = (relative) => fs.readFileSync(path.join(PUBLIC_DIR, relative), 'utf8');
const { readClientCss } = require('./client-css');

// Звуковые типы во всех видах, в которых их называют браузеры и ОС, плюс
// контейнеры, которые чаще всего прячут звук. Ни один не должен пройти.
const AUDIO_TYPES = [
    'audio/mpeg', 'audio/mp3', 'audio/ogg', 'audio/wav', 'audio/x-wav', 'audio/wave',
    'audio/vnd.wave', 'audio/x-pn-wav', 'audio/webm', 'audio/aac', 'audio/flac',
    'audio/opus', 'audio/mp4', 'audio/x-m4a', 'audio/3gpp', 'audio/midi',
    'Audio/MPEG', 'AUDIO/WEBM', 'audio/webm;codecs=opus', 'audio/ogg; codecs=opus',
    'application/ogg', 'video/ogg',
];

const AUDIO_ONLY_TYPES = AUDIO_TYPES.filter(mime => /^audio\//i.test(mime));

const EXPECTED_TYPES = [
    'application/pdf', 'image/gif', 'image/jpeg', 'image/png', 'image/webp',
    'text/plain', 'video/mp4', 'video/quicktime', 'video/webm',
];

console.log('Mime policy tests\n');

// ---------- Белый список ----------

test('the white list is exactly photos, video, PDF and TXT, and it cannot be changed at runtime', () => {
    assert.deepStrictEqual([...policy.ALLOWED_UPLOAD_MIMES].sort(), EXPECTED_TYPES);
    assert.ok(Object.isFrozen(policy.ALLOWED_UPLOAD_MIMES));
    assert.ok(Object.isFrozen(policy.MIME_ALIASES));
    assert.ok(Object.isFrozen(policy.ANONYMOUS_FILE_NAMES));
    assert.throws(() => policy.ALLOWED_UPLOAD_MIMES.push('audio/mpeg'), TypeError);
});

test('the client list matches the server list (ALLOWED_MIME_TYPES) and anonymous names match the server ones', () => {
    assert.deepStrictEqual([...policy.ALLOWED_UPLOAD_MIMES].sort(), [...serverUtils.ALLOWED_MIME_TYPES].sort());
    assert.deepStrictEqual(policy.ANONYMOUS_FILE_NAMES, serverUtils.ANONYMIZED_FILE_NAMES);
    for (const mime of policy.ALLOWED_UPLOAD_MIMES) {
        assert.strictEqual(policy.anonymousFileName(mime), serverUtils.anonymizedFileName(mime), mime);
    }
    assert.strictEqual(policy.anonymousFileName('application/x-evil'), serverUtils.anonymizedFileName('application/x-evil'));
});

test('isAllowedUpload: every listed type is allowed', () => {
    for (const mime of EXPECTED_TYPES) assert.strictEqual(policy.isAllowedUpload(mime), true, mime);
});

test('isAllowedUpload: audio types are not allowed in any spelling', () => {
    for (const mime of AUDIO_TYPES) assert.strictEqual(policy.isAllowedUpload(mime), false, mime);
});

test('isAllowedUpload: strict comparison (case, parameters, synonyms are not forgiven; no inherited keys)', () => {
    for (const mime of [
        'IMAGE/PNG', 'Image/Jpeg', 'image/png; x=1', ' image/png', 'image/png ', 'image/jpg', 'image/pjpeg',
        'application/octet-stream', 'text/html', 'image/svg+xml', 'application/x-evil', '',
        '__proto__', 'constructor', 'toString', 'hasOwnProperty',
    ]) {
        assert.strictEqual(policy.isAllowedUpload(mime), false, JSON.stringify(mime));
    }
    for (const value of [undefined, null, 0, 1, true, {}, [], ['image/png'], { toString: () => 'image/png' }]) {
        assert.strictEqual(policy.isAllowedUpload(value), false, String(typeof value));
    }
});

// ---------- Определение типа файла ----------

test('normalizeMime: case, parameters and synonyms; garbage becomes an empty string', () => {
    assert.strictEqual(policy.normalizeMime('Image/PNG'), 'image/png');
    assert.strictEqual(policy.normalizeMime('video/webm;codecs=vp9'), 'video/webm');
    assert.strictEqual(policy.normalizeMime(' text/plain ; charset=utf-8 '), 'text/plain');
    assert.strictEqual(policy.normalizeMime('image/jpg'), 'image/jpeg');
    assert.strictEqual(policy.normalizeMime('image/pjpeg'), 'image/jpeg');
    assert.strictEqual(policy.normalizeMime('IMAGE/PJPEG; x=1'), 'image/jpeg');
    assert.strictEqual(policy.normalizeMime('audio/MPEG'), 'audio/mpeg', 'unknown types stay as they are, but are never allowed');
    assert.strictEqual(policy.normalizeMime(''), '');
    for (const value of [undefined, null, 5, {}, []]) assert.strictEqual(policy.normalizeMime(value), '');
});

test('normalizeMime: synonyms are looked up by own keys only', () => {
    assert.strictEqual(policy.normalizeMime('__proto__'), '__proto__');
    assert.strictEqual(policy.normalizeMime('constructor'), 'constructor');
    assert.strictEqual(policy.isAllowedUpload(policy.normalizeMime('constructor')), false);
});

test('detectFileMime: the type reported by the browser wins, synonyms and parameters are normalized', () => {
    assert.strictEqual(policy.detectFileMime({ type: 'image/png', name: 'a.bin' }), 'image/png');
    assert.strictEqual(policy.detectFileMime({ type: 'image/jpg', name: 'a.jpg' }), 'image/jpeg');
    assert.strictEqual(policy.detectFileMime({ type: 'Video/WebM;codecs=vp9', name: 'a.webm' }), 'video/webm');
    assert.strictEqual(policy.detectFileMime({ type: 'application/pdf', name: 'a.txt' }), 'application/pdf');
});

test('detectFileMime: an empty type is completed from .txt and .pdf only', () => {
    assert.strictEqual(policy.detectFileMime({ type: '', name: 'notes.txt' }), 'text/plain');
    assert.strictEqual(policy.detectFileMime({ type: '', name: 'NOTES.TXT' }), 'text/plain');
    assert.strictEqual(policy.detectFileMime({ type: '', name: 'doc.PDF' }), 'application/pdf');
    assert.strictEqual(policy.detectFileMime({ name: 'doc.pdf' }), 'application/pdf');
    for (const name of ['photo.png', 'clip.mp4', 'song.mp3', 'voice.ogg', 'sound.wav', 'voice.webm', 'noext', '']) {
        assert.strictEqual(policy.detectFileMime({ type: '', name }), '', name);
    }
    assert.strictEqual(policy.detectFileMime(null), '');
    assert.strictEqual(policy.detectFileMime(undefined), '');
    assert.strictEqual(policy.detectFileMime({}), '');
});

test('audio never passes the whole pipeline (detect, then allow), whatever the file is called', () => {
    const names = ['song.mp3', 'voice.ogg', 'sound.wav', 'voice.webm', 'fake.pdf', 'fake.txt', 'photo.jpg', ''];
    for (const type of AUDIO_TYPES) {
        for (const name of names) {
            const mime = policy.detectFileMime({ type, name });
            assert.strictEqual(policy.isAllowedUpload(mime), false, `${type} / ${name} -> ${mime}`);
        }
    }
    // Звук без типа от браузера: расширение .mp3/.ogg/.wav ничего не открывает.
    for (const name of ['song.mp3', 'voice.ogg', 'sound.wav', 'voice.opus', 'voice.m4a']) {
        assert.strictEqual(policy.isAllowedUpload(policy.detectFileMime({ type: '', name })), false, name);
    }
});

// ---------- Что показывается и как называется ----------

test('safeBlobMime: listed types stay, everything else becomes opaque bytes', () => {
    for (const mime of EXPECTED_TYPES) assert.strictEqual(policy.safeBlobMime(mime), mime, mime);
    for (const mime of [
        ...AUDIO_TYPES, 'text/html', 'image/svg+xml', 'application/javascript', 'application/xhtml+xml',
        'IMAGE/PNG', 'image/png; x=1', 'application/octet-stream', '', '__proto__',
    ]) {
        assert.strictEqual(policy.safeBlobMime(mime), 'application/octet-stream', JSON.stringify(mime));
    }
    for (const value of [undefined, null, 7, {}, ['image/png']]) {
        assert.strictEqual(policy.safeBlobMime(value), 'application/octet-stream');
    }
});

test('fileIconName: image, video and documents have their icons, audio and the unknown get the plain file', () => {
    assert.strictEqual(policy.fileIconName('image/png'), 'image');
    assert.strictEqual(policy.fileIconName('image/webp'), 'image');
    assert.strictEqual(policy.fileIconName('video/mp4'), 'video');
    assert.strictEqual(policy.fileIconName('video/quicktime'), 'video');
    assert.strictEqual(policy.fileIconName('application/pdf'), 'file-text');
    assert.strictEqual(policy.fileIconName('text/plain'), 'file-text');
    for (const mime of [...AUDIO_ONLY_TYPES, 'application/ogg', 'application/octet-stream', 'application/zip', '']) {
        assert.strictEqual(policy.fileIconName(mime), 'file', mime);
    }
    for (const value of [undefined, null, 3, {}]) assert.strictEqual(policy.fileIconName(value), 'file');
});

test('isMediaMime: only photos and video are media (they get anonymous names inside an E2EE envelope)', () => {
    for (const mime of ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/quicktime']) {
        assert.strictEqual(policy.isMediaMime(mime), true, mime);
    }
    for (const mime of ['application/pdf', 'text/plain', 'audio/mpeg', 'audio/webm', 'application/octet-stream', '']) {
        assert.strictEqual(policy.isMediaMime(mime), false, mime);
    }
    for (const value of [undefined, null, 1, {}]) assert.strictEqual(policy.isMediaMime(value), false);
});

test('anonymousFileName: fixed names by type; audio, unknown and inherited keys get the neutral name', () => {
    assert.strictEqual(policy.anonymousFileName('image/jpeg'), 'photo.jpg');
    assert.strictEqual(policy.anonymousFileName('video/quicktime'), 'video.mov');
    assert.strictEqual(policy.anonymousFileName('application/pdf'), 'document.pdf');
    assert.strictEqual(policy.anonymousFileName('text/plain'), 'text.txt');
    for (const mime of [...AUDIO_TYPES, 'application/octet-stream', '__proto__', 'constructor', 'toString', '']) {
        assert.strictEqual(policy.anonymousFileName(mime), 'file', mime);
    }
    for (const value of [undefined, null, 1, {}]) assert.strictEqual(policy.anonymousFileName(value), 'file');
    assert.ok(!/audio/i.test(JSON.stringify(policy.ANONYMOUS_FILE_NAMES)), 'no audio name anywhere');
});

// ---------- Загрузка модуля ----------

test('the browser path: a plain script with no module system publishes MimePolicy on self and needs no DOM', () => {
    const sandbox = {};
    sandbox.self = sandbox;
    vm.runInNewContext(fs.readFileSync(MODULE_FILE, 'utf8'), sandbox, { filename: 'mime-policy.js' });
    const loaded = sandbox.MimePolicy;
    assert.strictEqual(typeof loaded, 'object');
    assert.strictEqual([...loaded.ALLOWED_UPLOAD_MIMES].sort().join(), EXPECTED_TYPES.join());
    assert.strictEqual(loaded.isAllowedUpload('image/png'), true);
    assert.strictEqual(loaded.isAllowedUpload('audio/mpeg'), false);
    assert.strictEqual(loaded.safeBlobMime('audio/ogg'), 'application/octet-stream');
    assert.strictEqual(loaded.fileIconName('audio/wav'), 'file');
    assert.strictEqual(loaded.detectFileMime({ type: 'image/jpg', name: 'a.jpg' }), 'image/jpeg');
});

// ---------- Подключение к странице ----------

const html = readPublic('index.html');

function tagWithId(id) {
    const match = new RegExp(`<[a-zA-Z][^>]*\\sid="${id}"[^>]*>`).exec(html);
    return match ? match[0] : null;
}

test('index.html: the module script is loaded exactly once and before the app scripts (js/*.js)', () => {
    const sources = [...html.matchAll(/<script\b[^>]*\ssrc="([^"]+)"/g)].map(m => m[1]);
    const moduleAt = sources.indexOf('lib/mime-policy.js');
    const scriptAt = sources.indexOf(clientScriptFiles()[0]);
    assert.ok(moduleAt >= 0, 'lib/mime-policy.js is not linked from index.html: ' + sources.join(', '));
    assert.ok(scriptAt >= 0);
    assert.strictEqual(sources.lastIndexOf('lib/mime-policy.js'), moduleAt, 'linked more than once');
    assert.ok(moduleAt < scriptAt, 'the app scripts (js/*.js) would start without MimePolicy');
    assert.ok(fs.existsSync(MODULE_FILE));
});

test('index.html: the file picker accept list is exactly the white list (plus .pdf and .txt for systems with no type)', () => {
    const input = tagWithId('file-input');
    assert.ok(input, 'no #file-input');
    const accept = /\saccept="([^"]*)"/.exec(input);
    assert.ok(accept, 'no accept attribute on #file-input');
    const tokens = accept[1].split(',').map(t => t.trim());
    const types = tokens.filter(t => t.includes('/')).sort();
    const extensions = tokens.filter(t => t.startsWith('.')).sort();
    assert.deepStrictEqual(types, [...policy.ALLOWED_UPLOAD_MIMES].sort());
    assert.deepStrictEqual(extensions, ['.pdf', '.txt']);
    assert.strictEqual(tokens.length, types.length + extensions.length, 'unexpected token in accept: ' + accept[1]);
});

test('index.html: no voice button and every static icon reference exists in icons.js', () => {
    assert.strictEqual(tagWithId('record-btn'), null);
    const iconsSource = readPublic('icons.js');
    const defined = new Set([...iconsSource.matchAll(/^\s+'([a-z0-9-]+)':\s*'</gm)].map(m => m[1]));
    assert.ok(defined.size > 40 && defined.has('send') && defined.has('paperclip'), 'icons.js was not parsed');
    const used = new Set([...html.matchAll(/<use\s+href="#i-([a-z0-9-]+)"/g)].map(m => m[1]));
    assert.ok(used.size > 10);
    const missing = [...used].filter(name => !defined.has(name));
    assert.deepStrictEqual(missing, [], 'index.html references icons that icons.js does not define');
});

test('icons.js: every icon fileIconName can return exists, and the microphone and note icons are gone', () => {
    const iconsSource = readPublic('icons.js');
    const defined = new Set([...iconsSource.matchAll(/^\s+'([a-z0-9-]+)':\s*'</gm)].map(m => m[1]));
    for (const mime of ['image/png', 'video/mp4', 'application/pdf', 'text/plain', 'application/octet-stream']) {
        assert.ok(defined.has(policy.fileIconName(mime)), `no icon for ${mime}`);
    }
    assert.ok(!defined.has('mic'), 'the microphone icon is still defined');
    assert.ok(!defined.has('music'), 'the note icon is still defined');
});

// Критерий 2.4 (docs/dev/roadmap.md): в клиентском коде нет записи и звука.
// Единственное допустимое совпадение по всему проду — запрет микрофона в
// Permissions-Policy (lib/privacy.js), а это не public/.
function listFiles(dir, base) {
    const found = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const relative = base ? `${base}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
            if (relative === 'vendor') continue; // чужие библиотеки не правим и не ищем в них
            found.push(...listFiles(path.join(dir, entry.name), relative));
        } else if (/\.(js|html|css|webmanifest|svg|json|txt)$/i.test(entry.name)) {
            found.push(relative);
        }
    }
    return found;
}

test('public/ (except vendor) has no voice recording, microphone or audio code (criterion 2.4)', () => {
    const files = listFiles(PUBLIC_DIR, '');
    assert.ok(files.includes('js/01-state.js') && files.includes('index.html') && files.includes('lib/mime-policy.js'), 'file list is broken');
    // (?<!ato)mic: атрибут доступности aria-atomic — не микрофон.
    const forbidden = /record|(?<!ato)mic|голосов|MediaRecorder|getUserMedia|audio\/|\bmusic\b/i;
    const hits = [];
    for (const file of files) {
        readPublic(file).split('\n').forEach((line, index) => {
            if (forbidden.test(line)) hits.push(`public/${file}:${index + 1}  ${line.trim().slice(0, 120)}`);
        });
    }
    assert.deepStrictEqual(hits, [], 'в клиентском коде остались следы записи или звука:\n' + hits.join('\n'));
});

// Тексты интерфейса — тоже клиентский код. «Аудио» по-русски латинские
// подстроки критерия 2.4 не видят, а обещание звука в подсказке — та же
// ошибка, что и лишняя кнопка. «Без звука» (отключённые уведомления чата) —
// другое, поэтому слово «звук» целиком не запрещено.
test('interface texts do not mention audio, voice or a microphone', () => {
    const forbidden = /аудио|голос|микрофон|диктофон/i;
    const hits = [];
    for (const file of listFiles(PUBLIC_DIR, '')) {
        readPublic(file).split('\n').forEach((line, index) => {
            if (forbidden.test(line)) hits.push(`public/${file}:${index + 1}  ${line.trim().slice(0, 120)}`);
        });
    }
    assert.deepStrictEqual(hits, [], 'в клиентских текстах остались упоминания звука:\n' + hits.join('\n'));
});

test('style.css and script.js have no player or recording leftovers', () => {
    const css = readClientCss();
    const script = readClientScript();
    assert.ok(!/\.message-audio|\.recording\b|rec-blink|#record-btn/.test(css));
    assert.ok(!/createElement\(\s*['"]audio['"]\s*\)|message_type\s*===\s*['"]audio['"]|message-audio/.test(script));
    assert.ok(!/\brecordBtn\b/.test(script));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
