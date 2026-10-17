'use strict';
// Поиск браузера для смоука в настоящем Chrome (test/browser/helpers/find-browser.js):
// порядок поиска, явный CHROME_PATH, понятная ошибка при опечатке в нём, признак CI,
// флаги запуска (временный профиль, песочница). Без браузера и без запуска процессов.
// Сам смоук — npm run test:browser (docs/dev/testing.md).
// Запуск: node test/browser-path.test.js

const assert = require('assert');
const { BrowserPathError, candidatePaths, findBrowser, isCi } = require('./browser/helpers/find-browser');
const { launchFlags } = require('./browser/helpers/browser');

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

const existing = (...files) => (file) => files.includes(file);

console.log('Browser lookup tests\n');

test('CHROME_PATH выигрывает у любого найденного браузера', () => {
    const found = findBrowser({
        platform: 'linux',
        env: { CHROME_PATH: '/opt/my/chrome', PATH: '/usr/bin' },
        exists: existing('/opt/my/chrome', '/usr/bin/google-chrome'),
    });
    assert.deepStrictEqual(found, { path: '/opt/my/chrome', source: 'CHROME_PATH' });
});

test('CHROME_PATH на несуществующий файл — ошибка, а не тихий поиск другого браузера', () => {
    assert.throws(
        () => findBrowser({ platform: 'linux', env: { CHROME_PATH: '/opt/нет/chrome' }, exists: existing('/usr/bin/google-chrome') }),
        (err) => err instanceof BrowserPathError && /CHROME_PATH/.test(err.message) && /нет\/chrome/.test(err.message),
    );
});

test('пустой или пробельный CHROME_PATH считается незаданным', () => {
    const found = findBrowser({ platform: 'linux', env: { CHROME_PATH: '  ', PATH: '' }, exists: existing('/usr/bin/chromium') });
    assert.strictEqual(found.path, '/usr/bin/chromium');
    assert.strictEqual(found.source, 'поиск');
});

test('Windows: Chrome в Program Files раньше Edge; без переменных окружения — стандартные каталоги', () => {
    const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
    const edge = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
    assert.strictEqual(findBrowser({ platform: 'win32', env: {}, exists: existing(edge, chrome) }).path, chrome);
    assert.strictEqual(findBrowser({ platform: 'win32', env: {}, exists: existing(edge) }).path, edge);
});

test('Windows: Chrome из профиля пользователя (LOCALAPPDATA) находится', () => {
    const local = 'C:\\Users\\dev\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe';
    const found = findBrowser({ platform: 'win32', env: { LOCALAPPDATA: 'C:\\Users\\dev\\AppData\\Local' }, exists: existing(local) });
    assert.strictEqual(found.path, local);
});

test('Linux: google-chrome раньше chromium; запасной вариант — каталог из PATH', () => {
    assert.strictEqual(
        findBrowser({ platform: 'linux', env: { PATH: '/usr/bin' }, exists: existing('/usr/bin/chromium', '/usr/bin/google-chrome') }).path,
        '/usr/bin/google-chrome',
    );
    assert.strictEqual(
        findBrowser({ platform: 'linux', env: { PATH: '/home/dev/bin:/usr/bin' }, exists: existing('/home/dev/bin/chromium') }).path,
        '/home/dev/bin/chromium',
    );
});

test('macOS: Chrome в /Applications', () => {
    const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    assert.strictEqual(findBrowser({ platform: 'darwin', env: {}, exists: existing(chrome) }).path, chrome);
});

test('ничего не установлено — null (раннер сам решает: пропуск локально, сбой в CI)', () => {
    for (const platform of ['win32', 'darwin', 'linux']) {
        assert.strictEqual(findBrowser({ platform, env: { PATH: '/usr/bin' }, exists: () => false }), null, platform);
    }
});

test('список мест без повторов', () => {
    const list = candidatePaths({ platform: 'win32', env: { PROGRAMFILES: 'C:\\Program Files', 'PROGRAMFILES(X86)': 'C:\\Program Files (x86)' } });
    assert.strictEqual(new Set(list).size, list.length);
});

test('isCi: CI=true/1 — да; пусто, 0 и false — нет', () => {
    assert.strictEqual(isCi({ CI: 'true' }), true);
    assert.strictEqual(isCi({ CI: '1' }), true);
    assert.strictEqual(isCi({}), false);
    assert.strictEqual(isCi({ CI: '' }), false);
    assert.strictEqual(isCi({ CI: '0' }), false);
    assert.strictEqual(isCi({ CI: 'false' }), false);
});

test('флаги запуска: временный профиль, порт отладки выбирает браузер, headless по умолчанию', () => {
    const flags = launchFlags({ userDataDir: '/tmp/nyxo-profile', headed: false, env: {} });
    assert.ok(flags.includes('--user-data-dir=/tmp/nyxo-profile'));
    assert.ok(flags.includes('--remote-debugging-port=0'));
    assert.ok(flags.includes('--headless=new'));
    assert.ok(!flags.includes('--no-sandbox'), 'локально песочница Chrome включена');
    assert.ok(!flags.some(flag => flag.startsWith('--remote-allow-origins')), 'порт отладки не открывается для чужих origin');
});

test('флаги запуска: в CI песочница отключена, с окном — без headless', () => {
    const ci = launchFlags({ userDataDir: '/tmp/p', headed: false, env: { CI: 'true' } });
    assert.ok(ci.includes('--no-sandbox'));
    const headed = launchFlags({ userDataDir: '/tmp/p', headed: true, env: {} });
    assert.ok(!headed.some(flag => flag.startsWith('--headless')));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
