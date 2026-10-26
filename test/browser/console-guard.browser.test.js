'use strict';
// Проверка самой проверки: страж консоли (helpers/page.js) должен ловить всё, на
// чём держится условие «консоль без ошибок и без нарушений CSP» остальных наборов.
// Без этого набора зелёные сценарии могли бы значить «страж ослеп».
// В страницу вносятся искусственные нарушения; каждое должно появиться в
// page.problems. В конце записи вычищаются, иначе withProfiles честно упал бы.

const assert = require('assert');
const { createBrowserSuite } = require('./helpers/suite');
const { waitUntil } = require('../e2e/helpers/scenarios');

const suite = createBrowserSuite('console-guard');

// [название, действие в странице, что должно появиться среди замечаний]
const CASES = [
    ['console.error', (page) => page.evaluate(() => { console.error('искусственная ошибка'); }), /console\.error: искусственная ошибка/],
    ['необработанное исключение', (page) => page.evaluate(() => { setTimeout(() => { throw new Error('искусственное исключение'); }, 0); }), /исключение страницы: .*искусственное исключение/],
    ['inline-скрипт (CSP script-src)', (page) => page.evaluate(() => { const s = document.createElement('script'); s.textContent = 'window.nyxoProbe = 1'; document.body.appendChild(s); }), /script-src/],
    ['inline-стиль (CSP style-src)', (page) => page.evaluate(() => { document.body.insertAdjacentHTML('beforeend', '<div style="color:red"></div>'); }), /style-src/],
    ['запрос на чужой адрес (CSP connect-src)', (page) => page.evaluate(() => fetch('https://example.invalid/x').catch(() => 'blocked')), /connect-src/],
    ['картинка с чужого адреса (CSP img-src)', (page) => page.evaluate(() => { const img = new Image(); img.src = 'https://example.invalid/a.png'; document.body.appendChild(img); }), /img-src/],
    ['404 на свой файл', (page) => page.evaluate(() => fetch('/no-such-file.js').then(res => res.status)), /404/],
    ['ошибка в воркере', (page) => page.evaluate(() => { new Worker('/pow-worker.js').postMessage({ nonsense: true }); }), /pow-worker\.js/],
];

suite.test('страж консоли ловит ошибку, исключение, нарушения CSP, 404 и ошибку воркера', async () => {
    await suite.withProfiles(['alice'], async ([alice]) => {
        const page = await alice.newPage();
        await page.goto(`${suite.baseUrl}/`);
        await page.waitForSelector('#anon-start-btn');
        assert.deepStrictEqual(page.problems, [], 'чистая страница входа уже даёт замечания консоли');
        assert.deepStrictEqual(page.warnings, [], 'чистая страница входа уже даёт предупреждения консоли');

        for (const [name, run, expected] of CASES) {
            const before = page.problems.length;
            await run(page);
            await waitUntil(() => page.problems.slice(before).some(text => expected.test(text)), { timeoutMs: 8000, what: `страж не поймал: ${name}` });
        }

        assert.throws(() => page.assertConsoleClean('контроль'), /в консоли браузера есть ошибки/);
        page.problems.splice(0);
        page.assertConsoleClean('после вычистки');
    });
});
