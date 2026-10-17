'use strict';
// Каркас файла-набора смоука в настоящем браузере.
//
//     const { createBrowserSuite } = require('./helpers/suite');
//     const suite = createBrowserSuite('group');
//     suite.test('…', async () => {
//         await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
//             const page = await alice.newPage();
//             await page.goto(suite.baseUrl + '/');
//             …
//         });
//     });
//
// Сервер и база — те же, что у сквозных тестов (test/e2e/helpers/scenarios.js:
// своя база nyxo_e2e_*, настоящий server.js на свободном порту). Браузер — по
// CHROME_PATH или в типичных местах (helpers/find-browser.js).
//
// Адрес — http://smoke.localhost:<порт>, а не 127.0.0.1: на 127.0.0.1 и
// localhost service worker сознательно выключен (режим разработки, см.
// public/lib/sw-client.js), а на поддомене *.localhost работает как в боевом
// режиме. Chrome сам считает *.localhost петлёвым адресом и безопасным
// контекстом (WebCrypto, куки, SW), настраивать hosts не нужно.
//
// Нет браузера: локально — наборы пропускаются с понятным сообщением, в CI
// (переменная CI) — падают: пропущенный смоук в CI был бы незаметной дырой.
//
// withProfiles запускает по отдельному процессу браузера на имя (отдельный
// временный профиль: свои куки, localStorage, IndexedDB — «два устройства»),
// после теста проверяет консоль всех вкладок и закрывает браузеры. При сбое
// сохраняет снимки вкладок в test/browser/.screens.

const { test } = require('node:test');
const { createSuite } = require('../../e2e/helpers/scenarios');
const { BrowserProfile } = require('./browser');
const { findBrowser, isCi } = require('./find-browser');

const HOST = 'smoke.localhost';

function slug(text) {
    return String(text).toLowerCase().replace(/[^a-zа-яё0-9]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}

function lookup() {
    try {
        const found = findBrowser();
        if (found) return { found };
        return { problem: 'Chrome/Chromium не найден: установите Chrome или задайте путь в CHROME_PATH' };
    } catch (err) {
        return { problem: err.message };
    }
}

function createBrowserSuite(name, options = {}) {
    const { found, problem } = lookup();
    const headed = Boolean(process.env.NYXO_BROWSER_HEADED);
    // Без браузера база и сервер не нужны: набор не требует ни Postgres, ни портов.
    const suite = problem ? { name } : createSuite(name, options);
    suite.browser = found || null;
    suite.currentTest = '';

    Object.defineProperty(suite, 'baseUrl', {
        get() { return `http://${HOST}:${suite.server.port}`; },
    });

    suite.test = (title, fn) => {
        if (problem) {
            if (isCi()) return test(title, () => { throw new Error(`${problem} (в CI браузер обязателен)`); });
            return test(title, { skip: problem }, () => {});
        }
        return test(title, async (t) => {
            suite.currentTest = title;
            await fn(t);
        });
    };

    // Профили браузера на время fn; fn получает массив профилей в порядке names.
    suite.withProfiles = async (names, fn) => {
        const profiles = [];
        try {
            for (const profileName of names) {
                profiles.push(await BrowserProfile.launch({ name: profileName, executable: found.path, headed }));
            }
            const result = await fn(profiles);
            for (const profile of profiles) {
                for (const page of profile.pages) page.assertConsoleClean(`${suite.currentTest}, профиль ${profile.name}`);
                if (profile.workerProblems.length > 0) {
                    throw new Error(`в консоли воркеров (${profile.name}) есть ошибки:\n  ${profile.workerProblems.join('\n  ')}`);
                }
            }
            return result;
        } catch (err) {
            // Снимок на момент сбоя: по нему видно, что человек увидел бы в окне.
            for (const profile of profiles) {
                for (const [index, page] of profile.pages.entries()) {
                    await page.screenshot(`FAIL-${name}-${slug(suite.currentTest)}-${profile.name}-${index + 1}`).catch(() => {});
                }
            }
            throw err;
        } finally {
            for (const profile of profiles) await profile.close().catch((err) => console.error(`# профиль ${profile.name} закрыт с ошибкой: ${err.message}`));
        }
    };

    // Информация для отчёта: какой браузер и откуда взят.
    suite.describeBrowser = async () => {
        if (!found) return null;
        const profile = await BrowserProfile.launch({ name: 'version', executable: found.path, headed });
        try {
            const { product } = await profile.version();
            return { ...found, product };
        } finally {
            await profile.close();
        }
    };

    return suite;
}

module.exports = { createBrowserSuite, HOST };
