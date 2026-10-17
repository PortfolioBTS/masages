'use strict';
// Поиск Chrome/Chromium для смоука в настоящем браузере.
//
// Порядок: переменная CHROME_PATH (явный выбор человека или CI), затем типичные
// места установки на Windows, macOS и Linux, затем имена в PATH (Linux).
// Edge на Chromium тоже годится — CDP у него тот же, — но стоит последним:
// сначала берётся то, что и есть «настоящий Chrome». Firefox и Safari не
// подходят: у них нет Chrome DevTools Protocol.
//
// Всё, что трогает систему (существование файла, PATH, переменные), передаётся
// параметрами — тест test/browser-path.test.js проверяет порядок и ошибки без
// установленного браузера.

const fs = require('fs');
const path = require('path');

// Переменная CHROME_PATH задана, но файла нет: тихо искать дальше нельзя —
// человек думает, что тест идёт в одном браузере, а идёт в другом.
class BrowserPathError extends Error {}

function windowsCandidates(env) {
    // Переменные окружения могут быть не заданы (урезанное окружение CI-агента) —
    // тогда стандартные каталоги.
    const roots = [...new Set([env.PROGRAMFILES, env['PROGRAMFILES(X86)'], env.LOCALAPPDATA, 'C:\\Program Files', 'C:\\Program Files (x86)'].filter(Boolean))];
    const chrome = roots.map(root => path.win32.join(root, 'Google', 'Chrome', 'Application', 'chrome.exe'));
    const chromium = roots.map(root => path.win32.join(root, 'Chromium', 'Application', 'chrome.exe'));
    const edge = roots.map(root => path.win32.join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe'));
    return [...chrome, ...chromium, ...edge];
}

function macCandidates() {
    return [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    ];
}

const LINUX_NAMES = ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser', 'microsoft-edge-stable', 'microsoft-edge'];
const LINUX_DIRS = ['/usr/bin', '/usr/local/bin', '/snap/bin', '/opt/google/chrome'];

function linuxCandidates(env) {
    const fixed = LINUX_DIRS.flatMap(dir => LINUX_NAMES.map(name => path.posix.join(dir, name)));
    const fromPath = String(env.PATH || '').split(':').filter(Boolean)
        .flatMap(dir => LINUX_NAMES.map(name => path.posix.join(dir, name)));
    return [...fixed, ...fromPath];
}

// Список мест для поиска по порядку, без повторов.
function candidatePaths({ platform = process.platform, env = process.env } = {}) {
    const list = platform === 'win32' ? windowsCandidates(env) : platform === 'darwin' ? macCandidates() : linuxCandidates(env);
    return [...new Set(list)];
}

// { path, source } или null. source: 'CHROME_PATH' | 'поиск'.
function findBrowser({ platform = process.platform, env = process.env, exists = fs.existsSync } = {}) {
    const explicit = String(env.CHROME_PATH || '').trim();
    if (explicit) {
        if (!exists(explicit)) throw new BrowserPathError(`CHROME_PATH указывает на несуществующий файл: ${explicit}`);
        return { path: explicit, source: 'CHROME_PATH' };
    }
    for (const candidate of candidatePaths({ platform, env })) {
        if (exists(candidate)) return { path: candidate, source: 'поиск' };
    }
    return null;
}

// В CI (переменная CI, GitHub Actions задаёт CI=true) отсутствие браузера — сбой
// окружения, который нельзя пропустить молча; локально набор просто пропускается.
function isCi(env = process.env) {
    const value = String(env.CI || '').trim().toLowerCase();
    return value !== '' && value !== '0' && value !== 'false';
}

module.exports = { BrowserPathError, candidatePaths, findBrowser, isCi };
