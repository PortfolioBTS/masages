'use strict';
// Общая часть тестов, которым нужен «весь CSS клиента» как текст. Стили лежат в
// нескольких файлах public/css/*.css (раньше — один public/style.css), а каскад
// задаёт порядок <link rel="stylesheet"> в index.html, поэтому файлы берутся
// в нём же и в том же порядке: тест видит ровно то, что видит браузер.

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Адреса локальных таблиц стилей из index.html (без начального «/») в порядке подключения.
function cssFiles() {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
    return [...html.matchAll(/<link\b[^>]*\brel="stylesheet"[^>]*>/g)]
        .map((match) => /\bhref="([^"]+)"/.exec(match[0])[1])
        .filter((href) => !/^([a-z][a-z0-9+.-]*:|\/\/)/i.test(href));
}

// Склейка всех таблиц стилей клиента в порядке подключения.
function readClientCss() {
    return cssFiles().map((href) => fs.readFileSync(path.join(PUBLIC_DIR, ...href.split('/')), 'utf8')).join('');
}

module.exports = { cssFiles, readClientCss };
