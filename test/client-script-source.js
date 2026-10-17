'use strict';
// Исходник браузерного скрипта приложения для тестов, которые читают клиентский код как текст.
//
// Раньше это был один файл public/script.js. В T6.2 (R14) он разбит на классические скрипты
// public/js/NN-имя.js: общая глобальная область, порядок подключения — порядок тегов
// <script src="js/..."> в public/index.html. Здесь этот порядок и берётся (список файлов
// нигде не дублируется: новый файл достаточно подключить в index.html).
//
// readClientScript() возвращает ровно тот текст, который был в script.js: у каждого файла
// отрезается заголовок (комментарии до первой пустой строки — «что здесь и откуда вынесено»),
// остальное склеивается через пустую строку — в том месте, где в исходнике стояла граница.
// Поэтому поиск функций, констант и запрещённых выражений ведёт себя как раньше.

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Адреса скриптов приложения (['js/01-state.js', ...]) в порядке подключения.
function clientScriptFiles(publicDir = PUBLIC_DIR) {
    const html = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');
    return [...html.matchAll(/<script\s+src="(js\/[^"]+)"><\/script>/g)].map((m) => m[1]);
}

// Тело файла без заголовка: заголовок кончается первой пустой строкой.
function stripHeader(text) {
    const cut = text.indexOf('\n\n');
    return cut < 0 ? text : text.slice(cut + 2);
}

function readClientScript(publicDir = PUBLIC_DIR) {
    const files = clientScriptFiles(publicDir);
    if (files.length === 0) throw new Error('в public/index.html нет тегов <script src="js/...">');
    return files
        .map((file) => stripHeader(fs.readFileSync(path.join(publicDir, ...file.split('/')), 'utf8')))
        .join('\n');
}

module.exports = { PUBLIC_DIR, clientScriptFiles, stripHeader, readClientScript };
