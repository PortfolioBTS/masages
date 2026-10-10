#!/usr/bin/env node
'use strict';
// Расставляет атрибуты integrity (sha384) у <script src> и <link rel="stylesheet">
// в public/index.html по текущим файлам public/ (логика — lib/client-sri.js).
//
// SRI в репозитории ПОКА НЕ ВКЛЮЧЁН: скрипт готов к волне 6 (разбиение файлов
// клиента), сейчас его запускать не нужно, а test/client-sri.test.js следит,
// чтобы атрибуты не появились случайно.
//
// Запуск: node scripts/update-sri.js            — записать актуальные атрибуты
//         node scripts/update-sri.js --check    — только проверить (код 1, если устарели)
//         node scripts/update-sri.js --remove   — убрать все integrity
// После правки index.html пересоберите манифест (хэш страницы входит в него).

const fs = require('fs');
const path = require('path');
const { applySri } = require('../lib/client-sri');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const INDEX = path.join(PUBLIC_DIR, 'index.html');

function readPublic(urlPath) {
    const file = path.join(PUBLIC_DIR, ...urlPath.split('/').filter(Boolean));
    return fs.existsSync(file) ? fs.readFileSync(file) : null;
}

function main(argv) {
    const check = argv.includes('--check');
    const remove = argv.includes('--remove');
    for (const arg of argv) {
        if (!['--check', '--remove'].includes(arg)) throw new Error(`неизвестный параметр ${arg}`);
    }
    if (check && remove) throw new Error('--check и --remove вместе не нужны');
    const html = fs.readFileSync(INDEX, 'utf8');
    const result = applySri(html, readPublic, { remove });
    const missingFiles = result.tags.filter((tag) => tag.status === 'no-file');
    if (missingFiles.length > 0) {
        throw new Error('в public/ нет файлов, на которые ссылается index.html: ' + missingFiles.map((tag) => tag.url).join(', '));
    }
    const bad = result.tags.filter((tag) => tag.status !== 'ok');
    if (check) {
        if (bad.length === 0) {
            console.log(`SRI актуален: ${result.tags.length} тегов`);
        } else {
            for (const tag of bad) console.error(`  ${tag.status === 'missing' ? 'нет integrity' : 'устарел integrity'}: ${tag.url}`);
            process.exitCode = 1;
        }
        return;
    }
    if (result.html === html) {
        console.log('index.html без изменений');
        return;
    }
    fs.writeFileSync(INDEX, result.html);
    console.log(remove ? 'integrity убраны из index.html' : `index.html обновлён: ${bad.length} из ${result.tags.length} тегов`);
}

try {
    main(process.argv.slice(2));
} catch (err) {
    console.error('Ошибка: ' + (err && err.message ? err.message : err));
    process.exitCode = 1;
}
