'use strict';
// Исходники сервера для тестов-сканеров. Код сервера лежит в server.js (точка входа) и в src/**
// (разбиение server.js, T6.1): тесты, которые раньше читали server.js целиком, читают этот набор
// файлов. Порядок стабильный: server.js, затем src/** — внутри папки по алфавиту, поэтому
// src/db/** идёт раньше src/http/**, а те — раньше src/realtime/** и src/services/**.
// Тестом не является (раннер берёт только *.test.js).

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Пути относительно корня репозитория, через «/».
function serverSourceFiles(root = ROOT) {
    const files = ['server.js'];
    const walk = (dir) => {
        const abs = path.join(root, dir);
        if (!fs.existsSync(abs)) return;
        const entries = fs.readdirSync(abs, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        for (const entry of entries) {
            const rel = `${dir}/${entry.name}`;
            if (entry.isDirectory()) walk(rel);
            else if (entry.name.endsWith('.js')) files.push(rel);
        }
    };
    walk('src');
    return files;
}

// Весь код сервера одним текстом (файлы через перевод строки).
function readServerSource(root = ROOT) {
    return serverSourceFiles(root).map((file) => fs.readFileSync(path.join(root, file), 'utf8')).join('\n');
}

module.exports = { serverSourceFiles, readServerSource };
