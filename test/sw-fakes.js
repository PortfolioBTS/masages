'use strict';
// Подделки для тестов service worker (public/lib/sw-core.js, public/sw.js) в Node:
// CacheStorage в памяти и локальный HTTP-сайт, который отдаёт синтетический public/
// вместе с манифестом клиента. Файл не тест (раннер берёт только *.test.js).

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const manifestLib = require('../lib/client-manifest');

const FAKE_BASE = 'http://sw.test';

// Cache, совместимый по тем методам, которые зовёт sw-core. Ключ — путь без query,
// как у настоящего Cache при ignoreSearch (SW всегда ищет по пути).
class FakeCache {
    constructor() {
        this.entries = new Map();
    }

    keyOf(request) {
        return new URL(typeof request === 'string' ? request : request.url, FAKE_BASE).pathname;
    }

    async put(request, response) {
        if (response.status === 206) throw new TypeError('Cache.put: частичный ответ нельзя сохранить');
        const body = new Uint8Array(await response.arrayBuffer());
        this.entries.set(this.keyOf(request), { status: response.status, headers: [...response.headers], body });
    }

    async match(request) {
        const entry = this.entries.get(this.keyOf(request));
        return entry ? new Response(entry.body, { status: entry.status, headers: entry.headers }) : undefined;
    }

    async keys() {
        return [...this.entries.keys()].map((pathname) => new Request(FAKE_BASE + pathname));
    }

    async delete(request) {
        return this.entries.delete(this.keyOf(request));
    }
}

class FakeCacheStorage {
    constructor() {
        this.caches = new Map();
        // Тест может подставить сбой на открытие кэша по имени (имитация сбоя хранилища).
        this.failOpen = null;
    }

    async open(name) {
        if (this.failOpen && this.failOpen(name)) throw new Error('хранилище недоступно');
        if (!this.caches.has(name)) this.caches.set(name, new FakeCache());
        return this.caches.get(name);
    }

    async has(name) {
        return this.caches.has(name);
    }

    async delete(name) {
        return this.caches.delete(name);
    }

    async keys() {
        return [...this.caches.keys()];
    }
}

// Сайт: каталог public/ во временной папке + HTTP-сервер. Манифест строится из каталога на каждый
// запрос, поэтому правка файла на диске = «выкат новой версии».
async function startSite(files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-sw-'));
    const site = {
        dir,
        hits: [],            // пути запросов по порядку
        overrides: new Map(), // путь -> Buffer | { status, headers, body }: подмена ответа мимо диска
        write(rel, content) {
            const target = path.join(dir, ...rel.split('/'));
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, content);
        },
        remove(rel) {
            fs.rmSync(path.join(dir, ...rel.split('/')), { force: true });
        },
        manifestText: () => manifestLib.buildManifestText(dir),
        manifestSha256: () => manifestLib.manifestSha256(manifestLib.buildManifestText(dir)),
        hitsFor: (pathname) => site.hits.filter((hit) => hit === pathname).length,
    };
    for (const [rel, content] of Object.entries(files)) site.write(rel, content);

    const server = http.createServer((req, res) => {
        const pathname = new URL(req.url, 'http://x').pathname;
        site.hits.push(pathname);
        const forced = site.overrides.get(pathname);
        if (forced) {
            const spec = Buffer.isBuffer(forced) ? { status: 200, headers: {}, body: forced } : forced;
            res.writeHead(spec.status, spec.headers);
            res.end(spec.body);
            return;
        }
        if (pathname === '/client-manifest.json') {
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(site.manifestText());
            return;
        }
        const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
        const file = path.join(dir, ...rel.split('/'));
        if (!file.startsWith(dir) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('нет такого файла');
            return;
        }
        res.writeHead(200, { 'Content-Type': pathname.endsWith('.html') || pathname === '/' ? 'text/html; charset=utf-8' : 'application/javascript' });
        res.end(fs.readFileSync(file));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    site.origin = `http://127.0.0.1:${server.address().port}`;
    site.close = async () => {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        fs.rmSync(dir, { recursive: true, force: true });
    };
    return site;
}

// Минимальный, но настоящий набор файлов клиента.
function sampleFiles(overrides = {}) {
    return {
        'index.html': '<!DOCTYPE html><title>Nyxo</title><script src="app.js"></script>\n',
        'app.js': 'console.log("app v1");\n',
        'style.css': 'body{color:#fff}\n',
        'lib/helper.js': 'window.helper = 1;\n',
        'vendor/socket.io.min.js': '/* vendor */\n',
        ...overrides,
    };
}

module.exports = { FakeCache, FakeCacheStorage, startSite, sampleFiles };
