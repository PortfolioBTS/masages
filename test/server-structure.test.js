'use strict';
// Структура сервера после разбиения server.js на src/ (T6.1, roadmap R14).
//   * createServer(config) собирает сервер без базы и не открывает порт;
//   * слои Express и маршруты — в том же порядке, что были в server.js (список снят с версии до разбиения);
//   * фабрики берут из ctx только то, что создано выше по src/create-server.js (иначе при запросе
//     вместо функции окажется undefined);
//   * файлы src/** не длиннее 1200 строк, server.js — тонкая точка входа.
//
// Запуск: node test/server-structure.test.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Окружение — до загрузки модулей (lib/message-crypto читает ключ при загрузке).
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = crypto.randomBytes(32).toString('base64url');
process.env.MESSAGE_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
process.env.DATABASE_URL = 'postgresql://nobody:unused@127.0.0.1:1/none';
const uploadsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-structure-'));
process.env.UPLOADS_DIR = uploadsDir;

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

// Слои app._router.stack: «имя» для middleware (и путь, если он смонтирован не в корень),
// «методы путь [число обработчиков]» для маршрутов.
function describeStack(app) {
    return app._router.stack.map((layer) => {
        if (layer.route) return `${Object.keys(layer.route.methods).sort().join(',')} ${layer.route.path} [${layer.route.stack.length}]`;
        const root = String(layer.regexp) === '/^\\/?(?=\\/|$)/i';
        return `use ${layer.name}${root ? '' : ' ' + layer.regexp}`;
    });
}

// Слои и маршруты Express до разбиения (8ffdcbb), по порядку регистрации.
const EXPECTED_STACK = [
    'use query',
    'use expressInit',
    'use metricsMiddleware',
    'use onionMiddleware',
    'use <anonymous>',
    'use <anonymous>',
    'use hstsMiddleware',
    'use <anonymous>',
    'use cookieParser',
    'use swKillSwitch',
    'use serveStatic',
    'get /link.my [1]',
    'get /healthz [1]',
    'get /readyz [1]',
    'get /metrics [1]',
    'get /.well-known/security.txt [1]',
    'get /security.txt [1]',
    'get /client-manifest.json [1]',
    'use session',
    'use <anonymous>',
    'use middleware',
    'use jsonParser /^\\/api\\/keys\\/key-shares\\/?(?=\\/|$)/i',
    'use jsonParser /^\\/api\\/keys\\/pq-one-time-prekeys\\/?(?=\\/|$)/i',
    'use <anonymous>',
    'use jsonParser',
    'use <anonymous> /^\\/api\\/?(?=\\/|$)/i',
    'put /api/keys/identity [2]',
    'put /api/keys/signed-prekey [2]',
    'put /api/keys/pq-prekey [2]',
    'post /api/keys/one-time-prekeys [2]',
    'post /api/keys/pq-one-time-prekeys [2]',
    'delete /api/keys/pq-one-time-prekeys [2]',
    'get /api/keys/one-time-prekeys/count [2]',
    'get /api/keys/identities [2]',
    'get /api/keys/bundle/:targetUserId [2]',
    'delete /api/keys [2]',
    'get /api/kt/head [3]',
    'get /api/kt/roots [2]',
    'get /api/kt/proof [2]',
    'get /api/kt/self [2]',
    'get /api/chats/:chatId/participants [2]',
    'get /api/chats/:chatId/member-certs [2]',
    'post /api/chats/:chatId/member-certs [2]',
    'post /api/keys/key-shares [2]',
    'get /api/keys/key-shares/:chatId [2]',
    'post /api/keys/key-requests [2]',
    'get /api/keys/key-requests/:chatId [2]',
    'post /api/keys/key-requests/done [2]',
    'get /uploads/:filename [1]',
    'get /api/pow/challenge [1]',
    'post /api/register/anonymous [2]',
    'post /api/account/delete [1]',
    'post /api/logout [1]',
    'get /api/auth [1]',
    'post /api/user/privacy [1]',
    'get /api/user [1]',
    'post /api/user/lifetime [1]',
    'get /api/chats [1]',
    'get /api/messages/:chatId [1]',
    'post /api/chats/:chatId/read [1]',
    'post /api/messages [1]',
    'post /api/chats [1]',
    'get /api/chats/invite/:chatId [1]',
    'post /api/chats/:chatId/invite/rotate [1]',
    'post /api/chats/:chatId/invite/disable [1]',
    'post /api/chats/join/preview [3]',
    'post /api/chats/join [3]',
    'get /api/chats/:chatId/join-requests [1]',
    'get /api/join-requests/mine [1]',
    'post /api/join-requests/:id/approve [1]',
    'post /api/join-requests/:id/deny [1]',
    'delete /api/join-requests/:id [1]',
    'delete /api/chats/:chatId [1]',
    'put /api/messages/:messageId [1]',
    'delete /api/messages/:messageId [1]',
    'post /api/messages/file [2]',
    'post /api/reactions [1]',
    'delete /api/reactions/:messageId/:emoji [1]',
    'post /api/messages/:messageId/set-expiry [1]',
    'post /api/chats/:chatId/expiry [1]',
    'post /api/chats/:chatId/set-default-expiry [1]',
    'get /api/chats/:chatId/settings [1]',
    'post /api/chats/:chatId/prefs [1]',
    'use <anonymous> /^\\/api\\/?(?=\\/|$)/i',
    'use <anonymous>',
];

// ---------- сборка ----------

const quiet = (fn) => {
    const log = console.log, warn = console.warn;
    console.log = console.warn = () => {};
    try { return fn(); } finally { console.log = log; console.warn = warn; }
};
const { loadConfig } = require('../src/config');
const { createServer } = require('../src/create-server');
const built = quiet(() => createServer(loadConfig(ROOT)));
const { app, server, io, ctx } = built;

test('createServer собирает сервер без базы и не открывает порт; start() вызывается отдельно', () => {
    assert.deepStrictEqual(Object.keys(built).sort(), ['app', 'ctx', 'io', 'server', 'start']);
    assert.strictEqual(typeof built.start, 'function');
    assert.strictEqual(server.listening, false);
    assert.strictEqual(ctx.readiness.migrated, false, 'порт открывается только после миграций');
    assert.strictEqual(ctx.UPLOADS_DIR, uploadsDir);
    assert.strictEqual(ctx.ROOT_DIR, ROOT);
});

test('слои Express и маршруты — в прежнем порядке (до разбиения server.js)', () => {
    assert.deepStrictEqual(describeStack(app), EXPECTED_STACK);
});

test('socket.io: два middleware (сессия, авторизация) и один обработчик подключения', () => {
    const ns = io._nsps.get('/');
    assert.strictEqual(ns._fns.length, 2);
    assert.strictEqual(ns.listeners('connection').length, 1);
});

test('serverContext для lib/routes и lib/jobs — замороженный объект с прежним набором полей', () => {
    const sc = ctx.serverContext;
    assert.ok(Object.isFrozen(sc));
    assert.deepStrictEqual(Object.keys(sc).sort(), ['dbAll', 'dbGet', 'dbRun', 'env', 'io', 'isProduction', 'kt', 'logError', 'metrics', 'pool', 'readiness', 'withTransaction']);
});

// ---------- проводка ctx ----------

const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const listFiles = (dir) => fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? listFiles(`${dir}/${e.name}`) : [`${dir}/${e.name}`]));
const SRC_FILES = listFiles('src').filter((f) => f.endsWith('.js'));

// Имена из «{ a, b: c, d }»: ключи, без комментариев и пустых.
const namesOf = (list) => list.split(',').map((s) => s.trim().split(':')[0].trim()).filter(Boolean);

// Тело функции верхнего уровня модуля (закрывающая скобка — в начале строки).
function functionBody(text, name) {
    const start = text.search(new RegExp(`^function ${name}\\(`, 'm'));
    assert.ok(start >= 0, `нет функции ${name}`);
    const end = text.indexOf('\n}\n', start);
    return text.slice(start, end + 2);
}
const ctxNamesOf = (body) => {
    const m = /const \{([^}]*)\} = ctx;/.exec(body);
    return m ? namesOf(m[1]) : [];
};
const returnNamesOf = (body) => {
    const all = [...body.matchAll(/^ {4}return \{([^}]*)\};$/gm)];
    return all.length ? namesOf(all[all.length - 1][1]) : [];
};

// Порядок вызовов из src/create-server.js: { fn, file }.
function composeOrder(text) {
    const fileOf = new Map();
    for (const m of text.matchAll(/const \{([^}]*)\} = require\('\.\/([^']+)'\);/g)) {
        for (const name of namesOf(m[1])) fileOf.set(name, `src/${m[2]}.js`);
    }
    const calls = [];
    for (const m of text.matchAll(/^ {4}(?:Object\.assign\(ctx, (\w+)\([^)]*\)\);|(\w+)\(ctx\);|const \{ start \} = (\w+)\(ctx\);)$/gm)) {
        const fn = m[1] || m[2] || m[3];
        calls.push({ fn, file: fileOf.get(fn), keepsReturn: Boolean(m[1]) });
    }
    return calls;
}

test('фабрики берут из ctx только созданное выше (порядок src/create-server.js)', () => {
    const calls = composeOrder(read('src/create-server.js'));
    assert.ok(calls.length >= 25, `найдено вызовов: ${calls.length}`);
    const provided = new Set(returnNamesOf(functionBody(read('src/config.js'), 'loadConfig')).concat(['ROOT_DIR']));
    for (const { fn, file, keepsReturn } of calls) {
        assert.ok(file, `${fn}: нет require в create-server.js`);
        const body = functionBody(read(file), fn);
        for (const name of ctxNamesOf(body)) {
            assert.ok(provided.has(name), `${file}: ${fn} берёт ${name} из ctx, а он создаётся позже или нигде`);
        }
        if (keepsReturn) for (const name of returnNamesOf(body)) provided.add(name);
        // маршруты и парсеры тела регистрирует configureApp: к этому моменту ctx уже полный
        if (fn === 'configureApp') {
            for (const route of SRC_FILES.filter((f) => f.startsWith('src/http/routes/') && !f.endsWith('/index.js'))) {
                for (const name of ctxNamesOf(functionBody(read(route), 'register'))) {
                    assert.ok(provided.has(name), `${route}: register берёт ${name} из ctx, а он не создан к configureApp`);
                }
            }
        }
    }
});

test('самопроверка проводки: имя, которого нет выше, обнаруживается', () => {
    const body = 'function createX(ctx) {\n    const { pool, noSuchName } = ctx;\n    return { a, b };\n}\n';
    assert.deepStrictEqual(ctxNamesOf(body), ['pool', 'noSuchName']);
    assert.deepStrictEqual(returnNamesOf(body), ['a', 'b']);
    assert.deepStrictEqual(namesOf('a, b: rootDir,\n c'), ['a', 'b', 'c']);
});

// ---------- размер файлов ----------

test('файлы src/** не длиннее 1200 строк', () => {
    for (const file of SRC_FILES) {
        const lines = read(file).split('\n').length;
        assert.ok(lines <= 1200, `${file}: ${lines} строк`);
    }
});

test('server.js — тонкая точка входа: запуск только как программа (require.main === module)', () => {
    const text = read('server.js');
    assert.ok(text.split('\n').length <= 40, 'server.js вырос: логика должна быть в src/');
    assert.match(text, /require\.main === module/);
    assert.match(text, /createServer\(loadConfig\(__dirname\)\)\.start\(\)/);
    assert.match(text, /module\.exports = \{[^}]*createServer/);
});

// ---------- уборка ----------

io.close();
ctx.pool.end().catch(() => {});
fs.rmSync(uploadsDir, { recursive: true, force: true });

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
