'use strict';
// Каркас файла-набора и общие сценарии.
//
//     const { test } = require('node:test');
//     const { createSuite } = require('./helpers/scenarios');
//     const suite = createSuite('rooms');               // хуки before/after — здесь
//     test('...', async () => {
//         const a = suite.client();                       // новый «браузер»
//         await a.registerAnon();
//     });
//
// createSuite регистрирует хуки node:test: before — своя база
// (nyxo_e2e_<время>_<rand>), по желанию легаси-фикстура, сервер; after —
// остановка серверов, удаление базы. Если хоть один тест набора упал, логи
// всех его серверов сохраняются в test/e2e/.logs/.

const fs = require('fs');
const path = require('path');
const { before, after, afterEach } = require('node:test');
const { createDatabase, dropDatabase, connectPool } = require('./pg');
const { ServerHandle } = require('./server');
const { createTimeHelpers } = require('./time');
const { loadLegacyFixture, legacyServerSecrets } = require('./legacy');
const { randomSecrets, LOGS_DIR } = require('./env');

const HOOK_TIMEOUT_MS = 120000;

// options: env — окружение всех серверов набора; legacy — загрузить
// легаси-фикстуру (и взять её секреты); startServer: false — сервер набор
// запускает сам (suite.startServer()).
function createSuite(name, { env = {}, legacy = false, startServer: autoStart = true } = {}) {
    const suite = {
        name,
        dbName: null,
        databaseUrl: null,
        db: null,          // пул к базе набора: прямые проверки и перемотка
        time: null,        // helpers/time.js
        legacy: null,      // метаданные фикстуры (legacy-2.0.0.json)
        server: null,      // первый сервер набора
        servers: [],
        secrets: legacy ? legacyServerSecrets() : randomSecrets(),
        failed: false,
    };

    // Ещё сервер на ту же базу (реплика) или первый, если startServer: false.
    // Секреты общие для всех серверов набора: куки и шифрование сообщений
    // должны сходиться между репликами.
    suite.newServer = ({ env: extra = {}, name: serverName } = {}) => {
        const server = new ServerHandle({
            databaseUrl: suite.databaseUrl,
            env: { ...env, ...extra },
            secrets: suite.secrets,
            name: serverName || `${name}-${suite.servers.length + 1}`,
        });
        suite.servers.push(server);
        return server;
    };
    suite.startServer = async (opts) => {
        const server = await suite.newServer(opts).start();
        if (!suite.server) suite.server = server;
        return server;
    };
    suite.client = (opts) => suite.server.client(opts);
    suite.query = (text, params) => suite.db.query(text, params);

    before(async () => {
        try {
            const created = await createDatabase();
            suite.dbName = created.name;
            suite.databaseUrl = created.url;
            suite.db = connectPool(created.url);
            suite.time = createTimeHelpers(suite.db);
            if (legacy) suite.legacy = await loadLegacyFixture(created.url);
            if (autoStart) await suite.startServer();
        } catch (err) {
            suite.failed = true;
            throw err;
        }
    }, { timeout: HOOK_TIMEOUT_MS });

    afterEach((t) => {
        if (!t.passed) suite.failed = true;
    });

    after(async () => {
        for (const server of suite.servers) await server.stop().catch(() => {});
        if (suite.failed) saveLogs(suite);
        for (const server of suite.servers) await server.dispose().catch(() => {});
        if (suite.db) await suite.db.end().catch(() => {});
        if (suite.dbName) await dropDatabase(suite.dbName);
    }, { timeout: HOOK_TIMEOUT_MS });

    return suite;
}

function saveLogs(suite) {
    fs.mkdirSync(LOGS_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    for (const server of suite.servers) {
        const file = path.join(LOGS_DIR, `${stamp}-${suite.name}-${server.name}.log`);
        fs.writeFileSync(file, `${server.logs.text()}\n`);
        console.log(`# лог сервера ${server.name}: ${path.relative(process.cwd(), file)}`);
    }
}

// ---- Общие сценарии ----

// Комната owner, в которую member вошёл по коду через заявку и одобрение:
// { roomId, code, ownerChat, memberChat, requestId }.
async function roomWithMember(owner, member, { name = 'Комната' } = {}) {
    const ownerChat = await owner.createRoom(name);
    const { code } = await owner.invite(ownerChat.id);
    const pending = await member.join(code);
    if (!pending.pending) throw new Error(`ожидалась заявка, а пришло ${JSON.stringify(pending)}`);
    await owner.approve(pending.requestId);
    const memberChat = (await member.chats()).find(c => c.room_id === ownerChat.room_id);
    if (!memberChat) throw new Error('после одобрения у участника нет чата комнаты');
    return { roomId: ownerChat.room_id, code, ownerChat, memberChat, requestId: pending.requestId };
}

module.exports = { createSuite, roomWithMember, HOOK_TIMEOUT_MS };
