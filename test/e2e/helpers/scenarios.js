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
// остановка серверов, удаление базы.
//
// Падение набора не должно оставаться без следов. Если упал тест, хук или
// процесс (необработанное исключение, в том числе из таймера после конца
// теста), в test/e2e/.logs/ сохраняются логи всех серверов набора и файл
// «…-suite.log» с причинами (helpers/failure-log.js). Уборка (остановка
// серверов, удаление базы) не бросает исключений: её сбой при зелёных тестах
// — предупреждение в выводе и в suite.log, а не «fail 1» без объяснений.

const { before, after, afterEach } = require('node:test');
const { createDatabase, dropDatabase, connectPool } = require('./pg');
const { ServerHandle, settleBeforeExit } = require('./server');
const { createTimeHelpers } = require('./time');
const { loadLegacyFixture, legacyServerSecrets } = require('./legacy');
const { randomSecrets } = require('./env');
const { SuiteDiagnostics } = require('./failure-log');

const HOOK_TIMEOUT_MS = 120000;

// Наборы этого процесса, у которых after-хук ещё не закончил уборку: на них
// смотрят обработчики process (installProcessGuards).
const liveSuites = new Set();
let guardsInstalled = false;

function saveSuite(suite) {
    try {
        suite.diagnostics.save({ dbName: suite.dbName, servers: suite.servers });
    } catch (err) {
        // Диагностика не должна ронять процесс сама.
        console.error(`# не удалось сохранить логи набора ${suite.name}: ${err.message}`);
    }
}

// Обработчики уровня процесса, одни на файл-набор (процесс). Runner сам
// ловит необработанные исключения и ошибки промисов и записывает их как
// падение файла — но не знает про серверы набора. Эти обработчики ничего не
// гасят: они только сохраняют причину и логи, пока процесс жив.
function installProcessGuards() {
    if (guardsInstalled) return;
    guardsInstalled = true;
    const fatal = (kind) => (reason) => {
        for (const suite of liveSuites) {
            suite.diagnostics.fail(kind, reason);
            saveSuite(suite);   // сразу: процесс могут добить раньше after-хука
        }
    };
    process.on('uncaughtException', fatal('uncaughtException'));
    process.on('unhandledRejection', fatal('unhandledRejection'));
    // Процесс завершается, а after-хук набора не закончился (тайм-аут хука,
    // принудительный выход, process.exit из чужого кода): файловый ввод-вывод
    // в 'exit' синхронный, успеваем.
    process.on('exit', (code) => {
        for (const suite of liveSuites) {
            if (code === 0 && !suite.diagnostics.needsSave) continue;
            if (code !== 0) suite.diagnostics.fail('exit', `процесс набора завершился с кодом ${code}, не дойдя до конца after-хука`);
            saveSuite(suite);
        }
    });
}

// options: env — окружение всех серверов набора; legacy — загрузить
// легаси-фикстуру (и взять её секреты); startServer: false — сервер набор
// запускает сам (suite.startServer()).
function createSuite(name, { env = {}, legacy = false, startServer: autoStart = true } = {}) {
    const diagnostics = new SuiteDiagnostics(name);
    let ready = false;   // before-хук дошёл до конца
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
        diagnostics,       // причины сбоев набора (helpers/failure-log.js)
        get failed() { return diagnostics.failed; },
    };
    liveSuites.add(suite);
    installProcessGuards();

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
            ready = true;
        } catch (err) {
            diagnostics.fail('before: подготовка набора (база, фикстура, сервер)', err);
            throw err;
        }
    }, { timeout: HOOK_TIMEOUT_MS });

    afterEach((t) => {
        if (!t.passed) diagnostics.fail(`тест «${t.name}»`, t.error);
    });

    after(async () => {
        // before мог не дойти до конца без своего исключения: тайм-аут хука.
        if (!ready && !diagnostics.failed) {
            diagnostics.fail('before', 'хук before не завершился успешно (тайм-аут хука или ошибка до его выполнения)');
        }
        // Каждый шаг уборки — отдельно и без исключения наружу: остановка
        // сервера не должна мешать удалению базы, а сбой удаления — менять
        // результат набора.
        const step = async (what, fn) => {
            try {
                await fn();
            } catch (err) {
                diagnostics.warn(what, err);
            }
        };
        for (const server of suite.servers) await step(`остановка сервера ${server.name}`, () => server.stop());
        await step('тишина перед выходом процесса', () => settleBeforeExit());
        // Логи — до уборки: после остановки в них уже строка о завершении.
        if (diagnostics.needsSave) saveSuite(suite);
        for (const server of suite.servers) await step(`уборка сервера ${server.name}`, () => server.dispose());
        if (suite.db) await step('закрытие пула теста', () => suite.db.end());
        if (suite.dbName) await step(`удаление базы ${suite.dbName}`, () => dropDatabase(suite.dbName));
        // Ещё раз: к причинам могли добавиться сбои уборки (метка файлов та же).
        if (diagnostics.needsSave) saveSuite(suite);
        // Хук последний: после него runner завершает процесс (см. settleBeforeExit в server.js).
        await step('тишина перед выходом процесса', () => settleBeforeExit());
        liveSuites.delete(suite);
    }, { timeout: HOOK_TIMEOUT_MS });

    return suite;
}

// Ожидание условия, которое не сообщает о себе событием (файл удалён с
// диска, строка исчезла из базы): проверка раз в intervalMs до timeoutMs.
// Не «подождать N мс на всякий случай» — выход сразу, как только условие
// выполнено.
async function waitUntil(check, { timeoutMs = 5000, intervalMs = 25, what = 'условие' } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = await check();
        if (value) return value;
        if (Date.now() > deadline) throw new Error(`не дождались за ${timeoutMs} мс: ${what}`);
        await new Promise(resolve => setTimeout(resolve, intervalMs));
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

module.exports = { createSuite, roomWithMember, waitUntil, HOOK_TIMEOUT_MS };
