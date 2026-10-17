'use strict';
// Сборка сервера. createServer(config) создаёт всё, что раньше создавалось при загрузке server.js,
// в порядке зависимостей, но НЕ открывает порт и не трогает процесс: это делает start()
// (src/lifecycle.js), и только когда server.js запущен как программа.
//
// ctx — плоский контекст: каждая фабрика берёт из него нужное (const { pool, io } = ctx) и возвращает
// то, что создала; результат добавляется в ctx. Имена в ctx — те же, что были у переменных верхнего
// уровня server.js. Порядок вызовов ниже важен: фабрика может брать из ctx только то, что создано выше
// (это проверяет test/server-structure.test.js).

const { createBase, createKtContext } = require('./context');
const { createUploads } = require('./services/uploads');
const { createApp } = require('./http/create-app');
const { createRealIp } = require('./http/middleware/real-ip');
const { createOrigin } = require('./http/middleware/origin');
const { createHttpServer } = require('./http/server');
const { createIo } = require('./realtime/io');
const { createEvents } = require('./realtime/events');
const { createPool } = require('./db/pool');
const { createTransactions } = require('./db/transactions');
const { createExpiry } = require('./services/expiry');
const { createSchema } = require('./db/schema');
const { createMigrations } = require('./db/migrate');
const { createRateLimits } = require('./http/middleware/rate-limits');
const { createSession } = require('./http/middleware/session');
const { createActivity } = require('./services/activity');
const { createChats } = require('./services/chats');
const { createMessages } = require('./services/messages');
const { createPow } = require('./services/pow');
const { createRooms } = require('./services/rooms');
const { createBot } = require('./services/bot');
const { createAccounts } = require('./services/accounts');
const { createUploadMiddleware } = require('./http/middleware/upload');
const { createJobs } = require('./jobs/index');
const { registerSocketHandlers } = require('./realtime/socket-handlers');
const { configureApp } = require('./http/app');
const { createLifecycle } = require('./lifecycle');

function createServer(config) {
    const ctx = { ...config };

    Object.assign(ctx, createBase());
    Object.assign(ctx, createUploads(ctx));
    Object.assign(ctx, createApp());
    Object.assign(ctx, createRealIp());
    Object.assign(ctx, createOrigin());
    Object.assign(ctx, createHttpServer(ctx));
    Object.assign(ctx, createIo(ctx));
    Object.assign(ctx, createEvents(ctx));
    Object.assign(ctx, createPool(ctx));
    Object.assign(ctx, createTransactions(ctx));
    Object.assign(ctx, createExpiry(ctx));
    Object.assign(ctx, createSchema(ctx));
    Object.assign(ctx, createMigrations(ctx));
    Object.assign(ctx, createRateLimits(ctx));
    Object.assign(ctx, createSession(ctx));
    Object.assign(ctx, createActivity(ctx));
    Object.assign(ctx, createChats(ctx));
    Object.assign(ctx, createMessages(ctx));
    Object.assign(ctx, createPow(ctx));
    Object.assign(ctx, createRooms(ctx));
    Object.assign(ctx, createBot(ctx));
    Object.assign(ctx, createAccounts(ctx));
    Object.assign(ctx, createUploadMiddleware(ctx));
    Object.assign(ctx, createKtContext(ctx));
    Object.assign(ctx, createJobs(ctx));
    registerSocketHandlers(ctx);
    configureApp(ctx);
    const { start } = createLifecycle(ctx);

    return { app: ctx.app, server: ctx.server, io: ctx.io, ctx, start };
}

module.exports = { createServer };
