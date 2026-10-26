'use strict';
// Порядок регистрации маршрутов приложения. Вызывается из configureApp (src/http/app.js) после
// лимитера /api. Порядок — ТОТ ЖЕ, что был в server.js: Express выбирает первый подходящий маршрут,
// а у части путей совпадающие шаблоны (/api/chats/invite/:chatId и /api/chats/:chatId/..., /api/chats/join
// и т.п.), поэтому модули нарезаны по непрерывным участкам прежнего порядка, а не по темам.
// Менять порядок можно только вместе со сверкой списка маршрутов (test/server-structure.test.js).
//
// Каждый модуль — register(app, ctx); ctx собирает src/create-server.js.

// Точки регистрации маршрутов вне server.js (lib/routes/): обычные маршруты API.
const { registerApiRoutes } = require('../../../lib/routes');
const e2ee = require('./e2ee');
const fileDownload = require('./file-download');
const pow = require('./pow');
const auth = require('./auth');
const account = require('./account');
const chats = require('./chats');
const invites = require('./invites');
const joinRequests = require('./join-requests');
const leave = require('./leave');
const messageEdit = require('./message-edit');
const fileUpload = require('./file-upload');
const reactions = require('./reactions');
const expiry = require('./expiry');

function registerRoutes(app, ctx) {
    const { serverContext } = ctx;

    e2ee.register(app, ctx);
    registerApiRoutes(app, serverContext);
    fileDownload.register(app, ctx);
    pow.register(app, ctx);
    auth.register(app, ctx);
    account.register(app, ctx);
    chats.register(app, ctx);
    invites.register(app, ctx);
    joinRequests.register(app, ctx);
    leave.register(app, ctx);
    messageEdit.register(app, ctx);
    fileUpload.register(app, ctx);
    reactions.register(app, ctx);
    expiry.register(app, ctx);
}

module.exports = { registerRoutes };
