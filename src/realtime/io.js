'use strict';
// Socket.io: сам сервер (проверка Origin в allowRequest), счётчики одновременных сокетов,
// IP клиента сокета, ключи комнат и подписка/отписка всех сокетов пользователя на чат.
// Обработчики подключения — в realtime/socket-handlers.js, события — в realtime/events.js.
// Вынесено из server.js.

const { Server } = require('socket.io');
const { createCounter } = require('../../lib/security-utils');
const { getPrivacyHeaders } = require('../../lib/privacy');

// Лимиты одновременных сокетов: на аккаунт — всегда, на IP — только для
// clearnet (у всех onion-клиентов один IP — контейнер tor).
const MAX_SOCKETS_PER_USER = 10;
const MAX_SOCKETS_PER_IP = 20;

function getSocketRoomKey(chatId, roomId) {
    return roomId ? `room:${roomId}` : `chat:${chatId}`;
}

function createIo(ctx) {
    const { resolveRealIp, isTrustedOrigin, server } = ctx;

    // Cross-Site WebSocket Hijacking: сессионная кука уходит и в рукопожатии,
    // которое открыла ЧУЖАЯ страница (CORS на WebSocket не действует), — и
    // любой сайт, открытый у залогиненного пользователя, мог подключиться к
    // сокету от его имени и читать входящие сообщения в реальном времени.
    // Рукопожатие (и polling, и websocket) пускаем только со своего источника.
    const io = new Server(server, {
        // Клиент socket.io лежит в public/vendor/ и входит в манифест клиента
        // (lib/client-manifest.js): его хэш сверяется с релизом, как у любого
        // другого файла. Раньше сервер сам отдавал /socket.io/socket.io.js из
        // node_modules — мимо статики, и в манифест этот файл не попал бы.
        serveClient: false,
        allowRequest: (req, callback) => {
            if (isTrustedOrigin(req.headers)) return callback(null, true);
            callback('Origin not allowed', false);
        },
    });

    // Ответы engine.io (/socket.io/: рукопожатие и long-polling) обрабатывает сам engine.io, мимо цепочки
    // Express, поэтому заголовки приватности из http/app.js до них не доходили (R1 п.9). Тело ответа -
    // служебные пакеты с идентификатором сессии сокета: кэшировать его нельзя.
    io.engine.on('headers', (headers) => {
        Object.assign(headers, getPrivacyHeaders(), {
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, private',
            Pragma: 'no-cache',
            'X-Robots-Tag': 'noindex, nofollow',
        });
    });

    const userSocketCount = createCounter();
    const ipSocketCount = createCounter();

    function getClientIp(handshake) {
        const headers = handshake.headers || {};
        // Тот же принцип, что и в HTTP-мидлваре: сначала находим адрес, который
        // реально подключился к нашему прокси (последний хоп X-Forwarded-For —
        // соответствует "доверяем 1 прокси" из app.set('trust proxy', 1)), и только
        // если ЭТОТ адрес принадлежит Cloudflare — доверяем CF-Connecting-IP.
        const xff = headers['x-forwarded-for'];
        const connectingIp = xff
            ? xff.split(',').map(s => s.trim()).filter(Boolean).pop()
            : handshake.address;
        return resolveRealIp(headers, connectingIp);
    }

    // Подписать/отписать все сокеты пользователя (все вкладки) на чат.
    function subscribeUserToChat(userId, chatId, roomId) {
        io.in('user:' + userId).socketsJoin(getSocketRoomKey(chatId, roomId));
    }
    function unsubscribeUserFromChat(userId, chatId, roomId) {
        io.in('user:' + userId).socketsLeave(getSocketRoomKey(chatId, roomId));
    }

    return { io, userSocketCount, ipSocketCount, getClientIp, subscribeUserToChat, unsubscribeUserFromChat };
}

module.exports = { createIo, getSocketRoomKey, MAX_SOCKETS_PER_USER, MAX_SOCKETS_PER_IP };
