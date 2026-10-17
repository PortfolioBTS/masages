'use strict';
// Обработчики socket.io: источник -> сессия -> авторизация -> лимиты подключений; подключение,
// вход в комнаты чатов и отключение. Вынесено из server.js.

// Onion-сервис (контейнер tor-service/)
const { isOnionSocket } = require('../../lib/tor-support');
const { logError } = require('../../lib/log-error');
const { MAX_SOCKETS_PER_USER, MAX_SOCKETS_PER_IP, getSocketRoomKey } = require('./io');

function registerSocketHandlers(ctx) {
    const {
        io, userSocketCount, ipSocketCount, getClientIp, dbGet, dbAll, sessionMiddleware, anonActivity,
    } = ctx;

    // Socket.io: источник (allowRequest — в realtime/io.js) -> сессия -> авторизация ->
    // лимит подключений на аккаунт и (для clearnet) на IP.
    io.use((socket, next) => {
        sessionMiddleware(socket.request, socket.request.res || {}, next);
    });
    io.use((socket, next) => {
        const sess = socket.request.session;
        // Раньше неавторизованный сокет принимался и тут же отключался уже в
        // 'connection' — клиент после этого сам не переподключался, и после
        // входа в аккаунт realtime не работал до перезагрузки страницы.
        if (!sess || !sess.userId) return next(new Error('Не авторизован'));
        // Та же проверка, что у HTTP-запросов. Продлить куку сокет не может —
        // её ставит только HTTP-ответ (клиент для этого вызывает /api/auth).
        anonActivity.validateSession(sess).then((verdict) => {
            if (verdict !== 'ok') return next(new Error('Не авторизован'));
            if (userSocketCount.get(sess.userId) >= MAX_SOCKETS_PER_USER) {
                return next(new Error('Слишком много подключений'));
            }
            // Onion-рукопожатие (сокет принят на ONION_PORT) приходит с адреса
            // контейнера tor — одного на всех, а его X-Forwarded-For присылает сам
            // клиент: IP тут ничего не значит.
            const ip = isOnionSocket(socket.request.socket) ? null : getClientIp(socket.handshake);
            if (ip && ipSocketCount.get(ip) >= MAX_SOCKETS_PER_IP) {
                return next(new Error('Слишком много подключений с вашего IP'));
            }
            socket.data.clientIp = ip;
            next();
        }, (err) => {
            logError('[Socket] Ошибка проверки сессии', err);
            next(new Error('Ошибка сервера'));
        });
    });

    io.on('connection', async (socket) => {
        const userId = socket.request.session.userId;

        // Счётчики растут только для реально установленных соединений. Раньше
        // счётчик IP увеличивался ещё в middleware, а единственное место
        // уменьшения — 'disconnect' — для отклонённого рукопожатия не наступает:
        // IP мог навсегда упереться в лимит. userSocketCount заодно — признак
        // «в сети на этом экземпляре» для touch и чистки неактивных.
        const ip = socket.data.clientIp;
        userSocketCount.increment(userId);
        if (ip) ipSocketCount.increment(ip);
        // Подключение — активность (в БД — не чаще раза за корзину).
        anonActivity.noteActivity(userId);
        socket.on('disconnect', () => {
            userSocketCount.decrement(userId);
            if (ip) ipSocketCount.decrement(ip);
            // Закрылся последний сокет — отсчёт неактивности начинается отсюда:
            // корзина этого момента попадает в БД.
            if (userSocketCount.get(userId) === 0) anonActivity.noteActivity(userId);
        });

        // Личная комната пользователя (на всех его вкладках/устройствах) —
        // адресная доставка событий конкретному человеку (E2EE key-share,
        // подписка на новый чат, принудительный выход).
        socket.join('user:' + userId);

        socket.on('joinChat', async (roomKey) => {
            if (typeof roomKey !== 'string' || roomKey.length === 0) return;
            try {
                if (roomKey.startsWith('room:')) {
                    const roomId = parseInt(roomKey.slice(5), 10);
                    if (!Number.isFinite(roomId)) return;
                    const participant = await dbGet(
                        'SELECT id FROM room_participants WHERE room_id = $1 AND user_id = $2',
                        [roomId, userId]
                    );
                    if (!participant) return;
                } else if (roomKey.startsWith('chat:')) {
                    const chatId = parseInt(roomKey.slice(5), 10);
                    if (!Number.isFinite(chatId)) return;
                    const chat = await dbGet(
                        'SELECT id FROM chats WHERE id = $1 AND user_id = $2',
                        [chatId, userId]
                    );
                    if (!chat) return;
                } else {
                    return;
                }
                socket.join(roomKey);
            } catch (err) {
                logError('joinChat error', err);
            }
        });

        // Сразу подписываем сокет на ВСЕ чаты пользователя. Раньше подписка
        // появлялась только при открытии конкретного чата, поэтому новые
        // сообщения в остальных чатах не обновляли ни список, ни счётчики.
        try {
            const chats = await dbAll('SELECT id, room_id FROM chats WHERE user_id = $1', [userId]);
            socket.join(chats.map(c => getSocketRoomKey(c.id, c.room_id)));
        } catch (err) {
            logError('Socket auto-join error', err);
        }
    });
}

module.exports = { registerSocketHandlers };
