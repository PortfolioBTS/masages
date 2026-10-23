'use strict';
// Обработчики socket.io: источник -> сессия -> авторизация -> лимиты подключений; подключение,
// подписка на чаты пользователя, ограничитель частоты событий и отключение. Вынесено из server.js.

// Onion-сервис (контейнер tor-service/)
const { isOnionSocket } = require('../../lib/tor-support');
const { logError } = require('../../lib/log-error');
const { createTokenBucket } = require('../../lib/token-bucket');
const { MAX_SOCKETS_PER_USER, MAX_SOCKETS_PER_IP, getSocketRoomKey } = require('./io');

// Частота входящих событий одного сокета (токен-бакет): клиент от себя ничего не шлёт, подписка
// на чаты делается сервером, так что любой поток событий - не работа, а нагрузка. SOCKET_EVENT_RATE
// - событий в секунду в среднем, SOCKET_EVENT_BURST - всплеск. Превышение - disconnect.
function envInt(value, fallback) {
    const n = Number(value);
    return Number.isInteger(n) && n >= 1 ? n : fallback;
}

function registerSocketHandlers(ctx) {
    const {
        io, userSocketCount, ipSocketCount, getClientIp, dbAll, sessionMiddleware, anonActivity,
    } = ctx;
    const eventRate = envInt(process.env.SOCKET_EVENT_RATE, 5);
    const eventBurst = envInt(process.env.SOCKET_EVENT_BURST, 20);

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

        // Событий от клиента сервер не принимает (обработчиков нет): подписка на чаты - дело сервера
        // (ниже и subscribeUserToChat при создании чата или входе в комнату). Раньше был обработчик
        // joinChat с запросом в БД на каждое событие: 10 сокетов по 8000 событий забивали пул
        // соединений (R1 п.2), а проверка членства и подписка расходились во времени с выходом из
        // комнаты. Лишние события отбрасываются ограничителем, а сокет, превысивший частоту, закрывается.
        const bucket = createTokenBucket({ capacity: eventBurst, refillPerSecond: eventRate });
        socket.use((packet, next) => {
            if (bucket.take()) return next();
            socket.disconnect(true);
        });

        // Сразу подписываем сокет на ВСЕ чаты пользователя. Раньше подписка
        // появлялась только при открытии конкретного чата, поэтому новые
        // сообщения в остальных чатах не обновляли ни список, ни счётчики.
        try {
            const roomKeys = async () => (await dbAll('SELECT id, room_id FROM chats WHERE user_id = $1', [userId]))
                .map(c => getSocketRoomKey(c.id, c.room_id));
            const subscribed = await roomKeys();
            socket.join(subscribed);
            // Гонка с выходом из комнаты (R2.2): список мог устареть, пока шёл запрос, а
            // выход отписывает сокеты пользователя сразу после коммита - раньше, чем этот
            // сокет вошёл. Поэтому после join список читается ещё раз и лишнее снимается.
            // Порядок «join, потом проверка» не оставляет окна: выход после проверки
            // отпишет уже вошедший сокет, выход до неё увидит проверка.
            const actual = new Set(await roomKeys());
            for (const key of subscribed) if (!actual.has(key)) socket.leave(key);
        } catch (err) {
            logError('Socket auto-join error', err);
        }
    });
}

module.exports = { registerSocketHandlers };
