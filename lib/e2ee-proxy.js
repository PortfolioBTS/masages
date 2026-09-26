// Прокси для E2EE Key Server.
//
// ВАЖНО: это НЕ самостоятельное Express-приложение. Модуль экспортирует
// функцию registerE2eeProxyRoutes(app), которую server.js вызывает ПОСЛЕ
// app.use(sessionMiddleware) — маршрутам нужна req.session.
//
// Предыдущая версия модуля вызывала app.put(...) прямо на верхнем уровне,
// где `app` не существует, — процесс падал с "ReferenceError: app is not
// defined" при require() ещё до начала прослушивания порта (crash-loop
// контейнера, см. логи деплоя от 2026-09-18).
const KEY_SERVER_URL = process.env.KEY_SERVER_URL || 'http://127.0.0.1:7420';
const KEY_SERVER_SECRET = process.env.INTERNAL_KEY_SERVER_SECRET;

// Middleware для проверки авторизации (локальная копия, у каждого модуля своя)
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    next();
}

// Общий хелпер проксирования: Node → key-server по loopback с
// внутренним секретом и уже проверенным userId из сессии. Тело ответа
// key-server отдаём клиенту как есть вместе со статусом.
async function proxyToKeyServer(req, res, method, path, body) {
    if (!KEY_SERVER_SECRET) {
        // Fail closed: без секрета проксировать некуда и незачем — лучше
        // честный 503, чем молча висящий запрос до таймаута.
        return res.status(503).json({ success: false, message: 'E2EE key server не настроен' });
    }
    try {
        const response = await fetch(`${KEY_SERVER_URL}${path}`, {
            method,
            headers: {
                ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
            body: body !== undefined ? JSON.stringify(body) : undefined,
            signal: AbortSignal.timeout(5000),
        });

        const data = await response.json().catch(() => ({ success: false, message: 'Некорректный ответ key server' }));
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] Key server proxy error:', error.message);
        res.status(502).json({ success: false, message: 'E2EE key server недоступен' });
    }
}

function registerE2eeProxyRoutes(app) {
    // Регистрация/обновление identity ключей
    app.put('/api/keys/identity', requireAuth, (req, res) =>
        proxyToKeyServer(req, res, 'PUT', '/internal/v1/keys/identity', req.body));

    // Ротация Signed PreKey
    app.put('/api/keys/signed-prekey', requireAuth, (req, res) =>
        proxyToKeyServer(req, res, 'PUT', '/internal/v1/keys/signed-prekey', req.body));

    // Пополнение пула One-Time PreKeys
    app.post('/api/keys/one-time-prekeys', requireAuth, (req, res) =>
        proxyToKeyServer(req, res, 'POST', '/internal/v1/keys/one-time-prekeys', req.body));

    // Количество оставшихся OPK
    app.get('/api/keys/one-time-prekeys/count', requireAuth, (req, res) =>
        proxyToKeyServer(req, res, 'GET', '/internal/v1/keys/one-time-prekeys/count'));

    // Key bundle собеседника для инициации X3DH-сессии
    app.get('/api/keys/bundle/:targetUserId', requireAuth, (req, res) => {
        const targetUserId = Number(req.params.targetUserId);
        if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
            return res.status(400).json({ success: false, message: 'Некорректный targetUserId' });
        }
        return proxyToKeyServer(req, res, 'GET', `/internal/v1/keys/bundle/${targetUserId}`);
    });

    // Удаление всех ключей пользователя
    app.delete('/api/keys', requireAuth, (req, res) =>
        proxyToKeyServer(req, res, 'DELETE', '/internal/v1/keys'));
}

// Серверная (без HTTP-запроса клиента) очистка ключей — при удалении
// анонимного аккаунта. Best effort: key-server может быть не настроен.
async function deleteKeysForUser(userId) {
    if (!KEY_SERVER_SECRET) return false;
    try {
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys`, {
            method: 'DELETE',
            headers: { 'X-Internal-Secret': KEY_SERVER_SECRET, 'X-User-Id': String(userId) },
            signal: AbortSignal.timeout(5000),
        });
        return response.ok;
    } catch (error) {
        console.warn('[E2EE] Не удалось удалить ключи пользователя', userId, '-', error.message);
        return false;
    }
}

module.exports = { registerE2eeProxyRoutes, deleteKeysForUser };
