// Прокси для E2EE Key Server.
//
// ВАЖНО: это НЕ самостоятельное Express-приложение. Модуль экспортирует
// функцию registerE2eeProxyRoutes(app, { dbGet, dbAll }), которую server.js
// вызывает ПОСЛЕ app.use(sessionMiddleware) — маршрутам нужна req.session.
//
// Предыдущая версия модуля вызывала app.put(...) прямо на верхнем уровне,
// где `app` не существует, — процесс падал с "ReferenceError: app is not
// defined" при require() ещё до начала прослушивания порта (crash-loop
// контейнера, см. логи деплоя от 2026-09-18).
//
// Чужие ключи (bundle, identities) отдаются только тем, у кого с владельцем
// ключей есть ОБЩАЯ комната. Раньше любой авторизованный мог перебирать id
// и узнавать, кто зарегистрирован и настроил E2EE, а главное — выкачивать
// чужие одноразовые prekey: каждый запрос bundle расходует один OPK цели,
// и после исчерпания пула новые сессии с ней строились без одноразовой
// части X3DH. Для bundle дополнительно действуют лимиты: 60 в час на
// вызывающего и 5 в час на пару (вызывающий, цель).
const KEY_SERVER_URL = process.env.KEY_SERVER_URL || 'http://127.0.0.1:7420';
const KEY_SERVER_SECRET = process.env.INTERNAL_KEY_SERVER_SECRET;

const HOUR_MS = 60 * 60 * 1000;
const BUNDLE_LIMIT_PER_CALLER = 60;
const BUNDLE_LIMIT_PER_PAIR = 5;
const LIMITER_SWEEP_MS = 10 * 60 * 1000;
const MAX_IDENTITY_IDS = 200;
// users.id — INTEGER: большее значение Postgres отверг бы ошибкой приведения.
const PG_INT_MAX = 2147483647;

const SHARED_ROOM_SQL =
    'SELECT 1 FROM room_participants a JOIN room_participants b ON a.room_id = b.room_id ' +
    'WHERE a.user_id = $1 AND b.user_id = $2 LIMIT 1';
const SHARED_ROOM_MANY_SQL =
    'SELECT DISTINCT b.user_id FROM room_participants a JOIN room_participants b ON a.room_id = b.room_id ' +
    'WHERE a.user_id = $1 AND b.user_id = ANY($2::int[])';

// Middleware для проверки авторизации (локальная копия, у каждого модуля своя)
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    next();
}

// Fail closed: без секрета проксировать некуда и незачем — лучше честный
// 503 сразу, чем молча висящий запрос до таймаута (и расход лимитов bundle
// на запросы, которые всё равно не выполнятся).
function requireKeyServer(req, res, next) {
    if (!KEY_SERVER_SECRET) {
        return res.status(503).json({ success: false, message: 'E2EE key server не настроен' });
    }
    next();
}

function parseUserId(value) {
    if (typeof value !== 'string' || !/^\d{1,10}$/.test(value)) return null;
    const id = Number(value);
    return id > 0 && id <= PG_INT_MAX ? id : null;
}

// "1,2,3" → [1, 2, 3] без повторов; null — если список пустой, битый или
// длиннее MAX_IDENTITY_IDS (key-server больше и не примет).
function parseIdList(raw) {
    if (typeof raw !== 'string') return null; // ?ids=1&ids=2 Express отдаёт массивом
    const ids = [];
    for (const part of raw.split(',')) {
        const id = parseUserId(part.trim());
        if (id === null) return null;
        if (!ids.includes(id)) ids.push(id);
        if (ids.length > MAX_IDENTITY_IDS) return null;
    }
    return ids;
}

// Счётчик со скользящим окном по журналу меток времени: в отличие от
// фиксированного окна не пропускает двойной объём на стыке окон, а памяти
// на ключ — не больше max меток.
function createSlidingWindowCounter(windowMs, max) {
    const hits = new Map(); // ключ → метки времени по возрастанию

    function recent(key, now) {
        const list = hits.get(key);
        if (!list) return null;
        let stale = 0;
        while (stale < list.length && list[stale] <= now - windowMs) stale++;
        if (stale > 0) list.splice(0, stale);
        if (list.length === 0) {
            hits.delete(key);
            return null;
        }
        return list;
    }

    return {
        // Сколько миллисекунд ждать до освобождения слота; 0 — слот есть.
        waitMs(key, now) {
            const list = recent(key, now);
            return list && list.length >= max ? list[0] + windowMs - now : 0;
        },
        hit(key, now) {
            const list = recent(key, now);
            if (list) list.push(now);
            else hits.set(key, [now]);
        },
        // Периодическая очистка: без неё в Map навсегда оставались бы ключи
        // пользователей, которые больше не приходили.
        sweep(now) {
            for (const key of hits.keys()) recent(key, now);
        },
    };
}

// Запрос к key-server по loopback с внутренним секретом и уже проверенным
// userId из сессии. Сетевые ошибки и таймаут пробрасываются вызывающему.
async function callKeyServer(userId, method, path, body) {
    const response = await fetch(`${KEY_SERVER_URL}${path}`, {
        method,
        headers: {
            ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
            'X-Internal-Secret': KEY_SERVER_SECRET,
            'X-User-Id': String(userId),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(5000),
    });
    const data = await response.json().catch(() => ({ success: false, message: 'Некорректный ответ key server' }));
    return { status: response.status, ok: response.ok, data };
}

function respondKeyServerDown(res, error) {
    console.error('[E2EE] Key server proxy error:', error.message);
    res.status(502).json({ success: false, message: 'E2EE key server недоступен' });
}

// Тело ответа key-server отдаём клиенту как есть вместе со статусом.
async function proxyToKeyServer(req, res, method, path, body) {
    try {
        const { status, data } = await callKeyServer(req.session.userId, method, path, body);
        res.status(status).json(data);
    } catch (error) {
        respondKeyServerDown(res, error);
    }
}

function registerE2eeProxyRoutes(app, deps) {
    const { dbGet, dbAll } = deps || {};
    if (typeof dbGet !== 'function' || typeof dbAll !== 'function') {
        // Без БД нельзя проверить общую комнату — лучше не стартовать, чем
        // отдавать чужие ключи без проверки или падать на каждом запросе.
        throw new TypeError('registerE2eeProxyRoutes(app, { dbGet, dbAll }): нужны функции dbGet и dbAll');
    }
    const guard = [requireAuth, requireKeyServer];

    const callerLimiter = createSlidingWindowCounter(HOUR_MS, BUNDLE_LIMIT_PER_CALLER);
    const pairLimiter = createSlidingWindowCounter(HOUR_MS, BUNDLE_LIMIT_PER_PAIR);
    setInterval(() => {
        const now = Date.now();
        callerLimiter.sweep(now);
        pairLimiter.sweep(now);
    }, LIMITER_SWEEP_MS).unref(); // таймер не должен держать процесс (и тесты) живым

    async function sharesRoom(userId, targetUserId) {
        return Boolean(await dbGet(SHARED_ROOM_SQL, [userId, targetUserId]));
    }

    // Оставляет из ids только тех, с кем у userId есть общая комната (сам
    // userId разрешён всегда), в исходном порядке.
    async function filterVisibleUsers(userId, ids) {
        const visible = new Set(ids.includes(userId) ? [userId] : []);
        const others = ids.filter(id => id !== userId);
        if (others.length > 0) {
            const rows = await dbAll(SHARED_ROOM_MANY_SQL, [userId, others]);
            for (const row of rows) visible.add(Number(row.user_id));
        }
        return ids.filter(id => visible.has(id));
    }

    // Регистрация/обновление identity ключей
    app.put('/api/keys/identity', ...guard, (req, res) =>
        proxyToKeyServer(req, res, 'PUT', '/internal/v1/keys/identity', req.body));

    // Ротация Signed PreKey
    app.put('/api/keys/signed-prekey', ...guard, (req, res) =>
        proxyToKeyServer(req, res, 'PUT', '/internal/v1/keys/signed-prekey', req.body));

    // Ротация постквантового (ML-KEM-768) prekey, подписанного identity-ключом
    app.put('/api/keys/pq-prekey', ...guard, (req, res) =>
        proxyToKeyServer(req, res, 'PUT', '/internal/v1/keys/pq-prekey', req.body));

    // Пополнение пула One-Time PreKeys
    app.post('/api/keys/one-time-prekeys', ...guard, (req, res) =>
        proxyToKeyServer(req, res, 'POST', '/internal/v1/keys/one-time-prekeys', req.body));

    // Количество оставшихся OPK
    app.get('/api/keys/one-time-prekeys/count', ...guard, (req, res) =>
        proxyToKeyServer(req, res, 'GET', '/internal/v1/keys/one-time-prekeys/count'));

    // Публичные identity-ключи участников (проверка safety number и смены
    // ключа). OPK не расходует. Недоступные id молча отбрасываются: ответ не
    // должен различать "нет такого пользователя" и "нет общей комнаты".
    app.get('/api/keys/identities', ...guard, async (req, res) => {
        const userId = Number(req.session.userId);
        const ids = parseIdList(req.query.ids);
        if (!ids) {
            return res.status(400).json({ success: false, message: `Некорректный список ids (не больше ${MAX_IDENTITY_IDS})` });
        }
        let allowed;
        try {
            allowed = await filterVisibleUsers(userId, ids);
        } catch (error) {
            console.error('[E2EE] identities access check error:', error);
            return res.status(500).json({ success: false, message: 'Ошибка проверки доступа' });
        }
        if (allowed.length === 0) return res.json({ success: true, identities: [] });

        let result;
        try {
            result = await callKeyServer(userId, 'GET', `/internal/v1/keys/identities?ids=${allowed.join(',')}`);
        } catch (error) {
            return respondKeyServerDown(res, error);
        }
        if (!result.ok) return res.status(result.status).json(result.data);
        if (!result.data || !Array.isArray(result.data.identities)) {
            return res.status(502).json({ success: false, message: 'Некорректный ответ key server' });
        }
        // Ещё раз по списку разрешённых — на случай, если key-server
        // вернёт лишнее: утечка чужого ключа не должна зависеть от него.
        const allowedSet = new Set(allowed);
        res.json({
            success: true,
            identities: result.data.identities.filter(item => item && allowedSet.has(Number(item.user_id))),
        });
    });

    // Key bundle собеседника для инициации X3DH-сессии
    app.get('/api/keys/bundle/:targetUserId', ...guard, async (req, res) => {
        const userId = Number(req.session.userId);
        const targetUserId = parseUserId(req.params.targetUserId);
        if (targetUserId === null) {
            return res.status(400).json({ success: false, message: 'Некорректный targetUserId' });
        }
        try {
            if (!(await sharesRoom(userId, targetUserId))) {
                return res.status(403).json({ success: false, message: 'Нет общего чата с пользователем' });
            }
        } catch (error) {
            console.error('[E2EE] bundle access check error:', error);
            return res.status(500).json({ success: false, message: 'Ошибка проверки доступа' });
        }

        // Проверка и учёт — синхронно, без await между ними: параллельные
        // запросы не проскочат лимит, пока предыдущий ещё ждёт key-server.
        const now = Date.now();
        const pairKey = `${userId}:${targetUserId}`;
        const callerWait = callerLimiter.waitMs(userId, now);
        const pairWait = pairLimiter.waitMs(pairKey, now);
        if (callerWait > 0 || pairWait > 0) {
            const waitSec = Math.ceil(Math.max(callerWait, pairWait) / 1000);
            const minutes = Math.max(1, Math.ceil(waitSec / 60));
            res.set('Retry-After', String(waitSec));
            return res.status(429).json({
                success: false,
                message: pairWait > 0
                    ? `Слишком много запросов ключей этого пользователя. Повторите через ${minutes} мин.`
                    : `Слишком много запросов ключей шифрования. Повторите через ${minutes} мин.`,
            });
        }
        callerLimiter.hit(userId, now);
        pairLimiter.hit(pairKey, now);

        return proxyToKeyServer(req, res, 'GET', `/internal/v1/keys/bundle/${targetUserId}`);
    });

    // Удаление всех ключей пользователя
    app.delete('/api/keys', ...guard, (req, res) =>
        proxyToKeyServer(req, res, 'DELETE', '/internal/v1/keys'));
}

// Серверная (без HTTP-запроса клиента) очистка ключей — при удалении
// аккаунта. Best effort: key-server может быть не настроен.
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
        // Без id: для анонимного аккаунта это был бы след в логах уже после
        // того, как все его данные удалены.
        console.warn('[E2EE] Не удалось удалить ключи удалённого пользователя:', error.message);
        return false;
    }
}

module.exports = { registerE2eeProxyRoutes, deleteKeysForUser };
