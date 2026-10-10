// Маршруты /api/keys/*: публичные E2EE-ключи пользователей (identity, signed
// prekey, постквантовый prekey, одноразовые prekey) и выдача bundle для
// X3DH/PQXDH. Сами ключи лежат во встроенном хранилище (lib/key-store.js, та
// же база, что и остальное приложение); этот модуль решает, кому и сколько
// раз их отдавать. Статусы и тексты ответов — часть контракта с клиентом
// (public/e2ee.js): менять их можно только вместе с ним.
//
// ВАЖНО: это НЕ самостоятельное Express-приложение. Модуль экспортирует
// функцию registerE2eeKeyRoutes(app, { dbGet, dbAll }), которую server.js
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
const { createKeyStore } = require('./key-store');

let keyStore = null; // создаётся в registerE2eeKeyRoutes (нужны dbGet/dbAll)

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

function parseUserId(value) {
    if (typeof value !== 'string' || !/^\d{1,10}$/.test(value)) return null;
    const id = Number(value);
    return id > 0 && id <= PG_INT_MAX ? id : null;
}

// "1,2,3" → [1, 2, 3] без повторов; null — если список пустой, битый или
// длиннее MAX_IDENTITY_IDS (хранилище больше и не примет).
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

// Запрос к хранилищу ключей с уже проверенным userId из сессии. Ошибки БД
// пробрасываются вызывающему — маршрут отвечает 502.
function callKeyStore(userId, method, path, body) {
    return keyStore.call(userId, method, path, body);
}

function respondKeyStoreFailed(res, error) {
    console.error('[E2EE] Ошибка хранилища ключей:', error.message);
    res.status(502).json({ success: false, message: 'E2EE key server недоступен' });
}

// Ответ хранилища отдаём клиенту как есть вместе со статусом.
async function respondFromKeyStore(req, res, method, path, body) {
    try {
        const { status, data } = await callKeyStore(req.session.userId, method, path, body);
        res.status(status).json(data);
    } catch (error) {
        respondKeyStoreFailed(res, error);
    }
}

// Ответ, когда хранилище лимита выдачи bundle не отвечает: лимит закрывается
// (запрос не выполняется), а не пропускается — как у остальных точных
// лимитов (lib/pg-limits.js).
const BUNDLE_LIMIT_BUSY = { success: false, code: 'busy', message: 'Сервис сейчас занят. Повторите попытку через несколько секунд.' };

// deps.bundleLimiter — хранилище лимита выдачи bundle с методом
// tryConsume(lockKey, rules) → { ok, waitMs: [...] } (lib/pg-limits.js,
// createPgSlidingLimiter): server.js передаёт лимитер в Postgres, и квота
// переживает рестарт. Без него (юнит-тесты, один процесс) счётчики лежат в
// памяти.
function registerE2eeKeyRoutes(app, deps) {
    const { dbGet, dbAll, bundleLimiter } = deps || {};
    if (typeof dbGet !== 'function' || typeof dbAll !== 'function') {
        // Без БД нельзя проверить общую комнату — лучше не стартовать, чем
        // отдавать чужие ключи без проверки или падать на каждом запросе.
        throw new TypeError('registerE2eeKeyRoutes(app, { dbGet, dbAll }): нужны функции dbGet и dbAll');
    }
    keyStore = createKeyStore({ dbGet, dbAll });

    const callerLimiter = createSlidingWindowCounter(HOUR_MS, BUNDLE_LIMIT_PER_CALLER);
    const pairLimiter = createSlidingWindowCounter(HOUR_MS, BUNDLE_LIMIT_PER_PAIR);
    if (!bundleLimiter) {
        setInterval(() => {
            const now = Date.now();
            callerLimiter.sweep(now);
            pairLimiter.sweep(now);
        }, LIMITER_SWEEP_MS).unref(); // таймер не должен держать процесс (и тесты) живым
    }

    // Проверить и учесть запрос bundle; { callerWait, pairWait } в мс — 0, если
    // слот есть (и тогда он уже занят этим запросом).
    async function consumeBundleQuota(userId, targetUserId) {
        const pairKey = `${userId}:${targetUserId}`;
        if (bundleLimiter) {
            const { waitMs } = await bundleLimiter.tryConsume(String(userId), [
                { key: `caller:${userId}`, max: BUNDLE_LIMIT_PER_CALLER },
                { key: `pair:${pairKey}`, max: BUNDLE_LIMIT_PER_PAIR },
            ]);
            return { callerWait: waitMs[0], pairWait: waitMs[1] };
        }
        // Проверка и учёт — синхронно, без await между ними: параллельные
        // запросы не проскочат лимит, пока предыдущий ещё ждёт хранилище.
        const now = Date.now();
        const callerWait = callerLimiter.waitMs(userId, now);
        const pairWait = pairLimiter.waitMs(pairKey, now);
        if (callerWait === 0 && pairWait === 0) {
            callerLimiter.hit(userId, now);
            pairLimiter.hit(pairKey, now);
        }
        return { callerWait, pairWait };
    }

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
    app.put('/api/keys/identity', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'PUT', '/internal/v1/keys/identity', req.body));

    // Ротация Signed PreKey
    app.put('/api/keys/signed-prekey', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'PUT', '/internal/v1/keys/signed-prekey', req.body));

    // Ротация постквантового (ML-KEM-768) prekey, подписанного identity-ключом
    app.put('/api/keys/pq-prekey', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'PUT', '/internal/v1/keys/pq-prekey', req.body));

    // Пополнение пула One-Time PreKeys
    app.post('/api/keys/one-time-prekeys', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'POST', '/internal/v1/keys/one-time-prekeys', req.body));

    // Пополнение пула одноразовых постквантовых prekey (ML-KEM-768, подпись
    // identity-ключом с меткой домена) и его полная очистка: клиент раз в 30
    // дней стирает пул и загружает новый.
    app.post('/api/keys/pq-one-time-prekeys', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'POST', '/internal/v1/keys/pq-one-time-prekeys', req.body));
    app.delete('/api/keys/pq-one-time-prekeys', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'DELETE', '/internal/v1/keys/pq-one-time-prekeys'));

    // Количество оставшихся одноразовых prekey: { count, pq_count }
    app.get('/api/keys/one-time-prekeys/count', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'GET', '/internal/v1/keys/one-time-prekeys/count'));

    // Публичные identity-ключи участников (проверка safety number и смены
    // ключа). OPK не расходует. Недоступные id молча отбрасываются: ответ не
    // должен различать "нет такого пользователя" и "нет общей комнаты".
    app.get('/api/keys/identities', requireAuth, async (req, res) => {
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
            result = await callKeyStore(userId, 'GET', `/internal/v1/keys/identities?ids=${allowed.join(',')}`);
        } catch (error) {
            return respondKeyStoreFailed(res, error);
        }
        if (!result.ok) return res.status(result.status).json(result.data);
        // Контракт хранилища — массив identities. Без проверки .filter ниже
        // упал бы в async-обработчике, а Express 4 такие ошибки не
        // перехватывает: запрос завис бы.
        if (!result.data || !Array.isArray(result.data.identities)) {
            return res.status(502).json({ success: false, message: 'Некорректный ответ key server' });
        }
        // Ещё раз по списку разрешённых — на случай, если хранилище вернёт
        // лишнее: утечка чужого ключа не должна зависеть от его выборки.
        const allowedSet = new Set(allowed);
        res.json({
            success: true,
            identities: result.data.identities.filter(item => item && allowedSet.has(Number(item.user_id))),
        });
    });

    // Key bundle собеседника для инициации X3DH-сессии
    app.get('/api/keys/bundle/:targetUserId', requireAuth, async (req, res) => {
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

        let quota;
        try {
            quota = await consumeBundleQuota(userId, targetUserId);
        } catch (error) {
            // Сбой хранилища лимита (в логе уже есть): лимит не открывается.
            res.set('Retry-After', '5');
            return res.status(503).json(BUNDLE_LIMIT_BUSY);
        }
        const { callerWait, pairWait } = quota;
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

        return respondFromKeyStore(req, res, 'GET', `/internal/v1/keys/bundle/${targetUserId}`);
    });

    // Удаление всех ключей пользователя
    app.delete('/api/keys', requireAuth, (req, res) =>
        respondFromKeyStore(req, res, 'DELETE', '/internal/v1/keys'));
}

// Серверная (без HTTP-запроса клиента) очистка ключей — при удалении
// аккаунта. Best effort: к этому моменту аккаунт уже удалён в БД, и сбой
// очистки ключей не должен его откатывать.
async function deleteKeysForUser(userId) {
    try {
        if (!keyStore) return false;
        return (await keyStore.deleteAll(userId)).ok;
    } catch (error) {
        // Без id: для анонимного аккаунта это был бы след в логах уже после
        // того, как все его данные удалены.
        console.warn('[E2EE] Не удалось удалить ключи удалённого пользователя:', error.message);
        return false;
    }
}

module.exports = { registerE2eeKeyRoutes, deleteKeysForUser };
