'use strict';
// Настройки аккаунта: приватность, данные пользователя, срок хранения аккаунта. Вынесено из server.js.

const {
    parseAnonLifetimeStrict, activityBucketMs, renewBucket, describeAnonLifetime,
} = require('../../../lib/anon-lifetime');
// Сессии в Postgres с огрублением времени, их продление и активность
// анонимов (контракт этапа 1, §4).
const { setSessionCookieLifetime } = require('../../../lib/session-store');
const { logError } = require('../../../lib/log-error');

function register(app, ctx) {
    const { SESSION_RENEW_MS, dbGet, startUserSession, anonActivity, loadAccount } = ctx;

    // Отметки прочтения: выключенные — собеседники не видят ✓✓ и не получают
    // messagesRead от этого пользователя (см. markChatRead).
    app.post('/api/user/privacy', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const readReceipts = req.body?.readReceipts;
        if (typeof readReceipts !== 'boolean') return res.json({ success: false, message: 'Некорректные параметры' });
        try {
            const row = await dbGet('UPDATE users SET read_receipts = $1 WHERE id = $2 RETURNING read_receipts', [readReceipts, userId]);
            if (!row) return res.json({ success: false, message: 'Пользователь не найден' });
            res.json({ success: true, readReceipts: row.read_receipts });
        } catch (error) {
            logError('Update privacy error', error);
            res.json({ success: false, message: 'Ошибка сохранения настроек' });
        }
    });

    app.get('/api/user', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const account = await loadAccount(userId);
        if (!account) return res.json({ success: false, message: 'Пользователь не найден' });
        res.json({ success: true, user: account });
    });

    // Смена срока жизни аккаунта (контракт этапа 1, §3). Срок обязателен и без
    // значения по умолчанию (parseAnonLifetimeStrict): пустой или кривой запрос
    // не должен молча превращать неделю в 30 минут. Новый срок отсчитывается от
    // момента смены: last_active_at — текущая корзина (только вверх, как и любая
    // запись активности). Сессия пересоздаётся с новым sid: у новой куки другой
    // срок (tab — без Expires, day/week — с Expires), а копия прежней куки,
    // которая жила бы по старому сроку, больше ничего не открывает. Сокет
    // держится на прежней сессии — клиент после ответа переподключает его.
    app.post('/api/user/lifetime', async (req, res) => {
        const sess = req.session;
        const userId = sess.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        let lifetime;
        try {
            lifetime = parseAnonLifetimeStrict(req.body?.lifetime);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }
        const now = Date.now();
        const row = await dbGet(
            `UPDATE users SET anon_lifetime = $2, last_active_at = GREATEST(last_active_at, $3)
         WHERE id = $1
         RETURNING EXTRACT(EPOCH FROM last_active_at) * 1000 AS last_active_ms`,
            [userId, lifetime, new Date(activityBucketMs(now))]
        );
        if (!row) {
            // Аккаунт удалён между проверкой сессии и этим запросом: следующая
            // проверка перечитает БД и закончит сессию.
            anonActivity.forget(userId);
            return res.json({ success: false, message: 'Пользователь не найден' });
        }
        const lastActiveMs = Number(row.last_active_ms);
        // Кэш — сразу после записи в БД: даже если пересоздать сессию не выйдет,
        // срок аккаунта уже новый, и прежнюю сессию middleware приведёт к нему
        // при следующем продлении (renewSession).
        anonActivity.remember(userId, { lifetime, lastActiveMs: now, persistedBucketMs: lastActiveMs });
        await startUserSession(req, {
            userId, username: sess.username, uniqueCode: sess.uniqueCode, avatar: sess.avatar,
            isAnonymous: true, anonLifetime: lifetime, renewBucket: renewBucket(now, SESSION_RENEW_MS),
        });
        setSessionCookieLifetime(req.session.cookie, lifetime);
        // Новый CSRF-токен для новой сессии уже выдан в startUserSession: токен,
        // который видели вместе с прежней кукой, дальше не действует.
        res.json({ success: true, ...describeAnonLifetime({ lifetime, lastActiveMs }) });
    });
}

module.exports = { register };
