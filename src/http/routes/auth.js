'use strict';
// Вход и выход: регистрация анонима, удаление аккаунта (и его псевдоним /api/logout), состояние
// сессии GET /api/auth. Вынесено из server.js.

const {
    parseAnonLifetime, activityBucketMs, renewBucket, describeAnonLifetime,
} = require('../../../lib/anon-lifetime');
// Сессии в Postgres с огрублением времени, их продление и активность
// анонимов (контракт этапа 1, §4).
const { setSessionCookieLifetime } = require('../../../lib/session-store');
// Бот-помощник: ответ по теме запроса, приветствие нового аккаунта и подписи
// кнопок-подсказок — чистые функции без БД (lib/bot-guide.js).
const botGuide = require('../../../lib/bot-guide');
// Onion-сервис (контейнер tor-service/)
const { onionUrlFor } = require('../../../lib/tor-support');
const { logError } = require('../../../lib/log-error');
// База недоступна или занята — 503 busy с Retry-After (lib/db-errors.js).
const { respondIfDbBusy } = require('../../../lib/db-errors');
const { withMessageIdRetry } = require('../../db/transactions');
const { insertUserWithBotChat, signedOutResponse } = require('../../services/accounts');

function register(app, ctx) {
    const {
        SESSION_RENEW_MS, metrics, withTransaction, registerLimiter, startUserSession, endSession,
        anonActivity, checkPow, respondPowFailure, generateUniqueCodeAsync, generateAnonymousUsernameAsync,
        loadAccount, deleteUserAccount,
    } = ctx;

    // lifetime: 'tab' | 'day' | 'week' (по умолчанию 'tab') — см.
    // lib/anon-lifetime.js. Живая сессия — 409 ещё до PoW: второй аккаунт в
    // том же браузере не нужен (клиент в этом случае входит через /api/auth), а
    // решение одноразовое. lifetime тоже проверяется до PoW: отказ из-за
    // опечатки в параметре не должен заставлять решать задачу заново.
    app.post('/api/register/anonymous', registerLimiter, async (req, res) => {
        if (req.session.userId) {
            return res.status(409).json({ success: false, code: 'already-authenticated', message: 'Вы уже вошли в аккаунт' });
        }
        let lifetime;
        try {
            lifetime = parseAnonLifetime(req.body?.lifetime);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }
        const powVerdict = await checkPow(req, 'register-anon');
        if (powVerdict !== 'ok') return respondPowFailure(res, powVerdict);
        try {
            const uniqueCode = await generateUniqueCodeAsync();
            const username = await generateAnonymousUsernameAsync();
            // Регистрация — первая активность; в БД — её корзина.
            const now = Date.now();
            const lastActiveMs = activityBucketMs(now);

            const { userId, botChatId } = await withMessageIdRetry(() => withTransaction(client => insertUserWithBotChat(client, {
                uniqueCode, username, anonLifetime: lifetime, lastActiveAt: new Date(lastActiveMs),
                welcomeText: botGuide.welcomeText(lifetime),
            })));

            await startUserSession(req, {
                userId, username, uniqueCode, avatar: '#667EEA',
                isAnonymous: true, anonLifetime: lifetime, renewBucket: renewBucket(now, SESSION_RENEW_MS),
            });
            // 'tab' — кука без срока (до закрытия браузера), 'day'/'week' — срок
            // + 15 минут; она продлевается вместе с сессией.
            setSessionCookieLifetime(req.session.cookie, lifetime);
            anonActivity.remember(userId, { lifetime, lastActiveMs: now, persistedBucketMs: lastActiveMs });

            // Имя и id анонимного пользователя в лог не пишутся: связка "время
            // создания — id — имя" в логах хостинга как раз и деанонимизирует.

            metrics.registered();
            res.json({
                success: true,
                user: {
                    id: userId,
                    username,
                    uniqueCode,
                    isAnonymous: true,
                    readReceipts: false,
                    ...describeAnonLifetime({ lifetime, lastActiveMs }),
                },
                botChatId,
            });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('[Anon] Не удалось зарегистрировать аккаунт', error);
            res.json({ success: false, message: 'Ошибка сервера' });
        }
    });

    // Удаление аккаунта со всеми данными (см. deleteUserAccount). Подтверждения
    // не нужно: аккаунт временный, и войти в него иначе, чем этой сессией, нельзя.
    // POST /api/logout — псевдоним: выйти из такого аккаунта и значит удалить его.
    async function deleteOwnAccount(req, res) {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        try {
            await deleteUserAccount(userId);
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('[Account] Не удалось удалить аккаунт', error);
            return res.json({ success: false, message: 'Ошибка удаления аккаунта' });
        }
        metrics.accountsDeleted('user');
        endSession(req, res, 'Аккаунт и все данные удалены');
    }
    app.post('/api/account/delete', deleteOwnAccount);
    app.post('/api/logout', deleteOwnAccount);

    // Состояние входа. Сам запрос — активность и продление сессии (middleware
    // после sessionMiddleware); CSRF-куку, если её нет, выдаёт middleware CSRF.
    // onionUrl — адрес onion-зеркала при тех же условиях, что заголовок
    // Onion-Location (lib/tor-support.js), иначе null.
    app.get('/api/auth', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json(signedOutResponse(req));
        const account = await loadAccount(userId);
        if (!account) {
            // Аккаунт удалён между проверкой сессии и этим запросом.
            anonActivity.forget(userId);
            req.authEnded = 'expired';
            return req.session.destroy(() => res.json(signedOutResponse(req)));
        }
        res.json({
            authenticated: true,
            user: {
                id: account.id,
                username: account.username,
                uniqueCode: account.uniqueCode,
                isAnonymous: true,
                readReceipts: account.readReceipts,
                anonLifetime: account.anonLifetime,
                anonInactivitySeconds: account.anonInactivitySeconds,
                anonExpiresAt: account.anonExpiresAt,
            },
            onionUrl: onionUrlFor(req),
        });
    });
}

module.exports = { register };
