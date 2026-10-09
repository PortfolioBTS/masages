'use strict';
// Активность анонимных аккаунтов и проверка их сессий (контракт этапа 1, §4).
//
// Источник истины — users.anon_lifetime и users.last_active_at: по ним
// удаляет чистка (server.js, purgeExpiredAnonymousUsers), их же видят другие
// экземпляры сервера. Здесь — кэш процесса, чтобы каждый запрос не делал
// SELECT, а last_active_at писался не чаще раза за корзину (5 минут, см.
// lib/anon-lifetime.js). Запись кэша:
//   * lifetime — выбранный срок;
//   * lastActiveMs — точное время последней активности, ТОЛЬКО в памяти;
//   * persistedBucketMs — корзина, уже записанная в БД (или прочитанная оттуда);
//   * loadedAtMs — когда запись читалась из БД. Запись старше 60 секунд
//     перечитывается: смена срока или активность на другом экземпляре
//     становятся видны здесь.
//
// Зависимости внедряются (dbGet, dbRun, часы, лог) — модуль проверяется
// фейками (test/anon-activity.test.js).

const { activityBucketMs, isAnonExpired, storedAnonLifetime } = require('./anon-lifetime');
const { logError } = require('./log-error');

// Через сколько запись кэша перечитывается из БД.
const STATE_RELOAD_MS = 60 * 1000;
// Записи пользователей без открытого сокета, не читавшиеся из БД столько
// времени, выбрасываются (touch): при следующем запросе запись всё равно
// перечиталась бы, а держать её — значит копить в памяти всех, кто
// когда-либо заходил на этот экземпляр.
const STATE_STALE_MS = 10 * 60 * 1000;

const isUserId = (value) => Number.isSafeInteger(value) && value > 0;

function createAnonActivity({
    dbGet,
    dbRun,
    now = Date.now,
    report = logError,
    reloadAfterMs = STATE_RELOAD_MS,
    staleAfterMs = STATE_STALE_MS,
} = {}) {
    if (typeof dbGet !== 'function' || typeof dbRun !== 'function') throw new TypeError('нужны dbGet и dbRun');
    const states = new Map();

    async function load(userId) {
        const row = await dbGet(
            `SELECT anon_lifetime, EXTRACT(EPOCH FROM last_active_at) * 1000 AS last_active_ms
             FROM users WHERE id = $1`,
            [userId]
        );
        if (!row) {
            states.delete(userId);
            return null;
        }
        const stored = row.last_active_ms === null || row.last_active_ms === undefined ? null : Number(row.last_active_ms);
        const previous = states.get(userId);
        // Точное время из памяти не теряется, если оно новее записанного.
        const candidates = [stored, previous && previous.lastActiveMs].filter(Number.isFinite);
        const state = {
            lifetime: storedAnonLifetime(row.anon_lifetime),
            lastActiveMs: candidates.length > 0 ? Math.max(...candidates) : null,
            persistedBucketMs: stored,
            loadedAtMs: now(),
        };
        states.set(userId, state);
        return state;
    }

    // 'ok' | 'expired' | 'invalid'. Сессия без isAnonymous — от входа по
    // паролю, которого больше нет: недействительна. Пользователя нет или
    // срок вышел — expired. Ничего не меняет ни в сессии, ни в БД: годится и
    // для HTTP, и для рукопожатия сокета.
    async function validateSession(sess) {
        if (!sess || sess.isAnonymous !== true) return 'invalid';
        const userId = sess.userId;
        if (!isUserId(userId)) return 'invalid';
        const t = now();
        let state = states.get(userId);
        let fresh = false;
        if (!state || !(t - state.loadedAtMs < reloadAfterMs)) {
            state = await load(userId);
            fresh = true;
        }
        if (!state) return 'expired';
        if (!isAnonExpired({ lifetime: state.lifetime, lastActiveMs: state.lastActiveMs, now: t })) return 'ok';
        // По кэшу срок вышел, но активность могла прийти на другой экземпляр.
        if (!fresh) state = await load(userId);
        return state && !isAnonExpired({ lifetime: state.lifetime, lastActiveMs: state.lastActiveMs, now: t }) ? 'ok' : 'expired';
    }

    // Активность пользователя (HTTP-запрос, подключение и отключение сокета).
    // В БД — корзина, не чаще раза за корзину и только вверх. Возвращает
    // промис записи или null, если писать нечего; ошибка записи — в лог,
    // промис не отклоняется. Записи кэша нет (её выбросили) — время всё
    // равно пишется: иначе отключение сокета после долгого молчания по HTTP
    // не попало бы в БД.
    function noteActivity(userId) {
        if (!isUserId(userId)) return null;
        const t = now();
        let state = states.get(userId);
        if (!state) {
            state = { lifetime: null, lastActiveMs: null, persistedBucketMs: null, loadedAtMs: -Infinity };
            states.set(userId, state);
        }
        if (!(state.lastActiveMs >= t)) state.lastActiveMs = t;
        const bucket = activityBucketMs(t);
        if (state.persistedBucketMs >= bucket) return null;
        const previous = state.persistedBucketMs;
        state.persistedBucketMs = bucket;
        return dbRun(
            'UPDATE users SET last_active_at = $2 WHERE id = $1 AND last_active_at < $2',
            [userId, new Date(bucket)]
        ).then(() => undefined, (err) => {
            // Следующая активность попробует записать снова.
            if (state.persistedBucketMs === bucket) state.persistedBucketMs = previous;
            report('[Anon] Не удалось записать активность', err);
        });
    }

    // Открытые сокеты этого экземпляра (раз в 2,5 минуты): last_active_at
    // всем одним UPDATE. Заодно из кэша выбрасываются давно не читавшиеся
    // записи тех, кто не в сети.
    async function touch(userIds) {
        const t = now();
        const online = new Set([...userIds].filter(isUserId));
        for (const [id, state] of states) {
            if (!online.has(id) && t - state.loadedAtMs >= staleAfterMs) states.delete(id);
        }
        if (online.size === 0) return;
        const bucket = activityBucketMs(t);
        await dbRun(
            'UPDATE users SET last_active_at = $2 WHERE id = ANY($1::int[]) AND last_active_at < $2',
            [[...online], new Date(bucket)]
        );
        for (const id of online) {
            const state = states.get(id);
            if (!state) continue;
            if (!(state.lastActiveMs >= t)) state.lastActiveMs = t;
            if (!(state.persistedBucketMs >= bucket)) state.persistedBucketMs = bucket;
        }
    }

    // Запись после регистрации или смены срока: то, что сервер только что
    // сам записал в БД, перечитывать незачем.
    function remember(userId, { lifetime, lastActiveMs, persistedBucketMs }) {
        states.set(userId, {
            lifetime: storedAnonLifetime(lifetime),
            lastActiveMs,
            persistedBucketMs,
            loadedAtMs: now(),
        });
    }

    function forget(userId) {
        states.delete(userId);
    }

    // Срок аккаунта по кэшу (после validateSession запись свежая) или null.
    function lifetimeOf(userId) {
        const state = states.get(userId);
        return state && state.lifetime ? state.lifetime : null;
    }

    return {
        validateSession,
        noteActivity,
        touch,
        remember,
        forget,
        lifetimeOf,
        _states: states,
    };
}

module.exports = { createAnonActivity, STATE_RELOAD_MS, STATE_STALE_MS };
