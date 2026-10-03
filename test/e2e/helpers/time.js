'use strict';
// Перемотка времени в базе набора. Сдвигаются ДАННЫЕ (в прошлое), а не
// часы вперёд: проверки в JS сервера (Date.now()) и NOW() Postgres
// остаются согласованы.
//
// Все сдвиги — в миллисекундах «назад». Кэш процесса сервера (anonStates —
// активность анонимов) перемотка не трогает: сбросить его можно рестартом
// сервера, а «просроченного» аноним удаляет чистка по базе.

const SHIFT = (param) => `make_interval(secs => ${param}::float8 / 1000)`;

function assertUpdated(result, what) {
    if (result.rowCount === 0) throw new Error(`перемотка времени: не найден ${what}`);
}

// id сессии из куки connect.sid (s:<sid>.<подпись>, urlencoded).
function sessionIdFromCookie(value) {
    if (!value) return null;
    const decoded = decodeURIComponent(value);
    if (!decoded.startsWith('s:')) return null;
    return decoded.slice(2).split('.')[0];
}

// Поля времени в JSON сессии: cookie.expires (ISO) и числовые поля *At (мс
// от эпохи, например createdAt анонима).
function shiftSessionData(sess, ms) {
    const copy = JSON.parse(JSON.stringify(sess));
    if (copy.cookie && typeof copy.cookie.expires === 'string') {
        const t = Date.parse(copy.cookie.expires);
        if (!Number.isNaN(t)) copy.cookie.expires = new Date(t - ms).toISOString();
    }
    for (const [key, value] of Object.entries(copy)) {
        if (/At$/.test(key) && typeof value === 'number' && value > 1e12) copy[key] = value - ms;
    }
    return copy;
}

function createTimeHelpers(db) {
    async function rewindSession(sid, ms) {
        const { rows } = await db.query('SELECT sess FROM session WHERE sid = $1', [sid]);
        if (!rows[0]) throw new Error(`перемотка времени: нет сессии ${sid}`);
        const sess = typeof rows[0].sess === 'string' ? JSON.parse(rows[0].sess) : rows[0].sess;
        await db.query(
            `UPDATE session SET sess = $2::json, expire = expire - ${SHIFT('$3')} WHERE sid = $1`,
            [sid, JSON.stringify(shiftSessionData(sess, ms)), ms]
        );
    }

    return {
        // users.last_active_at и created_at — на lastActiveMs / createdMs назад.
        async rewindUser(userId, { lastActiveMs = 0, createdMs = 0 } = {}) {
            assertUpdated(await db.query(
                `UPDATE users SET last_active_at = last_active_at - ${SHIFT('$2')},
                                  created_at = created_at - ${SHIFT('$3')}
                 WHERE id = $1`,
                [userId, lastActiveMs, createdMs]
            ), `пользователь ${userId}`);
        },

        rewindSession,

        // Все сессии пользователя (по sess.userId).
        async rewindUserSessions(userId, ms) {
            const { rows } = await db.query(`SELECT sid FROM session WHERE sess->>'userId' = $1`, [String(userId)]);
            for (const { sid } of rows) await rewindSession(sid, ms);
            return rows.length;
        },

        async rewindJoinRequest(requestId, ms) {
            assertUpdated(await db.query(
                `UPDATE join_requests SET created_at = created_at - ${SHIFT('$2')} WHERE id = $1`, [requestId, ms]
            ), `заявка ${requestId}`);
        },

        // Срок кода приглашения комнаты — на ms раньше.
        async rewindInvite(roomId, ms) {
            assertUpdated(await db.query(
                `UPDATE rooms SET code_expires_at = code_expires_at - ${SHIFT('$2')} WHERE id = $1`, [roomId, ms]
            ), `комната ${roomId}`);
        },

        async expireInvite(roomId) {
            assertUpdated(await db.query(
                `UPDATE rooms SET code_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, [roomId]
            ), `комната ${roomId}`);
        },

        async rewindMessage(messageId, ms) {
            assertUpdated(await db.query(
                `UPDATE messages SET created_at = created_at - ${SHIFT('$2')} WHERE id = $1`, [messageId, ms]
            ), `сообщение ${messageId}`);
        },

        // Срок исчезающего сообщения уже вышел: его удалит очистка сервера
        // (CLEANUP_INTERVAL_MS, в тестах 500 мс). Колонка без часового пояса —
        // время считается в самом Postgres, как у сервера.
        async expireMessage(messageId) {
            await db.query(
                `INSERT INTO message_expiry (message_id, expires_at) VALUES ($1, NOW() - INTERVAL '1 second')
                 ON CONFLICT (message_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
                [messageId]
            );
        },
    };
}

module.exports = { createTimeHelpers, sessionIdFromCookie, shiftSessionData };
