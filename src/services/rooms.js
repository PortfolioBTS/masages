'use strict';
// Комнаты, приглашения и заявки на вступление: поиск комнаты по коду, вступление участника,
// заявки, сертификаты состава. Чистка просроченных заявок. Вынесено из server.js.

const { isValidInviteCode, generateInviteCode } = require('../../lib/security-utils');
const {
    isInviteUsable, isRoomFull, MAX_PENDING_JOIN_REQUESTS_PER_ROOM, INVALID_INVITE_MESSAGE,
    JOIN_REQUEST_TTL_SECONDS,
} = require('../../lib/invites');
const { logError } = require('../../lib/log-error');

// ---- Приглашения и заявки на вступление ----
//
// Код приглашения (rooms.code, 26 символов) видят и меняют все участники
// комнаты. Параметры кода (lib/invites.js): срок, лимит участников
// (invite_max_members, NULL — без лимита), вступление только с одобрения
// любого участника (invite_require_approval, по умолчанию включено) и
// выключенный код (invite_disabled). Несуществующий, истёкший и
// выключенный код снаружи неразличимы: везде INVALID_INVITE_MESSAGE.

function inviteExpiresAtIso(expiresAt) {
    return expiresAt ? new Date(expiresAt).toISOString() : null;
}

// Новый код приглашения без подписанного сертификата: код остаётся и принимает только заявки, пока кто-то не создаст
// новую подписанную ссылку («Пригласить»). Вызывается внутри транзакции выхода или удаления аккаунта, под блокировкой
// комнаты. Срок и лимит участников прежние.
async function resetInviteAfterLeave(client, roomId) {
    await client.query(
        'UPDATE rooms SET invite_cert = NULL, invite_snap = NULL, invite_actor_id = NULL, code = $2 WHERE id = $1',
        [roomId, generateInviteCode()]
    );
}

const JOIN_REQUEST_LIVE_SQL = `created_at > NOW() - ${JOIN_REQUEST_TTL_SECONDS} * INTERVAL '1 second'`;
const JOIN_REQUEST_NOT_FOUND = { success: false, message: 'Заявка не найдена' };

// Строка списка чатов для только что вошедшего (как в POST /api/chats).
function roomChatPayload(chat, room) {
    return {
        id: chat.id, name: chat.name, avatar: chat.avatar, online: 0, is_bot: 0,
        room_id: room.id, invite_code: room.invite_disabled ? null : room.code,
    };
}

// Ответ на отказ addRoomMember с подробным вердиктом проверки сертификата.
function respondCertVerdict(res, verdict) {
    return res.status(verdict.status).json({ success: false, code: verdict.code, message: verdict.message });
}

function createRooms(ctx) {
    const {
        subscribeUserToChat, notifyChatListChanged, notifyRoomMembersChanged, notifyJoinRequestsChanged,
        notifyJoinRequestDecided, dbGet, dbAll, dbRun, withTransactionRetry, queryWithRetry, getOwnChat,
    } = ctx;

    // Комната вызывающего по его личному чату — с проверкой участия.
    async function getOwnRoom(chatIdParam, userId) {
        const chat = await getOwnChat(chatIdParam, userId);
        if (!chat) return { error: 'Чат не найден' };
        if (!chat.room_id) return { error: 'У этого чата нет кода приглашения' };
        const room = await dbGet(
            `SELECT r.id, r.name, r.code, r.code_expires_at, r.invite_max_members, r.invite_require_approval, r.invite_disabled,
                (r.invite_cert IS NOT NULL) AS invite_signed,
                (SELECT COUNT(*)::int FROM room_participants p WHERE p.room_id = r.id) AS member_count
         FROM rooms r
         JOIN room_participants rp ON rp.room_id = r.id AND rp.user_id = $2
         WHERE r.id = $1`,
            [chat.room_id, userId]
        );
        if (!room) return { error: 'Чат не найден' };
        return { chat, room };
    }

    // Комната по коду приглашения, если код можно использовать; иначе null —
    // одинаково для несуществующего, истёкшего и выключенного кода. Всё, что не
    // похоже на код нынешнего формата, в БД даже не ищется.
    async function findRoomByInviteCode(code) {
        if (!isValidInviteCode(code)) return null;
        const room = await dbGet(
            `SELECT r.id, r.name, r.code, r.code_expires_at, r.invite_max_members, r.invite_require_approval, r.invite_disabled,
                r.invite_cert,
                (SELECT COUNT(*)::int FROM room_participants p WHERE p.room_id = r.id) AS member_count
         FROM rooms r WHERE r.code = $1`,
            [code]
        );
        return room && isInviteUsable(room) ? room : null;
    }

    // Вступление в комнату — общий путь для входа по коду без одобрения и для
    // одобрения заявки. Участник + личная строка chats — одной транзакцией под
    // блокировкой строки комнаты (FOR NO KEY UPDATE):
    //   * вступления в одну комнату идут по очереди — два одновременных
    //     запроса не превысят лимит участников;
    //   * последний участник не может одновременно выйти и снести комнату
    //     вместе с новичком (DELETE /api/chats берёт FOR UPDATE);
    //   * отправка сообщений тоже встаёт в эту очередь: триггер seq обновляет
    //     rooms.msg_seq, и NO KEY UPDATE конфликтует с NO KEY UPDATE. Поэтому
    //     граница видимости новичка точна (инвариант О2 контракта порядка
    //     сообщений): отправка либо уже зафиксирована и её seq не больше
    //     прочитанного ниже rooms.msg_seq, либо ждёт и получит seq больше него.
    //     FOR UPDATE здесь не нужен и вреден: он блокировал бы и внешние ключи
    //     (KEY SHARE) всех вставок, ссылающихся на комнату.
    // Порядок блокировок users → rooms → room_participants → chats (раздел 8):
    // строка новичка берётся первой, до комнаты.
    // check(room, client) под блокировкой перепроверяет основание для
    // вступления (код — для входа по коду, живую заявку — для одобрения) и
    // возвращает код ошибки (строку), объект-ответ { reply: { status, body } } или null.
    // afterJoin(client, room) — в той же транзакции, только для нового участника: вставка
    // сертификата допуска или входа (signed-membership.md, 7.1). Прочитанные здесь
    // значения комнаты (invite_cert, invite_snap) принадлежат моменту блокировки: поворот
    // приглашения не успевает между проверкой сертификата и вставкой.
    // Новичок видит только сообщения после вступления: visible_from_seq —
    // rooms.msg_seq на этот момент (у заявки — на момент ОДОБРЕНИЯ, а не
    // подачи); та же граница — у непрочитанного (last_read_seq).
    async function addRoomMember(roomId, userId, check, afterJoin) {
        const result = await withTransactionRetry(async (client) => {
            const newcomer = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
            if (newcomer.rows.length === 0) return { error: 'not-found' };
            const locked = await client.query(
                `SELECT id, name, code, invite_max_members, invite_require_approval, invite_disabled, msg_seq,
                    invite_cert, invite_snap,
                    (code_expires_at IS NOT NULL AND code_expires_at > NOW()) AS code_live
             FROM rooms WHERE id = $1 FOR NO KEY UPDATE`,
                [roomId]
            );
            const room = locked.rows[0];
            if (!room) return { error: 'gone' };
            const checkError = check ? await check(room, client) : null;
            if (checkError) return { error: checkError };

            const existing = await client.query('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
            if (existing.rows[0]) {
                const dropped = await client.query('DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
                return { chat: existing.rows[0], room, joined: false, requestRemoved: dropped.rowCount > 0 };
            }
            const members = await client.query('SELECT COUNT(*)::int AS n FROM room_participants WHERE room_id = $1', [roomId]);
            if (isRoomFull(members.rows[0].n, room.invite_max_members)) return { error: 'full' };

            // Новичок видит группу под её названием — тем же, что в предпросмотре
            // приглашения. Раньше строка называлась «Чат с <имя первого
            // участника>»: в группе это неверно и лишний раз показывает имя.
            const name = room.name;
            const avatar = name.charAt(0).toUpperCase();
            await client.query(
                `INSERT INTO room_participants (room_id, user_id, visible_from_seq)
             VALUES ($1, $2, $3)
             ON CONFLICT (room_id, user_id) DO NOTHING`,
                [roomId, userId, room.msg_seq]
            );
            const chatResult = await client.query(
                `INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_seq)
             VALUES ($1, $2, $3, $4, 0, 0,
                     (SELECT visible_from_seq FROM room_participants WHERE room_id = $2 AND user_id = $1))
             RETURNING id`,
                [userId, roomId, name, avatar]
            );
            const dropped = await client.query('DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
            const extra = afterJoin ? await afterJoin(client, room) : null;
            return { chat: { id: chatResult.rows[0].id, name, avatar }, room, joined: true, requestRemoved: dropped.rowCount > 0, extra };
        });
        if (result.error) return result;

        const chat = roomChatPayload(result.chat, result.room);
        if (result.joined) {
            subscribeUserToChat(userId, chat.id, roomId);
            notifyRoomMembersChanged(roomId);
            notifyChatListChanged(userId);
        }
        if (result.requestRemoved) notifyJoinRequestsChanged(roomId);
        return { chat, joined: result.joined, extra: result.extra || null };
    }

    // Ключи участника из хранилища ключей (identity_keys) - для проверки сертификатов.
    function identityKeysOf(client, userId) {
        const run = client ? (sql, params) => client.query(sql, params).then(r => r.rows[0] || null) : dbGet;
        return run('SELECT identity_signing_key, identity_dh_key FROM identity_keys WHERE user_id = $1', [userId]);
    }

    // Заявка на вступление в комнату с одобрением. Повторный запрос возвращает
    // ту же заявку; просроченная (старше недели — фоновая чистка до неё ещё не
    // дошла) заменяется новой. Живых заявок в комнате — не больше
    // MAX_PENDING_JOIN_REQUESTS_PER_ROOM.
    async function createJoinRequest(roomId, userId) {
        await dbRun(`DELETE FROM join_requests WHERE room_id = $1 AND user_id = $2 AND NOT (${JOIN_REQUEST_LIVE_SQL})`, [roomId, userId]);
        const existing = await dbGet('SELECT id FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
        if (existing) return { id: existing.id };
        const pending = await dbGet(`SELECT COUNT(*)::int AS n FROM join_requests WHERE room_id = $1 AND ${JOIN_REQUEST_LIVE_SQL}`, [roomId]);
        if (pending.n >= MAX_PENDING_JOIN_REQUESTS_PER_ROOM) {
            return { error: 'В эту группу слишком много заявок. Попробуйте позже.' };
        }
        let inserted;
        try {
            inserted = (await queryWithRetry(
                'INSERT INTO join_requests (room_id, user_id) VALUES ($1, $2) ON CONFLICT (room_id, user_id) DO NOTHING RETURNING id',
                [roomId, userId]
            )).rows[0];
        } catch (err) {
            // Комнату снесли между проверкой кода и заявкой (вышел последний участник): код больше не действует.
            if (err && err.code === '23503') return { error: INVALID_INVITE_MESSAGE };
            throw err;
        }
        if (!inserted) {
            // Параллельный такой же запрос успел раньше — это та же заявка.
            const concurrent = await dbGet('SELECT id FROM join_requests WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
            return concurrent ? { id: concurrent.id } : { error: 'Не удалось отправить заявку. Попробуйте ещё раз.' };
        }
        notifyJoinRequestsChanged(roomId);
        return { id: inserted.id };
    }

    // Заявки на вступление старше недели: заявителю — "отклонена", участникам
    // — обновить список (в выборках просроченные заявки и так не видны).
    async function purgeExpiredJoinRequests() {
        try {
            const rows = await dbAll(`DELETE FROM join_requests WHERE NOT (${JOIN_REQUEST_LIVE_SQL}) RETURNING id, room_id, user_id`);
            for (const roomId of new Set(rows.map(r => r.room_id))) notifyJoinRequestsChanged(roomId);
            for (const row of rows) notifyJoinRequestDecided(row.user_id, { requestId: row.id, approved: false });
            if (rows.length > 0) console.log(`[Invites] Удалено просроченных заявок на вступление: ${rows.length}`);
        } catch (error) {
            logError('[Invites] Purge error', error);
        }
    }

    return {
        getOwnRoom, findRoomByInviteCode, addRoomMember, identityKeysOf, createJoinRequest,
        purgeExpiredJoinRequests,
    };
}

module.exports = {
    createRooms, resetInviteAfterLeave, JOIN_REQUEST_LIVE_SQL, respondCertVerdict, inviteExpiresAtIso,
    roomChatPayload, JOIN_REQUEST_NOT_FOUND,
};
