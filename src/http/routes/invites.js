'use strict';
// Приглашения в комнату: показ, перевыпуск, отключение, предпросмотр и вход по коду. Вынесено из server.js.

const { generateInviteCode, normalizeInviteCode } = require('../../../lib/security-utils');
const {
    describeInvite, parseInviteSettings, INVALID_INVITE_MESSAGE, isRoomFull, ROOM_FULL_MESSAGE,
} = require('../../../lib/invites');
const { isClientOutdated: isOutdatedProto } = require('../../../lib/proto');
// Подписанный состав группы (signed-membership.md): проверки сертификатов на сервере и общий с клиентом разбор.
const MembershipCerts = require('../../../lib/membership-certs');
const Membership = require('../../../public/lib/membership');
const { logError } = require('../../../lib/log-error');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const { CLIENT_OUTDATED } = require('../../../lib/message-ids');
const { respondCertVerdict, inviteExpiresAtIso, roomChatPayload } = require('../../services/rooms');
// База недоступна или занята — 503 busy с Retry-After (lib/db-errors.js).
const { respondIfDbBusy } = require('../../../lib/db-errors');

function register(app, ctx) {
    const {
        INVITE_TTL_SECONDS, dbGet, withTransactionRetry, joinUserLimiter, joinIpLimiter, getOwnChat,
        getOwnRoom, findRoomByInviteCode, addRoomMember, identityKeysOf, createJoinRequest,
    } = ctx;

    app.get('/api/chats/invite/:chatId', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        try {
            const own = await getOwnRoom(req.params.chatId, req.session.userId);
            if (own.error) return res.json({ success: false, message: own.error });
            res.json({ success: true, ...describeInvite(own.room, own.room.member_count) });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Get invite error', error);
            res.json({ success: false, message: 'Ошибка получения кода' });
        }
    });

    // Новый код приглашения с параметрами { ttlSeconds, maxMembers,
    // requireApproval } — любой участник комнаты. Старый код перестаёт
    // действовать сразу (так закрывается утёкшая ссылка); выключенный код
    // перевыпуск снова включает.
    //
    // Подписанное приглашение (signed-membership.md, 5.3, 7.2): вход без одобрения возможен только
    // по ссылке с секретом, поэтому при requireApproval = false обязательны inviteCert (сертификат
    // приглашения, подписанный автором и ключом приглашения) и inviteSnap (снимок состава автора);
    // срок такого приглашения не больше 720 часов (INVITE_MAX), а сервер сверяет длительность
    // сертификата с выбранным сроком, а не абсолютное время. При requireApproval = true сертификата
    // нет: код принимает только заявки, а invite_* обнуляются.
    app.post('/api/chats/:chatId/invite/rotate', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
        let settings;
        try {
            settings = parseInviteSettings(req.body, { defaultTtlSeconds: INVITE_TTL_SECONDS });
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }
        const signed = !settings.requireApproval;
        // Срок подписанного приглашения клиент кладёт в сертификат сам, поэтому он обязан его назвать.
        if (signed && (req.body.ttlSeconds === undefined || req.body.ttlSeconds === null || req.body.ttlSeconds === '')) {
            return res.status(400).json({ success: false, code: 'bad-request', message: 'Не задан срок действия кода' });
        }
        const ttlSeconds = signed ? Math.min(settings.ttlSeconds, Membership.INVITE_MAX_MIN * 60) : settings.ttlSeconds;
        try {
            const chat = await getOwnChat(req.params.chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });
            if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
            let verdict = null;
            if (signed) {
                verdict = await MembershipCerts.verifyInvite({
                    certB64: req.body.inviteCert, snapB64: req.body.inviteSnap, roomId: chat.room_id, actorId: userId,
                    actorKeys: await identityKeysOf(null, userId), ttlSeconds,
                });
                if (!verdict.ok) return respondCertVerdict(res, verdict);
            }
            // Порядок блокировок users → rooms → room_participants: автор приглашения обязан быть участником
            // ПОСЛЕ блокировки комнаты, иначе выход или удаление аккаунта автора между проверкой и записью
            // оставили бы invite_actor_id несуществующего пользователя (его выход обнуляет invite_*).
            const room = await withTransactionRetry(async (client) => {
                const me = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
                if (me.rows.length === 0) return null;
                const locked = await client.query('SELECT id FROM rooms WHERE id = $1 FOR NO KEY UPDATE', [chat.room_id]);
                if (locked.rows.length === 0) return null;
                const member = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, userId]);
                if (member.rows.length === 0) return null;
                const updated = await client.query(
                    `UPDATE rooms SET code = $1, code_expires_at = NOW() + $2::integer * INTERVAL '1 second',
                        invite_max_members = $4, invite_require_approval = $5, invite_disabled = FALSE,
                        invite_cert = $6, invite_snap = $7, invite_actor_id = $8
                 WHERE id = $3
                 RETURNING code, code_expires_at, invite_max_members, invite_require_approval`,
                    [generateInviteCode(), ttlSeconds, chat.room_id, settings.maxMembers, settings.requireApproval,
                        verdict ? Buffer.from(verdict.raw) : null, verdict ? Buffer.from(verdict.snap) : null, verdict ? userId : null]
                );
                return updated.rows[0];
            });
            if (!room) return res.json({ success: false, message: 'Чат не найден' });
            res.json({
                success: true,
                code: room.code,
                expiresAt: inviteExpiresAtIso(room.code_expires_at),
                maxMembers: room.invite_max_members,
                requireApproval: room.invite_require_approval,
            });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Rotate invite error', error);
            res.json({ success: false, message: 'Ошибка обновления кода' });
        }
    });

    // Выключить приглашение. Сам код тоже заменяется случайным, нигде не
    // показанным: выключенный код не оживёт, даже если флаг где-то забудут
    // проверить. Сертификат приглашения и его снимок обнуляются (уже сохранённые join остаются:
    // у них копия в aux). Уже поданные заявки остаются — их можно рассмотреть.
    app.post('/api/chats/:chatId/invite/disable', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
        try {
            const chat = await getOwnChat(req.params.chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });
            if (!chat.room_id) return res.json({ success: false, message: 'У этого чата нет кода приглашения' });
            const room = await dbGet(
                `UPDATE rooms SET code = $1, invite_disabled = TRUE, invite_cert = NULL, invite_snap = NULL, invite_actor_id = NULL
             WHERE id = $2 AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $2 AND user_id = $3)
             RETURNING id`,
                [generateInviteCode(), chat.room_id, userId]
            );
            if (!room) return res.json({ success: false, message: 'Чат не найден' });
            res.json({ success: true });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Disable invite error', error);
            res.json({ success: false, message: 'Ошибка отключения кода' });
        }
    });

    // Что за группа по коду — до вступления. Тот же лимитер, что у входа по
    // коду (общий счётчик): иначе предпросмотр стал бы бесплатным способом
    // перебирать коды.
    app.post('/api/chats/join/preview', joinUserLimiter, joinIpLimiter, async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        const code = normalizeInviteCode(req.body?.code);
        if (!code) return res.json({ success: false, message: 'Введите код приглашения' });
        try {
            const room = await findRoomByInviteCode(code);
            if (!room) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });
            // roomId и сертификат приглашения (signed-membership.md, 7.2): выдаются по КОДУ, то есть и тому, кто секрета не
            // знает, - раскрывают пригласившего (id, identity-ключ), число участников его V и хэш снимка (раздел 3). Сам
            // снимок по коду не отдаётся: он приходит в ответе на POST /join владельцу join-сертификата.
            res.json({
                success: true,
                roomId: room.id,
                roomName: room.name,
                memberCount: room.member_count,
                requireApproval: room.invite_require_approval !== false,
                inviteCert: room.invite_cert ? Membership.toB64(new Uint8Array(room.invite_cert)) : null,
            });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Join preview error', error);
            res.json({ success: false, message: 'Ошибка проверки кода' });
        }
    });

    // Вход по коду (signed-membership.md, 5.3-5.4, 7.2). Без joinCert - всегда заявка, даже если в комнате
    // requireApproval = false: код без секрета (набран руками, утёк в логи) не впускает. Вход без одобрения - только с
    // joinCert, подписанным ключом приглашения (его знает владелец ссылки с секретом) и identity-ключом входящего.
    // Ответ при успехе несёт inviteSnap - снимок приглашения: его получает только тот, чей joinCert прошёл проверку.
    app.post('/api/chats/join', joinUserLimiter, joinIpLimiter, async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
        const code = normalizeInviteCode(req.body?.code);
        if (!code) return res.json({ success: false, message: 'Введите код приглашения' });
        let joinRaw = null;
        if (req.body.joinCert !== undefined && req.body.joinCert !== null) {
            joinRaw = MembershipCerts.decodeField(req.body.joinCert, { min: 335, max: 335 });
            if (!joinRaw) return respondCertVerdict(res, MembershipCerts.BAD_CERT());
        }

        try {
            const room = await findRoomByInviteCode(code);
            if (!room) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });

            const existingChat = await dbGet('SELECT id, name, avatar FROM chats WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
            if (existingChat) {
                if (!joinRaw) return res.json({ success: true, chat: roomChatPayload(existingChat, room) });
                // Повторный запрос после потери ответа: тот же joinCert от уже вошедшего даёт тот же ответ, пока приглашение
                // не повернули; иначе - 409 (снимок получает только владелец действующего приглашения).
                const stored = await dbGet('SELECT cert FROM room_member_certs WHERE room_id = $1 AND subject_id = $2 AND kind = 3', [room.id, userId]);
                const current = await dbGet('SELECT invite_cert, invite_snap FROM rooms WHERE id = $1', [room.id]);
                const same = stored && Buffer.from(stored.cert).equals(Buffer.from(joinRaw));
                let unchanged = false;
                if (same && current && current.invite_cert) {
                    const ref = new Uint8Array(stored.cert).subarray(Membership.OFF.ref, Membership.OFF.ref + 32);
                    unchanged = Membership.bytesEqual(await Membership.certHash(new Uint8Array(current.invite_cert)), ref);
                }
                if (!unchanged) return res.status(409).json({ success: false, code: 'already-member', message: 'Вы уже состоите в этой группе' });
                return res.json({
                    success: true, chat: roomChatPayload(existingChat, room),
                    inviteSnap: Membership.toB64(new Uint8Array(current.invite_snap)),
                });
            }
            if (isRoomFull(room.member_count, room.invite_max_members)) {
                return res.json({ success: false, message: ROOM_FULL_MESSAGE });
            }

            const pendingResponse = async () => {
                const request = await createJoinRequest(room.id, userId);
                if (request.error) return res.json({ success: false, message: request.error });
                res.json({ success: true, pending: true, requestId: request.id, roomName: room.name });
            };
            // Без сертификата, в комнате с одобрением и в комнате без подписанного приглашения (его обнулил выход участника
            // или выключение) - заявка. Секрет ссылки в этом случае игнорируется.
            if (!joinRaw || room.invite_require_approval !== false || !room.invite_cert) return pendingResponse();

            // Код и сертификат перепроверяются под блокировкой комнаты: пока шли запросы выше, код могли сменить или
            // выключить, приглашение - повернуть, а одобрение - включить.
            const result = await addRoomMember(room.id, userId, async (locked, client) => {
                if (locked.code !== code || !locked.code_live || locked.invite_disabled) return 'invalid';
                if (locked.invite_require_approval !== false || !locked.invite_cert) return 'approval';
                const verdict = await MembershipCerts.verifyJoin({
                    joinRaw, inviteRaw: new Uint8Array(locked.invite_cert), roomId: room.id, userId,
                    userKeys: await identityKeysOf(client, userId),
                });
                return verdict.ok ? null : { reply: verdict };
            }, async (client, locked) => {
                await client.query(
                    'INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, aux) VALUES ($1, $2, 0, 3, $3, $4)',
                    [room.id, userId, Buffer.from(joinRaw), Buffer.from(locked.invite_cert)]
                );
                return { inviteSnap: locked.invite_snap ? Membership.toB64(new Uint8Array(locked.invite_snap)) : null };
            });
            if (result.error === 'approval') return pendingResponse();
            if (result.error === 'full') return res.json({ success: false, message: ROOM_FULL_MESSAGE });
            if (result.error && result.error.reply) return respondCertVerdict(res, result.error.reply);
            if (result.error) return res.json({ success: false, message: INVALID_INVITE_MESSAGE });
            const reply = { success: true, chat: result.chat };
            if (result.extra && result.extra.inviteSnap) reply.inviteSnap = result.extra.inviteSnap;
            res.json(reply);
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Join chat error', error);
            res.json({ success: false, message: 'Ошибка входа в чат' });
        }
    });
}

module.exports = { register };
