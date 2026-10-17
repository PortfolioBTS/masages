'use strict';
// Заявки на вступление: список для участников, свои заявки, одобрение, отказ, отзыв. Вынесено из server.js.

const { ROOM_FULL_MESSAGE } = require('../../../lib/invites');
const { isClientOutdated: isOutdatedProto } = require('../../../lib/proto');
// Подписанный состав группы (signed-membership.md): проверки сертификатов на сервере и общий с клиентом разбор.
const MembershipCerts = require('../../../lib/membership-certs');
const Membership = require('../../../public/lib/membership');
const { logError } = require('../../../lib/log-error');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const { CLIENT_OUTDATED } = require('../../../lib/message-ids');
const { JOIN_REQUEST_LIVE_SQL, JOIN_REQUEST_NOT_FOUND, respondCertVerdict } = require('../../services/rooms');
const { toPositiveInt } = require('../params');
const { respondIfDeadlock } = require('../../db/transactions');

function register(app, ctx) {
    const {
        notifyJoinRequestsChanged, notifyJoinRequestDecided, dbGet, dbAll, getOwnChat, addRoomMember,
        identityKeysOf, kt,
    } = ctx;

    // Живые заявки комнаты — любому её участнику. У заявителя — его identity-ключи и kt из
    // журнала ключей: одобряющий поручается за ключ заявителя до вступления, и проверить его по
    // журналу можно, пока заявитель ещё не в комнате (key-transparency.md, 6.5, GET /api/kt/proof).
    app.get('/api/chats/:chatId/join-requests', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        try {
            const chat = await getOwnChat(req.params.chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });
            if (!chat.room_id) return res.json({ success: true, requests: [] });
            const rows = await dbAll(
                `SELECT jr.id, jr.user_id, u.username, jr.created_at
             FROM join_requests jr JOIN users u ON u.id = jr.user_id
             WHERE jr.room_id = $1 AND jr.${JOIN_REQUEST_LIVE_SQL}
               AND EXISTS (SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2)
             ORDER BY jr.created_at, jr.id`,
                [chat.room_id, userId]
            );
            const identities = new Map();
            if (rows.length > 0) {
                const keyRows = await dbAll(
                    `SELECT user_id, identity_signing_key, identity_dh_key, kt_nonce, kt_gen, kt_epoch, kt_skt
                 FROM identity_keys WHERE user_id = ANY($1::bigint[])`,
                    [rows.map(r => r.user_id)]
                );
                for (const k of keyRows) {
                    identities.set(Number(k.user_id), {
                        signingKey: k.identity_signing_key.toString('base64'),
                        dhKey: k.identity_dh_key.toString('base64'),
                        kt: kt.hintOf(k),
                    });
                }
            }
            res.json({
                success: true,
                requests: rows.map(r => ({
                    id: r.id, userId: r.user_id, username: r.username, createdAt: r.created_at,
                    identity: identities.get(Number(r.user_id)) || null,
                })),
            });
        } catch (error) {
            logError('Get join requests error', error);
            res.json({ success: false, message: 'Ошибка загрузки заявок' });
        }
    });

    // Свои живые заявки (у заявителя: "ожидает одобрения").
    app.get('/api/join-requests/mine', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        try {
            const rows = await dbAll(
                `SELECT jr.id, r.name AS room_name, jr.created_at
             FROM join_requests jr JOIN rooms r ON r.id = jr.room_id
             WHERE jr.user_id = $1 AND jr.${JOIN_REQUEST_LIVE_SQL}
             ORDER BY jr.created_at DESC, jr.id`,
                [userId]
            );
            res.json({ success: true, requests: rows.map(r => ({ id: r.id, roomName: r.room_name, createdAt: r.created_at })) });
        } catch (error) {
            logError('Get own join requests error', error);
            res.json({ success: false, message: 'Ошибка загрузки заявок' });
        }
    });

    // Одобрить заявку — любой участник той же комнаты. Заявки чужих комнат
    // неотличимы от несуществующих. Вступление — тем же addRoomMember, что и
    // вход по коду без одобрения (лимит участников, visible_from_seq на момент
    // одобрения, подписка сокетов заявителя, roomMembersChanged).
    //
    // Одобрение подписывается (signed-membership.md, 5.2, 7.2): тело { cert, snap } - сертификат допуска
    // (vouch) от одобряющего заявителю и снимок состава одобряющего; без них - 400 cert-required /
    // snap-required. Сертификат и участие одобряющего проверяются ПОСЛЕ блокировки комнаты (7.1):
    // одобряющий мог выйти между проверкой подписи и вставкой, и сертификат с несуществующим подписавшим
    // остался бы навсегда.
    app.post('/api/join-requests/:id/approve', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
        const requestId = toPositiveInt(req.params.id);
        if (!requestId) return res.json(JOIN_REQUEST_NOT_FOUND);
        try {
            const request = await dbGet(
                `SELECT jr.id, jr.room_id, jr.user_id FROM join_requests jr
             JOIN room_participants rp ON rp.room_id = jr.room_id AND rp.user_id = $2
             WHERE jr.id = $1 AND jr.${JOIN_REQUEST_LIVE_SQL}`,
                [requestId, userId]
            );
            if (!request) return res.json(JOIN_REQUEST_NOT_FOUND);
            const applicantKeys = await identityKeysOf(null, request.user_id);
            if (!applicantKeys) {
                return res.status(409).json({ success: false, code: 'applicant-no-keys', message: 'Пользователь ещё не настроил шифрование' });
            }
            const verdict = await MembershipCerts.verifyVouch({
                certB64: req.body.cert, snapB64: req.body.snap, allowedKinds: [Membership.KIND.vouch],
                roomId: request.room_id, actorId: userId, subjectId: request.user_id,
                actorKeys: await identityKeysOf(null, userId), subjectKeys: applicantKeys,
            });
            if (!verdict.ok) return respondCertVerdict(res, verdict);
            // Под блокировкой комнаты — заявка всё ещё жива (её не отклонили и не
            // отозвали параллельно; FOR UPDATE — чтобы и не успели), а
            // одобряющий всё ещё участник. Строку заявителя addRoomMember берёт
            // самой первой (users → rooms), в том же порядке, что и
            // deleteUserAccount: одновременное удаление его аккаунта не даст
            // взаимной блокировки, заявка просто окажется удалённой.
            const result = await addRoomMember(request.room_id, request.user_id, async (room, client) => {
                const actor = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2', [room.id, userId]);
                if (actor.rows.length === 0) return 'not-participant';
                const live = await client.query(
                    `SELECT jr.id FROM join_requests jr
                 WHERE jr.id = $1 AND jr.user_id = $2 AND jr.room_id = $3 AND jr.${JOIN_REQUEST_LIVE_SQL}
                 FOR UPDATE OF jr`,
                    [requestId, request.user_id, room.id]
                );
                return live.rows.length > 0 ? null : 'not-found';
            }, async (client, room) => {
                await client.query(
                    'INSERT INTO room_member_certs (room_id, subject_id, actor_id, kind, cert, snap) VALUES ($1, $2, $3, 1, $4, $5)',
                    [room.id, request.user_id, userId, Buffer.from(verdict.raw), Buffer.from(verdict.snap)]
                );
                return null;
            });
            if (result.error === 'full') return res.json({ success: false, message: ROOM_FULL_MESSAGE });
            if (result.error === 'not-participant') {
                return res.status(404).json({ success: false, code: 'not-participant', message: 'Вы больше не состоите в этой группе' });
            }
            if (result.error) return res.json(JOIN_REQUEST_NOT_FOUND);
            notifyJoinRequestDecided(request.user_id, { requestId, approved: true, chat: result.chat });
            res.json({ success: true });
        } catch (error) {
            if (respondIfDeadlock(res, error)) return;
            logError('Approve join request error', error);
            res.json({ success: false, message: 'Ошибка одобрения заявки' });
        }
    });

    app.post('/api/join-requests/:id/deny', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const requestId = toPositiveInt(req.params.id);
        if (!requestId) return res.json(JOIN_REQUEST_NOT_FOUND);
        try {
            const removed = await dbGet(
                `DELETE FROM join_requests jr USING room_participants rp
             WHERE jr.id = $1 AND rp.room_id = jr.room_id AND rp.user_id = $2 AND jr.${JOIN_REQUEST_LIVE_SQL}
             RETURNING jr.id, jr.room_id, jr.user_id`,
                [requestId, userId]
            );
            if (!removed) return res.json(JOIN_REQUEST_NOT_FOUND);
            notifyJoinRequestsChanged(removed.room_id);
            notifyJoinRequestDecided(removed.user_id, { requestId: removed.id, approved: false });
            res.json({ success: true });
        } catch (error) {
            logError('Deny join request error', error);
            res.json({ success: false, message: 'Ошибка отклонения заявки' });
        }
    });

    // Заявитель отзывает свою заявку.
    app.delete('/api/join-requests/:id', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const requestId = toPositiveInt(req.params.id);
        if (!requestId) return res.json(JOIN_REQUEST_NOT_FOUND);
        try {
            const removed = await dbGet('DELETE FROM join_requests WHERE id = $1 AND user_id = $2 RETURNING room_id', [requestId, userId]);
            if (!removed) return res.json(JOIN_REQUEST_NOT_FOUND);
            notifyJoinRequestsChanged(removed.room_id);
            res.json({ success: true });
        } catch (error) {
            logError('Cancel join request error', error);
            res.json({ success: false, message: 'Ошибка отмены заявки' });
        }
    });
}

module.exports = { register };
