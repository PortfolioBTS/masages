'use strict';
// DELETE /api/chats/:chatId — выход из чата (для создателя комнаты и последнего участника — удаление).
// Вынесено из server.js.

const { logError } = require('../../../lib/log-error');
const { resetInviteAfterLeave } = require('../../services/rooms');
const { getSocketRoomKey } = require('../../realtime/io');
const { respondIfDeadlock } = require('../../db/transactions');

function register(app, ctx) {
    const {
        authorTags, removeUploadedFiles, io, unsubscribeUserFromChat, notifyChatListChanged,
        notifyRoomMembersChanged, notifyJoinRequestDecided, withTransactionRetry, getOwnChat,
    } = ctx;

    // Выход из комнаты или удаление чата с ботом. Для комнаты сообщения выходящего
    // остаются (тег автора на них сохраняется), а комната записывается в
    // user_left_rooms, если у него там есть сообщения: удаление аккаунта удалит их во
    // всех таких комнатах (sealed-sender.md, 12.1). ?deleteMessages=1 - удалить свои
    // сообщения сразу (параметр строки запроса: тело у DELETE клиентская функция
    // api() не отправляет); для чата с ботом параметр ничего не значит.
    app.delete('/api/chats/:chatId', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const deleteOwnMessages = req.query.deleteMessages === '1';
        try {
            const chat = await getOwnChat(req.params.chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });

            // Всё удаление — одной транзакцией (раньше — серия независимых
            // запросов: сбой посередине оставлял полуудалённый чат), файлы
            // удаляемых сообщений убираются с диска после COMMIT. Порядок
            // блокировок users → rooms → room_participants → chats → user_left_rooms →
            // messages (message-ordering.md, раздел 8.1): сначала строка выходящего,
            // потом комната, потому что одновременно идут отправки (users → rooms),
            // вступления и удаление аккаунта. При взаимной блокировке (40P01)
            // транзакция повторяется один раз.
            const outcome = await withTransactionRetry(async (client) => {
                const me = await client.query('SELECT id, created_at FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
                if (me.rows.length === 0) return null; // аккаунт удалён между проверкой сессии и этим запросом
                const state = { fileUrls: [], roomSurvived: false, droppedRequests: [], deletedIds: [] };
                if (chat.room_id) {
                    // Блокировка комнаты: два последних участника, выходящих
                    // одновременно, иначе оба видели бы "остался ещё один" и
                    // комната оставалась бы в БД навсегда. Она же упорядочивает выход
                    // с отправкой (8.5): отправка проверяет членство под
                    // rooms FOR NO KEY UPDATE.
                    await client.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [chat.room_id]);
                    await client.query('DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2', [chat.room_id, userId]);
                    await client.query('DELETE FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2', [chat.room_id, userId]);
                    await client.query('DELETE FROM e2ee_key_requests WHERE room_id = $1 AND requester_id = $2', [chat.room_id, userId]);
                    await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
                    // Сертификаты состава, где он субъект или подписавший (после chats, до user_left_rooms и messages -
                    // порядок message-ordering.md, 8.1). Выход не подписывается: управляет сервер (signed-membership.md, 5.6).
                    await client.query(
                        'DELETE FROM room_member_certs WHERE room_id = $1 AND (subject_id = $2 OR actor_id = $2)',
                        [chat.room_id, userId]
                    );
                    const remaining = await client.query('SELECT 1 FROM room_participants WHERE room_id = $1 LIMIT 1', [chat.room_id]);
                    if (remaining.rows.length === 0) {
                        // Последний участник вышел — сносим комнату целиком (запись
                        // user_left_rooms уходит каскадом от rooms).
                        // Заявки ушли бы и каскадом, но заявителям надо сказать,
                        // что рассматривать их больше некому.
                        const deleted = await client.query('DELETE FROM messages WHERE room_id = $1 RETURNING file_url', [chat.room_id]);
                        state.fileUrls = deleted.rows.map(r => r.file_url);
                        const requests = await client.query('DELETE FROM join_requests WHERE room_id = $1 RETURNING id, user_id', [chat.room_id]);
                        state.droppedRequests = requests.rows;
                        await client.query('DELETE FROM rooms WHERE id = $1', [chat.room_id]);
                    } else {
                        state.roomSurvived = true;
                        // Решение владельца (signed-membership.md, вопрос 17): при выходе любого участника подписанное
                        // приглашение обнуляется, а код заменяется новым - старая ссылка и старый код перестают работать.
                        await resetInviteAfterLeave(client, chat.room_id);
                        const tags = authorTags.tagsForAccount(chat.room_id, userId, me.rows[0].created_at, Date.now());
                        if (deleteOwnMessages) {
                            const deleted = await client.query(
                                'DELETE FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) RETURNING id, file_url',
                                [chat.room_id, tags]
                            );
                            state.fileUrls = deleted.rows.map(r => r.file_url);
                            state.deletedIds = deleted.rows.map(r => r.id);
                            await client.query('DELETE FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [userId, chat.room_id]);
                        } else {
                            const own = await client.query(
                                'SELECT 1 FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) LIMIT 1',
                                [chat.room_id, tags]
                            );
                            if (own.rows.length > 0) {
                                await client.query(
                                    'INSERT INTO user_left_rooms (user_id, room_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                                    [userId, chat.room_id]
                                );
                            } else {
                                // Сообщений нет (в том числе после срока): отслеживать нечего.
                                await client.query('DELETE FROM user_left_rooms WHERE user_id = $1 AND room_id = $2', [userId, chat.room_id]);
                            }
                        }
                    }
                    // Если участники остались — история остаётся у них: сообщения
                    // выходящего хранятся под тегом, а удалить их он вправе только
                    // сейчас (?deleteMessages=1) или вместе с аккаунтом.
                } else {
                    // Строка чата с ботом блокируется раньше его сообщений (как у
                    // ответа бота и отправки): chats → messages.
                    await client.query('SELECT id FROM chats WHERE id = $1 AND user_id = $2 FOR UPDATE', [chat.id, userId]);
                    const deleted = await client.query('DELETE FROM messages WHERE chat_id = $1 AND room_id IS NULL RETURNING file_url', [chat.id]);
                    state.fileUrls = deleted.rows.map(r => r.file_url);
                    await client.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chat.id, userId]);
                }
                return state;
            });
            if (!outcome) return res.json({ success: false, message: 'Не авторизован' });
            removeUploadedFiles(outcome.fileUrls);
            unsubscribeUserFromChat(userId, chat.id, chat.room_id);
            // Удалённые при выходе сообщения исчезают у остальных сразу.
            for (const id of outcome.deletedIds) {
                io.to(getSocketRoomKey(null, chat.room_id)).emit('messageDeleted', { id: String(id), room_id: chat.room_id });
            }
            if (outcome.roomSurvived) notifyRoomMembersChanged(chat.room_id, { inviteRotated: true });
            for (const request of outcome.droppedRequests) notifyJoinRequestDecided(request.user_id, { requestId: request.id, approved: false });
            notifyChatListChanged(userId);
            res.json({ success: true });
        } catch (error) {
            if (respondIfDeadlock(res, error)) return;
            logError('Delete chat error', error);
            res.json({ success: false, message: 'Ошибка удаления чата' });
        }
    });
}

module.exports = { register };
