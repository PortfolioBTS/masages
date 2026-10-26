'use strict';
// Анонимные аккаунты: коды и имена, создание пользователя с чатом бота, данные аккаунта для
// API, полное удаление пользователя и чистка аккаунтов с истёкшим сроком. Вынесено из server.js.

const { generateUniqueCode, randomString } = require('../../lib/security-utils');
const { describeAnonLifetime, ANON_LIFETIMES } = require('../../lib/anon-lifetime');
// Встроенное хранилище публичных E2EE-ключей (lib/key-store.js): ключи удалённого пользователя.
const { deleteKeysForUser } = require('../../lib/e2ee-keys');
const { deleteQuotaRows } = require('../../lib/upload-quota');
// Onion-сервис (контейнер tor-service/)
const { onionUrlFor } = require('../../lib/tor-support');
const { logError } = require('../../lib/log-error');
// Пачки до исчерпания с бюджетом времени прохода (ревью W7 R2.11).
const { drainBatches } = require('../../lib/drain-batches');

// Чистка просроченных анонимов: пачка и бюджет одного прохода. Бюджет меньше интервала
// задачи (5 минут, src/jobs/index.js): следующий проход не ждёт, пока кончится этот.
const PURGE_BATCH_SIZE = 200;
const PURGE_BUDGET_MS = 4 * 60 * 1000;
const { resetInviteAfterLeave } = require('./rooms');
const { writeMessageText } = require('./messages');

// Новый аккаунт и его чат с ботом с приветствием — внутри транзакции client.
// lastActiveAt — корзина активности момента регистрации (lib/anon-lifetime.js).
// Отметки о прочтении у нового аккаунта выключены явно, а не через DEFAULT
// колонки: ответ регистрации обещает readReceipts: false. Текст приветствия
// выбирает вызывающий. Возвращает { userId, botChatId } — id чата с ботом
// уходит клиенту.
async function insertUserWithBotChat(client, { uniqueCode, username, anonLifetime, lastActiveAt, welcomeText }) {
    const userResult = await client.query(
        `INSERT INTO users (unique_code, username, avatar, anon_lifetime, last_active_at, read_receipts)
         VALUES ($1, $2, $3, $4, $5, FALSE)
         RETURNING id`,
        [uniqueCode, username, '#667EEA', anonLifetime, lastActiveAt]
    );
    const userId = userResult.rows[0].id;
    // Счётчик seq чата с ботом и маркер прочитанного начинаются с одной и той
    // же случайной базы: непрочитанным станет только приветствие, которое
    // вставляется следом.
    const botResult = await client.query(
        `WITH base AS (SELECT nyxo_random_seq_base() AS seq)
         INSERT INTO chats (user_id, name, avatar, online, is_bot, msg_seq, last_read_seq)
         SELECT $1::int, $2::text, $3::text, $4::int, $5::int, base.seq, base.seq FROM base
         RETURNING id`,
        [userId, 'Бот Помощник', 'Б', 1, 1]
    );
    const botChatId = botResult.rows[0].id;
    await client.query(
        `INSERT INTO messages (chat_id, user_id, text, sent, status) VALUES ($1, $2, $3, 0, 'read')`,
        [botChatId, userId, writeMessageText(welcomeText, { room_id: null, chat_id: botChatId, user_id: userId })]
    );
    return { userId, botChatId };
}

// «Не вошёл» (контракт этапа 1, §3): reason/expired — только если сессия
// была, но аккаунт удалён по сроку или сессия недействительна. Клиент
// покажет «данные удалены по сроку», а не просто экран входа.
function signedOutResponse(req) {
    const body = { authenticated: false };
    if (req.authEnded) {
        body.reason = 'expired';
        body.expired = true;
    }
    body.onionUrl = onionUrlFor(req);
    return body;
}

// Адреса файлов удалённых строк — циклом, а не push(...rows): DELETE … RETURNING file_url возвращает строку на каждое
// сообщение, и на сотнях тысяч строк spread переполняет стек — удаление аккаунта откатывалось (повторное ревью W7, Н5).
function addFileUrls(list, rows) {
    for (const row of rows) list.push(row.file_url);
}

function createAccounts(ctx) {
    const {
        authorTags, metrics, removeUploadedFiles, io, userSocketCount, notifyRoomMembersChanged,
        notifyJoinRequestsChanged, notifyJoinRequestDecided, dbGet, dbAll, dbRun, withTransactionRetry,
        anonActivity,
    } = ctx;

    // Коды без смещения распределения — см. randomString в lib/security-utils.js.
    async function generateUniqueCodeAsync() {
        for (let attempts = 0; attempts < 100; attempts++) {
            const code = generateUniqueCode();
            const row = await dbGet('SELECT id FROM users WHERE unique_code = $1', [code]);
            if (!row) return code;
        }
        throw new Error('Could not generate unique code');
    }

    async function generateAnonymousUsernameAsync() {
        for (let attempts = 0; attempts < 100; attempts++) {
            const username = `Гость-${randomString('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 4)}`;
            const row = await dbGet('SELECT id FROM users WHERE username = $1', [username]);
            if (!row) return username;
        }
        throw new Error('Could not generate anonymous username');
    }

    // Поля аккаунта для ответов API — из строки users: срок и корзина последней
    // активности (её только что записал middleware после sessionMiddleware,
    // если корзина сменилась). anonExpiresAt — «когда удалится, если больше не
    // будет активности».
    async function loadAccount(userId) {
        const row = await dbGet(
            `SELECT username, unique_code, read_receipts, anon_lifetime,
                EXTRACT(EPOCH FROM last_active_at) * 1000 AS last_active_ms
         FROM users WHERE id = $1`,
            [userId]
        );
        if (!row) return null;
        return {
            id: userId,
            username: row.username,
            uniqueCode: row.unique_code,
            readReceipts: row.read_receipts,
            ...describeAnonLifetime({
                lifetime: row.anon_lifetime,
                lastActiveMs: row.last_active_ms === null ? null : Number(row.last_active_ms),
            }),
        };
    }

    // Полное удаление пользователя (POST /api/account/delete и его псевдоним
    // /api/logout, чистка по сроку): его сообщения (и их файлы) во ВСЕХ комнатах,
    // где он состоит, и в тех, откуда вышел, оставив там сообщения (user_left_rooms),
    // реакции, E2EE key-shares, участие в комнатах, его заявки на вступление,
    // опустевшие комнаты со всей историей и заявками в них, окна квоты вложений,
    // chats (chat_settings — каскадом), unread, сама строка users;
    // message_expiry и реакции на его сообщения уходят каскадом. Сообщения комнат
    // находятся по тегам автора (sealed-sender.md, 12.2): для каждой комнаты - теги
    // пользователя за все недели с создания аккаунта, по всем ключам сообщений. Одной
    // транзакцией — раньше это была серия отдельных DELETE, и первая же ошибка
    // FK (например, из e2ee_key_shares, который ссылается на users без каскада)
    // оставляла пользователя в БД навсегда. После COMMIT — файлы с диска,
    // сессии на всех устройствах, сокеты, публичные E2EE-ключи (встроенное
    // хранилище) и уведомление оставшимся участникам комнат.
    //
    // Порядок блокировок users → rooms → room_participants → chats → user_left_rooms →
    // upload_quota → messages (message-ordering.md, раздел 8.1) — тот же, что у
    // отправки, вступления и выхода из комнаты. При взаимной блокировке (40P01) транзакция повторяется
    // один раз (withTransactionRetry), поэтому результаты собираются заново на
    // каждой попытке.
    async function deleteUserAccount(userId) {
        const outcome = await withTransactionRetry(async (client) => {
            const result = { fileUrls: [], survivingRoomIds: [], requestRoomIds: [], droppedRequests: [] };
            // Блокировка строки пользователя: параллельная отправка сообщения
            // (она берёт users FOR KEY SHARE первым оператором) дождётся конца
            // удаления и получит «нет пользователя», а не оставит сообщение, которое
            // уже никто не удалит.
            const user = await client.query('SELECT id, created_at FROM users WHERE id = $1 FOR UPDATE', [userId]);
            if (user.rows.length === 0) return null;
            const rooms = await client.query('SELECT DISTINCT room_id FROM room_participants WHERE user_id = $1 ORDER BY room_id', [userId]);
            const roomIds = rooms.rows.map(r => r.room_id);
            // Комнаты, откуда он вышел, оставив там сообщения: их тоже надо почистить.
            const left = await client.query('SELECT room_id FROM user_left_rooms WHERE user_id = $1', [userId]);
            const messageRoomIds = [...new Set([...roomIds, ...left.rows.map(r => r.room_id)])].sort((a, b) => a - b);
            // Комнаты блокируются так же, как при выходе из чата (DELETE
            // /api/chats/:chatId): иначе одновременный выход последнего другого
            // участника оставил бы пустую комнату навсегда. Порядок по id — без
            // взаимных блокировок между двумя такими удалениями.
            if (messageRoomIds.length > 0) {
                await client.query('SELECT id FROM rooms WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE', [messageRoomIds]);
            }
            await client.query('DELETE FROM e2ee_key_shares WHERE sender_id = $1 OR recipient_id = $1', [userId]);
            await client.query('DELETE FROM e2ee_key_requests WHERE requester_id = $1', [userId]);
            await client.query('DELETE FROM room_participants WHERE user_id = $1', [userId]);
            // Сообщения бота уходят каскадом от своей строки chats (messages.chat_id ON DELETE
            // CASCADE), и RETURNING у явного DELETE ниже уже ничего не вернул бы: адреса
            // файлов снимаются ДО удаления чатов. Пока users заблокирована FOR UPDATE, новые
            // сообщения бота с файлами вставить некому.
            const botFiles = await client.query(
                'SELECT file_url FROM messages WHERE room_id IS NULL AND user_id = $1 AND file_url IS NOT NULL',
                [userId]
            );
            addFileUrls(result.fileUrls, botFiles.rows);
            await client.query('DELETE FROM chats WHERE user_id = $1', [userId]);
            // Сертификаты состава, где он субъект или подписавший, и подписанные приглашения комнат, из которых он уходит
            // (решение владельца, вопрос 17): код заменяется новым. Комнаты уже заблокированы выше.
            await client.query('DELETE FROM room_member_certs WHERE subject_id = $1 OR actor_id = $1', [userId]);
            for (const roomId of roomIds) await resetInviteAfterLeave(client, roomId);
            await client.query('DELETE FROM user_left_rooms WHERE user_id = $1', [userId]);
            // Окна квоты - по псевдонимам от текущего и всех прежних ключей сообщений.
            await deleteQuotaRows(client, authorTags.qkeysFor(userId));
            // Сообщения комнат - по (комната, теги): в строке user_id нет. Запросы по
            // комнате, а не одним массивом пар: у старого аккаунта тегов до 600 недель
            // на ключ, и массив из всех комнат сразу получился бы огромным.
            const now = Date.now();
            for (const roomId of messageRoomIds) {
                const tags = authorTags.tagsForAccount(roomId, userId, user.rows[0].created_at, now);
                const roomMessages = await client.query(
                    'DELETE FROM messages WHERE room_id = $1 AND author_tag = ANY($2::bytea[]) RETURNING file_url',
                    [roomId, tags]
                );
                addFileUrls(result.fileUrls, roomMessages.rows);
            }
            // Чат с ботом: сообщения владельца (в том числе ответы бота) каскадом уже ушли вместе
            // с чатом; это страховка на случай строки без чата.
            const botMessages = await client.query('DELETE FROM messages WHERE room_id IS NULL AND user_id = $1 RETURNING file_url', [userId]);
            addFileUrls(result.fileUrls, botMessages.rows);
            await client.query('DELETE FROM reactions WHERE user_id = $1', [userId]);
            const ownRequests = await client.query('DELETE FROM join_requests WHERE user_id = $1 RETURNING room_id', [userId]);
            result.requestRoomIds = [...new Set(ownRequests.rows.map(r => r.room_id))];

            if (messageRoomIds.length > 0) {
                const orphaned = await client.query(
                    `DELETE FROM messages m WHERE m.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = m.room_id)
                 RETURNING file_url`,
                    [messageRoomIds]
                );
                addFileUrls(result.fileUrls, orphaned.rows);
                // Заявки в опустевшие комнаты ушли бы и каскадом, но заявителям
                // надо сказать, что рассматривать их больше некому.
                const orphanedRequests = await client.query(
                    `DELETE FROM join_requests jr WHERE jr.room_id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = jr.room_id)
                 RETURNING id, user_id`,
                    [messageRoomIds]
                );
                result.droppedRequests = orphanedRequests.rows;
                const removedRooms = await client.query(
                    `DELETE FROM rooms r WHERE r.id = ANY($1::int[])
                   AND NOT EXISTS (SELECT 1 FROM room_participants rp WHERE rp.room_id = r.id)
                 RETURNING id`,
                    [messageRoomIds]
                );
                const removed = new Set(removedRooms.rows.map(r => r.id));
                result.survivingRoomIds = roomIds.filter(id => !removed.has(id));
            }
            await client.query('DELETE FROM users WHERE id = $1', [userId]);
            // Домен журнала ключей — после основного, в его порядке: kt_state FOR SHARE → identity_keys →
            // kt_pending (message-ordering.md, 8.1). Регистрация ключа и закрытие эпохи берут их так же,
            // поэтому взаимных блокировок нет. Prekey пользователя уходят следом за identity_keys, как
            // и в регистрации; nonce обязательства удаляется вместе со строкой identity_keys, и записи
            // журнала перестают связываться с ключами. Запись kt_pending в эпоху уже не попадёт.
            await client.query('SELECT 1 FROM kt_state FOR SHARE');
            await client.query('DELETE FROM identity_keys WHERE user_id = $1', [userId]);
            for (const table of ['pq_one_time_prekeys', 'one_time_prekeys', 'signed_pq_prekeys', 'signed_prekeys']) {
                await client.query(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
            }
            await client.query('DELETE FROM kt_pending WHERE user_id = $1', [userId]);
            return result;
        });
        if (!outcome) return false;
        const { fileUrls, survivingRoomIds, requestRoomIds, droppedRequests } = outcome;

        removeUploadedFiles(fileUrls);
        anonActivity.forget(userId);
        io.in('user:' + userId).disconnectSockets(true);
        for (const roomId of survivingRoomIds) notifyRoomMembersChanged(roomId, { inviteRotated: true });
        for (const roomId of requestRoomIds) notifyJoinRequestsChanged(roomId);
        for (const request of droppedRequests) notifyJoinRequestDecided(request.user_id, { requestId: request.id, approved: false });
        deleteKeysForUser(userId);
        // Сессии на других устройствах. После COMMIT и отдельно: таблицы session
        // может ещё не быть (42P01), а ошибка внутри транзакции откатила бы всё.
        try {
            await dbRun(`DELETE FROM session WHERE sess->>'userId' = $1`, [String(userId)]);
        } catch (error) {
            if (error.code !== '42P01') logError('[Account] Не удалось удалить сессии', error);
        }
        return true;
    }

    // Анонимные аккаунты, срок которых вышел (lib/anon-lifetime.js): выбранный
    // срок без активности по users.last_active_at (корзина, округлённая вверх,
    // — граница та же, что у isAnonExpired). Потолка от создания нет. Раньше
    // удаление шло только через 5 часов после создания и откладывалось, пока
    // жива строка в таблице session, — даже если вкладку давно закрыли.
    // Пользователи с открытым сокетом на этом экземпляре не трогаются: их
    // активность продлевает touch, а сокеты других экземпляров продлевают
    // last_active_at в БД сами. Время — часы сервера, как у записи корзин.
    // Ошибка выборки — наверх, в runExclusive (lib/jobs): такой проход не
    // засчитывается. Проход берёт пачки, пока они полные (раньше — одна пачка в 200
    // строк раз в 5 минут, и при наплыве аккаунты жили дольше срока), но не дольше
    // PURGE_BUDGET_MS; остаток — следующему проходу. Аккаунт, который не удалился, в
    // этом проходе больше не выбирается.
    async function purgeExpiredAnonymousUsers({ batchSize = PURGE_BATCH_SIZE, budgetMs = PURGE_BUDGET_MS } = {}) {
        const now = Date.now();
        const deadline = (lifetime) => new Date(now - ANON_LIFETIMES[lifetime] * 1000);
        const result = await drainBatches({
            batchSize, budgetMs, skipIds: userSocketCount.keys(),
            fetchBatch: (skipIds, limit) => dbAll(`
        SELECT id FROM users
        WHERE ((anon_lifetime = 'tab' AND last_active_at <= $1)
            OR (anon_lifetime = 'day' AND last_active_at <= $2)
            OR (anon_lifetime = 'week' AND last_active_at <= $3))
          AND NOT (id = ANY($4::int[]))
        ORDER BY last_active_at
        LIMIT $5
    `, [deadline('tab'), deadline('day'), deadline('week'), skipIds, limit]),
            handle: (row) => deleteUserAccount(row.id),
            onError: (err) => logError('[Anon] Не удалось удалить просроченный аккаунт', err),
        });
        // В лог — только счётчики, без id анонимных аккаунтов.
        metrics.accountsDeleted('expired', result.processed);
        if (result.processed > 0) console.log(`[Anon] Удалено просроченных анонимных аккаунтов: ${result.processed}`);
        if (!result.exhausted) console.log('[Anon] Проход чистки упёрся в предел времени — остаток удалит следующий');
    }

    return {
        generateUniqueCodeAsync, generateAnonymousUsernameAsync, loadAccount, deleteUserAccount,
        purgeExpiredAnonymousUsers,
    };
}

module.exports = { createAccounts, insertUserWithBotChat, signedOutResponse };
