'use strict';
// Чаты и сообщения: список чатов, история, отметка «прочитано», отправка сообщения и создание чата
// (пять маршрутов подряд — как в прежнем порядке регистрации). Вынесено из server.js.

const { sanitizeText } = require('../../../lib/privacy');
const { generateInviteCode } = require('../../../lib/security-utils');
const { isClientOutdated: isOutdatedProto } = require('../../../lib/proto');
// Бот-помощник: ответ по теме запроса, приветствие нового аккаунта и подписи
// кнопок-подсказок — чистые функции без БД (lib/bot-guide.js).
const botGuide = require('../../../lib/bot-guide');
const { logError } = require('../../../lib/log-error');
// Id и курсоры сообщений, тела ошибок 400/409 (docs/security/message-ordering.md).
const {
    CLIENT_OUTDATED, parseSeq, BAD_SEQ, parseClientMessageId, BAD_MESSAGE_ID, isMessageIdConflict,
    ID_CONFLICT, insertDroppingGoneReply,
} = require('../../../lib/message-ids');
// Форма E2EE-конверта и тела отказов 400 для комнат и бота (R7).
const { MAX_ENVELOPE_LENGTH } = require('../../../lib/e2ee-envelope');
const {
    readMessageText, roomMessagePayload, apiMessage, e2eePolicyViolation, messageFromRow,
    respondRoomSendError, writeMessageText,
} = require('../../services/messages');
const { toPositiveInt, isNonEmptyString } = require('../params');
const { chatScope } = require('../../services/chats');
const { parseRequestedExpiry } = require('../../services/expiry');
const { withMessageIdRetry } = require('../../db/transactions');
// База недоступна или занята — 503 busy с Retry-After (lib/db-errors.js).
const { respondIfDbBusy } = require('../../../lib/db-errors');
const { getSocketRoomKey } = require('../../realtime/io');

// Список чатов с последним сообщением и числом непрочитанных.
//
// Раньше это были ПЯТЬ коррелированных подзапросов на каждый чат, каждый с
// условием вида (room_id = X) OR (chat_id = Y). Такое OR не может
// использовать индекс, поэтому каждый подзапрос проходил ВСЮ таблицу
// messages: чатов × 5 полных проходов на каждое открытие приложения, и ещё
// раз — на каждое входящее сообщение в любом другом чате. С ростом таблицы
// это и было главным источником "всё очень медленно".
//
// Теперь для каждого чата работает только одна из двух веток (вторая
// отсекается условием на c.room_id), и обе идут по уникальным индексам
// порядка idx_messages_room_seq/idx_messages_chat_seq: последнее сообщение —
// одна запись индекса от конца (ORDER BY seq DESC LIMIT 1), непрочитанные —
// только записи после last_read_seq (не больше 100). Сравнение seq — только
// внутри области (комнаты или чата с ботом).
//
// Последнее сообщение комнаты — только из видимых участнику (seq больше его
// visible_from_seq); непрочитанные и так начинаются после last_read_seq,
// который при вступлении ставится на ту же границу.
// lm_room_id/lm_chat_id/lm_user_id нужны только для AAD расшифровки (чат с ботом)
// и клиенту не отдаются; предпросмотр комнаты не расшифровывается вовсе (там
// всегда E2EE-конверт).
//
// Непрочитанное: в комнате — всё после личного маркера last_read_seq (своих
// сообщений в нём нет: отправитель сдвигает маркер сам, sealed-sender.md, 8.3, а
// автора в строке комнаты нет — отфильтровать «свои» по user_id нечем); у чата с
// ботом — ответы бота (sent = 0). Закреплённые — сверху; дальше по времени последнего
// сообщения (оно хранится с точностью до минуты, так что при равных минутах
// порядок стабилен, но произволен); чаты без сообщений — по времени создания
// (id случайные и порядка не несут). Архивные остаются в списке — клиент
// показывает их отдельным разделом.
//
// member_count и expiry_seconds — в этом же запросе, без запроса на
// каждый чат: число участников — index-only scan по уникальному индексу
// room_participants (room_id, user_id), таймер — по первичным
// ключам room_settings/chat_settings. expiry_seconds — действующий срок:
// общий таймер комнаты (для бота — личный), иначе DEFAULT_MESSAGE_EXPIRY_SECONDS
// ($2), иначе 0. Код выключенного приглашения не отдаётся.
const CHAT_LIST_SQL = `
    SELECT c.id, c.name, c.avatar, c.online, c.is_bot, c.room_id,
           CASE WHEN r.invite_disabled THEN NULL ELSE r.code END AS invite_code,
           c.pinned, c.muted, c.archived,
           mc.cnt AS member_count,
           COALESCE(CASE WHEN c.room_id IS NOT NULL THEN rs.default_message_expiry ELSE cs.default_message_expiry END, $2::numeric) AS expiry_seconds,
           lm.id AS last_message_id, lm.seq AS last_message_seq,
           lm.text AS last_message, lm.encrypted AS last_message_encrypted,
           lm.message_type AS last_message_type, lm.created_at AS last_created_at,
           lm.room_id AS lm_room_id, lm.chat_id AS lm_chat_id, lm.user_id AS lm_user_id,
           COALESCE(uc.cnt, 0) AS unread
    FROM chats c
    LEFT JOIN rooms r ON r.id = c.room_id
    LEFT JOIN room_participants rp ON rp.room_id = c.room_id AND rp.user_id = c.user_id
    LEFT JOIN room_settings rs ON rs.room_id = c.room_id
    LEFT JOIN chat_settings cs ON cs.chat_id = c.id AND c.room_id IS NULL
    LEFT JOIN LATERAL (
        SELECT COUNT(*)::int AS cnt FROM room_participants p WHERE p.room_id = c.room_id
    ) mc ON c.room_id IS NOT NULL
    LEFT JOIN LATERAL (
        SELECT * FROM (
            (SELECT x.id, x.seq, x.text, x.encrypted, x.message_type, x.created_at, x.room_id, x.chat_id, x.user_id
               FROM messages x
              WHERE c.room_id IS NOT NULL AND x.room_id = c.room_id AND x.seq > COALESCE(rp.visible_from_seq, 0)
              ORDER BY x.seq DESC LIMIT 1)
            UNION ALL
            (SELECT x.id, x.seq, x.text, x.encrypted, x.message_type, x.created_at, x.room_id, x.chat_id, x.user_id
               FROM messages x
              WHERE c.room_id IS NULL AND x.chat_id = c.id AND x.room_id IS NULL
              ORDER BY x.seq DESC LIMIT 1)
        ) last_rows LIMIT 1
    ) lm ON TRUE
    LEFT JOIN LATERAL (
        SELECT COUNT(*) AS cnt FROM (
            (SELECT 1 FROM messages m
              WHERE c.room_id IS NOT NULL AND m.room_id = c.room_id
                AND m.seq > c.last_read_seq
              LIMIT 100)
            UNION ALL
            (SELECT 1 FROM messages m
              WHERE c.room_id IS NULL AND m.chat_id = c.id AND m.room_id IS NULL
                AND m.seq > c.last_read_seq AND m.sent = 0
              LIMIT 100)
        ) unread_rows
    ) uc ON TRUE
    WHERE c.user_id = $1
    ORDER BY c.pinned DESC, lm.created_at DESC NULLS LAST, c.created_at DESC NULLS LAST, c.id DESC
`;

const MESSAGES_PAGE_SIZE = 100;
const MAX_MESSAGES_PAGE_SIZE = 200;

function register(app, ctx) {
    const {
        GLOBAL_DEFAULT_EXPIRY_SECONDS, INVITE_TTL_SECONDS, io, subscribeUserToChat, notifyChatListChanged,
        emitVisibleRoomMessage, dbGet, dbAll, withTransactionRetry, newMessageExpirySeconds, getOwnChat,
        markChatRead, unarchiveForRecipients, insertChatMessage, insertRoomMessage, describeMessageIdUse,
        advanceSenderMarker, scheduleBotReply,
    } = ctx;

    app.get('/api/chats', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        try {
            const chats = await dbAll(CHAT_LIST_SQL, [req.session.userId, GLOBAL_DEFAULT_EXPIRY_SECONDS]);
            // Предпросмотр E2EE-сообщения в списке чатов не расшифровываем —
            // это потребовало бы Sender Key каждого отправителя каждого чата
            // ещё до открытия чата. Показываем нейтральную подпись, конверт
            // клиенту не отдаём вовсе (script.js подставляет плейсхолдер).
            res.json({
                success: true,
                chats: chats.map(({ lm_room_id, lm_chat_id, lm_user_id, ...c }) => ({
                    ...c,
                    last_message_id: c.last_message_id === null ? null : String(c.last_message_id),
                    last_message_seq: c.last_message_seq === null ? null : Number(c.last_message_seq),
                    unread: Number(c.unread),
                    expiry_seconds: Number(c.expiry_seconds) || 0,
                    // Строка комнаты - всегда E2EE-конверт (CHECK messages_room_e2ee), её
                    // предпросмотр не отдаётся; у чата с ботом - открытый текст.
                    last_message: c.last_message_encrypted || lm_room_id
                        ? null
                        : readMessageText(c.last_message, { room_id: lm_room_id, chat_id: lm_chat_id, user_id: lm_user_id }),
                })),
            });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Get chats error', error);
            res.json({ success: false, message: 'Ошибка загрузки чатов' });
        }
    });

    // История чата постранично: последние MESSAGES_PAGE_SIZE сообщений, более
    // старые — через ?beforeSeq=<seq самого старого из загруженных>. Раньше
    // отдавалась вся история целиком (плюс IN-список из всех её id для
    // реакций), и открытие большого чата становилось всё медленнее.
    // Старый параметр ?before=<id> — 400 client-outdated: id порядка не задаёт
    // (раздел 14 контракта).
    app.get('/api/messages/:chatId', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        if (req.query.before !== undefined) return res.status(400).json(CLIENT_OUTDATED);
        let beforeSeq = null;
        if (req.query.beforeSeq !== undefined) {
            beforeSeq = parseSeq(req.query.beforeSeq);
            if (!beforeSeq) return res.status(400).json(BAD_SEQ);
        }
        try {
            const chat = await getOwnChat(req.params.chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });

            const limit = Math.min(toPositiveInt(req.query.limit) || MESSAGES_PAGE_SIZE, MAX_MESSAGES_PAGE_SIZE);
            const scope = chatScope(chat);
            const params = [scope.value, limit + 1, Number(chat.visible_from_seq) || 0];
            if (beforeSeq) params.push(beforeSeq);

            // Цитата ответа берётся только из ТОГО ЖЕ чата, только если она не
            // удалена и видна участнику (seq новее его visible_from_seq). Раньше
            // reply_to_id не проверялся при отправке, и подставив чужой id,
            // можно было получить расшифрованный текст сообщения из любого
            // чужого чата; удалённые сообщения тоже продолжали "светиться" в
            // цитатах, а новичок комнаты видел в цитатах историю до вступления.
            // Сначала id страницы (index-only scan по idx_messages_*_seq), потом
            // сами строки по первичному ключу.
            //
            // Сообщения КОМНАТЫ отдаются без автора (sealed-sender.md, 8.1): без JOIN
            // users, без user_id, chat_id, sender_username, sender_avatar и без поля
            // mine — сервер не считает тег на каждую строку, а сторону пузыря не
            // расшифрованного сообщения клиент определяет по умолчанию как «чужое».
            // author_tag нужен только для AAD расшифровки строки и наружу не уходит.
            // Цитата комнаты — { id, seq, text (конверт), encrypted }: автора цитаты
            // клиент узнаёт, расшифровав её.
            const pageCte = `
            WITH page AS MATERIALIZED (
                SELECT m.id, m.seq FROM messages m
                WHERE ${scope.where('m')} AND m.seq > $3 ${beforeSeq ? 'AND m.seq < $4' : ''}
                ORDER BY m.seq DESC
                LIMIT $2
            )`;
            let rows;
            if (chat.room_id) {
                rows = await dbAll(`${pageCte}
                SELECT m.id, m.seq, m.room_id, m.author_tag, m.text, m.file_url, m.file_name, m.file_type,
                       m.message_type, m.sent, m.status, m.edited_at, m.encrypted, m.created_at,
                       m.reply_to_id AS reply_target_id,
                       rt.id AS reply_to_id, rt.seq AS reply_to_seq, rt.text AS reply_to_text,
                       rt.author_tag AS reply_to_author_tag, rt.room_id AS reply_to_room_id,
                       rt.encrypted AS reply_to_encrypted
                FROM page
                JOIN messages m ON m.id = page.id
                LEFT JOIN messages rt ON rt.id = m.reply_to_id AND ${scope.where('rt')} AND rt.seq > $3
                ORDER BY m.seq DESC
            `, params);
            } else {
                rows = await dbAll(`${pageCte}
                SELECT m.id, m.seq, m.chat_id, m.room_id, m.user_id, m.text, m.file_url, m.file_name, m.file_type,
                       m.message_type, m.sent, m.status, m.edited_at, m.encrypted, m.created_at,
                       m.reply_to_id AS reply_target_id,
                       u.username AS sender_username, u.avatar AS sender_avatar,
                       rt.id AS reply_to_id, rt.text AS reply_to_text, rt.user_id AS reply_to_sender_id,
                       rt.room_id AS reply_to_room_id, rt.chat_id AS reply_to_chat_id,
                       rt.encrypted AS reply_to_encrypted,
                       ru.username AS reply_to_sender_username, ru.avatar AS reply_to_sender_avatar
                FROM page
                JOIN messages m ON m.id = page.id
                JOIN users u ON u.id = m.user_id
                LEFT JOIN messages rt ON rt.id = m.reply_to_id AND ${scope.where('rt')} AND rt.seq > $3
                LEFT JOIN users ru ON ru.id = rt.user_id
                ORDER BY m.seq DESC
            `, params);
            }

            const hasMore = rows.length > limit;
            if (hasMore) rows.length = limit;
            rows.reverse();

            // Реакции: [{ emoji, count, mine }] — сколько человек поставили эмодзи и стоит ли оно
            // у читающего (по нему клиент после перезагрузки умеет снять реакцию). Кто именно
            // поставил, не отдаётся.
            const reactionsMap = {};
            if (rows.length > 0) {
                const reactions = await dbAll(
                    `SELECT message_id, emoji, COUNT(*)::int AS count, BOOL_OR(user_id = $2) AS mine
                     FROM reactions WHERE message_id = ANY($1::int[]) GROUP BY message_id, emoji ORDER BY message_id, emoji`,
                    [rows.map(m => m.id), userId]
                );
                reactions.forEach(r => {
                    (reactionsMap[r.message_id] ||= []).push({ emoji: r.emoji, count: r.count, mine: r.mine });
                });
            }

            const messages = chat.room_id
                ? rows.map(row => {
                    const text = readMessageText(row.text, row);
                    const replyTo = row.reply_to_id
                        ? {
                            id: row.reply_to_id, seq: Number(row.reply_to_seq),
                            text: readMessageText(row.reply_to_text, { room_id: row.reply_to_room_id, id: row.reply_to_id, author_tag: row.reply_to_author_tag }),
                            encrypted: row.reply_to_encrypted,
                        }
                        : (row.reply_target_id ? { id: row.reply_target_id, deleted: true } : null);
                    return { ...roomMessagePayload(row, text, { replyTo }), reactions: reactionsMap[row.id] || [] };
                })
                : rows.map(({ reply_target_id, reply_to_text, reply_to_sender_id, reply_to_room_id, reply_to_chat_id,
                    reply_to_encrypted, reply_to_sender_username, reply_to_sender_avatar, ...m }) => apiMessage({
                    ...m,
                    text: readMessageText(m.text, m),
                    reactions: reactionsMap[m.id] || [],
                    reply_to: m.reply_to_id ? {
                        id: m.reply_to_id,
                        text: readMessageText(reply_to_text, { room_id: reply_to_room_id, chat_id: reply_to_chat_id, user_id: reply_to_sender_id }),
                        sender_id: reply_to_sender_id, encrypted: reply_to_encrypted,
                        sender_username: reply_to_sender_username, sender_avatar: reply_to_sender_avatar
                    } : (reply_target_id ? { id: reply_target_id, deleted: true } : null)
                }));

            // Первая (самая свежая) страница = пользователь видит конец чата. Отметка
            // прочитанного — побочное действие загрузки: её сбой (взаимная блокировка с
            // отправкой, таймаут блокировки; ревью W7 R2.9) не должен ломать саму историю —
            // клиент отметит прочитанное позже через POST /api/chats/:chatId/read.
            if (!beforeSeq && messages.length > 0) {
                try {
                    await markChatRead(chat, userId, messages[messages.length - 1].seq);
                } catch (err) {
                    logError('[Chats] Не удалось отметить прочитанное при загрузке истории', err);
                }
            }

            res.json({
                success: true,
                messages,
                hasMore,
                chat: {
                    id: chat.id, room_id: chat.room_id, name: chat.name, avatar: chat.avatar, is_bot: chat.is_bot,
                    // Подписи кнопок-подсказок — только у чата с ботом. Их отдаёт сервер,
                    // чтобы кнопки и ключевые слова бота не расходились (lib/bot-guide.js).
                    ...(chat.is_bot ? { quickReplies: [...botGuide.QUICK_REPLIES] } : {}),
                },
            });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Get messages error', error);
            res.json({ success: false, message: 'Ошибка загрузки сообщений' });
        }
    });

    // Клиент сообщает, что показал пользователю новые сообщения открытого чата
    // (пришедшие по сокету), — иначе они считались бы непрочитанными. Тело —
    // { upToSeq }; старое { upToId } — 400 client-outdated.
    app.post('/api/chats/:chatId/read', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        if (req.body?.upToSeq === undefined && req.body?.upToId !== undefined) return res.status(400).json(CLIENT_OUTDATED);
        const upToSeq = parseSeq(req.body?.upToSeq);
        if (!upToSeq) return res.json({ success: false, message: 'Некорректный upToSeq' });
        const chat = await getOwnChat(req.params.chatId, userId);
        if (!chat) return res.json({ success: false, message: 'Чат не найден' });
        // Не даём отметить прочитанным больше, чем реально есть (и видно
        // участнику) в этом чате.
        const scope = chatScope(chat);
        const latest = await dbGet(
            `SELECT MAX(m.seq) AS seq FROM messages m WHERE ${scope.where('m')} AND m.seq <= $2 AND m.seq > $3`,
            [scope.value, upToSeq, Number(chat.visible_from_seq) || 0]
        );
        await markChatRead(chat, userId, latest && latest.seq);
        res.json({ success: true });
    });

    app.post('/api/messages', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        // Общий признак версии клиента (message-ordering.md, 14.1) — первая проверка
        // запроса, до остальных: устаревшая вкладка получает одну понятную ошибку.
        if (isOutdatedProto(req.body?.proto)) return res.status(400).json(CLIENT_OUTDATED);
        const { chatId, text, replyToId } = req.body || {};
        const encrypted = req.body?.encrypted === true;
        if (!isNonEmptyString(text) || !toPositiveInt(chatId)) return res.json({ success: false, message: 'Введите текст сообщения' });
        // У E2EE-сообщений text — это JSON-конверт (senderKeyId/iv/ct/подпись,
        // см. public/e2ee.js), а не читаемый текст: он больше обычного
        // сообщения той же "длины" за счёт base64 и служебных полей.
        const maxLen = encrypted ? MAX_ENVELOPE_LENGTH : 4000;
        if (text.length > maxLen) return res.json({ success: false, message: `Сообщение не может быть длиннее ${maxLen} символов` });
        let requestedExpiry;
        try {
            requestedExpiry = parseRequestedExpiry(req.body?.expirySeconds);
        } catch (err) {
            return res.json({ success: false, message: err.message });
        }

        try {
            const chat = await getOwnChat(chatId, userId);
            if (!chat) return res.json({ success: false, message: 'Чат не найден' });

            // Сообщение комнаты без clientMessageId — устаревшая вкладка: 400
            // client-outdated; неверный формат — ошибка клиента: 400 bad-message-id.
            // Чат с ботом поле игнорирует: id выдаёт DEFAULT.
            let clientId = null;
            if (chat.room_id) {
                const raw = req.body.clientMessageId;
                if (raw === undefined || raw === null || raw === '') return res.status(400).json(CLIENT_OUTDATED);
                clientId = parseClientMessageId(raw);
                if (clientId === null) return res.status(400).json(BAD_MESSAGE_ID);
            }

            // Комната — только конверт правильной формы, бот — только открытый текст
            // (старая вкладка, не знающая про обязательное шифрование, получит
            // просьбу обновить страницу).
            const violation = e2eePolicyViolation(chat, encrypted, text.trim());
            if (violation) return res.status(400).json(violation);

            // Для E2EE-конверта sanitizeText не нужен и вреден по смыслу: это
            // не человеческий текст, а base64/JSON, который клиент должен
            // получить обратно байт-в-байт для расшифровки.
            const safeText = encrypted ? text.trim() : sanitizeText(text.trim());
            if (!safeText) return res.json({ success: false, message: 'Введите текст сообщения' });

            // Отвечать можно только на видимое отправителю сообщение из ЭТОГО же
            // чата (иначе ответ на старый id вытащил бы в цитату текст из истории
            // до вступления). Удалённое сообщение строки уже не имеет. Цитата
            // комнаты — { id, seq, text (конверт), encrypted }: автора клиент узнаёт
            // сам, расшифровав цитату (sealed-sender.md, 8.1); у чата с ботом — как раньше.
            const scope = chatScope(chat);
            let replyTo = null;
            const replyTargetId = toPositiveInt(replyToId);
            if (replyTargetId) {
                const visibleFrom = Number(chat.visible_from_seq) || 0;
                if (chat.room_id) {
                    const target = await dbGet(
                        `SELECT m.id, m.seq, m.text, m.room_id, m.author_tag, m.encrypted
                     FROM messages m WHERE m.id = $1 AND ${scope.where('m', '$2')} AND m.seq > $3`,
                        [replyTargetId, scope.value, visibleFrom]
                    );
                    if (target) {
                        replyTo = { id: target.id, seq: Number(target.seq), text: readMessageText(target.text, target), encrypted: target.encrypted };
                    }
                } else {
                    const target = await dbGet(
                        `SELECT m.id, m.text, m.room_id, m.chat_id, m.user_id, m.encrypted, u.username, u.avatar
                     FROM messages m JOIN users u ON u.id = m.user_id
                     WHERE m.id = $1 AND ${scope.where('m', '$2')} AND m.seq > $3`,
                        [replyTargetId, scope.value, visibleFrom]
                    );
                    if (target) {
                        replyTo = {
                            id: target.id, text: readMessageText(target.text, target), sender_id: target.user_id,
                            encrypted: target.encrypted, sender_username: target.username, sender_avatar: target.avatar,
                        };
                    }
                }
            }

            const expirySeconds = await newMessageExpirySeconds(chat, requestedExpiry);

            if (chat.room_id) {
                const roomId = chat.room_id;
                let outcome;
                try {
                    // Цель ответа удалили после проверки видимости — сообщение уходит без ответа (R2.8).
                    outcome = await insertDroppingGoneReply(() => insertRoomMessage({
                        userId, roomId, id: clientId, plainText: safeText, expirySeconds,
                        fields: { message_type: 'text', sent: 1, status: 'sent', reply_to_id: replyTo ? replyTo.id : null, encrypted },
                    }), () => { replyTo = null; });
                } catch (err) {
                    if (isMessageIdConflict(err)) {
                        // Вставка откатилась целиком (в том числе приращение seq). Тот же
                        // запрос — 200 с сохранённой строкой, без повторной рассылки; иначе 409.
                        const use = await describeMessageIdUse({ id: clientId, roomId, userId, expectedText: safeText, file: false });
                        if (use.status === 'duplicate') {
                            return res.json({ success: true, message: messageFromRow(use.row, safeText, replyTo) });
                        }
                        return res.status(409).json(ID_CONFLICT);
                    }
                    throw err;
                }
                if (outcome.error) return respondRoomSendError(res, outcome.error);

                // text уже известен в открытом виде (safeText) — не расшифровываем то,
                // что сами только что зашифровали, и не перечитываем строку из БД.
                const row = {
                    id: outcome.row.id, seq: outcome.row.seq, room_id: roomId, file_url: null, file_name: null, file_type: null,
                    message_type: 'text', sent: 1, status: 'sent', edited_at: null, encrypted, created_at: outcome.row.created_at,
                };
                await advanceSenderMarker(chat, row.seq);
                // Новичкам, вступившим уже после этого сообщения, событие не уходит.
                await emitVisibleRoomMessage('newMessage', roomId, userId, row.seq, roomMessagePayload(row, safeText, { replyTo }));
                res.json({ success: true, message: roomMessagePayload(row, safeText, { replyTo, mine: true }) });
                unarchiveForRecipients(chat, userId);
                return;
            }

            // Чат с ботом: id по DEFAULT, при гонке или попадании в надгробие — один повтор.
            const fields = {
                chat_id: chat.id, room_id: null, user_id: userId,
                text: writeMessageText(safeText, { room_id: null, chat_id: chat.id, user_id: userId }),
                message_type: 'text', sent: 1, status: 'sent',
                reply_to_id: replyTo ? replyTo.id : null, encrypted,
            };
            const inserted = await insertDroppingGoneReply(
                () => withMessageIdRetry(() => insertChatMessage(userId, fields, expirySeconds)),
                () => { replyTo = null; fields.reply_to_id = null; }
            );
            // Нет строки пользователя: аккаунт удалён, пока шёл запрос.
            if (!inserted) return res.status(401).json({ success: false, message: 'Не авторизован' });

            // text уже известен в открытом виде (safeText) — не расшифровываем то,
            // что сами только что зашифровали, и не перечитываем строку из БД.
            const message = apiMessage({
                id: inserted.id, seq: inserted.seq, chat_id: chat.id, room_id: null, user_id: userId,
                text: safeText, file_url: null, file_name: null, file_type: null,
                message_type: 'text', sent: 1, status: 'sent', edited_at: null,
                encrypted, created_at: inserted.created_at,
                reply_to_id: replyTo ? replyTo.id : null, reply_to: replyTo, reactions: [],
                sender_username: req.session.username, sender_avatar: req.session.avatar || '',
            });
            io.to(getSocketRoomKey(chat.id, null)).emit('newMessage', message);
            res.json({ success: true, message });

            // Чат с ботом ходит открытым текстом: конверт сюда не принимается (выше).
            if (chat.is_bot) scheduleBotReply(chat, safeText);
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Send message error', error);
            res.json({ success: false, message: 'Ошибка отправки' });
        }
    });

    app.post('/api/chats', async (req, res) => {
        const userId = req.session.userId;
        if (!userId) return res.json({ success: false, message: 'Не авторизован' });
        const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
        if (!name) return res.json({ success: false, message: 'Введите имя чата' });
        if (name.length > 64) return res.json({ success: false, message: 'Название чата не может быть длиннее 64 символов' });

        const avatar = name.charAt(0).toUpperCase();
        try {
            const roomCode = generateInviteCode();
            // Порядок блокировок users → rooms → room_participants → chats
            // (message-ordering.md, раздел 8): строку создателя берём явно и
            // первой. Иначе внешние ключи room_participants и chats проверяли бы
            // users после rooms — в обратном порядке, чем удаление аккаунта.
            const created = await withTransactionRetry(async (client) => {
                const owner = await client.query('SELECT id FROM users WHERE id = $1 FOR KEY SHARE', [userId]);
                if (owner.rows.length === 0) return null; // аккаунт удалён между проверкой сессии и этим запросом
                const roomResult = await client.query(
                    `INSERT INTO rooms (name, code, code_expires_at) VALUES ($1, $2, NOW() + $3::integer * INTERVAL '1 second')
                 RETURNING id, msg_seq`,
                    [name, roomCode, INVITE_TTL_SECONDS]
                );
                const newRoomId = roomResult.rows[0].id;
                // Создатель видит всю историю (seq комнаты всегда больше 0), а
                // непрочитанного у пустой комнаты нет: маркер — её счётчик сейчас.
                await client.query('INSERT INTO room_participants (room_id, user_id, visible_from_seq) VALUES ($1, $2, 0)', [newRoomId, userId]);
                const chatResult = await client.query(
                    'INSERT INTO chats (user_id, room_id, name, avatar, online, is_bot, last_read_seq) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
                    [userId, newRoomId, name, avatar, 0, 0, roomResult.rows[0].msg_seq]
                );
                return { roomId: newRoomId, chatId: chatResult.rows[0].id };
            });
            if (!created) return res.json({ success: false, message: 'Не авторизован' });
            const { roomId, chatId } = created;
            subscribeUserToChat(userId, chatId, roomId);
            notifyChatListChanged(userId);
            res.json({ success: true, chat: { id: chatId, name, avatar, online: 0, is_bot: 0, room_id: roomId, invite_code: roomCode } });
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Create chat error', error);
            res.json({ success: false, message: 'Ошибка создания чата' });
        }
    });
}

module.exports = { register };
