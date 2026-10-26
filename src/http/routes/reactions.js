'use strict';
// Реакции на сообщения. Вынесено из server.js.

const { logError } = require('../../../lib/log-error');
const { toPositiveInt } = require('../params');
const { getSocketRoomKey } = require('../../realtime/io');
// База недоступна или занята — 503 busy с Retry-After (lib/db-errors.js).
const { respondIfDbBusy } = require('../../../lib/db-errors');

// В UI предлагается фиксированный набор из 5 эмодзи для реакций. Раньше на
// бэке проверялась только длина строки (≤10 символов), а не содержимое — это
// пропускало вход в message.reactions, который на фронте рендерится в
// innerHTML без escapeHtml (см. п.3 аудита). Теперь бэк принимает только
// эмодзи из этого списка.
const ALLOWED_REACTION_EMOJIS = new Set(['👍', '❤️', '😂', '😢', '🔥']);

// Версии итога реакции (повторное ревью клиента W7, RR-6). Ответ на POST/DELETE и события reactionChanged приходят
// клиенту в любом порядке (копия события автору уходит после ответа и после событий других, посчитанных позже), и
// более старый итог затирал более свежий. Поэтому изменения одного (сообщение, эмодзи) выстраиваются в очередь
// (изменение, подсчёт и версия — подряд, без чужих изменений между ними), а итог получает версию v — строго
// растущую в процессе и после рестарта (от часов, в микросекундах). Клиент применяет итог, только если v больше
// уже применённой. Сервер один (Railway, один процесс), поэтому очереди в памяти достаточно.
let lastReactionVersion = 0;
function nextReactionVersion() {
    lastReactionVersion = Math.max(lastReactionVersion + 1, Date.now() * 1000);
    return lastReactionVersion;
}

function createKeyQueue() {
    const tails = new Map();
    return function serialize(key, task) {
        const previous = tails.get(key) || Promise.resolve();
        const run = previous.then(task, task);
        const tail = run.then(() => {}, () => {});
        tails.set(key, tail);
        tail.then(() => { if (tails.get(key) === tail) tails.delete(key); });
        return run;
    };
}

function register(app, ctx) {
    const { io, emitRoomMessageEvent, dbGet, dbAll, dbRun, queryWithRetry, userCanAccessMessage } = ctx;
    const serializeReaction = createKeyQueue();

    // Сколько человек поставили это эмодзи на сообщение. Итог отдаётся и в ответе, и в
    // событии: клиент ставит абсолютное число, а не «+1», и сравнивает версии v.
    async function countReaction(messageId, emoji) {
        const row = await dbGet('SELECT COUNT(*)::int AS count FROM reactions WHERE message_id = $1 AND emoji = $2', [messageId, emoji]);
        return row ? row.count : 0;
    }

    // Событие reactionChanged { id, emoji, count, room_id | chat_id }: участникам комнаты,
    // кроме тех, для кого сообщение под границей видимости (visible_from_seq >= seq: они
    // вступили позже и сообщения не видят, как и в messageEdited); в чате с ботом — владельцу.
    // Копия автору реакции (все его вкладки) дополнена mine: поставлена ли реакция теперь у него,
    // — по ней вкладки выставляют отметку «моя». Кто именно поставил реакцию, остальным не сообщается.
    // Сбой рассылки не должен ломать уже записанную реакцию — он только логируется.
    async function announceReaction(userId, messageId, emoji, count, active, v) {
        try {
            const message = await dbGet('SELECT id, seq, room_id, chat_id FROM messages WHERE id = $1', [messageId]);
            if (!message) return;
            const payload = { id: String(messageId), emoji, count, v };
            if (message.room_id) {
                const hidden = await dbAll(
                    'SELECT user_id FROM room_participants WHERE room_id = $1 AND visible_from_seq >= $2',
                    [message.room_id, message.seq]
                );
                payload.room_id = message.room_id;
                emitRoomMessageEvent('reactionChanged', message.room_id, userId, payload, { hiddenUserIds: hidden.map(row => row.user_id), toAuthor: false });
                io.to('user:' + userId).emit('reactionChanged', { ...payload, mine: active });
            } else {
                io.to(getSocketRoomKey(message.chat_id, null)).emit('reactionChanged', { ...payload, chat_id: message.chat_id, room_id: null, mine: active });
            }
        } catch (error) {
            logError('Reaction broadcast error', error);
        }
    }

    app.post('/api/reactions', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        const { emoji } = req.body || {};
        const messageId = toPositiveInt(req.body?.messageId);
        if (!messageId || !emoji) return res.json({ success: false, message: 'Параметры отсутствуют' });
        if (typeof emoji !== 'string' || !ALLOWED_REACTION_EMOJIS.has(emoji)) return res.json({ success: false, message: 'Недопустимый emoji' });

        try {
            if (!(await userCanAccessMessage(req.session.userId, messageId))) {
                return res.json({ success: false, message: 'Сообщение недоступно' });
            }
            const { count, v } = await serializeReaction(`${messageId}:${emoji}`, async () => {
                await queryWithRetry('INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [messageId, req.session.userId, emoji]);
                return { count: await countReaction(messageId, emoji), v: nextReactionVersion() };
            });
            res.json({ success: true, count, mine: true, v });
            await announceReaction(req.session.userId, messageId, emoji, count, true, v);
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Add reaction error', error);
            res.json({ success: false, message: 'Ошибка добавления реакции' });
        }
    });

    app.delete('/api/reactions/:messageId/:emoji', async (req, res) => {
        if (!req.session.userId) return res.json({ success: false, message: 'Не авторизован' });
        const messageId = toPositiveInt(req.params.messageId);
        // req.params уже декодирован Express'ом. Повторный decodeURIComponent
        // падал с URIError на любом '%' в параметре — вне try, т.е. ронял процесс.
        const emoji = req.params.emoji;
        if (!messageId || !ALLOWED_REACTION_EMOJIS.has(emoji)) {
            return res.json({ success: false, message: 'Недопустимые параметры' });
        }

        try {
            if (!(await userCanAccessMessage(req.session.userId, messageId))) {
                return res.json({ success: false, message: 'Сообщение недоступно' });
            }
            const { count, v } = await serializeReaction(`${messageId}:${emoji}`, async () => {
                await dbRun(
                    'DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
                    [messageId, req.session.userId, emoji]
                );
                return { count: await countReaction(messageId, emoji), v: nextReactionVersion() };
            });
            res.json({ success: true, count, mine: false, v });
            await announceReaction(req.session.userId, messageId, emoji, count, false, v);
        } catch (error) {
            if (respondIfDbBusy(res, error)) return;
            logError('Remove reaction error', error);
            res.json({ success: false, message: 'Ошибка удаления реакции' });
        }
    });
}

module.exports = { register };
