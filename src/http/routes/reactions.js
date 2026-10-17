'use strict';
// Реакции на сообщения. Вынесено из server.js.

const { logError } = require('../../../lib/log-error');
const { toPositiveInt } = require('../params');
const { respondIfDeadlock } = require('../../db/transactions');

// В UI предлагается фиксированный набор из 5 эмодзи для реакций. Раньше на
// бэке проверялась только длина строки (≤10 символов), а не содержимое — это
// пропускало вход в message.reactions, который на фронте рендерится в
// innerHTML без escapeHtml (см. п.3 аудита). Теперь бэк принимает только
// эмодзи из этого списка.
const ALLOWED_REACTION_EMOJIS = new Set(['👍', '❤️', '😂', '😢', '🔥']);

function register(app, ctx) {
    const { dbRun, queryWithRetry, userCanAccessMessage } = ctx;

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
            await queryWithRetry('INSERT INTO reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [messageId, req.session.userId, emoji]);
            res.json({ success: true });
        } catch (error) {
            if (respondIfDeadlock(res, error)) return;
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
            await dbRun(
                'DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
                [messageId, req.session.userId, emoji]
            );
            res.json({ success: true });
        } catch (error) {
            logError('Remove reaction error', error);
            res.json({ success: false, message: 'Ошибка удаления реакции' });
        }
    });
}

module.exports = { register };
