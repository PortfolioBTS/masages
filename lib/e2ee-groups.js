// Серверная часть группового E2EE: список участников чата и
// key-shares — попарно зашифрованная (клиентом, через X3DH) доставка
// Sender Key от одного участника остальным. Сервер здесь видит только
// непрозрачный шифротекст и метаданные маршрутизации (кто кому шлёт
// в рамках какой комнаты) — то же самое допущение threat model L4, что
// и в e2ee-key-server (см. handlers.rs::get_bundle).
//
// ВАЖНО про модель данных: chats.id — это персональная строка КАЖДОГО
// участника (у разных участников одного разговора РАЗНЫЕ chatId), а
// общий для всех идентификатор — chats.room_id (см. паттерн
// c.room_id IS NOT NULL AND ... в server.js). Поэтому все проверки
// доступа и все ключи в БД здесь строятся по room_id, а не по chatId,
// присланному конкретным клиентом — иначе участники одного разговора
// просто не находили бы key-share друг друга.
//
// Регистрируется в server.js так же, как e2ee-proxy.js: после
// sessionMiddleware, функцией registerE2eeGroupRoutes(app, deps).

const MAX_SHARES_PER_REQUEST = 200;
// Самый крупный key-share — x3dh-init с постквантовой частью: ML-KEM-768
// ciphertext 1088 байт (1452 символа base64), identity DH + signing и
// эфемерный ключ (по 44 символа), id трёх prekey, счётчик и сам завёрнутый
// SKDM (~300 байт JSON → ~400 символов base64). С именами полей JSON это
// ≈2.4 КБ, с запасом на подпись/паддинг — до ~4 КБ. 8192 оставляет
// двукратный запас сверху; поднимать дальше незачем — лимит заодно
// ограничивает, сколько места в БД участник может занять чужими строками.
const MAX_SHARE_CIPHERTEXT = 8192;
// Сколько недоставленных key-share может ждать одного получателя в одной
// комнате. Честному трафику хватает с большим запасом (одна запись на
// отправителя за каждую ротацию его Sender Key, а получатель забирает и
// удаляет их при каждой синхронизации), а участник комнаты не может
// бесконечно заполнять таблицу строками для того, кто долго не заходит.
const MAX_PENDING_SHARES_PER_RECIPIENT = 1000;

async function initE2eeGroupsSchema(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS e2ee_key_shares (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            ciphertext TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_e2ee_key_shares_recipient ON e2ee_key_shares(recipient_id, room_id);`);
}

function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    next();
}

function registerE2eeGroupRoutes(app, deps) {
    const { dbGet, dbAll, dbRun, io } = deps;

    // Резолвит chatId (персональная строка вызывающего) в room_id и
    // одновременно проверяет, что вызывающий действительно участник —
    // тот же принцип, что и во всех остальных /api/chats и /api/messages
    // маршрутах server.js.
    async function resolveOwnRoom(userId, chatId) {
        const chat = await dbGet('SELECT id, room_id FROM chats WHERE id = $1 AND user_id = $2', [chatId, userId]);
        if (!chat) return { error: 'not-found' };
        if (!chat.room_id) return { error: 'no-room' };
        return { roomId: chat.room_id };
    }

    app.get('/api/chats/:chatId/participants', requireAuth, async (req, res) => {
        try {
            const resolved = await resolveOwnRoom(req.session.userId, req.params.chatId);
            if (resolved.error === 'not-found') return res.json({ success: false, message: 'Чат не найден' });
            if (resolved.error === 'no-room') {
                // Бот/одиночный чат — групповое E2EE неприменимо, но это
                // не ошибка: клиент просто не предлагает шифрование здесь.
                return res.json({ success: true, roomId: null, participants: [] });
            }
            const rows = await dbAll(
                'SELECT u.id, u.username FROM users u JOIN room_participants rp ON u.id = rp.user_id WHERE rp.room_id = $1 ORDER BY u.id ASC',
                [resolved.roomId]
            );
            res.json({ success: true, roomId: resolved.roomId, participants: rows });
        } catch (error) {
            console.error('[E2EE] participants error:', error);
            res.json({ success: false, message: 'Ошибка получения участников' });
        }
    });

    app.post('/api/keys/key-shares', requireAuth, async (req, res) => {
        try {
            const { chatId, shares } = req.body || {};
            if (!chatId || !Array.isArray(shares) || shares.length === 0) {
                return res.json({ success: false, message: 'Некорректный запрос' });
            }
            if (shares.length > MAX_SHARES_PER_REQUEST) {
                return res.json({ success: false, message: 'Слишком много получателей за один запрос' });
            }
            const resolved = await resolveOwnRoom(req.session.userId, chatId);
            if (resolved.error) return res.json({ success: false, message: 'Чат не найден или недоступен для E2EE' });

            const memberRows = await dbAll('SELECT user_id FROM room_participants WHERE room_id = $1', [resolved.roomId]);
            const memberIds = new Set(memberRows.map(r => r.user_id));

            for (const share of shares) {
                const recipientId = Number(share && share.recipientUserId);
                const ciphertext = share && share.ciphertext;
                if (!Number.isFinite(recipientId) || typeof ciphertext !== 'string' || ciphertext.length === 0) {
                    return res.json({ success: false, message: 'Некорректный элемент shares' });
                }
                if (ciphertext.length > MAX_SHARE_CIPHERTEXT) {
                    return res.json({ success: false, message: 'key-share слишком большой' });
                }
                if (!memberIds.has(recipientId)) {
                    return res.json({ success: false, message: 'Получатель не является участником чата' });
                }
            }

            // Лимит очереди получателя проверяется для всего запроса сразу и
            // до вставки: частичная доставка оставила бы клиента в уверенности,
            // что ключ получили все. Проверка и вставка не атомарны, так что
            // параллельные запросы могут немного превысить лимит — это
            // допустимо, цель — не дать очереди расти неограниченно.
            const perRecipient = new Map();
            for (const share of shares) {
                const recipientId = Number(share.recipientUserId);
                perRecipient.set(recipientId, (perRecipient.get(recipientId) || 0) + 1);
            }
            const pendingRows = await dbAll(
                'SELECT recipient_id, COUNT(*)::int AS cnt FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = ANY($2::int[]) GROUP BY recipient_id',
                [resolved.roomId, [...perRecipient.keys()]]
            );
            for (const row of pendingRows) {
                if (Number(row.cnt) + perRecipient.get(Number(row.recipient_id)) > MAX_PENDING_SHARES_PER_RECIPIENT) {
                    return res.json({
                        success: false,
                        message: 'У получателя слишком много недоставленных ключей шифрования. Попробуйте позже.',
                    });
                }
            }

            for (const share of shares) {
                const recipientId = Number(share.recipientUserId);
                await dbRun(
                    'INSERT INTO e2ee_key_shares (room_id, sender_id, recipient_id, ciphertext) VALUES ($1, $2, $3, $4)',
                    [resolved.roomId, req.session.userId, recipientId, share.ciphertext]
                );
                // Лёгкий сигнал получателю "иди забери" — доставка не
                // теряется, даже если он сейчас офлайн: запись уже в БД,
                // и обычный вызов GET /api/keys/key-shares/:chatId её
                // найдёт. Socket-пуш — просто ускорение для тех, кто
                // сейчас в сети.
                io.to('user:' + recipientId).emit('e2eeKeyShare', { roomId: resolved.roomId });
            }

            res.json({ success: true, sent: shares.length });
        } catch (error) {
            console.error('[E2EE] post key-shares error:', error);
            res.json({ success: false, message: 'Ошибка отправки key-share' });
        }
    });

    app.get('/api/keys/key-shares/:chatId', requireAuth, async (req, res) => {
        try {
            const resolved = await resolveOwnRoom(req.session.userId, req.params.chatId);
            if (resolved.error) return res.json({ success: true, roomId: null, shares: [] });

            // fetch-and-delete: одноразовая доставка, чтобы таблица не
            // росла бесконечно и чтобы повторный вызов не переигрывал уже
            // применённые клиентом key-share.
            const rows = await dbAll(
                'SELECT id, sender_id, ciphertext FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2 ORDER BY id ASC',
                [resolved.roomId, req.session.userId]
            );
            if (rows.length > 0) {
                const ids = rows.map(r => r.id);
                const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
                await dbRun(`DELETE FROM e2ee_key_shares WHERE id IN (${placeholders})`, ids);
            }
            res.json({
                success: true,
                roomId: resolved.roomId,
                shares: rows.map(r => ({ senderId: r.sender_id, ciphertext: r.ciphertext })),
            });
        } catch (error) {
            console.error('[E2EE] get key-shares error:', error);
            res.json({ success: false, message: 'Ошибка получения key-share' });
        }
    });
}

module.exports = { initE2eeGroupsSchema, registerE2eeGroupRoutes };
