// Серверная часть группового E2EE: список участников чата и
// key-shares — попарно зашифрованная (клиентом, через X3DH) доставка
// Sender Key от одного участника остальным, а также запросы ключа (потерянный
// key-share лечится просьбой «пришлите ключ ещё раз»). Сервер здесь видит только
// непрозрачный шифротекст и метаданные маршрутизации (кто кому шлёт
// в рамках какой комнаты) — то же самое допущение threat model L4, что
// и в хранилище ключей (lib/key-store.js, getBundle).
//
// ВАЖНО про модель данных: chats.id — это персональная строка КАЖДОГО
// участника (у разных участников одного разговора РАЗНЫЕ chatId), а
// общий для всех идентификатор — chats.room_id (см. паттерн
// c.room_id IS NOT NULL AND ... в server.js). Поэтому все проверки
// доступа и все ключи в БД здесь строятся по room_id, а не по chatId,
// присланному конкретным клиентом — иначе участники одного разговора
// просто не находили бы key-share друг друга.
//
// Регистрируется в server.js так же, как e2ee-keys.js: после
// sessionMiddleware, функцией registerE2eeGroupRoutes(app, deps).

const { createSlidingWindowCounter } = require('./e2ee-keys');

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
// комнате и сколько из них — от одного отправителя. Ротация Sender Key раз в
// 100 сообщений или 7 дней даёт отправителю одну запись на получателя за
// ротацию, и участник, который долго не заходит, не должен срывать рассылку
// остальным: при превышении потолка отвергается НЕ запрос, а вытесняются самые
// старые ожидающие строки (запрос успешен). Потолок на тройку (комната,
// отправитель, получатель) не даёт одному шумному отправителю вытеснить чужие
// ключи; общий потолок на получателя ограничивает таблицу. Аккаунты удаляются
// после 7 дней без активности, так что вытеснение касается лишь давно
// отсутствующих — а потерянный ключ потом лечит запрос ключа.
const MAX_PENDING_SHARES_PER_RECIPIENT = 1000;
const MAX_PENDING_SHARES_PER_SENDER = 200;
// Защита от спама ротацией: не больше 30 отправок key-share в час на пару
// (пользователь, комната). «Отправка» — один запрос POST (до 200 получателей).
const KEY_SHARE_POSTS_PER_HOUR = 30;
// Запросы ключа: не больше 10 запросов в час на пару (пользователь,
// комната), не больше 20 ключей в запросе и 50 ожидающих строк на пару,
// срок жизни строки — 7 дней. Время хранится в часах от начала эпохи: точное
// время запроса не нужно, а метка поменьше.
const KEY_REQUEST_POSTS_PER_HOUR = 10;
const MAX_KEY_REQUEST_IDS = 20;
const MAX_PENDING_KEY_REQUESTS = 50;
const KEY_REQUEST_TTL_HOURS = 7 * 24;
const MAX_KEY_REQUESTS_RETURNED = 500;
const HOUR_MS = 60 * 60 * 1000;
const LIMITER_SWEEP_MS = 10 * 60 * 1000;

const LIMIT_BUSY = { success: false, code: 'busy', message: 'Сервис сейчас занят. Повторите попытку через несколько секунд.' };

async function initE2eeGroupsSchema(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS e2ee_key_shares (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            ciphertext TEXT NOT NULL
            -- Времени создания нет: в коде оно не нужно, а точное время выдачи
            -- ключа участнику (message-ordering.md, раздел 11) — лишняя метка.
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_e2ee_key_shares_recipient ON e2ee_key_shares(recipient_id, room_id);`);
    // Запросы ключа: «у меня нет Sender Key с таким id, пришлите». key_id — 16
    // байт senderKeyId из конверта (непрозрачный для сервера идентификатор, не
    // связанный с пользователем), поэтому владельца ключа сервер не определяет:
    // запрос видят все участники комнаты, а откликается тот, чей это ключ.
    // Строки живут 7 дней; запросивший сам стирает свои (key-requests/done),
    // когда ключ дошёл.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS e2ee_key_requests (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            key_id BYTEA NOT NULL,
            created_hour INTEGER NOT NULL,
            UNIQUE (room_id, requester_id, key_id)
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_e2ee_key_requests_hour ON e2ee_key_requests(created_hour)');
}

function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    next();
}

const currentHour = () => Math.floor(Date.now() / HOUR_MS);

// senderKeyId в запросе: строка base64 ровно из 16 байт в каноническом виде.
function parseKeyId(value) {
    if (typeof value !== 'string' || value.length !== 24) return null;
    const bytes = Buffer.from(value, 'base64');
    return bytes.length === 16 && bytes.toString('base64') === value ? bytes : null;
}

function parseChatId(value) {
    const id = Number(value);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
}

// deps.keyShareLimiter и deps.keyRequestLimiter — хранилища лимитов с методом
// tryConsume(lockKey, rules) → { ok, waitMs: [...] } (lib/pg-limits.js,
// createPgSlidingLimiter): server.js передаёт их в Postgres, и квота переживает
// рестарт; при сбое хранилища лимит закрывается (503 busy). Без них (юнит-тесты,
// один процесс) счётчики лежат в памяти.
function registerE2eeGroupRoutes(app, deps) {
    const { dbGet, dbAll, dbRun, io, keyShareLimiter, keyRequestLimiter } = deps;
    // Вставка key-share — один оператор с внешними ключами на rooms и users, вне
    // порядка блокировок (message-ordering.md, раздел 8.2): с удалением аккаунта
    // она может сойтись во взаимной блокировке (40P01). server.js передаёт запись
    // с одним повтором и ответ 503 busy; без них (тесты на фейковой БД) — как есть.
    const insertWithRetry = typeof deps.queryWithRetry === 'function' ? deps.queryWithRetry : dbRun;
    const respondIfDeadlock = typeof deps.respondIfDeadlock === 'function' ? deps.respondIfDeadlock : () => false;

    // Лимит «не больше max запросов в час на ключ». С хранилищем в Postgres —
    // через него; иначе по счётчику в памяти. Результат: { ok } или { ok:false, waitMs }.
    function makeHourlyLimit(limiter, name, max) {
        if (limiter) {
            return async (userId, roomId) => {
                const { waitMs } = await limiter.tryConsume(String(userId), [{ key: `${name}:${userId}:${roomId}`, max }]);
                return waitMs[0] > 0 ? { ok: false, waitMs: waitMs[0] } : { ok: true };
            };
        }
        const counter = createSlidingWindowCounter(HOUR_MS, max);
        setInterval(() => counter.sweep(Date.now()), LIMITER_SWEEP_MS).unref(); // не держит процесс (и тесты) живым
        return async (userId, roomId) => {
            // Проверка и учёт — синхронно, без await между ними.
            const key = `${userId}:${roomId}`;
            const now = Date.now();
            const waitMs = counter.waitMs(key, now);
            if (waitMs > 0) return { ok: false, waitMs };
            counter.hit(key, now);
            return { ok: true };
        };
    }
    const consumeKeySharePost = makeHourlyLimit(keyShareLimiter, 'keyshare', KEY_SHARE_POSTS_PER_HOUR);
    const consumeKeyRequestPost = makeHourlyLimit(keyRequestLimiter, 'keyreq', KEY_REQUEST_POSTS_PER_HOUR);

    // true — ответ отправлен (лимит исчерпан или хранилище лимита недоступно).
    async function respondIfLimited(res, consume, userId, roomId, what) {
        let quota;
        try {
            quota = await consume(userId, roomId);
        } catch {
            // Сбой хранилища лимита (в логе уже есть): лимит не открывается.
            res.set('Retry-After', '5');
            res.status(503).json(LIMIT_BUSY);
            return true;
        }
        if (quota.ok) return false;
        const waitSec = Math.max(1, Math.ceil(quota.waitMs / 1000));
        res.set('Retry-After', String(waitSec));
        res.status(429).json({
            success: false,
            message: `Слишком много ${what}. Повторите через ${Math.max(1, Math.ceil(waitSec / 60))} мин.`,
        });
        return true;
    }

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

            // Лимит отправок — после проверки формата (кривой запрос квоту не
            // тратит) и до записи.
            if (await respondIfLimited(res, consumeKeySharePost, req.session.userId, resolved.roomId, 'отправок ключей шифрования')) return;

            for (const share of shares) {
                const recipientId = Number(share.recipientUserId);
                await insertWithRetry(
                    'INSERT INTO e2ee_key_shares (room_id, sender_id, recipient_id, ciphertext) VALUES ($1, $2, $3, $4)',
                    [resolved.roomId, req.session.userId, recipientId, share.ciphertext]
                );
            }

            // Очередь получателя не должна расти без предела, но и отказывать
            // отправителю нельзя: давно не заходивший участник сорвал бы рассылку
            // всем. Вместо отказа вытесняются самые старые ожидающие строки —
            // сперва сверх потолка на тройку (комната, отправитель, получатель),
            // потом сверх общего потолка на получателя. Проверка и вытеснение не
            // атомарны с вставкой: параллельные запросы могут ненадолго превысить
            // потолок — цель лишь не дать очереди расти неограниченно.
            const recipientIds = [...new Set(shares.map(share => Number(share.recipientUserId)))];
            const counts = await dbAll(
                `SELECT recipient_id, COUNT(*)::int AS total, (COUNT(*) FILTER (WHERE sender_id = $3))::int AS from_sender
                   FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = ANY($2::int[]) GROUP BY recipient_id`,
                [resolved.roomId, recipientIds, req.session.userId]
            );
            for (const row of counts) {
                const recipientId = Number(row.recipient_id);
                let total = Number(row.total);
                if (Number(row.from_sender) > MAX_PENDING_SHARES_PER_SENDER) {
                    total -= Number(row.from_sender) - MAX_PENDING_SHARES_PER_SENDER;
                    await insertWithRetry(
                        `DELETE FROM e2ee_key_shares WHERE id IN (
                             SELECT id FROM e2ee_key_shares WHERE room_id = $1 AND sender_id = $2 AND recipient_id = $3
                             ORDER BY id DESC OFFSET $4)`,
                        [resolved.roomId, req.session.userId, recipientId, MAX_PENDING_SHARES_PER_SENDER]
                    );
                }
                if (total > MAX_PENDING_SHARES_PER_RECIPIENT) {
                    await insertWithRetry(
                        `DELETE FROM e2ee_key_shares WHERE id IN (
                             SELECT id FROM e2ee_key_shares WHERE room_id = $1 AND recipient_id = $2
                             ORDER BY id DESC OFFSET $3)`,
                        [resolved.roomId, recipientId, MAX_PENDING_SHARES_PER_RECIPIENT]
                    );
                }
            }

            // Лёгкий сигнал получателю "иди забери" — доставка не
            // теряется, даже если он сейчас офлайн: запись уже в БД,
            // и обычный вызов GET /api/keys/key-shares/:chatId её
            // найдёт. Socket-пуш — просто ускорение для тех, кто
            // сейчас в сети.
            for (const recipientId of recipientIds) {
                io.to('user:' + recipientId).emit('e2eeKeyShare', { roomId: resolved.roomId });
            }

            res.json({ success: true, sent: shares.length });
        } catch (error) {
            if (respondIfDeadlock(res, error)) return;
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

    // ---- Запросы ключа ----

    // «У меня нет Sender Key с этими id». Id отправителя клиент не называет (его
    // нет в конверте после 4.3): запрос ретранслируется всем участникам комнаты,
    // а откликается тот, чей это ключ. Для офлайн-владельцев строка остаётся в
    // БД на 7 дней (GET ниже).
    app.post('/api/keys/key-requests', requireAuth, async (req, res) => {
        try {
            const { chatId, senderKeyIds } = req.body || {};
            const chat = parseChatId(chatId);
            if (chat === null || !Array.isArray(senderKeyIds) || senderKeyIds.length === 0 || senderKeyIds.length > MAX_KEY_REQUEST_IDS) {
                return res.status(400).json({ success: false, message: 'Некорректный запрос' });
            }
            const keyIds = [];
            for (const raw of senderKeyIds) {
                const bytes = parseKeyId(raw);
                if (!bytes) return res.status(400).json({ success: false, message: 'Некорректный идентификатор ключа' });
                if (!keyIds.some(known => known.equals(bytes))) keyIds.push(bytes);
            }
            const resolved = await resolveOwnRoom(req.session.userId, chat);
            if (resolved.error) return res.json({ success: false, message: 'Чат не найден или недоступен для E2EE' });

            if (await respondIfLimited(res, consumeKeyRequestPost, req.session.userId, resolved.roomId, 'запросов ключа')) return;

            const hour = currentHour();
            // Просроченные строки комнаты убираются заодно с запросом; общая уборка — задача jobs().
            await dbRun('DELETE FROM e2ee_key_requests WHERE room_id = $1 AND created_hour < $2', [resolved.roomId, hour - KEY_REQUEST_TTL_HOURS]);
            for (const keyId of keyIds) {
                // Повторный запрос продлевает срок строки.
                await insertWithRetry(
                    `INSERT INTO e2ee_key_requests (room_id, requester_id, key_id, created_hour) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (room_id, requester_id, key_id) DO UPDATE SET created_hour = EXCLUDED.created_hour`,
                    [resolved.roomId, req.session.userId, keyId, hour]
                );
            }
            // Ожидающих строк на пару (запросивший, комната) не больше 50: лишние старые вытесняются.
            await insertWithRetry(
                `DELETE FROM e2ee_key_requests WHERE id IN (
                     SELECT id FROM e2ee_key_requests WHERE room_id = $1 AND requester_id = $2
                     ORDER BY created_hour DESC, id DESC OFFSET $3)`,
                [resolved.roomId, req.session.userId, MAX_PENDING_KEY_REQUESTS]
            );

            const members = await dbAll('SELECT user_id FROM room_participants WHERE room_id = $1', [resolved.roomId]);
            const payload = {
                roomId: resolved.roomId,
                fromUserId: req.session.userId,
                senderKeyIds: keyIds.map(bytes => bytes.toString('base64')),
            };
            for (const member of members) {
                if (Number(member.user_id) === Number(req.session.userId)) continue;
                io.to('user:' + member.user_id).emit('e2eeKeyRequest', payload);
            }
            res.json({ success: true, requested: keyIds.length });
        } catch (error) {
            if (respondIfDeadlock(res, error)) return;
            console.error('[E2EE] post key-requests error:', error);
            res.json({ success: false, message: 'Ошибка запроса ключа' });
        }
    });

    // Ожидающие запросы других участников комнаты — для владельца, который был
    // офлайн. Строки не удаляются: ключ может быть не его, а запрос — чужой
    // ответ ещё ждёт; сам запросивший стирает свои, когда ключ дошёл.
    app.get('/api/keys/key-requests/:chatId', requireAuth, async (req, res) => {
        try {
            const chat = parseChatId(req.params.chatId);
            const resolved = chat === null ? { error: 'not-found' } : await resolveOwnRoom(req.session.userId, chat);
            if (resolved.error) return res.json({ success: true, roomId: null, requests: [] });
            const rows = await dbAll(
                `SELECT requester_id, key_id FROM e2ee_key_requests
                  WHERE room_id = $1 AND requester_id <> $2 AND created_hour >= $3
                  ORDER BY id ASC LIMIT ${MAX_KEY_REQUESTS_RETURNED}`,
                [resolved.roomId, req.session.userId, currentHour() - KEY_REQUEST_TTL_HOURS]
            );
            const byRequester = new Map();
            for (const row of rows) {
                const id = Number(row.requester_id);
                if (!byRequester.has(id)) byRequester.set(id, []);
                byRequester.get(id).push(Buffer.from(row.key_id).toString('base64'));
            }
            res.json({
                success: true,
                roomId: resolved.roomId,
                requests: [...byRequester].map(([fromUserId, senderKeyIds]) => ({ fromUserId, senderKeyIds })),
            });
        } catch (error) {
            console.error('[E2EE] get key-requests error:', error);
            res.json({ success: false, message: 'Ошибка получения запросов ключа' });
        }
    });

    // Ключ дошёл: запросивший стирает свои строки (чужие этим маршрутом не тронуть).
    app.post('/api/keys/key-requests/done', requireAuth, async (req, res) => {
        try {
            const { chatId, senderKeyIds } = req.body || {};
            const chat = parseChatId(chatId);
            if (chat === null || !Array.isArray(senderKeyIds) || senderKeyIds.length === 0 || senderKeyIds.length > MAX_KEY_REQUEST_IDS) {
                return res.status(400).json({ success: false, message: 'Некорректный запрос' });
            }
            const keyIds = senderKeyIds.map(parseKeyId);
            if (keyIds.some(bytes => !bytes)) return res.status(400).json({ success: false, message: 'Некорректный идентификатор ключа' });
            const resolved = await resolveOwnRoom(req.session.userId, chat);
            if (resolved.error) return res.json({ success: false, message: 'Чат не найден или недоступен для E2EE' });
            await dbRun(
                'DELETE FROM e2ee_key_requests WHERE room_id = $1 AND requester_id = $2 AND key_id = ANY($3::bytea[])',
                [resolved.roomId, req.session.userId, keyIds]
            );
            res.json({ success: true });
        } catch (error) {
            console.error('[E2EE] done key-requests error:', error);
            res.json({ success: false, message: 'Ошибка удаления запросов ключа' });
        }
    });
}

// Уборка просроченных запросов ключа: раз в час, под runExclusive (lib/jobs).
async function purgeExpiredKeyRequests(pool) {
    const result = await pool.query('DELETE FROM e2ee_key_requests WHERE created_hour < $1', [currentHour() - KEY_REQUEST_TTL_HOURS]);
    return result.rowCount;
}

function jobs(ctx) {
    return [{
        name: 'purgeKeyRequests',
        run: () => purgeExpiredKeyRequests(ctx.pool),
        firstDelayMs: 3 * 60 * 1000,
        intervalMs: HOUR_MS,
        maintenance: true,
    }];
}

module.exports = {
    initE2eeGroupsSchema,
    registerE2eeGroupRoutes,
    purgeExpiredKeyRequests,
    jobs,
    MAX_PENDING_SHARES_PER_RECIPIENT,
    MAX_PENDING_SHARES_PER_SENDER,
    KEY_SHARE_POSTS_PER_HOUR,
    KEY_REQUEST_POSTS_PER_HOUR,
    MAX_PENDING_KEY_REQUESTS,
    KEY_REQUEST_TTL_HOURS,
};
