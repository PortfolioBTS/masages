'use strict';
// Схема базы (roadmap R0): initDatabase и её помощники — случайные id и таблица заявок.
// Выполняется под блокировкой миграций (db/migrate.js). Вынесено из server.js.

const { initKeyStoreSchema } = require('../../lib/key-store');
// Групповой E2EE: участники чата + попарная доставка Sender Key
// (key-shares). Тоже регистрируется после sessionMiddleware.
const { initE2eeGroupsSchema } = require('../../lib/e2ee-groups');
const { initUploadQuotaSchema } = require('../../lib/upload-quota');
// Точные лимиты и одноразовость PoW в Postgres (UNLOGGED-таблицы, ключи — HMAC).
const { initPgLimitsSchema } = require('../../lib/pg-limits');
// Сброс схемы версии 2.0.0 при первом старте (вызывается из initDatabase).
const { resetLegacyDatabase } = require('../../lib/legacy-reset');
const { logError } = require('../../lib/log-error');
// Надгробия id сообщений, триггеры seq и проверки id (initDatabase).
const { initMessageOrderSchema } = require('../../lib/message-order-schema');
const { maybeDumpCa } = require('./dump-ca');

// ---- Случайные id для users, rooms, chats, join_requests, messages ----
//
// Последовательные id выдавали размер и темп роста сервиса (id свежей
// регистрации = число пользователей) и порядок событий: по id комнаты или
// чата было видно, кто и когда создал её раньше. Поэтому id этих таблиц —
// случайные из [1 000 000, 2^31 - 1]: 48 бит из gen_random_uuid() (PG 13+,
// внутри pg_strong_random — криптостойкий ГСЧ; первые 12 hex-цифр UUIDv4
// случайны целиком) по модулю размера диапазона (смещение ~2^-17 — не
// различимо), с перепроверкой занятости в цикле. У messages порядок и
// непрочитанное держатся не на id, а на seq (message-ordering.md); id
// сообщений комнаты выбирает клиент, DEFAULT нужен чату с ботом.
//
// Тело функции — константа: database.sql содержит ту же функцию.
const RANDOM_ID_FUNCTION_BODY = `
DECLARE
    candidate integer;
    taken boolean;
BEGIN
    LOOP
        candidate := (1000000 + ('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 12))::bit(48)::bigint % 2146483648)::integer;
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE id = $1)', target) INTO taken USING candidate;
        IF NOT taken THEN
            RETURN candidate;
        END IF;
    END LOOP;
END
`;
const RANDOM_ID_TABLES = ['users', 'rooms', 'chats', 'join_requests', 'messages'];

function createSchema(ctx) {
    const { UPLOADS_DIR, pool, dbAll, disappearingMessagesManager } = ctx;

    // ---- Итоговая схема базы (roadmap R0) ----
    //
    // Пока новая версия не выкачена, схема описана прямо в DDL initDatabase: все
    // изменения волн вносятся в эти CREATE TABLE, без ALTER-миграций, а после
    // выката схему меняют только файлы lib/migrations/ (docs/dev/migrations.md).
    // Шагов совместимости со старыми схемами здесь нет: схема версии 2.0.0 при
    // первом старте сбрасывается целиком (lib/legacy-reset.js), а локальные и
    // тестовые базы создаются заново.
    //
    // initDatabase идемпотентна и идёт под блокировкой миграций на каждом старте:
    // CREATE ... IF NOT EXISTS по готовой схеме ничего не меняет. Внешние ключи и
    // их ON DELETE заданы прямо в CREATE TABLE. Ключи на users — без каскада:
    // deleteUserAccount удаляет строки пользователя сам, в нужном порядке, одной
    // транзакцией. Таблицы со своими init*Schema (ключи E2EE, key-share, таймеры
    // исчезающих сообщений) создаются в lib/ рядом с кодом, который ими владеет.
    async function initDatabase() {
        await maybeDumpCa().catch(err => { logError('[DUMP_CA] Ошибка', err); process.exit(1); });

        // Схема версии 2.0.0 (аккаунты с email и паролем) — сбросить до создания
        // таблиц: реальных пользователей нет, а переносить тестовые данные незачем.
        await resetLegacyDatabase({ pool, uploadsDir: UPLOADS_DIR });

        // Аккаунты только временные (roadmap R2): срок жизни и последняя активность
        // обязательны, по ним чистка удаляет неактивных. created_at — до минуты:
        // точное время регистрации никому не нужно и лишь помогает сопоставить
        // аккаунт с логами. Отметки прочтения выключены, пока пользователь их не
        // включит (POST /api/user/privacy).
        await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            unique_code TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            avatar TEXT DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            read_receipts BOOLEAN NOT NULL DEFAULT FALSE,
            anon_lifetime TEXT NOT NULL CHECK (anon_lifetime IN ('tab', 'day', 'week')),
            last_active_at TIMESTAMPTZ NOT NULL
        )
    `);
        // Чистка неактивных аккаунтов (раз в несколько минут) идёт по сроку жизни и
        // последней активности, без прохода по всей таблице users.
        await pool.query('CREATE INDEX IF NOT EXISTS idx_users_lifetime ON users(anon_lifetime, last_active_at)');

        // База счётчиков seq комнат и чатов с ботом (DEFAULT rooms.msg_seq и
        // chats.msg_seq): равномерно из [0; 2^30). 2^32 делится на 2^30 без
        // остатка, поэтому смещения нет, а запас до переполнения INTEGER — 2^30
        // сообщений в одной области. Функция нужна до CREATE TABLE rooms/chats.
        await pool.query(`
        CREATE OR REPLACE FUNCTION nyxo_random_seq_base() RETURNS integer
        LANGUAGE sql VOLATILE AS $fn$
          SELECT (('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8))::bit(32)::bigint % 1073741824)::integer
        $fn$
    `);

        await pool.query(`
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            -- последний выданный seq сообщений комнаты (триггер nyxo_message_seq).
            -- Начинается со случайной базы: новичок по seq не узнает, сколько
            -- сообщений было до него
            msg_seq INTEGER NOT NULL DEFAULT nyxo_random_seq_base(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            -- срок жизни кода приглашения (INVITE_TTL_HOURS)
            code_expires_at TIMESTAMPTZ,
            -- параметры кода (POST /api/chats/:chatId/invite/rotate): лимит
            -- участников (NULL — без лимита), вступление только с одобрения
            -- участника, выключенный код
            invite_max_members INTEGER,
            invite_require_approval BOOLEAN NOT NULL DEFAULT TRUE,
            invite_disabled BOOLEAN NOT NULL DEFAULT FALSE,
            -- подписанное приглашение (signed-membership.md, 7.1): сертификат
            -- приглашения (335 байт), снимок состава автора (16 байт на участника)
            -- и автор приглашения (без внешнего ключа: выход или удаление аккаунта
            -- автора обнуляет все три столбца). NULL - код принимает только заявки
            invite_cert BYTEA CHECK (invite_cert IS NULL OR octet_length(invite_cert) = 335),
            invite_snap BYTEA CHECK (invite_snap IS NULL OR (octet_length(invite_snap) % 16 = 0 AND octet_length(invite_snap) <= 16384)),
            invite_actor_id INTEGER,
            CONSTRAINT rooms_invite_signed CHECK (
                (invite_cert IS NULL) = (invite_snap IS NULL) AND (invite_cert IS NULL) = (invite_actor_id IS NULL)
            )
        )
    `);

        // chats.id у каждого участника своя (личная строка), общий для всех —
        // room_id. Комната удаляется целиком — строки chats уходят вместе с ней.
        await pool.query(`
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            avatar TEXT NOT NULL,
            online INTEGER DEFAULT 0,
            is_bot INTEGER DEFAULT 0,
            -- счётчик seq чата с ботом (у комнаты он в rooms.msg_seq)
            msg_seq INTEGER NOT NULL DEFAULT nyxo_random_seq_base(),
            -- непрочитанные: seq последнего прочитанного сообщения в личной
            -- строке chats каждого участника. Задаёт приложение при создании
            -- строки (счётчик области на этот момент): «фантомно непрочитанных»
            -- нет, а колонка без DEFAULT не даст забыть об этом
            last_read_seq INTEGER NOT NULL,
            -- порядок чатов без сообщений: id случайные и порядка не несут
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            -- личные флаги чата (POST /api/chats/:chatId/prefs): собеседники их
            -- не видят
            pinned BOOLEAN NOT NULL DEFAULT FALSE,
            muted BOOLEAN NOT NULL DEFAULT FALSE,
            archived BOOLEAN NOT NULL DEFAULT FALSE
        )
    `);

        // Sealed sender на хранении (docs/security/sealed-sender.md): в строке
        // сообщения КОМНАТЫ нет ни user_id, ни chat_id (личная строка отправителя) —
        // вместо них author_tag, псевдоним автора на неделю (lib/author-tag.js).
        // Строка чата с БОТОМ наоборот: chat_id и user_id (владелец; у ответов бота
        // тоже), без тега. Взаимоисключение держит CHECK messages_author_scope.
        // chat_id ... ON DELETE CASCADE: SET NULL нарушил бы CHECK для строк бота при
        // удалении строки chats; файлы каскадно удалённых строк убирает уборщик
        // файлов-сирот. Комната удаляется — сообщения уходят каскадом; ответ на
        // удалённое сообщение теряет связь с оригиналом (SET NULL), а не блокирует
        // удаление. Приложение и так удаляет в правильном порядке (DELETE
        // /api/chats/:chatId, deleteUserAccount), каскады — страховка на случай,
        // если порядок там по ошибке изменят.
        //
        // Порядок сообщений внутри области (комнаты или чата с ботом) задаёт seq, а
        // не id и не created_at (docs/security/message-ordering.md): id случайный
        // (комнатные сообщения его выбирает клиент до шифрования, остальным id
        // выдаёт DEFAULT), created_at огрублён до минуты. seq выдаёт триггер
        // nyxo_message_seq из счётчика строки области; значение из INSERT он
        // игнорирует. Колонки time (HH:MM в часовом поясе сервера) и deleted
        // (удаление физическое) не нужны: клиент форматирует created_at сам.
        await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            seq INTEGER NOT NULL,
            chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            author_tag BYTEA,
            text TEXT NOT NULL,
            file_url TEXT,
            file_name TEXT,
            file_type TEXT,
            message_type TEXT DEFAULT 'text',
            sent INTEGER DEFAULT 1,
            status TEXT DEFAULT 'sent',
            edited_at TIMESTAMPTZ,
            reply_to_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
            -- E2EE: text хранит клиентский шифроконверт вместо обычного текста
            -- (public/e2ee.js). Серверное шифрование "at rest" (lib/message-crypto.js)
            -- применяется поверх в обоих случаях — флаг только про то, что лежит
            -- ВНУТРИ после его снятия.
            encrypted BOOLEAN NOT NULL DEFAULT FALSE,
            -- время хранится с точностью до минуты (раздел 11 контракта):
            -- порядок задаёт seq, точное время лежит только внутри E2EE-конверта
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            -- размер вложения — для квоты UPLOAD_QUOTA_MB
            file_size BIGINT,
            -- В комнате только E2EE-конверты (roadmap R7). Маршруты это уже
            -- проверяют (lib/e2ee-envelope.js); ограничение — второй рубеж на
            -- случай ошибки в коде: открытый текст комнаты не ляжет в базу вовсе.
            CONSTRAINT messages_room_e2ee CHECK (room_id IS NULL OR encrypted),
            CONSTRAINT messages_author_scope CHECK (
                   (room_id IS NULL     AND chat_id IS NOT NULL AND user_id IS NOT NULL AND author_tag IS NULL)
                OR (room_id IS NOT NULL AND chat_id IS NULL     AND user_id IS NULL     AND author_tag IS NOT NULL
                    AND octet_length(author_tag) = 16)
            )
        )
    `);

        // Новичок видит только сообщения комнаты, отправленные ПОСЛЕ его вступления
        // (visible_from_seq — seq последнего сообщения на тот момент; видно
        // сообщения с seq > visible_from_seq). Уникальный (room_id, user_id):
        // проверка "участник ли комнаты" идёт на каждый файл и реакцию, и
        // один пользователь не может оказаться в комнате дважды (с двумя
        // visible_from_seq).
        await pool.query(`
        CREATE TABLE IF NOT EXISTS room_participants (
            id SERIAL PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            visible_from_seq INTEGER NOT NULL,
            UNIQUE (room_id, user_id)
        )
    `);

        // Сертификаты состава группы (signed-membership.md, 7.1): допуск (vouch, 1), вход по
        // приглашению (join, 3) и повторный допуск (revouch, 4); приглашение (invite) лежит
        // в rooms. Времени создания нет: минута допуска внутри сертификата. Субъекта нет
        // среди внешних ключей: строки удаляет приложение вместе с выходом или удалением
        // аккаунта субъекта и подписавшего (порядок блокировок message-ordering.md, 8.1:
        // после chats, до user_left_rooms), комната - каскадом.
        await pool.query(`
        CREATE TABLE IF NOT EXISTS room_member_certs (
            room_id    INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            subject_id INTEGER NOT NULL,
            actor_id   INTEGER NOT NULL,
            kind       SMALLINT NOT NULL CHECK (kind IN (1, 3, 4)),
            cert       BYTEA NOT NULL CHECK (octet_length(cert) IN (271, 335)),
            aux        BYTEA CHECK (aux IS NULL OR octet_length(aux) = 335),
            snap       BYTEA CHECK (snap IS NULL OR (octet_length(snap) % 16 = 0 AND octet_length(snap) <= 16384)),
            PRIMARY KEY (room_id, subject_id, actor_id, kind),
            CONSTRAINT room_member_certs_length CHECK (octet_length(cert) = CASE kind WHEN 3 THEN 335 ELSE 271 END)
        )
    `);
        await pool.query('CREATE INDEX IF NOT EXISTS idx_rmc_subject ON room_member_certs(subject_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_rmc_actor ON room_member_certs(actor_id)');

        // Комнаты, откуда пользователь вышел, оставив там сообщения (sealed-sender.md,
        // 5 и 12): удаление аккаунта удаляет их во всех таких комнатах, а теги без
        // этой записи найти было бы негде. Запись создаётся только если у пользователя
        // там остались сообщения. Ключ на users - без каскада (как у остальных таблиц
        // пользователя: deleteUserAccount удаляет строки сам), на rooms - с каскадом.
        await pool.query(`
        CREATE TABLE IF NOT EXISTS user_left_rooms (
            user_id INTEGER NOT NULL REFERENCES users(id),
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, room_id)
        )
    `);
        await pool.query('CREATE INDEX IF NOT EXISTS idx_user_left_rooms_room ON user_left_rooms(room_id)');
        // Квота вложений под псевдонимом qkey (lib/upload-quota.js): в users столбцов
        // окна нет, а в самой таблице нет user_id.
        await initUploadQuotaSchema(pool);

        // Реакции исчезают вместе со своим сообщением: иначе снос всех сообщений
        // комнаты падал бы на внешнем ключе, как только у любого есть реакция.
        await pool.query(`
        CREATE TABLE IF NOT EXISTS reactions (
            id SERIAL PRIMARY KEY,
            message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            emoji TEXT NOT NULL,
            UNIQUE (message_id, user_id, emoji)
        )
    `);
        await initJoinRequests();

        // Сессии: тот же DDL, что у connect-pg-simple (его table.sql). Стор создал
        // бы таблицу сам при первом запросе, но индекс по пользователю нужен сразу:
        // выход и удаление аккаунта сбрасывают все его сессии (sess->>'userId'), и
        // без индекса это проход по всей таблице.
        await pool.query(`
        CREATE TABLE IF NOT EXISTS session (
            sid VARCHAR NOT NULL COLLATE "default",
            sess JSON NOT NULL,
            expire TIMESTAMP(6) NOT NULL,
            CONSTRAINT session_pkey PRIMARY KEY (sid)
        )
    `);
        await pool.query('CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON session(expire)');
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_session_user ON session((sess->>'userId'))`);

        await initE2eeGroupsSchema(pool);
        // Лимиты и использованные решения PoW (UNLOGGED, lib/pg-limits.js).
        await initPgLimitsSchema(pool);
        // Публичные E2EE-ключи хранятся в этой же базе (lib/key-store.js).
        await initKeyStoreSchema(pool);
        // Таблицы message_expiry/chat_settings/room_settings ссылаются на
        // messages/chats/rooms, поэтому создаются только после них.
        await disappearingMessagesManager.initialize();

        // Индексы для выборок "сообщения области по seq". Это же уникальные
        // индексы порядка (O1 контракта): пара (область, seq) не повторяется, а
        // seq растёт в порядке фиксации вставок. Включённые колонки позволяют
        // последнему сообщению, счётчику непрочитанного, странице истории и
        // кандидатам поиска читаться index-only scan'ом: без них планировщик
        // выбирал бы обратный проход по первичному ключу с фильтром по room_id —
        // для "тихой" комнаты это просмотр почти всей таблицы. В списке INCLUDE нет
        // ни id, ни seq: они уже в ключе или в первичном ключе. Каскад удаления
        // комнаты обслуживает префикс (room_id).
        await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_room_seq ON messages(room_id, seq) INCLUDE (sent, encrypted) WHERE room_id IS NOT NULL');
        await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_chat_seq ON messages(chat_id, seq) INCLUDE (user_id, sent, encrypted) WHERE room_id IS NULL');
        // Внешний ключ messages.chat_id ... ON DELETE CASCADE: частичный индекс
        // выше по условию запроса RI (chat_id = $1, без room_id IS NULL) не
        // применим, и без этого индекса удаление каждой строки chats сканировало бы
        // всю таблицу messages (выход из комнаты, удаление аккаунта).
        await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id) WHERE chat_id IS NOT NULL');
        // Внешний ключ messages.user_id (только чат с ботом): запрос RI при удалении
        // users - `WHERE user_id = $1`, и частичный индекс с условием по room_id он
        // бы не использовал. Условие user_id IS NOT NULL следует из равенства, а
        // строки комнат (user_id NULL) в индекс не попадают.
        await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id) WHERE user_id IS NOT NULL');
        // Тег автора: правка, удаление, прочитано, выход и удаление аккаунта ищут
        // строки комнаты по (комната, набор тегов).
        await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_room_author ON messages(room_id, author_tag) WHERE room_id IS NOT NULL');
        // Каждая картинка/файл в чате проверяет доступ поиском по file_url —
        // без индекса это был бы полный проход по всей таблице messages на КАЖДЫЙ
        // запрос /uploads/*.
        await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_file_url ON messages(file_url) WHERE file_url IS NOT NULL');
        // Для ON DELETE SET NULL по reply_to_id: без индекса удаление каждого
        // сообщения сканировало бы всю таблицу в поисках ответов на него (снос
        // комнаты с N сообщениями — N полных проходов).
        await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_reply_to_id ON messages(reply_to_id) WHERE reply_to_id IS NOT NULL');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_room_id ON chats(room_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_room_participants_user ON room_participants(user_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_reactions_msg_user ON reactions(message_id, user_id)');
        // Авто-разархивация получателей идёт на КАЖДОЕ новое сообщение комнаты;
        // по частичному индексу она читает только архивные строки комнаты
        // (обычно ни одной), а не строки всех её участников.
        await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_archived ON chats(room_id) WHERE archived');

        await setRandomIdDefaults();
        // Надгробия id, триггеры seq и проверки id (lib/message-order-schema.js):
        // нужны messages, rooms, chats и DEFAULT id выше.
        await initMessageOrderSchema(pool);

        console.log('База данных инициализирована');
    }

    // DEFAULT со ссылкой на таблицу (nyxo_random_id('users'::regclass)) можно
    // задать только после CREATE TABLE: внутри него таблицы ещё нет, поэтому
    // отдельным ALTER. ALTER берёт ACCESS EXCLUSIVE блокировку, и повторять его на
    // каждом старте незачем: он выполняется только там, где DEFAULT ещё не задан.
    async function setRandomIdDefaults() {
        await pool.query(`
        CREATE OR REPLACE FUNCTION nyxo_random_id(target regclass) RETURNS integer
        LANGUAGE plpgsql VOLATILE AS $fn$${RANDOM_ID_FUNCTION_BODY}$fn$
    `);
        const current = await dbAll(
            `SELECT table_name, column_default FROM information_schema.columns
         WHERE table_schema = current_schema() AND column_name = 'id' AND table_name = ANY($1::text[])`,
            [RANDOM_ID_TABLES]
        );
        for (const table of RANDOM_ID_TABLES) {
            const row = current.find(r => r.table_name === table);
            if (!String((row && row.column_default) || '').includes('nyxo_random_id(')) {
                await pool.query(`ALTER TABLE ${table} ALTER COLUMN id SET DEFAULT nyxo_random_id('${table}'::regclass)`);
            }
        }
    }

    // Заявки на вступление (комнаты с одобрением). join_requests.id виден
    // заявителю и участникам комнаты — он случайный, как id пользователей и
    // комнат (DEFAULT ставит setRandomIdDefaults), чтобы по нему нельзя было
    // судить, сколько заявок подают по всему сервису. Внешний ключ на users без
    // каскада — как у остальных таблиц: deleteUserAccount удаляет строки сам.
    async function initJoinRequests() {
        await pool.query(`
        CREATE TABLE IF NOT EXISTS join_requests (
            id INTEGER PRIMARY KEY,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now()),
            UNIQUE (room_id, user_id)
        )
    `);
        await pool.query('CREATE INDEX IF NOT EXISTS idx_join_requests_user ON join_requests(user_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_join_requests_created ON join_requests(created_at)');
    }

    return { initDatabase };
}

module.exports = { createSchema };
