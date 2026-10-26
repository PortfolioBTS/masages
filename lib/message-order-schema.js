'use strict';
// Схема порядка и идентификаторов сообщений: триггеры seq, надгробия id и
// задача очистки надгробий (docs/security/message-ordering.md, разделы 5.2–5.3).
//
// Таблицы messages, rooms, chats и room_participants создаёт initDatabase
// (src/db/schema.js) — вместе с колонками seq и счётчиками msg_seq. Здесь то, что к
// ним добавляется после создания:
//   * message_tombstones — id удалённых сообщений, которые нельзя занять заново
//     30 суток; в таблице нет ни комнаты, ни автора, ни точного времени, только
//     id и срок с точностью до суток;
//   * функции и триггеры messages: проверка надгробия, выдача seq, запись
//     надгробия при ЛЮБОМ удалении строки (таймер, автор, удаление аккаунта,
//     каскад комнаты). Триггер не оставляет пути удаления без надгробия;
//   * фоновая задача очистки просроченных надгробий (lib/jobs, JOB_MODULES).
//
// initMessageOrderSchema идемпотентна: функции пересоздаются CREATE OR REPLACE,
// триггеры — только если их ещё нет (CREATE OR REPLACE TRIGGER появился в
// PostgreSQL 14, а проект поддерживает 13).

// Срок надгробия — 31 сутки от дня удаления (округление вверх до суток, так что
// фактически от 30 до 31): занять id удалённого сообщения нельзя минимум 30 суток.
const TOMBSTONE_DAYS = 31;

const ID_CHECK_FUNCTION = `
    CREATE OR REPLACE FUNCTION nyxo_message_id_check() RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN
      IF EXISTS (SELECT 1 FROM message_tombstones WHERE id = NEW.id AND expires_at > now()) THEN
        RAISE EXCEPTION 'message id is retired' USING ERRCODE = '23505', CONSTRAINT = 'message_tombstones_pkey';
      END IF;
      RETURN NEW;
    END $fn$
`;

// Выдаёт seq. Строка области блокируется на время транзакции вставки: так
// отправки в одну комнату и вступление новичка выстраиваются в очередь, а seq
// совпадает с порядком фиксации транзакций. Значение seq из INSERT игнорируется.
const SEQ_FUNCTION = `
    CREATE OR REPLACE FUNCTION nyxo_message_seq() RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN
      IF NEW.room_id IS NOT NULL THEN
        UPDATE rooms SET msg_seq = msg_seq + 1 WHERE id = NEW.room_id RETURNING msg_seq INTO NEW.seq;
      ELSE
        UPDATE chats SET msg_seq = msg_seq + 1 WHERE id = NEW.chat_id RETURNING msg_seq INTO NEW.seq;
      END IF;
      IF NEW.seq IS NULL THEN
        RAISE EXCEPTION 'message scope not found' USING ERRCODE = '23503';
      END IF;
      RETURN NEW;
    END $fn$
`;

// ON CONFLICT ... DO UPDATE, а не DO NOTHING: если старое надгробие этого id уже
// просрочено, но очистка до него ещё не дошла, а сообщение с освободившимся id
// снова удалили, срок должен начаться заново, а не остаться прошлым.
const TOMBSTONE_FUNCTION = `
    CREATE OR REPLACE FUNCTION nyxo_message_tombstone() RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN
      INSERT INTO message_tombstones (id, expires_at)
      VALUES (OLD.id, date_trunc('day', now()) + interval '${TOMBSTONE_DAYS} days')
      ON CONFLICT (id) DO UPDATE SET expires_at = GREATEST(message_tombstones.expires_at, EXCLUDED.expires_at);
      RETURN NULL;
    END $fn$
`;

// Имя триггера определяет порядок срабатывания (по алфавиту): проверка
// надгробия идёт раньше выдачи seq, поэтому запрещённый id не берёт блокировку
// строки комнаты.
const TRIGGERS = Object.freeze([
    { name: 'messages_10_id_check', when: 'BEFORE INSERT', fn: 'nyxo_message_id_check' },
    { name: 'messages_20_seq', when: 'BEFORE INSERT', fn: 'nyxo_message_seq' },
    { name: 'messages_90_tombstone', when: 'AFTER DELETE', fn: 'nyxo_message_tombstone' },
]);

async function initMessageOrderSchema(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS message_tombstones (
            id INTEGER PRIMARY KEY,
            -- с точностью до суток (раздел 11 контракта)
            expires_at TIMESTAMPTZ NOT NULL
        )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_message_tombstones_expires ON message_tombstones(expires_at)');
    await pool.query(ID_CHECK_FUNCTION);
    await pool.query(SEQ_FUNCTION);
    await pool.query(TOMBSTONE_FUNCTION);
    for (const trigger of TRIGGERS) {
        // Имена — константы этого файла, не ввод пользователя.
        await pool.query(`
            DO $do$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgrelid = 'messages'::regclass AND tgname = '${trigger.name}' AND NOT tgisinternal
                ) THEN
                    CREATE TRIGGER ${trigger.name} ${trigger.when} ON messages
                        FOR EACH ROW EXECUTE FUNCTION ${trigger.fn}();
                END IF;
            END
            $do$
        `);
    }
}

// Просроченные надгробия: запись действует, пока expires_at > now() (так её
// читает триггер проверки), а очистка убирает остальные.
async function purgeExpiredTombstones(pool) {
    const result = await pool.query('DELETE FROM message_tombstones WHERE expires_at <= now()');
    return result.rowCount;
}

// Задачи для реестра lib/jobs (JOB_MODULES): раз в час, под runExclusive.
function jobs(ctx) {
    return [{
        name: 'purgeMessageTombstones',
        run: () => purgeExpiredTombstones(ctx.pool),
        firstDelayMs: 2 * 60 * 1000,
        intervalMs: 60 * 60 * 1000,
        maintenance: true,
    }];
}

module.exports = {
    TOMBSTONE_DAYS,
    TRIGGERS,
    initMessageOrderSchema,
    purgeExpiredTombstones,
    jobs,
};
