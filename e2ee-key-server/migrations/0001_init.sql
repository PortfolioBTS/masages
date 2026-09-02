-- E2EE Key Exchange Server — schema
--
-- Владение: эта схема принадлежит исключительно Rust-сервису e2ee-key-server.
-- Node-приложение эти таблицы не читает и не пишет напрямую.
--
-- Намеренно НЕТ FOREIGN KEY на users(id) из Node-БД: сервисы физически
-- используют один и тот же Postgres-инстанс (упрощение для бета/соло-разработки),
-- но логически развязаны. user_id — это просто BIGINT, соответствующий
-- users.id в Node-схеме; целостность обеспечивается на уровне приложения.
--
-- Сервер НИКОГДА не хранит приватные ключи. Только публичный материал.

CREATE TABLE IF NOT EXISTS identity_keys (
    user_id               BIGINT PRIMARY KEY,
    identity_signing_key  BYTEA NOT NULL,   -- Ed25519 public key, 32 bytes
    identity_dh_key       BYTEA NOT NULL,   -- X25519 public key, 32 bytes
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Один текущий Signed PreKey на пользователя (ротация = перезапись).
CREATE TABLE IF NOT EXISTS signed_prekeys (
    user_id      BIGINT PRIMARY KEY,
    key_id       BIGINT NOT NULL,
    public_key   BYTEA NOT NULL,   -- X25519 public key, 32 bytes
    signature    BYTEA NOT NULL,   -- Ed25519 signature over public_key, 64 bytes
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Пул одноразовых prekeys. Каждая запись удаляется атомарно при выдаче bundle.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL,
    key_id       BIGINT NOT NULL,
    public_key   BYTEA NOT NULL,   -- X25519 public key, 32 bytes
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, key_id)
);

CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekeys(user_id);
