-- Постквантовый prekey (ML-KEM-768) для PQXDH.
--
-- Один текущий ключ на пользователя, ротация = перезапись — так же, как
-- signed_prekeys. Это «last resort» ключ из спецификации PQXDH: при выдаче
-- bundle он НЕ расходуется, пула одноразовых PQ-prekey нет. Спецификация
-- это допускает; цена — одинаковый PQ-prekey во всех сессиях, начатых
-- между ротациями.
--
-- 0001_init.sql не меняется: sqlx сверяет контрольные суммы уже
-- применённых миграций, и правка старого файла сломала бы старт сервиса.

CREATE TABLE IF NOT EXISTS signed_pq_prekeys (
    user_id      BIGINT PRIMARY KEY,
    key_id       BIGINT NOT NULL,
    public_key   BYTEA NOT NULL,   -- ML-KEM-768 encapsulation key, 1184 bytes
    signature    BYTEA NOT NULL,   -- Ed25519 (identity_signing_key) над public_key, 64 bytes
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
