use sqlx::PgPool;

use crate::crypto::{PUBKEY_LEN, SIGNATURE_LEN};

pub struct SignedPrekeyRow {
    pub key_id: i64,
    pub public_key: [u8; PUBKEY_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

pub struct IdentityRow {
    pub identity_signing_key: [u8; PUBKEY_LEN],
    pub identity_dh_key: [u8; PUBKEY_LEN],
}

pub struct OneTimePrekeyRow {
    pub key_id: i64,
    pub public_key: [u8; PUBKEY_LEN],
}

pub struct Bundle {
    pub identity: IdentityRow,
    pub signed_prekey: SignedPrekeyRow,
    pub one_time_prekey: Option<OneTimePrekeyRow>,
}

fn to_arr32(v: Vec<u8>) -> [u8; PUBKEY_LEN] {
    // Инвариант: в БД эти колонки всегда ровно 32 байта — проверяется при
    // записи (crypto::decode_pubkey). Несовпадение длины означает порчу
    // данных на диске, а не пользовательский ввод, поэтому паника здесь
    // уместнее, чем тихая деградация.
    v.try_into().expect("corrupt row: expected 32-byte key")
}

fn to_arr64(v: Vec<u8>) -> [u8; SIGNATURE_LEN] {
    v.try_into()
        .expect("corrupt row: expected 64-byte signature")
}

pub async fn upsert_identity_keys(
    pool: &PgPool,
    user_id: i64,
    signing_key: &[u8; PUBKEY_LEN],
    dh_key: &[u8; PUBKEY_LEN],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO identity_keys (user_id, identity_signing_key, identity_dh_key, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (user_id) DO UPDATE
            SET identity_signing_key = EXCLUDED.identity_signing_key,
                identity_dh_key = EXCLUDED.identity_dh_key,
                updated_at = now()
        "#,
    )
    .bind(user_id)
    .bind(&signing_key[..])
    .bind(&dh_key[..])
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_identity_signing_key(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<[u8; PUBKEY_LEN]>, sqlx::Error> {
    let row = sqlx::query_as::<_, (Vec<u8>,)>(
        "SELECT identity_signing_key FROM identity_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(k,)| to_arr32(k)))
}

pub async fn upsert_signed_prekey(
    pool: &PgPool,
    user_id: i64,
    key_id: i64,
    public_key: &[u8; PUBKEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO signed_prekeys (user_id, key_id, public_key, signature, created_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (user_id) DO UPDATE
            SET key_id = EXCLUDED.key_id,
                public_key = EXCLUDED.public_key,
                signature = EXCLUDED.signature,
                created_at = now()
        "#,
    )
    .bind(user_id)
    .bind(key_id)
    .bind(&public_key[..])
    .bind(&signature[..])
    .execute(pool)
    .await?;
    Ok(())
}

/// Массовая загрузка one-time prekeys. Дубликаты (тот же key_id) молча
/// игнорируются — идемпотентно на случай повторной отправки клиентом.
/// Возвращает число реально вставленных строк.
pub async fn insert_one_time_prekeys(
    pool: &PgPool,
    user_id: i64,
    key_ids: &[i64],
    public_keys: &[Vec<u8>],
) -> Result<u64, sqlx::Error> {
    debug_assert_eq!(key_ids.len(), public_keys.len());
    let result = sqlx::query(
        r#"
        INSERT INTO one_time_prekeys (user_id, key_id, public_key)
        SELECT $1, t.key_id, t.public_key
        FROM UNNEST($2::bigint[], $3::bytea[]) AS t(key_id, public_key)
        ON CONFLICT (user_id, key_id) DO NOTHING
        "#,
    )
    .bind(user_id)
    .bind(key_ids)
    .bind(public_keys)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn count_one_time_prekeys(pool: &PgPool, user_id: i64) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// Атомарно собирает bundle для установления сессии с target_user_id:
/// identity keys + текущий signed prekey + (если есть) один one-time
/// prekey, который тут же удаляется (claim-and-consume под
/// `FOR UPDATE SKIP LOCKED`, чтобы конкурентные запросы не выдавали
/// один и тот же OPK дважды). Если у target нет identity-ключей или
/// signed prekey — считаем, что пользователь не завершил E2EE-онбординг,
/// и возвращаем None.
pub async fn fetch_bundle(
    pool: &PgPool,
    target_user_id: i64,
) -> Result<Option<Bundle>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let identity = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT identity_signing_key, identity_dh_key FROM identity_keys WHERE user_id = $1",
    )
    .bind(target_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((signing_key, dh_key)) = identity else {
        return Ok(None);
    };

    let spk = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>)>(
        "SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = $1",
    )
    .bind(target_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((spk_key_id, spk_pub, spk_sig)) = spk else {
        return Ok(None);
    };

    let otpk = sqlx::query_as::<_, (i64, i64, Vec<u8>)>(
        r#"
        DELETE FROM one_time_prekeys
        WHERE id = (
            SELECT id FROM one_time_prekeys
            WHERE user_id = $1
            ORDER BY id ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, key_id, public_key
        "#,
    )
    .bind(target_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(Bundle {
        identity: IdentityRow {
            identity_signing_key: to_arr32(signing_key),
            identity_dh_key: to_arr32(dh_key),
        },
        signed_prekey: SignedPrekeyRow {
            key_id: spk_key_id,
            public_key: to_arr32(spk_pub),
            signature: to_arr64(spk_sig),
        },
        one_time_prekey: otpk.map(|(_, key_id, public_key)| OneTimePrekeyRow {
            key_id,
            public_key: to_arr32(public_key),
        }),
    }))
}

/// Полное удаление ключевого материала пользователя — используется при
/// удалении аккаунта, часть требований по эфемерности из threat model.
pub async fn delete_all_keys(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM one_time_prekeys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM signed_prekeys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM identity_keys WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
