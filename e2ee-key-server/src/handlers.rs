use axum::{
    extract::{Path, Query, State},
    Json,
};

use crate::{
    auth::AuthedUser,
    crypto::{decode_pq_pubkey, decode_pubkey, decode_signature, encode_b64, verify_pq_prekey},
    db,
    error::AppError,
    models::*,
    AppState,
};

/// Столько же пропускает Node-прокси (lib/e2ee-proxy.js): больше участников
/// в одной проверке identity не бывает, а длинный список — лишняя нагрузка.
const MAX_IDENTITY_IDS: usize = 200;

pub async fn health() -> &'static str {
    "ok"
}

/// Разбирает `1,2,3` в отсортированный список уникальных положительных id.
/// Пустой список, пустые элементы, не-цифры, 0, переполнение i64 и больше
/// MAX_IDENTITY_IDS элементов — 400: на битый запрос честнее отказать,
/// чем молча ответить по его части. Лимит проверяется до разбора
/// элемента, чтобы длинная строка из запятых не раздувала работу.
fn parse_id_list(raw: &str) -> Result<Vec<i64>, AppError> {
    let mut ids = Vec::new();
    for (index, part) in raw.split(',').enumerate() {
        if index >= MAX_IDENTITY_IDS {
            return Err(AppError::BadRequest(format!(
                "ids: at most {MAX_IDENTITY_IDS} ids per request"
            )));
        }
        let part = part.trim();
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AppError::BadRequest(
                "ids: expected comma-separated positive integers".into(),
            ));
        }
        let id: i64 = part
            .parse()
            .map_err(|_| AppError::BadRequest("ids: id out of range".into()))?;
        if id == 0 {
            return Err(AppError::BadRequest("ids: id must be positive".into()));
        }
        ids.push(id);
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// PUT /internal/v1/keys/identity
/// Регистрирует/полностью заменяет identity-ключи вызывающего пользователя.
/// В V1 предполагается одно устройство на пользователя — мультидевайс
/// (несколько параллельных identity per user) вне рамок этого шага.
pub async fn put_identity_keys(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
    Json(req): Json<IdentityKeysRequest>,
) -> Result<Json<OkResponse>, AppError> {
    let signing_key = decode_pubkey("identity_signing_key", &req.identity_signing_key)?;
    let dh_key = decode_pubkey("identity_dh_key", &req.identity_dh_key)?;

    db::upsert_identity_keys(&state.pool, user_id, &signing_key, &dh_key).await?;
    Ok(Json(OkResponse::ok()))
}

/// PUT /internal/v1/keys/signed-prekey
/// Ротация Signed PreKey. Требует, чтобы identity-ключи уже были
/// зарегистрированы (иначе нечем проверить подпись — 409).
pub async fn put_signed_prekey(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
    Json(req): Json<SignedPrekeyRequest>,
) -> Result<Json<OkResponse>, AppError> {
    let public_key = decode_pubkey("public_key", &req.public_key)?;
    let signature = decode_signature("signature", &req.signature)?;

    let signing_key = db::get_identity_signing_key(&state.pool, user_id)
        .await?
        .ok_or_else(|| {
            AppError::Conflict("identity keys must be registered before a signed prekey".into())
        })?;

    crate::crypto::verify_signed_prekey(&signing_key, &public_key, &signature)?;

    db::upsert_signed_prekey(&state.pool, user_id, req.key_id, &public_key, &signature).await?;
    Ok(Json(OkResponse::ok()))
}

/// PUT /internal/v1/keys/pq-prekey
/// Ротация постквантового (ML-KEM-768) prekey для PQXDH. Как и SPK,
/// подписан identity_signing_key (над сырыми 1184 байтами ключа), поэтому
/// без зарегистрированного identity — 409.
pub async fn put_pq_prekey(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
    Json(req): Json<PqPrekeyRequest>,
) -> Result<Json<OkResponse>, AppError> {
    let public_key = decode_pq_pubkey("public_key", &req.public_key)?;
    let signature = decode_signature("signature", &req.signature)?;

    let signing_key = db::get_identity_signing_key(&state.pool, user_id)
        .await?
        .ok_or_else(|| {
            AppError::Conflict("identity keys must be registered before a PQ prekey".into())
        })?;

    verify_pq_prekey(&signing_key, &public_key, &signature)?;

    db::upsert_pq_prekey(&state.pool, user_id, req.key_id, &public_key, &signature).await?;
    Ok(Json(OkResponse::ok()))
}

/// GET /internal/v1/keys/identities?ids=1,2,3
/// Публичные identity-ключи нескольких пользователей — для safety number и
/// обнаружения смены ключа у собеседников. В отличие от bundle, OPK не
/// расходует. Кому чьи ключи можно видеть (общая комната), решает
/// Node-прокси до вызова: сюда приходит уже отфильтрованный список.
pub async fn get_identities(
    State(state): State<AppState>,
    AuthedUser(_requesting_user_id): AuthedUser,
    Query(query): Query<IdentitiesQuery>,
) -> Result<Json<IdentitiesResponse>, AppError> {
    let ids = parse_id_list(query.ids.as_deref().unwrap_or(""))?;
    let rows = db::fetch_identities(&state.pool, &ids).await?;

    Ok(Json(IdentitiesResponse {
        identities: rows
            .into_iter()
            .map(|(user_id, identity)| IdentityDto {
                user_id,
                identity_signing_key: encode_b64(&identity.identity_signing_key),
                identity_dh_key: encode_b64(&identity.identity_dh_key),
            })
            .collect(),
    }))
}

/// POST /internal/v1/keys/one-time-prekeys
/// Пополнение пула one-time prekeys. Дубликаты key_id тихо игнорируются.
pub async fn post_one_time_prekeys(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
    Json(req): Json<OneTimePrekeysRequest>,
) -> Result<Json<OneTimePrekeysUploadResponse>, AppError> {
    if req.keys.is_empty() {
        return Err(AppError::BadRequest("keys must not be empty".into()));
    }
    if req.keys.len() > state.config.max_otpk_batch {
        return Err(AppError::BadRequest(format!(
            "batch too large: max {} keys per request",
            state.config.max_otpk_batch
        )));
    }

    let mut key_ids = Vec::with_capacity(req.keys.len());
    let mut public_keys = Vec::with_capacity(req.keys.len());
    for item in &req.keys {
        let pk = decode_pubkey("keys[].public_key", &item.public_key)?;
        key_ids.push(item.key_id);
        public_keys.push(pk.to_vec());
    }

    let inserted =
        db::insert_one_time_prekeys(&state.pool, user_id, &key_ids, &public_keys).await?;
    Ok(Json(OneTimePrekeysUploadResponse {
        success: true,
        inserted,
    }))
}

/// GET /internal/v1/keys/one-time-prekeys/count
/// Позволяет Node/клиенту решить, пора ли пополнять пул OPK.
pub async fn get_one_time_prekey_count(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
) -> Result<Json<OneTimePrekeyCountResponse>, AppError> {
    let count = db::count_one_time_prekeys(&state.pool, user_id).await?;
    Ok(Json(OneTimePrekeyCountResponse { count }))
}

/// GET /internal/v1/keys/bundle/:target_user_id
/// Выдаёт bundle для старта X3DH-сессии с target_user_id, атомарно
/// забирая один one-time prekey из пула (если есть).
///
/// Принятая по threat model L4 утечка метаданных: сервер узнаёт, что
/// user_id запросил bundle target_user_id (кто с кем хочет говорить).
/// Скрытие этого паттерна запросов потребовало бы mixnet/PIR, что прямо
/// исключено зафиксированной моделью угроз (L4, не L5/L6).
pub async fn get_bundle(
    State(state): State<AppState>,
    AuthedUser(_requesting_user_id): AuthedUser,
    Path(target_user_id): Path<i64>,
) -> Result<Json<BundleResponse>, AppError> {
    let bundle = db::fetch_bundle(&state.pool, target_user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(BundleResponse {
        identity_signing_key: encode_b64(&bundle.identity.identity_signing_key),
        identity_dh_key: encode_b64(&bundle.identity.identity_dh_key),
        signed_prekey: SignedPrekeyDto {
            key_id: bundle.signed_prekey.key_id,
            public_key: encode_b64(&bundle.signed_prekey.public_key),
            signature: encode_b64(&bundle.signed_prekey.signature),
        },
        one_time_prekey: bundle.one_time_prekey.map(|o| OneTimePrekeyDto {
            key_id: o.key_id,
            public_key: encode_b64(&o.public_key),
        }),
        pq_prekey: bundle.pq_prekey.map(|p| SignedPrekeyDto {
            key_id: p.key_id,
            public_key: encode_b64(&p.public_key),
            signature: encode_b64(&p.signature),
        }),
    }))
}

/// DELETE /internal/v1/keys
/// Полная очистка ключевого материала вызывающего пользователя, включая
/// PQ-prekey (например, при удалении аккаунта). Часть требований по
/// эфемерности.
pub async fn delete_keys(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
) -> Result<Json<OkResponse>, AppError> {
    db::delete_all_keys(&state.pool, user_id).await?;
    Ok(Json(OkResponse::ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_list_sorts_and_dedups() {
        assert_eq!(parse_id_list("3,1,3, 2").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_id_list("42").unwrap(), vec![42]);
    }

    #[test]
    fn parse_id_list_rejects_empty() {
        for raw in ["", " ", ",", "1,", ",1", "1,,2"] {
            assert!(parse_id_list(raw).is_err(), "{raw:?} must be rejected");
        }
    }

    #[test]
    fn parse_id_list_rejects_garbage() {
        for raw in ["abc", "1,x", "-1", "0", "+5", "1.5", "1 2", "99999999999999999999"] {
            assert!(parse_id_list(raw).is_err(), "{raw:?} must be rejected");
        }
    }

    #[test]
    fn parse_id_list_enforces_limit() {
        let list = |n: usize| {
            (1..=n)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        assert_eq!(parse_id_list(&list(MAX_IDENTITY_IDS)).unwrap().len(), MAX_IDENTITY_IDS);
        assert!(parse_id_list(&list(MAX_IDENTITY_IDS + 1)).is_err());
    }
}
