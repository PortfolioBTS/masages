use axum::{
    extract::{Path, State},
    Json,
};

use crate::{
    auth::AuthedUser,
    crypto::{decode_pubkey, decode_signature, encode_b64},
    db,
    error::AppError,
    models::*,
    AppState,
};

pub async fn health() -> &'static str {
    "ok"
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
    }))
}

/// DELETE /internal/v1/keys
/// Полная очистка ключевого материала вызывающего пользователя
/// (например, при удалении аккаунта). Часть требований по эфемерности.
pub async fn delete_keys(
    State(state): State<AppState>,
    AuthedUser(user_id): AuthedUser,
) -> Result<Json<OkResponse>, AppError> {
    db::delete_all_keys(&state.pool, user_id).await?;
    Ok(Json(OkResponse::ok()))
}
