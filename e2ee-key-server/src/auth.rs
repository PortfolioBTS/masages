//! Внутренняя аутентификация.
//!
//! Этот сервис НИКОГДА не должен быть доступен напрямую из интернета —
//! клиент всегда обращается через Node, который уже проверил сессию
//! пользователя (existing express-session) и проксирует запрос сюда по
//! loopback, подставляя заголовки:
//!   X-Internal-Secret: общий секрет из .env (сравнение constant-time)
//!   X-User-Id: числовой id уже аутентифицированного пользователя
//!
//! Секрет — это defense-in-depth на случай ослабления сетевой изоляции,
//! а не основной механизм безопасности; основной механизм — bind на
//! 127.0.0.1 и отсутствие публичного порта на этот процесс.

use axum::{extract::FromRequestParts, http::request::Parts};
use subtle::ConstantTimeEq;

use crate::{error::AppError, AppState};

pub struct AuthedUser(pub i64);

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let given_secret = parts
            .headers
            .get("x-internal-secret")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let expected = state.config.internal_shared_secret.as_bytes();
        let given = given_secret.as_bytes();
        let equal = given.len() == expected.len() && given.ct_eq(expected).unwrap_u8() == 1;
        if !equal {
            return Err(AppError::Unauthorized);
        }

        let user_id: i64 = parts
            .headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or(AppError::Unauthorized)?;

        Ok(AuthedUser(user_id))
    }
}
