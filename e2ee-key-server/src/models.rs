use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct IdentityKeysRequest {
    pub identity_signing_key: String, // base64, Ed25519 pub, 32 bytes
    pub identity_dh_key: String,      // base64, X25519 pub, 32 bytes
}

#[derive(Deserialize)]
pub struct SignedPrekeyRequest {
    pub key_id: i64,
    pub public_key: String, // base64, X25519 pub, 32 bytes
    pub signature: String,  // base64, Ed25519 signature, 64 bytes
}

#[derive(Deserialize)]
pub struct OneTimePrekeyItem {
    pub key_id: i64,
    pub public_key: String, // base64, X25519 pub, 32 bytes
}

#[derive(Deserialize)]
pub struct OneTimePrekeysRequest {
    pub keys: Vec<OneTimePrekeyItem>,
}

#[derive(Serialize)]
pub struct OkResponse {
    pub success: bool,
}

impl OkResponse {
    pub fn ok() -> Self {
        Self { success: true }
    }
}

#[derive(Serialize)]
pub struct OneTimePrekeysUploadResponse {
    pub success: bool,
    pub inserted: u64,
}

#[derive(Serialize)]
pub struct OneTimePrekeyCountResponse {
    pub count: i64,
}

#[derive(Serialize)]
pub struct SignedPrekeyDto {
    pub key_id: i64,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct OneTimePrekeyDto {
    pub key_id: i64,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct BundleResponse {
    pub identity_signing_key: String,
    pub identity_dh_key: String,
    pub signed_prekey: SignedPrekeyDto,
    /// None если у пользователя временно кончились one-time prekeys.
    /// X3DH в этом случае деградирует (пропускается DH-шаг с OPK) —
    /// сессия остаётся безопасной, но теряется часть forward secrecy
    /// для самого первого сообщения. Клиент должен показать это как
    /// повод срочно пополнить пул своих OPK на стороне получателя.
    pub one_time_prekey: Option<OneTimePrekeyDto>,
}
