//! Криптографические проверки на стороне сервера.
//!
//! ВАЖНО: сервер здесь выступает только верификатором и хранилищем
//! ПУБЛИЧНОГО материала. Приватные ключи генерируются и остаются на
//! клиенте (сервис ④, WASM), сюда они никогда не попадают, и этот модуль
//! не содержит ни одной операции, требующей приватного ключа.
//!
//! Дизайн identity-ключей: вместо схемы Signal с одним X25519-ключом,
//! конвертируемым в форму для подписи через XEdDSA, используются ДВА
//! отдельных ключа на пользователя:
//!   - identity_signing_key — Ed25519, только для подписи Signed PreKey;
//!   - identity_dh_key      — X25519, только для DH в X3DH (DH1/DH2).
//! Это отступление от «чистого» X3DH ради простоты и корректности
//! реализации: не нужен самодельный код конвертации Montgomery↔Edwards.
//! Компромисс осознанный и не снижает итоговых security-свойств протокола.

use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const PUBKEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub fn decode_b64(field: &str, s: &str) -> Result<Vec<u8>, AppError> {
    STANDARD
        .decode(s)
        .map_err(|_| AppError::BadRequest(format!("{field}: invalid base64")))
}

/// Декодирует и проверяет 32-байтовый публичный ключ (X25519 или Ed25519).
/// Отбраковывает all-zero ключ — известная low-order/identity точка на
/// Curve25519, использование которой в DH даёт предсказуемый общий секрет.
/// Это defense-in-depth: настоящая защита от small-subgroup атак должна
/// быть и на стороне клиента при вычислении DH, но лишняя проверка на
/// границе сервиса ничего не стоит.
pub fn decode_pubkey(field: &str, s: &str) -> Result<[u8; PUBKEY_LEN], AppError> {
    let bytes = decode_b64(field, s)?;
    let arr: [u8; PUBKEY_LEN] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: must be {PUBKEY_LEN} bytes")))?;
    if arr.iter().all(|b| *b == 0) {
        return Err(AppError::BadRequest(format!(
            "{field}: all-zero key rejected (low-order point)"
        )));
    }
    Ok(arr)
}

pub fn decode_signature(field: &str, s: &str) -> Result<[u8; SIGNATURE_LEN], AppError> {
    let bytes = decode_b64(field, s)?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: must be {SIGNATURE_LEN} bytes")))
}

/// Проверяет подпись Signed PreKey ключом identity_signing_key.
///
/// Это проверка defense-in-depth на upload: сервер отклоняет заведомо
/// битые bundle. Настоящая security-гарантия X3DH требует, чтобы
/// ПОЛУЧАТЕЛЬ bundle тоже независимо проверял эту подпись перед
/// использованием SPK — сервер в модели угроз L4 не доверенная сторона,
/// и клиентская проверка не должна полагаться на то, что сервер её уже
/// сделал.
pub fn verify_signed_prekey(
    identity_signing_key: &[u8; PUBKEY_LEN],
    spk_public_key: &[u8; PUBKEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), AppError> {
    let verifying_key = VerifyingKey::from_bytes(identity_signing_key)
        .map_err(|_| AppError::BadRequest("identity_signing_key: invalid Ed25519 point".into()))?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(spk_public_key, &sig)
        .map_err(|_| AppError::BadRequest("signed_prekey: signature verification failed".into()))
}

pub fn encode_b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let signing_key = fixed_signing_key(1);
        let verifying_key = signing_key.verifying_key();
        let spk_public = [7u8; 32];
        let sig = signing_key.sign(&spk_public);

        let result = verify_signed_prekey(&verifying_key.to_bytes(), &spk_public, &sig.to_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let signing_key = fixed_signing_key(2);
        let verifying_key = signing_key.verifying_key();
        let spk_public = [7u8; 32];
        let sig = signing_key.sign(&spk_public);

        let tampered_public = [8u8; 32]; // подпись выдана для другого сообщения
        let result =
            verify_signed_prekey(&verifying_key.to_bytes(), &tampered_public, &sig.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let signing_key_a = fixed_signing_key(3);
        let signing_key_b = fixed_signing_key(4);
        let spk_public = [9u8; 32];
        let sig = signing_key_b.sign(&spk_public); // подписано не тем ключом

        let result = verify_signed_prekey(
            &signing_key_a.verifying_key().to_bytes(),
            &spk_public,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_pubkey_rejects_all_zero() {
        let zero_b64 = encode_b64(&[0u8; 32]);
        let result = decode_pubkey("test_field", &zero_b64);
        assert!(result.is_err());
    }

    #[test]
    fn decode_pubkey_rejects_wrong_length() {
        let short_b64 = encode_b64(&[1u8; 16]);
        let result = decode_pubkey("test_field", &short_b64);
        assert!(result.is_err());
    }

    #[test]
    fn decode_pubkey_accepts_valid_key() {
        let key_b64 = encode_b64(&[42u8; 32]);
        let result = decode_pubkey("test_field", &key_b64);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [42u8; 32]);
    }

    #[test]
    fn decode_signature_rejects_wrong_length() {
        let bad_b64 = encode_b64(&[1u8; 32]); // подпись должна быть 64 байта
        let result = decode_signature("test_field", &bad_b64);
        assert!(result.is_err());
    }
}
