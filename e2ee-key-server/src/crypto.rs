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
//!   - identity_signing_key — Ed25519, только для подписи Signed PreKey
//!     и постквантового (ML-KEM-768) prekey;
//!   - identity_dh_key      — X25519, только для DH в X3DH (DH1/DH2).
//! Это отступление от «чистого» X3DH ради простоты и корректности
//! реализации: не нужен самодельный код конвертации Montgomery↔Edwards.
//! Компромисс осознанный и не снижает итоговых security-свойств протокола.

use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const PUBKEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// ML-KEM-768 encapsulation key (FIPS 203): 3 полинома × 256 коэффициентов
/// по 12 бит (ByteEncode_12, 3 × 384 байта) и 32 байта seed ρ.
pub const PQ_PUBKEY_LEN: usize = 1184;
const PQ_ENCODED_POLYS_LEN: usize = 3 * 384;
const MLKEM_Q: u16 = 3329;

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

/// Декодирует ML-KEM-768 encapsulation key и делает ту же проверку ввода,
/// что FIPS 203 требует от шифрующей стороны перед Encaps: каждый
/// 12-битный коэффициент t должен быть < q. Ключ с «неприведёнными»
/// коэффициентами не мог получиться из честного KeyGen — это порча или
/// попытка подсунуть собеседникам ключ, который они всё равно отвергнут.
/// Нулевой t отбраковывается по той же логике, что all-zero X25519 в
/// decode_pubkey: при t = 0 шифротекст раскрывает инкапсулированный секрет.
pub fn decode_pq_pubkey(field: &str, s: &str) -> Result<[u8; PQ_PUBKEY_LEN], AppError> {
    let bytes = decode_b64(field, s)?;
    let arr: [u8; PQ_PUBKEY_LEN] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: must be {PQ_PUBKEY_LEN} bytes")))?;
    let polys = &arr[..PQ_ENCODED_POLYS_LEN];
    if polys.iter().all(|b| *b == 0) {
        return Err(AppError::BadRequest(format!(
            "{field}: all-zero ML-KEM public vector rejected"
        )));
    }
    // ByteEncode_12: каждые 3 байта несут два коэффициента, младшие биты первыми.
    let reduced = polys.chunks_exact(3).all(|c| {
        let first = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let second = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        first < MLKEM_Q && second < MLKEM_Q
    });
    if !reduced {
        return Err(AppError::BadRequest(format!(
            "{field}: not a valid ML-KEM-768 encapsulation key (coefficient out of range)"
        )));
    }
    Ok(arr)
}

/// Проверяет подпись prekey (классического или PQ) ключом
/// identity_signing_key над СЫРЫМИ байтами публичного ключа.
///
/// Это проверка defense-in-depth на upload: сервер отклоняет заведомо
/// битые bundle. Настоящая security-гарантия X3DH/PQXDH требует, чтобы
/// ПОЛУЧАТЕЛЬ bundle тоже независимо проверял эту подпись перед
/// использованием prekey — сервер в модели угроз L4 не доверенная сторона,
/// и клиентская проверка не должна полагаться на то, что сервер её уже
/// сделал.
fn verify_prekey_signature(
    label: &str,
    identity_signing_key: &[u8; PUBKEY_LEN],
    prekey_public: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), AppError> {
    let verifying_key = VerifyingKey::from_bytes(identity_signing_key)
        .map_err(|_| AppError::BadRequest("identity_signing_key: invalid Ed25519 point".into()))?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(prekey_public, &sig)
        .map_err(|_| AppError::BadRequest(format!("{label}: signature verification failed")))
}

/// Подпись X25519 Signed PreKey.
pub fn verify_signed_prekey(
    identity_signing_key: &[u8; PUBKEY_LEN],
    spk_public_key: &[u8; PUBKEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), AppError> {
    verify_prekey_signature("signed_prekey", identity_signing_key, spk_public_key, signature)
}

/// Подпись ML-KEM-768 prekey. Длины сообщений (32 и 1184 байта) разные,
/// поэтому подпись одного вида prekey не может сойти за подпись другого,
/// хотя оба подписаны одним identity-ключом без доменного префикса.
pub fn verify_pq_prekey(
    identity_signing_key: &[u8; PUBKEY_LEN],
    pq_public_key: &[u8; PQ_PUBKEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), AppError> {
    verify_prekey_signature("pq_prekey", identity_signing_key, pq_public_key, signature)
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

    // Байты 7 кодируют коэффициенты 0x707 и 0x070 — оба < q, то есть это
    // корректный по форме ML-KEM-768 ключ.
    fn sample_pq_public() -> [u8; PQ_PUBKEY_LEN] {
        [7u8; PQ_PUBKEY_LEN]
    }

    #[test]
    fn verify_pq_accepts_valid_signature() {
        let signing_key = fixed_signing_key(5);
        let pq_public = sample_pq_public();
        let sig = signing_key.sign(&pq_public);

        let result = verify_pq_prekey(
            &signing_key.verifying_key().to_bytes(),
            &pq_public,
            &sig.to_bytes(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_pq_rejects_tampered_key() {
        let signing_key = fixed_signing_key(6);
        let pq_public = sample_pq_public();
        let sig = signing_key.sign(&pq_public);

        // Подмена одного бита в seed ρ — подпись выдана для другого ключа.
        let mut tampered = pq_public;
        tampered[PQ_PUBKEY_LEN - 1] ^= 1;
        let result = verify_pq_prekey(
            &signing_key.verifying_key().to_bytes(),
            &tampered,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_pq_rejects_wrong_signer() {
        let signing_key_a = fixed_signing_key(7);
        let signing_key_b = fixed_signing_key(8);
        let pq_public = sample_pq_public();
        let sig = signing_key_b.sign(&pq_public); // подписано не тем ключом

        let result = verify_pq_prekey(
            &signing_key_a.verifying_key().to_bytes(),
            &pq_public,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_pq_rejects_signature_over_prefix() {
        // Подпись над первыми 32 байтами (как у классического SPK) не должна
        // подтверждать весь PQ-ключ.
        let signing_key = fixed_signing_key(9);
        let pq_public = sample_pq_public();
        let sig = signing_key.sign(&pq_public[..PUBKEY_LEN]);

        let result = verify_pq_prekey(
            &signing_key.verifying_key().to_bytes(),
            &pq_public,
            &sig.to_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_pq_pubkey_accepts_valid_key() {
        let key = sample_pq_public();
        let result = decode_pq_pubkey("test_field", &encode_b64(&key));
        assert_eq!(result.unwrap(), key);
    }

    #[test]
    fn decode_pq_pubkey_rejects_wrong_length() {
        for len in [0, PUBKEY_LEN, PQ_PUBKEY_LEN - 1, PQ_PUBKEY_LEN + 1] {
            let bytes = vec![7u8; len];
            let result = decode_pq_pubkey("test_field", &encode_b64(&bytes));
            assert!(result.is_err(), "length {len} must be rejected");
        }
    }

    #[test]
    fn decode_pq_pubkey_checks_coefficient_range() {
        // Первый коэффициент = 3328 (q - 1) — допустимо.
        let mut key = sample_pq_public();
        key[0] = 0x00;
        key[1] = 0x0d;
        assert!(decode_pq_pubkey("test_field", &encode_b64(&key)).is_ok());

        // Первый коэффициент = 3329 (q) — отвергается.
        key[0] = 0x01;
        assert!(decode_pq_pubkey("test_field", &encode_b64(&key)).is_err());

        // Второй коэффициент тройки байтов = 3329: старшая тетрада key[4]
        // даёт младшие 4 бита, key[5] — старшие 8.
        let mut key = sample_pq_public();
        key[4] = 0x17;
        key[5] = 0xd0;
        assert!(decode_pq_pubkey("test_field", &encode_b64(&key)).is_err());
    }

    #[test]
    fn decode_pq_pubkey_rejects_all_zero_vector() {
        let mut key = [0u8; PQ_PUBKEY_LEN];
        key[PQ_ENCODED_POLYS_LEN..].fill(9); // ненулевой только seed ρ
        assert!(decode_pq_pubkey("test_field", &encode_b64(&key)).is_err());
    }
}
