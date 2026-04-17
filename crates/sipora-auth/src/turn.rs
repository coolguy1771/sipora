use base64::Engine;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Generate a short-lived TURN credential pair.
/// Username format: `{expiry_timestamp}:{aor}`
/// Password: base64(HMAC-SHA256(username, shared_secret))
pub fn generate_turn_credentials(
    aor: &str,
    shared_secret: &[u8],
    ttl_s: u64,
) -> Result<(String, String), &'static str> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + ttl_s;

    let username = format!("{timestamp}:{aor}");
    let password = compute_hmac(username.as_bytes(), shared_secret)?;

    Ok((username, password))
}

fn compute_hmac(data: &[u8], key: &[u8]) -> Result<String, &'static str> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "invalid HMAC key length")?;
    mac.update(data);
    let result = mac.finalize();
    Ok(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
}

/// Verify a TURN credential (for testing/audit purposes).
pub fn verify_turn_credential(username: &str, password: &str, shared_secret: &[u8]) -> bool {
    let Ok(expected) = compute_hmac(username.as_bytes(), shared_secret) else {
        return false;
    };
    constant_time_eq(expected.as_bytes(), password.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turn_credential_roundtrip() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let (username, password) =
            generate_turn_credentials("alice@example.com", secret, 86400).expect("credentials");

        assert!(username.contains("alice@example.com"));
        assert!(!password.is_empty());
        assert!(verify_turn_credential(&username, &password, secret));
    }

    #[test]
    fn test_wrong_password_rejected() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let (username, _) =
            generate_turn_credentials("bob@example.com", secret, 3600).expect("credentials");

        assert!(!verify_turn_credential(&username, "wrong", secret));
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let other = b"other_secret_key_32_bytes_long!!";
        let (username, password) =
            generate_turn_credentials("carol@example.com", secret, 3600).expect("credentials");

        assert!(!verify_turn_credential(&username, &password, other));
    }
}
