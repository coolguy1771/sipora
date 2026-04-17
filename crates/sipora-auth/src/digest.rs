//! SIP HTTP Digest authentication (RFC 2617, used by RFC 3261) requires **MD5** for
//! `HA1`, `HA2`, and the digest response. That is protocol-defined, not a general-purpose
//! integrity hash. Do not use this module for non-SIP digest or password storage; passwords
//! at rest use Argon2 elsewhere in this crate.

use md5::{Digest, Md5};

pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub qop: String,
    pub algorithm: String,
}

impl DigestChallenge {
    pub fn new(realm: &str, nonce: &str) -> Self {
        Self {
            realm: realm.to_owned(),
            nonce: nonce.to_owned(),
            qop: "auth".to_owned(),
            algorithm: "MD5".to_owned(),
        }
    }

    pub fn to_www_authenticate(&self) -> String {
        format!(
            "Digest realm=\"{}\", nonce=\"{}\", qop=\"{}\", algorithm={}",
            self.realm, self.nonce, self.qop, self.algorithm
        )
    }
}

#[derive(Debug)]
pub struct DigestResponse {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
    pub qop: Option<String>,
}

impl DigestResponse {
    pub fn parse(header_value: &str) -> Option<Self> {
        let stripped = header_value.strip_prefix("Digest ")?;
        let mut username = String::new();
        let mut realm = String::new();
        let mut nonce = String::new();
        let mut uri = String::new();
        let mut response = String::new();
        let mut nc = None;
        let mut cnonce = None;
        let mut qop = None;

        for part in stripped.split(',') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"');
                match k {
                    "username" => username = v.to_owned(),
                    "realm" => realm = v.to_owned(),
                    "nonce" => nonce = v.to_owned(),
                    "uri" => uri = v.to_owned(),
                    "response" => response = v.to_owned(),
                    "nc" => nc = Some(v.to_owned()),
                    "cnonce" => cnonce = Some(v.to_owned()),
                    "qop" => qop = Some(v.to_owned()),
                    _ => {}
                }
            }
        }

        Some(Self {
            username,
            realm,
            nonce,
            uri,
            response,
            nc,
            cnonce,
            qop,
        })
    }
}

pub fn compute_ha1(username: &str, realm: &str, password: &str) -> String {
    let input = format!("{username}:{realm}:{password}");
    let digest = Md5::digest(input.as_bytes());
    hex::encode(digest)
}

pub fn compute_ha2(method: &str, uri: &str) -> String {
    let input = format!("{method}:{uri}");
    let digest = Md5::digest(input.as_bytes());
    hex::encode(digest)
}

pub fn compute_response(
    ha1: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    qop: &str,
    ha2: &str,
) -> String {
    let input = format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}");
    let digest = Md5::digest(input.as_bytes());
    hex::encode(digest)
}

pub fn compute_response_no_qop(ha1: &str, nonce: &str, ha2: &str) -> String {
    let input = format!("{ha1}:{nonce}:{ha2}");
    let digest = Md5::digest(input.as_bytes());
    hex::encode(digest)
}

pub fn verify_digest(resp: &DigestResponse, ha1: &str, method: &str) -> bool {
    let ha2 = compute_ha2(method, &resp.uri);

    let expected = match (&resp.qop, &resp.nc, &resp.cnonce) {
        (Some(qop), Some(nc), Some(cnonce)) => {
            compute_response(ha1, &resp.nonce, nc, cnonce, qop, &ha2)
        }
        _ => compute_response_no_qop(ha1, &resp.nonce, &ha2),
    };

    constant_time_eq(expected.as_bytes(), resp.response.as_bytes())
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

pub fn verify_argon2_password(hash: &str, password: &str) -> bool {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_computation() {
        let ha1 = compute_ha1("alice", "example.com", "password123");
        let ha2 = compute_ha2("REGISTER", "sip:example.com");
        let resp = compute_response_no_qop(&ha1, "dcd98b7102dd", &ha2);
        assert!(!resp.is_empty());
        assert_eq!(resp.len(), 32);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn test_argon2_roundtrip() {
        let hash = hash_password("test_password").unwrap();
        assert!(verify_argon2_password(&hash, "test_password"));
        assert!(!verify_argon2_password(&hash, "wrong_password"));
    }
}
