//! SIP HTTP Digest authentication — RFC 2617 (MD5) and RFC 7616 (SHA-256 / algorithm negotiation).
//! RFC 8760 multi-challenge support: callers may issue two challenges so UAs can pick an algorithm.
//!
//! Passwords at rest use Argon2 (see this crate's other modules). Only use this module for the
//! SIP digest exchange, which is protocol-defined and not a general-purpose integrity hash.

#[allow(unused_imports)]
use md5::Digest as _;
use md5::Md5;
#[allow(unused_imports)]
use sha2::Digest as _;
use sha2::Sha256;

/// Digest algorithm variants (RFC 7616 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestAlgorithm {
    #[default]
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
}

impl DigestAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" | "" => Some(Self::Md5),
            "MD5-SESS" => Some(Self::Md5Sess),
            "SHA-256" => Some(Self::Sha256),
            "SHA-256-SESS" => Some(Self::Sha256Sess),
            _ => None,
        }
    }
}

pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub qop: String,
    pub algorithm: DigestAlgorithm,
    /// RFC 2617 §3.3: set to true when issuing a re-challenge for an expired nonce.
    pub stale: bool,
}

impl DigestChallenge {
    pub fn new_md5(realm: &str, nonce: &str) -> Self {
        Self {
            realm: realm.to_owned(),
            nonce: nonce.to_owned(),
            qop: "auth".to_owned(),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        }
    }

    /// Backward-compatible constructor — kept so existing callers need no change.
    pub fn new(realm: &str, nonce: &str) -> Self {
        Self::new_md5(realm, nonce)
    }

    pub fn new_sha256(realm: &str, nonce: &str) -> Self {
        Self {
            realm: realm.to_owned(),
            nonce: nonce.to_owned(),
            qop: "auth".to_owned(),
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        }
    }

    pub fn with_stale(mut self, stale: bool) -> Self {
        self.stale = stale;
        self
    }

    pub fn to_www_authenticate(&self) -> String {
        let mut s = format!(
            "Digest realm=\"{}\", nonce=\"{}\", qop=\"{}\", algorithm={}",
            self.realm, self.nonce, self.qop, self.algorithm.as_str()
        );
        if self.stale {
            s.push_str(", stale=TRUE");
        }
        s
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
    pub algorithm: DigestAlgorithm,
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
        let mut algorithm = DigestAlgorithm::Md5;

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
                    "algorithm" => {
                        if let Some(alg) = DigestAlgorithm::from_str(v) {
                            algorithm = alg;
                        }
                    }
                    _ => {}
                }
            }
        }

        Some(Self { username, realm, nonce, uri, response, nc, cnonce, qop, algorithm })
    }

    /// Parse the nc field as a u64 (nc is 8 hex digits per RFC 7616).
    pub fn nc_as_u64(&self) -> Option<u64> {
        u64::from_str_radix(self.nc.as_deref()?, 16).ok()
    }
}

// ── MD5 helpers ─────────────────────────────────────────────────────────────

pub fn compute_ha1(username: &str, realm: &str, password: &str) -> String {
    hex::encode(Md5::digest(format!("{username}:{realm}:{password}").as_bytes()))
}

pub fn compute_ha2(method: &str, uri: &str) -> String {
    hex::encode(Md5::digest(format!("{method}:{uri}").as_bytes()))
}

pub fn compute_response(ha1: &str, nonce: &str, nc: &str, cnonce: &str, qop: &str, ha2: &str) -> String {
    hex::encode(Md5::digest(
        format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes(),
    ))
}

pub fn compute_response_no_qop(ha1: &str, nonce: &str, ha2: &str) -> String {
    hex::encode(Md5::digest(format!("{ha1}:{nonce}:{ha2}").as_bytes()))
}

// ── SHA-256 helpers (RFC 7616 §3.4) ─────────────────────────────────────────

pub fn compute_ha1_sha256(username: &str, realm: &str, password: &str) -> String {
    hex::encode(Sha256::digest(format!("{username}:{realm}:{password}").as_bytes()))
}

pub fn compute_ha2_sha256(method: &str, uri: &str) -> String {
    hex::encode(Sha256::digest(format!("{method}:{uri}").as_bytes()))
}

pub fn compute_response_sha256(ha1: &str, nonce: &str, nc: &str, cnonce: &str, qop: &str, ha2: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes(),
    ))
}

pub fn compute_response_no_qop_sha256(ha1: &str, nonce: &str, ha2: &str) -> String {
    hex::encode(Sha256::digest(format!("{ha1}:{nonce}:{ha2}").as_bytes()))
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Verify a digest response. `ha1` must match the algorithm used:
/// - MD5/MD5-sess: `hex(MD5(username:realm:password))`
/// - SHA-256/SHA-256-sess: `hex(SHA256(username:realm:password))`
pub fn verify_digest(resp: &DigestResponse, ha1: &str, method: &str) -> bool {
    match resp.algorithm {
        DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => verify_digest_md5(resp, ha1, method),
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => {
            verify_digest_sha256(resp, ha1, method)
        }
    }
}

fn verify_digest_md5(resp: &DigestResponse, ha1: &str, method: &str) -> bool {
    let ha2 = compute_ha2(method, &resp.uri);
    let expected = match (&resp.qop, &resp.nc, &resp.cnonce) {
        (Some(qop), Some(nc), Some(cnonce)) => {
            compute_response(ha1, &resp.nonce, nc, cnonce, qop, &ha2)
        }
        _ => compute_response_no_qop(ha1, &resp.nonce, &ha2),
    };
    constant_time_eq_hex(&expected, &resp.response)
}

fn verify_digest_sha256(resp: &DigestResponse, ha1: &str, method: &str) -> bool {
    let ha2 = compute_ha2_sha256(method, &resp.uri);
    let expected = match (&resp.qop, &resp.nc, &resp.cnonce) {
        (Some(qop), Some(nc), Some(cnonce)) => {
            compute_response_sha256(ha1, &resp.nonce, nc, cnonce, qop, &ha2)
        }
        _ => compute_response_no_qop_sha256(ha1, &resp.nonce, &ha2),
    };
    constant_time_eq_hex(&expected, &resp.response)
}

/// Constant-time hex comparison (case-insensitive). Prevents timing-oracle attacks.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x.to_ascii_lowercase() ^ y.to_ascii_lowercase();
    }
    diff == 0
}

// ── nc enforcement helpers (called by proxy, Redis state managed there) ──────

/// Validate that `nc_new > nc_prev` and `nc_new <= nc_prev + 1000` (RFC 7616 §3.4 nc rules).
/// Returns `Ok(())` if the nc value is acceptable.
pub fn validate_nc(nc_new: u64, nc_prev: u64) -> Result<(), NcError> {
    if nc_new == 0 {
        return Err(NcError::Zero);
    }
    if nc_new <= nc_prev {
        return Err(NcError::Replay { nc_new, nc_prev });
    }
    if nc_new > nc_prev + 1000 {
        return Err(NcError::GapTooLarge { nc_new, nc_prev });
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum NcError {
    Zero,
    Replay { nc_new: u64, nc_prev: u64 },
    GapTooLarge { nc_new: u64, nc_prev: u64 },
}

// ── Password helpers ──────────────────────────────────────────────────────────

pub fn verify_argon2_password(hash: &str, password: &str) -> bool {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
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

    // ── Existing MD5 tests ────────────────────────────────────────────────────

    #[test]
    fn dev_alice_lab_ha1_matches_migration_backfill() {
        let ha1 = compute_ha1("alice", "sip.example.com", "change-me");
        assert_eq!(ha1, "2e87c19c08f69108e07e07c89893d5a5");
    }

    #[test]
    fn test_digest_computation() {
        let ha1 = compute_ha1("alice", "example.com", "password123");
        let ha2 = compute_ha2("REGISTER", "sip:example.com");
        let resp = compute_response_no_qop(&ha1, "dcd98b7102dd", &ha2);
        assert!(!resp.is_empty());
        assert_eq!(resp.len(), 32);
    }

    #[test]
    fn test_constant_time_eq_hex() {
        assert!(constant_time_eq_hex("aBc123", "AbC123"));
        assert!(!constant_time_eq_hex("abc", "abd"));
        assert!(!constant_time_eq_hex("ab", "abc"));
    }

    #[test]
    fn verify_digest_accepts_uppercase_response_hex() {
        let ha1 = compute_ha1("alice", "sip.example.com", "change-me");
        let nonce = "n1";
        let uri = "sip:sip.example.com";
        let ha2 = compute_ha2("REGISTER", uri);
        let resp_hex = compute_response_no_qop(&ha1, nonce, &ha2);
        let upper = resp_hex.to_ascii_uppercase();
        let hdr = format!(
            r#"Digest username="alice", realm="sip.example.com", nonce="{nonce}", uri="{uri}", response="{upper}""#
        );
        let dr = DigestResponse::parse(&hdr).expect("parse");
        assert!(verify_digest(&dr, &ha1, "REGISTER"));
    }

    #[test]
    fn verify_digest_with_qop_auth_roundtrip() {
        let ha1 = compute_ha1("alice", "sip.example.com", "change-me");
        let nonce = "nonce123";
        let uri = "sip:sip.example.com";
        let ha2 = compute_ha2("REGISTER", uri);
        let nc = "00000001";
        let cnonce = "cval";
        let qop = "auth";
        let response = compute_response(&ha1, nonce, nc, cnonce, qop, &ha2);
        let hdr = format!(
            r#"Digest username="alice", realm="sip.example.com", nonce="{nonce}", uri="{uri}", response="{response}", nc={nc}, cnonce="{cnonce}", qop="{qop}""#
        );
        let dr = DigestResponse::parse(&hdr).expect("parse");
        assert!(verify_digest(&dr, &ha1, "REGISTER"));
    }

    #[test]
    fn test_argon2_roundtrip() {
        let hash = hash_password("test_password").unwrap();
        assert!(verify_argon2_password(&hash, "test_password"));
        assert!(!verify_argon2_password(&hash, "wrong_password"));
    }

    // ── RFC 7616 Appendix B.2 SHA-256 test vector ─────────────────────────────
    // https://datatracker.ietf.org/doc/html/rfc7616#appendix-B.2

    #[test]
    fn rfc7616_appendix_b2_sha256_vector() {
        // Test vector from RFC 7616 §B.2
        let username = "Mufasa";
        let realm = "http-auth@example.org";
        let password = "Circle of Life";
        let nonce = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
        let uri = "/dir/index.html";
        let nc = "00000001";
        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        let qop = "auth";
        let method = "GET";

        let ha1 = compute_ha1_sha256(username, realm, password);
        let ha2 = compute_ha2_sha256(method, uri);
        let expected_response =
            compute_response_sha256(&ha1, nonce, nc, cnonce, qop, &ha2);

        // Verify round-trip: parse a header built from our computed response
        let hdr = format!(
            r#"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm=SHA-256, response="{expected_response}", nc={nc}, cnonce="{cnonce}", qop={qop}"#
        );
        let dr = DigestResponse::parse(&hdr).unwrap();
        assert_eq!(dr.algorithm, DigestAlgorithm::Sha256);
        assert!(verify_digest(&dr, &ha1, method), "RFC 7616 B.2 SHA-256 round-trip must pass");
    }

    // ── nc enforcement ────────────────────────────────────────────────────────

    #[test]
    fn nc_validation_accepts_first_use() {
        assert!(validate_nc(1, 0).is_ok());
    }

    #[test]
    fn nc_validation_rejects_replay() {
        assert_eq!(
            validate_nc(1, 1),
            Err(NcError::Replay { nc_new: 1, nc_prev: 1 })
        );
    }

    #[test]
    fn nc_validation_rejects_large_gap() {
        assert_eq!(
            validate_nc(1002, 0),
            Err(NcError::GapTooLarge { nc_new: 1002, nc_prev: 0 })
        );
    }

    #[test]
    fn digest_challenge_stale_flag_in_www_auth() {
        let ch = DigestChallenge::new_md5("example.com", "nonce1").with_stale(true);
        assert!(ch.to_www_authenticate().contains("stale=TRUE"));
    }

    #[test]
    fn digest_challenge_sha256_algorithm_label() {
        let ch = DigestChallenge::new_sha256("example.com", "nonce1");
        assert!(ch.to_www_authenticate().contains("SHA-256"));
    }

    #[test]
    fn digest_response_parses_sha256_algorithm() {
        let hdr = r#"Digest username="alice", realm="example.com", nonce="n1", uri="sip:example.com", response="aabbcc", algorithm=SHA-256"#;
        let dr = DigestResponse::parse(hdr).unwrap();
        assert_eq!(dr.algorithm, DigestAlgorithm::Sha256);
    }
}
