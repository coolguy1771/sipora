//! GRUU computation (RFC 5627-style instance tagging).

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Deterministic public GRUU from AoR and instance id (`+sip.instance` contents).
pub fn compute_pub_gruu(domain: &str, user: &str, instance_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{user}|{instance_id}").as_bytes());
    let digest = h.finalize();
    let hx = hex::encode(digest);
    let token: String = hx.chars().take(20).collect();
    format!("sip:{user}@{domain};gr={token}")
}

/// Per-registration opaque temporary GRUU token (UUID).
pub fn new_temp_gruu(domain: &str, user: &str) -> String {
    let token = Uuid::new_v4().simple();
    format!("sip:{user}@{domain};gr={token}")
}

/// Returns the `gr` parameter value from a SIP URI, if present.
pub fn gr_token_from_uri(uri: &str) -> Option<&str> {
    uri.split(';').skip(1).find_map(|p| {
        let p = p.split('?').next().unwrap_or(p);
        let (k, v) = p.split_once('=')?;
        k.eq_ignore_ascii_case("gr").then_some(v.trim())
    })
}
