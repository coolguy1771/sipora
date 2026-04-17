use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CdrRecord {
    pub id: Uuid,
    pub correlation_id: Uuid,
    pub leg: char,
    pub from_uri: String,
    pub to_uri: String,
    pub setup_at: DateTime<Utc>,
    pub answered_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_s: Option<i64>,
    pub result_code: u16,
    pub codec: Option<String>,
    pub rtp_loss_pct: Option<f64>,
    pub rtp_jitter_ms: Option<f64>,
    pub srtp_cipher: Option<String>,
    pub media_ip: Option<String>,
    pub proxy_node: Option<String>,
    pub hash_chain: Option<String>,
}

/// Compute SHA-256 hash of CDR fields + previous hash for tamper evidence
pub fn compute_cdr_hash(record: &CdrRecord, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.id.to_string().as_bytes());
    hasher.update(record.correlation_id.to_string().as_bytes());
    hasher.update([record.leg as u8]);
    hasher.update(record.from_uri.as_bytes());
    hasher.update(record.to_uri.as_bytes());
    hasher.update(record.setup_at.to_rfc3339().as_bytes());
    hasher.update(record.result_code.to_string().as_bytes());
    hasher.update(prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Serialize CDR to JSON for Kafka publishing
pub fn serialize_cdr_json(record: &CdrRecord) -> crate::Result<String> {
    serde_json::to_string(record).map_err(|e| crate::DataError::Serialization(e.to_string()))
}

pub const KAFKA_TOPIC: &str = "sip.cdrs";
pub const KAFKA_SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cdr() -> CdrRecord {
        CdrRecord {
            id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            leg: 'A',
            from_uri: "sip:alice@example.com".into(),
            to_uri: "sip:bob@example.com".into(),
            setup_at: Utc::now(),
            answered_at: None,
            ended_at: None,
            duration_s: None,
            result_code: 200,
            codec: Some("opus".into()),
            rtp_loss_pct: Some(0.5),
            rtp_jitter_ms: Some(15.0),
            srtp_cipher: Some("AES_128_CM_HMAC_SHA1_80".into()),
            media_ip: Some("10.0.0.1".into()),
            proxy_node: Some("proxy-1".into()),
            hash_chain: None,
        }
    }

    #[test]
    fn test_hash_chain() {
        let cdr = make_test_cdr();
        let hash1 = compute_cdr_hash(&cdr, "");
        let hash2 = compute_cdr_hash(&cdr, &hash1);
        assert_ne!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_cdr_serialization() {
        let cdr = make_test_cdr();
        let json = serialize_cdr_json(&cdr).unwrap();
        assert!(json.contains("alice@example.com"));
    }
}
