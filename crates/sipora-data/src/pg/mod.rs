mod cdr_insert;
mod cdr_query;
mod pool;
mod schema_check;
mod users;

pub use cdr_insert::insert_cdr;
pub use cdr_query::{CdrSearchParams, search_cdrs};
pub use pool::connect_pool;
pub use schema_check::verify_provisioning_schema;
pub use users::{
    SipDigestCredentials, UserSummary, create_user, get_user_by_id,
    get_user_sip_digest_credentials, get_user_sip_digest_ha1, list_users,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub domain: String,
    pub password_argon2: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrunkCert {
    pub id: Uuid,
    pub trunk_id: String,
    pub pem: String,
    pub fingerprint: String,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectRule {
    pub id: Uuid,
    pub from_uri: String,
    pub to_uri: String,
    pub rule_type: String,
    pub q_value: f32,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

impl RedirectRule {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        let after_start = self.valid_from.is_none_or(|t| now >= t);
        let before_end = self.valid_until.is_none_or(|t| now < t);
        after_start && before_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_redirect_rule_active() {
        let rule = RedirectRule {
            id: Uuid::new_v4(),
            from_uri: "sip:old@example.com".into(),
            to_uri: "sip:new@example.com".into(),
            rule_type: "temporary".into(),
            q_value: 1.0,
            valid_from: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            valid_until: Some(Utc.with_ymd_and_hms(2030, 12, 31, 23, 59, 59).unwrap()),
        };
        assert!(rule.is_active(Utc::now()));
    }
}
