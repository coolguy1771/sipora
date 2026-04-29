use crate::DataError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSummary {
    pub id: Uuid,
    pub username: String,
    pub domain: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SipDigestCredentials {
    pub sip_digest_ha1: Option<String>,
    pub sip_digest_ha1_sha256: Option<String>,
}

const CREATE_USER_INSERT_SQL: &str = r#"
        INSERT INTO users (
            username,
            domain,
            password_argon2,
            sip_digest_ha1,
            sip_digest_ha1_sha256,
            enabled
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, username, domain, enabled, created_at
        "#;

const GET_USER_SIP_DIGEST_CREDENTIALS_SQL: &str = r#"
        SELECT sip_digest_ha1, sip_digest_ha1_sha256
        FROM users
        WHERE lower(username) = lower($1) AND lower(domain) = lower($2) AND enabled = true
          AND sip_digest_ha1_sha256 IS NOT NULL
        UNION ALL
        SELECT sip_digest_ha1, sip_digest_ha1_sha256
        FROM users
        WHERE lower(username) = lower($1) AND lower(domain) = lower($2) AND enabled = true
          AND sip_digest_ha1_sha256 IS NULL AND sip_digest_ha1 IS NOT NULL
        LIMIT 1
        "#;

pub async fn list_users(pool: &PgPool, domain: &str) -> Result<Vec<UserSummary>, DataError> {
    sqlx::query_as::<_, UserSummary>(
        r#"
        SELECT id, username, domain, enabled, created_at
        FROM users
        WHERE domain = $1
        ORDER BY created_at DESC
        LIMIT 10000
        "#,
    )
    .bind(domain)
    .fetch_all(pool)
    .await
    .map_err(|e| DataError::Database(e.to_string()))
}

pub async fn get_user_by_id(
    pool: &PgPool,
    id: Uuid,
    domain: &str,
) -> Result<Option<UserSummary>, DataError> {
    sqlx::query_as::<_, UserSummary>(
        r#"
        SELECT id, username, domain, enabled, created_at
        FROM users
        WHERE id = $1 AND domain = $2
        "#,
    )
    .bind(id)
    .bind(domain)
    .fetch_optional(pool)
    .await
    .map_err(|e| DataError::Database(e.to_string()))
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    domain: &str,
    password: &str,
    enabled: bool,
) -> Result<UserSummary, DataError> {
    let username = username.to_lowercase();
    let domain = domain.to_lowercase();
    let hash = sipora_auth::digest::hash_password(password)
        .map_err(|e| DataError::Serialization(format!("password hash: {e}")))?;
    let (sip_digest_ha1, sip_digest_ha1_sha256) =
        compute_user_sip_digest_ha1s(&username, &domain, password);
    sqlx::query_as::<_, UserSummary>(CREATE_USER_INSERT_SQL)
        .bind(&username)
        .bind(&domain)
        .bind(&hash)
        .bind(&sip_digest_ha1)
        .bind(&sip_digest_ha1_sha256)
        .bind(enabled)
        .fetch_one(pool)
        .await
        .map_err(map_insert_err)
}

fn compute_user_sip_digest_ha1s(username: &str, domain: &str, password: &str) -> (String, String) {
    (
        sipora_auth::digest::compute_ha1(username, domain, password),
        sipora_auth::digest::compute_ha1_sha256(username, domain, password),
    )
}

/// SIP digest HA1 for an enabled user (`realm` in digest must match `domain`).
pub async fn get_user_sip_digest_ha1(
    pool: &PgPool,
    username: &str,
    domain: &str,
) -> Result<Option<String>, DataError> {
    get_user_sip_digest_credentials(pool, username, domain)
        .await
        .map(legacy_md5_ha1)
}

/// SIP digest credentials for an enabled user (`realm` in digest must match `domain`).
pub async fn get_user_sip_digest_credentials(
    pool: &PgPool,
    username: &str,
    domain: &str,
) -> Result<Option<SipDigestCredentials>, DataError> {
    sqlx::query_as::<_, SipDigestCredentials>(GET_USER_SIP_DIGEST_CREDENTIALS_SQL)
        .bind(username)
        .bind(domain)
        .fetch_optional(pool)
        .await
        .map_err(|e| DataError::Database(e.to_string()))
}

fn legacy_md5_ha1(credentials: Option<SipDigestCredentials>) -> Option<String> {
    credentials.and_then(|c| c.sip_digest_ha1)
}

fn map_insert_err(e: sqlx::Error) -> DataError {
    if let sqlx::Error::Database(ref d) = e
        && let Some(code) = d.code()
        && code.as_ref() == "23505"
    {
        return DataError::Conflict("user already exists".into());
    }
    DataError::Database(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_digest_ha1s_computes_md5_and_sha256() {
        let (md5_ha1, sha256_ha1) =
            compute_user_sip_digest_ha1s("alice", "sip.example.com", "change-me");

        assert_eq!(
            md5_ha1,
            sipora_auth::digest::compute_ha1("alice", "sip.example.com", "change-me",)
        );
        assert_eq!(
            sha256_ha1,
            sipora_auth::digest::compute_ha1_sha256("alice", "sip.example.com", "change-me",)
        );
    }

    #[test]
    fn create_user_insert_sql_writes_both_digest_columns() {
        assert!(CREATE_USER_INSERT_SQL.contains("sip_digest_ha1_sha256"));
        assert!(CREATE_USER_INSERT_SQL.contains("VALUES ($1, $2, $3, $4, $5, $6)"));
    }

    #[test]
    fn legacy_digest_projection_returns_md5_from_dual_algorithm_row() {
        let credentials = SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: Some("sha256-ha1".to_string()),
        };

        assert_eq!(
            legacy_md5_ha1(Some(credentials)),
            Some("md5-ha1".to_string())
        );
    }

    #[test]
    fn legacy_digest_projection_returns_none_for_sha256_only_row() {
        let credentials = SipDigestCredentials {
            sip_digest_ha1: None,
            sip_digest_ha1_sha256: Some("sha256-ha1".to_string()),
        };

        assert_eq!(legacy_md5_ha1(Some(credentials)), None);
    }

    #[test]
    fn digest_credentials_sql_uses_index_friendly_fallback_branches() {
        let sql = GET_USER_SIP_DIGEST_CREDENTIALS_SQL.to_ascii_lowercase();

        assert!(sql.contains("union all"));
        assert!(sql.contains("sip_digest_ha1_sha256 is not null"));
        assert!(sql.contains("sip_digest_ha1_sha256 is null and sip_digest_ha1 is not null"));
        assert!(!sql.contains(" or sip_digest_ha1"));
    }
}
