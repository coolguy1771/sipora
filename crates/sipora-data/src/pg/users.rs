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
    let hash = sipora_auth::digest::hash_password(password)
        .map_err(|e| DataError::Serialization(format!("password hash: {e}")))?;
    let sip_digest_ha1 = sipora_auth::digest::compute_ha1(username, domain, password);
    sqlx::query_as::<_, UserSummary>(
        r#"
        INSERT INTO users (username, domain, password_argon2, sip_digest_ha1, enabled)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, username, domain, enabled, created_at
        "#,
    )
    .bind(username)
    .bind(domain)
    .bind(&hash)
    .bind(&sip_digest_ha1)
    .bind(enabled)
    .fetch_one(pool)
    .await
    .map_err(map_insert_err)
}

/// SIP digest HA1 for an enabled user (`realm` in digest must match `domain`).
pub async fn get_user_sip_digest_ha1(
    pool: &PgPool,
    username: &str,
    domain: &str,
) -> Result<Option<String>, DataError> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT sip_digest_ha1
        FROM users
        WHERE lower(username) = lower($1) AND lower(domain) = lower($2) AND enabled = true
          AND sip_digest_ha1 IS NOT NULL
        "#,
    )
    .bind(username)
    .bind(domain)
    .fetch_optional(pool)
    .await
    .map_err(|e| DataError::Database(e.to_string()))
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
