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
    sqlx::query_as::<_, UserSummary>(
        r#"
        INSERT INTO users (username, domain, password_argon2, enabled)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, domain, enabled, created_at
        "#,
    )
    .bind(username)
    .bind(domain)
    .bind(&hash)
    .bind(enabled)
    .fetch_one(pool)
    .await
    .map_err(map_insert_err)
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
