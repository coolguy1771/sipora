use crate::DataError;
use sqlx::PgPool;

/// Ensures migrations for the provisioning API have been applied (`users` table).
pub async fn verify_provisioning_schema(pool: &PgPool) -> Result<(), DataError> {
    let (ok,): (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'users'
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| DataError::Database(e.to_string()))?;
    if !ok {
        return Err(DataError::Database(
            "missing table `public.users`: apply SQL migrations from the repo `migrations/` directory \
             (e.g. `20250415000001_users.sql`) to this database before starting sipora-api"
                .into(),
        ));
    }
    Ok(())
}
