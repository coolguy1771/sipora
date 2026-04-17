use crate::DataError;
use sipora_core::config::PostgresConfig;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub async fn connect_pool(cfg: &PostgresConfig) -> Result<PgPool, DataError> {
    PgPoolOptions::new()
        .max_connections(cfg.max_pool_size)
        .connect(&cfg.url)
        .await
        .map_err(|e| DataError::Database(format_postgres_connect_error(&e)))
}

fn format_postgres_connect_error(e: &sqlx::Error) -> String {
    let base = e.to_string();
    let hint = match e {
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            " (connection refused: is PostgreSQL running and is `postgres.url` correct?)"
        }
        sqlx::Error::Database(d) => {
            let msg = d.message();
            if msg.contains("password authentication failed") {
                " (authentication failed: check database user/password in `postgres.url`)"
            } else if msg.contains("does not exist") && msg.contains("database") {
                " (database may not exist: create it or fix the database name in `postgres.url`)"
            } else {
                ""
            }
        }
        _ => "",
    };
    format!("{base}{hint}")
}
