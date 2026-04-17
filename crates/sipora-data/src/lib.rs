pub mod cdr;
pub mod kafka_cdr;
pub mod pg;

pub use sqlx::PgPool;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DataError {
    #[error("database error: {0}")]
    Database(String),
    #[error("kafka error: {0}")]
    Kafka(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, DataError>;
