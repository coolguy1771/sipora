use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SiporaError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("sip protocol error: {0}")]
    Sip(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("redis error: {0}")]
    Redis(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, SiporaError>;
