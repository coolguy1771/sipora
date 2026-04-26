pub mod digest;
pub mod jwt;
pub mod nonce;
pub mod stir;
pub mod turn;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("nonce expired or reused")]
    NonceInvalid,
    #[error("jwt validation failed: {0}")]
    JwtInvalid(String),
    #[error("user not found")]
    UserNotFound,
    #[error("redis error: {0}")]
    Redis(String),
    #[error("database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub authenticated: bool,
    pub username: String,
    pub domain: String,
    pub aor: String,
}
