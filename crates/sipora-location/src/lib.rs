pub mod redis_store;
pub mod service;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LocationError {
    #[error("redis error: {0}")]
    Redis(String),
    #[error("max contacts exceeded for AOR")]
    MaxContactsExceeded,
}

pub type Result<T> = std::result::Result<T, LocationError>;

#[derive(Debug, Clone)]
pub struct ContactBinding {
    pub uri: String,
    pub q_value: f32,
    pub expires: u32,
}
