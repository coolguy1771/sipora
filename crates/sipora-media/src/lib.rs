pub mod rtpengine;
pub mod srtp;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MediaError {
    #[error("rtpengine error: {0}")]
    RtpEngine(String),
    #[error("srtp policy violation: {0}")]
    SrtpViolation(String),
    #[error("unsupported codec: {0}")]
    UnsupportedCodec(String),
    #[error("transport error: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, MediaError>;
