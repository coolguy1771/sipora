pub mod session;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SdpError {
    #[error("SDP parse error: {0}")]
    Parse(String),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("unsupported codec: {0}")]
    UnsupportedCodec(String),
}

pub type Result<T> = std::result::Result<T, SdpError>;
