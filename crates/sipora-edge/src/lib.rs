pub mod firewall;
pub mod ratelimit;
pub mod redis_ratelimit;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EdgeError {
    #[error("rate limited: {method} from {ip}")]
    RateLimited { ip: String, method: String },
    #[error("IP blocked: {0}")]
    IpBlocked(String),
    #[error("malformed SIP message: {0}")]
    MalformedMessage(String),
    #[error("topology violation: {0}")]
    TopologyViolation(String),
}

pub type Result<T> = std::result::Result<T, EdgeError>;
