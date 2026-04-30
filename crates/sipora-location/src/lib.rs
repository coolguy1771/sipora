pub mod gruu;
pub mod presence;
pub mod redis_store;
pub mod service;
pub mod subscription;

use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactBinding {
    pub uri: String,
    pub q_value: f32,
    pub expires: u32,
    #[serde(default)]
    pub sip_instance: Option<String>,
    #[serde(default)]
    pub pub_gruu: Option<String>,
    #[serde(default)]
    pub temp_gruu: Option<String>,
    #[serde(default)]
    pub reg_id: Option<u32>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub ob_flow_token: Option<String>,
    #[serde(default)]
    pub pn_provider: Option<String>,
    #[serde(default)]
    pub pn_prid: Option<String>,
    #[serde(default)]
    pub pn_param: Option<String>,
    /// Unix seconds of last successful REGISTER upsert for this binding (push idle).
    #[serde(default)]
    pub last_register_unix: Option<u64>,
}

impl Default for ContactBinding {
    fn default() -> Self {
        Self {
            uri: String::new(),
            q_value: 1.0,
            expires: 0,
            sip_instance: None,
            pub_gruu: None,
            temp_gruu: None,
            reg_id: None,
            path: Vec::new(),
            ob_flow_token: None,
            pn_provider: None,
            pn_prid: None,
            pn_param: None,
            last_register_unix: None,
        }
    }
}
