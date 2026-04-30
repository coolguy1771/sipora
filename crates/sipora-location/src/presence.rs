//! Presence document storage (PUBLISH / PIDF) with ETag.

use crate::{LocationError, Result};
use fred::prelude::{Expiration, KeysInterface, Pool};
use serde::{Deserialize, Serialize};
use sipora_core::redis_keys;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceDoc {
    pub etag: String,
    pub body: Vec<u8>,
    pub content_type: String,
}

#[derive(Debug)]
pub enum PresenceError {
    EtagMismatch,
    NotFound,
    Redis(String),
}

pub async fn load_presence(pool: &Pool, domain: &str, user: &str) -> Result<Option<PresenceDoc>> {
    let key = redis_keys::presence_doc_key(domain, user);
    let s: Option<String> = pool
        .get(&key)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    match s {
        Some(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| LocationError::Redis(e.to_string())),
        None => Ok(None),
    }
}

/// Stores presence; returns new ETag.
pub async fn publish_presence(
    pool: &Pool,
    domain: &str,
    user: &str,
    body: Option<&[u8]>,
    content_type: &str,
    if_match: Option<&str>,
    expires: u32,
) -> std::result::Result<String, PresenceError> {
    let key = redis_keys::presence_doc_key(domain, user);
    let ttl = expires.max(60) as i64;

    let existing: Option<String> = pool
        .get(&key)
        .await
        .map_err(|e| PresenceError::Redis(e.to_string()))?;

    if let Some(ref json) = existing {
        let doc: PresenceDoc =
            serde_json::from_str(json).map_err(|e| PresenceError::Redis(e.to_string()))?;
        if let Some(im) = if_match
            && im != doc.etag
        {
            return Err(PresenceError::EtagMismatch);
        }
    } else if if_match.is_some() {
        return Err(PresenceError::NotFound);
    }

    let new_etag = uuid::Uuid::new_v4().simple().to_string();
    let doc = PresenceDoc {
        etag: new_etag.clone(),
        body: body.map(|b| b.to_vec()).unwrap_or_default(),
        content_type: content_type.to_owned(),
    };
    let json = serde_json::to_string(&doc).map_err(|e| PresenceError::Redis(e.to_string()))?;
    let _: Option<String> = pool
        .set(&key, json, Some(Expiration::EX(ttl)), None, false)
        .await
        .map_err(|e| PresenceError::Redis(e.to_string()))?;
    Ok(new_etag)
}
