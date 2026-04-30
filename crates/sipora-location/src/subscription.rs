//! SIP SUBSCRIBE subscription records (Redis).

use crate::{LocationError, Result};
use fred::prelude::{Expiration, KeysInterface, Pool, SetsInterface};
use serde::{Deserialize, Serialize};
use sipora_core::redis_keys;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub aor: String,
    pub subscriber_uri: String,
    pub event_package: String,
    pub call_id: String,
    pub from_tag: String,
    pub to_tag: String,
    pub expires: u32,
    pub state: String,
    pub contact: String,
    pub route_set: Vec<String>,
}

pub async fn save_subscription(
    pool: &Pool,
    domain: &str,
    user: &str,
    sub: &Subscription,
) -> Result<()> {
    let key = redis_keys::subscription_key(&sub.event_package, domain, user, &sub.id);
    let val = serde_json::to_string(sub).map_err(|e| LocationError::Redis(e.to_string()))?;
    let ttl = sub.expires.max(60) as i64;
    let _: Option<String> = pool
        .set(&key, val, Some(Expiration::EX(ttl)), None, false)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    let idx = redis_keys::subscription_aor_index(&sub.event_package, domain, user);
    let _: i64 = pool
        .sadd(&idx, sub.id.clone())
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    let _: i64 = pool
        .expire(&idx, ttl, None)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    Ok(())
}

pub async fn delete_subscription(
    pool: &Pool,
    domain: &str,
    user: &str,
    event: &str,
    sub_id: &str,
) -> Result<()> {
    let key = redis_keys::subscription_key(event, domain, user, sub_id);
    let json: Option<String> = pool
        .get(&key)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    if let Some(ref raw) = json
        && let Ok(sub) = serde_json::from_str::<Subscription>(raw)
    {
        let ck = redis_keys::subscription_notify_cseq_key(&sub.call_id);
        let _: i64 = pool
            .del(&ck)
            .await
            .map_err(|e| LocationError::Redis(e.to_string()))?;
    }
    let _: i64 = pool
        .del(&key)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    let idx = redis_keys::subscription_aor_index(event, domain, user);
    let _: i64 = pool
        .srem(&idx, sub_id.to_string())
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    Ok(())
}

pub async fn list_subscriptions_for_aor(
    pool: &Pool,
    domain: &str,
    user: &str,
    event: &str,
) -> Result<Vec<Subscription>> {
    let idx = redis_keys::subscription_aor_index(event, domain, user);
    let ids: Vec<String> = pool
        .smembers(&idx)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    let mut out = Vec::new();
    for id in ids {
        let key = redis_keys::subscription_key(event, domain, user, &id);
        let s: Option<String> = pool
            .get(&key)
            .await
            .map_err(|e| LocationError::Redis(e.to_string()))?;
        if let Some(json) = s
            && let Ok(sub) = serde_json::from_str::<Subscription>(&json)
        {
            out.push(sub);
        }
    }
    Ok(out)
}

/// Next NOTIFY `CSeq` for this `Call-ID` (monotonic per dialog).
pub async fn next_notify_cseq(pool: &Pool, call_id: &str, ttl_s: i64) -> Result<u32> {
    let key = redis_keys::subscription_notify_cseq_key(call_id);
    let n: i64 = pool
        .incr(&key)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    if n == 1 {
        let _: i64 = pool
            .expire(&key, ttl_s, None)
            .await
            .map_err(|e| LocationError::Redis(e.to_string()))?;
    }
    Ok(n as u32)
}
