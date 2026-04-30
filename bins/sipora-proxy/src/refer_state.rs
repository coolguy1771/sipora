//! In-dialog REFER coordination (Redis-backed state).

use anyhow::Result;
use fred::prelude::{Expiration, KeysInterface};
use serde::{Deserialize, Serialize};
use sipora_core::redis::RedisPool;
use sipora_core::redis_keys::refer_state_key;

const REFER_STATE_TTL_SECS: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferState {
    pub referrer_call_id: String,
    pub referee_contact: String,
    pub event_id: String,
    pub cseq: u32,
    pub version: u32,
}

pub fn redis_key_for_call(call_id: &str) -> String {
    refer_state_key(call_id)
}

pub async fn load_refer_state(redis: &RedisPool, call_id: &str) -> Result<Option<ReferState>> {
    let key = redis_key_for_call(call_id);
    let v: Option<String> = redis.get(&key).await?;
    let Some(raw) = v else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(&raw)?))
}

pub async fn save_refer_state(redis: &RedisPool, call_id: &str, st: &ReferState) -> Result<()> {
    let key = redis_key_for_call(call_id);
    let v = serde_json::to_string(st)?;
    let _: Option<String> = redis
        .set(
            &key,
            v,
            Some(Expiration::EX(REFER_STATE_TTL_SECS)),
            None,
            false,
        )
        .await?;
    Ok(())
}

pub async fn delete_refer_state(redis: &RedisPool, call_id: &str) -> Result<()> {
    let key = redis_key_for_call(call_id);
    let _: i64 = redis.del(&key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refer_state_serde_roundtrip() {
        let st = ReferState {
            referrer_call_id: "cid1".into(),
            referee_contact: "sip:b@x".into(),
            event_id: "e1".into(),
            cseq: 2,
            version: 1,
        };
        let j = serde_json::to_string(&st).unwrap();
        let back: ReferState = serde_json::from_str(&j).unwrap();
        assert_eq!(back.event_id, st.event_id);
        assert_eq!(back.referrer_call_id, st.referrer_call_id);
    }
}
