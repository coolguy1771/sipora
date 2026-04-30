//! Redis sorted-set storage for contact bindings (member = JSON [`ContactBinding`]).

use crate::gruu;
use crate::{ContactBinding, LocationError, Result};
use fred::prelude::{Expiration, KeysInterface, Pool, SortedSetsInterface};
use sipora_core::redis_keys;

fn decode_binding_member(s: &str) -> ContactBinding {
    serde_json::from_str::<ContactBinding>(s).unwrap_or_else(|_| ContactBinding {
        uri: s.to_owned(),
        q_value: 1.0,
        expires: 0,
        ..Default::default()
    })
}

/// Store one contact for an AOR; expires the whole key after `ttl_s`.
pub async fn upsert_contact(
    pool: &Pool,
    domain: &str,
    username: &str,
    binding: &ContactBinding,
    ttl_s: i64,
) -> Result<()> {
    let key = redis_keys::location_key(domain, username);
    let score = binding.q_value as f64;
    let member = serde_json::to_string(binding).map_err(|e| LocationError::Redis(e.to_string()))?;
    let vals = vec![(score, member)];
    pool.zadd::<i64, _, _>(&key, None, None, false, false, vals)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    let _: i64 = pool
        .expire(&key, ttl_s, None)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;

    if let Some(ref pg) = binding.pub_gruu
        && let Some(tok) = gruu::gr_token_from_uri(pg)
    {
        let ik = redis_keys::pub_gruu_index_key(domain, tok);
        let _: Option<String> = pool
            .set(
                &ik,
                username.to_string(),
                Some(Expiration::EX(ttl_s.max(1))),
                None,
                false,
            )
            .await
            .map_err(|e| LocationError::Redis(e.to_string()))?;
    }
    Ok(())
}

/// Resolve AoR username from a pub-GRUU `gr` token (see [`crate::gruu`]).
pub async fn lookup_user_for_pub_gruu(
    pool: &Pool,
    domain: &str,
    gr_token: &str,
) -> Result<Option<String>> {
    let key = redis_keys::pub_gruu_index_key(domain, gr_token);
    pool.get::<Option<String>, _>(&key)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))
}

/// Return contact bindings for an AOR (highest score first).
pub async fn list_contact_uris(
    pool: &Pool,
    domain: &str,
    username: &str,
) -> Result<Vec<ContactBinding>> {
    let key = redis_keys::location_key(domain, username);
    let members: Vec<String> = pool
        .zrevrange(&key, 0, -1, false)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    Ok(members.iter().map(|s| decode_binding_member(s)).collect())
}
