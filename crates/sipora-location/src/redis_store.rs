//! Redis sorted-set storage for contact bindings (q-value score).

use crate::{ContactBinding, LocationError, Result};
use fred::prelude::{KeysInterface, Pool, SortedSetsInterface};
use sipora_core::redis_keys;

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
    let member = binding.uri.clone();
    let vals = vec![(score, member)];
    pool.zadd::<i64, _, _>(&key, None, None, false, false, vals)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    let _: i64 = pool
        .expire(&key, ttl_s, None)
        .await
        .map_err(|e| LocationError::Redis(e.to_string()))?;
    Ok(())
}

/// Return contact URIs for an AOR (highest score first). Scores are not echoed; use `q=1.0` placeholders.
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
    Ok(members
        .into_iter()
        .map(|uri| ContactBinding {
            uri,
            q_value: 1.0,
            expires: 0,
        })
        .collect())
}
