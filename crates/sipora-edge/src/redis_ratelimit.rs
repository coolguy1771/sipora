//! Redis-backed rate limiting for the edge (token bucket style window via INCR + EXPIRE).

use crate::ratelimit::{RateLimiter, ThrottleResult};
use fred::prelude::{Expiration, KeysInterface, Pool};
use sipora_core::config::RateLimitConfig;

pub async fn is_blocked(pool: &Pool, block_key: &str) -> Result<bool, fred::error::Error> {
    let n: i64 = pool.exists(block_key).await?;
    Ok(n > 0)
}

async fn incr_windowed(pool: &Pool, key: &str, window_s: i64) -> Result<i64, fred::error::Error> {
    let c: i64 = pool.incr(key).await?;
    if c == 1 {
        let _: i64 = pool.expire(key, window_s, None).await?;
    }
    Ok(c)
}

async fn maybe_block(
    pool: &Pool,
    limiter: &RateLimiter,
    cfg: &RateLimitConfig,
    ip: &str,
    violations: i64,
) -> Result<(), fred::error::Error> {
    if violations < cfg.block_threshold as i64 {
        return Ok(());
    }
    let bk = limiter.block_key(ip);
    let _: Option<String> = pool
        .set(
            bk,
            "1",
            Some(Expiration::EX(cfg.block_cooldown_s as i64)),
            None,
            false,
        )
        .await?;
    let _: i64 = pool.del(limiter.violation_key(ip)).await?;
    Ok(())
}

/// Returns throttle decision after updating Redis counters.
pub async fn check(
    pool: &Pool,
    limiter: &RateLimiter,
    cfg: &RateLimitConfig,
    ip: &str,
    method: &str,
) -> Result<ThrottleResult, fred::error::Error> {
    let bk = limiter.block_key(ip);
    if is_blocked(pool, &bk).await? {
        return Ok(ThrottleResult {
            allowed: false,
            current_count: u64::MAX,
            limit: limiter.limit_for_method(method),
            retry_after: Some(cfg.block_cooldown_s),
        });
    }

    let rk = limiter.rate_key(ip, method);
    let count = incr_windowed(pool, &rk, cfg.block_window_s as i64).await? as u64;
    let mut result = limiter.evaluate(method, count);

    if !result.allowed {
        let vk = limiter.violation_key(ip);
        let v = incr_windowed(pool, &vk, cfg.block_window_s as i64).await?;
        maybe_block(pool, limiter, cfg, ip, v).await?;
    }

    if is_blocked(pool, &bk).await? {
        result.allowed = false;
        result.retry_after = Some(cfg.block_cooldown_s);
    }

    Ok(result)
}
