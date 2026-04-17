//! Centralized Redis connection for Sipora services.

use crate::config::RedisConfig;
use crate::error::{Result, SiporaError};
use fred::prelude::{Builder, ClientLike, Config};
use fred::types::config::ServerConfig;
use url::Url;

pub use fred::prelude::Pool as RedisPool;

fn parse_redis_host_port(url_str: &str) -> Result<(String, u16)> {
    let u = Url::parse(url_str).map_err(|e| SiporaError::Config(format!("redis url: {e}")))?;
    let host = u
        .host_str()
        .ok_or_else(|| SiporaError::Config("redis url must include a host".into()))?;
    let port = u.port().unwrap_or(6379);
    Ok((host.to_string(), port))
}

pub async fn connect_pool(cfg: &RedisConfig) -> Result<RedisPool> {
    let first = cfg
        .nodes
        .first()
        .ok_or_else(|| SiporaError::Config("redis.nodes is empty".into()))?;
    let mut config =
        Config::from_url(first.as_str()).map_err(|e| SiporaError::Redis(e.to_string()))?;
    if cfg.cluster_mode {
        let mut hosts = Vec::with_capacity(cfg.nodes.len());
        for n in &cfg.nodes {
            hosts.push(parse_redis_host_port(n)?);
        }
        config.server = ServerConfig::new_clustered(hosts);
    } else if cfg.nodes.len() > 1 {
        tracing::warn!(
            count = cfg.nodes.len(),
            "redis: cluster_mode is false; using first node only"
        );
    }
    let pool = Builder::from_config(config)
        .build_pool(4)
        .map_err(|e| SiporaError::Redis(e.to_string()))?;
    pool.init()
        .await
        .map_err(|e| SiporaError::Redis(e.to_string()))?;
    Ok(pool)
}
