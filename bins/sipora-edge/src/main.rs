mod listener;

use anyhow::Result;
use clap::Parser;
use sipora_core::health::serve_health;
use sipora_core::health_ready::AtomicReady;
use sipora_edge::firewall::SipFirewall;
use sipora_edge::ratelimit::RateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Parser)]
#[command(
    name = "sipora-edge",
    about = "SIP edge: TLS/TCP, firewall, Redis-backed rate limits"
)]
struct Cli {
    #[arg(long, env = "SIPORA_CONFIG", default_value = "sipora")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = sipora_core::config::SiporaConfig::load_from_config_input(&cli.config)?;

    let _telemetry = sipora_core::telemetry::init_telemetry(
        "sipora-edge",
        &config.telemetry.otlp_endpoint,
        config.telemetry.metrics_interval_s,
        config.telemetry.success_sample_rate,
    )?;

    let pool = Arc::new(
        sipora_core::redis::connect_pool(&config.redis)
            .await
            .map_err(|e| anyhow::anyhow!("redis: {e} (edge requires Redis for rate limiting)"))?,
    );

    let ready = AtomicReady::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_health = shutdown_rx.clone();
    let health_addr = SocketAddr::from(([0, 0, 0, 0], config.general.health_port));
    let ready_health = ready.clone();
    tokio::spawn(async move {
        let _ = serve_health(health_addr, ready_health, shutdown_health).await;
    });

    let rl = RateLimiter::new(config.rate_limit.clone());
    let firewall = SipFirewall::new(true, true, 100);

    let cert = load_optional(&config.tls.listen_cert_pem_path)?;
    let key = load_optional(&config.tls.listen_key_pem_path)?;
    let mtls_ca = load_optional(&config.tls.mtls_client_ca_pem_path)?;
    let ocsp_der = load_optional(&config.tls.ocsp_response_der_path)?;

    let bind = SocketAddr::from(([0, 0, 0, 0], config.general.sips_port));
    let shutdown_tcp = shutdown_rx.clone();
    let edge_ctx = listener::EdgeListenContext {
        pool: Arc::clone(&pool),
        rl: rl.clone(),
        rl_cfg: config.rate_limit.clone(),
        firewall: firewall.clone(),
        shutdown: shutdown_tcp,
    };
    tokio::spawn(async move {
        if let Err(e) =
            listener::run_tls_or_tcp_edge(bind, cert, key, mtls_ca, ocsp_der, edge_ctx).await
        {
            tracing::error!("edge listener: {e}");
        }
    });

    let ws_bind = SocketAddr::from(([0, 0, 0, 0], config.general.wss_port));
    let ws_table = sipora_edge::ws_table::new_ws_connection_table();
    let ws_ctx = listener::EdgeListenContext {
        pool: Arc::clone(&pool),
        rl: rl.clone(),
        rl_cfg: config.rate_limit.clone(),
        firewall: firewall.clone(),
        shutdown: shutdown_rx,
    };
    tokio::spawn(async move {
        if let Err(e) = listener::run_ws_edge(ws_bind, ws_ctx, ws_table).await {
            tracing::error!("edge WebSocket listener: {e}");
        }
    });

    ready.set_ready(true);
    tracing::info!(
        "sipora-edge listening (SIP on sips_port, WebSocket on wss_port, health on health_port)"
    );

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    tracing::info!("shutting down");
    Ok(())
}

fn load_optional(path: &Option<String>) -> Result<Option<Vec<u8>>> {
    match path {
        None => Ok(None),
        Some(p) => Ok(Some(
            std::fs::read(p).map_err(|e| anyhow::anyhow!("read {p}: {e}"))?,
        )),
    }
}
