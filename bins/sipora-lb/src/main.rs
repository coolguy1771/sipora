mod balancer;
mod udp;

use anyhow::Result;
use balancer::{LoadBalancer, ProxyNode};
use clap::Parser;
use sipora_core::health::serve_health;
use sipora_core::health_ready::AtomicReady;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Parser)]
#[command(name = "sipora-lb", about = "SIP-aware load balancer")]
struct Cli {
    #[arg(long, env = "SIPORA_CONFIG", default_value = "sipora")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = sipora_core::config::SiporaConfig::load_from_config_input(&cli.config)?;

    let _telemetry = sipora_core::telemetry::init_telemetry(
        "sipora-lb",
        &config.telemetry.otlp_endpoint,
        config.telemetry.metrics_interval_s,
        config.telemetry.success_sample_rate,
    )?;

    balancer::warmup_from_config(&config);

    let ready = AtomicReady::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_health = shutdown_rx.clone();
    let health_addr = SocketAddr::from(([0, 0, 0, 0], config.general.health_port));
    let rh = ready.clone();
    tokio::spawn(async move {
        let _ = serve_health(health_addr, rh, shutdown_health).await;
    });

    let mut lb = LoadBalancer::new(3, 0.5, 60, 300);
    let mut id_to_sock = HashMap::new();
    for (i, spec) in config.upstreams.lb_sip_proxies.iter().enumerate() {
        let id = format!("lb-{i}");
        match udp::resolve_lb_upstream(spec).await {
            Some(sock) => {
                id_to_sock.insert(id.clone(), sock);
                lb.add_node(ProxyNode::new(&id, spec, 100));
            }
            None => tracing::warn!(spec, "lb: could not resolve upstream; skipping"),
        }
    }
    if id_to_sock.is_empty() {
        tracing::warn!("lb: no resolvable upstreams; UDP loop still bound but will not route");
    }
    let id_to_sock = Arc::new(id_to_sock);

    let sip_addr = SocketAddr::from(([0, 0, 0, 0], config.general.sip_udp_port));
    tokio::spawn(async move {
        if let Err(e) = udp::run_udp_lb(sip_addr, lb, id_to_sock, shutdown_rx).await {
            tracing::error!("sipora-lb udp: {e}");
        }
    });

    ready.set_ready(true);
    tracing::info!(udp = %sip_addr, health = %health_addr, "sipora-lb listening");

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    tracing::info!("shutting down");
    Ok(())
}
