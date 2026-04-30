use anyhow::Result;
use clap::Parser;
use sipora_core::health::serve_health;
use sipora_core::health_ready::AtomicReady;
use sipora_proxy::{dialog, forward_table, proxy_ws, udp};
use sipora_transport::tcp_pool::TcpConnectionPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::watch;

#[derive(Parser)]
#[command(
    name = "sipora-proxy",
    about = "SIP proxy, registrar, and redirect server"
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
        "sipora-proxy",
        &config.telemetry.otlp_endpoint,
        config.telemetry.metrics_interval_s,
        config.telemetry.success_sample_rate,
    )?;

    let ready = AtomicReady::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_health = shutdown_rx.clone();
    let health_addr = SocketAddr::from(([0, 0, 0, 0], config.general.health_port));
    let rh = ready.clone();
    tokio::spawn(async move {
        let _ = serve_health(health_addr, rh, shutdown_health).await;
    });

    let redis = sipora_core::redis::connect_pool(&config.redis)
        .await
        .map_err(|e| anyhow::anyhow!("redis: {e}"))?;

    let pg = sipora_data::pg::connect_pool(&config.postgres)
        .await
        .map_err(|e| anyhow::anyhow!("postgres: {e}"))?;
    sipora_data::pg::verify_provisioning_schema(&pg)
        .await
        .map_err(|e| anyhow::anyhow!("postgres schema: {e}"))?;

    let sip_addr = SocketAddr::from(([0, 0, 0, 0], config.general.sip_udp_port));
    let mf = config.proxy.max_forwards;
    let domain_cfg = config.general.domain.clone();
    let advertise = config
        .general
        .sip_advertised_host
        .clone()
        .unwrap_or_else(|| "127.0.0.1".into());
    let sip_port = config.general.sip_udp_port;
    let min_exp = config.registrar.min_expires;
    let max_exp = config.registrar.max_expires;
    let def_exp = config.registrar.default_expires;
    let nonce_ttl = config.registrar.nonce_ttl_s;
    let push_bearer = config
        .push
        .auth_bearer_env
        .as_deref()
        .and_then(|name| std::env::var(name).ok());
    let udp_cfg = udp::UdpProxyConfig {
        domain: domain_cfg,
        advertise: advertise.clone(),
        sip_port,
        max_forwards: mf,
        registrar: udp::RegistrarLimits {
            min_expires: min_exp,
            max_expires: max_exp,
            default_expires: def_exp,
        },
        nonce_ttl_s: nonce_ttl,
        fork_parallel: config.proxy.fork_parallel,
        pg,
        stir: build_stir_config(&config.stir),
        max_message_bytes: config.transport.max_message_bytes,
        outbound_edge_uri: config.registrar.outbound_edge_uri.clone(),
        push_gateway_url: config.push.gateway_url.clone(),
        push_timeout_ms: config.push.timeout_ms,
        push_auth_bearer: push_bearer,
        push_device_idle_secs: config.push.device_idle_secs,
        http_client: reqwest::Client::new(),
    };
    let forward_table = forward_table::new_forward_table();
    let dialog_table = dialog::new_dialog_table();
    let transaction_table = udp::new_transaction_table();
    let ws_listen = config.proxy.ws_listen_port;
    let ws_table_opt = (ws_listen != 0).then(sipora_edge::ws_table::new_ws_connection_table);
    let ws_for_udp = ws_table_opt.clone();
    let shutdown_for_ws = (ws_listen != 0).then(|| shutdown_rx.clone());
    let (ws_ingress_tx, ws_ingress_rx) = if ws_listen != 0 {
        let (t, r) = mpsc::channel(sipora_edge::ws_table::WS_OUTBOUND_QUEUE);
        (Some(t), Some(r))
    } else {
        (None, None)
    };
    let max_msg = config.transport.max_message_bytes;
    let (tcp_ingress_tx, tcp_ingress_rx) = mpsc::channel(256);
    let tcp_pool = Arc::new(TcpConnectionPool::new(tcp_ingress_tx, max_msg));
    tokio::spawn(async move {
        if let Err(e) = udp::run_udp_proxy(
            sip_addr,
            redis,
            udp_cfg,
            forward_table,
            dialog_table,
            transaction_table,
            ws_for_udp,
            ws_ingress_rx,
            Some(tcp_pool),
            Some(tcp_ingress_rx),
            shutdown_rx,
        )
        .await
        {
            tracing::error!("udp proxy: {e}");
        }
    });

    if let (Some(shutdown_ws), Some(ws_table)) = (shutdown_for_ws, ws_table_opt) {
        let ws_addr = SocketAddr::from(([0, 0, 0, 0], ws_listen));
        let adv = advertise.clone();
        let ing = ws_ingress_tx;
        tokio::spawn(async move {
            if let Err(e) =
                proxy_ws::run_proxy_ws_listener(ws_addr, adv, ws_listen, ws_table, ing, shutdown_ws)
                    .await
            {
                tracing::error!("proxy WebSocket listener: {e}");
            }
        });
    }

    ready.set_ready(true);
    tracing::info!(
        udp = %sip_addr,
        ws = ws_listen,
        health = %health_addr,
        "sipora-proxy listening"
    );

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    tracing::info!("shutting down");
    Ok(())
}

fn build_stir_config(cfg: &sipora_core::config::StirConfig) -> udp::StirConfig {
    use std::net::IpAddr;
    // `mode` is normalized in `StirConfig::validate` (called from `SiporaConfig::load*`).
    let mode = match cfg.mode.as_str() {
        "disabled" => udp::StirMode::Disabled,
        "permissive" => udp::StirMode::Permissive,
        "strict" => udp::StirMode::Strict,
        _ => unreachable!("[stir].mode should be one of disabled|permissive|strict after validate"),
    };
    let trusted_peer_ips: Vec<IpAddr> = cfg
        .trusted_peer_ips
        .iter()
        .filter_map(|s| {
            s.parse::<IpAddr>()
                .map_err(|e| tracing::warn!(ip = %s, "stir: invalid trusted_peer_ip: {e}"))
                .ok()
        })
        .collect();
    if !matches!(mode, udp::StirMode::Disabled) {
        tracing::info!(mode = %cfg.mode, peers = trusted_peer_ips.len(), "STIR/SHAKEN verification enabled");
    }
    udp::StirConfig {
        mode,
        trusted_peer_ips,
        cert_cache: sipora_auth::stir::CertCache::new(),
    }
}
