mod cdr;
mod codec;
mod routing;
mod udp;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use sipora_core::config::SiporaConfig;
use sipora_core::health::serve_health;
use sipora_core::health_ready::AtomicReady;
use std::net::SocketAddr;
use tokio::sync::watch;

#[derive(Parser)]
#[command(
    name = "sipora-b2bua",
    about = "SIP B2BUA: UDP signaling toward a downstream peer, codec-filtered INVITE SDP, CDR hooks"
)]
struct Cli {
    #[arg(long, env = "SIPORA_CONFIG", default_value = "sipora")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = SiporaConfig::load_from_config_input(&cli.config)?;
    let _telemetry = sipora_core::telemetry::init_telemetry(
        "sipora-b2bua",
        &config.telemetry.otlp_endpoint,
        config.telemetry.metrics_interval_s,
        config.telemetry.success_sample_rate,
    )?;
    run_cdr_codec_demo(&config).await?;

    let downstream_spec = config.b2bua.downstream.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [b2bua].downstream in config (SIP downstream host:port for the B-leg)"
        )
    })?;
    let downstream_sa = udp::resolve_downstream(downstream_spec)
        .await
        .ok_or_else(|| {
            anyhow::anyhow!("could not resolve [b2bua].downstream={downstream_spec:?}")
        })?;

    let advertise = config
        .general
        .sip_advertised_host
        .clone()
        .unwrap_or_else(|| "127.0.0.1".into());
    let sip_port = config.general.sip_udp_port;
    let sip_addr = SocketAddr::from(([0, 0, 0, 0], sip_port));
    let b2bua_rt = udp::B2buaUdpRuntime {
        downstream: downstream_sa,
        advertise,
        sip_port,
        policy: codec::CodecPolicy::new(config.media.allowed_codecs.clone()),
        router: routing::ProxyRouter::new(config.proxy.max_forwards),
        stir: build_b2bua_stir(&config.stir)?,
    };

    let ready = AtomicReady::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_health = shutdown_rx.clone();
    let health_addr = SocketAddr::from(([0, 0, 0, 0], config.general.health_port));
    let rh = ready.clone();
    tokio::spawn(async move {
        let _ = serve_health(health_addr, rh, shutdown_health).await;
    });

    tokio::spawn(async move {
        if let Err(e) = udp::run_udp_b2bua(sip_addr, b2bua_rt, shutdown_rx).await {
            tracing::error!("b2bua udp: {e}");
        }
    });

    ready.set_ready(true);
    tracing::info!(
        udp = %sip_addr,
        downstream = %downstream_spec,
        health = %health_addr,
        "sipora-b2bua listening (INVITE SDP filtered; other methods relayed to downstream)"
    );

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    tracing::info!("shutting down");
    Ok(())
}

fn build_b2bua_stir(cfg: &sipora_core::config::StirConfig) -> Result<Option<udp::B2buaStirConfig>> {
    let (Some(pem_path), Some(cert_url)) = (&cfg.privkey_pem_path, &cfg.cert_url) else {
        return Ok(None);
    };
    let privkey_pem = std::fs::read(pem_path)
        .map_err(|e| anyhow::anyhow!("stir: cannot read privkey_pem_path={pem_path:?}: {e}"))?;
    let attest = match cfg.attest.as_str() {
        "B" => sipora_auth::stir::AttestLevel::Partial,
        "C" => sipora_auth::stir::AttestLevel::Gateway,
        _ => sipora_auth::stir::AttestLevel::Full,
    };
    tracing::info!(cert_url = %cert_url, attest = %cfg.attest, "B2BUA STIR/SHAKEN signing enabled");
    Ok(Some(udp::B2buaStirConfig {
        privkey_pem,
        cert_url: cert_url.clone(),
        attest,
    }))
}

async fn run_cdr_codec_demo(config: &SiporaConfig) -> Result<()> {
    let policy = codec::CodecPolicy::new(config.media.allowed_codecs.clone());
    tracing::info!(
        codec_count = config.media.allowed_codecs.len(),
        opus_allowed = policy.is_allowed("opus"),
        "codec policy ready"
    );
    let sample_sdp = "v=0\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:18 G729/8000\r\n";
    let (_sdp, stripped) = policy.filter_sdp_codecs(sample_sdp);
    tracing::debug!(?stripped, "warmup sdp codec filter");

    let now = Utc::now();
    let (mut a_leg, mut b_leg) =
        cdr::generate_call_cdrs("sip:alice@example.com", "sip:bob@example.com", now);
    a_leg.complete(486, now);
    b_leg.set_media_stats("opus", 0.01, 2.0, "AEAD_AES_128_GCM", "192.0.2.10");
    a_leg.log_snapshot("a-leg");
    b_leg.log_snapshot("b-leg");

    try_kafka_cdrs(config, [&a_leg, &b_leg]).await?;
    try_postgres_cdrs(config, [&a_leg, &b_leg]).await?;
    Ok(())
}

async fn try_kafka_cdrs(config: &SiporaConfig, legs: [&cdr::CallDetailRecord; 2]) -> Result<()> {
    let Some(brokers) = sipora_data::kafka_cdr::brokers_csv(&config.kafka.brokers) else {
        return Ok(());
    };
    let prod =
        sipora_data::kafka_cdr::producer(&brokers).map_err(|e| anyhow::anyhow!("kafka: {e}"))?;
    for leg in legs {
        let rec = leg.to_data_cdr();
        let json = sipora_data::cdr::serialize_cdr_json(&rec)
            .map_err(|e| anyhow::anyhow!("cdr json: {e}"))?;
        sipora_data::kafka_cdr::publish_json(
            &prod,
            &config.kafka.cdr_topic,
            &rec.correlation_id.to_string(),
            &json,
        )
        .await
        .map_err(|e| anyhow::anyhow!("kafka send: {e}"))?;
    }
    tracing::info!(topic = %config.kafka.cdr_topic, "cdr records published to Kafka");
    Ok(())
}

async fn try_postgres_cdrs(config: &SiporaConfig, legs: [&cdr::CallDetailRecord; 2]) -> Result<()> {
    let Ok(pool) = sipora_data::pg::connect_pool(&config.postgres).await else {
        tracing::debug!("postgres unavailable; skip CDR insert");
        return Ok(());
    };
    if sipora_data::pg::verify_provisioning_schema(&pool)
        .await
        .is_err()
    {
        tracing::debug!("postgres schema check failed; skip CDR insert");
        return Ok(());
    }
    for leg in legs {
        let rec = leg.to_data_cdr();
        if let Err(e) = sipora_data::pg::insert_cdr(&pool, &rec).await {
            tracing::warn!(%e, "postgres cdr insert failed");
        }
    }
    tracing::info!("cdr records written to PostgreSQL");
    Ok(())
}
