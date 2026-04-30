use sipora_core::redis::RedisPool;
use sipora_edge::firewall::SipFirewall;
use sipora_edge::ratelimit::RateLimiter;
use sipora_edge::redis_ratelimit;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::header::Header;
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::status::StatusCode;
use sipora_transport::sip_tcp;
use sipora_transport::tls::{TlsTransport, load_certs_from_pem, load_key_from_pem};
use sipora_transport::websocket::WebSocketConnection;
use sipora_transport::websocket::WebSocketTransport;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::watch;

const MAX_SIP: usize = 1024 * 256;

/// Shared state for TLS or plain TCP edge accept loops.
pub struct EdgeListenContext {
    pub pool: Arc<RedisPool>,
    pub rl: RateLimiter,
    pub rl_cfg: sipora_core::config::RateLimitConfig,
    pub firewall: SipFirewall,
    pub shutdown: watch::Receiver<bool>,
}

pub async fn run_tls_or_tcp_edge(
    addr: SocketAddr,
    cert_pem: Option<Vec<u8>>,
    key_pem: Option<Vec<u8>>,
    mtls_ca: Option<Vec<u8>>,
    ocsp_der: Option<Vec<u8>>,
    ctx: EdgeListenContext,
) -> anyhow::Result<()> {
    match (cert_pem, key_pem) {
        (Some(c), Some(k)) => {
            let certs = load_certs_from_pem(&c);
            let key =
                load_key_from_pem(&k).ok_or_else(|| anyhow::anyhow!("invalid TLS key PEM"))?;
            let ca_ders: Vec<_> = mtls_ca.map(|p| load_certs_from_pem(&p)).unwrap_or_default();
            let ocsp = ocsp_der.unwrap_or_default();
            let tls = TlsTransport::bind(addr, certs, key, &ca_ders, ocsp)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            tracing::info!(%addr, "edge: TLS listener (SIPS)");
            edge_accept_loop_tls(tls, ctx).await
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(%addr, "edge: plain TCP listener (set tls.listen_*_pem_path for TLS)");
            edge_accept_loop_tcp(listener, ctx).await
        }
    }
}

async fn edge_accept_loop_tls(tls: TlsTransport, ctx: EdgeListenContext) -> anyhow::Result<()> {
    let EdgeListenContext {
        pool,
        rl,
        rl_cfg,
        firewall,
        mut shutdown,
    } = ctx;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            acc = tls.accept() => {
                let (mut stream, peer) = acc.map_err(|e| anyhow::anyhow!("{e}"))?;
                let pool = pool.clone();
                let rl = rl.clone();
                let rl_cfg = rl_cfg.clone();
                let fw = firewall.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_sip_stream(&mut stream, peer, &pool, &rl, &rl_cfg, &fw).await {
                        tracing::debug!(%peer, "edge: {e}");
                    }
                });
            }
        }
    }
}

async fn edge_accept_loop_tcp(
    listener: tokio::net::TcpListener,
    ctx: EdgeListenContext,
) -> anyhow::Result<()> {
    let EdgeListenContext {
        pool,
        rl,
        rl_cfg,
        firewall,
        mut shutdown,
    } = ctx;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            acc = listener.accept() => {
                let (mut stream, peer) = acc?;
                let pool = pool.clone();
                let rl = rl.clone();
                let rl_cfg = rl_cfg.clone();
                let fw = firewall.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_sip_stream(&mut stream, peer, &pool, &rl, &rl_cfg, &fw).await {
                        tracing::debug!(%peer, "edge: {e}");
                    }
                });
            }
        }
    }
}

pub async fn run_ws_edge(
    addr: SocketAddr,
    ctx: EdgeListenContext,
    ws_table: sipora_edge::ws_table::WsConnectionTable,
) -> anyhow::Result<()> {
    let transport = WebSocketTransport::bind(addr).await?;
    tracing::info!(%addr, "edge: WebSocket listener");
    let EdgeListenContext {
        pool,
        rl,
        rl_cfg,
        firewall,
        mut shutdown,
    } = ctx;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            acc = transport.accept() => {
                let (conn, peer) = acc.map_err(|e| anyhow::anyhow!("{e}"))?;
                let id = uuid::Uuid::new_v4().to_string();
                let (tx, rx) = mpsc::channel(sipora_edge::ws_table::WS_OUTBOUND_QUEUE);
                ws_table.write().await.insert(id.clone(), tx);
                let pool = pool.clone();
                let rl = rl.clone();
                let rl_cfg = rl_cfg.clone();
                let fw = firewall.clone();
                let ws_table_cleanup = Arc::clone(&ws_table);
                tokio::spawn(async move {
                    let res = run_single_ws_connection(conn, peer, rx, &pool, &rl, &rl_cfg, &fw).await;
                    ws_table_cleanup.write().await.remove(&id);
                    if let Err(e) = res {
                        tracing::debug!(%peer, "edge ws: {e}");
                    }
                });
            }
        }
    }
}

async fn run_single_ws_connection(
    mut conn: WebSocketConnection,
    peer: SocketAddr,
    mut outbound_rx: mpsc::Receiver<SipMessage>,
    pool: &RedisPool,
    rl: &RateLimiter,
    rl_cfg: &sipora_core::config::RateLimitConfig,
    fw: &SipFirewall,
) -> anyhow::Result<()> {
    let _keep = conn.start_keepalive();
    let ip = peer.ip().to_string();
    loop {
        tokio::select! {
            maybe_out = outbound_rx.recv() => {
                let Some(out_msg) = maybe_out else {
                    break Ok(());
                };
                let bytes = serialize_message(&out_msg);
                conn.send(&bytes)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            incoming = conn.recv() => {
                let Some(raw) = incoming else {
                    break Ok(());
                };
                let (_, msg) =
                    parse_sip_message(&raw).map_err(|e| anyhow::anyhow!("sip parse {e:?}"))?;
                if let Some(bytes) =
                    edge_process_sip_message(msg, &ip, pool, rl, rl_cfg, fw).await?
                {
                    conn.send(&bytes)
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
            }
        }
    }
}

async fn edge_process_sip_message(
    msg: SipMessage,
    ip: &str,
    pool: &RedisPool,
    rl: &RateLimiter,
    rl_cfg: &sipora_core::config::RateLimitConfig,
    fw: &SipFirewall,
) -> anyhow::Result<Option<Vec<u8>>> {
    match msg {
        SipMessage::Request(req) => {
            if let Err(detail) = fw.validate_required_headers(&req) {
                let resp = text_resp(&req, StatusCode::BAD_REQUEST, &detail);
                return Ok(Some(serialize_message(&SipMessage::Response(resp))));
            }
            let method = req.method.as_str();
            let th = redis_ratelimit::check(pool, rl, rl_cfg, ip, method).await?;
            if !th.allowed {
                let retry = th.retry_after.unwrap_or(rl_cfg.block_cooldown_s) as u32;
                let resp = retry_resp(&req, retry);
                return Ok(Some(serialize_message(&SipMessage::Response(resp))));
            }
            let resp = text_resp(&req, StatusCode::NOT_FOUND, "No upstream route configured");
            Ok(Some(serialize_message(&SipMessage::Response(resp))))
        }
        SipMessage::Response(_) => Ok(None),
    }
}

async fn handle_sip_stream<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
    pool: &RedisPool,
    rl: &RateLimiter,
    rl_cfg: &sipora_core::config::RateLimitConfig,
    fw: &SipFirewall,
) -> anyhow::Result<()> {
    let raw = sip_tcp::read_one_message(stream, MAX_SIP).await?;
    let ip = peer.ip().to_string();
    let (_, msg) = parse_sip_message(&raw).map_err(|e| anyhow::anyhow!("sip parse {e:?}"))?;
    if let Some(bytes) = edge_process_sip_message(msg, &ip, pool, rl, rl_cfg, fw).await? {
        stream.write_all(&bytes).await?;
    }
    Ok(())
}

fn text_resp(req: &Request, status: StatusCode, body: &str) -> Response {
    let mut r = base_from_request(req, status);
    r.headers.push(Header::ContentLength(body.len() as u32));
    r.body = body.as_bytes().to_vec();
    r
}

fn retry_resp(req: &Request, retry: u32) -> Response {
    let mut r = base_from_request(req, StatusCode::SERVICE_UNAVAILABLE);
    r.headers.push(Header::RetryAfter(retry));
    r.headers.push(Header::ContentLength(0));
    r
}

fn base_from_request(req: &Request, status: StatusCode) -> Response {
    let mut headers = Vec::new();
    for h in &req.headers {
        match h {
            Header::Via(_)
            | Header::From(_)
            | Header::To(_)
            | Header::CallId(_)
            | Header::CSeq(_) => headers.push(h.clone()),
            _ => {}
        }
    }
    Response {
        version: SipVersion::V2_0,
        status,
        reason: status.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    }
}
