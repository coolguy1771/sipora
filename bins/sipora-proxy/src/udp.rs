//! UDP registrar and request-only SIP handling. INVITE is forwarded without response relay;
//! see `AGENTS.md` ("SIP signaling scope") and `docs/qualification.md` for end-to-end INVITE paths.

use sipora_auth::digest::{DigestAlgorithm, DigestResponse};
use sipora_auth::stir::{CertCache, StirError, verify_identity_header};
use sipora_core::redis::RedisPool;
use sipora_data::pg::get_user_sip_digest_credentials;
use sipora_location::ContactBinding;
use sipora_location::gruu;
use sipora_location::presence::{PresenceError, load_presence, publish_presence};
use sipora_location::redis_store::{list_contact_uris, lookup_user_for_pub_gruu};
use sipora_location::subscription::{
    Subscription, delete_subscription, list_subscriptions_for_aor, next_notify_cseq,
    save_subscription,
};
use sipora_sip::overload::overload_response;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::transaction::TransactionKey;
use sipora_sip::transaction::manager::{TransactionManager, TransactionType};
use sipora_sip::types::header::{CSeq, Header, SubscriptionStateValue, Transport, Via};
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;
use sipora_transport::dns::{SipTransport, resolve_sip_targets};
use sipora_transport::enum_resolve_tel_to_sip;
use sipora_transport::udp::UdpTransport;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc, watch};
use uuid::Uuid;

use crate::dialog::{
    DialogKey, DialogState, DialogTable, RefreshTable, cancel_session_guard, dialog_for_request,
    insert_dialog_from_response, new_refresh_table, remove_dialog, spawn_session_guard,
};
use crate::event_bodies::{presence_body_from_doc, reginfo_xml};
use crate::forward_table::{
    ForwardTable, PendingForward, ResponseTarget, find_branch_by_call_id,
    find_branch_by_call_id_and_rseq, find_branches_by_call_id, get_pending_forward, insert_forward,
    prepare_response, remove_pending_branch, spawn_forward_sweeper,
};
use crate::ingress::{ProxyIngress, ReplyTarget};
use crate::message_sender::{MessageSender, MessageTarget};
use crate::notify::{build_notify_request, dispatch_notify};
use crate::responses::{
    PROXY_MIN_SE, sip_ok_sip_etag, sip_options_ok, sip_response, sip_response_expires,
    sip_response_multi_proxy_auth, sip_response_with_min_se,
};
use crate::routing::ProxyRouter;

mod register;

/// Expiry clamp range for REGISTER.
pub struct RegistrarLimits {
    pub min_expires: u32,
    pub max_expires: u32,
    pub default_expires: u32,
}

/// How the proxy handles inbound STIR Identity headers (RFC 8224).
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StirMode {
    /// Do not inspect Identity headers (default for legacy deployments).
    Disabled,
    /// Verify Identity if present; log failures but never reject.
    #[allow(dead_code)]
    Permissive,
    /// Require Identity on every INVITE; reject if absent or invalid.
    Strict,
}

/// STIR/SHAKEN verification policy for inbound INVITEs.
pub struct StirConfig {
    pub mode: StirMode,
    /// Source IPs whose P-Asserted-Identity headers are trusted (RFC 3325 §9.1).
    pub trusted_peer_ips: Vec<IpAddr>,
    pub cert_cache: CertCache,
    /// PEM bundle loaded from `[stir].trust_anchor_pem_path` (RFC 8226 §5 chain validation).
    pub trust_anchor_pem: Option<Arc<str>>,
}

impl Default for StirConfig {
    fn default() -> Self {
        Self {
            mode: StirMode::Disabled,
            trusted_peer_ips: vec![],
            cert_cache: CertCache::new(),
            trust_anchor_pem: None,
        }
    }
}

/// Static UDP proxy configuration (per process).
pub struct UdpProxyConfig {
    pub domain: String,
    pub advertise: String,
    pub sip_port: u16,
    pub max_forwards: u8,
    pub registrar: RegistrarLimits,
    pub nonce_ttl_s: u64,
    pub fork_parallel: bool,
    pub pg: PgPool,
    pub stir: StirConfig,
    pub max_message_bytes: usize,
    pub outbound_edge_uri: Option<String>,
    pub push_gateway_url: Option<String>,
    pub push_timeout_ms: u64,
    pub push_auth_bearer: Option<String>,
    pub push_device_idle_secs: u64,
    pub http_client: reqwest::Client,
}

pub type TransactionTable = Arc<RwLock<TransactionManager>>;

/// INVITE client Timer B (RFC 3261 §17.1.1.2). Uses production `TIMER_B` unless compiling tests.
#[cfg(test)]
const INVITE_CLIENT_TIMER_B: Duration = Duration::from_millis(250);
#[cfg(not(test))]
const INVITE_CLIENT_TIMER_B: Duration = sipora_sip::transaction::TIMER_B;

#[derive(Debug)]
struct PreparedForkFailure {
    response: Response,
    target: ResponseTarget,
}

#[derive(Debug, Default)]
pub struct CallForkState {
    branches: Vec<String>,
    completed: HashSet<String>,
    success_seen: bool,
    best_failure: Option<PreparedForkFailure>,
}

pub type ForkTable = Arc<RwLock<HashMap<String, CallForkState>>>;

pub fn new_fork_table() -> ForkTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn new_transaction_table() -> TransactionTable {
    Arc::new(RwLock::new(TransactionManager::new()))
}

const FORK_STATE_SWEEP_INTERVAL: Duration = Duration::from_secs(32);

pub async fn cleanup_stale_fork_states(fork_table: &ForkTable, forward_table: &ForwardTable) {
    let live_branches: HashSet<String> = forward_table.read().await.keys().cloned().collect();
    fork_table.write().await.retain(|_, state| {
        state
            .branches
            .iter()
            .any(|branch| live_branches.contains(branch))
    });
}

fn spawn_fork_sweeper(
    fork_table: ForkTable,
    forward_table: ForwardTable,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(FORK_STATE_SWEEP_INTERVAL);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
                _ = interval.tick() => cleanup_stale_fork_states(&fork_table, &forward_table).await,
            }
        }
    })
}

enum MergeIngress {
    Ws(crate::proxy_ws::WsIngressEnvelope),
    Tcp((SocketAddr, SipMessage)),
}

fn spawn_merge_ingress_bridges(
    ws_ingress: Option<tokio::sync::mpsc::Receiver<crate::proxy_ws::WsIngressEnvelope>>,
    tcp_ingress: Option<tokio::sync::mpsc::Receiver<(SocketAddr, SipMessage)>>,
) -> Option<tokio::sync::mpsc::Receiver<MergeIngress>> {
    if ws_ingress.is_none() && tcp_ingress.is_none() {
        return None;
    }
    let cap = sipora_edge::ws_table::WS_OUTBOUND_QUEUE;
    let (tx, rx) = tokio::sync::mpsc::channel(cap);
    if let Some(mut ws) = ws_ingress {
        let t = tx.clone();
        tokio::spawn(async move {
            while let Some(env) = ws.recv().await {
                if t.send(MergeIngress::Ws(env)).await.is_err() {
                    break;
                }
            }
        });
    }
    if let Some(mut tcp) = tcp_ingress {
        let t = tx.clone();
        tokio::spawn(async move {
            while let Some(pair) = tcp.recv().await {
                if t.send(MergeIngress::Tcp(pair)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    Some(rx)
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_merge_ingress_item(
    item: MergeIngress,
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    tcp_for_merge: &Option<Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    refresh_table: &RefreshTable,
    session_expired_tx: mpsc::Sender<DialogKey>,
) -> anyhow::Result<()> {
    match item {
        MergeIngress::Ws(env) => {
            let ingress = ProxyIngress::ws(
                socket.clone(),
                sip_sender.clone(),
                env.connection_id,
                env.peer,
            );
            match env.message {
                SipMessage::Request(req) => {
                    dispatch_request(
                        &ingress,
                        sip_sender,
                        redis,
                        router,
                        cfg,
                        forward_table,
                        dialog_table,
                        transaction_table,
                        fork_table,
                        refresh_table,
                        tcp_for_merge.as_ref(),
                        req,
                    )
                    .await
                }
                SipMessage::Response(resp) => {
                    dispatch_response(
                        socket,
                        sip_sender,
                        cfg,
                        forward_table,
                        fork_table,
                        dialog_table,
                        transaction_table,
                        refresh_table,
                        session_expired_tx.clone(),
                        resp,
                    )
                    .await
                }
            }
        }
        MergeIngress::Tcp((addr, msg)) => {
            let Some(pool) = tcp_for_merge else {
                tracing::warn!(%addr, "tcp ingress without pool");
                return Ok(());
            };
            let ingress = ProxyIngress::tcp_downstream(socket.clone(), pool.clone(), addr);
            match msg {
                SipMessage::Request(req) => {
                    dispatch_request(
                        &ingress,
                        sip_sender,
                        redis,
                        router,
                        cfg,
                        forward_table,
                        dialog_table,
                        transaction_table,
                        fork_table,
                        refresh_table,
                        tcp_for_merge.as_ref(),
                        req,
                    )
                    .await
                }
                SipMessage::Response(resp) => {
                    dispatch_response(
                        socket,
                        sip_sender,
                        cfg,
                        forward_table,
                        fork_table,
                        dialog_table,
                        transaction_table,
                        refresh_table,
                        session_expired_tx.clone(),
                        resp,
                    )
                    .await
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_udp_proxy(
    addr: SocketAddr,
    redis: RedisPool,
    cfg: UdpProxyConfig,
    forward_table: ForwardTable,
    dialog_table: DialogTable,
    transaction_table: TransactionTable,
    ws_table: Option<sipora_edge::ws_table::WsConnectionTable>,
    ws_ingress: Option<tokio::sync::mpsc::Receiver<crate::proxy_ws::WsIngressEnvelope>>,
    tcp_pool: Option<std::sync::Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    tcp_ingress: Option<tokio::sync::mpsc::Receiver<(SocketAddr, SipMessage)>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let udp = UdpTransport::bind(addr).await?;
    let socket = Arc::new(udp.into_inner());
    let udp_snd = Arc::new(crate::message_sender::UdpSender::new(socket.clone()));
    let ws_snd = ws_table
        .clone()
        .map(|t| Arc::new(crate::message_sender::WsSender::new(t)));
    let tcp_snd = tcp_pool
        .clone()
        .map(|p| Arc::new(crate::message_sender::TcpPoolSender::new(p)));
    let sip_sender: Arc<dyn MessageSender> = Arc::new(crate::notify::CompositeSender {
        udp: udp_snd,
        ws: ws_snd,
        tcp: tcp_snd,
    });
    let tcp_for_merge = tcp_pool.clone();
    let mut merged_rx = spawn_merge_ingress_bridges(ws_ingress, tcp_ingress);
    let router = ProxyRouter::new(cfg.max_forwards);
    let refresh_table = new_refresh_table();
    let (session_expired_tx, mut session_expired_rx) = mpsc::channel::<DialogKey>(256);
    let fork_table = new_fork_table();
    let _forward_sweeper = spawn_forward_sweeper(forward_table.clone(), shutdown.clone());
    let _fork_sweeper =
        spawn_fork_sweeper(fork_table.clone(), forward_table.clone(), shutdown.clone());
    let recv_cap = cfg.max_message_bytes.clamp(1024, 65535);
    let mut buf = vec![0u8; recv_cap];
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            expired_key = session_expired_rx.recv() => {
                let Some(k) = expired_key else {
                    return Ok(());
                };
                if let Err(e) = handle_session_expired(
                    k,
                    &socket,
                    &sip_sender,
                    &redis,
                    &cfg,
                    &dialog_table,
                    &refresh_table,
                )
                .await
                {
                    tracing::warn!(%e, "session-expired teardown");
                }
            }
            recv = socket.recv_from(&mut buf) => {
                let (n, peer) = recv?;
                let data = &buf[..n];
                let Ok((_, msg)) = parse_sip_message(data) else {
                    continue;
                };
                let result = match msg {
                    SipMessage::Request(req) => {
                        let ingress = ProxyIngress::udp(socket.clone(), peer);
                        dispatch_request(
                            &ingress,
                            &sip_sender,
                            &redis,
                            &router,
                            &cfg,
                            &forward_table,
                            &dialog_table,
                            &transaction_table,
                            &fork_table,
                            &refresh_table,
                            tcp_for_merge.as_ref(),
                            req,
                        )
                        .await
                    }
                    SipMessage::Response(resp) => {
                        dispatch_response(
                            &socket,
                            &sip_sender,
                            &cfg,
                            &forward_table,
                            &fork_table,
                            &dialog_table,
                            &transaction_table,
                            &refresh_table,
                            session_expired_tx.clone(),
                            resp,
                        )
                        .await
                    }
                };
                if let Err(e) = result {
                    tracing::warn!(%peer, "udp proxy: {e}");
                }
            }
            merge_item = async {
                merged_rx.as_mut().expect("merge branch only if Some").recv().await
            }, if merged_rx.is_some() => {
                let Some(item) = merge_item else {
                    merged_rx = None;
                    continue;
                };
                let result = dispatch_merge_ingress_item(
                    item,
                    &socket,
                    &sip_sender,
                    &tcp_for_merge,
                    &redis,
                    &router,
                    &cfg,
                    &forward_table,
                    &dialog_table,
                    &transaction_table,
                    &fork_table,
                    &refresh_table,
                    session_expired_tx.clone(),
                )
                .await;
                if let Err(e) = result {
                    tracing::warn!("merged ingress: {e}");
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    refresh_table: &RefreshTable,
    tcp_for_merge: Option<&Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    mut req: Request,
) -> anyhow::Result<()> {
    apply_rfc3581(&mut req, ingress.source);
    if let Some(status) = enforce_sips_policy(&req, ingress.ingress_transport()) {
        crate::ingress::respond(ingress, &sip_response(&req, status)).await;
        return Ok(());
    }
    track_server_transaction(transaction_table, &req).await;
    match req.method {
        Method::Invite => {
            handle_invite(
                ingress,
                sip_sender,
                redis,
                router,
                cfg,
                forward_table,
                transaction_table,
                fork_table,
                dialog_table,
                req,
            )
            .await
        }
        Method::Register => {
            register::handle_register(
                ingress,
                sip_sender,
                redis,
                router,
                cfg,
                forward_table,
                transaction_table,
                fork_table,
                dialog_table,
                tcp_for_merge,
                req,
            )
            .await
        }
        Method::Ack | Method::Bye | Method::Update | Method::Refer => {
            handle_dialog_request(
                ingress,
                redis,
                cfg,
                forward_table,
                transaction_table,
                dialog_table,
                refresh_table,
                req,
            )
            .await
        }
        Method::Cancel => handle_cancel(ingress, cfg, forward_table, transaction_table, req).await,
        Method::Prack => handle_prack(ingress, cfg, forward_table, req).await,
        Method::Options => {
            crate::ingress::respond(ingress, &sip_options_ok(&req)).await;
            Ok(())
        }
        Method::Message => handle_message(ingress, sip_sender, redis, cfg, req).await,
        Method::Subscribe => handle_subscribe(ingress, sip_sender, redis, cfg, req).await,
        Method::Notify => {
            handle_notify(
                ingress,
                redis,
                cfg,
                forward_table,
                transaction_table,
                dialog_table,
                refresh_table,
                req,
            )
            .await
        }
        Method::Publish => handle_publish(ingress, sip_sender, redis, cfg, req).await,
        _ => {
            crate::ingress::respond(ingress, &sip_response(&req, StatusCode::NOT_IMPLEMENTED))
                .await;
            Ok(())
        }
    }
}

async fn track_server_transaction(table: &TransactionTable, req: &Request) {
    let Some(key) = TransactionKey::from_request(req) else {
        return;
    };
    let tx_type = match req.method {
        Method::Invite => TransactionType::ServerInvite,
        _ => TransactionType::ServerNonInvite,
    };
    table.write().await.insert(key, tx_type);
}

async fn track_client_transaction(
    table: &TransactionTable,
    req: &Request,
    tx_type: TransactionType,
) {
    let Some(key) = TransactionKey::from_request(req) else {
        return;
    };
    table.write().await.insert(key, tx_type);
}

async fn remove_client_transaction(table: &TransactionTable, resp: &Response) {
    if resp.status.class() < 2 {
        return;
    }
    let Some(key) = transaction_key_from_response(resp) else {
        return;
    };
    table.write().await.remove(&key);
}

fn transaction_key_from_response(resp: &Response) -> Option<TransactionKey> {
    let via = response_top_via(resp)?;
    Some(TransactionKey {
        branch: via.branch.clone(),
        sent_by: sent_by(via),
        method: resp.cseq()?.method.as_str().to_string(),
    })
}

fn sent_by(via: &Via) -> String {
    match via.port {
        Some(port) => format!("{}:{port}", via.host),
        None => via.host.clone(),
    }
}

fn apply_rfc3581(req: &mut Request, peer: SocketAddr) {
    let Some(via) = top_via_mut(&mut req.headers) else {
        return;
    };
    let via_ip = via.host.parse::<IpAddr>().ok();
    if via_ip != Some(peer.ip()) {
        via.received = Some(peer.ip().to_string());
    }
    if matches!(via.rport, sipora_sip::types::header::RportParam::Requested) {
        via.rport = sipora_sip::types::header::RportParam::Filled(peer.port());
    }
}

fn top_via_mut(headers: &mut [Header]) -> Option<&mut Via> {
    headers.iter_mut().find_map(|header| match header {
        Header::Via(via) => Some(via),
        _ => None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_response(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    refresh_table: &RefreshTable,
    session_expired_tx: mpsc::Sender<DialogKey>,
    resp: Response,
) -> anyhow::Result<()> {
    let Some(branch) = response_proxy_branch(&resp, cfg) else {
        return Ok(());
    };
    remove_client_transaction(transaction_table, &resp).await;
    if is_cancel_success_response(&resp) {
        return Ok(());
    }

    let pending = get_pending_forward(forward_table, &branch).await;
    if is_parallel_branch(fork_table, &resp, &branch).await {
        return handle_parallel_response(
            socket,
            sip_sender,
            cfg,
            forward_table,
            fork_table,
            dialog_table,
            transaction_table,
            refresh_table,
            session_expired_tx,
            branch,
            resp,
            pending,
        )
        .await;
    }

    if should_try_next_fork(&resp, pending.as_ref()) {
        let Some(pending) = pending else {
            return Ok(());
        };
        return handle_fork_failure_response(
            socket,
            sip_sender,
            cfg,
            forward_table,
            transaction_table,
            &branch,
            resp,
            pending,
        )
        .await;
    }

    relay_final_response(
        socket,
        sip_sender,
        dialog_table,
        refresh_table,
        forward_table,
        session_expired_tx,
        &branch,
        resp,
        pending,
    )
    .await
}

fn response_proxy_branch(resp: &Response, cfg: &UdpProxyConfig) -> Option<String> {
    let top_via = response_top_via(resp)?;
    if !via_matches_proxy(top_via, &cfg.advertise, cfg.sip_port) {
        return None;
    }
    (!top_via.branch.is_empty()).then(|| top_via.branch.clone())
}

async fn is_parallel_branch(fork_table: &ForkTable, resp: &Response, branch: &str) -> bool {
    let Some(call_id) = resp.call_id() else {
        return false;
    };
    fork_table
        .read()
        .await
        .get(call_id)
        .is_some_and(|state| state.branches.iter().any(|b| b == branch))
}

#[allow(clippy::too_many_arguments)]
async fn handle_parallel_response(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    refresh_table: &RefreshTable,
    session_expired_tx: mpsc::Sender<DialogKey>,
    branch: String,
    resp: Response,
    pending: Option<PendingForward>,
) -> anyhow::Result<()> {
    if resp.status.is_provisional() {
        return relay_parallel_response(
            socket,
            sip_sender,
            dialog_table,
            refresh_table,
            forward_table,
            session_expired_tx.clone(),
            &branch,
            resp,
            pending,
        )
        .await;
    }
    if resp.status.is_success() {
        mark_parallel_success(fork_table, &resp, &branch).await;
        return relay_parallel_response(
            socket,
            sip_sender,
            dialog_table,
            refresh_table,
            forward_table,
            session_expired_tx.clone(),
            &branch,
            resp,
            pending,
        )
        .await;
    }
    if parallel_success_seen(fork_table, &resp).await {
        absorb_parallel_final_after_success(fork_table, forward_table, &resp, &branch).await;
        return Ok(());
    }
    if resp.status.is_global_error() {
        remove_fork_state(fork_table, &resp).await;
        cancel_parallel_siblings(
            socket,
            cfg,
            forward_table,
            transaction_table,
            &branch,
            &pending,
        )
        .await?;
        return relay_parallel_response(
            socket,
            sip_sender,
            dialog_table,
            refresh_table,
            forward_table,
            session_expired_tx,
            &branch,
            resp,
            pending,
        )
        .await;
    }
    handle_parallel_failure(socket, sip_sender, forward_table, fork_table, &branch, resp).await
}

#[allow(clippy::too_many_arguments)]
async fn relay_parallel_response(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    forward_table: &ForwardTable,
    session_expired_tx: mpsc::Sender<DialogKey>,
    branch: &str,
    resp: Response,
    pending: Option<PendingForward>,
) -> anyhow::Result<()> {
    relay_final_response(
        socket,
        sip_sender,
        dialog_table,
        refresh_table,
        forward_table,
        session_expired_tx,
        branch,
        resp,
        pending,
    )
    .await
}

async fn mark_parallel_success(fork_table: &ForkTable, resp: &Response, branch: &str) {
    let Some(call_id) = resp.call_id().map(str::to_owned) else {
        return;
    };
    let mut table = fork_table.write().await;
    let Some(state) = table.get_mut(&call_id) else {
        return;
    };
    state.success_seen = true;
    state.completed.insert(branch.to_string());
    if state.completed.len() == state.branches.len() {
        table.remove(&call_id);
    }
}

async fn parallel_success_seen(fork_table: &ForkTable, resp: &Response) -> bool {
    let Some(call_id) = resp.call_id() else {
        return false;
    };
    fork_table
        .read()
        .await
        .get(call_id)
        .is_some_and(|state| state.success_seen)
}

async fn absorb_parallel_final_after_success(
    fork_table: &ForkTable,
    forward_table: &ForwardTable,
    resp: &Response,
    branch: &str,
) {
    mark_parallel_completed(fork_table, resp, branch).await;
    remove_forward_branch(forward_table, branch).await;
}

async fn mark_parallel_completed(fork_table: &ForkTable, resp: &Response, branch: &str) {
    let Some(call_id) = resp.call_id().map(str::to_owned) else {
        return;
    };
    let mut table = fork_table.write().await;
    let Some(state) = table.get_mut(&call_id) else {
        return;
    };
    state.completed.insert(branch.to_string());
    if state.completed.len() == state.branches.len() {
        table.remove(&call_id);
    }
}

async fn remove_fork_state(fork_table: &ForkTable, resp: &Response) {
    let Some(call_id) = resp.call_id() else {
        return;
    };
    fork_table.write().await.remove(call_id);
}

async fn remove_forward_branch(forward_table: &ForwardTable, branch: &str) {
    forward_table.write().await.remove(branch);
}

fn is_cancel_success_response(resp: &Response) -> bool {
    resp.status.is_success()
        && resp
            .cseq()
            .is_some_and(|cseq| cseq.method == Method::Cancel)
}

#[allow(clippy::too_many_arguments)]
async fn cancel_parallel_siblings(
    socket: &Arc<tokio::net::UdpSocket>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    branch: &str,
    pending: &Option<PendingForward>,
) -> anyhow::Result<()> {
    let Some(original_request) = pending.as_ref().and_then(|p| p.original_request.as_ref()) else {
        return Ok(());
    };
    let Some(call_id) = original_request.call_id() else {
        return Ok(());
    };
    for sibling in find_branches_by_call_id(forward_table, call_id).await {
        if sibling != branch {
            cancel_parallel_sibling(
                socket,
                cfg,
                forward_table,
                transaction_table,
                &sibling,
                original_request,
            )
            .await?;
        }
    }
    Ok(())
}

async fn cancel_parallel_sibling(
    socket: &Arc<tokio::net::UdpSocket>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    branch: &str,
    original_request: &Request,
) -> anyhow::Result<()> {
    let pending = get_pending_forward(forward_table, branch).await;
    let Some(pending) = pending else {
        return Ok(());
    };
    let cancel = build_cancel_request(original_request, branch, &pending.forwarded_uri, cfg);
    track_client_transaction(transaction_table, &cancel, TransactionType::ClientNonInvite).await;
    let bytes = serialize_message(&SipMessage::Request(cancel));
    socket.send_to(&bytes, pending.target_addr).await?;
    remove_forward_branch(forward_table, branch).await;
    Ok(())
}

async fn handle_parallel_failure(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    forward_table: &ForwardTable,
    fork_table: &ForkTable,
    branch: &str,
    mut resp: Response,
) -> anyhow::Result<()> {
    let Some(call_id) = resp.call_id().map(str::to_owned) else {
        return Ok(());
    };
    let Some(target) = prepare_parallel_failure(forward_table, branch, &mut resp).await else {
        return Ok(());
    };
    let final_failure = record_parallel_failure(fork_table, &call_id, branch, resp, target).await;
    if let Some(failure) = final_failure {
        return send_response_target(socket, sip_sender, failure.response, failure.target).await;
    }
    Ok(())
}

async fn prepare_parallel_failure(
    forward_table: &ForwardTable,
    branch: &str,
    resp: &mut Response,
) -> Option<ResponseTarget> {
    let mut target = prepare_response(forward_table, branch, resp).await?;
    if let Some(via) = response_top_via(resp) {
        target = match target {
            ResponseTarget::Udp(a) => ResponseTarget::Udp(response_relay_addr(via).unwrap_or(a)),
            w @ ResponseTarget::Ws { .. } => w,
        };
    }
    Some(target)
}

async fn record_parallel_failure(
    fork_table: &ForkTable,
    call_id: &str,
    branch: &str,
    resp: Response,
    target: ResponseTarget,
) -> Option<PreparedForkFailure> {
    let mut table = fork_table.write().await;
    let state = table.get_mut(call_id)?;
    state.completed.insert(branch.to_string());
    record_best_failure(
        state,
        PreparedForkFailure {
            response: resp,
            target,
        },
    );
    if state.completed.len() != state.branches.len() {
        return None;
    }
    if state.success_seen {
        table.remove(call_id);
        return None;
    }
    table
        .remove(call_id)
        .and_then(|mut state| state.best_failure.take())
}

fn record_best_failure(state: &mut CallForkState, failure: PreparedForkFailure) {
    if state
        .best_failure
        .as_ref()
        .is_none_or(|best| failure_preferred(&failure.response, &best.response))
    {
        state.best_failure = Some(failure);
    }
}

// Deterministic non-2xx fork merge policy: 6xx is handled immediately before
// this path; among deferred failures, prefer 5xx over 4xx over 3xx. Ties keep
// the lower status code, then first-seen response.
fn failure_preferred(candidate: &Response, current: &Response) -> bool {
    let candidate_rank = failure_status_rank(candidate.status);
    let current_rank = failure_status_rank(current.status);
    candidate_rank > current_rank
        || (candidate_rank == current_rank && candidate.status.0 < current.status.0)
}

fn failure_status_rank(status: StatusCode) -> u8 {
    match status.class() {
        5 => 3,
        4 => 2,
        3 => 1,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_fork_failure_response(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    branch: &str,
    mut resp: Response,
    pending: PendingForward,
) -> anyhow::Result<()> {
    let Some(mut target) = prepare_response(forward_table, branch, &mut resp).await else {
        return Ok(());
    };
    if forward_next_fork(
        socket,
        sip_sender,
        cfg,
        forward_table,
        transaction_table,
        pending,
    )
    .await?
    {
        return Ok(());
    }
    if let Some(via) = response_top_via(&resp) {
        target = match target {
            ResponseTarget::Udp(a) => ResponseTarget::Udp(response_relay_addr(via).unwrap_or(a)),
            w @ ResponseTarget::Ws { .. } => w,
        };
    }
    send_response_target(socket, sip_sender, resp, target).await
}

#[allow(clippy::too_many_arguments)]
async fn relay_final_response(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    forward_table: &ForwardTable,
    session_expired_tx: mpsc::Sender<DialogKey>,
    branch: &str,
    mut resp: Response,
    pending: Option<PendingForward>,
) -> anyhow::Result<()> {
    let success_response = pending.as_ref().is_some_and(|_| resp.status.is_success());
    let Some(mut target) = prepare_response(forward_table, branch, &mut resp).await else {
        return Ok(());
    };
    if let Some(via) = response_top_via(&resp) {
        target = match target {
            ResponseTarget::Udp(a) => ResponseTarget::Udp(response_relay_addr(via).unwrap_or(a)),
            w @ ResponseTarget::Ws { .. } => w,
        };
    }
    if success_response
        && let Some(pending) = pending
        && let Some(dialog_key) = insert_dialog_from_response(
            dialog_table,
            &resp,
            pending.client_addr,
            pending.target_addr,
            pending.reply_ws_conn_id.clone(),
            pending.original_request.as_ref(),
        )
        .await
        && let Some(se) = response_session_expires(&resp)
    {
        spawn_session_guard(
            dialog_table,
            refresh_table,
            dialog_key,
            Duration::from_secs(se as u64),
            session_expired_tx.clone(),
        )
        .await;
    }
    send_response_target(socket, sip_sender, resp, target).await
}

fn response_session_expires(resp: &Response) -> Option<u32> {
    resp.headers.iter().find_map(|h| match h {
        Header::SessionExpires { delta_seconds, .. } => Some(*delta_seconds),
        _ => None,
    })
}

async fn send_response(
    socket: &Arc<tokio::net::UdpSocket>,
    resp: Response,
    target: SocketAddr,
) -> anyhow::Result<()> {
    let bytes = serialize_message(&SipMessage::Response(resp));
    socket.send_to(&bytes, target).await?;
    Ok(())
}

async fn send_response_target(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    resp: Response,
    target: ResponseTarget,
) -> anyhow::Result<()> {
    match target {
        ResponseTarget::Udp(a) => send_response(socket, resp, a).await,
        ResponseTarget::Ws { connection_id } => {
            sip_sender
                .send_sip(
                    &MessageTarget::Ws { connection_id },
                    SipMessage::Response(resp),
                )
                .await
        }
    }
}

fn should_try_next_fork(resp: &Response, pending: Option<&PendingForward>) -> bool {
    resp.status.class() >= 3
        && pending
            .as_ref()
            .is_some_and(|p| !p.remaining_targets.is_empty())
}

async fn forward_next_fork(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    pending: PendingForward,
) -> anyhow::Result<bool> {
    let Some(original_request) = pending.original_request.clone() else {
        return Ok(false);
    };
    for (index, target_uri) in pending.remaining_targets.iter().enumerate() {
        let Some(target) = resolve_udp_target(target_uri).await else {
            continue;
        };
        let remaining = pending
            .remaining_targets
            .iter()
            .skip(index + 1)
            .cloned()
            .collect();
        forward_invite_request(
            socket,
            sip_sender,
            forward_table,
            transaction_table,
            pending.client_addr,
            original_request.clone(),
            target_uri.clone(),
            target,
            Some(original_request),
            remaining,
            &cfg.advertise,
            cfg.sip_port,
            &[],
            pending.reply_ws_conn_id.clone(),
        )
        .await?;
        return Ok(true);
    }
    Ok(false)
}

fn response_top_via(resp: &Response) -> Option<&Via> {
    resp.headers.iter().find_map(|header| match header {
        Header::Via(via) => Some(via),
        _ => None,
    })
}

fn via_matches_proxy(via: &Via, advertise: &str, sip_port: u16) -> bool {
    via.host == advertise && via.port.unwrap_or(5060) == sip_port
}

fn response_relay_addr(via: &Via) -> Option<SocketAddr> {
    let host = via.received.as_deref().unwrap_or(&via.host);
    let port = match via.rport {
        sipora_sip::types::header::RportParam::Filled(port) => port,
        _ => via.port.unwrap_or(5060),
    };
    format!("{host}:{port}").parse().ok()
}

#[allow(clippy::too_many_arguments)]
async fn handle_dialog_request(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    mut req: Request,
) -> anyhow::Result<()> {
    let Some((dialog_key, state)) = dialog_for_request(dialog_table, &req).await else {
        if req.method != Method::Ack {
            crate::ingress::respond(
                ingress,
                &sip_response(&req, StatusCode::CALL_DOES_NOT_EXIST),
            )
            .await;
        }
        return Ok(());
    };
    tracing::trace!(
        cseq = state.cseq,
        caller = %state.caller_addr,
        callee = %state.callee_addr,
        session_expires = ?state.session_expires,
        "routing in-dialog request"
    );
    let target_uri = dialog_target_uri(ingress, &mut req, &state, cfg);
    let Some(target) = resolve_udp_target(&target_uri).await else {
        crate::ingress::respond(ingress, &overload_response(&req, 30)).await;
        return Ok(());
    };
    let method = req.method.clone();
    let refer_meta = if method == Method::Refer {
        refer_state_from_request(&req)
    } else {
        None
    };
    forward_dialog_request(
        ingress.socket.as_ref(),
        forward_table,
        transaction_table,
        ingress.source,
        req,
        target_uri,
        target,
        cfg,
    )
    .await?;
    if let Some(st) = refer_meta {
        let cid = st.referrer_call_id.clone();
        if let Err(e) = crate::refer_state::save_refer_state(redis, &cid, &st).await {
            tracing::warn!(%e, "refer state save");
        }
    }
    if method == Method::Bye {
        let cid = dialog_key.call_id.clone();
        cancel_session_guard(refresh_table, &dialog_key).await;
        let _ = crate::refer_state::delete_refer_state(redis, &cid).await;
        remove_dialog(dialog_table, &dialog_key);
    }
    Ok(())
}

fn ingress_source_is_caller(ingress: &ProxyIngress, state: &DialogState) -> bool {
    match &ingress.reply {
        ReplyTarget::Ws { connection_id, .. } => {
            state.caller_reply_ws.as_deref() == Some(connection_id.as_str())
        }
        _ => ingress.source == state.caller_addr,
    }
}

fn dialog_target_uri(
    ingress: &ProxyIngress,
    req: &mut Request,
    state: &DialogState,
    cfg: &UdpProxyConfig,
) -> String {
    let toward_callee = !ingress_source_is_caller(ingress, state);
    let own_route = format!("sip:{}:{}", cfg.advertise, cfg.sip_port);
    strip_own_route(&mut req.headers, &own_route);
    let target = if toward_callee {
        next_route_uri(&req.headers)
            .or_else(|| state.route_set.first().cloned())
            .unwrap_or_else(|| state.remote_target.clone())
    } else {
        next_route_uri(&req.headers)
            .or_else(|| state.caller_route_set.first().cloned())
            .unwrap_or_else(|| {
                state
                    .caller_remote_target
                    .clone()
                    .unwrap_or_else(|| state.from_party.uri.clone())
            })
    };
    strip_name_addr(&target).to_string()
}

fn strip_own_route(headers: &mut Vec<Header>, own_route: &str) {
    let Some(index) = headers.iter().position(|h| matches!(h, Header::Route(_))) else {
        return;
    };
    let Header::Route(routes) = &mut headers[index] else {
        return;
    };
    if routes
        .first()
        .is_some_and(|route| route.contains(own_route))
    {
        routes.remove(0);
    }
    if routes.is_empty() {
        headers.remove(index);
    }
}

fn next_route_uri(headers: &[Header]) -> Option<String> {
    headers.iter().find_map(|header| match header {
        Header::Route(routes) => routes.first().cloned(),
        _ => None,
    })
}

fn strip_name_addr(uri: &str) -> &str {
    uri.trim().trim_start_matches('<').trim_end_matches('>')
}

fn build_dialog_bye_for_uri(
    state: &DialogState,
    key: &DialogKey,
    request_uri: &str,
    route_set: &[String],
) -> Request {
    let mut headers = Vec::new();
    if !route_set.is_empty() {
        headers.push(Header::Route(route_set.to_vec()));
    }
    headers.push(Header::From(state.from_party.clone()));
    headers.push(Header::To(state.to_party.clone()));
    headers.push(Header::CallId(key.call_id.clone()));
    let bye_seq = state.cseq.saturating_add(1);
    headers.push(Header::CSeq(CSeq {
        seq: bye_seq,
        method: Method::Bye,
    }));
    headers.push(Header::MaxForwards(70));
    headers.push(Header::ContentLength(0));
    Request {
        method: Method::Bye,
        uri: request_uri.to_string(),
        version: SipVersion::V2_0,
        headers,
        body: Vec::new(),
    }
}

async fn send_session_expired_teardown(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    cfg: &UdpProxyConfig,
    state: &DialogState,
    key: &DialogKey,
) -> anyhow::Result<()> {
    let callee_uri = strip_name_addr(&state.remote_target).to_string();
    let caller_uri = strip_name_addr(
        state
            .caller_remote_target
            .as_deref()
            .unwrap_or(state.from_party.uri.as_str()),
    )
    .to_string();
    let mut bye_callee = build_dialog_bye_for_uri(state, key, &callee_uri, &state.route_set);
    let _ = prepend_proxy_via(&mut bye_callee, &cfg.advertise, cfg.sip_port);
    let b_callee = serialize_message(&SipMessage::Request(bye_callee));
    socket.send_to(&b_callee, state.callee_addr).await?;

    let caller_routes = state.caller_route_set.as_slice();
    let mut bye_caller = build_dialog_bye_for_uri(state, key, &caller_uri, caller_routes);
    let _ = prepend_proxy_via(&mut bye_caller, &cfg.advertise, cfg.sip_port);
    match &state.caller_reply_ws {
        Some(conn_id) => {
            sip_sender
                .send_sip(
                    &MessageTarget::Ws {
                        connection_id: conn_id.clone(),
                    },
                    SipMessage::Request(bye_caller),
                )
                .await?;
        }
        None => {
            let b = serialize_message(&SipMessage::Request(bye_caller));
            socket.send_to(&b, state.caller_addr).await?;
        }
    }
    Ok(())
}

async fn handle_session_expired(
    key: DialogKey,
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
) -> anyhow::Result<()> {
    let Some(state) = dialog_table.get(&key) else {
        return Ok(());
    };
    cancel_session_guard(refresh_table, &key).await;
    let send_res = send_session_expired_teardown(socket, sip_sender, cfg, &state, &key).await;
    let cid = key.call_id.clone();
    let _ = crate::refer_state::delete_refer_state(redis, &cid).await;
    remove_dialog(dialog_table, &key);
    send_res
}

fn dialog_key_from_replaces_header(req: &Request) -> Option<DialogKey> {
    req.headers.iter().find_map(|h| match h {
        Header::Replaces {
            call_id,
            from_tag,
            to_tag,
        } => Some(DialogKey {
            call_id: call_id.clone(),
            from_tag: from_tag.clone(),
            to_tag: to_tag.clone(),
        }),
        _ => None,
    })
}

fn invite_callee_aor_for_replaces(cfg: &UdpProxyConfig, req: &Request) -> (String, String) {
    let uri = req.uri.trim();
    if let Some((u, d)) = parse_sip_user_host(uri) {
        (u, normalize_domain(d, &cfg.domain))
    } else {
        (String::new(), String::new())
    }
}

fn refer_state_from_request(req: &Request) -> Option<crate::refer_state::ReferState> {
    let cid = req.call_id()?.to_string();
    let refer_to = req.headers.iter().find_map(|h| match h {
        Header::ReferTo(v) => Some(v.clone()),
        _ => None,
    })?;
    let cseq = req.cseq().map(|c| c.seq).unwrap_or(0);
    Some(crate::refer_state::ReferState {
        referrer_call_id: cid,
        referee_contact: refer_to,
        event_id: Uuid::new_v4().simple().to_string(),
        cseq,
        version: 1,
    })
}

fn notify_is_refer_terminated(req: &Request) -> bool {
    let refer_pkg = req.headers.iter().find_map(|h| match h {
        Header::Event(ev) => Some(ev.as_str()),
        _ => None,
    });
    let Some(ev) = refer_pkg else {
        return false;
    };
    let ev_lc = ev.to_ascii_lowercase();
    if !ev_lc.starts_with("refer") {
        return false;
    }
    req.headers.iter().any(|h| match h {
        Header::SubscriptionState { state, .. } => {
            matches!(*state, SubscriptionStateValue::Terminated)
        }
        _ => false,
    })
}

fn notify_event_package_is_refer(req: &Request) -> bool {
    let Some(ev) = req.headers.iter().find_map(|h| match h {
        Header::Event(e) => Some(e.as_str()),
        _ => None,
    }) else {
        return false;
    };
    ev.to_ascii_lowercase().starts_with("refer")
}

pub(crate) fn notify_refer_event_id_from_header(ev: &str) -> Option<String> {
    for part in ev.split(';').skip(1) {
        let p = part.trim();
        let mut sp = p.splitn(2, '=');
        let k = sp.next()?.trim();
        let v = sp.next()?.trim();
        if k.eq_ignore_ascii_case("id") {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

fn notify_refer_event_matches_state(req: &Request, st: &crate::refer_state::ReferState) -> bool {
    let Some(ev) = req.headers.iter().find_map(|h| match h {
        Header::Event(e) => Some(e.as_str()),
        _ => None,
    }) else {
        return true;
    };
    match notify_refer_event_id_from_header(ev) {
        Some(id) => id == st.event_id,
        None => true,
    }
}

fn notify_has_sipfrag_content_type(req: &Request) -> bool {
    req.headers.iter().any(|h| match h {
        Header::ContentType(ct) => ct.to_ascii_lowercase().contains("message/sipfrag"),
        _ => false,
    })
}

async fn correlate_refer_notify_with_redis(redis: &RedisPool, call_id: &str, req: &Request) {
    match crate::refer_state::load_refer_state(redis, call_id).await {
        Ok(Some(st)) => {
            if !notify_refer_event_matches_state(req, &st) {
                tracing::warn!(
                    call_id = %call_id,
                    expected_event_id = %st.event_id,
                    "NOTIFY refer Event id mismatch vs ReferState"
                );
            }
            if notify_has_sipfrag_content_type(req) && !req.body.is_empty() {
                tracing::trace!(call_id = %call_id, sipfrag_bytes = req.body.len(), "refer NOTIFY sipfrag");
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(%e, call_id = %call_id, "refer state load"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_dialog_request(
    socket: &tokio::net::UdpSocket,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    peer: SocketAddr,
    mut req: Request,
    target_uri: String,
    target: SocketAddr,
    cfg: &UdpProxyConfig,
) -> anyhow::Result<()> {
    req.uri = target_uri;
    let branch = prepend_proxy_via(&mut req, &cfg.advertise, cfg.sip_port);
    if req.method != Method::Ack {
        track_client_transaction(transaction_table, &req, TransactionType::ClientNonInvite).await;
        let vias = collect_via_stack(&req.headers);
        insert_forward(
            forward_table,
            branch,
            peer,
            None,
            target,
            vias,
            None,
            vec![],
            req.uri.clone(),
        )
        .await;
    }
    let bytes = serialize_message(&SipMessage::Request(req));
    socket.send_to(&bytes, target).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_invite(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    pool: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    req: Request,
) -> anyhow::Result<()> {
    let Some(req) = prepare_invite_ingress(ingress, cfg, req).await? else {
        return Ok(());
    };
    if reject_invite_for_max_forwards(ingress, router, &req).await {
        return Ok(());
    }
    if let Some(rep_key) = dialog_key_from_replaces_header(&req)
        && let Some(state) = dialog_table.get(&rep_key)
    {
        let target_uri = strip_name_addr(&state.remote_target).to_string();
        if let Some(target) = resolve_udp_target(&target_uri).await {
            let (callee_user, callee_domain) = invite_callee_aor_for_replaces(cfg, &req);
            let route = InitialInviteRoute {
                target_uri,
                target,
                remaining_targets: vec![],
                path: state.route_set.clone(),
                push_contact: None,
                callee_user,
                callee_domain,
            };
            return forward_initial_invite(
                ingress,
                sip_sender,
                Some(pool),
                forward_table,
                transaction_table,
                fork_table,
                cfg,
                req,
                route,
            )
            .await;
        }
    }
    let Some((contacts, callee_user, callee_domain)) =
        lookup_invite_contacts(ingress, pool, cfg, &req).await?
    else {
        return Ok(());
    };
    let Some(route) =
        select_invite_route(ingress, &req, contacts, callee_user, callee_domain).await
    else {
        return Ok(());
    };

    forward_initial_invite(
        ingress,
        sip_sender,
        Some(pool),
        forward_table,
        transaction_table,
        fork_table,
        cfg,
        req,
        route,
    )
    .await
}

async fn prepare_invite_ingress(
    ingress: &ProxyIngress,
    cfg: &UdpProxyConfig,
    req: Request,
) -> anyhow::Result<Option<Request>> {
    // RFC 3261 §17.2.1: send 100 Trying immediately on INVITE receipt
    crate::ingress::respond(ingress, &sip_response(&req, StatusCode::TRYING)).await;

    let mut req = req;
    // RFC 3325 §9.1: strip P-AI/P-PI from untrusted ingress before routing.
    let trusted = is_trusted_peer(ingress.source, &cfg.stir);
    strip_untrusted_identity_headers(&mut req, trusted);
    // RFC 8224: verify or require STIR Identity header per configured policy.
    if let Some(reject_code) = check_stir_identity(&mut req, &cfg.stir).await {
        crate::ingress::respond(ingress, &sip_response(&req, reject_code)).await;
        return Ok(None);
    }

    // RFC 4028 §8: reject if Session-Expires is below proxy minimum
    if check_session_expires(&req).is_some() {
        crate::ingress::respond(ingress, &sip_response_with_min_se(&req, PROXY_MIN_SE)).await;
        return Ok(None);
    }
    Ok(Some(req))
}

async fn reject_invite_for_max_forwards(
    ingress: &ProxyIngress,
    router: &ProxyRouter,
    req: &Request,
) -> bool {
    if router.check_max_forwards(req).is_none() {
        return false;
    }
    crate::ingress::respond(
        ingress,
        &SipMessage::Response(ProxyRouter::too_many_hops_response(req)),
    )
    .await;
    true
}

async fn lookup_invite_contacts(
    ingress: &ProxyIngress,
    pool: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
) -> anyhow::Result<Option<(Vec<ContactBinding>, String, String)>> {
    let uri = req.uri.trim();
    let (user, dom) = if uri.to_ascii_lowercase().starts_with("tel:") {
        let digits: String = uri.chars().filter(|c| c.is_ascii_digit()).collect();
        let Some(sip_uri) = enum_resolve_tel_to_sip(&digits).await else {
            crate::ingress::respond(
                ingress,
                &SipMessage::Response(ProxyRouter::not_found_response(req)),
            )
            .await;
            return Ok(None);
        };
        let Some((u, d)) = parse_sip_user_host(&sip_uri) else {
            crate::ingress::respond(ingress, &sip_response(req, StatusCode::BAD_REQUEST)).await;
            return Ok(None);
        };
        (u, normalize_domain(d, &cfg.domain))
    } else if let Some(tok) = gruu::gr_token_from_uri(uri) {
        let Some((_, d_raw)) = parse_sip_user_host(uri) else {
            crate::ingress::respond(
                ingress,
                &SipMessage::Response(ProxyRouter::not_found_response(req)),
            )
            .await;
            return Ok(None);
        };
        let dom = normalize_domain(d_raw, &cfg.domain);
        match lookup_user_for_pub_gruu(pool, &dom, tok).await {
            Ok(Some(real_user)) => (real_user, dom),
            Ok(None) => {
                crate::ingress::respond(
                    ingress,
                    &SipMessage::Response(ProxyRouter::not_found_response(req)),
                )
                .await;
                return Ok(None);
            }
            Err(e) => {
                tracing::warn!(%e, "pub-gruu lookup");
                crate::ingress::respond(
                    ingress,
                    &SipMessage::Response(ProxyRouter::service_unavailable(req, 30)),
                )
                .await;
                return Ok(None);
            }
        }
    } else if let Some((u, d)) = parse_sip_user_host(uri) {
        (u, normalize_domain(d, &cfg.domain))
    } else {
        crate::ingress::respond(
            ingress,
            &SipMessage::Response(ProxyRouter::not_found_response(req)),
        )
        .await;
        return Ok(None);
    };

    let contacts = match list_contact_uris(pool, &dom, &user).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "location lookup");
            crate::ingress::respond(
                ingress,
                &SipMessage::Response(ProxyRouter::service_unavailable(req, 30)),
            )
            .await;
            return Ok(None);
        }
    };
    if contacts.is_empty() {
        crate::ingress::respond(
            ingress,
            &SipMessage::Response(ProxyRouter::not_found_response(req)),
        )
        .await;
        return Ok(None);
    }
    Ok(Some((contacts, user, dom)))
}

async fn select_invite_route(
    ingress: &ProxyIngress,
    req: &Request,
    contacts: Vec<ContactBinding>,
    callee_user: String,
    callee_domain: String,
) -> Option<InitialInviteRoute> {
    match select_initial_invite_target(req, contacts, callee_user, callee_domain).await {
        InitialInviteTarget::Selected(route) => Some(route),
        InitialInviteTarget::Downgrade(status) => {
            crate::ingress::respond(ingress, &sip_response(req, status)).await;
            None
        }
        InitialInviteTarget::Unusable => {
            crate::ingress::respond(
                ingress,
                &SipMessage::Response(ProxyRouter::service_unavailable(req, 30)),
            )
            .await;
            None
        }
    }
}

async fn maybe_push_wake_for_idle_contact(
    ingress: &ProxyIngress,
    pool: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
    contact: &ContactBinding,
    callee_user: &str,
    callee_domain: &str,
) {
    let Some(url) = cfg.push_gateway_url.as_deref() else {
        return;
    };
    if contact.pn_provider.as_deref().unwrap_or("").is_empty()
        && contact.pn_prid.as_deref().unwrap_or("").is_empty()
    {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let idle = contact
        .last_register_unix
        .map(|t| now.saturating_sub(t) > cfg.push_device_idle_secs)
        .unwrap_or(true);
    if !idle {
        return;
    }
    let Some(cid) = req.call_id() else {
        return;
    };
    let invite_bytes = serialize_message(&SipMessage::Request(req.clone()));
    let reply = crate::push::pending_reply_from_ingress(ingress);
    if let Err(e) = crate::push::stash_pending_invite(
        pool,
        cid,
        &invite_bytes,
        &reply,
        callee_domain,
        callee_user,
    )
    .await
    {
        tracing::warn!(%e, "push stash invite");
    }
    let timeout = Duration::from_millis(cfg.push_timeout_ms.max(1));
    if let Err(e) = crate::push::wake_device(
        &cfg.http_client,
        url,
        timeout,
        cfg.push_auth_bearer.as_deref(),
        contact,
        cid,
    )
    .await
    {
        tracing::warn!(%e, "push wake_device");
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_initial_invite(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    pool: Option<&RedisPool>,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    cfg: &UdpProxyConfig,
    req: Request,
    route: InitialInviteRoute,
) -> anyhow::Result<()> {
    if let (Some(pool), Some(c)) = (pool, route.push_contact.as_ref()) {
        maybe_push_wake_for_idle_contact(
            ingress,
            pool,
            cfg,
            &req,
            c,
            &route.callee_user,
            &route.callee_domain,
        )
        .await;
    }
    if !cfg.fork_parallel {
        let original_request = req.clone();
        forward_invite_request(
            &ingress.socket,
            sip_sender,
            forward_table,
            transaction_table,
            ingress.source,
            req,
            route.target_uri,
            route.target,
            Some(original_request),
            route.remaining_targets,
            &cfg.advertise,
            cfg.sip_port,
            &route.path,
            None,
        )
        .await?;
        return Ok(());
    }

    forward_parallel_initial_invite(
        ingress,
        sip_sender,
        forward_table,
        transaction_table,
        fork_table,
        cfg,
        req,
        route,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward_parallel_initial_invite(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    cfg: &UdpProxyConfig,
    req: Request,
    route: InitialInviteRoute,
) -> anyhow::Result<()> {
    let call_id = req.call_id().map(str::to_owned);
    let original_request = req.clone();
    let mut branches = Vec::new();
    let first_branch = forward_invite_request(
        &ingress.socket,
        sip_sender,
        forward_table,
        transaction_table,
        ingress.source,
        req,
        route.target_uri,
        route.target,
        Some(original_request.clone()),
        vec![],
        &cfg.advertise,
        cfg.sip_port,
        &route.path,
        None,
    )
    .await?;
    branches.push(first_branch);

    for target_uri in route.remaining_targets {
        if let Some(target) = resolve_udp_target(&target_uri).await {
            let branch = forward_invite_request(
                &ingress.socket,
                sip_sender,
                forward_table,
                transaction_table,
                ingress.source,
                original_request.clone(),
                target_uri,
                target,
                Some(original_request.clone()),
                vec![],
                &cfg.advertise,
                cfg.sip_port,
                &[],
                None,
            )
            .await?;
            branches.push(branch);
        }
    }
    if let Some(call_id) = call_id {
        record_fork_branches(fork_table, &call_id, branches).await;
    }
    Ok(())
}

pub async fn record_fork_branches<S>(fork_table: &ForkTable, call_id: &str, branches: Vec<S>)
where
    S: Into<String>,
{
    let branches = branches.into_iter().map(Into::into).collect();
    let state = CallForkState {
        branches,
        ..CallForkState::default()
    };
    fork_table.write().await.insert(call_id.to_string(), state);
}

#[allow(clippy::large_enum_variant)]
enum InitialInviteTarget {
    Selected(InitialInviteRoute),
    Downgrade(StatusCode),
    Unusable,
}

struct InitialInviteRoute {
    target_uri: String,
    target: SocketAddr,
    remaining_targets: Vec<String>,
    /// Outbound Path (RFC 3327) as Route headers toward the UA.
    path: Vec<String>,
    /// First contact chosen for INVITE (push wake when idle).
    push_contact: Option<ContactBinding>,
    callee_user: String,
    callee_domain: String,
}

async fn select_initial_invite_target(
    req: &Request,
    mut contacts: Vec<ContactBinding>,
    callee_user: String,
    callee_domain: String,
) -> InitialInviteTarget {
    contacts.sort_by(|a, b| {
        b.q_value
            .partial_cmp(&a.q_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (index, contact) in contacts.iter().enumerate() {
        if let Some(status) = sips_downgrade_status(req, &contact.uri) {
            return InitialInviteTarget::Downgrade(status);
        }
        let Some(target) = resolve_udp_target(&contact.uri).await else {
            continue;
        };
        let remaining_targets = contacts
            .iter()
            .skip(index + 1)
            .map(|c| c.uri.clone())
            .collect();
        return InitialInviteTarget::Selected(InitialInviteRoute {
            target_uri: contact.uri.clone(),
            target,
            remaining_targets,
            path: contact.path.clone(),
            push_contact: Some(contact.clone()),
            callee_user,
            callee_domain,
        });
    }

    InitialInviteTarget::Unusable
}

#[allow(clippy::too_many_arguments)]
async fn forward_invite_request(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    peer: SocketAddr,
    mut req: Request,
    target_uri: String,
    target: SocketAddr,
    original_request: Option<Request>,
    remaining_targets: Vec<String>,
    advertise: &str,
    sip_port: u16,
    path_route: &[String],
    reply_ws_conn_id: Option<String>,
) -> anyhow::Result<String> {
    req.uri = target_uri;
    let branch = format!("z9hG4bK{}", Uuid::new_v4().as_simple());
    let original_via_stack = insert_forwarding_headers(&mut req, &branch, advertise, sip_port);
    if !path_route.is_empty() {
        req.headers.insert(1, Header::Route(path_route.to_vec()));
    }
    let tx_key = TransactionKey::from_request(&req);

    insert_forward(
        forward_table,
        branch.clone(),
        peer,
        reply_ws_conn_id,
        target,
        original_via_stack,
        original_request,
        remaining_targets,
        req.uri.clone(),
    )
    .await;

    let bytes = serialize_message(&SipMessage::Request(req));
    socket.send_to(&bytes, target).await?;
    let timer = if let Some(ref k) = tx_key {
        spawn_invite_retransmit_timer(
            Arc::clone(socket),
            Arc::clone(sip_sender),
            Arc::clone(forward_table),
            Arc::clone(transaction_table),
            branch.clone(),
            k.clone(),
            bytes,
            target,
        )
    } else {
        tokio::spawn(async {})
    };
    track_invite_client_transaction(transaction_table, tx_key, timer).await;
    Ok(branch)
}

fn insert_forwarding_headers(
    req: &mut Request,
    branch: &str,
    advertise: &str,
    sip_port: u16,
) -> Vec<Via> {
    let original_via_stack = collect_via_stack(&req.headers);
    let record_route = Header::RecordRoute(vec![format!("<sip:{advertise}:{sip_port};lr>")]);
    let mut headers = vec![proxy_via(branch, advertise, sip_port), record_route];
    headers.append(&mut req.headers);
    req.headers = headers;
    ProxyRouter::decrement_max_forwards(&mut req.headers);
    original_via_stack
}

fn proxy_via(branch: &str, advertise: &str, sip_port: u16) -> Header {
    Header::Via(Via {
        transport: Transport::Udp,
        host: advertise.to_string(),
        port: Some(sip_port),
        branch: branch.to_string(),
        received: None,
        rport: sipora_sip::types::header::RportParam::Absent,
        params: vec![],
    })
}

async fn send_invite_timeout_response_to_client(
    socket: &Arc<tokio::net::UdpSocket>,
    sip_sender: &Arc<dyn MessageSender>,
    pending: &PendingForward,
    resp: Response,
) -> anyhow::Result<()> {
    let mut target = if let Some(ref id) = pending.reply_ws_conn_id {
        ResponseTarget::Ws {
            connection_id: id.clone(),
        }
    } else {
        ResponseTarget::Udp(pending.client_addr)
    };
    if let Some(via) = response_top_via(&resp) {
        target = match target {
            ResponseTarget::Udp(a) => ResponseTarget::Udp(response_relay_addr(via).unwrap_or(a)),
            w @ ResponseTarget::Ws { .. } => w,
        };
    }
    send_response_target(socket, sip_sender, resp, target).await
}

async fn finish_invite_client_timer_b(
    socket: Arc<tokio::net::UdpSocket>,
    sip_sender: Arc<dyn MessageSender>,
    forward_table: ForwardTable,
    transaction_table: TransactionTable,
    branch: String,
    tx_key: TransactionKey,
) {
    let pending = remove_pending_branch(&forward_table, &branch).await;
    transaction_table.write().await.remove_quiet(&tx_key);
    let Some(pending) = pending else {
        return;
    };
    let Some(orig) = pending.original_request.as_ref() else {
        return;
    };
    let SipMessage::Response(resp) = sip_response(orig, StatusCode::REQUEST_TIMEOUT) else {
        return;
    };
    if let Err(e) =
        send_invite_timeout_response_to_client(&socket, &sip_sender, &pending, resp).await
    {
        tracing::warn!(branch = %branch, "INVITE Timer B: send 408 to client failed: {e}");
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_invite_retransmit_timer(
    socket: Arc<tokio::net::UdpSocket>,
    sip_sender: Arc<dyn MessageSender>,
    forward_table: ForwardTable,
    transaction_table: TransactionTable,
    branch: String,
    tx_key: TransactionKey,
    bytes: Vec<u8>,
    target: SocketAddr,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let deadline = Instant::now() + INVITE_CLIENT_TIMER_B;
        let mut delay = sipora_sip::transaction::TIMER_T1;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let sleep_for = delay.min(deadline.saturating_duration_since(now));
            tokio::time::sleep(sleep_for).await;
            if Instant::now() >= deadline {
                break;
            }
            if socket.send_to(&bytes, target).await.is_err() {
                transaction_table.write().await.remove_quiet(&tx_key);
                return;
            }
            delay = (delay * 2).min(sipora_sip::transaction::TIMER_T2);
        }
        finish_invite_client_timer_b(
            socket,
            sip_sender,
            forward_table,
            transaction_table,
            branch,
            tx_key,
        )
        .await;
    })
}

async fn track_invite_client_transaction(
    table: &TransactionTable,
    key: Option<TransactionKey>,
    timer: tokio::task::JoinHandle<()>,
) {
    if let Some(key) = key {
        table.write().await.insert_with_timer(
            key,
            TransactionType::ClientInvite,
            timer.abort_handle(),
        );
    } else {
        timer.abort();
    }
}

fn prepend_proxy_via(req: &mut Request, advertise: &str, sip_port: u16) -> String {
    let branch = format!("z9hG4bK{}", Uuid::new_v4().as_simple());
    let via = Header::Via(Via {
        transport: Transport::Udp,
        host: advertise.to_string(),
        port: Some(sip_port),
        branch: branch.clone(),
        received: None,
        rport: sipora_sip::types::header::RportParam::Absent,
        params: vec![],
    });
    req.headers.insert(0, via);
    ProxyRouter::decrement_max_forwards(&mut req.headers);
    branch
}

fn collect_via_stack(headers: &[Header]) -> Vec<Via> {
    headers
        .iter()
        .filter_map(|header| match header {
            Header::Via(via) => Some(via.clone()),
            _ => None,
        })
        .collect()
}

fn normalize_domain(dom: String, fallback: &str) -> String {
    if dom.is_empty() {
        fallback.to_string()
    } else {
        dom
    }
}

/// RFC 5630 §4: reject sips: URIs arriving over UDP with 403 Forbidden.
fn enforce_sips_policy(req: &Request, ingress: Transport) -> Option<StatusCode> {
    if is_sips_uri(&req.uri) && ingress == Transport::Udp {
        Some(StatusCode::FORBIDDEN)
    } else {
        None
    }
}

fn sips_downgrade_status(req: &Request, target_uri: &str) -> Option<StatusCode> {
    if is_sips_uri(&req.uri) && is_sip_uri(target_uri) {
        Some(StatusCode::TEMPORARILY_UNAVAILABLE)
    } else {
        None
    }
}

fn is_sips_uri(uri: &str) -> bool {
    has_uri_scheme(uri, "sips")
}

fn is_sip_uri(uri: &str) -> bool {
    has_uri_scheme(uri, "sip")
}

fn has_uri_scheme(uri: &str, scheme: &str) -> bool {
    let uri = strip_name_addr(uri);
    uri.split_once(':')
        .is_some_and(|(actual, _)| actual.eq_ignore_ascii_case(scheme))
}

/// RFC 4028 §8: if the request carries Session-Expires below PROXY_MIN_SE, return 422.
fn check_session_expires(req: &Request) -> Option<StatusCode> {
    req.headers.iter().find_map(|h| match h {
        Header::SessionExpires { delta_seconds, .. } if *delta_seconds < PROXY_MIN_SE => {
            Some(StatusCode::SESSION_INTERVAL_TOO_SMALL)
        }
        _ => None,
    })
}

/// RFC 3262 §3: route PRACK by `RAck` + Call-ID when possible, else Call-ID only.
async fn handle_prack(
    ingress: &ProxyIngress,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    mut req: Request,
) -> anyhow::Result<()> {
    let Some(call_id) = req.call_id() else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let branch = match prack_rack_tuple(&req) {
        Some((rseq, cseq)) => {
            match find_branch_by_call_id_and_rseq(forward_table, call_id, rseq, cseq).await {
                Some(b) => Some(b),
                None => find_branch_by_call_id(forward_table, call_id).await,
            }
        }
        None => find_branch_by_call_id(forward_table, call_id).await,
    };
    let Some(branch) = branch else {
        crate::ingress::respond(
            ingress,
            &sip_response(&req, StatusCode::CALL_DOES_NOT_EXIST),
        )
        .await;
        return Ok(());
    };
    if let Some(tuple) = prack_rack_tuple(&req) {
        let mut table = forward_table.write().await;
        let Some(pending) = table.get_mut(&branch) else {
            crate::ingress::respond(
                ingress,
                &sip_response(&req, StatusCode::CALL_DOES_NOT_EXIST),
            )
            .await;
            return Ok(());
        };
        if pending.last_prack_rack == Some(tuple) {
            return Ok(());
        }
        pending.last_prack_rack = Some(tuple);
    }
    let target_addr = {
        let table = forward_table.read().await;
        table.get(&branch).map(|p| p.target_addr)
    };
    let Some(target) = target_addr else {
        crate::ingress::respond(
            ingress,
            &sip_response(&req, StatusCode::CALL_DOES_NOT_EXIST),
        )
        .await;
        return Ok(());
    };
    if let Some(i) = req.headers.iter().position(
        |h| matches!(h, Header::Via(v) if via_matches_proxy(v, &cfg.advertise, cfg.sip_port)),
    ) {
        req.headers.remove(i);
    }
    prepend_proxy_via(&mut req, &cfg.advertise, cfg.sip_port);
    let bytes = serialize_message(&SipMessage::Request(req));
    ingress.socket.send_to(&bytes, target).await?;
    Ok(())
}

fn prack_rack_tuple(req: &Request) -> Option<(u32, u32)> {
    req.headers.iter().find_map(|h| match h {
        Header::RAck { rseq, cseq, .. } => Some((*rseq, *cseq)),
        _ => None,
    })
}

async fn handle_cancel(
    ingress: &ProxyIngress,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    req: Request,
) -> anyhow::Result<()> {
    // RFC 3261 §16.10: respond 200 OK immediately, then forward CANCEL downstream.
    crate::ingress::respond(ingress, &sip_response(&req, StatusCode::OK)).await;
    let Some(call_id) = req.call_id() else {
        return Ok(());
    };
    let branches = find_branches_by_call_id(forward_table, call_id).await;
    if branches.is_empty() {
        return Ok(());
    }
    for branch in branches {
        let pending_info = {
            let table = forward_table.read().await;
            table
                .get(&branch)
                .map(|p| (p.target_addr, p.forwarded_uri.clone()))
        };
        let Some((target_addr, forwarded_uri)) = pending_info else {
            continue;
        };
        // Forward CANCEL toward the callee. Keep the ForwardTable entry so the
        // 487 response the callee sends back is relayed to the caller normally.
        let cancel = build_cancel_request(&req, &branch, &forwarded_uri, cfg);
        track_client_transaction(transaction_table, &cancel, TransactionType::ClientNonInvite)
            .await;
        let bytes = serialize_message(&SipMessage::Request(cancel));
        ingress.socket.send_to(&bytes, target_addr).await?;
    }
    Ok(())
}

fn build_cancel_request(
    req: &Request,
    proxy_branch: &str,
    forwarded_uri: &str,
    cfg: &UdpProxyConfig,
) -> Request {
    use sipora_sip::types::header::CSeq;
    // RFC 3261 §9.1: CANCEL must copy From, To, Call-ID and CSeq-number (method → CANCEL).
    // Top Via must match the Via inserted for the forwarded INVITE (same branch).
    let mut headers = vec![Header::Via(Via {
        transport: Transport::Udp,
        host: cfg.advertise.clone(),
        port: Some(cfg.sip_port),
        branch: proxy_branch.to_string(),
        received: None,
        rport: sipora_sip::types::header::RportParam::Absent,
        params: vec![],
    })];
    for h in &req.headers {
        match h {
            Header::From(_) | Header::To(_) | Header::CallId(_) | Header::Route(_) => {
                headers.push(h.clone())
            }
            Header::CSeq(cseq) => headers.push(Header::CSeq(CSeq {
                seq: cseq.seq,
                method: Method::Cancel,
            })),
            _ => {}
        }
    }
    headers.push(Header::MaxForwards(70));
    headers.push(Header::ContentLength(0));
    Request {
        method: Method::Cancel,
        uri: forwarded_uri.to_string(),
        version: SipVersion::V2_0,
        headers,
        body: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn message_send_digest_challenge_with_algorithms(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
    realm: &str,
    stale: bool,
    algorithms: &[DigestAlgorithm],
) -> anyhow::Result<()> {
    let mut stored_nonces = Vec::new();
    let mut challenges = Vec::new();
    for algorithm in algorithms {
        let nonce = Uuid::new_v4().simple().to_string();
        if let Err(e) = register::store_register_nonce(redis, &nonce, cfg.nonce_ttl_s).await {
            register::rollback_register_challenge_nonces(redis, &stored_nonces).await;
            tracing::warn!(%e, "message nonce store");
            crate::ingress::respond(
                ingress,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
        challenges.push(register::register_challenge_header(
            *algorithm, realm, &nonce, stale,
        ));
        stored_nonces.push(nonce);
    }
    crate::ingress::respond(ingress, &sip_response_multi_proxy_auth(req, &challenges)).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn message_send_digest_challenge(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
    user: &str,
    realm: &str,
    stale: bool,
) -> anyhow::Result<()> {
    let credentials = match get_user_sip_digest_credentials(&cfg.pg, user, realm).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "message db");
            crate::ingress::respond(
                ingress,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
    };
    let algorithms = register::register_challenge_algorithms(credentials.as_ref());
    message_send_digest_challenge_with_algorithms(
        ingress,
        redis,
        cfg,
        req,
        realm,
        stale,
        &algorithms,
    )
    .await
}

// ── STIR/SHAKEN helpers (RFC 8224) ──────────────────────────────────────────

fn is_trusted_peer(peer: SocketAddr, cfg: &StirConfig) -> bool {
    cfg.trusted_peer_ips.contains(&peer.ip())
}

/// RFC 3325 §9.1: strip P-Asserted-Identity and P-Preferred-Identity headers
/// that arrived from untrusted network elements.
fn strip_untrusted_identity_headers(req: &mut Request, trusted: bool) {
    if !trusted {
        req.headers.retain(|h| {
            !matches!(
                h,
                Header::PAssertedIdentity(_) | Header::PPreferredIdentity(_)
            )
        });
    }
}

/// Verify the STIR Identity header on an INVITE and apply the configured policy.
///
/// In `Permissive` mode: invalid Identity headers are stripped from `req` so
/// the downstream UA does not receive unverifiable attestation claims; the call
/// proceeds regardless.
///
/// In `Strict` mode: absent or invalid Identity causes rejection with the
/// appropriate RFC 8224 §5 status code.
///
/// Returns `Some(status)` if the request must be rejected, `None` to continue.
async fn check_stir_identity(req: &mut Request, cfg: &StirConfig) -> Option<StatusCode> {
    if cfg.mode == StirMode::Disabled {
        return None;
    }

    let identity = req.headers.iter().find_map(|h| match h {
        Header::Identity(v) => Some(v.clone()),
        _ => None,
    });

    let identity_val = match identity {
        None => {
            return if cfg.mode == StirMode::Strict {
                Some(StatusCode::USE_IDENTITY_HEADER)
            } else {
                None
            };
        }
        Some(v) => v,
    };

    match verify_identity_header(
        &identity_val,
        &cfg.cert_cache,
        cfg.trust_anchor_pem.as_deref(),
    )
    .await
    {
        Ok(result) => {
            tracing::debug!(
                attest = ?result.attest,
                orig_tn = %result.orig_tn,
                cert_url = %result.cert_url,
                "STIR PASSporT verified"
            );
            None
        }
        Err(e) => {
            let code = match &e {
                StirError::CertFetch(_) | StirError::CertParse(_) | StirError::ChainInvalid(_) => {
                    StatusCode::BAD_IDENTITY_INFO
                }
                _ => StatusCode::INVALID_IDENTITY_HEADER,
            };
            tracing::warn!(%e, "STIR verification failed");
            if cfg.mode == StirMode::Strict {
                Some(code)
            } else {
                // Permissive: strip the unverifiable Identity header before forwarding.
                req.headers.retain(|h| !matches!(h, Header::Identity(_)));
                None
            }
        }
    }
}

fn header_content_type(req: &Request) -> Option<String> {
    req.headers.iter().find_map(|h| match h {
        Header::ContentType(c) => Some(c.clone()),
        _ => None,
    })
}

fn header_sip_if_match(req: &Request) -> Option<String> {
    req.headers.iter().find_map(|h| match h {
        Header::SipIfMatch(s) => Some(s.clone()),
        _ => None,
    })
}

fn header_event_package(req: &Request) -> String {
    req.headers
        .iter()
        .find_map(|h| match h {
            Header::Event(e) => Some(e.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "presence".to_string())
}

fn collect_route_set(req: &Request) -> Vec<String> {
    req.headers
        .iter()
        .flat_map(|h| match h {
            Header::Route(routes) => routes.clone(),
            _ => Vec::new(),
        })
        .collect()
}

fn message_proxy_authorization_value(req: &Request) -> Option<&str> {
    req.headers.iter().find_map(|h| match h {
        Header::ProxyAuthorization(v) => Some(v.as_str()),
        _ => None,
    })
}

async fn message_forward_to_bindings(
    sip_sender: &Arc<dyn MessageSender>,
    cfg: &UdpProxyConfig,
    req: &Request,
    bindings: &[ContactBinding],
) {
    for b in bindings {
        let mut fwd = req.clone();
        fwd.uri = b.uri.clone();
        prepend_proxy_via(&mut fwd, &cfg.advertise, cfg.sip_port);
        if !b.path.is_empty() {
            fwd.headers.insert(1, Header::Route(b.path.clone()));
        }
        let msg = SipMessage::Request(fwd);
        match crate::notify::resolve_message_target(&b.uri).await {
            Ok(t) => {
                if let Err(e) = sip_sender.send_sip(&t, msg).await {
                    tracing::warn!(%e, uri = %b.uri, "MESSAGE forward");
                }
            }
            Err(e) => tracing::warn!(%e, uri = %b.uri, "MESSAGE resolve target"),
        }
    }
}

async fn subscribe_notify_body(
    redis: &RedisPool,
    dom: &str,
    user: &str,
    event_pkg: &str,
) -> anyhow::Result<(Vec<u8>, String)> {
    let base = event_pkg.split(';').next().unwrap_or(event_pkg).trim();
    match base {
        "reg" => {
            let bindings = list_contact_uris(redis, dom, user)
                .await
                .unwrap_or_default();
            let aor = format!("sip:{user}@{dom}");
            let xml = reginfo_xml(&aor, &bindings, 1);
            Ok((xml.into_bytes(), "application/reginfo+xml".into()))
        }
        "presence" => match load_presence(redis, dom, user).await {
            Ok(Some(d)) => Ok((presence_body_from_doc(&d.body), d.content_type)),
            Ok(None) => Ok((Vec::new(), "application/pidf+xml".into())),
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
        },
        _ => Ok((Vec::new(), String::new())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_subscribe_initial_notify(
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    dom: &str,
    user: &str,
    sub: &Subscription,
    event_pkg: &str,
    expires: u32,
) -> anyhow::Result<()> {
    let ttl = expires.saturating_add(300).max(600) as i64;
    let cseq = next_notify_cseq(redis, &sub.call_id, ttl)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let (body, ct) = subscribe_notify_body(redis, dom, user, event_pkg).await?;
    let notify_req = build_notify_request(
        sub,
        &body,
        &ct,
        SubscriptionStateValue::Active,
        Some(expires),
        None,
        event_pkg,
        cseq,
        &cfg.advertise,
        cfg.sip_port,
    );
    dispatch_notify(sip_sender.as_ref(), &sub.contact, notify_req).await
}

#[allow(clippy::too_many_arguments)]
async fn publish_notify_subscribers(
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    dom: &str,
    user: &str,
    body: &[u8],
    ct: &str,
    expires: u32,
) -> anyhow::Result<()> {
    let subs = list_subscriptions_for_aor(redis, dom, user, "presence")
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let ttl = expires.saturating_add(300).max(600) as i64;
    for sub in subs {
        let cseq = match next_notify_cseq(redis, &sub.call_id, ttl).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(%e, "publish notify cseq");
                continue;
            }
        };
        let hdr = sub.event_package.as_str();
        let notify_req = build_notify_request(
            &sub,
            body,
            ct,
            SubscriptionStateValue::Active,
            Some(expires),
            None,
            hdr,
            cseq,
            &cfg.advertise,
            cfg.sip_port,
        );
        if let Err(e) = dispatch_notify(sip_sender.as_ref(), &sub.contact, notify_req).await {
            tracing::warn!(%e, sub_id = %sub.id, "publish fan-out notify");
            if let Err(del_e) = delete_subscription(redis, dom, user, "presence", &sub.id).await {
                tracing::warn!(%del_e, "purge subscription after notify failure");
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: Request,
) -> anyhow::Result<()> {
    let max_body = 1300usize.min(cfg.max_message_bytes);
    if req.body.len() > max_body {
        crate::ingress::respond(
            ingress,
            &sip_response(&req, StatusCode::REQUEST_ENTITY_TOO_LARGE),
        )
        .await;
        return Ok(());
    }
    let to_uri = req.to_header().map(|t| t.uri.clone());
    let parsed = parse_sip_user_host(&req.uri)
        .or_else(|| to_uri.as_ref().and_then(|u| parse_sip_user_host(u)));
    let Some((user, dom_raw)) = parsed else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let dom = normalize_domain(dom_raw, &cfg.domain);
    let auth_raw = message_proxy_authorization_value(&req);
    if auth_raw.is_none() {
        return message_send_digest_challenge(ingress, redis, cfg, &req, &user, &dom, false).await;
    }
    let Some(dr) = DigestResponse::parse(auth_raw.unwrap()) else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    if !dr.username.eq_ignore_ascii_case(&user) || !dr.realm.eq_ignore_ascii_case(&dom) {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::FORBIDDEN)).await;
        return Ok(());
    }
    match register::register_nonce_exists(redis, &dr.nonce).await {
        Ok(false) => {
            return message_send_digest_challenge(ingress, redis, cfg, &req, &user, &dom, true)
                .await;
        }
        Ok(true) => {}
        Err(e) => {
            tracing::warn!(%e, "message redis nonce exists");
            crate::ingress::respond(ingress, &overload_response(&req, 30)).await;
            return Ok(());
        }
    }
    if !register::register_digest_verified(ingress, redis, cfg, &req, &dom, &dr, "MESSAGE").await? {
        return Ok(());
    }
    if !register::register_enforce_digest_nc(ingress, redis, cfg, &req, &dr).await? {
        return Ok(());
    }
    let bindings = match list_contact_uris(redis, &dom, &user).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(%e, "message location");
            crate::ingress::respond(
                ingress,
                &sip_response(&req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
    };
    if bindings.is_empty() {
        crate::ingress::respond(
            ingress,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    }
    crate::ingress::respond(ingress, &sip_response(&req, StatusCode::ACCEPTED)).await;
    message_forward_to_bindings(sip_sender, cfg, &req, &bindings).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_notify(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    req: Request,
) -> anyhow::Result<()> {
    if dialog_for_request(dialog_table, &req).await.is_some() {
        if notify_event_package_is_refer(&req)
            && let Some(cid) = req.call_id()
        {
            correlate_refer_notify_with_redis(redis, cid, &req).await;
        }
        if notify_is_refer_terminated(&req)
            && let Some(cid) = req.call_id()
        {
            let _ = crate::refer_state::delete_refer_state(redis, cid).await;
        }
        return handle_dialog_request(
            ingress,
            redis,
            cfg,
            forward_table,
            transaction_table,
            dialog_table,
            refresh_table,
            req,
        )
        .await;
    }
    crate::ingress::respond(ingress, &sip_response(&req, StatusCode::OK)).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_publish(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: Request,
) -> anyhow::Result<()> {
    let Some(to) = req.to_header() else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let Some((user, dom_raw)) = parse_sip_user_host(&to.uri) else {
        crate::ingress::respond(
            ingress,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    };
    let dom = normalize_domain(dom_raw, &cfg.domain);
    let exp = req.expires().unwrap_or(3600).clamp(60, 86400);
    let ct = header_content_type(&req).unwrap_or_else(|| "application/pidf+xml".to_string());
    let if_match = header_sip_if_match(&req);
    match publish_presence(
        redis,
        &dom,
        &user,
        Some(req.body.as_slice()),
        ct.as_str(),
        if_match.as_deref(),
        exp,
    )
    .await
    {
        Ok(etag) => {
            let body = req.body.clone();
            crate::ingress::respond(ingress, &sip_ok_sip_etag(&req, etag)).await;
            if let Err(e) = publish_notify_subscribers(
                sip_sender,
                redis,
                cfg,
                &dom,
                &user,
                &body,
                ct.as_str(),
                exp,
            )
            .await
            {
                tracing::warn!(%e, "publish subscriber notify");
            }
        }
        Err(PresenceError::EtagMismatch) | Err(PresenceError::NotFound) => {
            crate::ingress::respond(
                ingress,
                &sip_response(&req, StatusCode::PRECONDITION_FAILED),
            )
            .await;
        }
        Err(PresenceError::Redis(e)) => {
            tracing::warn!(%e, "publish presence");
            crate::ingress::respond(
                ingress,
                &sip_response(&req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_subscribe(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: Request,
) -> anyhow::Result<()> {
    let Some(to) = req.to_header() else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let Some((user, dom_raw)) = parse_sip_user_host(&to.uri) else {
        crate::ingress::respond(
            ingress,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    };
    let dom = normalize_domain(dom_raw, &cfg.domain);
    let Some(call_id) = req.call_id() else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let Some(from_na) = req.headers.iter().find_map(|h| match h {
        Header::From(na) => Some(na.clone()),
        _ => None,
    }) else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let contact_uri = req
        .contacts()
        .first()
        .map(|c| c.uri.clone())
        .unwrap_or_default();
    let event_pkg = header_event_package(&req);
    let expires = req.expires().unwrap_or(3600).clamp(60, 86400);
    let sub = Subscription {
        id: Uuid::new_v4().simple().to_string(),
        aor: format!("{user}@{dom}"),
        subscriber_uri: from_na.uri.clone(),
        event_package: event_pkg.clone(),
        call_id: call_id.to_string(),
        from_tag: from_na.tag.unwrap_or_default(),
        to_tag: String::new(),
        expires,
        state: "active".to_string(),
        contact: contact_uri,
        route_set: collect_route_set(&req),
    };
    match save_subscription(redis, &dom, &user, &sub).await {
        Ok(()) => {}
        Err(e) => {
            tracing::warn!(%e, "subscribe save");
            crate::ingress::respond(
                ingress,
                &sip_response(&req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
    }
    crate::ingress::respond(
        ingress,
        &sip_response_expires(&req, StatusCode::OK, expires),
    )
    .await;
    if let Err(e) = dispatch_subscribe_initial_notify(
        sip_sender, redis, cfg, &dom, &user, &sub, &event_pkg, expires,
    )
    .await
    {
        tracing::warn!(%e, "subscribe initial notify");
    }
    Ok(())
}

/// Returns user and host part of `sip:user@host` or `sip:user@host:5060` (no angle brackets).
fn parse_sip_user_host(uri: &str) -> Option<(String, String)> {
    let u = uri.trim();
    let (scheme, u) = u.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("sip") && !scheme.eq_ignore_ascii_case("sips") {
        return None;
    }
    let u = u.split(';').next()?.split('?').next()?;
    if u.is_empty() {
        return None;
    }

    let (user, rest) = match u.find('@') {
        Some(at) => (&u[..at], &u[at + 1..]),
        None => ("", u),
    };
    if rest.is_empty() {
        return None;
    }

    Some((user.to_string(), rest.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContactTarget {
    host: String,
    port: Option<u16>,
    transport: SipTransport,
}

async fn resolve_udp_target(contact_uri: &str) -> Option<SocketAddr> {
    let target = parse_contact_target(contact_uri)?;
    if target.transport != SipTransport::Udp {
        return None;
    }
    resolve_sip_targets(&target.host, target.port, SipTransport::Udp)
        .await
        .into_iter()
        .next()
        .map(|target| target.addr)
}

fn parse_contact_target(contact_uri: &str) -> Option<ContactTarget> {
    let uri = strip_name_addr(contact_uri);
    let (_, hostport) = parse_sip_user_host(uri)?;
    let (host, port) = split_host_port_optional(&hostport)?;
    Some(ContactTarget {
        host,
        port,
        transport: contact_transport(uri)?,
    })
}

/// Host and port from a SIP/SIPS Contact URI (for NOTIFY resolution).
pub(crate) fn contact_host_port(contact_uri: &str) -> Option<(String, Option<u16>)> {
    let uri = strip_name_addr(contact_uri);
    let (_, hostport) = parse_sip_user_host(uri)?;
    split_host_port_optional(&hostport)
}

fn contact_transport(uri: &str) -> Option<SipTransport> {
    if is_sips_uri(uri) {
        return Some(SipTransport::Tls);
    }

    match uri_transport_param(uri) {
        Some(value) if value.eq_ignore_ascii_case("udp") => Some(SipTransport::Udp),
        Some(value) if value.eq_ignore_ascii_case("tcp") => Some(SipTransport::Tcp),
        Some(value) if value.eq_ignore_ascii_case("tls") => Some(SipTransport::Tls),
        Some(_) => None,
        None => Some(SipTransport::Udp),
    }
}

fn uri_transport_param(uri: &str) -> Option<&str> {
    uri.split('?')
        .next()?
        .split(';')
        .skip(1)
        .find_map(transport_param_value)
}

fn transport_param_value(param: &str) -> Option<&str> {
    let (name, value) = param.split_once('=')?;
    name.eq_ignore_ascii_case("transport").then_some(value)
}

fn split_host_port_optional(rest: &str) -> Option<(String, Option<u16>)> {
    if let Some(stripped) = rest.strip_prefix('[') {
        return split_ipv6_host_port(stripped);
    }

    match rest.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => Some((host.to_string(), Some(port))),
            Err(_) => Some((rest.to_string(), None)),
        },
        None => Some((rest.to_string(), None)),
    }
}

fn split_ipv6_host_port(rest: &str) -> Option<(String, Option<u16>)> {
    let bracket_end = rest.find(']')?;
    let host = &rest[..bracket_end];
    let after_bracket = &rest[bracket_end + 1..];
    let port = match after_bracket.strip_prefix(':') {
        Some(port) => Some(port.parse::<u16>().ok()?),
        None if after_bracket.is_empty() => None,
        None => return None,
    };
    Some((host.to_string(), port))
}

#[cfg(test)]
fn split_host_port(rest: &str) -> Option<(String, u16)> {
    if let Some(stripped) = rest.strip_prefix('[') {
        let bracket_end = stripped.find(']')?;
        let host = &stripped[..bracket_end];
        let after_bracket = &stripped[bracket_end + 1..];
        let port = match after_bracket.strip_prefix(':') {
            Some(port) => port.parse::<u16>().ok()?,
            None if after_bracket.is_empty() => 5060,
            None => return None,
        };
        return Some((host.to_string(), port));
    }

    match rest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => Some((h.to_string(), port)),
            Err(_) => Some((rest.to_string(), 5060)),
        },
        None => Some((rest.to_string(), 5060)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_table::{PendingForward, new_forward_table};
    use crate::message_sender::UdpSender;
    use sipora_sip::types::header::{CSeq, NameAddr, RportParam};
    use sqlx::postgres::PgPoolOptions;
    use std::time::Instant;

    fn test_sip_sender(sock: &Arc<tokio::net::UdpSocket>) -> Arc<dyn MessageSender> {
        Arc::new(UdpSender::new(sock.clone()))
    }

    fn test_session_tx() -> mpsc::Sender<DialogKey> {
        let (tx, _rx) = mpsc::channel::<DialogKey>(8);
        tx
    }

    #[test]
    fn parse_sip_user_host_accepts_ipv6_literal_without_user() {
        let parsed = parse_sip_user_host("sip:[2001:db8::1]:5070");

        assert_eq!(
            parsed,
            Some(("".to_string(), "[2001:db8::1]:5070".to_string()))
        );
    }

    #[test]
    fn refer_notify_event_id_parsing() {
        assert_eq!(
            notify_refer_event_id_from_header("refer;id=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(notify_refer_event_id_from_header("refer").as_deref(), None);
    }

    #[test]
    fn parse_sip_user_host_accepts_sips_with_parameters() {
        let parsed = parse_sip_user_host("sips:alice@example.com;transport=tls");

        assert_eq!(
            parsed,
            Some(("alice".to_string(), "example.com".to_string()))
        );
    }

    #[test]
    fn sips_policy_rejects_udp_ingress() {
        let mut req = invite_request();
        req.uri = "sips:bob@example.com".to_string();

        assert_eq!(
            enforce_sips_policy(&req, Transport::Udp),
            Some(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn sips_policy_allows_tls_ingress() {
        let mut req = invite_request();
        req.uri = "sips:bob@example.com".to_string();

        assert_eq!(enforce_sips_policy(&req, Transport::Tls), None);
    }

    #[test]
    fn sips_downgrade_to_sip_contact_is_unavailable() {
        let mut req = invite_request();
        req.uri = "sips:bob@example.com".to_string();

        assert_eq!(
            sips_downgrade_status(&req, "sip:bob@target.example.com"),
            Some(StatusCode::TEMPORARILY_UNAVAILABLE)
        );
    }

    #[test]
    fn sips_target_contact_is_not_a_downgrade() {
        let mut req = invite_request();
        req.uri = "sips:bob@example.com".to_string();

        assert_eq!(
            sips_downgrade_status(&req, "sips:bob@target.example.com"),
            None
        );
    }

    #[test]
    fn contact_target_uses_tls_for_sips_scheme() {
        let target = parse_contact_target("sips:bob@example.com").unwrap();

        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, None);
        assert_eq!(target.transport, SipTransport::Tls);
    }

    #[test]
    fn contact_target_uses_tls_transport_parameter() {
        let target = parse_contact_target("sip:bob@example.com;transport=tls").unwrap();

        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, None);
        assert_eq!(target.transport, SipTransport::Tls);
    }

    #[test]
    fn contact_target_uses_tcp_transport_parameter() {
        let target = parse_contact_target("sip:bob@example.com:5070;transport=tcp").unwrap();

        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, Some(5070));
        assert_eq!(target.transport, SipTransport::Tcp);
    }

    #[tokio::test]
    async fn udp_target_rejects_sips_contact_with_udp_transport_param() {
        let target = resolve_udp_target("sips:bob@127.0.0.1;transport=udp").await;

        assert_eq!(target, None);
    }

    #[test]
    fn parse_sip_user_host_accepts_uppercase_sips_scheme() {
        let parsed = parse_sip_user_host("SIPS:alice@example.com;transport=tls");

        assert_eq!(
            parsed,
            Some(("alice".to_string(), "example.com".to_string()))
        );
    }

    #[test]
    fn contact_target_rejects_unsupported_transport_parameter() {
        assert!(parse_contact_target("sip:bob@example.com;transport=sctp").is_none());
        assert!(parse_contact_target("sip:bob@example.com;transport=typo").is_none());
    }

    #[tokio::test]
    async fn udp_target_rejects_sips_contact() {
        let target = resolve_udp_target("sips:bob@127.0.0.1").await;

        assert_eq!(target, None);
    }

    #[tokio::test]
    async fn udp_target_rejects_tls_transport_contact() {
        let target = resolve_udp_target("sip:bob@127.0.0.1;transport=tls").await;

        assert_eq!(target, None);
    }

    #[tokio::test]
    async fn udp_target_rejects_tcp_transport_contact() {
        let target = resolve_udp_target("sip:bob@127.0.0.1:5070;transport=tcp").await;

        assert_eq!(target, None);
    }

    #[tokio::test]
    async fn udp_target_rejects_unsupported_transport_contact() {
        let target = resolve_udp_target("sip:bob@127.0.0.1;transport=ws").await;

        assert_eq!(target, None);
    }

    #[test]
    fn split_host_port_strips_ipv6_brackets_with_port() {
        let parsed = split_host_port("[2001:db8::1]:5070");

        assert_eq!(parsed, Some(("2001:db8::1".to_string(), 5070)));
    }

    #[test]
    fn split_host_port_strips_ipv6_brackets_without_port() {
        let parsed = split_host_port("[2001:db8::1]");

        assert_eq!(parsed, Some(("2001:db8::1".to_string(), 5060)));
    }

    #[test]
    fn apply_rfc3581_fills_received_and_requested_rport() {
        let peer = "127.0.0.1:5090".parse().unwrap();
        let mut req = invite_request();
        let Header::Via(via) = &mut req.headers[0] else {
            panic!("first header should be Via");
        };
        via.host = "10.0.0.10".to_string();
        via.rport = RportParam::Requested;

        apply_rfc3581(&mut req, peer);

        let via = req.via()[0];
        assert_eq!(via.received.as_deref(), Some("127.0.0.1"));
        assert_eq!(via.rport, RportParam::Filled(5090));
    }

    #[test]
    fn response_relay_addr_prefers_received_and_rport() {
        let mut req = invite_request();
        let Header::Via(via) = &mut req.headers[0] else {
            panic!("first header should be Via");
        };
        via.received = Some("127.0.0.1".to_string());
        via.rport = RportParam::Filled(5091);

        assert_eq!(
            response_relay_addr(via),
            Some("127.0.0.1:5091".parse().unwrap())
        );
    }

    #[test]
    fn register_digest_credential_selection_uses_md5_for_md5_algorithms() {
        let credentials = sipora_data::pg::SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: Some("sha256-ha1".to_string()),
        };

        assert_eq!(
            register::select_register_stored_ha1(
                &credentials,
                sipora_auth::digest::DigestAlgorithm::Md5,
            ),
            Some("md5-ha1")
        );
        assert_eq!(
            register::select_register_stored_ha1(
                &credentials,
                sipora_auth::digest::DigestAlgorithm::Md5Sess,
            ),
            Some("md5-ha1")
        );
    }

    #[test]
    fn register_digest_credential_selection_uses_sha256_for_sha256_algorithms() {
        let credentials = sipora_data::pg::SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: Some("sha256-ha1".to_string()),
        };

        assert_eq!(
            register::select_register_stored_ha1(
                &credentials,
                sipora_auth::digest::DigestAlgorithm::Sha256,
            ),
            Some("sha256-ha1")
        );
        assert_eq!(
            register::select_register_stored_ha1(
                &credentials,
                sipora_auth::digest::DigestAlgorithm::Sha256Sess,
            ),
            Some("sha256-ha1")
        );
    }

    #[test]
    fn register_challenge_algorithms_keep_dual_challenge_when_sha256_exists() {
        let credentials = sipora_data::pg::SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: Some("sha256-ha1".to_string()),
        };

        assert_eq!(
            register::register_challenge_algorithms(Some(&credentials)),
            vec![DigestAlgorithm::Sha256, DigestAlgorithm::Md5]
        );
    }

    #[test]
    fn register_challenge_algorithms_use_md5_only_for_md5_only_user() {
        let credentials = sipora_data::pg::SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: None,
        };

        assert_eq!(
            register::register_challenge_algorithms(Some(&credentials)),
            vec![DigestAlgorithm::Md5]
        );
    }

    #[test]
    fn sha256_attempt_for_md5_only_user_rechallenges_with_md5() {
        let credentials = sipora_data::pg::SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: None,
        };

        assert!(register::should_rechallenge_md5_only(
            Some(&credentials),
            DigestAlgorithm::Sha256
        ));
        assert!(!register::should_rechallenge_md5_only(
            Some(&credentials),
            DigestAlgorithm::Md5
        ));
    }

    #[tokio::test]
    async fn initial_invite_target_selects_later_udp_send_eligible_contact() {
        let contacts = vec![
            ContactBinding {
                uri: "sip:bob@127.0.0.1;transport=tcp".to_string(),
                q_value: 1.0,
                expires: 300,
                ..Default::default()
            },
            ContactBinding {
                uri: "sip:bob@127.0.0.1:5097".to_string(),
                q_value: 0.5,
                expires: 300,
                ..Default::default()
            },
        ];

        let selected = select_initial_invite_target(
            &invite_request(),
            contacts,
            "bob".into(),
            "example.com".into(),
        )
        .await;

        let InitialInviteTarget::Selected(route) = selected else {
            panic!("expected later UDP contact to be selected");
        };
        assert_eq!(route.target_uri, "sip:bob@127.0.0.1:5097");
        assert_eq!(route.target, "127.0.0.1:5097".parse().unwrap());
    }

    #[tokio::test]
    async fn initial_invite_target_reports_sips_downgrade_before_udp_filtering() {
        let mut req = invite_request();
        req.uri = "sips:bob@example.com".to_string();
        let contacts = vec![ContactBinding {
            uri: "sip:bob@127.0.0.1;transport=tcp".to_string(),
            q_value: 1.0,
            expires: 300,
            ..Default::default()
        }];

        let selected =
            select_initial_invite_target(&req, contacts, "bob".into(), "example.com".into()).await;

        let InitialInviteTarget::Downgrade(status) = selected else {
            panic!("expected downgrade to be reported before UDP filtering");
        };
        assert_eq!(status, StatusCode::TEMPORARILY_UNAVAILABLE);
    }

    #[tokio::test]
    async fn forward_invite_inserts_pending_forward() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let peer = "127.0.0.1:5090".parse().unwrap();
        let table = new_forward_table();
        let transaction_table = new_transaction_table();

        let sip = test_sip_sender(&socket);
        forward_invite_request(
            &socket,
            &sip,
            &table,
            &transaction_table,
            peer,
            invite_request(),
            "sip:bob@127.0.0.1:5091".to_string(),
            target_addr,
            Some(invite_request()),
            vec![],
            "proxy.example.com",
            5060,
            &[],
            None,
        )
        .await
        .unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _) = target.recv_from(&mut buf).await.unwrap();
        let (_, msg) = parse_sip_message(&buf[..n]).unwrap();
        let SipMessage::Request(forwarded) = msg else {
            panic!("forwarded INVITE must remain a request");
        };
        let branch = forwarded.via()[0].branch.clone();
        let forwards = table.read().await;
        assert_eq!(forwards[&branch].client_addr, peer);
        assert_eq!(forwards[&branch].original_via_stack.len(), 1);
        assert!(forwarded.headers.iter().any(|header| {
            matches!(header, Header::RecordRoute(routes) if routes[0].contains(";lr"))
        }));
    }

    #[tokio::test]
    async fn forward_invite_inserts_path_route_after_top_via() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let peer = "127.0.0.1:5090".parse().unwrap();
        let table = new_forward_table();
        let transaction_table = new_transaction_table();
        let path = vec!["<sip:edge.example.com;lr>".to_string()];

        let sip = test_sip_sender(&socket);
        forward_invite_request(
            &socket,
            &sip,
            &table,
            &transaction_table,
            peer,
            invite_request(),
            "sip:bob@127.0.0.1:5091".to_string(),
            target_addr,
            Some(invite_request()),
            vec![],
            "proxy.example.com",
            5060,
            &path,
            None,
        )
        .await
        .unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _) = target.recv_from(&mut buf).await.unwrap();
        let (_, msg) = parse_sip_message(&buf[..n]).unwrap();
        let SipMessage::Request(forwarded) = msg else {
            panic!("expected request");
        };
        assert!(matches!(&forwarded.headers[0], Header::Via(_)));
        assert!(matches!(&forwarded.headers[1], Header::Route(r) if r == &path));
    }

    #[tokio::test]
    async fn invite_timer_b_sends_408_and_clears_pending() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client.local_addr().unwrap();
        let table = new_forward_table();
        let transaction_table = new_transaction_table();
        let sip = test_sip_sender(&socket);
        let orig = invite_request();

        forward_invite_request(
            &socket,
            &sip,
            &table,
            &transaction_table,
            peer,
            orig.clone(),
            format!("sip:bob@{target_addr}"),
            target_addr,
            Some(orig),
            vec![],
            "proxy.example.com",
            5060,
            &[],
            None,
        )
        .await
        .unwrap();

        let mut buf = vec![0u8; 8192];
        let (n, _) = target.recv_from(&mut buf).await.unwrap();
        parse_sip_message(&buf[..n]).unwrap();

        let recv =
            tokio::time::timeout(Duration::from_millis(600), client.recv_from(&mut buf)).await;
        let (n, _) = recv.expect("timeout waiting for 408").expect("recv 408");
        let msg = parse_sip_message(&buf[..n]).unwrap().1;
        let SipMessage::Response(resp) = msg else {
            panic!("expected response");
        };
        assert_eq!(resp.status, StatusCode::REQUEST_TIMEOUT);
        assert!(table.read().await.is_empty());
        assert!(transaction_table.read().await.is_empty());
    }

    #[tokio::test]
    async fn session_expired_teardown_sends_bye_to_both_udp_ends() {
        let caller = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cfg = test_cfg();
        let sip = test_sip_sender(&proxy);
        let state = crate::dialog::DialogState {
            route_set: vec![],
            remote_target: "sip:bob@callee".to_string(),
            from_party: NameAddr {
                display_name: None,
                uri: "sip:alice@example.com".to_string(),
                tag: Some("from-tag".to_string()),
                params: vec![],
            },
            to_party: NameAddr {
                display_name: None,
                uri: "sip:bob@example.com".to_string(),
                tag: Some("to-tag".to_string()),
                params: vec![],
            },
            cseq: 1,
            caller_addr: caller.local_addr().unwrap(),
            callee_addr: callee.local_addr().unwrap(),
            caller_reply_ws: None,
            caller_remote_target: None,
            caller_route_set: vec![],
            session_expires: Some(30),
            session_refresher: None,
        };
        let key = DialogKey {
            call_id: "call-1".into(),
            from_tag: "from-tag".into(),
            to_tag: "to-tag".into(),
        };
        send_session_expired_teardown(&proxy, &sip, &cfg, &state, &key)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), callee.recv_from(&mut buf))
            .await
            .expect("timeout waiting for BYE to callee")
            .unwrap();
        let callee_msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), caller.recv_from(&mut buf))
            .await
            .expect("timeout waiting for BYE to caller")
            .unwrap();
        let caller_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(callee_msg.contains("BYE sip:bob@callee"));
        assert!(callee_msg.contains("CSeq: 2 BYE"));
        assert!(caller_msg.contains("BYE sip:alice@example.com"));
        assert!(caller_msg.contains("Call-ID: call-1"));
    }

    #[tokio::test]
    async fn forward_next_fork_sends_invite_to_remaining_target() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let table = new_forward_table();
        let cfg = test_cfg();
        let pending = PendingForward {
            client_addr: "127.0.0.1:5090".parse().unwrap(),
            reply_ws_conn_id: None,
            target_addr,
            original_via_stack: vec![],
            original_request: Some(invite_request()),
            remaining_targets: vec![format!("sip:bob@{target_addr}")],
            forwarded_uri: format!("sip:bob@{target_addr}"),
            final_forwarded: false,
            inserted_at: Instant::now(),
            last_reliable_rseq: None,
            last_prack_rack: None,
        };

        let transaction_table = new_transaction_table();
        let sip = test_sip_sender(&socket);
        forward_next_fork(&socket, &sip, &cfg, &table, &transaction_table, pending)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _) = target.recv_from(&mut buf).await.unwrap();
        let (_, msg) = parse_sip_message(&buf[..n]).unwrap();
        assert!(matches!(msg, SipMessage::Request(_)));
        assert_eq!(table.read().await.len(), 1);
    }

    #[tokio::test]
    async fn parallel_initial_invite_forwards_all_remaining_targets() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        let table = new_forward_table();
        let transaction_table = new_transaction_table();
        let fork_table = new_fork_table();

        let cfg = test_cfg();
        let peer: SocketAddr = "127.0.0.1:5090".parse().unwrap();
        let ingress = ProxyIngress::udp(socket.clone(), peer);
        let sip = test_sip_sender(&socket);
        forward_initial_invite(
            &ingress,
            &sip,
            None,
            &table,
            &transaction_table,
            &fork_table,
            &cfg,
            invite_request(),
            InitialInviteRoute {
                target_uri: format!("sip:bob@{first_addr}"),
                target: first_addr,
                remaining_targets: vec![format!("sip:bob@{second_addr}")],
                path: vec![],
                push_contact: None,
                callee_user: String::new(),
                callee_domain: String::new(),
            },
        )
        .await
        .unwrap();

        let first_req = recv_request(&first).await;
        let second_req = recv_request(&second).await;
        assert_eq!(first_req.method, Method::Invite);
        assert_eq!(second_req.method, Method::Invite);
        assert_eq!(table.read().await.len(), 2);
    }

    #[tokio::test]
    async fn serial_initial_invite_keeps_remaining_targets_deferred() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        let table = new_forward_table();
        let transaction_table = new_transaction_table();
        let fork_table = new_fork_table();

        let mut cfg = test_cfg();
        cfg.fork_parallel = false;
        let peer: SocketAddr = "127.0.0.1:5090".parse().unwrap();
        let ingress = ProxyIngress::udp(socket.clone(), peer);
        let sip = test_sip_sender(&socket);
        forward_initial_invite(
            &ingress,
            &sip,
            None,
            &table,
            &transaction_table,
            &fork_table,
            &cfg,
            invite_request(),
            InitialInviteRoute {
                target_uri: format!("sip:bob@{first_addr}"),
                target: first_addr,
                remaining_targets: vec![format!("sip:bob@{second_addr}")],
                path: vec![],
                push_contact: None,
                callee_user: String::new(),
                callee_domain: String::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(recv_request(&first).await.method, Method::Invite);
        assert_no_datagram(&second).await;
        let pending = table.read().await.values().next().unwrap().clone();
        assert_eq!(
            pending.remaining_targets,
            vec![format!("sip:bob@{second_addr}")]
        );
    }

    #[tokio::test]
    async fn global_failure_cancels_parallel_sibling_branch() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sibling = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let sibling_addr = sibling.local_addr().unwrap();
        let table = new_forward_table();
        let fork_table = new_fork_table();
        let cfg = test_cfg();

        insert_test_forward(&table, "z9hG4bK-a", client_addr, sibling_addr).await;
        insert_test_forward(&table, "z9hG4bK-b", client_addr, sibling_addr).await;
        record_fork_branches(&fork_table, "call-1", vec!["z9hG4bK-a", "z9hG4bK-b"]).await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-a", StatusCode(603)),
        )
        .await
        .unwrap();

        let cancel = recv_request(&sibling).await;
        assert_eq!(cancel.method, Method::Cancel);
        assert_eq!(recv_response(&client).await.status, StatusCode(603));
    }

    #[tokio::test]
    async fn parallel_failures_are_deferred_until_all_branches_complete() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let table = new_forward_table();
        let fork_table = new_fork_table();
        let cfg = test_cfg();

        insert_test_forward(&table, "z9hG4bK-a", client_addr, client_addr).await;
        insert_test_forward(&table, "z9hG4bK-b", client_addr, client_addr).await;
        record_fork_branches(&fork_table, "call-1", vec!["z9hG4bK-a", "z9hG4bK-b"]).await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-a", StatusCode::NOT_FOUND),
        )
        .await
        .unwrap();
        assert_no_datagram(&client).await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-b", StatusCode::SERVICE_UNAVAILABLE),
        )
        .await
        .unwrap();

        assert_eq!(
            recv_response(&client).await.status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(!fork_table.read().await.contains_key("call-1"));
    }

    #[tokio::test]
    async fn parallel_success_relays_later_success_from_sibling() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let table = new_forward_table();
        let fork_table = new_fork_table();
        let cfg = test_cfg();

        insert_test_forward(&table, "z9hG4bK-a", client_addr, client_addr).await;
        insert_test_forward(&table, "z9hG4bK-b", client_addr, client_addr).await;
        record_fork_branches(&fork_table, "call-1", vec!["z9hG4bK-a", "z9hG4bK-b"]).await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-a", StatusCode::OK),
        )
        .await
        .unwrap();
        assert_eq!(recv_response(&client).await.status, StatusCode::OK);

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-b", StatusCode::OK),
        )
        .await
        .unwrap();

        assert_eq!(recv_response(&client).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn cancel_success_response_is_consumed_hop_by_hop() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let table = new_forward_table();
        let cfg = test_cfg();

        insert_test_forward(&table, "z9hG4bK-cancel", client_addr, client_addr).await;
        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &new_fork_table(),
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response_for_method("z9hG4bK-cancel", StatusCode::OK, Method::Cancel),
        )
        .await
        .unwrap();

        assert_no_datagram(&client).await;
    }

    #[tokio::test]
    async fn parallel_global_failure_after_success_is_absorbed() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let table = new_forward_table();
        let fork_table = new_fork_table();
        let cfg = test_cfg();

        insert_test_forward(&table, "z9hG4bK-a", client_addr, client_addr).await;
        insert_test_forward(&table, "z9hG4bK-b", client_addr, client_addr).await;
        record_fork_branches(&fork_table, "call-1", vec!["z9hG4bK-a", "z9hG4bK-b"]).await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-a", StatusCode::OK),
        )
        .await
        .unwrap();
        assert_eq!(recv_response(&client).await.status, StatusCode::OK);

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-b", StatusCode(603)),
        )
        .await
        .unwrap();

        assert_no_datagram(&client).await;
        assert!(!fork_table.read().await.contains_key("call-1"));
    }

    #[tokio::test]
    async fn fork_cleanup_removes_states_without_live_forward_branches() {
        let table = new_forward_table();
        let fork_table = new_fork_table();
        record_fork_branches(&fork_table, "call-1", vec!["z9hG4bK-a", "z9hG4bK-b"]).await;

        cleanup_stale_fork_states(&fork_table, &table).await;

        assert!(!fork_table.read().await.contains_key("call-1"));
    }

    #[tokio::test]
    async fn fork_state_is_removed_after_success_and_all_siblings_complete() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let table = new_forward_table();
        let fork_table = new_fork_table();
        let cfg = test_cfg();

        insert_test_forward(&table, "z9hG4bK-a", client_addr, client_addr).await;
        insert_test_forward(&table, "z9hG4bK-b", client_addr, client_addr).await;
        record_fork_branches(&fork_table, "call-1", vec!["z9hG4bK-a", "z9hG4bK-b"]).await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-a", StatusCode::OK),
        )
        .await
        .unwrap();
        assert_eq!(recv_response(&client).await.status, StatusCode::OK);

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_response("z9hG4bK-b", StatusCode::BUSY_HERE),
        )
        .await
        .unwrap();

        assert_no_datagram(&client).await;
        assert!(!fork_table.read().await.contains_key("call-1"));
    }

    #[tokio::test]
    async fn cancel_request_preserves_route_headers_from_original_invite() {
        let mut invite = invite_request();
        let route = "<sip:edge.example.com;lr>".to_string();
        invite.headers.push(Header::Route(vec![route.clone()]));

        let cancel = build_cancel_request(
            &invite,
            "z9hG4bK-proxy",
            "sip:bob@127.0.0.1:5090",
            &test_cfg(),
        );

        assert!(
            cancel
                .headers
                .iter()
                .any(|h| { matches!(h, Header::Route(routes) if routes == &vec![route.clone()]) })
        );
    }

    #[tokio::test]
    async fn failed_fork_response_is_relayed_when_remaining_targets_are_unusable() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let table = new_forward_table();
        let cfg = test_cfg();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_string(),
            client_addr,
            None,
            "127.0.0.1:5099".parse().unwrap(),
            vec![client_via()],
            Some(invite_request()),
            vec![
                "sips:bob@127.0.0.1".to_string(),
                "sip:bob@127.0.0.1;transport=tcp".to_string(),
                "sip:bob@127.0.0.1;transport=ws".to_string(),
            ],
            "sip:bob@127.0.0.1:5099".to_string(),
        )
        .await;

        dispatch_response(
            &socket,
            &test_sip_sender(&socket),
            &cfg,
            &table,
            &new_fork_table(),
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            test_session_tx(),
            proxy_failure_response(),
        )
        .await
        .unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            client.recv_from(&mut buf),
        )
        .await
        .expect("client should receive original failure")
        .unwrap();
        let (_, msg) = parse_sip_message(&buf[..n]).unwrap();
        let SipMessage::Response(resp) = msg else {
            panic!("expected response");
        };
        assert_eq!(resp.status, StatusCode::BUSY_HERE);
    }

    async fn insert_test_forward(
        table: &ForwardTable,
        branch: &str,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) {
        insert_forward(
            table,
            branch.to_string(),
            client_addr,
            None,
            target_addr,
            vec![client_via()],
            Some(invite_request()),
            vec![],
            format!("sip:bob@{target_addr}"),
        )
        .await;
    }

    async fn recv_request(socket: &tokio::net::UdpSocket) -> Request {
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("expected SIP request")
        .unwrap();
        let (_, msg) = parse_sip_message(&buf[..n]).unwrap();
        let SipMessage::Request(req) = msg else {
            panic!("expected request");
        };
        req
    }

    async fn recv_response(socket: &tokio::net::UdpSocket) -> Response {
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("expected SIP response")
        .unwrap();
        let (_, msg) = parse_sip_message(&buf[..n]).unwrap();
        let SipMessage::Response(resp) = msg else {
            panic!("expected response");
        };
        resp
    }

    async fn assert_no_datagram(socket: &tokio::net::UdpSocket) {
        let mut buf = vec![0u8; 2048];
        let recv = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            socket.recv_from(&mut buf),
        )
        .await;
        assert!(recv.is_err(), "unexpected datagram received");
    }

    fn client_via() -> Via {
        Via {
            transport: Transport::Udp,
            host: "client.example.com".to_string(),
            port: Some(5060),
            branch: "z9hG4bK-client".to_string(),
            received: None,
            rport: RportParam::Absent,
            params: vec![],
        }
    }

    fn proxy_response(branch: &str, status: StatusCode) -> Response {
        proxy_response_for_method(branch, status, Method::Invite)
    }

    fn proxy_response_for_method(branch: &str, status: StatusCode, method: Method) -> Response {
        let mut req = invite_request();
        if let Some(cseq) = req.headers.iter_mut().find_map(|h| match h {
            Header::CSeq(cseq) => Some(cseq),
            _ => None,
        }) {
            cseq.method = method;
        }
        let mut resp = match sip_response(&req, status) {
            SipMessage::Response(resp) => resp,
            SipMessage::Request(_) => unreachable!("sip_response returns a response"),
        };
        resp.headers.insert(
            0,
            Header::Via(Via {
                transport: Transport::Udp,
                host: "proxy.example.com".to_string(),
                port: Some(5060),
                branch: branch.to_string(),
                received: None,
                rport: RportParam::Absent,
                params: vec![],
            }),
        );
        resp
    }

    fn proxy_failure_response() -> Response {
        proxy_response("z9hG4bK-proxy", StatusCode::BUSY_HERE)
    }

    fn test_cfg() -> UdpProxyConfig {
        UdpProxyConfig {
            domain: "example.com".to_string(),
            advertise: "proxy.example.com".to_string(),
            sip_port: 5060,
            max_forwards: 70,
            registrar: RegistrarLimits {
                min_expires: 60,
                max_expires: 3600,
                default_expires: 300,
            },
            nonce_ttl_s: 120,
            fork_parallel: true,
            pg: PgPoolOptions::new()
                .connect_lazy("postgres://localhost/sipora")
                .unwrap(),
            stir: StirConfig::default(),
            max_message_bytes: 65535,
            outbound_edge_uri: None,
            push_gateway_url: None,
            push_timeout_ms: 5000,
            push_auth_bearer: None,
            push_device_idle_secs: 120,
            http_client: reqwest::Client::new(),
        }
    }

    fn invite_request() -> Request {
        Request {
            method: Method::Invite,
            uri: "sip:bob@example.com".to_string(),
            version: SipVersion::V2_0,
            headers: vec![
                Header::Via(Via {
                    transport: Transport::Udp,
                    host: "client.example.com".to_string(),
                    port: Some(5060),
                    branch: "z9hG4bK-client".to_string(),
                    received: None,
                    rport: RportParam::Absent,
                    params: vec![],
                }),
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".to_string(),
                    tag: Some("from-tag".to_string()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.com".to_string(),
                    tag: None,
                    params: vec![],
                }),
                Header::CallId("call-1".to_string()),
                Header::CSeq(CSeq {
                    seq: 1,
                    method: Method::Invite,
                }),
                Header::MaxForwards(70),
                Header::ContentLength(0),
            ],
            body: Vec::new(),
        }
    }
}
