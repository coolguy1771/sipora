//! UDP registrar and request-only SIP handling. INVITE is forwarded without response relay;
//! see `AGENTS.md` ("SIP signaling scope") and `docs/qualification.md` for end-to-end INVITE paths.

use fred::prelude::{Expiration, KeysInterface, LuaInterface, SetOptions};
use sipora_auth::digest::{
    DigestAlgorithm, DigestChallenge, DigestResponse, EffectiveHa1Error,
    effective_stored_ha1_for_digest, validate_nc, verify_digest,
};
use sipora_auth::stir::{CertCache, StirError, verify_identity_header};
use sipora_core::redis::RedisPool;
use sipora_core::redis_keys::{
    LUA_REGISTER_COMMIT_LOCK_DELETE_IF_MATCH, register_commit_lock_key, register_digest_nonce_key,
    register_digest_nonce_nc_key, register_transaction_ok_key,
};
use sipora_data::pg::{SipDigestCredentials, get_user_sip_digest_credentials};
use sipora_location::ContactBinding;
use sipora_location::redis_store::{list_contact_uris, upsert_contact};
use sipora_sip::overload::overload_response;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::transaction::TransactionKey;
use sipora_sip::transaction::manager::{TransactionManager, TransactionType};
use sipora_sip::types::header::{Header, Transport, Via};
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;
use sipora_transport::dns::{SipTransport, resolve_sip_targets};
use sipora_transport::udp::UdpTransport;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use uuid::Uuid;

use crate::dialog::{
    DialogState, DialogTable, RefreshTable, cancel_session_guard, dialog_for_request,
    insert_dialog_from_response, new_refresh_table, remove_dialog, spawn_session_guard,
};
use crate::forward_table::{
    ForwardTable, PendingForward, find_branch_by_call_id, find_branch_by_call_id_and_rseq,
    find_branches_by_call_id, get_pending_forward, insert_forward, prepare_response,
    spawn_forward_sweeper,
};
use crate::routing::ProxyRouter;

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
}

impl Default for StirConfig {
    fn default() -> Self {
        Self {
            mode: StirMode::Disabled,
            trusted_peer_ips: vec![],
            cert_cache: CertCache::new(),
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
}

pub type TransactionTable = Arc<RwLock<TransactionManager>>;

#[derive(Debug)]
struct PreparedForkFailure {
    response: Response,
    target: SocketAddr,
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

pub async fn run_udp_proxy(
    addr: SocketAddr,
    redis: RedisPool,
    cfg: UdpProxyConfig,
    forward_table: ForwardTable,
    dialog_table: DialogTable,
    transaction_table: TransactionTable,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let udp = UdpTransport::bind(addr).await?;
    let socket = Arc::new(udp.into_inner());
    let router = ProxyRouter::new(cfg.max_forwards);
    let refresh_table = new_refresh_table();
    let fork_table = new_fork_table();
    let _forward_sweeper = spawn_forward_sweeper(forward_table.clone(), shutdown.clone());
    let _fork_sweeper =
        spawn_fork_sweeper(fork_table.clone(), forward_table.clone(), shutdown.clone());
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
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
                        dispatch_request(
                            &socket,
                            &redis,
                            &router,
                            &cfg,
                            &forward_table,
                            &dialog_table,
                            &transaction_table,
                            &fork_table,
                            &refresh_table,
                            peer,
                            req,
                        )
                        .await
                    }
                    SipMessage::Response(resp) => {
                        dispatch_response(
                            &socket,
                            &cfg,
                            &forward_table,
                            &fork_table,
                            &dialog_table,
                            &transaction_table,
                            &refresh_table,
                            resp,
                        )
                        .await
                    }
                };
                if let Err(e) = result {
                    tracing::warn!(%peer, "udp proxy: {e}");
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    socket: &Arc<tokio::net::UdpSocket>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    refresh_table: &RefreshTable,
    peer: SocketAddr,
    mut req: Request,
) -> anyhow::Result<()> {
    apply_rfc3581(&mut req, peer);
    if let Some(status) = enforce_sips_policy(&req, Transport::Udp) {
        respond(socket, peer, &sip_response(&req, status)).await;
        return Ok(());
    }
    track_server_transaction(transaction_table, &req).await;
    match req.method {
        Method::Invite => {
            handle_invite(
                socket,
                redis,
                router,
                cfg,
                forward_table,
                transaction_table,
                fork_table,
                peer,
                req,
            )
            .await
        }
        Method::Register => handle_register(socket, redis, cfg, peer, req).await,
        Method::Ack | Method::Bye | Method::Update => {
            handle_dialog_request(
                socket,
                cfg,
                forward_table,
                transaction_table,
                dialog_table,
                refresh_table,
                peer,
                req,
            )
            .await
        }
        Method::Cancel => {
            handle_cancel(socket, cfg, forward_table, transaction_table, peer, req).await
        }
        Method::Prack => handle_prack(socket, cfg, forward_table, peer, req).await,
        Method::Options => {
            respond(socket, peer, &sip_options_ok(&req)).await;
            Ok(())
        }
        _ => {
            respond(
                socket,
                peer,
                &sip_response(&req, StatusCode::NOT_IMPLEMENTED),
            )
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
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    refresh_table: &RefreshTable,
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
            cfg,
            forward_table,
            fork_table,
            dialog_table,
            transaction_table,
            refresh_table,
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
        dialog_table,
        refresh_table,
        forward_table,
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
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    refresh_table: &RefreshTable,
    branch: String,
    resp: Response,
    pending: Option<PendingForward>,
) -> anyhow::Result<()> {
    if resp.status.is_provisional() {
        return relay_parallel_response(
            socket,
            dialog_table,
            refresh_table,
            forward_table,
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
            dialog_table,
            refresh_table,
            forward_table,
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
            dialog_table,
            refresh_table,
            forward_table,
            &branch,
            resp,
            pending,
        )
        .await;
    }
    handle_parallel_failure(socket, forward_table, fork_table, &branch, resp).await
}

#[allow(clippy::too_many_arguments)]
async fn relay_parallel_response(
    socket: &Arc<tokio::net::UdpSocket>,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    forward_table: &ForwardTable,
    branch: &str,
    resp: Response,
    pending: Option<PendingForward>,
) -> anyhow::Result<()> {
    relay_final_response(
        socket,
        dialog_table,
        refresh_table,
        forward_table,
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
        return send_response(socket, failure.response, failure.target).await;
    }
    Ok(())
}

async fn prepare_parallel_failure(
    forward_table: &ForwardTable,
    branch: &str,
    resp: &mut Response,
) -> Option<SocketAddr> {
    let mut target = prepare_response(forward_table, branch, resp).await?;
    if let Some(via) = response_top_via(resp) {
        target = response_relay_addr(via).unwrap_or(target);
    }
    Some(target)
}

async fn record_parallel_failure(
    fork_table: &ForkTable,
    call_id: &str,
    branch: &str,
    resp: Response,
    target: SocketAddr,
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
    if forward_next_fork(socket, cfg, forward_table, transaction_table, pending).await? {
        return Ok(());
    }
    if let Some(via) = response_top_via(&resp) {
        target = response_relay_addr(via).unwrap_or(target);
    }
    send_response(socket, resp, target).await
}

async fn relay_final_response(
    socket: &Arc<tokio::net::UdpSocket>,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    forward_table: &ForwardTable,
    branch: &str,
    mut resp: Response,
    pending: Option<PendingForward>,
) -> anyhow::Result<()> {
    let success_response = pending.as_ref().is_some_and(|_| resp.status.is_success());
    let Some(mut target) = prepare_response(forward_table, branch, &mut resp).await else {
        return Ok(());
    };
    if let Some(via) = response_top_via(&resp) {
        target = response_relay_addr(via).unwrap_or(target);
    }
    if success_response && let Some(pending) = pending {
        let session_expires = response_session_expires(&resp);
        if let (Some(dialog_key), Some(se)) = (
            insert_dialog_from_response(
                dialog_table,
                &resp,
                pending.client_addr,
                pending.target_addr,
            )
            .await,
            session_expires,
        ) {
            spawn_session_guard(dialog_table, refresh_table, dialog_key, se).await;
        }
    }
    send_response(socket, resp, target).await
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

fn should_try_next_fork(resp: &Response, pending: Option<&PendingForward>) -> bool {
    resp.status.class() >= 3
        && pending
            .as_ref()
            .is_some_and(|p| !p.remaining_targets.is_empty())
}

async fn forward_next_fork(
    socket: &Arc<tokio::net::UdpSocket>,
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
    socket: &tokio::net::UdpSocket,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    peer: SocketAddr,
    mut req: Request,
) -> anyhow::Result<()> {
    let Some((dialog_key, state)) = dialog_for_request(dialog_table, &req).await else {
        if req.method != Method::Ack {
            respond(
                socket,
                peer,
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
    let target_uri = dialog_target_uri(&mut req, &state, cfg);
    let Some(target) = resolve_udp_target(&target_uri).await else {
        respond(socket, peer, &overload_response(&req, 30)).await;
        return Ok(());
    };
    let method = req.method.clone();
    forward_dialog_request(
        socket,
        forward_table,
        transaction_table,
        peer,
        req,
        target_uri,
        target,
        cfg,
    )
    .await?;
    if method == Method::Bye {
        cancel_session_guard(refresh_table, &dialog_key).await;
        remove_dialog(dialog_table, &dialog_key);
    }
    Ok(())
}

fn dialog_target_uri(req: &mut Request, state: &DialogState, cfg: &UdpProxyConfig) -> String {
    let own_route = format!("sip:{}:{}", cfg.advertise, cfg.sip_port);
    strip_own_route(&mut req.headers, &own_route);
    let target = next_route_uri(&req.headers)
        .or_else(|| state.route_set.first().cloned())
        .unwrap_or_else(|| state.remote_target.clone());
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
    socket: &Arc<tokio::net::UdpSocket>,
    pool: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    let Some(req) = prepare_invite_ingress(socket, cfg, peer, req).await? else {
        return Ok(());
    };
    if reject_invite_for_max_forwards(socket, router, peer, &req).await {
        return Ok(());
    }
    let Some(contacts) = lookup_invite_contacts(socket, pool, cfg, peer, &req).await? else {
        return Ok(());
    };
    let Some(route) = select_invite_route(socket, peer, &req, contacts).await else {
        return Ok(());
    };

    forward_initial_invite(
        socket,
        forward_table,
        transaction_table,
        fork_table,
        cfg,
        peer,
        req,
        route,
    )
    .await
}

async fn prepare_invite_ingress(
    socket: &Arc<tokio::net::UdpSocket>,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<Option<Request>> {
    // RFC 3261 §17.2.1: send 100 Trying immediately on INVITE receipt
    respond(socket, peer, &sip_response(&req, StatusCode::TRYING)).await;

    let mut req = req;
    // RFC 3325 §9.1: strip P-AI/P-PI from untrusted ingress before routing.
    let trusted = is_trusted_peer(peer, &cfg.stir);
    strip_untrusted_identity_headers(&mut req, trusted);
    // RFC 8224: verify or require STIR Identity header per configured policy.
    if let Some(reject_code) = check_stir_identity(&mut req, &cfg.stir).await {
        respond(socket, peer, &sip_response(&req, reject_code)).await;
        return Ok(None);
    }

    // RFC 4028 §8: reject if Session-Expires is below proxy minimum
    if check_session_expires(&req).is_some() {
        respond(socket, peer, &sip_response_with_min_se(&req, PROXY_MIN_SE)).await;
        return Ok(None);
    }
    Ok(Some(req))
}

async fn reject_invite_for_max_forwards(
    socket: &Arc<tokio::net::UdpSocket>,
    router: &ProxyRouter,
    peer: SocketAddr,
    req: &Request,
) -> bool {
    if router.check_max_forwards(req).is_none() {
        return false;
    }
    respond(
        socket,
        peer,
        &SipMessage::Response(ProxyRouter::too_many_hops_response(req)),
    )
    .await;
    true
}

async fn lookup_invite_contacts(
    socket: &Arc<tokio::net::UdpSocket>,
    pool: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
) -> anyhow::Result<Option<Vec<ContactBinding>>> {
    let Some((user, dom)) = parse_sip_user_host(&req.uri) else {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::not_found_response(req)),
        )
        .await;
        return Ok(None);
    };
    let dom = normalize_domain(dom, &cfg.domain);
    let contacts = match list_contact_uris(pool, &dom, &user).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "location lookup");
            respond(
                socket,
                peer,
                &SipMessage::Response(ProxyRouter::service_unavailable(req, 30)),
            )
            .await;
            return Ok(None);
        }
    };
    if contacts.is_empty() {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::not_found_response(req)),
        )
        .await;
        return Ok(None);
    }
    Ok(Some(contacts))
}

async fn select_invite_route(
    socket: &Arc<tokio::net::UdpSocket>,
    peer: SocketAddr,
    req: &Request,
    contacts: Vec<ContactBinding>,
) -> Option<InitialInviteRoute> {
    match select_initial_invite_target(req, contacts).await {
        InitialInviteTarget::Selected(route) => Some(route),
        InitialInviteTarget::Downgrade(status) => {
            respond(socket, peer, &sip_response(req, status)).await;
            None
        }
        InitialInviteTarget::Unusable => {
            respond(
                socket,
                peer,
                &SipMessage::Response(ProxyRouter::service_unavailable(req, 30)),
            )
            .await;
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_initial_invite(
    socket: &Arc<tokio::net::UdpSocket>,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
    route: InitialInviteRoute,
) -> anyhow::Result<()> {
    if !cfg.fork_parallel {
        let original_request = req.clone();
        forward_invite_request(
            socket,
            forward_table,
            transaction_table,
            peer,
            req,
            route.target_uri,
            route.target,
            Some(original_request),
            route.remaining_targets,
            &cfg.advertise,
            cfg.sip_port,
        )
        .await?;
        return Ok(());
    }

    forward_parallel_initial_invite(
        socket,
        forward_table,
        transaction_table,
        fork_table,
        cfg,
        peer,
        req,
        route,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward_parallel_initial_invite(
    socket: &Arc<tokio::net::UdpSocket>,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
    route: InitialInviteRoute,
) -> anyhow::Result<()> {
    let call_id = req.call_id().map(str::to_owned);
    let original_request = req.clone();
    let mut branches = Vec::new();
    let first_branch = forward_invite_request(
        socket,
        forward_table,
        transaction_table,
        peer,
        req,
        route.target_uri,
        route.target,
        Some(original_request.clone()),
        vec![],
        &cfg.advertise,
        cfg.sip_port,
    )
    .await?;
    branches.push(first_branch);

    for target_uri in route.remaining_targets {
        if let Some(target) = resolve_udp_target(&target_uri).await {
            let branch = forward_invite_request(
                socket,
                forward_table,
                transaction_table,
                peer,
                original_request.clone(),
                target_uri,
                target,
                Some(original_request.clone()),
                vec![],
                &cfg.advertise,
                cfg.sip_port,
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

enum InitialInviteTarget {
    Selected(InitialInviteRoute),
    Downgrade(StatusCode),
    Unusable,
}

struct InitialInviteRoute {
    target_uri: String,
    target: SocketAddr,
    remaining_targets: Vec<String>,
}

async fn select_initial_invite_target(
    req: &Request,
    mut contacts: Vec<ContactBinding>,
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
        });
    }

    InitialInviteTarget::Unusable
}

#[allow(clippy::too_many_arguments)]
async fn forward_invite_request(
    socket: &Arc<tokio::net::UdpSocket>,
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
) -> anyhow::Result<String> {
    req.uri = target_uri;
    let branch = format!("z9hG4bK{}", Uuid::new_v4().as_simple());
    let original_via_stack = insert_forwarding_headers(&mut req, &branch, advertise, sip_port);
    let tx_key = TransactionKey::from_request(&req);

    insert_forward(
        forward_table,
        branch.clone(),
        peer,
        target,
        original_via_stack,
        original_request,
        remaining_targets,
        req.uri.clone(),
    )
    .await;

    let bytes = serialize_message(&SipMessage::Request(req));
    socket.send_to(&bytes, target).await?;
    let timer = spawn_invite_retransmit_timer(socket, bytes, target);
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

fn spawn_invite_retransmit_timer(
    socket: &Arc<tokio::net::UdpSocket>,
    bytes: Vec<u8>,
    target: SocketAddr,
) -> tokio::task::JoinHandle<()> {
    let socket = Arc::clone(socket);
    tokio::spawn(async move {
        let mut delay = sipora_sip::transaction::TIMER_T1;
        loop {
            tokio::time::sleep(delay).await;
            if socket.send_to(&bytes, target).await.is_err() {
                return;
            }
            delay = (delay * 2).min(sipora_sip::transaction::TIMER_T2);
        }
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

fn register_authorization_value(req: &Request) -> Option<&str> {
    let raw = req.headers.iter().find_map(|h| match h {
        Header::Authorization(v) => Some(v.as_str()),
        Header::ProxyAuthorization(v) => Some(v.as_str()),
        Header::Extension { name, value } if name.eq_ignore_ascii_case("authorization") => {
            Some(value.as_str())
        }
        Header::Extension { name, value } if name.eq_ignore_ascii_case("proxy-authorization") => {
            Some(value.as_str())
        }
        _ => None,
    });
    raw.filter(|s| !s.trim().is_empty())
}

async fn store_register_nonce(redis: &RedisPool, nonce: &str, ttl_s: u64) -> anyhow::Result<()> {
    let key = register_digest_nonce_key(nonce);
    let ttl = ttl_s.max(1) as i64;
    let _: Option<String> = redis
        .set(&key, "1", Some(Expiration::EX(ttl)), None, false)
        .await?;
    Ok(())
}

async fn register_nonce_exists(redis: &RedisPool, nonce: &str) -> anyhow::Result<bool> {
    let key = register_digest_nonce_key(nonce);
    let n: i64 = redis.exists(&key).await?;
    Ok(n > 0)
}

async fn invalidate_register_nonce(redis: &RedisPool, nonce: &str) -> anyhow::Result<()> {
    let key = register_digest_nonce_key(nonce);
    let _: i64 = redis.del(&key).await?;
    Ok(())
}

async fn register_tx_ok_exists(
    redis: &RedisPool,
    call_id: &str,
    cseq: u32,
) -> anyhow::Result<bool> {
    let key = register_transaction_ok_key(call_id, cseq);
    let n: i64 = redis.exists(&key).await?;
    Ok(n > 0)
}

/// SET NX PX with a unique token. Returns `Some(token)` if this caller holds the lock.
async fn try_register_commit_lock(
    redis: &RedisPool,
    lock_key: &str,
) -> anyhow::Result<Option<String>> {
    const LOCK_MS: i64 = 15_000;
    let token = Uuid::new_v4().simple().to_string();
    let set: Option<String> = redis
        .set(
            lock_key,
            &token,
            Some(Expiration::PX(LOCK_MS)),
            Some(SetOptions::NX),
            false,
        )
        .await?;
    Ok(if set.is_some() { Some(token) } else { None })
}

async fn release_register_commit_lock(redis: &RedisPool, lock_key: &str, token: &str) {
    let res: Result<i64, _> = redis
        .eval(
            LUA_REGISTER_COMMIT_LOCK_DELETE_IF_MATCH,
            vec![lock_key],
            vec![token],
        )
        .await;
    match res {
        Ok(0) => {
            tracing::debug!(
                key = %lock_key,
                token = %token,
                "release_register_commit_lock LUA_REGISTER_COMMIT_LOCK_DELETE_IF_MATCH: Ok(0) CAS not applied (token mismatch, replay, or lock expired)"
            );
        }
        Err(e) => {
            tracing::warn!(%e, key = %lock_key, "register commit lock cas-del");
        }
        Ok(_) => {}
    }
}

async fn mark_register_tx_ok(redis: &RedisPool, call_id: &str, cseq: u32) -> anyhow::Result<()> {
    let key = register_transaction_ok_key(call_id, cseq);
    let ttl: i64 = 70;
    let _: Option<String> = redis
        .set(&key, "1", Some(Expiration::EX(ttl)), None, false)
        .await?;
    Ok(())
}

fn sip_options_ok(req: &Request) -> SipMessage {
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
    headers.push(Header::Allow(vec![
        Method::Invite,
        Method::Ack,
        Method::Bye,
        Method::Cancel,
        Method::Register,
        Method::Options,
    ]));
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::OK,
        reason: StatusCode::OK.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

/// Build a 401 with multiple WWW-Authenticate headers (RFC 8760 dual-algorithm challenge).
fn sip_response_multi_www_auth(req: &Request, challenges: &[String]) -> SipMessage {
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
    for ch in challenges {
        headers.push(Header::WwwAuthenticate(ch.clone()));
    }
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::UNAUTHORIZED,
        reason: StatusCode::UNAUTHORIZED.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

/// Minimum Session-Expires value this proxy accepts (RFC 4028 §7.4).
const PROXY_MIN_SE: u32 = 90;

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

/// Build a 422 Session Interval Too Small response with a Min-SE header.
fn sip_response_with_min_se(req: &Request, min_se: u32) -> SipMessage {
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
    headers.push(Header::MinSE(min_se));
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status: StatusCode::SESSION_INTERVAL_TOO_SMALL,
        reason: StatusCode::SESSION_INTERVAL_TOO_SMALL
            .reason_phrase()
            .to_owned(),
        headers,
        body: Vec::new(),
    })
}

/// RFC 3262 §3: route PRACK by `RAck` + Call-ID when possible, else Call-ID only.
async fn handle_prack(
    socket: &tokio::net::UdpSocket,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    peer: SocketAddr,
    mut req: Request,
) -> anyhow::Result<()> {
    let Some(call_id) = req.call_id() else {
        respond(socket, peer, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
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
        respond(
            socket,
            peer,
            &sip_response(&req, StatusCode::CALL_DOES_NOT_EXIST),
        )
        .await;
        return Ok(());
    };
    let target_addr = {
        let table = forward_table.read().await;
        table.get(&branch).map(|p| p.target_addr)
    };
    let Some(target) = target_addr else {
        respond(
            socket,
            peer,
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
    socket.send_to(&bytes, target).await?;
    Ok(())
}

fn prack_rack_tuple(req: &Request) -> Option<(u32, u32)> {
    req.headers.iter().find_map(|h| match h {
        Header::RAck { rseq, cseq, .. } => Some((*rseq, *cseq)),
        _ => None,
    })
}

async fn handle_cancel(
    socket: &tokio::net::UdpSocket,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    // RFC 3261 §16.10: respond 200 OK immediately, then forward CANCEL downstream.
    respond(socket, peer, &sip_response(&req, StatusCode::OK)).await;
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
        socket.send_to(&bytes, target_addr).await?;
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

async fn handle_register(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    let Some(to) = req.to_header() else {
        respond(socket, peer, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let Some((user, dom_raw)) = parse_sip_user_host(&to.uri) else {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    };
    let dom = normalize_domain(dom_raw, &cfg.domain);
    let contacts = req.contacts();
    let Some(contact) = contacts.first() else {
        respond(socket, peer, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let reg = &cfg.registrar;
    let expires = req
        .expires()
        .unwrap_or(reg.default_expires)
        .clamp(reg.min_expires, reg.max_expires);
    let binding = ContactBinding {
        uri: contact.uri.clone(),
        q_value: contact.q_value(),
        expires,
    };

    match register_authorization_value(&req) {
        None => {
            register_send_digest_challenge(socket, redis, cfg, peer, &req, &user, &dom, false).await
        }
        Some(auth_raw) => {
            register_complete_digest(
                socket, redis, cfg, peer, &req, &user, &dom, &binding, expires, auth_raw,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_send_digest_challenge(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    user: &str,
    realm: &str,
    stale: bool,
) -> anyhow::Result<()> {
    let credentials = match get_user_sip_digest_credentials(&cfg.pg, user, realm).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "register db");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
    };
    let algorithms = register_challenge_algorithms(credentials.as_ref());
    register_send_digest_challenge_with_algorithms(
        socket,
        redis,
        cfg,
        peer,
        req,
        realm,
        stale,
        &algorithms,
    )
    .await
}

fn register_challenge_algorithms(
    credentials: Option<&SipDigestCredentials>,
) -> Vec<DigestAlgorithm> {
    match credentials {
        Some(c) if c.sip_digest_ha1_sha256.is_some() && c.sip_digest_ha1.is_some() => {
            vec![DigestAlgorithm::Sha256, DigestAlgorithm::Md5]
        }
        Some(c) if c.sip_digest_ha1_sha256.is_some() => vec![DigestAlgorithm::Sha256],
        _ => vec![DigestAlgorithm::Md5],
    }
}

/// RFC 8760: send SHA-256 first when available, with MD5 for legacy UAs.
/// RFC 2617: set stale=TRUE when re-challenging after a nonce expiry.
#[allow(clippy::too_many_arguments)]
async fn register_send_digest_challenge_with_algorithms(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    realm: &str,
    stale: bool,
    algorithms: &[DigestAlgorithm],
) -> anyhow::Result<()> {
    let mut stored_nonces = Vec::new();
    let mut challenges = Vec::new();
    for algorithm in algorithms {
        let nonce = Uuid::new_v4().simple().to_string();
        if let Err(e) = store_register_nonce(redis, &nonce, cfg.nonce_ttl_s).await {
            rollback_register_challenge_nonces(redis, &stored_nonces).await;
            tracing::warn!(%e, "register nonce store");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
        challenges.push(register_challenge_header(*algorithm, realm, &nonce, stale));
        stored_nonces.push(nonce);
    }
    respond(socket, peer, &sip_response_multi_www_auth(req, &challenges)).await;
    Ok(())
}

async fn rollback_register_challenge_nonces(redis: &RedisPool, nonces: &[String]) {
    for nonce in nonces {
        if let Err(e) = invalidate_register_nonce(redis, nonce).await {
            tracing::warn!(%e, %nonce, "register nonce rollback after store failure");
        }
    }
}

fn register_challenge_header(
    algorithm: DigestAlgorithm,
    realm: &str,
    nonce: &str,
    stale: bool,
) -> String {
    match algorithm {
        DigestAlgorithm::Sha256 => DigestChallenge::new_sha256(realm, nonce),
        DigestAlgorithm::Md5 => DigestChallenge::new_md5(realm, nonce),
        DigestAlgorithm::Md5Sess | DigestAlgorithm::Sha256Sess => {
            unreachable!("REGISTER challenges use non-session algorithms")
        }
    }
    .with_stale(stale)
    .to_www_authenticate()
}

fn register_call_id_cseq(req: &Request) -> Option<(&str, u32)> {
    let call_id = req.call_id()?;
    let cs = req.cseq()?;
    (cs.method == Method::Register).then_some((call_id, cs.seq))
}

#[allow(clippy::too_many_arguments)]
async fn register_digest_commit_after_lock(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    user: &str,
    dom: &str,
    binding: &ContactBinding,
    expires: u32,
    auth_raw: &str,
    call_id: &str,
    cseq_n: u32,
) -> anyhow::Result<()> {
    let Some(dr) = DigestResponse::parse(auth_raw) else {
        respond(socket, peer, &sip_response(req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    if !dr.username.eq_ignore_ascii_case(user) || !dr.realm.eq_ignore_ascii_case(dom) {
        respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
        return Ok(());
    }
    match register_nonce_exists(redis, &dr.nonce).await {
        Ok(false) => {
            // Nonce expired (TTL elapsed) — re-challenge with stale=TRUE so the UA
            // retries with a fresh nonce without prompting for credentials (RFC 2617 §3.3).
            register_send_digest_challenge(socket, redis, cfg, peer, req, &dr.username, dom, true)
                .await
        }
        Ok(true) => {
            register_commit_digest(
                socket, redis, cfg, peer, req, dom, user, binding, expires, &dr, call_id, cseq_n,
            )
            .await
        }
        Err(e) => {
            tracing::warn!(%e, "register redis (nonce exists)");
            respond(socket, peer, &overload_response(req, 30)).await;
            Ok(())
        }
    }
}

/// `Ok(None)` if the request was fully answered (idempotent 200 or 503).
/// `Ok(Some((lock_key, token)))` if the caller holds the commit lock (release with CAS del).
async fn register_try_acquire_commit_lock(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    peer: SocketAddr,
    req: &Request,
    call_id: &str,
    cseq_n: u32,
) -> anyhow::Result<Option<(String, String)>> {
    match register_tx_ok_exists(redis, call_id, cseq_n).await {
        Ok(true) => {
            respond(socket, peer, &SipMessage::Response(simple_ok(req))).await;
            return Ok(None);
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(%e, "register redis (tx ok exists)");
            respond(socket, peer, &overload_response(req, 30)).await;
            return Ok(None);
        }
    }

    let lock_key = register_commit_lock_key(call_id, cseq_n);
    let lock_token = match try_register_commit_lock(redis, &lock_key).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            match register_tx_ok_exists(redis, call_id, cseq_n).await {
                Ok(true) => {
                    respond(socket, peer, &SipMessage::Response(simple_ok(req))).await;
                }
                Ok(false) => {
                    tracing::warn!("register redis (tx ok false after lock miss; commit pending)");
                    respond(socket, peer, &overload_response(req, 30)).await;
                }
                Err(e) => {
                    tracing::warn!(%e, "register redis (tx ok after lock miss)");
                    respond(socket, peer, &overload_response(req, 30)).await;
                }
            }
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!(%e, "register redis (commit lock)");
            respond(socket, peer, &overload_response(req, 30)).await;
            return Ok(None);
        }
    };

    Ok(Some((lock_key, lock_token)))
}

#[allow(clippy::too_many_arguments)] // REGISTER digest + binding; refactor into a ctx struct if extended.
async fn register_complete_digest(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    user: &str,
    dom: &str,
    binding: &ContactBinding,
    expires: u32,
    auth_raw: &str,
) -> anyhow::Result<()> {
    let Some((call_id, cseq_n)) = register_call_id_cseq(req) else {
        respond(socket, peer, &sip_response(req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };

    let (lock_key, lock_token) =
        match register_try_acquire_commit_lock(socket, redis, peer, req, call_id, cseq_n).await? {
            Some(pair) => pair,
            None => return Ok(()),
        };

    let commit_res = register_digest_commit_after_lock(
        socket, redis, cfg, peer, req, user, dom, binding, expires, auth_raw, call_id, cseq_n,
    )
    .await;

    release_register_commit_lock(redis, &lock_key, &lock_token).await;
    commit_res
}

fn select_register_stored_ha1(
    credentials: &SipDigestCredentials,
    algorithm: DigestAlgorithm,
) -> Option<&str> {
    match algorithm {
        DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => credentials.sip_digest_ha1.as_deref(),
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => {
            credentials.sip_digest_ha1_sha256.as_deref()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_commit_digest(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    dom: &str,
    user: &str,
    binding: &ContactBinding,
    expires: u32,
    dr: &DigestResponse,
    call_id: &str,
    cseq_n: u32,
) -> anyhow::Result<()> {
    if !register_digest_verified(socket, redis, cfg, peer, req, dom, dr).await? {
        return Ok(());
    }
    if !register_enforce_digest_nc(socket, redis, cfg, peer, req, dr).await? {
        return Ok(());
    }
    if !register_store_binding(socket, redis, peer, req, dom, user, binding, expires, dr).await? {
        return Ok(());
    }
    if let Err(e) = mark_register_tx_ok(redis, call_id, cseq_n).await {
        tracing::warn!(%e, "register tx ok marker");
    }
    respond(socket, peer, &SipMessage::Response(simple_ok(req))).await;
    Ok(())
}

async fn register_digest_verified(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    dom: &str,
    dr: &DigestResponse,
) -> anyhow::Result<bool> {
    let credentials = match get_user_sip_digest_credentials(&cfg.pg, &dr.username, dom).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            register_missing_selected_ha1(socket, redis, cfg, peer, req, dom, dr, None).await?;
            return Ok(false);
        }
        Err(e) => {
            tracing::warn!(%e, "register db");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(false);
        }
    };
    let Some(ha1) = select_register_stored_ha1(&credentials, dr.algorithm) else {
        register_missing_selected_ha1(socket, redis, cfg, peer, req, dom, dr, Some(&credentials))
            .await?;
        return Ok(false);
    };
    let Some(ha1_verify) = register_effective_ha1(socket, peer, req, dr, ha1).await else {
        return Ok(false);
    };
    if verify_digest(dr, &ha1_verify, "REGISTER") {
        return Ok(true);
    }
    invalidate_register_nonce_after_forbid(redis, dr, "register invalidate nonce").await;
    respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
async fn register_missing_selected_ha1(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    realm: &str,
    dr: &DigestResponse,
    credentials: Option<&SipDigestCredentials>,
) -> anyhow::Result<()> {
    tracing::warn!(
        algorithm = %dr.algorithm.as_str(),
        username = %dr.username,
        realm = %dr.realm,
        "REGISTER digest: missing HA1 for selected digest algorithm"
    );
    invalidate_register_nonce_after_forbid(redis, dr, "register invalidate nonce").await;
    if should_rechallenge_md5_only(credentials, dr.algorithm) {
        return register_send_digest_challenge_with_algorithms(
            socket,
            redis,
            cfg,
            peer,
            req,
            realm,
            false,
            &[DigestAlgorithm::Md5],
        )
        .await;
    }
    respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
    Ok(())
}

fn should_rechallenge_md5_only(
    credentials: Option<&SipDigestCredentials>,
    algorithm: DigestAlgorithm,
) -> bool {
    matches!(
        algorithm,
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess
    ) && credentials
        .is_some_and(|c| c.sip_digest_ha1.is_some() && c.sip_digest_ha1_sha256.is_none())
}

async fn register_effective_ha1(
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    req: &Request,
    dr: &DigestResponse,
    ha1: &str,
) -> Option<String> {
    match effective_stored_ha1_for_digest(dr, ha1) {
        Ok(h) => Some(h),
        Err(EffectiveHa1Error::MissingCnonce) => {
            tracing::warn!(username = %dr.username, "REGISTER digest -sess without cnonce");
            respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
            None
        }
        Err(e) => {
            tracing::warn!(%e, username = %dr.username, "REGISTER digest HA1 derive");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            None
        }
    }
}

async fn invalidate_register_nonce_after_forbid(redis: &RedisPool, dr: &DigestResponse, msg: &str) {
    if let Err(e) = invalidate_register_nonce(redis, &dr.nonce).await {
        tracing::warn!(%e, message = %msg, "register invalidate nonce");
    }
}

async fn register_enforce_digest_nc(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    dr: &DigestResponse,
) -> anyhow::Result<bool> {
    let Some(nc_new) = dr.nc_as_u64() else {
        return Ok(true);
    };
    let nc_key = register_digest_nonce_nc_key(&dr.nonce);
    let Some(nc_prev) = register_previous_nc(socket, redis, peer, req, &nc_key).await? else {
        return Ok(false);
    };
    if let Err(nc_err) = validate_nc(nc_new, nc_prev) {
        tracing::warn!(?nc_err, nonce = %dr.nonce, "register nc replay");
        invalidate_register_nonce_after_forbid(redis, dr, "register invalidate nonce (nc replay)")
            .await;
        respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
        return Ok(false);
    }
    register_store_nc(socket, redis, cfg, peer, req, &nc_key, nc_new).await
}

async fn register_previous_nc(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    peer: SocketAddr,
    req: &Request,
    nc_key: &str,
) -> anyhow::Result<Option<u64>> {
    match redis.get::<Option<String>, _>(nc_key).await {
        Ok(Some(s)) => match s.parse::<u64>() {
            Ok(v) => Ok(Some(v)),
            Err(pe) => {
                tracing::warn!(%pe, %nc_key, nc_raw = %s, "register redis nc value is not a decimal u64");
                respond(
                    socket,
                    peer,
                    &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
                )
                .await;
                Ok(None)
            }
        },
        Ok(None) => Ok(Some(0)),
        Err(e) => {
            tracing::warn!(%e, "register redis (nc get)");
            respond(socket, peer, &overload_response(req, 30)).await;
            Ok(None)
        }
    }
}

async fn register_store_nc(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    nc_key: &str,
    nc_new: u64,
) -> anyhow::Result<bool> {
    let nc_set: Result<Option<String>, _> = redis
        .set(
            nc_key,
            nc_new.to_string(),
            Some(Expiration::EX(cfg.nonce_ttl_s.max(1) as i64)),
            None,
            false,
        )
        .await;
    match nc_set {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!(%e, %nc_key, nc_new, "register redis (nc set); aborting REGISTER to avoid nc replay window");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_store_binding(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    peer: SocketAddr,
    req: &Request,
    dom: &str,
    user: &str,
    binding: &ContactBinding,
    expires: u32,
    dr: &DigestResponse,
) -> anyhow::Result<bool> {
    if let Err(e) = upsert_contact(redis, dom, user, binding, expires as i64).await {
        tracing::warn!(%e, "register upsert");
        respond(
            socket,
            peer,
            &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
        )
        .await;
        return Ok(false);
    }
    if let Err(e) = invalidate_register_nonce(redis, &dr.nonce).await {
        tracing::warn!(%e, "register invalidate nonce after upsert");
    }
    Ok(true)
}

async fn respond(socket: &tokio::net::UdpSocket, peer: SocketAddr, msg: &SipMessage) {
    let _ = socket.send_to(&serialize_message(msg), peer).await;
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

    match verify_identity_header(&identity_val, &cfg.cert_cache).await {
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
                StirError::CertFetch(_) | StirError::CertParse(_) => StatusCode::BAD_IDENTITY_INFO,
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

fn sip_response(req: &Request, status: StatusCode) -> SipMessage {
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
    headers.push(Header::ContentLength(0));
    SipMessage::Response(Response {
        version: SipVersion::V2_0,
        status,
        reason: status.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    })
}

fn simple_ok(req: &Request) -> Response {
    let mut headers = Vec::new();
    for h in &req.headers {
        match h {
            Header::Via(_)
            | Header::From(_)
            | Header::To(_)
            | Header::CallId(_)
            | Header::CSeq(_)
            | Header::Contact(_) => headers.push(h.clone()),
            _ => {}
        }
    }
    headers.push(Header::ContentLength(0));
    Response {
        version: SipVersion::V2_0,
        status: StatusCode::OK,
        reason: StatusCode::OK.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    }
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
    use sipora_sip::types::header::{CSeq, NameAddr, RportParam};
    use sqlx::postgres::PgPoolOptions;
    use std::time::Instant;

    #[test]
    fn parse_sip_user_host_accepts_ipv6_literal_without_user() {
        let parsed = parse_sip_user_host("sip:[2001:db8::1]:5070");

        assert_eq!(
            parsed,
            Some(("".to_string(), "[2001:db8::1]:5070".to_string()))
        );
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
            select_register_stored_ha1(&credentials, sipora_auth::digest::DigestAlgorithm::Md5),
            Some("md5-ha1")
        );
        assert_eq!(
            select_register_stored_ha1(&credentials, sipora_auth::digest::DigestAlgorithm::Md5Sess),
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
            select_register_stored_ha1(&credentials, sipora_auth::digest::DigestAlgorithm::Sha256,),
            Some("sha256-ha1")
        );
        assert_eq!(
            select_register_stored_ha1(
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
            register_challenge_algorithms(Some(&credentials)),
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
            register_challenge_algorithms(Some(&credentials)),
            vec![DigestAlgorithm::Md5]
        );
    }

    #[test]
    fn sha256_attempt_for_md5_only_user_rechallenges_with_md5() {
        let credentials = sipora_data::pg::SipDigestCredentials {
            sip_digest_ha1: Some("md5-ha1".to_string()),
            sip_digest_ha1_sha256: None,
        };

        assert!(should_rechallenge_md5_only(
            Some(&credentials),
            DigestAlgorithm::Sha256
        ));
        assert!(!should_rechallenge_md5_only(
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
            },
            ContactBinding {
                uri: "sip:bob@127.0.0.1:5097".to_string(),
                q_value: 0.5,
                expires: 300,
            },
        ];

        let selected = select_initial_invite_target(&invite_request(), contacts).await;

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
        }];

        let selected = select_initial_invite_target(&req, contacts).await;

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

        forward_invite_request(
            &socket,
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
    async fn forward_next_fork_sends_invite_to_remaining_target() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let table = new_forward_table();
        let cfg = test_cfg();
        let pending = PendingForward {
            client_addr: "127.0.0.1:5090".parse().unwrap(),
            target_addr,
            original_via_stack: vec![],
            original_request: Some(invite_request()),
            remaining_targets: vec![format!("sip:bob@{target_addr}")],
            forwarded_uri: format!("sip:bob@{target_addr}"),
            final_forwarded: false,
            inserted_at: Instant::now(),
            last_reliable_rseq: None,
        };

        let transaction_table = new_transaction_table();
        forward_next_fork(&socket, &cfg, &table, &transaction_table, pending)
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
        forward_initial_invite(
            &socket,
            &table,
            &transaction_table,
            &fork_table,
            &cfg,
            "127.0.0.1:5090".parse().unwrap(),
            invite_request(),
            InitialInviteRoute {
                target_uri: format!("sip:bob@{first_addr}"),
                target: first_addr,
                remaining_targets: vec![format!("sip:bob@{second_addr}")],
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
        forward_initial_invite(
            &socket,
            &table,
            &transaction_table,
            &fork_table,
            &cfg,
            "127.0.0.1:5090".parse().unwrap(),
            invite_request(),
            InitialInviteRoute {
                target_uri: format!("sip:bob@{first_addr}"),
                target: first_addr,
                remaining_targets: vec![format!("sip:bob@{second_addr}")],
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
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            proxy_response("z9hG4bK-a", StatusCode::NOT_FOUND),
        )
        .await
        .unwrap();
        assert_no_datagram(&client).await;

        dispatch_response(
            &socket,
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            proxy_response("z9hG4bK-a", StatusCode::OK),
        )
        .await
        .unwrap();
        assert_eq!(recv_response(&client).await.status, StatusCode::OK);

        dispatch_response(
            &socket,
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
            &cfg,
            &table,
            &new_fork_table(),
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            proxy_response("z9hG4bK-a", StatusCode::OK),
        )
        .await
        .unwrap();
        assert_eq!(recv_response(&client).await.status, StatusCode::OK);

        dispatch_response(
            &socket,
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
            proxy_response("z9hG4bK-a", StatusCode::OK),
        )
        .await
        .unwrap();
        assert_eq!(recv_response(&client).await.status, StatusCode::OK);

        dispatch_response(
            &socket,
            &cfg,
            &table,
            &fork_table,
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
            &cfg,
            &table,
            &new_fork_table(),
            &crate::dialog::new_dialog_table(),
            &new_transaction_table(),
            &crate::dialog::new_refresh_table(),
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
