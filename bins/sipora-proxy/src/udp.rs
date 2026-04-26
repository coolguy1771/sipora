//! UDP registrar and request-only SIP handling. INVITE is forwarded without response relay;
//! see `AGENTS.md` ("SIP signaling scope") and `docs/qualification.md` for end-to-end INVITE paths.

use fred::prelude::{Expiration, KeysInterface, LuaInterface, SetOptions};
use sipora_auth::digest::{DigestChallenge, DigestResponse, verify_digest};
use sipora_core::redis::RedisPool;
use sipora_core::redis_keys::{
    LUA_REGISTER_COMMIT_LOCK_DELETE_IF_MATCH, register_commit_lock_key, register_digest_nonce_key,
    register_transaction_ok_key,
};
use sipora_data::pg::get_user_sip_digest_ha1;
use sipora_location::ContactBinding;
use sipora_location::redis_store::{list_contact_uris, upsert_contact};
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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
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

/// Static UDP proxy configuration (per process).
pub struct UdpProxyConfig {
    pub domain: String,
    pub advertise: String,
    pub sip_port: u16,
    pub max_forwards: u8,
    pub registrar: RegistrarLimits,
    pub nonce_ttl_s: u64,
    pub pg: PgPool,
}

pub type TransactionTable = Arc<RwLock<TransactionManager>>;

pub fn new_transaction_table() -> TransactionTable {
    Arc::new(RwLock::new(TransactionManager::new()))
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
    let _forward_sweeper = spawn_forward_sweeper(forward_table.clone(), shutdown.clone());
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
    refresh_table: &RefreshTable,
    peer: SocketAddr,
    mut req: Request,
) -> anyhow::Result<()> {
    apply_rfc3581(&mut req, peer);
    if let Some(status) = enforce_sips_policy(&req) {
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

async fn dispatch_response(
    socket: &Arc<tokio::net::UdpSocket>,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    dialog_table: &DialogTable,
    transaction_table: &TransactionTable,
    refresh_table: &RefreshTable,
    mut resp: Response,
) -> anyhow::Result<()> {
    let Some(top_via) = response_top_via(&resp) else {
        return Ok(());
    };
    if !via_matches_proxy(top_via, &cfg.advertise, cfg.sip_port) {
        return Ok(());
    }
    let branch = top_via.branch.clone();
    if branch.is_empty() {
        return Ok(());
    }
    remove_client_transaction(transaction_table, &resp).await;

    let pending = get_pending_forward(forward_table, &branch).await;
    if should_try_next_fork(&resp, pending.as_ref()) {
        let Some(pending) = pending else {
            return Ok(());
        };
        let _ = prepare_response(forward_table, &branch, &mut resp).await;
        return forward_next_fork(socket, cfg, forward_table, transaction_table, pending).await;
    }

    let first_success = pending
        .as_ref()
        .is_some_and(|p| resp.status.is_success() && !p.final_forwarded);
    let Some(mut target) = prepare_response(forward_table, &branch, &mut resp).await else {
        return Ok(());
    };
    if let Some(via) = response_top_via(&resp) {
        target = response_relay_addr(via).unwrap_or(target);
    }
    if first_success && let Some(pending) = pending {
        let session_expires = resp.headers.iter().find_map(|h| match h {
            Header::SessionExpires { delta_seconds, .. } => Some(*delta_seconds),
            _ => None,
        });
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
) -> anyhow::Result<()> {
    let Some(original_request) = pending.original_request.clone() else {
        return Ok(());
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
        return forward_invite_request(
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
        .await;
    }
    Ok(())
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
        respond(
            socket,
            peer,
            &sip_response(&req, StatusCode::SERVICE_UNAVAILABLE),
        )
        .await;
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
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    // RFC 3261 §17.2.1: send 100 Trying immediately on INVITE receipt
    respond(socket, peer, &sip_response(&req, StatusCode::TRYING)).await;
    // RFC 4028 §8: reject if Session-Expires is below proxy minimum
    if check_session_expires(&req).is_some() {
        respond(socket, peer, &sip_response_with_min_se(&req, PROXY_MIN_SE)).await;
        return Ok(());
    }
    if router.check_max_forwards(&req).is_some() {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::too_many_hops_response(&req)),
        )
        .await;
        return Ok(());
    }
    let Some((user, dom)) = parse_sip_user_host(&req.uri) else {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    };
    let dom = normalize_domain(dom, &cfg.domain);
    let contacts = match list_contact_uris(pool, &dom, &user).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "location lookup");
            respond(
                socket,
                peer,
                &SipMessage::Response(ProxyRouter::service_unavailable(&req, 30)),
            )
            .await;
            return Ok(());
        }
    };
    if contacts.is_empty() {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    }
    let mut contacts = contacts;
    contacts.sort_by(|a, b| {
        b.q_value
            .partial_cmp(&a.q_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let target_uri = contacts[0].uri.clone();
    let remaining_targets = contacts.iter().skip(1).map(|c| c.uri.clone()).collect();
    let Some(target) = resolve_udp_target(&target_uri).await else {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::service_unavailable(&req, 30)),
        )
        .await;
        return Ok(());
    };
    let original_request = req.clone();
    forward_invite_request(
        socket,
        forward_table,
        transaction_table,
        peer,
        req,
        target_uri,
        target,
        Some(original_request),
        remaining_targets,
        &cfg.advertise,
        cfg.sip_port,
    )
    .await
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
) -> anyhow::Result<()> {
    req.uri = target_uri;
    let branch = format!("z9hG4bK{}", Uuid::new_v4().as_simple());
    let original_via_stack = collect_via_stack(&req.headers);
    let via = Header::Via(Via {
        transport: Transport::Udp,
        host: advertise.to_string(),
        port: Some(sip_port),
        branch: branch.clone(),
        received: None,
        rport: sipora_sip::types::header::RportParam::Absent,
        params: vec![],
    });
    let record_route = Header::RecordRoute(vec![format!("<sip:{advertise}:{sip_port};lr>")]);
    let mut headers = vec![via, record_route];
    headers.extend(req.headers);
    req.headers = headers;
    ProxyRouter::decrement_max_forwards(&mut req.headers);
    // Extract transaction key before req is consumed by serialization
    let tx_key = TransactionKey::from_request(&req);
    insert_forward(
        forward_table,
        branch,
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
    // Spawn RFC 3261 §17.1.1.2 Timer A: retransmit INVITE at T1, 2T1, 4T1, … capped at T2
    let socket_arc = Arc::clone(socket);
    let timer = tokio::spawn(async move {
        let mut delay = sipora_sip::transaction::TIMER_T1;
        loop {
            tokio::time::sleep(delay).await;
            if socket_arc.send_to(&bytes, target).await.is_err() {
                return;
            }
            delay = (delay * 2).min(sipora_sip::transaction::TIMER_T2);
        }
    });
    if let Some(key) = tx_key {
        transaction_table.write().await.insert_with_timer(
            key,
            TransactionType::ClientInvite,
            timer.abort_handle(),
        );
    } else {
        timer.abort();
    }
    Ok(())
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

fn sip_response_www_auth(req: &Request, www: &str) -> SipMessage {
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
    headers.push(Header::WwwAuthenticate(www.to_owned()));
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
fn enforce_sips_policy(req: &Request) -> Option<StatusCode> {
    if req.uri.starts_with("sips:") {
        Some(StatusCode::FORBIDDEN)
    } else {
        None
    }
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
            Header::From(_) | Header::To(_) | Header::CallId(_) => headers.push(h.clone()),
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
        None => register_send_digest_challenge(socket, redis, cfg, peer, &req, &dom).await,
        Some(auth_raw) => {
            register_complete_digest(
                socket, redis, cfg, peer, &req, &user, &dom, &binding, expires, auth_raw,
            )
            .await
        }
    }
}

async fn register_send_digest_challenge(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: &Request,
    realm: &str,
) -> anyhow::Result<()> {
    let nonce = Uuid::new_v4().simple().to_string();
    if let Err(e) = store_register_nonce(redis, &nonce, cfg.nonce_ttl_s).await {
        tracing::warn!(%e, "register nonce");
        respond(
            socket,
            peer,
            &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
        )
        .await;
        return Ok(());
    }
    let ch = DigestChallenge::new(realm, &nonce);
    respond(
        socket,
        peer,
        &sip_response_www_auth(req, &ch.to_www_authenticate()),
    )
    .await;
    Ok(())
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
            respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
            Ok(())
        }
        Ok(true) => {
            register_commit_digest(
                socket, redis, cfg, peer, req, dom, user, binding, expires, &dr, call_id, cseq_n,
            )
            .await
        }
        Err(e) => {
            tracing::warn!(%e, "register redis (nonce exists)");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVICE_UNAVAILABLE),
            )
            .await;
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
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVICE_UNAVAILABLE),
            )
            .await;
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
                    respond(
                        socket,
                        peer,
                        &sip_response(req, StatusCode::SERVICE_UNAVAILABLE),
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(%e, "register redis (tx ok after lock miss)");
                    respond(
                        socket,
                        peer,
                        &sip_response(req, StatusCode::SERVICE_UNAVAILABLE),
                    )
                    .await;
                }
            }
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!(%e, "register redis (commit lock)");
            respond(
                socket,
                peer,
                &sip_response(req, StatusCode::SERVICE_UNAVAILABLE),
            )
            .await;
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
    let ha1 = match get_user_sip_digest_ha1(&cfg.pg, &dr.username, dom).await {
        Ok(h) => h,
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
    let Some(ha1) = ha1 else {
        tracing::warn!(
            username = %dr.username,
            realm = %dr.realm,
            "REGISTER digest: missing sip_digest_ha1 (migrate DB or POST /api/v1/users)"
        );
        if let Err(e) = invalidate_register_nonce(redis, &dr.nonce).await {
            tracing::warn!(%e, "register invalidate nonce");
        }
        respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
        return Ok(());
    };
    if !verify_digest(dr, &ha1, "REGISTER") {
        if let Err(e) = invalidate_register_nonce(redis, &dr.nonce).await {
            tracing::warn!(%e, "register invalidate nonce");
        }
        respond(socket, peer, &sip_response(req, StatusCode::FORBIDDEN)).await;
        return Ok(());
    }

    if let Err(e) = upsert_contact(redis, dom, user, binding, expires as i64).await {
        tracing::warn!(%e, "register upsert");
        respond(
            socket,
            peer,
            &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
        )
        .await;
        return Ok(());
    }
    if let Err(e) = invalidate_register_nonce(redis, &dr.nonce).await {
        tracing::warn!(%e, "register invalidate nonce after upsert");
    }
    if let Err(e) = mark_register_tx_ok(redis, call_id, cseq_n).await {
        tracing::warn!(%e, "register tx ok marker");
    }
    respond(socket, peer, &SipMessage::Response(simple_ok(req))).await;
    Ok(())
}

async fn respond(socket: &tokio::net::UdpSocket, peer: SocketAddr, msg: &SipMessage) {
    let _ = socket.send_to(&serialize_message(msg), peer).await;
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
    let u = u.strip_prefix("sip:").or_else(|| u.strip_prefix("sips:"))?;
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

async fn resolve_udp_target(contact_uri: &str) -> Option<SocketAddr> {
    let (_, hostport) = parse_sip_user_host(contact_uri)?;
    let (host, port) = split_host_port(&hostport)?;
    resolve_sip_targets(&host, Some(port), SipTransport::Udp)
        .await
        .into_iter()
        .next()
        .map(|target| target.addr)
}

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
            pg: PgPoolOptions::new()
                .connect_lazy("postgres://localhost/sipora")
                .unwrap(),
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
