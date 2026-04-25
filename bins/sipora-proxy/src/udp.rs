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
use sipora_sip::types::header::{Header, Transport, Via};
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;
use sipora_transport::udp::UdpTransport;
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::watch;
use uuid::Uuid;

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

pub async fn run_udp_proxy(
    addr: SocketAddr,
    redis: RedisPool,
    cfg: UdpProxyConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let udp = UdpTransport::bind(addr).await?;
    let socket = udp.into_inner();
    let router = ProxyRouter::new(cfg.max_forwards);
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
                let SipMessage::Request(req) = msg else {
                    continue;
                };
                if let Err(e) = dispatch_request(
                    &socket,
                    &redis,
                    &router,
                    &cfg,
                    peer,
                    req,
                )
                .await
                {
                    tracing::warn!(%peer, "udp proxy: {e}");
                }
            }
        }
    }
}

async fn dispatch_request(
    socket: &tokio::net::UdpSocket,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    match req.method {
        Method::Invite => handle_invite(socket, redis, router, cfg, peer, req).await,
        Method::Register => handle_register(socket, redis, cfg, peer, req).await,
        Method::Bye | Method::Cancel => {
            respond(socket, peer, &sip_response(&req, StatusCode::OK)).await;
            Ok(())
        }
        Method::Options => {
            respond(socket, peer, &sip_options_ok(&req)).await;
            Ok(())
        }
        Method::Ack => Ok(()),
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

async fn handle_invite(
    socket: &tokio::net::UdpSocket,
    pool: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
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
    let target_uri = contacts[0].uri.clone();
    let Some(target) = resolve_udp_target(&target_uri).await else {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::service_unavailable(&req, 30)),
        )
        .await;
        return Ok(());
    };
    forward_invite_request(
        socket,
        req,
        target_uri,
        target,
        &cfg.advertise,
        cfg.sip_port,
    )
    .await
}

async fn forward_invite_request(
    socket: &tokio::net::UdpSocket,
    mut req: Request,
    target_uri: String,
    target: SocketAddr,
    advertise: &str,
    sip_port: u16,
) -> anyhow::Result<()> {
    req.uri = target_uri;
    let branch = format!("z9hG4bK{}", Uuid::new_v4().as_simple());
    let via = Header::Via(Via {
        transport: Transport::Udp,
        host: advertise.to_string(),
        port: Some(sip_port),
        branch,
        received: None,
        rport: sipora_sip::types::header::RportParam::Absent,
        params: vec![],
    });
    let mut headers = vec![via];
    headers.extend(req.headers);
    req.headers = headers;
    ProxyRouter::decrement_max_forwards(&mut req.headers);
    let bytes = serialize_message(&SipMessage::Request(req));
    socket.send_to(&bytes, target).await?;
    Ok(())
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
    let at = u.find('@')?;
    let user = u[..at].to_string();
    let rest = u[at + 1..].to_string();
    Some((user, rest))
}

async fn resolve_udp_target(contact_uri: &str) -> Option<SocketAddr> {
    let (_, hostport) = parse_sip_user_host(contact_uri)?;
    let (host, port) = split_host_port(&hostport)?;
    let mut it = tokio::net::lookup_host((host.as_str(), port)).await.ok()?;
    it.next()
}

fn split_host_port(rest: &str) -> Option<(String, u16)> {
    match rest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => Some((h.to_string(), port)),
            Err(_) => Some((rest.to_string(), 5060)),
        },
        None => Some((rest.to_string(), 5060)),
    }
}
