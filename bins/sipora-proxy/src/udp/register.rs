//! REGISTER digest, binding upsert, and push replay after successful registration.

use fred::prelude::{Expiration, KeysInterface, LuaInterface, SetOptions};
use sipora_auth::digest::{
    DigestAlgorithm, DigestChallenge, DigestResponse, EffectiveHa1Error,
    effective_stored_ha1_for_digest, validate_nc, verify_digest,
};
use sipora_core::redis::RedisPool;
use sipora_core::redis_keys::{
    LUA_REGISTER_COMMIT_LOCK_DELETE_IF_MATCH, register_commit_lock_key, register_digest_nonce_key,
    register_digest_nonce_nc_key, register_transaction_ok_key,
};
use sipora_data::pg::{SipDigestCredentials, get_user_sip_digest_credentials};
use sipora_location::ContactBinding;
use sipora_location::gruu;
use sipora_location::redis_store::upsert_contact;
use sipora_sip::overload::overload_response;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::types::header::{ContactValue, Header};
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;
use std::sync::Arc;
use uuid::Uuid;

use crate::dialog::DialogTable;
use crate::forward_table::ForwardTable;
use crate::ingress::ProxyIngress;
use crate::message_sender::MessageSender;
use crate::responses::{simple_ok, sip_response, sip_response_multi_www_auth};
use crate::routing::ProxyRouter;

use super::{
    ForkTable, TransactionTable, UdpProxyConfig, handle_invite, normalize_domain,
    parse_sip_user_host,
};

/// Stable non-identifying tag for logs (SHA-256 hex prefix of username bytes).
fn username_log_tag(username: &str) -> String {
    use core::fmt::Write;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(username.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest.iter() {
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex.truncate(16);
    format!("u#{hex}")
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

pub(super) async fn store_register_nonce(
    redis: &RedisPool,
    nonce: &str,
    ttl_s: u64,
) -> anyhow::Result<()> {
    let key = register_digest_nonce_key(nonce);
    let ttl = ttl_s.max(1) as i64;
    let _: Option<String> = redis
        .set(&key, "1", Some(Expiration::EX(ttl)), None, false)
        .await?;
    Ok(())
}

pub(super) async fn register_nonce_exists(redis: &RedisPool, nonce: &str) -> anyhow::Result<bool> {
    let key = register_digest_nonce_key(nonce);
    let n: i64 = redis.exists(&key).await?;
    Ok(n > 0)
}

pub(super) async fn invalidate_register_nonce(
    redis: &RedisPool,
    nonce: &str,
) -> anyhow::Result<()> {
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

#[allow(clippy::too_many_arguments)]
async fn replay_push_pending_invites_after_register(
    socket: Arc<tokio::net::UdpSocket>,
    sip_sender: Arc<dyn MessageSender>,
    tcp_for_merge: Option<Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    dom: &str,
    user: &str,
) {
    let drained = match crate::push::drain_pending_invite_replays(redis, dom, user).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(%e, "push pending drain");
            return;
        }
    };
    for (bytes, reply) in drained {
        let Some(ing) = crate::push::replay_ingress_from_spec(
            socket.clone(),
            sip_sender.clone(),
            tcp_for_merge.clone(),
            &reply,
        ) else {
            tracing::warn!("push replay: bad ingress spec");
            continue;
        };
        let Ok((_, msg)) = parse_sip_message(&bytes) else {
            tracing::warn!("push replay: parse");
            continue;
        };
        let SipMessage::Request(inv) = msg else {
            continue;
        };
        if let Err(e) = handle_invite(
            &ing,
            &sip_sender,
            redis,
            router,
            cfg,
            forward_table,
            transaction_table,
            fork_table,
            dialog_table,
            inv,
        )
        .await
        {
            tracing::warn!(%e, "push replay handle_invite");
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_register(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    tcp_for_merge: Option<&Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
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
    let contacts = req.contacts();
    let Some(contact) = contacts.first() else {
        crate::ingress::respond(ingress, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let reg = &cfg.registrar;
    let expires = req
        .expires()
        .unwrap_or(reg.default_expires)
        .clamp(reg.min_expires, reg.max_expires);
    let binding = binding_from_register(contact, &req, &dom, &user, expires);

    match register_authorization_value(&req) {
        None => register_send_digest_challenge(ingress, redis, cfg, &req, &user, &dom, false).await,
        Some(auth_raw) => {
            register_complete_digest(
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
                &req,
                &user,
                &dom,
                &binding,
                expires,
                auth_raw,
            )
            .await
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn register_send_digest_challenge(
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
            tracing::warn!(%e, "register db");
            crate::ingress::respond(
                ingress,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
    };
    let algorithms = register_challenge_algorithms(credentials.as_ref());
    register_send_digest_challenge_with_algorithms(
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

pub(super) fn register_challenge_algorithms(
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
        if let Err(e) = store_register_nonce(redis, &nonce, cfg.nonce_ttl_s).await {
            rollback_register_challenge_nonces(redis, &stored_nonces).await;
            tracing::warn!(%e, "register nonce store");
            crate::ingress::respond(
                ingress,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(());
        }
        match register_challenge_header(*algorithm, realm, &nonce, stale) {
            Ok(header) => {
                challenges.push(header);
                stored_nonces.push(nonce);
            }
            Err(e) => {
                if let Err(r) = invalidate_register_nonce(redis, &nonce).await {
                    tracing::warn!(%r, %nonce, "register nonce rollback after challenge header error");
                }
                rollback_register_challenge_nonces(redis, &stored_nonces).await;
                tracing::warn!(
                    %e,
                    algorithm = %algorithm.as_str(),
                    "register challenge header"
                );
                crate::ingress::respond(
                    ingress,
                    &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
                )
                .await;
                return Ok(());
            }
        }
    }
    crate::ingress::respond(ingress, &sip_response_multi_www_auth(req, &challenges)).await;
    Ok(())
}

pub(super) async fn rollback_register_challenge_nonces(redis: &RedisPool, nonces: &[String]) {
    for nonce in nonces {
        if let Err(e) = invalidate_register_nonce(redis, nonce).await {
            tracing::warn!(%e, %nonce, "register nonce rollback after store failure");
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RegisterChallengeHeaderError;

impl std::fmt::Display for RegisterChallengeHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session digest algorithm not supported for REGISTER challenge"
        )
    }
}

impl std::error::Error for RegisterChallengeHeaderError {}

pub(super) fn register_challenge_header(
    algorithm: DigestAlgorithm,
    realm: &str,
    nonce: &str,
    stale: bool,
) -> Result<String, RegisterChallengeHeaderError> {
    let challenge = match algorithm {
        DigestAlgorithm::Sha256 => DigestChallenge::new_sha256(realm, nonce),
        DigestAlgorithm::Md5 => DigestChallenge::new_md5(realm, nonce),
        DigestAlgorithm::Md5Sess | DigestAlgorithm::Sha256Sess => {
            return Err(RegisterChallengeHeaderError);
        }
    };
    Ok(challenge.with_stale(stale).to_www_authenticate())
}

fn register_call_id_cseq(req: &Request) -> Option<(&str, u32)> {
    let call_id = req.call_id()?;
    let cs = req.cseq()?;
    (cs.method == Method::Register).then_some((call_id, cs.seq))
}

#[allow(clippy::too_many_arguments)]
async fn register_digest_commit_after_lock(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    tcp_for_merge: Option<&Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
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
        crate::ingress::respond(ingress, &sip_response(req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    if !dr.username.eq_ignore_ascii_case(user) || !dr.realm.eq_ignore_ascii_case(dom) {
        crate::ingress::respond(ingress, &sip_response(req, StatusCode::FORBIDDEN)).await;
        return Ok(());
    }
    match register_nonce_exists(redis, &dr.nonce).await {
        Ok(false) => {
            // Nonce expired (TTL elapsed) — re-challenge with stale=TRUE so the UA
            // retries with a fresh nonce without prompting for credentials (RFC 2617 §3.3).
            register_send_digest_challenge(ingress, redis, cfg, req, &dr.username, dom, true).await
        }
        Ok(true) => {
            register_commit_digest(
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
                dom,
                user,
                binding,
                expires,
                &dr,
                call_id,
                cseq_n,
            )
            .await
        }
        Err(e) => {
            tracing::warn!(%e, "register redis (nonce exists)");
            crate::ingress::respond(ingress, &overload_response(req, 30)).await;
            Ok(())
        }
    }
}

/// `Ok(None)` if the request was fully answered (idempotent 200 or 503).
/// `Ok(Some((lock_key, token)))` if the caller holds the commit lock (release with CAS del).
async fn register_try_acquire_commit_lock(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    req: &Request,
    call_id: &str,
    cseq_n: u32,
) -> anyhow::Result<Option<(String, String)>> {
    match register_tx_ok_exists(redis, call_id, cseq_n).await {
        Ok(true) => {
            crate::ingress::respond(ingress, &simple_ok(req)).await;
            return Ok(None);
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(%e, "register redis (tx ok exists)");
            crate::ingress::respond(ingress, &overload_response(req, 30)).await;
            return Ok(None);
        }
    }

    let lock_key = register_commit_lock_key(call_id, cseq_n);
    let lock_token = match try_register_commit_lock(redis, &lock_key).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            match register_tx_ok_exists(redis, call_id, cseq_n).await {
                Ok(true) => {
                    crate::ingress::respond(ingress, &simple_ok(req)).await;
                }
                Ok(false) => {
                    tracing::warn!("register redis (tx ok false after lock miss; commit pending)");
                    crate::ingress::respond(ingress, &overload_response(req, 30)).await;
                }
                Err(e) => {
                    tracing::warn!(%e, "register redis (tx ok after lock miss)");
                    crate::ingress::respond(ingress, &overload_response(req, 30)).await;
                }
            }
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!(%e, "register redis (commit lock)");
            crate::ingress::respond(ingress, &overload_response(req, 30)).await;
            return Ok(None);
        }
    };

    Ok(Some((lock_key, lock_token)))
}

#[allow(clippy::too_many_arguments)] // REGISTER digest + binding; refactor into a ctx struct if extended.
async fn register_complete_digest(
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    tcp_for_merge: Option<&Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    req: &Request,
    user: &str,
    dom: &str,
    binding: &ContactBinding,
    expires: u32,
    auth_raw: &str,
) -> anyhow::Result<()> {
    let Some((call_id, cseq_n)) = register_call_id_cseq(req) else {
        crate::ingress::respond(ingress, &sip_response(req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };

    let (lock_key, lock_token) =
        match register_try_acquire_commit_lock(ingress, redis, req, call_id, cseq_n).await? {
            Some(pair) => pair,
            None => return Ok(()),
        };

    let commit_res = register_digest_commit_after_lock(
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
        user,
        dom,
        binding,
        expires,
        auth_raw,
        call_id,
        cseq_n,
    )
    .await;

    release_register_commit_lock(redis, &lock_key, &lock_token).await;
    commit_res
}

pub(crate) fn select_register_stored_ha1(
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
    ingress: &ProxyIngress,
    sip_sender: &Arc<dyn MessageSender>,
    redis: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    forward_table: &ForwardTable,
    transaction_table: &TransactionTable,
    fork_table: &ForkTable,
    dialog_table: &DialogTable,
    tcp_for_merge: Option<&Arc<sipora_transport::tcp_pool::TcpConnectionPool>>,
    req: &Request,
    dom: &str,
    user: &str,
    binding: &ContactBinding,
    expires: u32,
    dr: &DigestResponse,
    call_id: &str,
    cseq_n: u32,
) -> anyhow::Result<()> {
    if !register_digest_verified(ingress, redis, cfg, req, dom, dr, "REGISTER").await? {
        return Ok(());
    }
    if !register_enforce_digest_nc(ingress, redis, cfg, req, dr).await? {
        return Ok(());
    }
    let mut store_binding = binding.clone();
    store_binding.last_register_unix = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    if !register_store_binding(ingress, redis, req, dom, user, &store_binding, expires, dr).await? {
        return Ok(());
    }
    if let Err(e) = mark_register_tx_ok(redis, call_id, cseq_n).await {
        tracing::warn!(%e, "register tx ok marker");
    }
    let contacts_h = req.contacts();
    let Some(contact_in) = contacts_h.first() else {
        crate::ingress::respond(ingress, &sip_response(req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    crate::ingress::respond(
        ingress,
        &SipMessage::Response(register_success_response(
            req,
            contact_in,
            &store_binding,
            expires,
            cfg,
        )),
    )
    .await;
    replay_push_pending_invites_after_register(
        ingress.socket.clone(),
        sip_sender.clone(),
        tcp_for_merge.cloned(),
        redis,
        router,
        cfg,
        forward_table,
        transaction_table,
        fork_table,
        dialog_table,
        dom,
        user,
    )
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn register_digest_verified(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
    dom: &str,
    dr: &DigestResponse,
    sip_method: &str,
) -> anyhow::Result<bool> {
    let credentials = match get_user_sip_digest_credentials(&cfg.pg, &dr.username, dom).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            register_missing_selected_ha1(ingress, redis, cfg, req, dom, dr, None).await?;
            return Ok(false);
        }
        Err(e) => {
            tracing::warn!(%e, "register db");
            crate::ingress::respond(
                ingress,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            return Ok(false);
        }
    };
    let Some(ha1) = select_register_stored_ha1(&credentials, dr.algorithm) else {
        register_missing_selected_ha1(ingress, redis, cfg, req, dom, dr, Some(&credentials))
            .await?;
        return Ok(false);
    };
    let Some(ha1_verify) = register_effective_ha1(ingress, req, dr, ha1).await else {
        return Ok(false);
    };
    if verify_digest(dr, &ha1_verify, sip_method) {
        return Ok(true);
    }
    invalidate_register_nonce_after_forbid(redis, dr, "register invalidate nonce").await;
    crate::ingress::respond(ingress, &sip_response(req, StatusCode::FORBIDDEN)).await;
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
async fn register_missing_selected_ha1(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
    realm: &str,
    dr: &DigestResponse,
    credentials: Option<&SipDigestCredentials>,
) -> anyhow::Result<()> {
    tracing::warn!(
        algorithm = %dr.algorithm.as_str(),
        username = %username_log_tag(&dr.username),
        realm = %dr.realm,
        "REGISTER digest: missing HA1 for selected digest algorithm"
    );
    invalidate_register_nonce_after_forbid(redis, dr, "register invalidate nonce").await;
    if should_rechallenge_md5_only(credentials, dr.algorithm) {
        return register_send_digest_challenge_with_algorithms(
            ingress,
            redis,
            cfg,
            req,
            realm,
            false,
            &[DigestAlgorithm::Md5],
        )
        .await;
    }
    crate::ingress::respond(ingress, &sip_response(req, StatusCode::FORBIDDEN)).await;
    Ok(())
}

pub(crate) fn should_rechallenge_md5_only(
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
    ingress: &ProxyIngress,
    req: &Request,
    dr: &DigestResponse,
    ha1: &str,
) -> Option<String> {
    match effective_stored_ha1_for_digest(dr, ha1) {
        Ok(h) => Some(h),
        Err(EffectiveHa1Error::MissingCnonce) => {
            tracing::warn!(
                username = %username_log_tag(&dr.username),
                "REGISTER digest -sess without cnonce"
            );
            crate::ingress::respond(ingress, &sip_response(req, StatusCode::FORBIDDEN)).await;
            None
        }
        Err(e) => {
            tracing::warn!(
                %e,
                username = %username_log_tag(&dr.username),
                "REGISTER digest HA1 derive"
            );
            crate::ingress::respond(
                ingress,
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

pub(super) async fn register_enforce_digest_nc(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
    req: &Request,
    dr: &DigestResponse,
) -> anyhow::Result<bool> {
    let Some(nc_new) = dr.nc_as_u64() else {
        return Ok(true);
    };
    let nc_key = register_digest_nonce_nc_key(&dr.nonce);
    let Some(nc_prev) = register_previous_nc(ingress, redis, req, &nc_key).await? else {
        return Ok(false);
    };
    if let Err(nc_err) = validate_nc(nc_new, nc_prev) {
        tracing::warn!(?nc_err, nonce = %dr.nonce, "register nc replay");
        invalidate_register_nonce_after_forbid(redis, dr, "register invalidate nonce (nc replay)")
            .await;
        crate::ingress::respond(ingress, &sip_response(req, StatusCode::FORBIDDEN)).await;
        return Ok(false);
    }
    register_store_nc(ingress, redis, cfg, req, &nc_key, nc_new).await
}

async fn register_previous_nc(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    req: &Request,
    nc_key: &str,
) -> anyhow::Result<Option<u64>> {
    match redis.get::<Option<String>, _>(nc_key).await {
        Ok(Some(s)) => match s.parse::<u64>() {
            Ok(v) => Ok(Some(v)),
            Err(pe) => {
                tracing::warn!(%pe, %nc_key, nc_raw = %s, "register redis nc value is not a decimal u64");
                crate::ingress::respond(
                    ingress,
                    &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
                )
                .await;
                Ok(None)
            }
        },
        Ok(None) => Ok(Some(0)),
        Err(e) => {
            tracing::warn!(%e, "register redis (nc get)");
            crate::ingress::respond(ingress, &overload_response(req, 30)).await;
            Ok(None)
        }
    }
}

async fn register_store_nc(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    cfg: &UdpProxyConfig,
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
            crate::ingress::respond(
                ingress,
                &sip_response(req, StatusCode::SERVER_INTERNAL_ERROR),
            )
            .await;
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_store_binding(
    ingress: &ProxyIngress,
    redis: &RedisPool,
    req: &Request,
    dom: &str,
    user: &str,
    binding: &ContactBinding,
    expires: u32,
    dr: &DigestResponse,
) -> anyhow::Result<bool> {
    if let Err(e) = upsert_contact(redis, dom, user, binding, expires as i64).await {
        tracing::warn!(%e, "register upsert");
        crate::ingress::respond(
            ingress,
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
fn collect_path_headers(req: &Request) -> Vec<String> {
    let mut out = Vec::new();
    for h in &req.headers {
        if let Header::Path(p) = h {
            out.extend(p.iter().cloned());
        }
    }
    out
}

fn sip_instance_from_contact(cv: &ContactValue) -> Option<String> {
    cv.params.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("+sip.instance") {
            v.as_ref().map(|s| s.trim_matches('"').to_string())
        } else {
            None
        }
    })
}

fn reg_id_from_contact(cv: &ContactValue) -> Option<u32> {
    cv.params.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("reg-id") {
            v.as_ref()?.parse().ok()
        } else {
            None
        }
    })
}

fn binding_from_register(
    contact: &ContactValue,
    req: &Request,
    domain: &str,
    user: &str,
    expires: u32,
) -> ContactBinding {
    let path = collect_path_headers(req);
    let sip_inst = sip_instance_from_contact(contact);
    let reg_id = reg_id_from_contact(contact);
    let (pub_gruu, temp_gruu) = match sip_inst.as_ref() {
        Some(inst) if !inst.is_empty() => (
            Some(gruu::compute_pub_gruu(domain, user, inst)),
            Some(gruu::new_temp_gruu(domain, user)),
        ),
        _ => (None, None),
    };
    ContactBinding {
        uri: contact.uri.clone(),
        q_value: contact.q_value(),
        expires,
        sip_instance: sip_inst,
        pub_gruu,
        temp_gruu,
        reg_id,
        path,
        ..Default::default()
    }
}

fn merge_register_contact(
    contact_in: &ContactValue,
    binding: &ContactBinding,
    expires: u32,
) -> ContactValue {
    let mut params = contact_in.params.clone();
    let upsert = |params: &mut Vec<(String, Option<String>)>, key: &str, val: &str| {
        let quoted = format!("\"{}\"", val.trim_matches('"'));
        if let Some((_, v)) = params.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            *v = Some(quoted);
        } else {
            params.push((key.to_string(), Some(quoted)));
        }
    };
    if let Some(ref pg) = binding.pub_gruu {
        upsert(&mut params, "pub-gruu", pg);
    }
    if let Some(ref tg) = binding.temp_gruu {
        upsert(&mut params, "temp-gruu", tg);
    }
    ContactValue {
        uri: contact_in.uri.clone(),
        q: contact_in.q.or(Some(binding.q_value)),
        expires: Some(expires),
        params,
    }
}

fn register_success_response(
    req: &Request,
    contact_in: &ContactValue,
    binding: &ContactBinding,
    expires: u32,
    cfg: &UdpProxyConfig,
) -> Response {
    let mut headers = Vec::new();
    for h in &req.headers {
        match h {
            Header::Via(_)
            | Header::From(_)
            | Header::To(_)
            | Header::CallId(_)
            | Header::CSeq(_) => headers.push(h.clone()),
            Header::Contact(_) => {}
            _ => {}
        }
    }
    let cv = merge_register_contact(contact_in, binding, expires);
    headers.push(Header::Contact(vec![cv]));
    if !binding.path.is_empty() {
        headers.push(Header::Path(binding.path.clone()));
    }
    if let Some(ref edge) = cfg.outbound_edge_uri {
        headers.push(Header::ServiceRoute(vec![edge.clone()]));
    }
    headers.push(Header::Expires(expires));
    headers.push(Header::ContentLength(0));
    Response {
        version: SipVersion::V2_0,
        status: StatusCode::OK,
        reason: StatusCode::OK.reason_phrase().to_owned(),
        headers,
        body: Vec::new(),
    }
}
