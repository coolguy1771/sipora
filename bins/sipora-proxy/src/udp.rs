use sipora_core::redis::RedisPool;
use sipora_location::ContactBinding;
use sipora_location::redis_store::{list_contact_uris, upsert_contact};
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::header::{Header, Transport, Via};
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;
use sipora_transport::udp::UdpTransport;
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
}

pub async fn run_udp_proxy(
    addr: SocketAddr,
    pool: RedisPool,
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
                    &pool,
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
    pool: &RedisPool,
    router: &ProxyRouter,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    match req.method {
        Method::Invite => handle_invite(socket, pool, router, cfg, peer, req).await,
        Method::Register => handle_register(socket, pool, cfg, peer, req).await,
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
        rport: None,
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

async fn handle_register(
    socket: &tokio::net::UdpSocket,
    pool: &RedisPool,
    cfg: &UdpProxyConfig,
    peer: SocketAddr,
    req: Request,
) -> anyhow::Result<()> {
    let Some(to) = req.to_header() else {
        respond(socket, peer, &sip_response(&req, StatusCode::BAD_REQUEST)).await;
        return Ok(());
    };
    let Some((user, dom)) = parse_sip_user_host(&to.uri) else {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::not_found_response(&req)),
        )
        .await;
        return Ok(());
    };
    let dom = normalize_domain(dom, &cfg.domain);
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
    if let Err(e) = upsert_contact(pool, &dom, &user, &binding, expires as i64).await {
        tracing::warn!(%e, "register upsert");
        respond(
            socket,
            peer,
            &sip_response(&req, StatusCode::SERVER_INTERNAL_ERROR),
        )
        .await;
        return Ok(());
    }
    respond(socket, peer, &SipMessage::Response(simple_ok(&req))).await;
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
