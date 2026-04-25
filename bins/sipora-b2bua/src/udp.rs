use crate::codec::CodecPolicy;
use crate::routing::ProxyRouter;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::header::{Header, Transport, Via};
use sipora_sip::types::message::{Request, SipMessage};
use sipora_sip::types::method::Method;
use sipora_transport::udp::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::watch;
use uuid::Uuid;

/// B2BUA UDP relay: downstream address, codec policy, and router (owned per task).
pub struct B2buaUdpRuntime {
    pub downstream: SocketAddr,
    pub advertise: String,
    pub sip_port: u16,
    pub policy: CodecPolicy,
    pub router: ProxyRouter,
}

pub async fn resolve_downstream(spec: &str) -> Option<SocketAddr> {
    let spec = spec.trim();
    if let Ok(a) = spec.parse::<SocketAddr>() {
        return Some(a);
    }
    let (host, port) = split_host_port(spec)?;
    let mut it = tokio::net::lookup_host((host.as_str(), port)).await.ok()?;
    it.next()
}

fn split_host_port(spec: &str) -> Option<(String, u16)> {
    let (h, p) = spec.rsplit_once(':')?;
    let port = p.parse::<u16>().ok()?;
    Some((h.to_string(), port))
}

pub async fn run_udp_b2bua(
    addr: SocketAddr,
    rt: B2buaUdpRuntime,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let downstream = rt.downstream;
    let upstream_set: HashSet<SocketAddr> = [downstream].into_iter().collect();
    let relay: Arc<Mutex<HashMap<String, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let udp = UdpTransport::bind(addr).await?;
    let socket = udp.into_inner();
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

                if upstream_set.contains(&peer) {
                    if let SipMessage::Response(resp) = &msg {
                        let cid = resp.call_id().unwrap_or("").to_string();
                        if cid.is_empty() {
                            continue;
                        }
                        let client = relay.lock().await.get(&cid).copied();
                        if let Some(client) = client {
                            let _ = socket.send_to(data, client).await;
                        }
                    }
                    continue;
                }

                match msg {
                    SipMessage::Request(req) => {
                        let cid = req.call_id().unwrap_or("").to_string();
                        if cid.is_empty() {
                            tracing::debug!(%peer, "b2bua: missing Call-ID");
                            continue;
                        }
                        relay.lock().await.insert(cid, peer);

                        if req.method == Method::Invite {
                            if let Err(e) = forward_invite(&socket, &rt, peer, req).await {
                                tracing::warn!(%peer, "b2bua invite: {e}");
                            }
                        } else if let Err(e) = socket.send_to(data, downstream).await {
                            tracing::debug!(%downstream, "b2bua forward: {e}");
                        }
                    }
                    SipMessage::Response(_) => {}
                }
            }
        }
    }
}

async fn forward_invite(
    socket: &tokio::net::UdpSocket,
    rt: &B2buaUdpRuntime,
    peer: SocketAddr,
    mut req: Request,
) -> anyhow::Result<()> {
    if rt.router.check_max_forwards(&req).is_some() {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::too_many_hops_response(&req)),
        )
        .await;
        return Ok(());
    }

    if !req.body.is_empty()
        && let Ok(s) = std::str::from_utf8(&req.body)
        && s.contains("v=0")
    {
        let (new_sdp, removed) = rt.policy.filter_sdp_codecs(s);
        if !removed.is_empty() {
            tracing::debug!(?removed, "b2bua: filtered codecs from SDP");
        }
        set_body(&mut req, new_sdp.into_bytes());
    }

    let branch = format!("z9hG4bK{}", Uuid::new_v4().as_simple());
    let via = Header::Via(Via {
        transport: Transport::Udp,
        host: rt.advertise.clone(),
        port: Some(rt.sip_port),
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
    socket.send_to(&bytes, rt.downstream).await?;
    Ok(())
}

fn set_body(req: &mut Request, body: Vec<u8>) {
    let len = body.len() as u32;
    req.body = body;
    let mut found = false;
    for h in &mut req.headers {
        if let Header::ContentLength(n) = h {
            *n = len;
            found = true;
            break;
        }
    }
    if !found {
        req.headers.push(Header::ContentLength(len));
    }
}

async fn respond(socket: &tokio::net::UdpSocket, peer: SocketAddr, msg: &SipMessage) {
    let _ = socket.send_to(&serialize_message(msg), peer).await;
}
