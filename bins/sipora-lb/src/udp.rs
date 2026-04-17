use crate::balancer::LoadBalancer;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::types::message::SipMessage;
use sipora_transport::udp::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::watch;

pub async fn resolve_lb_upstream(spec: &str) -> Option<SocketAddr> {
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

pub async fn run_udp_lb(
    addr: SocketAddr,
    lb: LoadBalancer,
    id_to_upstream: Arc<HashMap<String, SocketAddr>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let upstream_set: HashSet<SocketAddr> = id_to_upstream.values().copied().collect();
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
                            tracing::debug!(%peer, "lb: missing Call-ID");
                            continue;
                        }
                        let Some(node) = lb.select_node(&cid) else {
                            tracing::warn!(%peer, "lb: no healthy upstream");
                            continue;
                        };
                        let Some(&upstream) = id_to_upstream.get(&node.id) else {
                            tracing::warn!(node_id = %node.id, "lb: missing upstream socket");
                            continue;
                        };
                        relay.lock().await.insert(cid, peer);
                        if let Err(e) = socket.send_to(data, upstream).await {
                            tracing::debug!(%upstream, "lb: forward: {e}");
                        }
                    }
                    SipMessage::Response(_) => {}
                }
            }
        }
    }
}
