//! Build and dispatch out-of-dialog NOTIFY toward a subscriber Contact.

use async_trait::async_trait;
use sipora_location::subscription::Subscription;
use sipora_sip::types::header::CSeq;
use sipora_sip::types::header::{Header, NameAddr, SubscriptionStateValue, Transport, Via};
use sipora_sip::types::message::{Request, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_transport::dns::{SipTransport, resolve_sip_targets};

use crate::message_sender::{MessageSender, MessageTarget};

fn strip_angle(uri: &str) -> &str {
    uri.trim().trim_start_matches('<').trim_end_matches('>')
}

fn uri_param<'a>(uri: &'a str, name: &str) -> Option<&'a str> {
    uri.split('?').next()?.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.eq_ignore_ascii_case(name).then_some(v)
    })
}

fn uri_transport(uri: &str) -> Option<&str> {
    uri_param(uri, "transport")
}

/// Resolve [`MessageTarget`] from a Contact URI (UDP / TCP / TLS / WS with `ws-conn`).
pub async fn resolve_message_target(contact_uri: &str) -> anyhow::Result<MessageTarget> {
    let raw = strip_angle(contact_uri);
    let ws_conn = uri_param(raw, "ws-conn")
        .or_else(|| uri_param(raw, "ws_conn"))
        .map(str::trim);
    let tr = uri_transport(raw).unwrap_or("udp");
    if tr.eq_ignore_ascii_case("ws") || tr.eq_ignore_ascii_case("wss") {
        let id =
            ws_conn.ok_or_else(|| anyhow::anyhow!("transport=ws contact needs ws-conn=<id>"))?;
        return Ok(MessageTarget::Ws {
            connection_id: id.to_string(),
        });
    }
    let (host, port) = crate::udp::contact_host_port(contact_uri)
        .ok_or_else(|| anyhow::anyhow!("bad sip contact for notify"))?;
    let sip_tr = if raw.to_ascii_lowercase().starts_with("sips:") {
        SipTransport::Tls
    } else {
        match tr.to_ascii_lowercase().as_str() {
            "tcp" => SipTransport::Tcp,
            "tls" => SipTransport::Tls,
            _ => SipTransport::Udp,
        }
    };
    let targets = resolve_sip_targets(&host, port, sip_tr).await;
    let first = targets
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no resolved target for notify"))?;
    Ok(match sip_tr {
        SipTransport::Tcp | SipTransport::Tls => MessageTarget::Tcp {
            host: first.addr.ip().to_string(),
            port: first.addr.port(),
        },
        SipTransport::Udp => MessageTarget::Udp(first.addr),
    })
}

fn opt_tag(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// NOTIFY `Request` toward `sub.contact` (subscriber).
#[allow(clippy::too_many_arguments)]
pub fn build_notify_request(
    sub: &Subscription,
    body: &[u8],
    content_type: &str,
    state: SubscriptionStateValue,
    state_expires: Option<u32>,
    state_reason: Option<String>,
    event_header: &str,
    notify_cseq: u32,
    advertise: &str,
    sip_port: u16,
) -> Request {
    let req_uri = strip_angle(&sub.contact).to_string();
    let from_uri = if sub.aor.contains("sip:") || sub.aor.contains("sips:") {
        sub.aor.clone()
    } else {
        format!("sip:{}", sub.aor)
    };
    let from_na = NameAddr {
        display_name: None,
        uri: from_uri,
        tag: opt_tag(&sub.to_tag),
        params: vec![],
    };
    let to_na = NameAddr {
        display_name: None,
        uri: sub.subscriber_uri.clone(),
        tag: opt_tag(&sub.from_tag),
        params: vec![],
    };
    let branch = format!("z9hG4bK{}", uuid::Uuid::new_v4().as_simple());
    let top_via = Header::Via(Via {
        transport: Transport::Udp,
        host: advertise.to_string(),
        port: Some(sip_port),
        branch,
        received: None,
        rport: sipora_sip::types::header::RportParam::Absent,
        params: vec![],
    });
    let mut headers = vec![top_via];
    for r in &sub.route_set {
        if !r.is_empty() {
            headers.push(Header::Route(vec![r.clone()]));
        }
    }
    headers.push(Header::MaxForwards(70));
    headers.push(Header::From(from_na));
    headers.push(Header::To(to_na));
    headers.push(Header::CallId(sub.call_id.clone()));
    headers.push(Header::CSeq(CSeq {
        seq: notify_cseq,
        method: Method::Notify,
    }));
    headers.push(Header::Event(event_header.to_string()));
    headers.push(Header::SubscriptionState {
        state,
        expires: state_expires,
        reason: state_reason,
    });
    if !content_type.is_empty() {
        headers.push(Header::ContentType(content_type.to_string()));
    }
    let cl = body.len() as u32;
    headers.push(Header::ContentLength(cl));
    Request {
        method: Method::Notify,
        uri: req_uri,
        version: SipVersion::V2_0,
        headers,
        body: body.to_vec(),
    }
}

pub async fn dispatch_notify(
    sender: &dyn MessageSender,
    contact_uri: &str,
    req: Request,
) -> anyhow::Result<()> {
    let target = resolve_message_target(contact_uri).await?;
    sender.send_sip(&target, SipMessage::Request(req)).await
}

/// Composite sender: picks implementation by [`MessageTarget`] variant.
pub struct CompositeSender {
    pub udp: std::sync::Arc<crate::message_sender::UdpSender>,
    pub ws: Option<std::sync::Arc<crate::message_sender::WsSender>>,
    pub tcp: Option<std::sync::Arc<crate::message_sender::TcpPoolSender>>,
}

#[async_trait]
impl MessageSender for CompositeSender {
    async fn send_sip(&self, target: &MessageTarget, msg: SipMessage) -> anyhow::Result<()> {
        match target {
            MessageTarget::Udp(_) => self.udp.send_sip(target, msg).await,
            MessageTarget::Ws { .. } => {
                let Some(ws) = &self.ws else {
                    anyhow::bail!("WebSocket sender not configured");
                };
                ws.send_sip(target, msg).await
            }
            MessageTarget::Tcp { .. } => {
                let Some(tcp) = &self.tcp else {
                    anyhow::bail!("TCP pool sender not configured");
                };
                tcp.send_sip(target, msg).await
            }
        }
    }
}
