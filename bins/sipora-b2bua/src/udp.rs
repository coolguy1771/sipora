use crate::call::B2buaCallStore;
use crate::codec::CodecPolicy;
use crate::routing::ProxyRouter;
use sipora_auth::stir::{AttestLevel, identity_header_value, sign_passport};
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::header::{Header, NameAddr, Transport, Via};
use sipora_sip::types::message::{Request, SipMessage};
use sipora_sip::types::method::Method;
use sipora_transport::udp::UdpTransport;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::watch;
use uuid::Uuid;

type SharedCallStore = Arc<Mutex<B2buaCallStore>>;

/// STIR/SHAKEN signing credentials for outbound PASSporTs (RFC 8224).
pub struct B2buaStirConfig {
    /// EC private key PEM (`BEGIN EC PRIVATE KEY` or `BEGIN PRIVATE KEY`).
    pub privkey_pem: Vec<u8>,
    /// Publicly reachable URL for the STI-AS signing certificate.
    pub cert_url: String,
    /// Attestation level the B2BUA can vouch for (A/B/C per RFC 8588).
    pub attest: AttestLevel,
}

/// B2BUA UDP relay: downstream address, codec policy, and router (owned per task).
pub struct B2buaUdpRuntime {
    pub downstream: SocketAddr,
    pub advertise: String,
    pub sip_port: u16,
    pub policy: CodecPolicy,
    pub router: ProxyRouter,
    /// If set, sign every outbound INVITE with a STIR PASSporT.
    pub stir: Option<B2buaStirConfig>,
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
    let calls: SharedCallStore = Arc::new(Mutex::new(B2buaCallStore::default()));
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
                    relay_downstream_response(&socket, &calls, data, &msg).await;
                    continue;
                }

                if let SipMessage::Request(req) = msg {
                    if req.call_id().unwrap_or("").is_empty() {
                        tracing::debug!(%peer, "b2bua: missing Call-ID");
                        continue;
                    }
                    handle_client_request(&socket, &rt, &calls, peer, data, req).await;
                }
            }
        }
    }
}

async fn relay_downstream_response(
    socket: &tokio::net::UdpSocket,
    calls: &SharedCallStore,
    data: &[u8],
    msg: &SipMessage,
) {
    let SipMessage::Response(resp) = msg else {
        return;
    };
    if resp.call_id().unwrap_or("").is_empty() {
        return;
    }
    let client = calls.lock().await.client_addr_for_response(resp);
    if let Some(client) = client {
        let _ = socket.send_to(data, client).await;
    }
}

async fn handle_client_request(
    socket: &tokio::net::UdpSocket,
    rt: &B2buaUdpRuntime,
    calls: &SharedCallStore,
    peer: SocketAddr,
    data: &[u8],
    req: Request,
) {
    if req.method == Method::Invite {
        forward_client_invite(socket, rt, calls, peer, req).await;
    } else {
        forward_client_non_invite(socket, rt.downstream, calls, peer, data, &req).await;
    }
}

async fn forward_client_invite(
    socket: &tokio::net::UdpSocket,
    rt: &B2buaUdpRuntime,
    calls: &SharedCallStore,
    peer: SocketAddr,
    req: Request,
) {
    let client_req = req.clone();
    match forward_invite(socket, rt, peer, req).await {
        Ok(Some(downstream_req)) => {
            calls
                .lock()
                .await
                .record_invite(&client_req, &downstream_req, peer, rt.downstream);
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(%peer, "b2bua invite: {e}"),
    }
}

async fn forward_client_non_invite(
    socket: &tokio::net::UdpSocket,
    downstream: SocketAddr,
    calls: &SharedCallStore,
    peer: SocketAddr,
    data: &[u8],
    req: &Request,
) {
    if let Err(e) = socket.send_to(data, downstream).await {
        tracing::debug!(%downstream, "b2bua forward: {e}");
    }
    calls.lock().await.record_pending_request(req, peer);
}

async fn forward_invite(
    socket: &tokio::net::UdpSocket,
    rt: &B2buaUdpRuntime,
    peer: SocketAddr,
    mut req: Request,
) -> anyhow::Result<Option<Request>> {
    if rt.router.check_max_forwards(&req).is_some() {
        respond(
            socket,
            peer,
            &SipMessage::Response(ProxyRouter::too_many_hops_response(&req)),
        )
        .await;
        return Ok(None);
    }

    if !req.body.is_empty()
        && let Ok(s) = std::str::from_utf8(&req.body)
        && s.contains("v=0")
    {
        let media_profile = sdp_media_profile(s);
        tracing::debug!(
            ice_capable = media_profile.is_ice_capable,
            dtls_srtp = media_profile.has_dtls_srtp,
            "b2bua: observed SDP media profile for future rtpengine integration"
        );
        let (new_sdp, removed) = rt.policy.filter_sdp_codecs(s);
        if !removed.is_empty() {
            tracing::debug!(?removed, "b2bua: filtered codecs from SDP");
        }
        set_body(&mut req, new_sdp.into_bytes());
    }

    // RFC 8224: sign a PASSporT for the outbound INVITE when STI-AS credentials
    // are configured. Signing failure is non-fatal — the call still proceeds.
    if let Some(stir) = &rt.stir {
        attach_passport(&mut req, stir);
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

    let downstream_req = req.clone();
    let bytes = serialize_message(&SipMessage::Request(req));
    socket.send_to(&bytes, rt.downstream).await?;
    Ok(Some(downstream_req))
}

/// Extract a telephone number or SIP user-part from a URI for use as a PASSporT TN.
fn tn_from_uri(uri: &str) -> String {
    if let Some(rest) = uri.strip_prefix("tel:") {
        return rest.split(';').next().unwrap_or(rest).to_owned();
    }
    let after_scheme = uri
        .strip_prefix("sips:")
        .or_else(|| uri.strip_prefix("sip:"))
        .unwrap_or(uri);
    after_scheme
        .split('@')
        .next()
        .unwrap_or(after_scheme)
        .to_owned()
}

/// Sign a PASSporT and attach an Identity header to the outbound INVITE.
fn attach_passport(req: &mut Request, stir: &B2buaStirConfig) {
    let orig_tn = req
        .headers
        .iter()
        .find_map(|h| {
            if let Header::From(NameAddr { uri, .. }) = h {
                Some(tn_from_uri(uri))
            } else {
                None
            }
        })
        .unwrap_or_default();
    let dest_tn = tn_from_uri(&req.uri);
    let origid = Uuid::new_v4().to_string();

    match sign_passport(
        &orig_tn,
        &[dest_tn.as_str()],
        stir.attest,
        &origid,
        &stir.privkey_pem,
        &stir.cert_url,
    ) {
        Ok(token) => {
            // Remove any pre-existing Identity header before attaching ours.
            req.headers.retain(|h| !matches!(h, Header::Identity(_)));
            req.headers.push(Header::Identity(identity_header_value(
                &token,
                &stir.cert_url,
            )));
            tracing::debug!(%orig_tn, %dest_tn, "STIR PASSporT attached");
        }
        Err(e) => tracing::warn!(%e, "STIR signing failed; forwarding without Identity"),
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SdpMediaProfile {
    is_ice_capable: bool,
    has_dtls_srtp: bool,
}

fn sdp_media_profile(sdp: &str) -> SdpMediaProfile {
    SdpMediaProfile {
        is_ice_capable: has_any_sdp_attr(sdp, &["candidate", "ice-ufrag", "ice-pwd"]),
        has_dtls_srtp: has_any_sdp_attr(sdp, &["fingerprint"]),
    }
}

fn has_any_sdp_attr(sdp: &str, names: &[&str]) -> bool {
    sdp.lines().any(|line| {
        let line = line.trim();
        names.iter().any(|name| {
            line.strip_prefix("a=")
                .and_then(|attr| attr.strip_prefix(name))
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdp_media_profile_for_plain_sdp_has_no_ice_or_dtls_srtp_markers() {
        let sdp = "v=0\r\nm=audio 4000 RTP/AVP 0\r\n";

        let profile = sdp_media_profile(sdp);

        assert!(!profile.is_ice_capable);
        assert!(!profile.has_dtls_srtp);
    }

    #[test]
    fn sdp_media_profile_detects_ice_capable_dtls_srtp_sdp() {
        let sdp = concat!(
            "v=0\r\n",
            "m=audio 4000 UDP/TLS/RTP/SAVPF 111\r\n",
            "a=ice-ufrag:abc\r\n",
            "a=ice-pwd:def\r\n",
            "a=fingerprint:sha-256 00:11\r\n",
        );

        let profile = sdp_media_profile(sdp);

        assert!(profile.is_ice_capable);
        assert!(profile.has_dtls_srtp);
    }
}
