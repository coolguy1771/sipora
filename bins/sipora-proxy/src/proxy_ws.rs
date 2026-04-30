//! SIP-over-WebSocket accept loop for sipora-proxy (OPTIONS + WS `Via` stamping).

use std::net::SocketAddr;

use sipora_edge::ws_table::{WS_OUTBOUND_QUEUE, WsConnectionTable};
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::header::{Header, RportParam, Transport, Via};
use sipora_sip::types::message::{Request, Response, SipMessage, SipVersion};
use sipora_sip::types::method::Method;
use sipora_sip::types::status::StatusCode;
use sipora_transport::websocket::{WebSocketConnection, WebSocketTransport};
use tokio::sync::mpsc;
use tokio::sync::watch;
use uuid::Uuid;

/// SIP from a WebSocket client, for the UDP proxy core (`run_udp_proxy` merge loop).
#[derive(Debug)]
pub struct WsIngressEnvelope {
    pub peer: SocketAddr,
    pub connection_id: String,
    pub message: SipMessage,
}

pub async fn run_proxy_ws_listener(
    bind_addr: SocketAddr,
    advertise_host: String,
    via_port: u16,
    ws_table: WsConnectionTable,
    ingress_tx: Option<mpsc::Sender<WsIngressEnvelope>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let transport = WebSocketTransport::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "sipora-proxy WebSocket listener");
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            acc = transport.accept() => {
                let (conn, peer) = acc.map_err(|e| anyhow::anyhow!("websocket accept: {e}"))?;
                let conn_id = Uuid::new_v4().to_string();
                let (tx, rx) = mpsc::channel::<SipMessage>(WS_OUTBOUND_QUEUE);
                ws_table.write().await.insert(conn_id.clone(), tx);
                let advertise = advertise_host.clone();
                let tbl = ws_table.clone();
                let ing = ingress_tx.clone();
                tokio::spawn(async move {
                    let res = run_proxy_ws_connection(
                        conn,
                        rx,
                        advertise,
                        via_port,
                        tbl,
                        conn_id,
                        peer,
                        ing,
                    )
                    .await;
                    if let Err(e) = res {
                        tracing::debug!(%peer, "proxy ws session: {e}");
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_proxy_ws_connection(
    mut conn: WebSocketConnection,
    mut outbound_rx: mpsc::Receiver<SipMessage>,
    advertise_host: String,
    via_port: u16,
    ws_table: WsConnectionTable,
    conn_id: String,
    peer: SocketAddr,
    ingress_tx: Option<mpsc::Sender<WsIngressEnvelope>>,
) -> anyhow::Result<()> {
    let _keepalive = conn.start_keepalive();
    loop {
        tokio::select! {
            maybe_out = outbound_rx.recv() => {
                let Some(msg) = maybe_out else { break };
                let bytes = serialize_message(&msg);
                conn.send(&bytes).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            incoming = conn.recv() => {
                let Some(raw) = incoming else { break };
                let (_, msg) =
                    parse_sip_message(&raw).map_err(|e| anyhow::anyhow!("sip parse {e:?}"))?;
                match msg {
                    SipMessage::Request(mut req) => {
                        if req.method == Method::Options {
                            let out = ws_options_ok(&req, &advertise_host, via_port);
                            let bytes = serialize_message(&out);
                            conn.send(&bytes).await.map_err(|e| anyhow::anyhow!("{e}"))?;
                        } else if let Some(ref tx) = ingress_tx {
                            stamp_ws_proxy_via(&mut req, &advertise_host, via_port);
                            let env = WsIngressEnvelope {
                                peer,
                                connection_id: conn_id.clone(),
                                message: SipMessage::Request(req),
                            };
                            if tx.send(env).await.is_err() {
                                break;
                            }
                        } else {
                            let out = minimal_response(&req, StatusCode::NOT_IMPLEMENTED);
                            let bytes = serialize_message(&out);
                            conn.send(&bytes).await.map_err(|e| anyhow::anyhow!("{e}"))?;
                        }
                    }
                    SipMessage::Response(resp) => {
                        if let Some(ref tx) = ingress_tx {
                            let env = WsIngressEnvelope {
                                peer,
                                connection_id: conn_id.clone(),
                                message: SipMessage::Response(resp),
                            };
                            if tx.send(env).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    ws_table.write().await.remove(&conn_id);
    Ok(())
}

fn ws_top_via(advertise: &str, port: u16) -> Header {
    Header::Via(Via {
        transport: Transport::Ws,
        host: advertise.to_string(),
        port: Some(port),
        branch: format!("z9hG4bK{}", Uuid::new_v4().as_simple()),
        received: None,
        rport: RportParam::Absent,
        params: vec![],
    })
}

fn stamp_ws_proxy_via(req: &mut Request, advertise: &str, via_port: u16) {
    req.headers.insert(0, ws_top_via(advertise, via_port));
}

fn ws_options_ok(req: &Request, advertise: &str, via_port: u16) -> SipMessage {
    let mut headers = vec![ws_top_via(advertise, via_port)];
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

fn minimal_response(req: &Request, status: StatusCode) -> SipMessage {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sipora_sip::types::header::Transport;

    #[test]
    fn options_prepends_ws_via() {
        let req = Request {
            method: Method::Options,
            uri: "sip:proxy.example.com".to_string(),
            version: SipVersion::V2_0,
            headers: vec![Header::Via(Via {
                transport: Transport::Udp,
                host: "client.example.net".to_string(),
                port: Some(5060),
                branch: "z9hG4bK-client".to_string(),
                received: None,
                rport: RportParam::Absent,
                params: vec![],
            })],
            body: Vec::new(),
        };
        let SipMessage::Response(r) = ws_options_ok(&req, "proxy.example.com", 5080) else {
            panic!("expected response");
        };
        let Header::Via(top) = &r.headers[0] else {
            panic!("expected Via");
        };
        assert_eq!(top.transport, Transport::Ws);
        assert_eq!(top.host, "proxy.example.com");
        assert_eq!(top.port, Some(5080));
    }
}
