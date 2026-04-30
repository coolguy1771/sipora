//! Unified reply path for UDP, WebSocket, and pooled TCP SIP ingress.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::header::Transport;
use sipora_sip::types::message::SipMessage;
use sipora_transport::tcp_pool::TcpConnectionPool;
use tokio::net::UdpSocket;

use crate::message_sender::{MessageSender, MessageTarget};

/// Where provisional/final responses to the client are sent.
#[derive(Clone)]
pub enum ReplyTarget {
    Udp,
    Ws {
        sip_sender: Arc<dyn MessageSender>,
        connection_id: String,
    },
    Tcp {
        pool: Arc<TcpConnectionPool>,
        peer: SocketAddr,
    },
}

/// Per-request ingress: shared UDP socket for downstream + reply path to client.
pub struct ProxyIngress {
    pub socket: Arc<UdpSocket>,
    pub reply: ReplyTarget,
    /// Client address (UDP peer or TCP peer of WebSocket).
    pub source: SocketAddr,
}

impl ProxyIngress {
    pub fn udp(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self {
            socket,
            reply: ReplyTarget::Udp,
            source: peer,
        }
    }

    pub fn ws(
        socket: Arc<UdpSocket>,
        sip_sender: Arc<dyn MessageSender>,
        connection_id: String,
        source: SocketAddr,
    ) -> Self {
        Self {
            socket,
            reply: ReplyTarget::Ws {
                sip_sender,
                connection_id,
            },
            source,
        }
    }

    /// Inbound leg on the TCP pool (e.g. carrier); responses use `pool.send` to `peer`.
    pub fn tcp_downstream(
        socket: Arc<UdpSocket>,
        pool: Arc<TcpConnectionPool>,
        peer: SocketAddr,
    ) -> Self {
        Self {
            socket,
            reply: ReplyTarget::Tcp { pool, peer },
            source: peer,
        }
    }

    pub fn ingress_transport(&self) -> Transport {
        match &self.reply {
            ReplyTarget::Udp => Transport::Udp,
            ReplyTarget::Ws { .. } => Transport::Ws,
            ReplyTarget::Tcp { .. } => Transport::Tcp,
        }
    }
}

pub async fn respond(ingress: &ProxyIngress, msg: &SipMessage) {
    match &ingress.reply {
        ReplyTarget::Udp => {
            let _ = ingress
                .socket
                .send_to(&serialize_message(msg), ingress.source)
                .await;
        }
        ReplyTarget::Ws {
            sip_sender,
            connection_id,
        } => {
            let _ = sip_sender
                .send_sip(
                    &MessageTarget::Ws {
                        connection_id: connection_id.clone(),
                    },
                    msg.clone(),
                )
                .await;
        }
        ReplyTarget::Tcp { pool, peer } => {
            let raw = serialize_message(msg);
            let _ = pool.send(*peer, Bytes::from(raw)).await;
        }
    }
}
