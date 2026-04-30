//! Abstraction for sending SIP to UDP peers or WebSocket connections (NOTIFY and future paths).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use sipora_edge::ws_table::WsConnectionTable;
use sipora_sip::serialize::serialize_message;
use sipora_sip::types::message::SipMessage;
use sipora_transport::tcp_pool::TcpConnectionPool;
use tokio::net::UdpSocket;
use tokio::net::lookup_host;

#[derive(Debug, Clone)]
pub enum MessageTarget {
    Udp(SocketAddr),
    Ws { connection_id: String },
    Tcp { host: String, port: u16 },
}

#[async_trait]
pub trait MessageSender: Send + Sync {
    async fn send_sip(&self, target: &MessageTarget, msg: SipMessage) -> anyhow::Result<()>;
}

pub struct UdpSender {
    socket: Arc<UdpSocket>,
}

impl UdpSender {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }
}

#[async_trait]
impl MessageSender for UdpSender {
    async fn send_sip(&self, target: &MessageTarget, msg: SipMessage) -> anyhow::Result<()> {
        let MessageTarget::Udp(addr) = target else {
            anyhow::bail!("UdpSender: expected UDP target");
        };
        let bytes = serialize_message(&msg);
        self.socket.send_to(&bytes, *addr).await?;
        Ok(())
    }
}

pub struct WsSender {
    table: WsConnectionTable,
}

impl WsSender {
    pub fn new(table: WsConnectionTable) -> Self {
        Self { table }
    }
}

#[async_trait]
impl MessageSender for WsSender {
    async fn send_sip(&self, target: &MessageTarget, msg: SipMessage) -> anyhow::Result<()> {
        let MessageTarget::Ws { connection_id } = target else {
            anyhow::bail!("WsSender: expected WebSocket target");
        };
        let tx = {
            let g = self.table.read().await;
            g.get(connection_id)
                .cloned()
                .with_context(|| format!("unknown WebSocket connection id: {connection_id}"))?
        };
        tx.send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("WebSocket peer disconnected"))?;
        Ok(())
    }
}

pub struct TcpPoolSender {
    pool: Arc<TcpConnectionPool>,
}

impl TcpPoolSender {
    pub fn new(pool: Arc<TcpConnectionPool>) -> Self {
        Self { pool }
    }
}

async fn resolve_tcp_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let mut it = lookup_host((host, port)).await?;
    it.next()
        .ok_or_else(|| anyhow::anyhow!("tcp resolve: no addresses for {host}:{port}"))
}

#[async_trait]
impl MessageSender for TcpPoolSender {
    async fn send_sip(&self, target: &MessageTarget, msg: SipMessage) -> anyhow::Result<()> {
        let MessageTarget::Tcp { host, port } = target else {
            anyhow::bail!("TcpPoolSender: expected TCP target");
        };
        let addr = resolve_tcp_addr(host, *port).await?;
        let raw = serialize_message(&msg);
        self.pool
            .send(addr, Bytes::from(raw))
            .await
            .map_err(|e| anyhow::anyhow!("tcp pool send: {e}"))?;
        Ok(())
    }
}
