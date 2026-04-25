pub mod dns;
pub mod sip_tcp;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod websocket;

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub transport: TransportType,
    pub tls_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportType {
    Udp,
    Tcp,
    Tls,
    WebSocket,
}
