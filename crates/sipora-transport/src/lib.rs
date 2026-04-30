pub mod dns;
pub mod enum_lookup;
pub mod sip_tcp;
pub mod tcp;
pub mod tcp_pool;
pub mod tls;
pub mod tls_client;
pub mod udp;
pub mod websocket;

pub use enum_lookup::enum_resolve_tel_to_sip;

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
    Wss,
}
