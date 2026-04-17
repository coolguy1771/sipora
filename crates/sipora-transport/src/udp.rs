use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(%addr, "UDP transport listening");
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }
}
