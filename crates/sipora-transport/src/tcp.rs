use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

pub struct TcpTransport {
    listener: TcpListener,
}

impl TcpTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "TCP transport listening");
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept().await
    }
}
