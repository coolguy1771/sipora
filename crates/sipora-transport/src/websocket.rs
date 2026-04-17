use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

pub struct WebSocketTransport {
    listener: TcpListener,
}

impl WebSocketTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "WebSocket transport listening");
        Ok(Self { listener })
    }

    pub async fn accept(
        &self,
    ) -> Result<(WebSocketConnection, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
        let (stream, addr) = self.listener.accept().await?;
        let ws_stream = accept_async(stream).await?;
        Ok((WebSocketConnection { inner: ws_stream }, addr))
    }
}

pub struct WebSocketConnection {
    inner: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
}

impl WebSocketConnection {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        while let Some(msg) = self.inner.next().await {
            match msg {
                Ok(Message::Text(text)) => return Some(text.as_bytes().to_vec()),
                Ok(Message::Binary(bin)) => return Some(bin.to_vec()),
                Ok(Message::Close(_)) => return None,
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!("websocket recv error: {e}");
                    return None;
                }
            }
        }
        None
    }

    pub async fn send(
        &mut self,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let text: String = String::from_utf8_lossy(data).into_owned();
        self.inner.send(Message::Text(text.into())).await?;
        Ok(())
    }
}
