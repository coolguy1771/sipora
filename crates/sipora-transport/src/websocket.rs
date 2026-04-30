use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};

use crate::TransportType;

type WsTcpStream = WebSocketStream<TcpStream>;
type WsSplitSink = SplitSink<WsTcpStream, Message>;
type WsSplitRead = SplitStream<WsTcpStream>;

pub struct WebSocketTransport {
    listener: TcpListener,
}

impl WebSocketTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "WebSocket transport listening");
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts TCP and completes the WebSocket handshake (`sip` subprotocol).
    pub async fn accept_stream(
        &self,
    ) -> Result<(WsTcpStream, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
        let (stream, addr) = self.listener.accept().await?;
        let ws = handshake_ws(stream).await?;
        Ok((ws, addr))
    }

    #[allow(clippy::result_large_err)]
    pub async fn accept(
        &self,
    ) -> Result<(WebSocketConnection, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
        let (ws, addr) = self.accept_stream().await?;
        Ok((WebSocketConnection::from_upgraded(ws, false), addr))
    }
}

#[allow(clippy::result_large_err)]
async fn handshake_ws(
    stream: TcpStream,
) -> Result<WsTcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = accept_hdr_async(stream, |req: &Request, response| {
        choose_sip_subprotocol(req, response)
    })
    .await?;
    Ok(ws_stream)
}

#[allow(clippy::result_large_err)]
fn choose_sip_subprotocol(
    req: &Request,
    mut response: Response,
) -> Result<Response, tokio_tungstenite::tungstenite::handshake::server::ErrorResponse> {
    if !offers_sip_subprotocol(req) {
        return Err(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Some("Missing Sec-WebSocket-Protocol: sip".to_owned()))
            .expect("valid websocket rejection"));
    }

    response
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
    Ok(response)
}

fn offers_sip_subprotocol(req: &Request) -> bool {
    req.headers()
        .get_all("Sec-WebSocket-Protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == "sip")
}

pub struct WebSocketConnection {
    tls: bool,
    read: WsSplitRead,
    write: Arc<Mutex<WsSplitSink>>,
}

impl WebSocketConnection {
    /// Wraps an upgraded WebSocket over TCP. Set `tls` to true when the connection uses TLS (wss).
    pub fn from_upgraded(ws_stream: WsTcpStream, tls: bool) -> Self {
        let (write, read) = ws_stream.split();
        Self {
            tls,
            read,
            write: Arc::new(Mutex::new(write)),
        }
    }

    pub fn transport_type(&self) -> TransportType {
        if self.tls {
            TransportType::Wss
        } else {
            TransportType::WebSocket
        }
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        while let Some(msg) = self.read.next().await {
            match msg {
                Ok(Message::Text(text)) if text == "\r\n" || text == "\r\n\r\n" => continue,
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

    pub async fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let text: String = String::from_utf8_lossy(data).into_owned();
        let mut sink = self.write.lock().await;
        sink.send(Message::Text(text.into())).await?;
        Ok(())
    }

    /// Sends CRLF keepalive frames every 30 seconds (RFC 7118-style).
    pub fn start_keepalive(&self) -> tokio::task::JoinHandle<()> {
        let write = Arc::clone(&self.write);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let mut sink = write.lock().await;
                if sink.send(Message::Text("\r\n".into())).await.is_err() {
                    break;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    #[tokio::test]
    async fn accepts_clients_that_offer_sip_subprotocol() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move { transport.accept().await });
        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));

        let (_client, response) = connect_async(request).await.unwrap();
        let accepted = server.await.unwrap();

        assert!(accepted.is_ok());
        assert_eq!(response.headers()["Sec-WebSocket-Protocol"], "sip");
    }

    #[tokio::test]
    async fn rejects_clients_without_sip_subprotocol() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move { transport.accept().await });

        let client = connect_async(format!("ws://{addr}")).await;
        let accepted = server.await.unwrap();

        assert!(client.is_err());
        assert!(accepted.is_err());
    }

    #[tokio::test]
    async fn rejects_uppercase_sip_subprotocol() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move { transport.accept().await });
        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("SIP"));

        let client = connect_async(request).await;
        let accepted = server.await.unwrap();

        assert!(client.is_err());
        assert!(accepted.is_err());
    }

    #[tokio::test]
    async fn accepts_sip_from_multiple_offered_subprotocols() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move { transport.accept().await });
        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("chat, sip"),
        );

        let (_client, response) = connect_async(request).await.unwrap();
        let accepted = server.await.unwrap();

        assert!(accepted.is_ok());
        assert_eq!(response.headers()["Sec-WebSocket-Protocol"], "sip");
    }

    #[tokio::test]
    async fn recv_skips_crlf_keepalive_text_frames() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = transport.accept().await.unwrap();
            connection.recv().await
        });
        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
        let (mut client, _) = connect_async(request).await.unwrap();

        client.send(Message::Text("\r\n".into())).await.unwrap();
        client.send(Message::Text("\r\n\r\n".into())).await.unwrap();
        client
            .send(Message::Text(
                "OPTIONS sip:example.com SIP/2.0\r\n\r\n".into(),
            ))
            .await
            .unwrap();

        let received = server.await.unwrap();
        assert_eq!(
            received,
            Some(b"OPTIONS sip:example.com SIP/2.0\r\n\r\n".to_vec())
        );
    }

    #[tokio::test]
    async fn transport_returns_websocket_for_plain() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = transport.accept().await.unwrap();
            assert_eq!(conn.transport_type(), TransportType::WebSocket);
        });
        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
        let (_client, _) = connect_async(request).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn transport_returns_wss_when_built_with_tls_flag() {
        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (ws, _) = transport.accept_stream().await.unwrap();
            let conn = WebSocketConnection::from_upgraded(ws, true);
            assert_eq!(conn.transport_type(), TransportType::Wss);
        });
        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
        let (_client, _) = connect_async(request).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn keepalive_sends_crlf_every_interval() {
        tokio::time::pause();

        let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (conn, _) = transport.accept().await.unwrap();
            let _jh = conn.start_keepalive();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let mut request = format!("ws://{addr}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
        let (mut client, _) = connect_async(request).await.unwrap();

        tokio::time::sleep(Duration::from_secs(30)).await;

        let msg = client.next().await.expect("message").unwrap();
        match msg {
            Message::Text(t) => assert_eq!(t, "\r\n"),
            other => panic!("expected Text CRLF, got {other:?}"),
        }

        server.abort();
        let _ = server.await;
    }
}
