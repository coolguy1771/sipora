use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};

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

    #[allow(clippy::result_large_err)]
    pub async fn accept(
        &self,
    ) -> Result<(WebSocketConnection, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
        let (stream, addr) = self.listener.accept().await?;
        let ws_stream = accept_hdr_async(stream, |req: &Request, response| {
            choose_sip_subprotocol(req, response)
        })
        .await?;
        Ok((WebSocketConnection { inner: ws_stream }, addr))
    }
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
    inner: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
}

impl WebSocketConnection {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        while let Some(msg) = self.inner.next().await {
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

    pub async fn send(
        &mut self,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let text: String = String::from_utf8_lossy(data).into_owned();
        self.inner.send(Message::Text(text.into())).await?;
        Ok(())
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
}
