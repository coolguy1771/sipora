//! WebSocket-related integration tests (SIPp does not speak WebSocket).

use sipora_edge::ws_table::new_ws_connection_table;
use sipora_proxy::message_sender::{MessageSender, MessageTarget, WsSender};
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::types::message::SipMessage;
use sipora_transport::websocket::WebSocketTransport;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

#[tokio::test]
async fn ws_sender_delivers_sip_to_registered_connection() {
    let table = new_ws_connection_table();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SipMessage>(8);
    let id = "conn-e2e-1".to_owned();
    table.write().await.insert(id.clone(), tx);

    let sender = WsSender::new(table);
    let raw = b"OPTIONS sip:example.com SIP/2.0\r\n\r\n".to_vec();
    let (_, msg) = parse_sip_message(&raw).unwrap();
    sender
        .send_sip(
            &MessageTarget::Ws {
                connection_id: id.clone(),
            },
            msg,
        )
        .await
        .unwrap();

    let received = rx.recv().await.expect("channel message");
    match received {
        SipMessage::Request(r) => assert_eq!(r.method.as_str(), "OPTIONS"),
        other => panic!("expected request, got {other:?}"),
    }
}

#[tokio::test]
async fn websocket_transport_accepts_sip_subprotocol_from_client() {
    let transport = WebSocketTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = transport.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_conn, _) = transport.accept().await.unwrap();
    });

    let mut request = format!("ws://{addr}").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));

    let (_client, response) = connect_async(request).await.unwrap();
    assert_eq!(response.headers()["Sec-WebSocket-Protocol"], "sip");
    server.abort();
    let _ = server.await;
}
