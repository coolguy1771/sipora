use sipora_sip::types::header::{Header, Via};
use sipora_sip::types::message::{Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, watch};

const PENDING_FORWARD_TTL: Duration = Duration::from_secs(32);

#[derive(Debug, Clone)]
pub struct PendingForward {
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub original_via_stack: Vec<Via>,
    pub original_request: Option<Request>,
    pub remaining_targets: Vec<String>,
    pub final_forwarded: bool,
    pub inserted_at: Instant,
}

pub type ForwardTable = Arc<RwLock<HashMap<String, PendingForward>>>;

pub fn new_forward_table() -> ForwardTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub async fn insert_forward(
    table: &ForwardTable,
    branch: String,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    original_via_stack: Vec<Via>,
    original_request: Option<Request>,
    remaining_targets: Vec<String>,
) {
    table.write().await.insert(
        branch,
        PendingForward {
            client_addr,
            target_addr,
            original_via_stack,
            original_request,
            remaining_targets,
            final_forwarded: false,
            inserted_at: Instant::now(),
        },
    );
}

pub async fn get_pending_forward(table: &ForwardTable, branch: &str) -> Option<PendingForward> {
    table.read().await.get(branch).cloned()
}

pub async fn prepare_response(
    table: &ForwardTable,
    branch: &str,
    response: &mut Response,
) -> Option<SocketAddr> {
    let mut forwards = table.write().await;
    let pending = forwards.get_mut(branch)?;

    if response.status.is_success() && pending.final_forwarded {
        return None;
    }

    remove_top_via(response)?;
    restore_original_via_stack(response, &pending.original_via_stack);
    if response.status.is_success() {
        pending.final_forwarded = true;
    }

    let client_addr = pending.client_addr;
    if response.status.class() >= 3 {
        forwards.remove(branch);
    }
    Some(client_addr)
}

pub async fn sweep_expired_forwards(table: &ForwardTable) {
    let cutoff = Instant::now() - PENDING_FORWARD_TTL;
    table
        .write()
        .await
        .retain(|_, pending| pending.inserted_at > cutoff);
}

pub fn spawn_forward_sweeper(
    table: ForwardTable,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PENDING_FORWARD_TTL);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
                _ = interval.tick() => sweep_expired_forwards(&table).await,
            }
        }
    })
}

fn remove_top_via(response: &mut Response) -> Option<()> {
    let index = response
        .headers
        .iter()
        .position(|header| matches!(header, Header::Via(_)))?;
    response.headers.remove(index);
    Some(())
}

fn restore_original_via_stack(response: &mut Response, original_vias: &[Via]) {
    if original_vias.is_empty() || response.headers.iter().any(|h| matches!(h, Header::Via(_))) {
        return;
    }

    for via in original_vias.iter().rev() {
        response.headers.insert(0, Header::Via(via.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipora_sip::types::header::{CSeq, NameAddr, RportParam, Transport};
    use sipora_sip::types::message::SipVersion;
    use sipora_sip::types::method::Method;
    use sipora_sip::types::status::StatusCode;

    fn via(host: &str, branch: &str) -> Via {
        Via {
            transport: Transport::Udp,
            host: host.to_owned(),
            port: Some(5060),
            branch: branch.to_owned(),
            received: None,
            rport: RportParam::Absent,
            params: vec![],
        }
    }

    fn response(status: StatusCode) -> Response {
        Response {
            version: SipVersion::V2_0,
            status,
            reason: status.reason_phrase().to_owned(),
            headers: vec![
                Header::Via(via("proxy.example.com", "z9hG4bK-proxy")),
                Header::Via(via("client.example.com", "z9hG4bK-client")),
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".to_owned(),
                    tag: Some("from-tag".to_owned()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.com".to_owned(),
                    tag: Some("to-tag".to_owned()),
                    params: vec![],
                }),
                Header::CallId("call-1".to_owned()),
                Header::CSeq(CSeq {
                    seq: 1,
                    method: Method::Invite,
                }),
            ],
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn first_success_response_is_prepared_for_client() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            client_addr,
            vec![],
            None,
            vec![],
        )
        .await;
        let mut response = response(StatusCode::OK);

        let target = prepare_response(&table, "z9hG4bK-proxy", &mut response).await;

        assert_eq!(target, Some(client_addr));
        assert!(matches!(response.headers[0], Header::Via(_)));
        assert!(table.read().await["z9hG4bK-proxy"].final_forwarded);
    }

    #[tokio::test]
    async fn repeated_success_response_is_absorbed() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            client_addr,
            vec![],
            None,
            vec![],
        )
        .await;
        let mut first = response(StatusCode::OK);
        let mut second = response(StatusCode::OK);

        prepare_response(&table, "z9hG4bK-proxy", &mut first).await;
        let target = prepare_response(&table, "z9hG4bK-proxy", &mut second).await;

        assert_eq!(target, None);
    }

    #[tokio::test]
    async fn failure_response_removes_forward_entry() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            client_addr,
            vec![],
            None,
            vec![],
        )
        .await;
        let mut response = response(StatusCode::BUSY_HERE);

        let target = prepare_response(&table, "z9hG4bK-proxy", &mut response).await;

        assert_eq!(target, Some(client_addr));
        assert!(table.read().await.is_empty());
    }
}
