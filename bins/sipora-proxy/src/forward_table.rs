use sipora_sip::types::header::{Header, Via};
use sipora_sip::types::message::{Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, watch};

const PENDING_FORWARD_TTL: Duration = Duration::from_secs(32);

/// Where to send a proxied SIP response (UDP peer or WebSocket connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseTarget {
    Udp(SocketAddr),
    Ws { connection_id: String },
}

#[derive(Debug, Clone)]
pub struct PendingForward {
    pub client_addr: SocketAddr,
    /// When set, SIP responses for this branch go out over WebSocket instead of UDP.
    pub reply_ws_conn_id: Option<String>,
    pub target_addr: SocketAddr,
    pub original_via_stack: Vec<Via>,
    pub original_request: Option<Request>,
    pub remaining_targets: Vec<String>,
    /// Request-URI used in the forwarded request — needed to build a downstream CANCEL.
    pub forwarded_uri: String,
    pub final_forwarded: bool,
    pub inserted_at: Instant,
    /// Last `RSeq` from a relayed reliable 1xx on this fork (RFC 3262 PRACK routing).
    pub last_reliable_rseq: Option<u32>,
    /// Last `(rseq, cseq)` PRACK forwarded downstream (suppress duplicate PRACK retransmits).
    pub last_prack_rack: Option<(u32, u32)>,
}

pub type ForwardTable = Arc<RwLock<HashMap<String, PendingForward>>>;

pub fn new_forward_table() -> ForwardTable {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Looks up [`PendingForward`] entries whose `original_request` has the given SIP Call-ID.
///
/// Returns every matching branch key (one entry per forked INVITE leg).
pub async fn find_branches_by_call_id(table: &ForwardTable, call_id: &str) -> Vec<String> {
    table
        .read()
        .await
        .iter()
        .filter_map(|(branch, pending)| {
            pending
                .original_request
                .as_ref()
                .and_then(|req| req.call_id())
                .filter(|id| *id == call_id)
                .map(|_| branch.clone())
        })
        .collect()
}

/// Searches [`ForwardTable`] for a branch whose pending [`PendingForward::original_request`]
/// has a matching Call-ID, and returns that branch name if found.
///
/// When several forks share the same Call-ID, this returns one match (see
/// [`find_branches_by_call_id`] for all legs).
pub async fn find_branch_by_call_id(table: &ForwardTable, call_id: &str) -> Option<String> {
    find_branches_by_call_id(table, call_id)
        .await
        .into_iter()
        .next()
}

/// Picks the fork whose last relayed `RSeq` and INVITE CSeq match PRACK `RAck` (RFC 3262).
///
/// Returns [`None`] when `RAck` does not uniquely identify a leg (missing or ambiguous).
pub async fn find_branch_by_call_id_and_rseq(
    table: &ForwardTable,
    call_id: &str,
    rseq: u32,
    rack_cseq: u32,
) -> Option<String> {
    let table = table.read().await;
    let mut matches: Vec<String> = table
        .iter()
        .filter(|(_, pending)| {
            let call_match = pending
                .original_request
                .as_ref()
                .and_then(|req| req.call_id())
                .is_some_and(|id| id == call_id);
            if !call_match || pending.last_reliable_rseq != Some(rseq) {
                return false;
            }
            pending
                .original_request
                .as_ref()
                .and_then(|req| req.cseq())
                .is_none_or(|c| c.seq == rack_cseq)
        })
        .map(|(branch, _)| branch.clone())
        .collect();
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

/// Inserts a pending forward for `branch`.
///
/// Returns the previous [`PendingForward`] when `branch` already existed (overwrite).
#[allow(clippy::too_many_arguments)]
pub async fn insert_forward(
    table: &ForwardTable,
    branch: String,
    client_addr: SocketAddr,
    reply_ws_conn_id: Option<String>,
    target_addr: SocketAddr,
    original_via_stack: Vec<Via>,
    original_request: Option<Request>,
    remaining_targets: Vec<String>,
    forwarded_uri: String,
) -> Option<PendingForward> {
    let pending = PendingForward {
        client_addr,
        reply_ws_conn_id,
        target_addr,
        original_via_stack,
        original_request,
        remaining_targets,
        forwarded_uri,
        final_forwarded: false,
        inserted_at: Instant::now(),
        last_reliable_rseq: None,
        last_prack_rack: None,
    };
    let prev = table.write().await.insert(branch.clone(), pending);
    if prev.is_some() {
        tracing::warn!(
            branch = %branch,
            "insert_forward: replaced existing pending forward for branch"
        );
    }
    prev
}

pub async fn get_pending_forward(table: &ForwardTable, branch: &str) -> Option<PendingForward> {
    table.read().await.get(branch).cloned()
}

pub async fn prepare_response(
    table: &ForwardTable,
    branch: &str,
    response: &mut Response,
) -> Option<ResponseTarget> {
    let mut forwards = table.write().await;
    let pending = forwards.get_mut(branch)?;

    if let Some(rseq) = response.headers.iter().find_map(|h| match h {
        Header::RSeq(n) => Some(*n),
        _ => None,
    }) {
        if pending.last_reliable_rseq == Some(rseq) {
            return None;
        }
        pending.last_reliable_rseq = Some(rseq);
    }

    remove_top_via(response)?;
    restore_original_via_stack(response, &pending.original_via_stack);
    if response.status.is_success() {
        pending.final_forwarded = true;
    }

    let target = if let Some(ref id) = pending.reply_ws_conn_id {
        ResponseTarget::Ws {
            connection_id: id.clone(),
        }
    } else {
        ResponseTarget::Udp(pending.client_addr)
    };
    if response.status.class() >= 3 {
        forwards.remove(branch);
    }
    Some(target)
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
    use sipora_sip::types::header::{CSeq, Header, NameAddr, RportParam, Transport};
    use sipora_sip::types::message::SipVersion;
    use sipora_sip::types::method::Method;
    use sipora_sip::types::status::StatusCode;
    use std::time::Duration;

    fn invite_request_with_call_id(call_id: &str) -> Request {
        Request {
            method: Method::Invite,
            uri: "sip:bob@example.com".to_owned(),
            version: SipVersion::V2_0,
            headers: vec![
                Header::Via(Via {
                    transport: Transport::Udp,
                    host: "client.example.com".to_owned(),
                    port: Some(5060),
                    branch: "z9hG4bK-client".to_owned(),
                    received: None,
                    rport: RportParam::Absent,
                    params: vec![],
                }),
                Header::CallId(call_id.to_owned()),
                Header::CSeq(CSeq {
                    seq: 1,
                    method: Method::Invite,
                }),
            ],
            body: vec![],
        }
    }

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
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut response = response(StatusCode::OK);

        let target = prepare_response(&table, "z9hG4bK-proxy", &mut response).await;

        assert_eq!(target, Some(ResponseTarget::Udp(client_addr)));
        assert!(matches!(response.headers[0], Header::Via(_)));
        assert!(table.read().await["z9hG4bK-proxy"].final_forwarded);
    }

    #[tokio::test]
    async fn repeated_success_response_is_prepared_for_client() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut first = response(StatusCode::OK);
        let mut second = response(StatusCode::OK);

        prepare_response(&table, "z9hG4bK-proxy", &mut first).await;
        let target = prepare_response(&table, "z9hG4bK-proxy", &mut second).await;

        assert_eq!(target, Some(ResponseTarget::Udp(client_addr)));
        assert!(matches!(second.headers[0], Header::Via(_)));
    }

    #[tokio::test]
    async fn failure_response_removes_forward_entry() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut response = response(StatusCode::BUSY_HERE);

        let target = prepare_response(&table, "z9hG4bK-proxy", &mut response).await;

        assert_eq!(target, Some(ResponseTarget::Udp(client_addr)));
        assert!(table.read().await.is_empty());
    }

    fn response_one_via(status: StatusCode) -> Response {
        Response {
            version: SipVersion::V2_0,
            status,
            reason: status.reason_phrase().to_owned(),
            headers: vec![
                Header::Via(via("proxy.example.com", "z9hG4bK-proxy")),
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
    async fn redirection_response_removes_forward_even_with_remaining_targets() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec!["sip:bob@backup.example.com".to_owned()],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut resp = response(StatusCode::MOVED_TEMPORARILY);

        let target = prepare_response(&table, "z9hG4bK-proxy", &mut resp).await;

        assert_eq!(target, Some(ResponseTarget::Udp(client_addr)));
        assert!(table.read().await.is_empty());
    }

    #[tokio::test]
    async fn prepare_response_restores_original_via_stack_order() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        let stack = vec![
            via("orig-a.example.com", "z9hG4bKa"),
            via("orig-b.example.com", "z9hG4bKb"),
        ];
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            None,
            client_addr,
            stack,
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut resp = response_one_via(StatusCode::OK);

        let _ = prepare_response(&table, "z9hG4bK-proxy", &mut resp).await;

        let Header::Via(top) = &resp.headers[0] else {
            panic!("expected Via");
        };
        let Header::Via(second) = &resp.headers[1] else {
            panic!("expected second Via");
        };
        assert_eq!(top.host, "orig-a.example.com");
        assert_eq!(second.host, "orig-b.example.com");
    }

    #[tokio::test]
    async fn duplicate_reliable_provisional_skips_second_prepare() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut first = response(StatusCode::SESSION_PROGRESS);
        first.headers.push(Header::RSeq(7));
        let mut second = first.clone();

        assert!(
            prepare_response(&table, "z9hG4bK-proxy", &mut first)
                .await
                .is_some()
        );
        assert!(
            prepare_response(&table, "z9hG4bK-proxy", &mut second)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn provisional_response_forwards_without_final_forwarded() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        let mut resp = response(StatusCode::RINGING);

        let target = prepare_response(&table, "z9hG4bK-proxy", &mut resp).await;

        assert_eq!(target, Some(ResponseTarget::Udp(client_addr)));
        assert!(!table.read().await["z9hG4bK-proxy"].final_forwarded);
    }

    #[tokio::test]
    async fn sweep_expired_forwards_drops_stale_inserts() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "stale".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        {
            let mut forwards = table.write().await;
            forwards.get_mut("stale").unwrap().inserted_at =
                Instant::now() - PENDING_FORWARD_TTL - Duration::from_secs(1);
        }
        insert_forward(
            &table,
            "fresh".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;

        sweep_expired_forwards(&table).await;

        let forwards = table.read().await;
        assert!(!forwards.contains_key("stale"));
        assert!(forwards.contains_key("fresh"));
    }

    #[tokio::test]
    async fn insert_forward_overwrite_returns_previous() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        let other = "127.0.0.1:5070".parse().unwrap();
        assert!(
            insert_forward(
                &table,
                "same-branch".to_owned(),
                client_addr,
                None,
                client_addr,
                vec![],
                None,
                vec![],
                "sip:bob@127.0.0.1:5060".to_owned(),
            )
            .await
            .is_none()
        );
        let prev = insert_forward(
            &table,
            "same-branch".to_owned(),
            client_addr,
            None,
            other,
            vec![],
            None,
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        assert_eq!(prev.map(|p| p.target_addr), Some(client_addr));
        assert_eq!(table.read().await["same-branch"].target_addr, other);
    }

    #[tokio::test]
    async fn find_branch_by_call_id_returns_matching_branch() {
        let table = new_forward_table();
        let client_addr = "127.0.0.1:5060".parse().unwrap();
        insert_forward(
            &table,
            "z9hG4bK-proxy-1".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            Some(invite_request_with_call_id("call-abc")),
            vec![],
            "sip:bob@127.0.0.1:5060".to_owned(),
        )
        .await;
        insert_forward(
            &table,
            "z9hG4bK-proxy-2".to_owned(),
            client_addr,
            None,
            client_addr,
            vec![],
            Some(invite_request_with_call_id("call-xyz")),
            vec![],
            "sip:bob@127.0.0.1:5061".to_owned(),
        )
        .await;

        let branch = find_branch_by_call_id(&table, "call-abc").await;
        assert_eq!(branch.as_deref(), Some("z9hG4bK-proxy-1"));

        let missing = find_branch_by_call_id(&table, "call-unknown").await;
        assert!(missing.is_none());
    }
}
