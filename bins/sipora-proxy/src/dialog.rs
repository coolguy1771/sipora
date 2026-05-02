//! In-dialog routing state for the UDP proxy.
//!
//! ## Dialog table TTL
//!
//! Entries are stored in a bounded [`moka::sync::Cache`]. They expire after
//! [`DEFAULT_DIALOG_TABLE_TTL`] unless replaced by a newer insert, and are
//! capped at [`DEFAULT_DIALOG_TABLE_MAX_ENTRIES`] (LRU eviction under pressure).
//! Successful BYE forwarding removes the entry immediately via [`remove_dialog`].

use moka::sync::Cache;
use sipora_sip::types::header::{Header, NameAddr, Refresher};
use sipora_sip::types::message::{Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

/// Max dialog rows kept in memory before LRU eviction.
pub const DEFAULT_DIALOG_TABLE_MAX_ENTRIES: u64 = 50_000;

/// Time-to-live for a dialog row after insert or last upsert.
///
/// Configure process-wide by changing this constant (or add config wiring later).
pub const DEFAULT_DIALOG_TABLE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogKey {
    pub call_id: String,
    pub from_tag: String,
    pub to_tag: String,
}

impl DialogKey {
    pub(crate) fn reversed(&self) -> Self {
        Self {
            call_id: self.call_id.clone(),
            from_tag: self.to_tag.clone(),
            to_tag: self.from_tag.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DialogState {
    /// Callee-side dialog route set (from 2xx Record-Route / Contact path).
    pub route_set: Vec<String>,
    pub remote_target: String,
    pub from_party: NameAddr,
    pub to_party: NameAddr,
    pub cseq: u32,
    pub caller_addr: SocketAddr,
    pub callee_addr: SocketAddr,
    /// When the INVITE arrived over WebSocket, BYE toward the caller uses this connection.
    pub caller_reply_ws: Option<String>,
    /// Caller Contact from the inbound INVITE (Request-URI toward caller when set).
    pub caller_remote_target: Option<String>,
    /// Record-Route set from the inbound INVITE (dialog route toward caller).
    pub caller_route_set: Vec<String>,
    pub session_expires: Option<u32>,
    pub session_refresher: Option<Refresher>,
}

pub type DialogTable = Arc<Cache<DialogKey, DialogState>>;

pub fn new_dialog_table() -> DialogTable {
    Arc::new(
        Cache::builder()
            .max_capacity(DEFAULT_DIALOG_TABLE_MAX_ENTRIES)
            .time_to_live(DEFAULT_DIALOG_TABLE_TTL)
            .build(),
    )
}

/// Per-dialog session-timer guard handles: aborted on BYE or re-INVITE.
pub type RefreshTable = Arc<Mutex<HashMap<DialogKey, tokio::task::AbortHandle>>>;

pub fn new_refresh_table() -> RefreshTable {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Spawns a guard that notifies the UDP run loop after `sleep_for` when the session interval elapses.
pub async fn spawn_session_guard(
    dialog_table: &DialogTable,
    refresh_table: &RefreshTable,
    key: DialogKey,
    sleep_for: Duration,
    expired_tx: mpsc::Sender<DialogKey>,
) {
    let dialog_table = Arc::clone(dialog_table);
    let key_for_task = key.clone();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(sleep_for).await;
        tracing::warn!(
            call_id = %key_for_task.call_id,
            "session timer expired — requesting BYE teardown"
        );
        if expired_tx.send(key_for_task.clone()).await.is_err() {
            dialog_table.invalidate(&key_for_task);
        }
    });
    let mut guard = refresh_table.lock().await;
    if let Some(prev) = guard.insert(key, handle.abort_handle()) {
        prev.abort();
    }
}

/// Cancels any running session guard for the given dialog (called on BYE).
pub async fn cancel_session_guard(refresh_table: &RefreshTable, key: &DialogKey) {
    if let Some(handle) = refresh_table.lock().await.remove(key) {
        handle.abort();
    }
}

/// Drops a dialog after successful BYE handling or administrative cleanup.
pub fn remove_dialog(table: &DialogTable, dialog_key: &DialogKey) {
    table.invalidate(dialog_key);
}

pub async fn insert_dialog_from_response(
    table: &DialogTable,
    response: &Response,
    caller_addr: SocketAddr,
    callee_addr: SocketAddr,
    caller_reply_ws: Option<String>,
    caller_invite: Option<&Request>,
) -> Option<DialogKey> {
    let key = response_dialog_key(response)?;
    let (session_expires, session_refresher) = response
        .headers
        .iter()
        .find_map(|h| match h {
            Header::SessionExpires {
                delta_seconds,
                refresher,
            } => Some((*delta_seconds, *refresher)),
            _ => None,
        })
        .map(|(d, r)| (Some(d), r))
        .unwrap_or((None, None));
    let from_party = response.headers.iter().find_map(|h| match h {
        Header::From(na) => Some(na.clone()),
        _ => None,
    })?;
    let to_party = response.headers.iter().find_map(|h| match h {
        Header::To(na) => Some(na.clone()),
        _ => None,
    })?;
    let (caller_route_set, caller_remote_target) = match caller_invite {
        Some(r) => (request_record_route_set(r), request_first_contact_uri(r)),
        None => (Vec::new(), None),
    };
    let state = DialogState {
        route_set: response_route_set(response),
        remote_target: response_remote_target(response)?,
        from_party,
        to_party,
        cseq: response.cseq()?.seq,
        caller_addr,
        callee_addr,
        caller_reply_ws,
        caller_remote_target,
        caller_route_set,
        session_expires,
        session_refresher,
    };
    table.insert(key.clone(), state);
    Some(key)
}

pub async fn dialog_for_request(
    table: &DialogTable,
    request: &Request,
) -> Option<(DialogKey, DialogState)> {
    let key = request_dialog_key(request)?;
    if let Some(state) = table.get(&key) {
        return Some((key, state));
    }
    let rev = key.reversed();
    table.get(&rev).map(|state| (rev, state))
}

fn response_dialog_key(response: &Response) -> Option<DialogKey> {
    let call_id = response.call_id()?.to_owned();
    let from_tag = response.headers.iter().find_map(from_tag)?;
    let to_tag = response.headers.iter().find_map(to_tag)?;
    Some(DialogKey {
        call_id,
        from_tag,
        to_tag,
    })
}

fn request_dialog_key(request: &Request) -> Option<DialogKey> {
    let call_id = request.call_id()?.to_owned();
    let from_tag = request.from_header()?.tag.clone()?;
    let to_tag = request.to_header()?.tag.clone()?;
    Some(DialogKey {
        call_id,
        from_tag,
        to_tag,
    })
}

fn headers_record_route_set(headers: &[Header]) -> Vec<String> {
    headers
        .iter()
        .filter_map(|header| match header {
            Header::RecordRoute(routes) => Some(routes.clone()),
            _ => None,
        })
        .flatten()
        .rev()
        .collect()
}

fn response_route_set(response: &Response) -> Vec<String> {
    headers_record_route_set(&response.headers)
}

fn request_record_route_set(req: &Request) -> Vec<String> {
    headers_record_route_set(&req.headers)
}

fn request_first_contact_uri(req: &Request) -> Option<String> {
    req.contacts().first().map(|c| c.uri.clone())
}

fn response_remote_target(response: &Response) -> Option<String> {
    response
        .contacts()
        .first()
        .map(|contact| contact.uri.clone())
}

fn from_tag(header: &Header) -> Option<String> {
    match header {
        Header::From(name_addr) => name_addr.tag.clone(),
        _ => None,
    }
}

fn to_tag(header: &Header) -> Option<String> {
    match header {
        Header::To(name_addr) => name_addr.tag.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipora_sip::types::header::{CSeq, ContactValue, NameAddr, Refresher};
    use sipora_sip::types::message::{Request, SipVersion};
    use sipora_sip::types::method::Method;
    use sipora_sip::types::status::StatusCode;

    #[tokio::test]
    async fn stores_dialog_from_invite_success_response() {
        let table = new_dialog_table();
        let caller = "127.0.0.1:5060".parse().unwrap();
        let callee = "127.0.0.1:5070".parse().unwrap();

        let key =
            insert_dialog_from_response(&table, &success_response(), caller, callee, None, None)
                .await
                .unwrap();

        let state = table.get(&key).expect("dialog present");
        assert_eq!(state.remote_target, "sip:bob@callee.example.com");
        assert_eq!(state.route_set, vec!["<sip:edge.example.com;lr>"]);
        assert_eq!(state.cseq, 1);
        assert_eq!(state.caller_addr, caller);
        assert_eq!(state.callee_addr, callee);
        assert_eq!(state.session_expires, None);
        assert_eq!(state.session_refresher, None);
        assert!(state.caller_route_set.is_empty());
        assert!(state.caller_remote_target.is_none());
        assert_eq!(state.from_party.uri, "sip:alice@example.com");
        assert_eq!(state.to_party.uri, "sip:bob@example.com");
    }

    #[tokio::test]
    async fn stores_caller_routing_from_invite_headers() {
        let table = new_dialog_table();
        let caller = "127.0.0.1:5060".parse().unwrap();
        let callee = "127.0.0.1:5070".parse().unwrap();
        let invite = Request {
            method: Method::Invite,
            uri: "sip:bob@example.com".to_string(),
            version: SipVersion::V2_0,
            headers: vec![
                Header::RecordRoute(vec!["<sip:proxy.example.com;lr>".to_string()]),
                Header::Contact(vec![ContactValue {
                    uri: "sip:alice@10.0.0.1:5062;transport=udp".to_string(),
                    q: None,
                    expires: None,
                    params: vec![],
                }]),
            ],
            body: Vec::new(),
        };
        let key = insert_dialog_from_response(
            &table,
            &success_response(),
            caller,
            callee,
            None,
            Some(&invite),
        )
        .await
        .unwrap();
        let state = table.get(&key).expect("dialog present");
        assert_eq!(
            state.caller_remote_target.as_deref(),
            Some("sip:alice@10.0.0.1:5062;transport=udp")
        );
        assert_eq!(state.caller_route_set, vec!["<sip:proxy.example.com;lr>"]);
    }

    #[tokio::test]
    async fn stores_session_expires_refresher_from_response() {
        let table = new_dialog_table();
        let caller = "127.0.0.1:5060".parse().unwrap();
        let callee = "127.0.0.1:5070".parse().unwrap();
        let mut resp = success_response();
        resp.headers.push(Header::SessionExpires {
            delta_seconds: 90,
            refresher: Some(Refresher::Uac),
        });
        let key = insert_dialog_from_response(&table, &resp, caller, callee, None, None)
            .await
            .unwrap();
        let state = table.get(&key).expect("dialog present");
        assert_eq!(state.session_expires, Some(90));
        assert_eq!(state.session_refresher, Some(Refresher::Uac));
    }

    fn success_response() -> Response {
        Response {
            version: SipVersion::V2_0,
            status: StatusCode::OK,
            reason: "OK".to_string(),
            headers: vec![
                Header::From(NameAddr {
                    display_name: None,
                    uri: "sip:alice@example.com".to_string(),
                    tag: Some("from-tag".to_string()),
                    params: vec![],
                }),
                Header::To(NameAddr {
                    display_name: None,
                    uri: "sip:bob@example.com".to_string(),
                    tag: Some("to-tag".to_string()),
                    params: vec![],
                }),
                Header::CallId("call-1".to_string()),
                Header::CSeq(CSeq {
                    seq: 1,
                    method: Method::Invite,
                }),
                Header::Contact(vec![ContactValue {
                    uri: "sip:bob@callee.example.com".to_string(),
                    q: None,
                    expires: None,
                    params: vec![],
                }]),
                Header::RecordRoute(vec!["<sip:edge.example.com;lr>".to_string()]),
            ],
            body: Vec::new(),
        }
    }
}
